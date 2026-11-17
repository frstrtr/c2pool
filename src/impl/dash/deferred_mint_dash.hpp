// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// DASH binding of the deferred-mint queue (core/deferred_mint.hpp).
///
/// mint_solve_once() is the body main_dash's mint seam ran inline before the
/// queue existed: producer rebuild under a tracker read guard, then the
/// exclusive add. It is unchanged except that it now says WHY a solve did not
/// mint (core::MintOutcome), so the queue can tell a busy tracker (retry) from
/// a solve that can never mint (drop):
///
///   read guard busy        -> Busy
///   producer gate refusal  -> Dropped(gate)      identity / committed target
///   exclusive add busy     -> Busy
///   duplicate              -> Dropped(duplicate)
///   template txs not kept  -> Dropped(not_backable)
///   inserted               -> Minted(hash)
///
/// A deferred mint is built from the same inputs and the same frozen job as
/// the synchronous one; bits, tx refs and abswork are recomputed off the frozen
/// prev share, and the identity gate (m_hash == pow_hash) makes the share
/// byte-identical to what the synchronous path would have built, or declines it.

#include <core/deferred_mint.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>

#include <impl/dash/local_mint_ledger.hpp>
#include <impl/dash/mint_runloop.hpp>
#include <impl/dash/tracker_acquire.hpp>

#include <nlohmann/json.hpp>

#include <optional>

namespace dash::mint {

/// The binary's default for the deferred-mint queue (main_dash g_deferred_mint,
/// catalog sharechain.deferred_mint). OFF until a soak and a production canary
/// have measured it: --deferred-mint turns it on. Flipping this is its own PR.
inline constexpr bool kDeferredMintDefault = false;

/// One queued solve: self-contained (no pointer into the tracker, the job
/// registry or a stratum session).
struct DeferredSolve {
    dash::stratum::DASHWorkSource::MintShareInputs in;
    dash::stratum::FrozenMintJob                   frozen;   ///< copied at arrival
    /// classify_prev_was_tip() at arrival: the solve's prev was the node's best
    /// and no share of ours already claimed it. Only such a solve can still
    /// land on the best chain; the others become siblings that lose the
    /// equal-work tie (the soak metric reports the two separately).
    bool prev_was_tip{false};
};

/// One mint attempt. `a.from_queue` never takes the block-winning bounded wait
/// (that happened once, synchronously, when the solve arrived).
template <typename NodeT>
core::MintOutcome mint_solve_once(NodeT& node, const core::CoinParams& params,
                                  const DeferredSolve& s, const core::MintAttempt& a)
{
    using core::MintDropReason;
    using core::MintOutcome;
    using core::MintResult;

    // The ONE bounded wait a won block gets (#889) is the synchronous attempt;
    // a retry from the queue is an ordinary Opportunistic try.
    const bool wait = s.in.won_block && !a.from_queue;
    const auto urgency = wait ? dash::tracker_acquire::Urgency::BlockWinning
                              : dash::tracker_acquire::Urgency::Opportunistic;
    const auto budget_ms = dash::tracker_acquire::BLOCK_SHARE_LOCK_BUDGET.count();

    std::optional<dash::stratum::MintedShare> built;
    {
        auto guard = node.read_tracker(urgency);
        if (!guard) {
            if (wait) {
                if (a.deferrable)
                    LOG_WARNING << "[MINT-BLOCK] tracker still busy after " << budget_ms
                                << "ms; block-winning share deferred to the FRONT of the "
                                   "mint queue (the block itself was already submitted)";
                else
                    LOG_ERROR << "[MINT-BLOCK] FORFEIT — tracker still "
                                 "busy after "
                              << budget_ms
                              << "ms; cannot even REBUILD the "
                                 "block-winning share. The block was "
                                 "already submitted, but no p2pool peer "
                                 "will see it.";
            } else if (!a.deferrable) {
                LOG_WARNING << "[MINT] tracker busy — solve declined "
                               "(retry on next share)";
            }
            return MintOutcome{MintResult::Busy, MintDropReason::none, uint256()};
        }
        // The share type this chain mints: v16 DashShare (public) or v36
        // DashV36Share (private/isolated v36 sharechain).
        built = mint_from_inputs_any(guard->chain, params, s.in, s.frozen);
    }
    if (!built) {
        LOG_WARNING << "[MINT] producer rebuild declined the solve "
                       "(identity/target gate) — NOT minted"
                    << (a.from_queue ? " (deferred)" : "");
        return MintOutcome{MintResult::Dropped, MintDropReason::gate, uint256()};
    }

    auto share = built->to_share_type();
    const uint256 share_hash = share.hash();
    const auto r = node.add_local_share_ex(share, wait, a.think_after);
    using St = typename NodeT::LocalAddStatus;
    if (r.status != St::added) {
        share.invoke([](auto* obj) { delete obj; });   // not owned by the tracker
        switch (r.status) {
        case St::busy:
            if (wait) {
                if (a.deferrable)
                    LOG_WARNING << "[MINT-BLOCK] tracker still busy after " << budget_ms
                                << "ms; BLOCK-WINNING share " << share_hash.GetHex().substr(0, 16)
                                << " deferred to the FRONT of the mint queue (the block itself "
                                   "was already submitted)";
                else
                    node.record_block_share_forfeit(share_hash);   // the old path, exactly
            } else if (!a.deferrable) {
                LOG_WARNING << "[MINT] tracker busy — local share "
                            << share_hash.GetHex().substr(0, 16)
                            << " declined (retry on next solve)";
            }
            return MintOutcome{MintResult::Busy, MintDropReason::none, uint256()};
        case St::duplicate:    return MintOutcome{MintResult::Dropped, MintDropReason::duplicate, uint256()};
        case St::not_backable: return MintOutcome{MintResult::Dropped, MintDropReason::not_backable, uint256()};
        default:               return MintOutcome{MintResult::Dropped, MintDropReason::other, uint256()};
        }
    }
    LOG_INFO << "[MINT] share " << r.hash.GetHex().substr(0, 16)
             << " minted onto the sharechain (prev="
             << s.in.prev_share_hash.GetHex().substr(0, 16) << ")"
             << (a.from_queue ? (s.prev_was_tip ? " [deferred, prev was tip]"
                                                : " [deferred, prev was behind]")
                              : "");
    return MintOutcome{MintResult::Minted, MintDropReason::none, r.hash};
}

/// Soak metric: can this solve still land on the best chain? Only if its prev
/// is the node's best share AND no share of ours (minted or queued, not yet
/// elected) already claims that prev: a second solve on the same prev is a
/// sibling that loses the equal-work tie to the earlier one. The published
/// best does not move until the think after a mint, so "prev == best" alone
/// would call that sibling "tip".
inline bool classify_prev_was_tip(const uint256& prev, const uint256& best,
                                  const uint256& last_claimed_prev)
{
    if (prev != best)
        return false;
    return last_claimed_prev.IsNull() || prev != last_claimed_prev;
}

/// Which prev share a solve of ours already claims (soak metric only; io
/// thread only). A claim is made when a solve is minted or queued on a prev; a
/// MINTED share holds it for good (its siblings lose the tie to it), a QUEUED
/// one only until it is minted or finally dropped. Only the newest claimed
/// prev is tracked: a claim on a different prev replaces it (a solve on an older
/// prev is "behind" anyway, since prev != best).
class PrevClaimTracker
{
public:
    bool classify_tip(const uint256& prev, const uint256& best) const
    {
        return classify_prev_was_tip(prev, best, m_prev);
    }
    /// A solve on `prev` was minted synchronously (`minted`) or queued.
    void claim(const uint256& prev, bool minted)
    {
        if (prev != m_prev) {
            m_prev = prev;
            m_queued = 0;
            m_minted = false;
        }
        if (minted) m_minted = true;
        else        ++m_queued;
    }
    /// A queued solve on `prev` was minted from the queue.
    void queued_minted(const uint256& prev)
    {
        if (prev != m_prev) return;
        if (m_queued > 0) --m_queued;
        m_minted = true;
    }
    /// A queued solve on `prev` was finally dropped: release its claim.
    void queued_dropped(const uint256& prev)
    {
        if (prev != m_prev) return;
        if (m_queued > 0) --m_queued;
        if (m_queued == 0 && !m_minted) m_prev.SetNull();
    }
    const uint256& claimed_prev() const { return m_prev; }

private:
    uint256  m_prev;
    uint32_t m_queued{0};
    bool     m_minted{false};
};

/// The `mint_defer` object of the sharechain stats JSON (/sharechain/stats):
/// queue counters plus the on-best-chain outcome of the shares minted FROM THE
/// QUEUE, per cause. Lock-free for the caller (both inputs carry their own mutex).
inline nlohmann::json mint_defer_json(const core::DeferredMintSnapshot& snap,
                                      const LocalMintLedger& tip,
                                      const LocalMintLedger& behind)
{
    nlohmann::json d;
    d["enabled"]            = snap.enabled;
    d["depth"]              = snap.depth;
    d["deferred"]           = snap.counters.deferred;
    d["minted"]             = snap.counters.minted;
    d["busy_stops"]         = snap.counters.busy_stops;
    d["batch_thinks"]       = snap.thinks;
    d["off_thread"]         = snap.off_thread;
    d["budget_stops"]       = snap.counters.budget_stops;
    d["max_depth"]          = snap.counters.max_depth;
    d["max_age_ms_at_mint"] = snap.counters.max_age_ms_at_mint;
    nlohmann::json dropped = nlohmann::json::object();
    for (size_t i = 1; i < snap.counters.dropped.size(); ++i)
        if (snap.counters.dropped[i] > 0)
            dropped[core::to_string(static_cast<core::MintDropReason>(i))] = snap.counters.dropped[i];
    d["dropped"] = dropped;
    const auto ledger_json = [](const LocalMintLedger& l) {
        const auto st = l.stats();
        return nlohmann::json{{"minted", st.minted},     {"on_chain", st.on_chain},
                              {"orphaned", st.orphaned}, {"pending", st.pending},
                              {"gone", st.gone},         {"orphan_rate", st.orphan_rate}};
    };
    d["prev_was_tip"]    = ledger_json(tip);
    d["prev_was_behind"] = ledger_json(behind);
    return d;
}

} // namespace dash::mint
