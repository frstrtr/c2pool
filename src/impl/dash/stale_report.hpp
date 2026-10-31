// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ============================================================================
// stale_report.hpp — the node's own orphan/DOA report in minted shares
// (share_data stale_info), for both share types (v16 DashShare, v36
// DashV36Share).
//
// ORACLE: p2pool-dash work.py (v16 lineage). Every share a node mints is
// remembered (my_share_hashes, :57, :520); a share solved more than 3 work
// events after its job was handed out is dead on arrival (:479-480) and also
// remembered in my_doa_share_hashes (:521-522). At job time the node counts
// how many of its shares are NOT on the best chain (get_stale_counts,
// :149-161) and compares that with how many of its on-chain shares already
// announced a stale event:
//
//   stale_info = 'orphan' if orphans > orphans_recorded_in_chain else
//                'doa'    if doas    > doas_recorded_in_chain    else None
//                                                            (:345-349)
//
// The byte rides in share_data, so it is committed in the ref_hash of the job
// (frozen at job time, exactly like the oracle's get_work). Peers do not
// validate it (check() recomputes ref from the share's own byte), so this is
// informational: it feeds the pool-wide stale/efficiency statistics.
//
// "On the best chain" is the oracle predicate tracker.is_child_of(h, best)
// (work.py:72, :79). The oracle keeps the counts over the whole tracker view
// plus the shares already pruned while on-chain (removed_unstales, :70-80);
// here the same split is a small pending set checked live against the best
// share, folded into permanent counters once a verdict is deep enough
// (kSettleDepth) or the share left the tracker. A pending share that is a
// DESCENDANT of the best share (minted on top of it, not yet elected) counts
// as on-chain: the oracle makes its own share best synchronously
// (work.py:524-525), c2pool elects it on the next think(), and the job built
// in between must not announce a spurious orphan.
//
// Header-only, fenced to src/impl/dash/. KAT: test_dash_stale_report.cpp.
// ============================================================================

#include "share_types.hpp"   // dash::StaleInfo

#include <core/uint256.hpp>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <iterator>
#include <mutex>
#include <utility>

namespace dash::mint {

/// The six inputs of the oracle get_stale_counts (work.py:151-157).
struct StaleTally
{
    uint64_t my_shares{0};                  ///< len(my_share_hashes)
    uint64_t my_doa_shares{0};              ///< len(my_doa_share_hashes)
    uint64_t my_shares_in_chain{0};         ///< my shares on the best chain
    uint64_t my_doa_shares_in_chain{0};     ///< my DOA shares on the best chain
    uint64_t orphans_recorded_in_chain{0};  ///< my on-chain shares announcing orphan
    uint64_t doas_recorded_in_chain{0};     ///< my on-chain shares announcing doa
};

namespace detail {
inline uint64_t sat_sub(uint64_t a, uint64_t b) { return a > b ? a - b : 0; }
}

/// (orphans, doas) — work.py:159-161. DOA shares are also in my_shares, so
/// the orphan count excludes the DOA shares that are off the chain.
inline std::pair<uint64_t, uint64_t> stale_counts(const StaleTally& t)
{
    const uint64_t not_in_chain     = detail::sat_sub(t.my_shares, t.my_shares_in_chain);
    const uint64_t doa_not_in_chain = detail::sat_sub(t.my_doa_shares, t.my_doa_shares_in_chain);
    return {detail::sat_sub(not_in_chain, doa_not_in_chain), doa_not_in_chain};
}

/// The stale_info byte of the next minted share — work.py:345-349 verbatim:
/// an unannounced orphan wins over an unannounced DOA; none when every stale
/// event is already announced by an on-chain share.
inline StaleInfo next_stale_info(const StaleTally& t)
{
    const auto [orphans, doas] = stale_counts(t);
    if (orphans > t.orphans_recorded_in_chain)
        return StaleInfo::orphan;
    if (doas > t.doas_recorded_in_chain)
        return StaleInfo::doa;
    return StaleInfo::none;
}

/// work.py:479-480: a solve is on time when at most 3 work events happened
/// since its job was handed out (lp_count = new_work_event.times at get_work).
inline bool solve_on_time(uint64_t gen_at_job, uint64_t gen_now)
{
    return gen_now <= gen_at_job || gen_now - gen_at_job <= 3;
}

/// Where one minted share sits relative to the best share.
enum class StalePlacement {
    in_chain,   ///< ancestor of (or equal to) best, or minted on top of best
    off_chain,  ///< not on the best chain
    gone        ///< no longer in the tracker
};

/// `depth` receives best_height - minted_height when the share is at or
/// below the best share's height (0 otherwise). The caller holds the tracker
/// read guard; get_acc_height / get_nth_parent_via_skip use the leaf-mutexed
/// caches (see the lock note in local_mint_ledger.hpp).
template <typename ChainT>
inline StalePlacement place_minted_share(ChainT& chain, const uint256& best,
                                         const uint256& minted, int32_t& depth)
{
    depth = 0;
    if (!chain.contains(minted))
        return StalePlacement::gone;
    if (best.IsNull() || !chain.contains(best))
        return StalePlacement::in_chain;       // no best chain yet: no evidence of a loss
    if (minted == best)
        return StalePlacement::in_chain;
    const int32_t hm = chain.get_acc_height(minted);
    const int32_t hb = chain.get_acc_height(best);
    try {
        if (hm <= hb) {
            depth = hb - hm;
            return chain.get_nth_parent_via_skip(best, hb - hm) == minted
                ? StalePlacement::in_chain : StalePlacement::off_chain;
        }
        // Above the best share: on-chain only while best is its ancestor
        // (minted on top of best, election pending).
        return chain.get_nth_parent_via_skip(minted, hm - hb) == best
            ? StalePlacement::in_chain : StalePlacement::off_chain;
    } catch (const std::exception&) {
        return StalePlacement::off_chain;
    }
}

/// The node's own minted shares and their fate, for the stale_info byte.
/// Thread-safe (own mutex); bounded.
class LocalStaleLedger
{
public:
    /// Best-chain depth after which a verdict is folded into the permanent
    /// counters (a reorg deeper than this is not re-counted).
    static constexpr int32_t kSettleDepth = 20;
    /// Bound on the unsettled set; the oldest entries are forgotten (removed
    /// from every counter, so they count neither way).
    static constexpr std::size_t kMaxPending = 1024;

    /// work.py:520-522: every local mint; `doa` = solved after the grace;
    /// `announced` = the stale_info byte the share itself carries.
    void record_mint(const uint256& hash, bool doa, StaleInfo announced)
    {
        if (hash.IsNull())
            return;
        std::lock_guard<std::mutex> lk(m_mutex);
        ++m_my_shares;
        if (doa)
            ++m_my_doa_shares;
        m_pending.push_back(Entry{hash, doa, announced});
        while (m_pending.size() > kMaxPending) {
            const Entry& e = m_pending.front();
            --m_my_shares;
            if (e.doa)
                --m_my_doa_shares;
            m_pending.pop_front();
        }
    }

    /// The oracle tally against `best`: the settled counters plus a live pass
    /// over the unsettled shares.
    template <typename ChainT>
    StaleTally tally(ChainT& chain, const uint256& best) const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        StaleTally t;
        t.my_shares                 = m_my_shares;
        t.my_doa_shares             = m_my_doa_shares;
        t.my_shares_in_chain        = m_in_chain;
        t.my_doa_shares_in_chain    = m_doa_in_chain;
        t.orphans_recorded_in_chain = m_orphans_recorded;
        t.doas_recorded_in_chain    = m_doas_recorded;
        for (const auto& e : m_pending) {
            int32_t depth = 0;
            if (place_minted_share(chain, best, e.hash, depth) != StalePlacement::in_chain)
                continue;
            add_in_chain(t, e);
        }
        return t;
    }

    /// Fold every unsettled share whose verdict is final into the counters:
    /// on-chain at depth >= kSettleDepth -> in chain for good; off-chain with
    /// the best chain kSettleDepth past its height, or gone -> not in chain
    /// for good (the oracle's view of a share pruned while not is_child_of
    /// the best share).
    template <typename ChainT>
    void settle(ChainT& chain, const uint256& best)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        for (auto it = m_pending.begin(); it != m_pending.end();) {
            int32_t depth = 0;
            const auto where = place_minted_share(chain, best, it->hash, depth);
            bool done = false;
            if (where == StalePlacement::gone) {
                done = true;
            } else if (depth >= kSettleDepth) {
                if (where == StalePlacement::in_chain) {
                    ++m_in_chain;
                    if (it->doa) ++m_doa_in_chain;
                    if (it->announced == StaleInfo::orphan) ++m_orphans_recorded;
                    if (it->announced == StaleInfo::doa) ++m_doas_recorded;
                }
                done = true;
            }
            it = done ? m_pending.erase(it) : std::next(it);
        }
    }

    uint64_t my_shares() const { std::lock_guard<std::mutex> lk(m_mutex); return m_my_shares; }
    uint64_t my_doa_shares() const { std::lock_guard<std::mutex> lk(m_mutex); return m_my_doa_shares; }
    std::size_t pending_count() const { std::lock_guard<std::mutex> lk(m_mutex); return m_pending.size(); }

private:
    struct Entry {
        uint256 hash;
        bool doa{false};
        StaleInfo announced{StaleInfo::none};
    };

    static void add_in_chain(StaleTally& t, const Entry& e)
    {
        ++t.my_shares_in_chain;
        if (e.doa) ++t.my_doa_shares_in_chain;
        if (e.announced == StaleInfo::orphan) ++t.orphans_recorded_in_chain;
        if (e.announced == StaleInfo::doa) ++t.doas_recorded_in_chain;
    }

    mutable std::mutex m_mutex;
    std::deque<Entry> m_pending;
    uint64_t m_my_shares{0};
    uint64_t m_my_doa_shares{0};
    uint64_t m_in_chain{0};
    uint64_t m_doa_in_chain{0};
    uint64_t m_orphans_recorded{0};
    uint64_t m_doas_recorded{0};
};

} // namespace dash::mint
