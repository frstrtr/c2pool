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

#include <impl/dash/mint_runloop.hpp>
#include <impl/dash/tracker_acquire.hpp>

#include <optional>

namespace dash::mint {

/// One queued solve: self-contained (no pointer into the tracker, the job
/// registry or a stratum session).
struct DeferredSolve {
    dash::stratum::DASHWorkSource::MintShareInputs in;
    dash::stratum::FrozenMintJob                   frozen;   ///< copied at arrival
    /// The solve's prev share was the node's best share when it arrived. Only
    /// such a solve can still land on the best chain; one whose prev was
    /// already behind becomes a sibling that loses the equal-work tie (the
    /// soak metric reports the two separately).
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

    const bool won_block = s.in.won_block && !a.from_queue;
    const auto urgency = won_block ? dash::tracker_acquire::Urgency::BlockWinning
                                   : dash::tracker_acquire::Urgency::Opportunistic;

    std::optional<dash::stratum::MintedShare> built;
    {
        auto guard = node.read_tracker(urgency);
        if (!guard) {
            if (won_block)
                LOG_ERROR << "[MINT-BLOCK] FORFEIT — tracker still busy after "
                          << dash::tracker_acquire::BLOCK_SHARE_LOCK_BUDGET.count()
                          << "ms; cannot even REBUILD the block-winning share. The "
                             "block was already submitted, but no p2pool peer will "
                             "see it unless the share is minted later.";
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
    const auto r = node.add_local_share_ex(share, won_block, a.think_after);
    using St = typename NodeT::LocalAddStatus;
    if (r.status != St::added) {
        share.invoke([](auto* obj) { delete obj; });   // not owned by the tracker
        switch (r.status) {
        case St::busy:         return MintOutcome{MintResult::Busy, MintDropReason::none, uint256()};
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

} // namespace dash::mint
