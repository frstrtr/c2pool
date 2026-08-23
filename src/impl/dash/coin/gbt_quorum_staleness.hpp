// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// GBT-xcheck quorum-root staleness classifier — CLASSIFY a merkleRootQuorums
/// divergence before swapping to dashd, instead of treating EVERY difference as
/// an embedded error.
///
/// BACKGROUND. The #127 null-arm reward-safety backstop (work_source.cpp) cross-
/// checks our embedded CbTx merkleRootQuorums against dashd's getblocktemplate
/// and, on ANY difference, HARD-swaps to dashd's template on the theory that a
/// wrong quorum root is the bad-cbtx-quorummerkleroot reject vector. That is the
/// right default — but it has ONE inverted case.
///
/// MEASURED (mainnet, 2026-08). At each 24-block LLMQ DKG commitment boundary
/// (observed heights 2525987, 2526011, 2526035, 2526059, ... — a clean 24-block
/// cadence, episodes <1s) dashd's getblocktemplate momentarily serves the
/// PREVIOUS cycle's quorum root while our embedded arm has already advanced to
/// the freshly-committed one. Chain truth (dashd RPC, mined blocks): block
/// 2525987's CbTx merkleRootQuorums == our EMBEDDED root; dashd's own GBT at
/// that instant served the stale prior-cycle value (which equals OUR root one
/// cycle earlier). Same at 2526011. So in this ~1s window the reward-safety
/// direction is INVERTED: swapping to dashd serves the chain-would-reject
/// template, and it is the EMBEDDED root the chain commits.
///
/// This classifier isolates exactly that case and NOTHING else. It is a pure,
/// stateless predicate over the two parsed CbTx roots plus the last root the two
/// arms AGREED on (kept by the caller), so a KAT can pin it without a live
/// daemon, a stratum session, or a populated coin state (mirrors
/// special_tx_pool_delta.hpp).
///
/// SAFE-DIRECTION CONTRACT. Returns true (⇒ caller KEEPS embedded) ONLY when:
///   (1) the quorum roots actually differ (emb_quorum != dref_quorum);
///   (2) the MN-list root axis AGREES (mnlist_matches) — a simultaneous
///       quorum+MN divergence is body-divergence, not a pure DKG boundary, and
///       must take the ordinary swap;
///   (3) a prior AGREED quorum root exists (both arms matched at an earlier
///       serve) AND dashd's current root EQUALS it (dashd REGRESSED to the
///       pre-boundary value) AND our embedded root has ADVANCED PAST it
///       (emb_quorum != last_agreed).
///
/// The inverse skew — embedded stale, dashd fresh — makes dref the NEW value,
/// so dref != last_agreed and the predicate returns false: the caller swaps to
/// dashd, which is the reward-safe direction. With no prior agreement (cold
/// start) it also returns false (swap). A two-cycle dashd lag (dref equals a
/// root older than last_agreed) likewise returns false (swap) — we only assert
/// the chain-proven single-cycle-boundary case.

#include <core/uint256.hpp>

namespace dash {
namespace coin {

/// See file header. `last_agreed` is the most recent quorum root at which the
/// embedded and dashd arms matched, or nullptr when no such agreement has been
/// observed yet (cold start).
inline bool quorumroot_dashd_is_stale(const uint256& emb_quorum,
                                      const uint256& dref_quorum,
                                      bool           mnlist_matches,
                                      const uint256* last_agreed)
{
    if (emb_quorum == dref_quorum) return false;   // no divergence to classify
    if (!mnlist_matches)           return false;   // mixed divergence ⇒ swap
    if (last_agreed == nullptr)    return false;   // no history ⇒ swap
    if (last_agreed->IsNull())     return false;   // unset sentinel ⇒ swap
    // dashd regressed to the pre-boundary root while embedded advanced past it.
    return dref_quorum == *last_agreed && emb_quorum != *last_agreed;
}

} // namespace coin
} // namespace dash
