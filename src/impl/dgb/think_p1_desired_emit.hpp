// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SSOT for the think() Phase-1 DESIRED-EMIT decision — the requester-side rule
// that decides, per unverified sharechain head whose verification walk found
// nothing, WHETHER to emit a parent (desired) download request for that head's
// resolved parent hash `last`, and if not, WHY it is suppressed.
//
// This decision is currently OPEN-CODED 2x inline in share_tracker.hpp think()
// Phase 1: once in the walk0 branch (walk_count <= 0) and once in the for/else
// branch (verification walk completed without verifying). Both copies run the
// identical ladder:
//
//     if (!last.IsNull()) {                       // there IS a parent to request
//         if (head_height >= 2*CL + 10)  -> skip  // pruning-zone (re-pruned anyway)
//         else if (desired_hashes.count(last)) -> skip   // already desired (dedup)
//         else -> desired_hashes.insert(last); desired.push_back({peer,last,ts})
//     }
//
// A silent drift between the two copies — or against the p2pool oracle — would
// change which parents a c2pool-dgb node requests during sync (or double-request
// a hash, or keep requesting a prune-zone parent that clean_tracker immediately
// drops) with NO compile error. Lifting the decision to a single header-only
// SSOT lets a KAT pin the exact ladder, including the check ORDER (no-parent →
// pruning-zone → duplicate → emit) and the inclusive 2*CL+10 prune boundary.
//
// Oracle: p2pool data.py:2095-2108 OkayTracker.think(), the `desired.add(...)`
// emission inside the per-head verify loop; combined with c2pool-dgb's
// node-local prune-zone guard (a head at/over 2*CHAIN_LENGTH+10 has parents that
// clean_tracker would immediately re-prune, so no parent request is emitted) and
// the desired-set dedup-by-hash (p2pool `desired = set()`).
//
// Composes with think_p1_in_pruning_zone() from think_p1_walk_bounds.hpp so the
// prune boundary stays defined in exactly one place.
//
// Per-coin isolation: dgb/ only. Header-only, additive; this slice does NOT yet
// rewire share_tracker.hpp (that is the byte-identity-fenced delegation
// follow-on, mirroring the walk-bounds #353->#354 split) — it pins the decision
// as a pure free function so the KAT exercises it with no ShareTracker/NodeImpl
// standup. Consensus-neutral: the function only CLASSIFIES; the caller still
// performs the desired-set insert + push on Emit. No value semantics changed.

#include <impl/dgb/think_p1_walk_bounds.hpp>

#include <cstdint>

namespace dgb {

// Outcome of the think() Phase-1 desired-emit decision for one unverified head.
// Order matches the inline ladder's short-circuit precedence.
enum class ThinkP1DesiredEmit {
    SkipNoParent,     // last.IsNull(): head has no resolved parent to request
    SkipPruningZone,  // head_height >= 2*CL+10: parent would be re-pruned at once
    SkipDuplicate,    // parent hash already present in the desired set (dedup)
    EmitRequest,      // emit a desired (parent download) request for `last`
};

// Decide whether think() Phase-1 should emit a desired parent-download request.
//   last_is_null   : true if the head's resolved parent (`last`) is null.
//   head_height    : accumulated height of the head.
//   chain_length   : PoolConfig::chain_length() (CHAIN_LENGTH).
//   already_desired: true if `last` is already in the running desired-hash set.
// The caller performs the desired_hashes.insert(last) + desired.push_back(...)
// side effects ONLY when this returns EmitRequest.
inline ThinkP1DesiredEmit think_p1_desired_emit(bool last_is_null,
                                                int32_t head_height,
                                                int32_t chain_length,
                                                bool already_desired)
{
    if (last_is_null)
        return ThinkP1DesiredEmit::SkipNoParent;
    if (think_p1_in_pruning_zone(head_height, chain_length))
        return ThinkP1DesiredEmit::SkipPruningZone;
    if (already_desired)
        return ThinkP1DesiredEmit::SkipDuplicate;
    return ThinkP1DesiredEmit::EmitRequest;
}

} // namespace dgb