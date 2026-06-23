#pragma once

// SSOT for the think() Phase-1 desired-set walk BOUNDS — the two pure integer
// decisions that govern, per unverified sharechain head, (a) how far back to
// walk attempting verification and (b) whether to skip emitting a parent
// (desired) request because the head already sits in the prune zone.
//
// These two formulas are currently OPEN-CODED 2-3x inline in share_tracker.hpp
// think() Phase 1 (the walk0 branch and the for/else branch each re-derive the
// pruning threshold; the walk-count clamp carries the magic literal 5). A silent
// drift between the duplicated copies — or against the p2pool oracle — would
// change which parents a c2pool-dgb node requests during sync, with NO compile
// error. Lifting them to a single header-only SSOT lets a KAT pin the exact
// arithmetic (clamp at 5, floor at 0, inclusive prune threshold 2*CL+10).
//
// Oracle: p2pool data.py:2077-2108  OkayTracker.think(), per unverified head:
//     # walk back at most a few shares trying to verify one
//     to_test = self.get_chain(head, min(5, max(0, height - net.CHAIN_LENGTH)))
//     ...
//   and c2pool's node-local prune-zone guard: a head at/over
//   2*CHAIN_LENGTH+10 has parents that clean_tracker would immediately re-prune,
//   so no parent request is emitted for it.
//
// Per-coin isolation: dgb/ only. Header-only, additive; this slice does NOT yet
// rewire share_tracker.hpp (that is the byte-identity-fenced delegation
// follow-on) — it pins the bounds as free functions so the KAT exercises them
// with no ShareTracker/NodeImpl standup. Consensus-neutral: pure arithmetic,
// no value semantics changed.

#include <algorithm>
#include <cstdint>

namespace dgb {

// How far back think() Phase 1 walks from an unverified head attempting to
// verify one share.
//   has_last == false (unrooted head, no resolved segment): walk the full
//       accumulated height.
//   has_last == true: walk at most 5, and only the shares ABOVE CHAIN_LENGTH
//       (max(0, height - CHAIN_LENGTH)) — older shares are already settled.
inline int32_t think_p1_walk_count(int32_t head_height, bool has_last,
                                   int32_t chain_length)
{
    if (!has_last)
        return head_height;
    return std::min(5, std::max(0, head_height - chain_length));
}

// Prune-zone guard (inclusive). A head whose accumulated height has reached
// 2*CHAIN_LENGTH+10 will have any requested parent immediately re-pruned by
// clean_tracker, so think() suppresses the parent (desired) request for it.
inline bool think_p1_in_pruning_zone(int32_t head_height, int32_t chain_length)
{
    return head_height >= 2 * chain_length + 10;
}

} // namespace dgb
