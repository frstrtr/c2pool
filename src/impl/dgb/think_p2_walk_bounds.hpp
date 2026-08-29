// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SSOT for the think() Phase-2 verification-extension walk BOUNDS — the three
// pure integer decisions that govern, per VERIFIED sharechain head, how many
// shares think() Phase 2 walks backward attempting to extend verification:
//   want = how many shares below this head still need verifying,
//   can  = how many the resolved segment actually permits fetching,
//   get  = min(want, can) = the bounded walk count handed to get_chain().
//
// This formula is currently OPEN-CODED inline in share_tracker.hpp think()
// Phase 2 (the want/can/get block just before the get_chain(last, to_get)
// walk). A silent drift against the p2pool oracle — or against the sibling
// Phase-1 walk-bounds SSOT (think_p1_walk_bounds.hpp) — would change how far a
// c2pool-dgb node extends verification per think() cycle during sync, with NO
// compile error. Lifting it to a single header-only SSOT lets a KAT pin the
// exact arithmetic (want floor 0, the unrooted-vs-rooted `can` split, the
// -1-CHAIN_LENGTH offset on the rooted branch, get = min).
//
// Oracle: p2pool data.py:2098-2103  OkayTracker.think(), per verified head:
//     want = max(self.net.CHAIN_LENGTH - head_height, 0)
//     can  = max(last_height - 1 - self.net.CHAIN_LENGTH, 0)
//                 if last_last_hash is not None else last_height
//     get  = min(want, can)
//   (head_height = height of the verified head; last_height/last_last_hash =
//    the resolved tail segment's height and its parent, i.e. whether the
//    segment is rooted.)
//
// Per-coin isolation: dgb/ only. Header-only, additive; this slice does NOT yet
// rewire share_tracker.hpp (that is the byte-identity-fenced delegation
// follow-on) — it pins the bounds as a free function so the KAT exercises them
// with no ShareTracker/NodeImpl standup. Consensus-neutral: pure arithmetic,
// no value semantics changed. Sibling of think_p1_walk_bounds.hpp.

#include <algorithm>
#include <cstdint>

namespace dgb {

// The three Phase-2 walk-bound integers, returned together so the KAT (and the
// eventual delegation) can pin each independently.
struct ThinkP2WalkBounds {
    int32_t want;  // shares still needing verification below this head
    int32_t can;   // shares the resolved segment permits fetching
    int32_t get;   // min(want, can) — the bounded count handed to get_chain()
};

// Compute the Phase-2 verification-extension walk bounds for one verified head.
//   head_height : accumulated height of the verified head.
//   last_height : height of the resolved tail segment (`last`).
//   has_last    : whether the segment is rooted (last_last_hash is non-null).
//                 false => `can` is the full last_height (unrooted: nothing
//                 below has been settled away yet).
//   chain_length: net.CHAIN_LENGTH.
inline ThinkP2WalkBounds think_p2_walk_bounds(int32_t head_height,
                                              int32_t last_height,
                                              bool has_last,
                                              int32_t chain_length)
{
    int32_t want = std::max(chain_length - head_height, 0);
    int32_t can = has_last
        ? std::max(last_height - 1 - chain_length, 0)
        : last_height;
    int32_t get = std::min(want, can);
    return {want, can, get};
}

} // namespace dgb