#pragma once

// SSOT for the think() Phase-2 verification-extension BOUNDS — the pure integer
// decision governing, per verified sharechain head, how many ancestor shares to
// pull in (via get_chain) on this think() pass to extend the verified segment
// backward toward CHAIN_LENGTH.
//
// This formula is currently OPEN-CODED inline in share_tracker.hpp think()
// Phase 2 (the want / can / to_get triple just before the get_chain(last, N)
// walk). A silent drift against the p2pool oracle would change how aggressively
// a c2pool-dgb node back-fills verification during sync — too small starves the
// best chain, too large over-reads past the rooted boundary — with NO compile
// error. Lifting it to a single header-only SSOT lets a KAT pin the exact
// arithmetic (want clamp at 0, the rooted/unrooted can split, the min).
//
// Oracle: p2pool data.py:2098-2103  OkayTracker.think(), per verified head:
//     want = max(self.net.CHAIN_LENGTH - head_height, 0)
//     can = max(last_height - 1 - self.net.CHAIN_LENGTH, 0) \
//           if last_last_hash is not None else last_height
//     get = min(want, can)
//   head_height: accumulated height of the verified head.
//   last_height: height of the verified segment's tail (last_hash).
//   last_last_hash: the tail's own last — None when the tail is itself the
//       chain root (segment not yet rooted past CHAIN_LENGTH).
//
// Per-coin isolation: dgb/ only. Header-only, additive; this slice does NOT yet
// rewire share_tracker.hpp (that is the byte-identity-fenced delegation
// follow-on, mirroring #354 onto #353) — it pins the bound as a free function so
// the KAT exercises it with no ShareTracker/NodeImpl standup. Consensus-neutral:
// pure arithmetic, no value semantics changed.

#include <algorithm>
#include <cstdint>

namespace dgb {

// How many ancestor shares think() Phase 2 may pull this pass to extend a
// verified head backward.
//   want: the deficit between CHAIN_LENGTH and the head height, floored at 0
//       (a head already at/over CHAIN_LENGTH needs nothing).
//   can : how many the tail can safely supply without reading past the rooted
//       boundary. If the tail is rooted (last_has_parent == true) we must stop
//       1 share above CHAIN_LENGTH from the tail; floored at 0. If the tail is
//       itself the root (last_has_parent == false) the whole tail height is
//       available.
//   get = min(want, can).
inline int32_t think_p2_extend_get(int32_t head_height, int32_t last_height,
                                   bool last_has_parent, int32_t chain_length)
{
    const int32_t want = std::max(chain_length - head_height, 0);
    const int32_t can = last_has_parent
        ? std::max(last_height - 1 - chain_length, 0)
        : last_height;
    return std::min(want, can);
}

} // namespace dgb
