// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SSOT for the think() Phase-6 desired-shares TIMESTAMP CUTOFF — the two pure
// decisions that govern which outstanding (desired) share requests survive the
// final filter at the end of think():
//   (a) the cutoff timestamp itself, derived from the best share (or a 24h
//       fallback when there is no valid best), and
//   (b) the per-request keep/drop predicate against that cutoff.
//
// These are currently OPEN-CODED inline in share_tracker.hpp think() Phase 6
// (the best-valid vs no-best branch computing timestamp_cutoff, plus the
// `d.max_timestamp >= timestamp_cutoff` keep test in the desired loop). A silent
// drift — wrong fallback window, wrong 3600s back-off, or a flipped comparison —
// would change which shares a c2pool-dgb node keeps requesting during sync, with
// NO compile error: too-loose hammers peers with unanswerable requests until they
// drop us; too-tight starves the chain of legitimately-missing parents. Lifting
// the arithmetic to a single header-only SSOT lets a KAT pin it exactly.
//
// Oracle: p2pool data.py:2360-2374  OkayTracker.think() tail:
//     if best is not None:
//         timestamp_cutoff = min(int(time.time()), best_share.timestamp) - 3600
//     else:
//         timestamp_cutoff = int(time.time()) - 24*60*60
//     return best, [(peer_addr, hash) for peer_addr, hash, ts, targ in desired
//                   if ts >= timestamp_cutoff]
//
// Per-coin isolation: dgb/ only. Header-only, additive; this slice does NOT yet
// rewire share_tracker.hpp (that is the byte-identity-fenced delegation
// follow-on) — it pins the cutoff math as free functions so the KAT exercises
// them with no ShareTracker/NodeImpl standup. Consensus-neutral: pure arithmetic,
// no value semantics changed.

#include <algorithm>
#include <cstdint>

namespace dgb {

// The Phase-6 desired-shares timestamp cutoff.
//   best_valid == true : min(now, best_ts) - 3600   (1h grace below the best
//       share timestamp; min() guards a best share whose timestamp is ahead of
//       local clock from pushing the cutoff into the future).
//   best_valid == false: now - 24*60*60             (24h fallback window when no
//       best share is resolved yet).
// uint32_t arithmetic, byte-identical to the inline share_tracker.hpp formula.
inline uint32_t think_p6_timestamp_cutoff(bool best_valid, uint32_t best_ts,
                                          uint32_t now)
{
    if (best_valid)
        return std::min(now, best_ts) - 3600u;
    return now - 24u * 60u * 60u;
}

// Per-desired-request keep predicate: a request whose max-available timestamp is
// at or after the cutoff is retained (inclusive lower bound), matching the
// p2pool list-comprehension guard `ts >= timestamp_cutoff`.
inline bool think_p6_passes_cutoff(uint32_t max_timestamp, uint32_t cutoff)
{
    return max_timestamp >= cutoff;
}

} // namespace dgb