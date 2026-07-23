// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SSOT for the DGB POOL-ATTEMPTS-PER-SECOND estimator -- the pure arithmetic
// core of ShareTracker::get_pool_attempts_per_second(): given the resolved
// near/far endpoints of a sharechain window, compute the pool hashrate estimate
//
//   attempts_per_second = attempts / max(1, near_ts - far_ts)
//
// where attempts is the cumulative-work delta over the window (work, or min_work
// when the min-work variant is requested) and the time span is clamped to a
// strictly-positive denominator. This figure feeds the operator-facing "Pool:
// <hashrate>" status line AND the PPLNS / expected-time-to-block windows, so a
// silent drift (flipped sign on the span, dropping the <=0 clamp, a non-integer
// divide) would misreport pool hashrate with NO compile error -- operator-facing
// behavior the V36 master-compat invariant pins to the p2pool reference.
//
// Oracle: p2pool-dgb-scrypt data.py get_pool_attempts_per_second(tracker,
//   previous_share_hash, dist, min_work=False, integer=False):
//       assert dist >= 2
//       near = tracker.items[previous_share_hash]
//       far  = tracker.items[tracker.get_nth_parent_hash(previous_share_hash, dist-1)]
//       attempts = tracker.get_delta(near.hash, far.hash).work        # or .min_work
//       time = near.timestamp - far.timestamp
//       if time <= 0: time = 1
//       return attempts//time      # the integer=True path c2pool always takes
//
// The chain-walk halves of the oracle -- locating `far` via get_nth_parent_hash
// and summing the work delta via get_delta -- stay inside ShareTracker (they need
// the skip-list / TrackerView). This header captures ONLY the endpoint-resolution
// guards and the final clamp+divide as a free function over already-resolved
// inputs, so a KAT can pin the arithmetic with no NodeImpl / ShareTracker standup.
//
// Per-coin isolation: dgb/ only. Header-only, additive. This slice does NOT yet
// rewire share_tracker.hpp -- that is the byte-identity delegation follow-on.
// The lifted body is a verbatim copy of the inline arithmetic (same int32_t span
// type, same uint288 divide), so the follow-on is provably value-identical.
// Consensus-neutral: pure arithmetic, no value semantics changed.

#include <cstdint>

#include <core/uint256.hpp>  // uint288

namespace dgb {

// Resolved endpoints of a get_pool_attempts_per_second window. The caller
// performs the chain walk (dist guard, near lookup, far via get_nth_parent_hash,
// work delta via get_delta) and hands the results here.
struct PoolAttemptsInputs {
    int32_t dist;          // requested window depth; oracle asserts dist >= 2
    bool    near_in_chain; // previous_share_hash present in the tracker
    bool    far_resolved;  // get_nth_parent_hash(dist-1) found AND in the tracker
    uint288 attempts;      // get_delta(near, far).work (or .min_work) -- caller picks
    uint32_t near_ts;      // near.timestamp
    uint32_t far_ts;       // far.timestamp
};

// attempts_per_second over the resolved window.
//
// Returns 0 when the window cannot be formed: dist < 2 (oracle assert), the near
// share is absent, or the far endpoint did not resolve. Otherwise the time span
// is near_ts - far_ts clamped up to 1 (matching the oracle `if time <= 0: time =
// 1`), and the result is the integer division attempts / span (the integer=True
// path c2pool always uses). uint288 throughout -- no overflow on the cumulative
// work numerator.
inline uint288 compute_pool_attempts_per_second(const PoolAttemptsInputs& in) {
    if (in.dist < 2)        return uint288(0);
    if (!in.near_in_chain)  return uint288(0);
    if (!in.far_resolved)   return uint288(0);

    int32_t time_span = static_cast<int32_t>(in.near_ts) - static_cast<int32_t>(in.far_ts);
    if (time_span <= 0) time_span = 1;

    return in.attempts / uint288(time_span);
}

}  // namespace dgb