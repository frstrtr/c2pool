// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SSOT for the DGB EXPECTED-TIME-TO-BLOCK diagnostic — the final pure-arithmetic
// step the status loop applies when reporting how long the pool is expected to
// take to find a block:
//   etb_secs = average_attempts / real_pool_hs
// where average_attempts is the block-target's average attempts (the low 64 bits
// of chain::target_to_average_attempts(bits_to_target(block_bits))) and
// real_pool_hs is the efficiency-adjusted pool hashrate from pool_efficiency.hpp.
//
// This is currently OPEN-CODED inline in node.cpp's diagnostics loop (the
// `etb_secs = block_aps.GetLow64() / real_pool_hs` division plus the
// near-overflow sentinel) feeding the "Pool: <hashrate> ... Expected time to
// block: <duration>" line. A silent drift — a flipped numerator/denominator or
// dropping the overflow sentinel — would misreport a node's expected time to
// block with NO compile error, which is operator-facing behavior the V36
// master-compat invariant pins to the p2pool reference. Lifting the arithmetic
// to a single header-only SSOT lets a KAT pin it exactly against the oracle.
//
// Oracle: p2pool-dgb-scrypt main.py status loop:
//     'Expected time to block: %s' % format_dt(
//         2**256 / current_work.value['bits'].target / real_att_s)
//   i.e. average_attempts(target) / real_att_s, where the c2pool path computes
//   average_attempts via the existing chain::target_to_average_attempts SSOT and
//   guards the case where that count overflows uint64 while the target is
//   non-null (reporting a 1e18 sentinel rather than a meaningless small value).
//
// Per-coin isolation: dgb/ only. Header-only, additive; this slice does NOT yet
// rewire node.cpp (that is the byte-identity-fenced delegation follow-on that
// also folds in get_stale_counts + pool_efficiency). It pins the math as a free
// function so the KAT exercises it with no NodeImpl / ShareTracker standup. The
// bits->target->average_attempts conversion stays at the call site on the
// already-verified chain SSOTs; this function captures only the final combine +
// sentinel. Consensus-neutral: pure arithmetic, no value semantics changed.

#include <cstdint>

namespace dgb {

// Expected seconds for the pool to find a block.
//   etb_secs = average_attempts / real_pool_hs
//
// average_attempts        : static_cast<double>(block_aps.GetLow64()), the low 64
//                           bits of the block target's average-attempts count.
// real_pool_hs            : efficiency-adjusted pool hashrate (hashes/s).
// average_attempts_overflowed : block_aps.IsNull() — the average-attempts count
//                           does not fit in uint64 (its low64 is meaningless).
// block_target_nonzero    : !block_target.IsNull() — the block target is set.
//
// With no measured hashrate (real_pool_hs <= 0) there is nothing to divide by, so
// the caller never enters this path and etb stays 0; the same guard here keeps
// the function standalone-safe (never divides by zero). When the average-attempts
// count overflows uint64 but the target is genuinely non-null, the low64 division
// would yield a bogus tiny number, so a 1e18 sentinel is reported instead —
// matching the inline guard in node.cpp's diagnostics loop.
inline double compute_expected_time_to_block(double average_attempts,
                                             double real_pool_hs,
                                             bool average_attempts_overflowed,
                                             bool block_target_nonzero) {
    if (real_pool_hs <= 0.0)
        return 0.0;
    double etb_secs = average_attempts / real_pool_hs;
    if (average_attempts_overflowed && block_target_nonzero)
        etb_secs = 1e18;
    return etb_secs;
}

} // namespace dgb