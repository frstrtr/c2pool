// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// The DGB stratum start difficulty (VARDIFF item 2; kr1z1s p2pool-dgb-scrypt
// work.py get_work, the pseudoshare target of a job before any vardiff):
//   - with a node hash rate (attempts/s): average_attempts_to_target(rate /
//     10): no more than ~10 pseudoshares a second node-wide;
//   - else 3000 x the dust target: average_attempts_to_target(attempts(block)
//     * SPREAD * DUST_THRESHOLD / subsidy) * 3000 ("1/3000th the difficulty
//     of a full share");
//   - a difficulty >= 4 is rounded down to a power of two (2^2 .. 2^32);
//   - the target is clipped to SANE_TARGET_RANGE (2**256//1e11 - 1,
//     2**256//1000 - 1).
// Returned as an INTERNAL (p2pool) difficulty, the units of the stratum
// difficulty hint. Node-local (pseudoshares only), so doubles suffice.
// ---------------------------------------------------------------------------

#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <cmath>
#include <cstdint>

namespace dgb {

inline double dgb_start_difficulty(double node_rate, uint32_t block_bits, uint64_t subsidy,
                                   uint32_t spread, uint64_t dust_threshold)
{
    const double two_256 = std::ldexp(1.0, 256);
    const double diff1 = static_cast<double>(0xffff0000u) * std::ldexp(1.0, 192);   // difficulty-1 target
    double target = two_256;
    if (node_rate > 0.0) {
        target = std::min(target, two_256 / (node_rate / 10.0));
    } else {
        if (block_bits == 0 || subsidy == 0)
            return 0.0;
        const double block_target = chain::bits_to_target(block_bits).getdouble();
        const double block_att = two_256 / (block_target + 1.0);
        const double dust_att = block_att * spread * static_cast<double>(dust_threshold) / static_cast<double>(subsidy);
        if (!(dust_att > 0.0))
            return 0.0;
        target = std::min(target, 3000.0 * (two_256 / dust_att));
    }
    const double td = diff1 / target;
    for (int i = 32; i > 1; --i)
        if (td >= std::ldexp(1.0, i)) {
            target = diff1 / std::ldexp(1.0, i);
            break;
        }
    target = std::max(target, two_256 / 1e11);
    target = std::min(target, two_256 / 1000.0);
    return diff1 / target;
}

} // namespace dgb
