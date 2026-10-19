// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The 60%-by-work version-switch accept predicate that bch::check_share applies
// to an upgrade boundary share (share.version == parent.version + 1). Lifted out
// of share_check.hpp so the exact rounding can be pinned by a pure KAT
// (test/version_switch_floor_kat_test.cpp).
//
// Oracle (p2pool-merged-v36 data.py check()):
//
//     if counts.get(self.VERSION, 0) < sum(counts.itervalues())*60//100:
//         raise p2p.PeerMisbehavingError('switch without enough hash power upgraded')
//
// The threshold is FLOORED (Python //) before the comparison. The previous
// inline form `new_ver_weight*100 < total_weight*60` compares against the exact
// rational 0.6*T instead, so when 0.6*T is not a whole number and
// new_ver_weight == floor(0.6*T) it rejected a share the oracle admits.
//
// Overflow: total_weight is a sum of target_to_average_attempts (each < 2^257)
// over at most CHAIN_LENGTH/10 shares, so total_weight*60 stays far below 2^288.
//
// Empty window (total_weight == 0) evaluates 0 < 0 == false -> admitted, same as
// the oracle. Hardening that is a v37 change (#906), not a v36 one.

#pragma once

#include <cstdint>

#include <core/uint256.hpp>   // uint288

namespace bch {

// true  <=> the boundary share must be REJECTED ("switch without enough hash
// power upgraded"): the desiring weight is below floor(total_weight*60/100).
inline bool version_switch_underweight(const uint288& new_ver_weight,
                                       const uint288& total_weight)
{
    const uint288 threshold = (total_weight * static_cast<uint32_t>(60)) / uint288(100);
    return new_ver_weight < threshold;
}

} // namespace bch
