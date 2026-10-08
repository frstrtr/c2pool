// SPDX-License-Identifier: AGPL-3.0-or-later
// Conformance KAT: version-switch 60% gate rounding (ltc::version_switch_underweight).
//
// The oracle (p2pool-merged-v36 data.py) rejects an upgrade share when
//   counts.get(self.VERSION, 0) < sum(counts.itervalues())*60//100
// i.e. the threshold is FLOOR(total*60/100). The previous c2pool form,
// new*100 < total*60, is a strict real-number 60% test: whenever 60*total is
// not a multiple of 100 it rejected new == floor(0.6*total), which the oracle
// accepts. The share is then valid on p2pool and invalid on c2pool, at every
// version switch.
//
// Three boundary cases:
//   1. 60*T not a multiple of 100 (small T): floor(0.6T) is ACCEPTED (RED on
//      the old form), floor(0.6T)-1 is rejected.
//   2. 60*T a multiple of 100: 0.6T accepted, 0.6T-1 rejected. Both forms
//      agree here; the fix must not move this boundary.
//   3. Case 1 at real 288-bit work-sum magnitude (T = 2^250 + 12345).

#include <gtest/gtest.h>

#include <impl/ltc/share_check.hpp>

namespace {

uint288 hex288(const char* h) { uint288 v; v.SetHex(h); return v; }

// The pre-fix expression, kept only to prove case 1 is RED on it.
bool old_cross_multiply_reject(const uint288& a, const uint288& t)
{
    return a * uint32_t(100) < t * uint32_t(60);
}

} // namespace

TEST(VersionSwitchFloor, NonMultipleBoundaryAcceptsFloor)
{
    const uint288 T(7);            // 60*7 = 420, floor(4.2) = 4
    EXPECT_FALSE(ltc::version_switch_underweight(uint288(4), T));
    EXPECT_TRUE(ltc::version_switch_underweight(uint288(3), T));
    // Divergence pin: the old form rejected the oracle-valid share.
    EXPECT_TRUE(old_cross_multiply_reject(uint288(4), T));
}

TEST(VersionSwitchFloor, ExactMultipleBoundaryUnchanged)
{
    const uint288 T(10);           // 60*10 = 600, threshold exactly 6
    EXPECT_FALSE(ltc::version_switch_underweight(uint288(6), T));
    EXPECT_TRUE(ltc::version_switch_underweight(uint288(5), T));
    EXPECT_FALSE(old_cross_multiply_reject(uint288(6), T));
    EXPECT_TRUE(old_cross_multiply_reject(uint288(5), T));
}

TEST(VersionSwitchFloor, WorkScaleBoundaryAcceptsFloor)
{
    // T = 2^250 + 12345; 60*T mod 100 = 40. Constants from Python:
    //   T*60//100 and T*60//100 - 1
    const uint288 T     = hex288("400000000000000000000000000000000000000000000000000000000003039");
    const uint288 floor = hex288("266666666666666666666666666666666666666666666666666666666668355");
    const uint288 below = hex288("266666666666666666666666666666666666666666666666666666666668354");
    EXPECT_FALSE(ltc::version_switch_underweight(floor, T));
    EXPECT_TRUE(ltc::version_switch_underweight(below, T));
    EXPECT_TRUE(old_cross_multiply_reject(floor, T));
}
