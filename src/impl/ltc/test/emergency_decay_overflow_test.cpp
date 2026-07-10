// SPDX-License-Identifier: AGPL-3.0-or-later
// Conformance KAT — death-spiral emergency-decay uint256 overflow.
//
// Guards ltc::ShareTracker::emergency_decay_shl (Step 3 of
// compute_share_target, src/impl/ltc/share_tracker.hpp).
//
// REGRESSION: the emergency time-based decay used a bare `prev << halvings`
// on a 256-bit target. With a large prev (MAX_TARGET is 2^236-1 on mainnet)
// and a multi-window share gap, the shift overflows 256 bits and WRAPS to a
// tiny value — i.e. a HARDER target — which accelerates the very death
// spiral the decay exists to arrest. The old `halvings < 256` guard only
// bounded the shift width, never the magnitude. The fix saturates to
// max_target on overflow.
//
// CORE INVARIANT: emergency decay only ever EASES (target non-decreasing).
// A wrapped result would be strictly LESS than prev — that is exactly what
// each ASSERT_GE below catches.
//
// Standardized fix shape — DGB and BTC carry the identical helper and an
// equivalent KAT (per-coin fenced PRs, same arithmetic).

#include <gtest/gtest.h>

#include <impl/ltc/config_pool.hpp>
#include <impl/ltc/share_tracker.hpp>

using ltc::ShareTracker;

namespace {

uint256 hex(const char* h) { uint256 v; v.SetHex(h); return v; }

// mainnet share-difficulty floor: 2^236 - 1  (59 hex 'f's)
const uint256 MAX_T = hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

} // namespace

TEST(EmergencyDecayOverflow, ShiftZeroIsIdentity)
{
    uint256 prev = hex("1000000000000000000000000000000000000000000000000000000000");
    EXPECT_EQ(ShareTracker::emergency_decay_shl(prev, 0, MAX_T), prev);
}

TEST(EmergencyDecayOverflow, SmallShiftWithinHeadroomIsExact)
{
    uint256 prev = uint256(1);
    uint256 r = ShareTracker::emergency_decay_shl(prev, 8, MAX_T);
    EXPECT_EQ(r, uint256(256));   // 1 << 8
    EXPECT_TRUE(r <= MAX_T);
    EXPECT_TRUE(r >= prev);
}

// The regression: a large prev shifted past the 256-bit boundary must
// saturate to MAX_T, NOT wrap to a small value.
TEST(EmergencyDecayOverflow, LargeShiftSaturatesNoWrap)
{
    uint256 prev = MAX_T;                 // already at the ceiling
    for (unsigned int shift : {1u, 8u, 32u, 64u, 200u, 255u, 256u, 1000u})
    {
        uint256 r = ShareTracker::emergency_decay_shl(prev, shift, MAX_T);
        EXPECT_EQ(r, MAX_T) << "shift=" << shift << " did not saturate";
        EXPECT_TRUE(r >= prev) << "shift=" << shift << " eased target SHRANK (wrap)";
    }
}

// prev just below the ceiling: any shift >= 1 overflows and must saturate.
TEST(EmergencyDecayOverflow, NearCeilingSaturates)
{
    uint256 prev = hex("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~2^232
    uint256 r1 = ShareTracker::emergency_decay_shl(prev, 4, MAX_T);   // 2^236-ish -> over
    EXPECT_EQ(r1, MAX_T);
    EXPECT_TRUE(r1 >= prev);
    // shift of 3 still fits under 2^236 -> exact, no saturation
    uint256 r2 = ShareTracker::emergency_decay_shl(prev, 3, MAX_T);
    EXPECT_TRUE(r2 <= MAX_T);
    EXPECT_TRUE(r2 >= prev);
}

// General monotonicity sweep: for prev <= max, decay never produces a
// smaller target at any shift.
TEST(EmergencyDecayOverflow, NeverDecreasesTarget)
{
    const uint256 prevs[] = {
        uint256(1),
        hex("100000000000000000000000000000"),
        hex("1000000000000000000000000000000000000000000000000000000000"),
        MAX_T,
    };
    for (const auto& prev : prevs)
        for (unsigned int shift = 0; shift <= 260; ++shift)
        {
            uint256 r = ShareTracker::emergency_decay_shl(prev, shift, MAX_T);
            ASSERT_TRUE(r >= prev)  << "prev=" << prev.GetHex() << " shift=" << shift;
            ASSERT_TRUE(r <= MAX_T) << "prev=" << prev.GetHex() << " shift=" << shift;
        }
}