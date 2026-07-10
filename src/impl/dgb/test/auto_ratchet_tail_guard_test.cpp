// SPDX-License-Identifier: AGPL-3.0-or-later
// dgb_auto_ratchet_tail_guard_test: FENCED, additive conformance KAT for the
// AutoRatchet WORK-WEIGHTED 60% tail guard SSOT (auto_ratchet_tail_guard.hpp).
//
// Pins the canonical p2pool-dgb-scrypt switch rule (data.py:1399):
//   SWITCHED iff target_weight >= floor(total_weight * 60 / 100),
// over uint288 work-weight accumulators, NON-CIRCULARLY (hand-derived oracle
// values, plus a verbatim replica of the live inline expression to localise
// the one floor-boundary divergence documented in the SSOT header).
//
// auto_ratchet.hpp consensus path is NOT exercised here -- this is a pure
// arithmetic pin of the lifted SSOT. Test-only / dgb-tree-local.

#include <gtest/gtest.h>

#include <impl/dgb/auto_ratchet_tail_guard.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <map>
#include <utility>

using dgb::auto_ratchet::reduce_target_total;
using dgb::auto_ratchet::switched;
using dgb::auto_ratchet::tail_guard_passes;

namespace {

// Verbatim replica of the LIVE inline expression in
// AutoRatchet::get_share_version: tail_ok = !(target*100 < total*60).
// Kept here so the boundary tests below compare SSOT-canonical-floor against
// the inline exact-rational form WITHOUT importing the consensus header.
bool inline_tail_ok(const uint288& target, const uint288& total, int thr = 60)
{
    return !((target * static_cast<uint32_t>(100)) <
             (total  * static_cast<uint32_t>(thr)));
}

} // namespace

// --- reduce_target_total mirrors the inline accumulation -------------------
TEST(AutoRatchetTailGuard, ReduceSplitsAtTargetVersion)
{
    std::map<uint64_t, uint288> w{
        {34, uint288(5)},   // below target -> total only
        {35, uint288(7)},   // below target -> total only
        {36, uint288(11)},  // >= target    -> target + total
        {37, uint288(13)},  // >= target    -> target + total
    };
    auto tt = reduce_target_total(w, /*target_version=*/36);
    EXPECT_EQ(tt.first,  uint288(24));  // 11 + 13
    EXPECT_EQ(tt.second, uint288(36));  // 5 + 7 + 11 + 13
}

TEST(AutoRatchetTailGuard, EmptyMapIsZeroZero)
{
    std::map<uint64_t, uint288> w;
    auto tt = reduce_target_total(w, 36);
    EXPECT_EQ(tt.first,  uint288(0));
    EXPECT_EQ(tt.second, uint288(0));
}

// --- canonical floor switch gate (oracle data.py:1399) ---------------------
TEST(AutoRatchetTailGuard, SwitchedHonoursSixtyPercentFloor)
{
    // total=100 -> floor(100*60/100)=60. SWITCHED iff target >= 60.
    EXPECT_FALSE(switched(uint288(59),  uint288(100)));
    EXPECT_TRUE (switched(uint288(60),  uint288(100)));
    EXPECT_TRUE (switched(uint288(61),  uint288(100)));
    EXPECT_TRUE (switched(uint288(100), uint288(100)));
}

TEST(AutoRatchetTailGuard, AllOldNeverSwitches)
{
    // No V>=target work at all: target=0, gate=floor(total*60/100) >= 1 for
    // any total>=2 -> never switched.
    EXPECT_FALSE(switched(uint288(0), uint288(2)));
    EXPECT_FALSE(switched(uint288(0), uint288(1000)));
}

TEST(AutoRatchetTailGuard, ZeroTotalSwitches)
{
    // Empty window: gate=floor(0)=0, target=0 >= 0 -> vacuously switched.
    // Matches p2pool: 0 < 0 is False, so it does NOT stay on old format.
    EXPECT_TRUE(switched(uint288(0), uint288(0)));
}

// --- non-circular boundary: SSOT floor vs live inline exact-rational -------
// Demonstrates the SOLE divergence documented in the SSOT header:
// target == floor(total*60/100) AND (total*60) % 100 != 0.
// total=7: total*60=420, floor(420/100)=4.
//   SSOT canonical : target>=4 -> SWITCHED at target==4.
//   live inline     : 4*100=400 < 420 -> tail_ok=false (NOT switched) at 4.
TEST(AutoRatchetTailGuard, FloorBoundaryDivergesFromInlineByOneQuantum)
{
    const uint288 total(7);

    // Below the floor: both agree -> not switched.
    EXPECT_FALSE(switched(uint288(3), total));
    EXPECT_FALSE(inline_tail_ok(uint288(3), total));

    // AT the floor (=4): SSOT switches, inline still waits. The documented
    // off-by-one-quantum divergence, pinned so a future delegation is a
    // deliberate, reviewed change rather than a silent flip.
    EXPECT_TRUE (switched(uint288(4), total));        // canonical: 4 >= floor(4.2)=4
    EXPECT_FALSE(inline_tail_ok(uint288(4), total));  // inline:    400 < 420

    // Above the floor: both agree -> switched / tail_ok.
    EXPECT_TRUE(switched(uint288(5), total));
    EXPECT_TRUE(inline_tail_ok(uint288(5), total));
}

// Where (total*60) % 100 == 0 the floor is exact and the two forms AGREE for
// every target -> the divergence really is confined to the non-exact case.
TEST(AutoRatchetTailGuard, ExactFloorAgreesWithInline)
{
    const uint288 total(100);  // 100*60=6000, divisible by 100, floor exact.
    for (uint32_t t = 55; t <= 65; ++t) {
        const uint288 target(t);
        EXPECT_EQ(switched(target, total), inline_tail_ok(target, total))
            << "target=" << t;
    }
}

// --- tail_guard_passes end-to-end over a weight map ------------------------
TEST(AutoRatchetTailGuard, TailGuardPassesOnWorkWeightedMajority)
{
    // 70 work-units vote V36, 30 vote V35 -> 70 >= floor(100*60/100)=60 -> pass.
    std::map<uint64_t, uint288> pass{{35, uint288(30)}, {36, uint288(70)}};
    EXPECT_TRUE(tail_guard_passes(pass, 36));

    // 55 vote V36, 45 vote V35 -> 55 < 60 -> guard holds (do NOT activate).
    std::map<uint64_t, uint288> wait{{35, uint288(45)}, {36, uint288(55)}};
    EXPECT_FALSE(tail_guard_passes(wait, 36));
}

// Large uint288 work weights (realistic target_to_average_attempts scale):
// SSOT and inline agree -- the boundary case is measure-zero in practice.
TEST(AutoRatchetTailGuard, LargeWeightsAgreeWithInline)
{
    const uint288 big = uint288(uint64_t(1) << 40);     // ~1.1e12 work-units
    const uint288 total = big * static_cast<uint32_t>(100);
    for (uint32_t pct : {0u, 1u, 59u, 60u, 61u, 99u, 100u}) {
        const uint288 target = big * pct;
        EXPECT_EQ(switched(target, total), inline_tail_ok(target, total))
            << "pct=" << pct;
    }
}