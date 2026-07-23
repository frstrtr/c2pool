// ltc_auto_ratchet_tail_guard_test: FENCED, additive conformance KATs for the
// AutoRatchet WORK-WEIGHTED 60% tail guard, ported from the dgb boundary suite
// (src/impl/dgb/test/auto_ratchet_tail_guard_test.cpp) to fill the LTC unit
// coverage gap. LTC already has the staged-migration integration sim
// (auto_ratchet_sim_test.cpp) and the desired-version tally KATs
// (desired_version_tally_test.cpp); this file adds the focused *arithmetic*
// boundary pins those two do not carry.
//
// Unlike dgb, LTC has NO lifted auto_ratchet_tail_guard.hpp SSOT header: the
// tail guard is the INLINE expression in AutoRatchet::get_share_version
// (auto_ratchet.hpp:171):
//
//     tail_ok = !(tail_target * uint32_t(100) < tail_total * uint32_t(SWITCH))
//
// which is the EXACT-RATIONAL test  target < total*60/100. These KATs pin that
// LIVE inline form NON-CIRCULARLY, against (a) hand-derived oracle values and
// (b) an independent replica of the p2pool canonical FLOOR rule
// (data.py:1399): SWITCHED iff target >= floor(total*60/100). The two forms
// diverge in exactly one documented case -- target == floor(total*60/100) with
// (total*60) % 100 != 0 -- where the LTC inline waits one extra work-quantum
// (negligibly STRICTER). The FloorBoundary / ExactFloor / LargeWeights cases
// are the point of the port: they catch quantization / uint288 overflow bugs.
//
// The consensus path is NOT exercised here -- this is a pure arithmetic pin of
// the live inline rule. Test-only / ltc-tree-local. Joins the share_test
// executable (already on the build.yml --target allowlist).

#include <gtest/gtest.h>

#include <impl/ltc/auto_ratchet.hpp>   // ltc::AutoRatchet::SWITCH_THRESHOLD
#include <core/uint256.hpp>            // uint288 work-weight accumulator

#include <cstdint>
#include <map>
#include <utility>

using ltc::AutoRatchet;

namespace {

// Verbatim replica of the LIVE inline work-weighted tail guard in
// AutoRatchet::get_share_version (auto_ratchet.hpp:171):
//   tail_ok = !(tail_target * uint32_t(100) < tail_total * uint32_t(SWITCH));
// This is LTC's REAL consensus rule (EXACT-RATIONAL form). Kept local so the
// boundary tests pin the inline split WITHOUT driving the consensus path or
// importing a lifted SSOT. uint288 = work-weight accumulator.
bool inline_tail_ok(const uint288& target, const uint288& total,
                    int thr = AutoRatchet::SWITCH_THRESHOLD)
{
    return !((target * static_cast<uint32_t>(100)) <
             (total  * static_cast<uint32_t>(thr)));
}

// Independent replica of the p2pool CANONICAL switch oracle (data.py:1399)
// with EXACT FLOOR semantics: SWITCHED iff target >= floor(total*thr/100).
// This is NOT what LTC runs -- it is the reference the live inline form is
// pinned against, so the one-quantum divergence is localised deliberately.
bool canonical_floor_switched(const uint288& target, const uint288& total,
                              int thr = AutoRatchet::SWITCH_THRESHOLD)
{
    // floor(total * thr / 100) on the unsigned work accumulator. base_uint
    // multiply takes uint32_t; divide takes W, so wrap 100 in uint288.
    const uint288 floor_gate =
        (total * static_cast<uint32_t>(thr)) / uint288(static_cast<uint64_t>(100));
    return !(target < floor_gate);
}

// Mirror of the LTC inline accumulation loop (auto_ratchet.hpp:164-169):
// reduce a desired-version -> work-weight map into {weight voting >= target,
// total weight}. uint288 default-initialises to 0; the sum is order-independent.
std::pair<uint288, uint288>
reduce_target_total(const std::map<uint64_t, uint288>& weights,
                    int64_t target_version)
{
    uint288 target{}, total{};
    for (const auto& [ver, w] : weights) {
        total = total + w;
        if (static_cast<int64_t>(ver) >= target_version)
            target = target + w;
    }
    return {target, total};
}

// LTC end-to-end tail guard over a weight map: reduce, then apply the LIVE
// inline rule (NOT the floor oracle -- this is what the pool actually runs).
bool tail_guard_passes(const std::map<uint64_t, uint288>& weights,
                       int64_t target_version)
{
    const auto tt = reduce_target_total(weights, target_version);
    return inline_tail_ok(tt.first, tt.second);
}

} // namespace

// --- reduce_target_total mirrors the inline accumulation -------------------
TEST(LtcAutoRatchetTailGuard, ReduceSplitsAtTargetVersion)
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

TEST(LtcAutoRatchetTailGuard, EmptyMapIsZeroZero)
{
    std::map<uint64_t, uint288> w;
    auto tt = reduce_target_total(w, 36);
    EXPECT_EQ(tt.first,  uint288(0));
    EXPECT_EQ(tt.second, uint288(0));
}

// --- 60%-by-WORK gate at an EXACT floor (total=100) ------------------------
TEST(LtcAutoRatchetTailGuard, SwitchedHonoursSixtyPercentFloor)
{
    // total=100 -> floor(100*60/100)=60. Exact floor: inline == canonical.
    const uint288 total(100);
    EXPECT_FALSE(inline_tail_ok(uint288(59),  total));
    EXPECT_TRUE (inline_tail_ok(uint288(60),  total));
    EXPECT_TRUE (inline_tail_ok(uint288(61),  total));
    EXPECT_TRUE (inline_tail_ok(uint288(100), total));
    // Independent floor oracle agrees at every one of these points.
    EXPECT_EQ(canonical_floor_switched(uint288(59),  total), inline_tail_ok(uint288(59),  total));
    EXPECT_EQ(canonical_floor_switched(uint288(60),  total), inline_tail_ok(uint288(60),  total));
    EXPECT_EQ(canonical_floor_switched(uint288(100), total), inline_tail_ok(uint288(100), total));
}

TEST(LtcAutoRatchetTailGuard, AllOldNeverSwitches)
{
    // No V>=target work at all: target=0 -> target*100=0 < total*60 for any
    // total>=1 -> inline holds (never passes the gate).
    EXPECT_FALSE(inline_tail_ok(uint288(0), uint288(2)));
    EXPECT_FALSE(inline_tail_ok(uint288(0), uint288(1000)));
}

TEST(LtcAutoRatchetTailGuard, ZeroTotalSwitches)
{
    // Empty window: 0*100 < 0*60 is False, so !False = tail_ok=true. The guard
    // is vacuously satisfied (matches p2pool: 0 < 0 is False -> not "old").
    EXPECT_TRUE(inline_tail_ok(uint288(0), uint288(0)));
    EXPECT_TRUE(canonical_floor_switched(uint288(0), uint288(0)));
}

// --- non-circular boundary: LTC live inline vs canonical FLOOR oracle -------
// The SOLE divergence: target == floor(total*60/100) AND (total*60) % 100 != 0.
// total=7: total*60=420, floor(420/100)=4.
//   canonical floor : target>=4 -> SWITCHED at target==4.
//   LTC live inline  : 4*100=400 < 420 -> tail_ok=false (waits) at 4.
// LTC runs the inline form, so LTC is STRICTER by one work-quantum here. Pinned
// so a future byte-faithful rewrite is a deliberate, reviewed change.
TEST(LtcAutoRatchetTailGuard, FloorBoundaryDivergesFromInlineByOneQuantum)
{
    const uint288 total(7);

    // Below the floor: both agree -> not switched.
    EXPECT_FALSE(canonical_floor_switched(uint288(3), total));
    EXPECT_FALSE(inline_tail_ok(uint288(3), total));

    // AT the floor (=4): canonical switches, LTC inline still waits.
    EXPECT_TRUE (canonical_floor_switched(uint288(4), total));  // 4 >= floor(4.2)=4
    EXPECT_FALSE(inline_tail_ok(uint288(4), total));            // 400 < 420

    // Above the floor: both agree -> switched / tail_ok.
    EXPECT_TRUE(canonical_floor_switched(uint288(5), total));
    EXPECT_TRUE(inline_tail_ok(uint288(5), total));
}

// Where (total*60) % 100 == 0 the floor is exact and the two forms AGREE for
// every target -> the divergence really is confined to the non-exact case.
TEST(LtcAutoRatchetTailGuard, ExactFloorAgreesWithInline)
{
    const uint288 total(100);  // 100*60=6000, divisible by 100, floor exact.
    for (uint32_t t = 55; t <= 65; ++t) {
        const uint288 target(t);
        EXPECT_EQ(canonical_floor_switched(target, total), inline_tail_ok(target, total))
            << "target=" << t;
    }
}

// --- tail_guard_passes end-to-end over a weight map (LTC live rule) ---------
TEST(LtcAutoRatchetTailGuard, TailGuardPassesOnWorkWeightedMajority)
{
    // 70 work-units vote V36, 30 vote V35 -> 70*100 >= 100*60 -> pass.
    std::map<uint64_t, uint288> pass{{35, uint288(30)}, {36, uint288(70)}};
    EXPECT_TRUE(tail_guard_passes(pass, 36));

    // 55 vote V36, 45 vote V35 -> 5500 < 6000 -> guard holds (do NOT activate).
    std::map<uint64_t, uint288> wait{{35, uint288(45)}, {36, uint288(55)}};
    EXPECT_FALSE(tail_guard_passes(wait, 36));
}

// Large uint288 work weights (realistic target_to_average_attempts scale):
// canonical floor and LTC inline agree -- the boundary case is measure-zero in
// practice, and this exercises the multiply/divide path against overflow.
TEST(LtcAutoRatchetTailGuard, LargeWeightsAgreeWithInline)
{
    const uint288 big = uint288(uint64_t(1) << 40);     // ~1.1e12 work-units
    const uint288 total = big * static_cast<uint32_t>(100);
    for (uint32_t pct : {0u, 1u, 59u, 60u, 61u, 99u, 100u}) {
        const uint288 target = big * pct;
        EXPECT_EQ(canonical_floor_switched(target, total), inline_tail_ok(target, total))
            << "pct=" << pct;
    }
}
