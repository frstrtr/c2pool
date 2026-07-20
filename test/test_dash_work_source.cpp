// SPDX-License-Identifier: AGPL-3.0-or-later
///
/// KAT for dash::coin::select_dash_work — the embedded-vs-dashd work-source
/// selector (S8 embedded_gbt live-wire capstone). Proves the routing contract
/// and the RETAINED dashd fallback, without a live daemon or a populated
/// MN/mempool harness (the embedded builder is injected as a stub; its
/// oracle-parity output is already pinned by test_dash_embedded_gbt).
///
/// Contract under test:
///   1. viable() bundle          -> WorkSource::Embedded, embedded builder run,
///                                  fallback NEVER touched.
///   2. has_state=false          -> WorkSource::DashdFallback, fallback run.
///   3. viable but null mnstates -> fallback (defensive null-guard).
///   4. viable but null mempool  -> fallback (defensive null-guard).

#include <impl/dash/coin/work_source.hpp>
#include <c2pool/hashrate/tracker.hpp>

#include <cmath>

#include <gtest/gtest.h>

using dash::coin::EmbeddedWorkInputs;
using dash::coin::WorkSource;
using dash::coin::WorkSelection;
using dash::coin::select_dash_work;
using dash::coin::DashWorkData;
using dash::coin::MnStateMachine;
using dash::coin::Mempool;

namespace {

// Distinguishable sentinels so we can prove WHICH closure produced the result.
constexpr uint32_t EMB_SENTINEL_HEIGHT  = 0xE3BEDDEDu & 0xffffffu;  // "embedded"
constexpr uint32_t DASHD_SENTINEL_HEIGHT = 999'999u;

DashWorkData embedded_stub(bool& ran) {
    ran = true;
    DashWorkData w;
    w.m_height = EMB_SENTINEL_HEIGHT;
    return w;
}

DashWorkData dashd_stub(bool& ran) {
    ran = true;
    DashWorkData w;
    w.m_height = DASHD_SENTINEL_HEIGHT;
    return w;
}

} // namespace

// 1) Viable bundle routes to the EMBEDDED builder; fallback is not invoked.
TEST(DashWorkSource, ViableRoutesEmbedded)
{
    MnStateMachine mn;
    Mempool mp;
    EmbeddedWorkInputs emb;
    emb.has_state = true;
    emb.mnstates  = &mn;
    emb.mempool   = &mp;
    ASSERT_TRUE(emb.viable());

    bool emb_ran = false, fb_ran = false;
    WorkSelection sel = select_dash_work(
        emb,
        [&] { return embedded_stub(emb_ran); },
        [&] { return dashd_stub(fb_ran); });

    EXPECT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_TRUE(emb_ran);
    EXPECT_FALSE(fb_ran);
    EXPECT_EQ(sel.work.m_height, EMB_SENTINEL_HEIGHT);
}

// 2) No embedded state -> the RETAINED dashd getblocktemplate fallback runs.
TEST(DashWorkSource, NoStateRoutesDashdFallback)
{
    EmbeddedWorkInputs emb;        // has_state defaults false
    ASSERT_FALSE(emb.viable());

    bool emb_ran = false, fb_ran = false;
    WorkSelection sel = select_dash_work(
        emb,
        [&] { return embedded_stub(emb_ran); },
        [&] { return dashd_stub(fb_ran); });

    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_FALSE(emb_ran);
    EXPECT_TRUE(fb_ran);
    EXPECT_EQ(sel.work.m_height, DASHD_SENTINEL_HEIGHT);
}

// 3) has_state true but mnstates null -> not viable -> fallback (null-guard).
TEST(DashWorkSource, NullMnStatesRoutesFallback)
{
    Mempool mp;
    EmbeddedWorkInputs emb;
    emb.has_state = true;
    emb.mnstates  = nullptr;
    emb.mempool   = &mp;
    EXPECT_FALSE(emb.viable());

    bool emb_ran = false, fb_ran = false;
    WorkSelection sel = select_dash_work(
        emb,
        [&] { return embedded_stub(emb_ran); },
        [&] { return dashd_stub(fb_ran); });

    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_FALSE(emb_ran);
    EXPECT_TRUE(fb_ran);
}

// 4) has_state true but mempool null -> not viable -> fallback (null-guard).
TEST(DashWorkSource, NullMempoolRoutesFallback)
{
    MnStateMachine mn;
    EmbeddedWorkInputs emb;
    emb.has_state = true;
    emb.mnstates  = &mn;
    emb.mempool   = nullptr;
    EXPECT_FALSE(emb.viable());

    bool emb_ran = false, fb_ran = false;
    WorkSelection sel = select_dash_work(
        emb,
        [&] { return embedded_stub(emb_ran); },
        [&] { return dashd_stub(fb_ran); });

    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_FALSE(emb_ran);
    EXPECT_TRUE(fb_ran);
}

// ─── Firmware-grid vardiff quantization KAT (retention fix) ──────────────────
// HashrateTracker::set_difficulty_from_hashrate must advertise ONLY power-of-two
// difficulties, rounded DOWN from the estimator's ideal D. Many ASIC firmwares
// round the advertised pool difficulty down to a power-of-two grid, mine that
// easier target, and submit shares the pool's exact (higher) required difficulty
// silently rejects. Advertising the largest power of two <= D makes
// advertised == applied == required, and rounding DOWN keeps the accepted-share
// cadence at or above target. Driven purely through the public API.
namespace {
// Oracle mirroring the documented estimator (port of p2pool-dash work.py):
//   D_ideal = ewma_work * target / norm,  norm = tau*(1 - exp(-2*target/tau))
// with all accepted shares recorded in the same wall-second (decay ~ 1), so
// ewma_work == N*share_diff and the bias-corrected age floors at 2*target.
double ideal_D(int n, double share_diff, double target, double tau) {
    const double norm = tau * (1.0 - std::exp(-2.0 * target / tau));
    return static_cast<double>(n) * share_diff * target / norm;
}
bool is_power_of_two(double d) {
    if (!(d > 0.0)) return false;
    const double l = std::log2(d);
    return std::abs(l - std::floor(l)) < 1e-9;
}
} // namespace

TEST(HashrateVardiffQuantize, AdvertisesPowerOfTwoRoundedDown)
{
    constexpr double kTarget = 10.0;   // set_target_time_per_mining_share
    constexpr double kTau    = 90.0;   // vardiff_ewma_tau_ (fixed default)
    constexpr int    kShares = 15;     // > warmup (4)
    constexpr double kDiff   = 12.0;   // per accepted-share issued difficulty

    c2pool::hashrate::HashrateTracker t;
    t.set_difficulty_bounds(0.0005, 1e9);   // wide: exercise quantization, not clamp
    t.set_target_time_per_mining_share(kTarget);
    t.set_hashrate_vardiff(true);
    t.enable_vardiff(true);

    for (int i = 0; i < kShares; ++i)
        t.record_mining_share_submission(kDiff, /*accepted=*/true);

    const double q = t.get_current_difficulty();
    const double D = ideal_D(kShares, kDiff, kTarget, kTau);

    // (1) Advertised value is an exact power of two (timing-independent).
    EXPECT_TRUE(is_power_of_two(q)) << "advertised diff not power-of-two: " << q;
    // (2) Rounds DOWN — never advertise more than the estimator's ideal D.
    EXPECT_LE(q, D) << "advertised " << q << " exceeds ideal D " << D;
    // (3) It is THE largest such power of two (down one step, not two): 2q > D.
    EXPECT_GT(2.0 * q, D) << "advertised " << q << " rounded down too far vs D " << D;
}

// Floor-pinned KAT (F-1 regression): when a rig slows so far that the estimator's
// ideal D falls BELOW min_difficulty_, the [min,max] clamp pins the raw diff at the
// floor. DASH's min_difficulty_ (0.0005) is NOT itself on the power-of-two grid, so
// the pre-fix re-floor (max(min_difficulty_, d)) advertised the raw 0.0005 and
// re-opened the firmware reject gap at the floor. Post-fix the advertised value must
// STILL be an exact power of two: the largest grid step <= the floor (0.00048828125),
// i.e. at most one step below the configured floor, preserving the round-DOWN cadence.
// This assertion would FAIL pre-fix. A prior higher diff is seeded via the hint so the
// small (~2.3%) floor correction is not swallowed by the vardiff dead-band — this is
// the realistic path (a rig that had been faster and then slowed below the floor).
TEST(HashrateVardiffQuantize, FloorPinnedAdvertiseIsPowerOfTwo)
{
    constexpr double kTarget = 10.0;
    constexpr double kTau    = 90.0;
    constexpr int    kShares = 15;      // > warmup (4)
    constexpr double kFloor  = 0.0005;  // DASH min_difficulty_ (not a power of two)
    constexpr double kDiff   = 1e-5;    // tiny issued diff => ideal D below the floor

    c2pool::hashrate::HashrateTracker t;
    t.set_difficulty_bounds(kFloor, 1e9);
    t.set_target_time_per_mining_share(kTarget);
    t.set_hashrate_vardiff(true);
    t.enable_vardiff(true);
    // Rig was previously running well above the floor; the slow-down below the floor
    // is what the fix must quantize (also keeps the correction outside the dead-band).
    t.set_difficulty_hint(0.01);

    for (int i = 0; i < kShares; ++i)
        t.record_mining_share_submission(kDiff, /*accepted=*/true);

    const double q = t.get_current_difficulty();
    const double D = ideal_D(kShares, kDiff, kTarget, kTau);

    // Precondition: this really is the floor-pinned regime (ideal D below the floor).
    ASSERT_LT(D, kFloor) << "test mis-scaled: ideal D " << D << " not below floor";

    // (1) Advertised value is an exact power of two even when floor-pinned
    //     (pre-fix advertised the raw 0.0005 here and FAILED this assertion).
    EXPECT_TRUE(is_power_of_two(q)) << "floor-pinned advertise not power-of-two: " << q;
    // (2) It is the largest power of two <= the configured floor: one grid step below
    //     0.0005 (0.00048828125), never rounding down more than a single step.
    EXPECT_EQ(q, std::exp2(std::floor(std::log2(kFloor))));
    EXPECT_LE(q, kFloor);
    EXPECT_GT(2.0 * q, kFloor) << "floor-pinned advertise " << q << " rounded down too far";
}

TEST(HashrateVardiffQuantize, QuantizationFormulaIsFloorLog2)
{
    // Pure-math intent check: for any ideal D, the advertised value is the
    // largest power of two not exceeding D  (floor on the log2 grid).
    for (double D : {0.75, 1.0, 1.5, 3.0, 63.9, 64.0, 100.4, 65535.0}) {
        const double q = std::exp2(std::floor(std::log2(D)));
        EXPECT_TRUE(is_power_of_two(q));
        EXPECT_LE(q, D);
        EXPECT_GT(2.0 * q, D);
    }
}
