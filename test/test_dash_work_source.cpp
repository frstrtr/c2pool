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

// Hysteresis KAT (F-2). After the F-1 fix quantizes advertised diff to powers of
// two, the advertised value and current_difficulty_ both live on the 2^n grid, so
// a dead-band on the QUANTIZED ratio is inert (ratios are only 1, 2, 0.5). A rig
// whose un-quantized ideal D sits near a 2^n boundary then flaps its advertised
// bucket 2^n <-> 2^(n+1) on estimator noise, doubling set_difficulty churn and
// jittering rig-side hashrate graphs. The fix holds the current power-of-two
// bucket [C, 2C) and only re-quantizes when the UN-QUANTIZED ideal D leaves it
// DECISIVELY: at/above 2C by the dead-band margin (step up) or below C by the
// margin (step down). These KATs would FAIL pre-fix (a bare round-DOWN quantize
// steps the instant D crosses the plain 2^n edge). deadband = 0.10 (default).
namespace {
constexpr double kHystTarget = 10.0;   // set_target_time_per_mining_share
constexpr double kHystTau    = 90.0;   // vardiff_ewma_tau_ (fixed default)
constexpr double kDeadband   = 0.10;   // vardiff_deadband_ (default)

// Configure a tracker seeded (via hint) at an on-grid power-of-two bucket C.
// Passed by reference: HashrateTracker holds a std::mutex and is non-copyable.
void setup_hyst_tracker(c2pool::hashrate::HashrateTracker& t, double seed_C) {
    t.set_difficulty_bounds(0.0005, 1e9);   // wide: exercise hysteresis, not clamp
    t.set_target_time_per_mining_share(kHystTarget);
    t.set_hashrate_vardiff(true);
    t.enable_vardiff(true);
    t.set_difficulty_hint(seed_C);          // current bucket C (a power of two)
}
} // namespace

// UP: an ideal D that rises PAST a 2^n boundary but stays within the hysteresis
// band does NOT flap the advertised bucket; a decisive move past 2C*(1+deadband)
// steps. Seeded bucket C = 8 (2^3); boundary of interest is the upper edge 16.
TEST(HashrateVardiffHysteresis, BoundaryNoiseHeldButDecisiveMoveStepsUp)
{
    // per-share issued diff => ideal D grows ~2.06/share; at 8 shares D ~ 16.5,
    // i.e. just above the 2^n edge (16) yet below 2C*(1+deadband) = 17.6.
    constexpr double kDiff = 3.70;

    c2pool::hashrate::HashrateTracker t;
    setup_hyst_tracker(t, 8.0);
    for (int i = 0; i < 8; ++i)
        t.record_mining_share_submission(kDiff, /*accepted=*/true);

    const double D8 = ideal_D(8, kDiff, kHystTarget, kHystTau);
    // Precondition: D has crossed the plain 2^n edge (a pre-fix quantize would
    // already advertise 16 here) but sits inside the upper hysteresis band.
    ASSERT_GT(D8, 16.0)                          << "test mis-scaled: D8=" << D8;
    ASSERT_LT(D8, 2.0 * 8.0 * (1.0 + kDeadband)) << "test mis-scaled: D8=" << D8;
    // No-flap: advertised bucket held at C = 8 despite D having crossed 16.
    EXPECT_EQ(t.get_current_difficulty(), 8.0)
        << "boundary noise flapped the advertised bucket (D8=" << D8 << ")";

    // Decisive move up: push D well past 2C*(1+deadband)=17.6.
    for (int i = 8; i < 13; ++i)
        t.record_mining_share_submission(kDiff, /*accepted=*/true);
    const double D13 = ideal_D(13, kDiff, kHystTarget, kHystTau);
    ASSERT_GE(D13, 2.0 * 8.0 * (1.0 + kDeadband)) << "test mis-scaled: D13=" << D13;
    // Steps to the largest power of two <= D (round-DOWN preserved): 16.
    EXPECT_EQ(t.get_current_difficulty(), 16.0)
        << "decisive move did not step the advertised bucket (D13=" << D13 << ")";
    EXPECT_LE(t.get_current_difficulty(), D13);   // never advertise above ideal D
}

// DOWN: an ideal D that dips BELOW the current bucket's lower edge but stays
// within the margin holds; a decisive drop below C*(1-deadband) steps down.
// Two trackers both seeded at C = 16 (2^4).
TEST(HashrateVardiffHysteresis, LowerMarginHeldButDecisiveDropStepsDown)
{
    // Hold case: at warm-up completion (4 shares) D ~ 15.2 -- below the lower
    // edge 16 yet at/above C*(1-deadband) = 14.4. Pre-fix would step down to 8.
    {
        constexpr double kDiff = 6.815;   // D(4) ~ 15.2
        c2pool::hashrate::HashrateTracker t;
        setup_hyst_tracker(t, 16.0);
        for (int i = 0; i < 4; ++i)       // exactly warm-up: first adjust fires
            t.record_mining_share_submission(kDiff, /*accepted=*/true);
        const double D4 = ideal_D(4, kDiff, kHystTarget, kHystTau);
        ASSERT_LT(D4, 16.0)                     << "test mis-scaled: D4=" << D4;
        ASSERT_GE(D4, 16.0 * (1.0 - kDeadband)) << "test mis-scaled: D4=" << D4;
        EXPECT_EQ(t.get_current_difficulty(), 16.0)
            << "lower-margin noise flapped the advertised bucket down (D4=" << D4 << ")";
    }
    // Decisive case: D(4) ~ 11.0, clearly below C*(1-deadband)=14.4 -> step down.
    {
        constexpr double kDiff = 4.932;   // D(4) ~ 11.0
        c2pool::hashrate::HashrateTracker t;
        setup_hyst_tracker(t, 16.0);
        for (int i = 0; i < 4; ++i)
            t.record_mining_share_submission(kDiff, /*accepted=*/true);
        const double D4 = ideal_D(4, kDiff, kHystTarget, kHystTau);
        ASSERT_LT(D4, 16.0 * (1.0 - kDeadband)) << "test mis-scaled: D4=" << D4;
        // Steps to the largest power of two <= D (round-DOWN preserved): 8.
        EXPECT_EQ(t.get_current_difficulty(), 8.0)
            << "decisive drop did not step the advertised bucket (D4=" << D4 << ")";
        EXPECT_LE(t.get_current_difficulty(), D4);   // never advertise above ideal D
    }
}
