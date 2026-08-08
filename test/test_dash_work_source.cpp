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
#include <impl/dash/coin/special_tx_pool_delta.hpp>
#include <impl/dash/coin/rpc_data.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/pack.hpp>
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

// ─── Option B: pinned-tx splice on the SERVED-dashd arm ──────────────────────
// The donation consolidation (>100KB, fee 0) cannot enter dashd's mempool
// (policy standardness), so when the dashd arm serves, the pin must ride OUR
// copy of the template — gated by the SAME splice_pinned_txs the embedded arm
// uses. Fail-closed contract: no verify view (mempool/mnstates null) → the
// template is byte-identical to no-pin; never an unverified inclusion.
TEST(DashWorkSource, PinnedTxExcludedOnFallbackWithoutVerifyView)
{
    EmbeddedWorkInputs emb;            // has_state=false → fallback arm
    dash::coin::MutableTransaction pin;
    pin.vin.resize(1);
    std::vector<dash::coin::MutableTransaction> pins{pin};
    emb.pinned_local_txs = &pins;        // pin present, but no mempool/mnstates

    bool emb_ran = false, fb_ran = false;
    WorkSelection sel = select_dash_work(
        emb,
        [&] { return embedded_stub(emb_ran); },
        [&] { return dashd_stub(fb_ran); });

    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fb_ran);
    // Byte-identical to the no-pin shape: nothing appended anywhere.
    EXPECT_TRUE(sel.work.m_txs.empty());
    EXPECT_TRUE(sel.work.m_tx_hashes.empty());
    EXPECT_TRUE(sel.work.m_tx_fees.empty());
    EXPECT_TRUE(sel.work.m_tx_data_hex.empty());
}

TEST(DashWorkSource, PinnedTxOnFallbackFailsClosedWithoutUtxoView)
{
    // Verify view POINTERS present but the mempool has no UTXO view wired:
    // pinned_tx_admissible returns UtxoViewUnset and the pin must be EXCLUDED
    // (the primary without --embedded-utxo lands exactly here).
    MnStateMachine mn;
    dash::coin::Mempool mp;
    EmbeddedWorkInputs emb;            // has_state=false → fallback arm
    emb.mnstates = &mn;
    emb.mempool  = &mp;
    dash::coin::MutableTransaction pin;
    pin.vin.resize(1);
    std::vector<dash::coin::MutableTransaction> pins{pin};
    emb.pinned_local_txs = &pins;

    bool emb_ran = false, fb_ran = false;
    WorkSelection sel = select_dash_work(
        emb,
        [&] { return embedded_stub(emb_ran); },
        [&] { return dashd_stub(fb_ran); });

    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(sel.work.m_txs.empty());
    EXPECT_TRUE(sel.work.m_tx_data_hex.empty());
}

// POSITIVE PATH: verify view wired (mempool + UTXO + mnstates), pin admissible
// (mature input, fee exactly 0) -> appended to ALL FOUR tx vectors on the
// SERVED dashd template, fee recorded as 0, coinbase value untouched. This is
// the donation-consolidation contract: >100KB standardness never applies here.
TEST(DashWorkSource, PinnedTxSplicedOnFallbackWithVerifyView)
{
    using ::core::coin::UTXOViewCache;
    using ::core::coin::Outpoint;
    using ::core::coin::Coin;

    uint256 prev;
    prev.begin()[0] = 0x42;
    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(50'000, {}, /*height=*/1, /*cb=*/false));

    dash::coin::Mempool mp;
    mp.set_utxo(&utxo);
    MnStateMachine mn;

    dash::coin::MutableTransaction pin;
    pin.vin.resize(1);
    pin.vin[0].prevout.hash  = prev;
    pin.vin[0].prevout.index = 0;
    pin.vout.resize(1);
    pin.vout[0].value = 50'000;   // sum(in) == sum(out): fee exactly zero

    EmbeddedWorkInputs emb;       // has_state=false -> fallback arm
    emb.mnstates        = &mn;
    emb.mempool         = &mp;
    std::vector<dash::coin::MutableTransaction> pins{pin};
    emb.pinned_local_txs = &pins;

    bool emb_ran = false, fb_ran = false;
    WorkSelection sel = select_dash_work(
        emb,
        [&] { return embedded_stub(emb_ran); },
        [&] { return dashd_stub(fb_ran); });

    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fb_ran);
    ASSERT_EQ(sel.work.m_txs.size(), 1u);
    ASSERT_EQ(sel.work.m_tx_hashes.size(), 1u);
    ASSERT_EQ(sel.work.m_tx_fees.size(), 1u);
    ASSERT_EQ(sel.work.m_tx_data_hex.size(), 1u);
    EXPECT_EQ(sel.work.m_tx_fees[0], 0u);
    EXPECT_EQ(sel.work.m_tx_hashes[0], dash::coin::dash_txid(pin));
    EXPECT_FALSE(sel.work.m_tx_data_hex[0].empty());
    // Coinbase value untouched by the splice (fee 0 adds nothing to claim).
    EXPECT_EQ(sel.work.m_coinbase_value, 0u);
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


// HEIGHT WIRING (live defect 2026-08-07): the primary logged
// `pinned tx EXCLUDED h=0` because dashd's template copy carried no height at
// the splice point. Zero is not a harmless label — the gate's coinbase
// maturity arm reads it as next_height, which would mark every coinbase input
// immature. When dashd's copy is unset the bundle's own tip must fill it in.
// ─── The PLACEHOLDER fallback (corrected 2026-08-07) ───────────────────────
//
// This test previously asserted the OPPOSITE: that a fallback arriving with no
// height still gets the pin spliced, with the height filled from the bundle
// tip. It was written from the production log line
//
//     [dashd-splice] pinned tx EXCLUDED h=0 cause=input-missing-or-spent
//
// on the belief that "the shape the primary produced" was a real dashd
// template missing its height. It was not. The serve path binds this arm to a
// NO-OP closure returning DashWorkData{} (#1134 — the real dashd
// getblocktemplate must not run on the io thread), so that h=0 was a
// PLACEHOLDER, and every splice into it landed on a value nobody serves while
// the real template went unspliced.
//
// The corrected contract: a value indistinguishable from a default-constructed
// DashWorkData is not a template and is left alone. The serve path gates
// beside the coin state and appends at the real template instead
// (DASHWorkSource::resolve_coin_state_arm).
TEST(DashWorkSource, PlaceholderFallbackLeavesThePinAlone)
{
    using ::core::coin::UTXOViewCache;
    using ::core::coin::Outpoint;
    using ::core::coin::Coin;

    uint256 prev;
    prev.begin()[0] = 0x77;
    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(9'000, {}, /*height=*/1, /*cb=*/false));

    dash::coin::Mempool mp;
    mp.set_utxo(&utxo);
    MnStateMachine mn;

    // Admissible on the merits: input unspent, fee exactly zero. So anything
    // that DOES get spliced here is spliced into the placeholder.
    dash::coin::MutableTransaction pin;
    pin.vin.resize(1);
    pin.vin[0].prevout.hash  = prev;
    pin.vin[0].prevout.index = 0;
    pin.vout.resize(1);
    pin.vout[0].value = 9'000;

    EmbeddedWorkInputs emb;          // has_state=false -> fallback arm
    emb.mnstates        = &mn;
    emb.mempool         = &mp;
    std::vector<dash::coin::MutableTransaction> pins{pin};
    emb.pinned_local_txs = &pins;
    emb.prev_height     = 2'517'800; // a tip IS known — still not a template

    bool emb_ran = false, fb_ran = false;
    WorkSelection sel = select_dash_work(
        emb,
        [&] { return embedded_stub(emb_ran); },
        // EXACTLY what the serve path's no-op closure returns.
        [&] { fb_ran = true; return DashWorkData{}; });

    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fb_ran);
    EXPECT_TRUE(sel.work.m_txs.empty())
        << "a placeholder is not a template — splicing it is a no-op that "
           "reads as success in the log";
    EXPECT_TRUE(sel.work.m_tx_data_hex.empty());
}

// A fallback that carries ANY information is a real template, and the pin
// still rides it here. This is the discriminator the guard turns on, so it is
// asserted rather than assumed.
TEST(DashWorkSource, FallbackCarryingAHeightIsATemplateAndTakesThePin)
{
    using ::core::coin::UTXOViewCache;
    using ::core::coin::Outpoint;
    using ::core::coin::Coin;

    uint256 prev;
    prev.begin()[0] = 0x78;
    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(9'000, {}, /*height=*/1, /*cb=*/false));

    dash::coin::Mempool mp;
    mp.set_utxo(&utxo);
    MnStateMachine mn;

    dash::coin::MutableTransaction pin;
    pin.vin.resize(1);
    pin.vin[0].prevout.hash  = prev;
    pin.vin[0].prevout.index = 0;
    pin.vout.resize(1);
    pin.vout[0].value = 9'000;

    EmbeddedWorkInputs emb;
    emb.mnstates        = &mn;
    emb.mempool         = &mp;
    std::vector<dash::coin::MutableTransaction> pins{pin};
    emb.pinned_local_txs = &pins;
    emb.prev_height     = 2'517'800;

    bool emb_ran = false, fb_ran = false;
    WorkSelection sel = select_dash_work(
        emb,
        [&] { return embedded_stub(emb_ran); },
        [&] { fb_ran = true; DashWorkData w; w.m_height = 2'517'801; return w; });

    EXPECT_EQ(sel.source, WorkSource::DashdFallback);
    EXPECT_TRUE(fb_ran);
    ASSERT_EQ(sel.work.m_txs.size(), 1u) << "a real template still carries the pin";
    EXPECT_EQ(sel.work.m_tx_fees[0], 0u);
    EXPECT_EQ(sel.work.m_height, 2'517'801u);
}

// ─── #107: creditPool divergence — explained vs unexplained ─────────────────
// KAT for special_tx_pool_delta, the arithmetic that decides whether a GBT
// creditPool divergence is ACCOUNTED FOR by pending DIP-0027 asset movement
// (dashd includes those txs, we exclude them by design, C-3) or is genuine
// drift the reward-safety backstop must keep shouting about. Numbers are the
// ones measured live on mainnet the night of 2026-08-06/07, so a regression
// here is a regression against reality:
//   h=2517494 lock   +0.02689906 DASH ; h=2517504 unlock -72.0000019 with a
//   190-duff payload fee tail.
// Folded into this EXISTING allowlisted target on purpose: a fresh
// add_executable absent from the build.yml --target allowlist would be a
// silently-passing NOT_BUILT sentinel (#143).
namespace {

template <typename Payload>
std::vector<unsigned char> pack_payload(const Payload& pl) {
    auto ps = ::pack(pl);
    auto span = ps.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(span.data()),
        reinterpret_cast<const unsigned char*>(span.data()) + span.size());
}

::bitcoin_family::coin::TxOut out_of(int64_t v) { ::bitcoin_family::coin::TxOut o; o.value = v; return o; }

/// Type-8: pool GAINS sum(payload.creditOutputs).
dash::coin::MutableTransaction make_lock(int64_t credit_value) {
    dash::coin::vendor::CAssetLockPayload pl;
    pl.creditOutputs.push_back(out_of(credit_value));
    dash::coin::MutableTransaction tx;
    tx.version = 3;
    tx.type    = dash::coin::vendor::CAssetLockPayload::SPECIALTX_TYPE;   // 8
    tx.extra_payload = pack_payload(pl);
    return tx;
}

/// Type-9: pool LOSES (payload.fee + sum(vout)); no inputs, outputs are minted.
dash::coin::MutableTransaction make_unlock(int64_t out_value, uint32_t fee) {
    dash::coin::vendor::CAssetUnlockPayload pl;
    pl.index           = 1;
    pl.fee             = fee;
    pl.requestedHeight = 1000;
    dash::coin::MutableTransaction tx;
    tx.version = 3;
    tx.type    = dash::coin::vendor::CAssetUnlockPayload::SPECIALTX_TYPE; // 9
    tx.vout.push_back(out_of(out_value));
    tx.extra_payload = pack_payload(pl);
    return tx;
}

dash::coin::MutableTransaction make_plain() {
    dash::coin::MutableTransaction tx;
    tx.version = 2;
    tx.type    = 0;
    tx.vout.push_back(out_of(50'000));
    return tx;
}

} // namespace

// 1) The mainnet h=2517494 shape: one pending lock of 0.02689906 DASH.
TEST(DashSpecialPoolDelta, PendingLockExplainsThePositiveDivergence)
{
    const int64_t kLock = 2'689'906;                 // measured on mainnet
    const int64_t ours  = 3'028'884'293'639;         // our CbTx creditPool
    const int64_t dashd = ours + kLock;              // dashd's, with the lock

    std::vector<dash::coin::MutableTransaction> txs{ make_plain(), make_lock(kLock) };
    const auto sp = dash::coin::special_tx_pool_delta(txs);

    EXPECT_EQ(sp.count, 1u);
    EXPECT_FALSE(sp.unparsable);
    EXPECT_EQ(sp.delta, kLock);
    EXPECT_TRUE(sp.explains(ours, dashd));
}

// 2) The h=2517504 shape: an unlock, whose miner fee lives in the payload.
TEST(DashSpecialPoolDelta, PendingUnlockSubtractsOutputsPlusPayloadFee)
{
    const int64_t kOut = 7'200'000'000;              // 72 DASH
    const uint32_t kFee = 190;                       // the measured fee tail
    const int64_t ours  = 3'029'419'859'335;
    const int64_t dashd = ours - (kOut + kFee);

    std::vector<dash::coin::MutableTransaction> txs{ make_unlock(kOut, kFee) };
    const auto sp = dash::coin::special_tx_pool_delta(txs);

    EXPECT_EQ(sp.count, 1u);
    EXPECT_EQ(sp.delta, -(kOut + static_cast<int64_t>(kFee)));
    EXPECT_TRUE(sp.explains(ours, dashd));
}

// 3) Both directions in one template — the signs must not cancel by accident.
TEST(DashSpecialPoolDelta, MixedLockAndUnlockSumSigned)
{
    const int64_t kLock = 35'000'000;
    const int64_t kOut  = 2'108'300'000;
    const uint32_t kFee = 190;
    const int64_t expected = kLock - (kOut + static_cast<int64_t>(kFee));
    const int64_t ours  = 3'023'215'610'725;
    const int64_t dashd = ours + expected;

    std::vector<dash::coin::MutableTransaction> txs{
        make_lock(kLock), make_plain(), make_unlock(kOut, kFee) };
    const auto sp = dash::coin::special_tx_pool_delta(txs);

    EXPECT_EQ(sp.count, 2u);
    EXPECT_EQ(sp.delta, expected);
    EXPECT_TRUE(sp.explains(ours, dashd));
}

// 4) A divergence the pending special txs do NOT account for stays a mismatch.
//    This is the whole reason the check is an equation and not a heuristic.
TEST(DashSpecialPoolDelta, UnrelatedDivergenceIsNotExplained)
{
    const int64_t kLock = 2'689'906;
    const int64_t ours  = 3'028'884'293'639;
    const int64_t dashd = ours + kLock + 1;          // one duff off

    std::vector<dash::coin::MutableTransaction> txs{ make_lock(kLock) };
    const auto sp = dash::coin::special_tx_pool_delta(txs);

    EXPECT_EQ(sp.delta, kLock);
    EXPECT_FALSE(sp.explains(ours, dashd));
}

// 5) No special txs: even an exactly-equal pool must not be reported as
//    "explained by special movement" — there was nothing to explain it with.
TEST(DashSpecialPoolDelta, NoSpecialTxsNeverExplains)
{
    std::vector<dash::coin::MutableTransaction> txs{ make_plain(), make_plain() };
    const auto sp = dash::coin::special_tx_pool_delta(txs);

    EXPECT_EQ(sp.count, 0u);
    EXPECT_EQ(sp.delta, 0);
    EXPECT_FALSE(sp.explains(1'000, 1'000));
}

// 6) Fail-closed: a special tx whose payload does not parse leaves us knowing
//    NOTHING about the true movement, so nothing may be explained by it.
TEST(DashSpecialPoolDelta, UnparsablePayloadExplainsNothing)
{
    dash::coin::MutableTransaction broken;
    broken.version = 3;
    broken.type    = dash::coin::vendor::CAssetLockPayload::SPECIALTX_TYPE;
    broken.extra_payload = { 0xff, 0xff, 0xff };     // not a valid payload

    std::vector<dash::coin::MutableTransaction> txs{ make_lock(1'000), broken };
    const auto sp = dash::coin::special_tx_pool_delta(txs);

    EXPECT_TRUE(sp.unparsable);
    EXPECT_FALSE(sp.explains(0, 0));
    EXPECT_FALSE(sp.explains(0, 1'000));
}
