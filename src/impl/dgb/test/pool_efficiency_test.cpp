// dgb::compute_stale_prop / compute_real_pool_hashrate — pool efficiency KAT.
//
// FENCED conformance test (no production code touched). Pins the pool
// EFFICIENCY / REAL-HASHRATE diagnostics arithmetic lifted into
// pool_efficiency.hpp against the p2pool-dgb-scrypt oracle main.py status loop:
//     real_att_s = get_pool_attempts_per_second(...) / (1 - stale_prop)
// with stale_prop = (orphan + doa) / total_recent over the recent share window.
//
// The expected values here are HAND-DERIVED from the oracle formulas (not
// produced by calling the helper under test), so the test is non-circular: it
// independently recomputes the oracle expression and asserts the helper matches.
//
// MUST appear in BOTH the ctest registration (this dir CMakeLists.txt) AND the
// build.yml --target allowlist, or it becomes a #143-style NOT_BUILT sentinel
// that reds master.

#include <impl/dgb/pool_efficiency.hpp>

#include <gtest/gtest.h>

namespace {

// ---- compute_stale_prop -------------------------------------------------

TEST(DgbPoolEfficiency, StalePropEmptyWindowIsZero) {
    // total_recent == 0 -> 0.0, never NaN.
    EXPECT_DOUBLE_EQ(dgb::compute_stale_prop(0, 0, 0), 0.0);
    // Even with (impossibly) non-zero counts, an empty window short-circuits.
    EXPECT_DOUBLE_EQ(dgb::compute_stale_prop(7, 3, 0), 0.0);
}

TEST(DgbPoolEfficiency, StalePropNoStalesIsZero) {
    EXPECT_DOUBLE_EQ(dgb::compute_stale_prop(0, 0, 100), 0.0);
}

TEST(DgbPoolEfficiency, StalePropOrphanPlusDoaOverTotal) {
    // 3 orphan + 2 doa over 100 recent -> 5/100 = 0.05 (hand-derived).
    EXPECT_DOUBLE_EQ(dgb::compute_stale_prop(3, 2, 100), 0.05);
    // 1 orphan + 0 doa over 4 -> 0.25.
    EXPECT_DOUBLE_EQ(dgb::compute_stale_prop(1, 0, 4), 0.25);
    // All stale: 50 over 50 -> 1.0.
    EXPECT_DOUBLE_EQ(dgb::compute_stale_prop(30, 20, 50), 1.0);
}

// ---- compute_real_pool_hashrate ----------------------------------------

TEST(DgbPoolEfficiency, RealHashrateZeroStaleIsIdentity) {
    // stale_prop == 0 -> divisor is 1 -> unchanged.
    EXPECT_DOUBLE_EQ(dgb::compute_real_pool_hashrate(1000.0, 0.0), 1000.0);
}

TEST(DgbPoolEfficiency, RealHashrateScalesByInverseEfficiency) {
    // Oracle: pool_hs / (1 - stale_prop). Recompute the oracle expression
    // independently (non-circular) and assert the helper equals it.
    const double pool_hs = 1000.0;
    const double stale_prop = 0.05;
    const double oracle = pool_hs / (1.0 - stale_prop); // ~1052.6315789...
    EXPECT_DOUBLE_EQ(dgb::compute_real_pool_hashrate(pool_hs, stale_prop), oracle);
    // Sanity anchor on the magnitude (hand: 1000/0.95 > 1052, < 1053).
    EXPECT_GT(dgb::compute_real_pool_hashrate(pool_hs, stale_prop), 1052.0);
    EXPECT_LT(dgb::compute_real_pool_hashrate(pool_hs, stale_prop), 1053.0);
}

TEST(DgbPoolEfficiency, RealHashrateGuardSuppressesNearAllStale) {
    // stale_prop == 0.999 is NOT < 0.999 -> guard holds -> identity, no blow-up.
    EXPECT_DOUBLE_EQ(dgb::compute_real_pool_hashrate(1000.0, 0.999), 1000.0);
    // Above the threshold likewise suppressed.
    EXPECT_DOUBLE_EQ(dgb::compute_real_pool_hashrate(1000.0, 1.0), 1000.0);
}

TEST(DgbPoolEfficiency, RealHashrateNoMeasuredWorkIsIdentity) {
    // pool_hs <= 0 -> nothing to scale.
    EXPECT_DOUBLE_EQ(dgb::compute_real_pool_hashrate(0.0, 0.05), 0.0);
    EXPECT_DOUBLE_EQ(dgb::compute_real_pool_hashrate(-5.0, 0.05), -5.0);
}

// ---- end-to-end chain mirroring node.cpp diagnostics --------------------

TEST(DgbPoolEfficiency, ChainStalePropThenRealHashrateMatchesOracle) {
    // node.cpp: stale_prop from counts, then real_pool_hs from raw aps.
    const double sp = dgb::compute_stale_prop(3, 2, 100); // 0.05
    EXPECT_DOUBLE_EQ(sp, 0.05);
    const double pool_hs = 2000.0;
    const double oracle = pool_hs / (1.0 - sp); // 2000/0.95
    EXPECT_DOUBLE_EQ(dgb::compute_real_pool_hashrate(pool_hs, sp), oracle);
}

} // namespace
