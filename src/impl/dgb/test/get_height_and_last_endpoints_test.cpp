// SPDX-License-Identifier: AGPL-3.0-or-later
// dgb get_height_and_last endpoints — chain-walk window arithmetic KAT.
//
// FENCED, additive (no production code touched this slice). Pins
// src/impl/dgb/coin/get_height_and_last_endpoints.hpp against the
// p2pool-dgb-scrypt oracle that governs every consumer of
// forest.get_height_and_last():
//     util/forest.py:171-173  get_height_and_last -> (delta.height, delta.tail)
//     data.py:160-161         assert height >= net.REAL_CHAIN_LENGTH or last is None
//     data.py:695-696         if height < CHAIN_LENGTH + 1 and last is not None: raise
//     pplns window            depth = min(height, REAL_CHAIN_LENGTH); _pplns_max_shares = max(0, depth-1)
//     pool_monitor.hpp:98     if (height < 10) return 0;
//
// Every expectation is hand-derived from the oracle formula and the DGB net
// constants (REAL_CHAIN_LENGTH = 12*60*60//15 = 2880 mainnet / 400 testnet,
// MONITOR_MIN_HEIGHT = 10), NOT read from the code under test. This header lifts
// only the integer window guards over the already-resolved (height, last) pair;
// the get_delta_to_last skip-list walk stays in the forest. redistribute.hpp /
// pool_monitor.hpp / share_check.hpp are NOT rewired (delegation is the
// byte-identity follow-on). MUST appear in BOTH this dir CMakeLists.txt AND the
// build.yml --target allowlist, or it becomes a #143 NOT_BUILT sentinel.

#include <impl/dgb/coin/get_height_and_last_endpoints.hpp>

#include <gtest/gtest.h>

using namespace dgb;

static constexpr int32_t CL_MAIN = 2880;  // REAL_CHAIN_LENGTH mainnet
static constexpr int32_t CL_TEST = 400;   // REAL_CHAIN_LENGTH testnet

// --- ROOTED-TAIL invariant: height >= REAL_CHAIN_LENGTH or last is None -----
TEST(DgbGhalEndpoints, RootedTailInvariant) {
    // Fully rooted: deep chain with a concrete tail -> holds regardless of last.
    EXPECT_TRUE(rooted_tail_invariant_holds(CL_MAIN, /*last_is_null=*/false, CL_MAIN));
    EXPECT_TRUE(rooted_tail_invariant_holds(CL_MAIN + 1, false, CL_MAIN));
    // Shallow but unrooted (last == None) -> holds.
    EXPECT_TRUE(rooted_tail_invariant_holds(5, /*last_is_null=*/true, CL_MAIN));
    EXPECT_TRUE(rooted_tail_invariant_holds(0, true, CL_MAIN));
    // Shallow AND rooted (last present) -> VIOLATION (the oracle assert fires).
    EXPECT_FALSE(rooted_tail_invariant_holds(5, /*last_is_null=*/false, CL_MAIN));
    EXPECT_FALSE(rooted_tail_invariant_holds(CL_MAIN - 1, false, CL_MAIN));
    // Boundary: exactly REAL_CHAIN_LENGTH is rooted (>=).
    EXPECT_TRUE(rooted_tail_invariant_holds(CL_TEST, false, CL_TEST));
    EXPECT_FALSE(rooted_tail_invariant_holds(CL_TEST - 1, false, CL_TEST));
}

// --- attempt_verify entry guard: height >= CL+1 or last is None -------------
TEST(DgbGhalEndpoints, VerifyDepthGuard) {
    // data.py:696 raises when (height < CHAIN_LENGTH+1) AND (last is not None).
    // ok == NOT(raise).
    EXPECT_FALSE(verify_depth_ok(CL_MAIN, /*last_is_null=*/false, CL_MAIN));     // CL < CL+1, rooted -> raise
    EXPECT_TRUE(verify_depth_ok(CL_MAIN + 1, false, CL_MAIN));                   // height == CL+1 -> ok
    EXPECT_TRUE(verify_depth_ok(3, /*last_is_null=*/true, CL_MAIN));             // unrooted -> ok at any depth
    EXPECT_FALSE(verify_depth_ok(3, false, CL_MAIN));                            // shallow + rooted -> raise
    // Boundary at CHAIN_LENGTH+1 exactly (testnet).
    EXPECT_TRUE(verify_depth_ok(CL_TEST + 1, false, CL_TEST));
    EXPECT_FALSE(verify_depth_ok(CL_TEST, false, CL_TEST));
}

// --- PPLNS window depth = min(height, REAL_CHAIN_LENGTH) ---------------------
TEST(DgbGhalEndpoints, PplnsWindowDepthClamps) {
    EXPECT_EQ(pplns_window_depth(100, CL_MAIN), 100);          // below clamp -> identity
    EXPECT_EQ(pplns_window_depth(CL_MAIN, CL_MAIN), CL_MAIN);  // at clamp
    EXPECT_EQ(pplns_window_depth(CL_MAIN + 5000, CL_MAIN), CL_MAIN);  // above -> clamped
    EXPECT_EQ(pplns_window_depth(0, CL_MAIN), 0);
    EXPECT_EQ(pplns_window_depth(450, CL_TEST), CL_TEST);      // testnet clamp 400
    EXPECT_EQ(pplns_window_depth(399, CL_TEST), 399);
}

// --- PPLNS window activation = depth >= 1 -----------------------------------
TEST(DgbGhalEndpoints, PplnsWindowActivation) {
    EXPECT_FALSE(pplns_window_active(0));   // redistribute.hpp:454 early-return
    EXPECT_TRUE(pplns_window_active(1));
    EXPECT_TRUE(pplns_window_active(CL_MAIN));
    EXPECT_FALSE(pplns_window_active(-3));   // defensive: never active below 1
}

// --- p2pool _pplns_max_shares = max(0, min(height, REAL_CHAIN_LENGTH) - 1) ---
TEST(DgbGhalEndpoints, PplnsMaxSharesMatchesOracle) {
    EXPECT_EQ(pplns_max_shares(0, CL_MAIN), 0);          // max(0, 0-1) = 0
    EXPECT_EQ(pplns_max_shares(1, CL_MAIN), 0);          // max(0, 1-1) = 0
    EXPECT_EQ(pplns_max_shares(2, CL_MAIN), 1);          // max(0, 2-1) = 1
    EXPECT_EQ(pplns_max_shares(100, CL_MAIN), 99);
    EXPECT_EQ(pplns_max_shares(CL_MAIN, CL_MAIN), CL_MAIN - 1);        // 2879
    EXPECT_EQ(pplns_max_shares(CL_MAIN + 1000, CL_MAIN), CL_MAIN - 1); // clamped then -1
    EXPECT_EQ(pplns_max_shares(CL_TEST, CL_TEST), CL_TEST - 1);        // 399
}

// --- pool-monitor diagnostic gate: height >= 10 -----------------------------
TEST(DgbGhalEndpoints, MonitorCycleGate) {
    EXPECT_FALSE(monitor_cycle_runs(0));
    EXPECT_FALSE(monitor_cycle_runs(9));    // pool_monitor.hpp:98 boundary -> no-op
    EXPECT_TRUE(monitor_cycle_runs(10));    // exactly the floor runs
    EXPECT_TRUE(monitor_cycle_runs(2880));
}

// --- non-circular cross-check: window depth, max_shares, and activation are
//     mutually consistent across the whole 0..2*CL range (derived purely from
//     the oracle min/clamp identities, no code-under-test constants). ---------
TEST(DgbGhalEndpoints, WindowConsistencyNonCircular) {
    for (int32_t h = 0; h <= 2 * CL_MAIN; ++h) {
        int32_t depth = pplns_window_depth(h, CL_MAIN);
        // depth never exceeds the clamp, never below 0
        ASSERT_LE(depth, CL_MAIN);
        ASSERT_GE(depth, 0);
        // expected clamp recomputed independently
        int32_t expect_depth = (h < CL_MAIN) ? h : CL_MAIN;
        ASSERT_EQ(depth, expect_depth);
        // max_shares is exactly depth-1 floored at 0
        ASSERT_EQ(pplns_max_shares(h, CL_MAIN), (expect_depth > 0 ? expect_depth - 1 : 0));
        // active iff there is at least one share in range
        ASSERT_EQ(pplns_window_active(depth), expect_depth >= 1);
    }
}