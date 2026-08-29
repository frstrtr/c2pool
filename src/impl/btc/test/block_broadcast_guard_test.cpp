// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::coin::broadcast_block_with_fallback dual-path guard KATs.
//
// Offline contract slice locking the won-block fallback orchestration the BTC
// run-loop depends on: P2P relay is PRIMARY, submitblock RPC is the FALLBACK
// (fired ONLY when P2P is unavailable / relay-failed -- deliberately NOT
// always-both). The function's doc-comment promises a false return is the
// ONLY "reached neither sink" signal and that a won block is NEVER
// silent-dropped. A THROWING relay_p2p() sink violated that promise: the
// exception unwound PAST the function, bypassing the submitblock fallback
// entirely and silently dropping the won block -- the exact hole the fallback
// exists to close. These KATs lock BOTH legs guarded (mirror of the NMC #468
// leg-guard fix in nmc_block_broadcast_test.cpp).
//
// Rides the already-allowlisted btc_share_test executable, so no build.yml
// --target allowlist change is needed and there is no #137-style NOT_BUILT
// sentinel risk. p2pool-merged-v36 surface: NONE.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <stdexcept>

#include "../coin/block_broadcast.hpp"

// 1) Primary succeeds -> true, and the submitblock fallback is NOT invoked
//    (the deliberate no-double-broadcast rule).
TEST(BtcBlockBroadcastGuard, P2pSuccessSkipsFallback) {
    bool rpc_called = false;
    auto relay  = [] { return true; };
    auto submit = [&] { rpc_called = true; return true; };

    EXPECT_TRUE(btc::coin::broadcast_block_with_fallback(relay, submit));
    EXPECT_FALSE(rpc_called);  // primary won -> no double submit
}

// 2) Primary relay-fails (returns false) -> submitblock fallback fires.
TEST(BtcBlockBroadcastGuard, P2pFalseFiresFallback) {
    int  rpc_calls = 0;
    auto relay  = [] { return false; };
    auto submit = [&] { ++rpc_calls; return true; };

    EXPECT_TRUE(btc::coin::broadcast_block_with_fallback(relay, submit));
    EXPECT_EQ(rpc_calls, 1);
}

// 3) PRIMARY-LEG GUARD (the fix): a THROWING relay sink is a relay-failed mode,
//    not a reason to skip the fallback. The submitblock RPC STILL fires, the
//    won block reaches the node, and the dispatcher does NOT propagate the
//    throw. Before the guard this exception unwound past the function and the
//    block was silently dropped.
TEST(BtcBlockBroadcastGuard, ThrowingP2pStillFiresFallback) {
    int  rpc_calls = 0;
    auto relay  = []() -> bool { throw std::runtime_error("p2p down mid-relay"); };
    auto submit = [&] { ++rpc_calls; return true; };

    bool ok = false;
    EXPECT_NO_THROW(ok = btc::coin::broadcast_block_with_fallback(relay, submit));
    EXPECT_TRUE(ok);             // fallback carried the won block
    EXPECT_EQ(rpc_calls, 1);     // fallback fired despite the throw
}

// 4) Throwing primary with NO fallback sink -> definite false (reached neither
//    sink, the caller's documented "scream / lost-subsidy" path), never a throw.
TEST(BtcBlockBroadcastGuard, ThrowingP2pNoFallbackReturnsFalse) {
    auto relay = []() -> bool { throw std::runtime_error("p2p down"); };

    bool ok = true;
    EXPECT_NO_THROW(ok = btc::coin::broadcast_block_with_fallback(relay, /*submit_rpc=*/{}));
    EXPECT_FALSE(ok);
}

// 5) FALLBACK-LEG GUARD: when submitblock itself throws there is no further
//    sink, so the throw collapses to a definite false return -> the caller's
//    "reached neither sink, scream" contract fires instead of an exception
//    escaping the won-block handler.
TEST(BtcBlockBroadcastGuard, ThrowingFallbackReturnsFalse) {
    auto relay  = [] { return false; };
    auto submit = []() -> bool { throw std::runtime_error("submitblock rpc threw"); };

    bool ok = true;
    EXPECT_NO_THROW(ok = btc::coin::broadcast_block_with_fallback(relay, submit));
    EXPECT_FALSE(ok);
}

// 6) Neither sink live -> safe false no-op (no throw, no silent-drop).
TEST(BtcBlockBroadcastGuard, NoSinkIsSafeFalse) {
    bool ok = true;
    EXPECT_NO_THROW(ok = btc::coin::broadcast_block_with_fallback({}, {}));
    EXPECT_FALSE(ok);
}