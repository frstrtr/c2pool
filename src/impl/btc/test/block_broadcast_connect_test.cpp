// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::coin::broadcast_block_for_connect CONNECT-AUTHORITATIVE KATs.
//
// The won-block connect path differs from the cross-coin FALLBACK policy
// (broadcast_block_with_fallback): a P2P relay "success" only means the block
// was ANNOUNCED to a peer (a cmpctblock header). Under compact-block relay the
// daemon then requests the body via getblocktxn, which the c2pool broadcaster
// does not serve, so the daemon never ConnectBlock()s the block and the subsidy
// is SILENTLY LOST even though relay_p2p() returned true. submitblock delivers
// the full block and is connect-authoritative, so this path fires the RPC leg
// UNCONDITIONALLY -- the exact invariant these KATs lock.
//
// This is BTC-lane-fenced and does NOT alter the cross-coin
// core::broadcast_block_with_fallback contract (the always-fire convergence is
// the v37 broadcaster-convergence shape held on HOLD, #500/#498). The guard
// twin block_broadcast_guard_test.cpp still locks the unchanged fallback policy.
//
// Rides the already-allowlisted btc_share_test executable, so no build.yml
// --target allowlist change is needed and there is no #137-style NOT_BUILT
// sentinel risk. p2pool-merged-v36 surface: NONE.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <stdexcept>

#include "../coin/block_broadcast.hpp"

// 1) THE FIX: P2P relay succeeds (cmpctblock announce-success) -> the
//    submitblock RPC STILL fires. This is the connect-authoritative invariant:
//    an announce alone does not connect the tip, so the RPC leg must not be
//    short-circuited the way the FALLBACK policy short-circuits it.
TEST(BtcBlockBroadcastConnect, P2pSuccessStillFiresSubmitblock) {
    bool rpc_called = false;
    auto relay  = [] { return true; };            // announced to peer
    auto submit = [&] { rpc_called = true; return true; };

    EXPECT_TRUE(btc::coin::broadcast_block_for_connect(relay, submit));
    EXPECT_TRUE(rpc_called);  // ALWAYS fires -- block actually connects via RPC
}

// 1b) Contrast lock: the unchanged FALLBACK policy DOES short-circuit on the
//     same inputs. Pinning both side-by-side documents that the connect path is
//     a deliberately distinct policy, not a change to the shared contract.
TEST(BtcBlockBroadcastConnect, FallbackPolicyStillShortCircuits) {
    bool rpc_called = false;
    auto relay  = [] { return true; };
    auto submit = [&] { rpc_called = true; return true; };

    EXPECT_TRUE(btc::coin::broadcast_block_with_fallback(relay, submit));
    EXPECT_FALSE(rpc_called);  // fallback: no double-broadcast (UNCHANGED)
}

// 2) P2P relay fails -> RPC still delivers the block (reaches the network).
TEST(BtcBlockBroadcastConnect, P2pFailRpcStillConnects) {
    int rpc_calls = 0;
    auto relay  = [] { return false; };
    auto submit = [&] { ++rpc_calls; return true; };

    EXPECT_TRUE(btc::coin::broadcast_block_for_connect(relay, submit));
    EXPECT_EQ(rpc_calls, 1);
}

// 3) Both sinks fail -> reaches NEITHER -> false, so the won-block path screams
//    (never a silent success).
TEST(BtcBlockBroadcastConnect, BothFailReachesNeither) {
    auto relay  = [] { return false; };
    auto submit = [] { return false; };

    EXPECT_FALSE(btc::coin::broadcast_block_for_connect(relay, submit));
}

// 4) RPC accepts even when P2P is an empty (null) sink -> connect path engages
//    the connect-authoritative leg regardless of P2P availability.
TEST(BtcBlockBroadcastConnect, NullP2pRpcConnects) {
    std::function<bool()> no_p2p;   // empty: models m_p2p == nullptr
    int rpc_calls = 0;
    auto submit = [&] { ++rpc_calls; return true; };

    EXPECT_TRUE(btc::coin::broadcast_block_for_connect(no_p2p, submit));
    EXPECT_EQ(rpc_calls, 1);
}
// ── #744/#787 M1: a THROWING RPC leg must never destroy an ARM A relay win ──
// Once ARM B (m_rpc) is armed, a daemon unreachable at submit time raises a
// JsonRpcException out of submit_block_hex. Both legs of
// broadcast_block_for_connect are now guarded so that throw cannot unwind out
// and turn an already-succeeded P2P relay into a false "reached NEITHER -- lost
// subsidy" alarm.

// 5) RPC leg THROWS but P2P relayed -> block still counts as reaching the
//    network (true), and no exception escapes.
TEST(BtcBlockBroadcastConnect, RpcThrowsButP2pRelayed) {
    auto relay  = [] { return true; };
    auto submit = []() -> bool { throw std::runtime_error("daemon unreachable"); };

    bool result = false;
    EXPECT_NO_THROW({ result = btc::coin::broadcast_block_for_connect(relay, submit); });
    EXPECT_TRUE(result);   // ARM A's relay win stands despite the throwing RPC leg
}

// 6) RPC leg THROWS and P2P did NOT relay -> reaches neither -> false (scream),
//    but still no exception escapes the won-block path.
TEST(BtcBlockBroadcastConnect, RpcThrowsAndP2pFailedReachesNeither) {
    auto relay  = [] { return false; };
    auto submit = []() -> bool { throw std::runtime_error("daemon unreachable"); };

    bool result = true;
    EXPECT_NO_THROW({ result = btc::coin::broadcast_block_for_connect(relay, submit); });
    EXPECT_FALSE(result);
}

// 7) A THROWING P2P relay leg must not skip the connect-authoritative RPC leg
//    (the RPC still delivers the block).
TEST(BtcBlockBroadcastConnect, P2pThrowsRpcStillConnects) {
    auto relay  = []() -> bool { throw std::runtime_error("relay sink threw"); };
    int rpc_calls = 0;
    auto submit = [&] { ++rpc_calls; return true; };

    bool result = false;
    EXPECT_NO_THROW({ result = btc::coin::broadcast_block_for_connect(relay, submit); });
    EXPECT_TRUE(result);
    EXPECT_EQ(rpc_calls, 1);   // RPC leg reached despite the throwing relay
}
