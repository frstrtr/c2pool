// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// test_dash_won_block_dualpath -- the S8 broadcaster-gate BINDING KAT for DASH.
//
// The deterministic gate-closer for DASH's won-block broadcaster dual-path
// (mirrors dgb_forced_won_share_dualpath_test). It drives a FORCED won block
// through the REAL dispatch handler (dash::coin::broadcast_won_block, the closure
// main_dash.cpp installs as the DASHWorkSource submit sink) and asserts the one
// won block fans out down BOTH broadcast arms --
//   ARM A : embedded P2P relay (ALWAYS-PRIMARY, daemonless) -> receives block_bytes
//   ARM B : dashd submitblock RPC backup (on-demand)        -> receives block_hex
// -- carrying the BYTE-IDENTICAL block (HexStr(bytes) of arm A == hex of arm B).
//
// Unlike DGB (which reconstructs the block from a share hash), the DASH stratum
// path hands the dispatcher the ALREADY-reconstructed wire bytes, so this KAT
// pins the dual-arm FAN-OUT + cross-arm byte identity + fail-loud posture over
// the finished block blob. Fail-closed end-to-end is also pinned: a won block
// with NEITHER arm wired engages nothing and reports any()==false (the caller's
// "block NOT relayed" LOUD path -- never a silent lost subsidy).
//
// Reward/consensus-NEUTRAL: broadcast path only; no PoW hash, share format,
// coinbase commitment, or PPLNS math touched. SYNTHETIC seams only -- no live
// CoinClient / dashd / network. Per-coin isolation: src/impl/dash/ only. MUST
// appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist (the
// NOT_BUILT sentinel trap).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <impl/dash/coin/won_block_dispatch.hpp>

using dash::coin::broadcast_won_block;
using dash::coin::P2pRelaySink;
using dash::coin::RpcSubmitSink;

namespace {

// A non-trivial synthetic won-block blob (the finished wire bytes the DASH
// stratum submit path hands the dispatcher). Content is opaque to the broadcast
// path -- carried verbatim down both arms.
std::vector<unsigned char> make_block_bytes()
{
    std::vector<unsigned char> b;
    b.reserve(120);
    for (int i = 0; i < 120; ++i)
        b.push_back(static_cast<unsigned char>((i * 7 + 3) & 0xff));
    return b;
}

// Independent hex encoder so the cross-arm identity (arm A bytes hex-encode to
// exactly the hex arm B submitted) is asserted self-containedly, not assumed.
std::string to_hex(const std::vector<unsigned char>& b)
{
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(b.size() * 2);
    for (unsigned char c : b) { s += d[c >> 4]; s += d[c & 0x0f]; }
    return s;
}

} // namespace

// 1) THE GATE: one forced won block -> BOTH arms carry the byte-identical block
//    (embedded P2P primary bytes, submitblock backup hex).
TEST(DashWonBlockDualPath, BothArmsCarryIdenticalBlock)
{
    const auto block = make_block_bytes();
    const std::string block_hex = to_hex(block);

    std::vector<unsigned char> relayed;
    bool did_relay = false;
    P2pRelaySink p2p = [&](const std::vector<unsigned char>& b) { did_relay = true; relayed = b; };

    std::string submitted_hex;
    int submit_calls = 0;
    RpcSubmitSink rpc = [&](const std::string& hex) -> bool {
        ++submit_calls; submitted_hex = hex; return true;
    };

    const auto r = broadcast_won_block(p2p, rpc, block, block_hex);

    // ARM A -- embedded P2P relay fired with the exact block bytes.
    ASSERT_TRUE(did_relay);
    EXPECT_TRUE(r.p2p_sent);
    EXPECT_EQ(relayed, block);

    // ARM B -- submitblock backup fired exactly once, with the exact block hex.
    ASSERT_EQ(submit_calls, 1);
    EXPECT_TRUE(r.rpc_ok);
    EXPECT_EQ(submitted_hex, block_hex);

    // CROSS-ARM IDENTITY: arm-A bytes hex-encode to exactly arm-B's submitted hex.
    EXPECT_EQ(to_hex(relayed), submitted_hex);

    // Primary is P2P; the block reached the network.
    EXPECT_STREQ(r.landed_first, "p2p");
    EXPECT_TRUE(r.any());
}

// 2) DAEMONLESS (S8 critical path): embedded P2P relay ALONE, no dashd arm --
//    the won block still reaches the network on the primary arm.
TEST(DashWonBlockDualPath, DaemonlessP2pOnlyReachesNetwork)
{
    const auto block = make_block_bytes();
    const std::string block_hex = to_hex(block);

    std::vector<unsigned char> relayed;
    P2pRelaySink p2p = [&](const std::vector<unsigned char>& b) { relayed = b; };

    const auto r = broadcast_won_block(p2p, /*rpc=*/{}, block, block_hex);

    EXPECT_TRUE(r.p2p_sent);
    EXPECT_FALSE(r.rpc_ok);
    EXPECT_EQ(relayed, block);
    EXPECT_STREQ(r.landed_first, "p2p");
    EXPECT_TRUE(r.any());   // reached the network daemonless
}

// 3) RPC-only deployment (--no-p2p-relay / no coin peer): the same won block
//    still reaches the network via the submitblock backup alone, identical hex.
TEST(DashWonBlockDualPath, RpcOnlyDeploymentReachesNetwork)
{
    const auto block = make_block_bytes();
    const std::string block_hex = to_hex(block);

    std::string submitted_hex;
    int submit_calls = 0;
    RpcSubmitSink rpc = [&](const std::string& hex) -> bool {
        ++submit_calls; submitted_hex = hex; return true;
    };

    const auto r = broadcast_won_block(/*p2p=*/{}, rpc, block, block_hex);

    EXPECT_FALSE(r.p2p_sent);
    ASSERT_EQ(submit_calls, 1);
    EXPECT_TRUE(r.rpc_ok);
    EXPECT_EQ(submitted_hex, block_hex);
    EXPECT_STREQ(r.landed_first, "rpc");
    EXPECT_TRUE(r.any());
}

// 4) FAIL-LOUD end-to-end: a won block with NEITHER arm wired engages nothing
//    and reports any()==false -- the caller's LOUD "block NOT relayed" path, not
//    a silent drop.
TEST(DashWonBlockDualPath, NoArmsReachesNeitherSink)
{
    const auto block = make_block_bytes();
    const std::string block_hex = to_hex(block);

    const auto r = broadcast_won_block(/*p2p=*/{}, /*rpc=*/{}, block, block_hex);

    EXPECT_FALSE(r.p2p_sent);
    EXPECT_FALSE(r.rpc_ok);
    EXPECT_FALSE(r.any());
    EXPECT_STREQ(r.landed_first, "none");
}

// 5) DUAL-PATH RESILIENCE: a THROWING primary arm must NOT skip the backup --
//    the block still reaches the network via submitblock, no silent drop.
TEST(DashWonBlockDualPath, ThrowingPrimaryFallsThroughToBackup)
{
    const auto block = make_block_bytes();
    const std::string block_hex = to_hex(block);

    P2pRelaySink p2p = [&](const std::vector<unsigned char>&) {
        throw std::runtime_error("relay socket down");
    };
    std::string submitted_hex;
    RpcSubmitSink rpc = [&](const std::string& hex) -> bool {
        submitted_hex = hex; return true;
    };

    const auto r = broadcast_won_block(p2p, rpc, block, block_hex);

    EXPECT_FALSE(r.p2p_sent);          // primary threw -> not counted
    EXPECT_TRUE(r.rpc_ok);             // backup carried it
    EXPECT_EQ(submitted_hex, block_hex);
    EXPECT_TRUE(r.any());              // block still reached the network
    EXPECT_STREQ(r.landed_first, "rpc");
}
