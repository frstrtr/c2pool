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
#include <impl/dash/coin/coin_p2p_magic.hpp>

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
    P2pRelaySink p2p = [&](const std::vector<unsigned char>& b) -> bool {
        did_relay = true; relayed = b; return true;   // connected peer -> relayed
    };

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
    P2pRelaySink p2p = [&](const std::vector<unsigned char>& b) -> bool {
        relayed = b; return true;   // connected peer -> relayed
    };

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

    P2pRelaySink p2p = [&](const std::vector<unsigned char>&) -> bool {
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

// 6) H1 HONEST REPORTING: a DISCONNECTED coin-P2P peer makes submit_block_p2p_raw
//    silently drop the block, so the relay sink reports false. The dispatcher must
//    NOT claim p2p_sent -- it relies on the submitblock RPC backup, and
//    landed_first is "rpc", never a false "p2p". (Before the fix the sink returned
//    void and p2p_sent was set true unconditionally: a lost subsidy logged as a win.)
TEST(DashWonBlockDualPath, DisconnectedP2pNotClaimedRelaysViaBackup)
{
    const auto block = make_block_bytes();
    const std::string block_hex = to_hex(block);

    // The sink reports the peer is not connected -> NOT relayed.
    bool relay_attempted = false;
    P2pRelaySink p2p = [&](const std::vector<unsigned char>&) -> bool {
        relay_attempted = true;
        return false;   // coin-P2P peer disconnected: silent-drop territory
    };
    std::string submitted_hex;
    RpcSubmitSink rpc = [&](const std::string& hex) -> bool {
        submitted_hex = hex; return true;
    };

    const auto r = broadcast_won_block(p2p, rpc, block, block_hex);

    EXPECT_TRUE(relay_attempted);
    EXPECT_FALSE(r.p2p_sent);           // honest: the disconnected arm did NOT send
    EXPECT_TRUE(r.rpc_ok);              // backup carried it
    EXPECT_EQ(submitted_hex, block_hex);
    EXPECT_STREQ(r.landed_first, "rpc");   // NOT a false "p2p"
    EXPECT_TRUE(r.any());
}

// 7) H1 fail-loud: a disconnected P2P arm AND no RPC backup => the block reached
//    NEITHER sink. any()==false and p2p_sent must be honest (false), so the caller
//    takes the LOUD "block NOT relayed" path instead of a silent lost subsidy.
TEST(DashWonBlockDualPath, DisconnectedP2pWithNoBackupReachesNeither)
{
    const auto block = make_block_bytes();
    const std::string block_hex = to_hex(block);

    P2pRelaySink p2p = [&](const std::vector<unsigned char>&) -> bool {
        return false;   // disconnected
    };

    const auto r = broadcast_won_block(p2p, /*rpc=*/{}, block, block_hex);

    EXPECT_FALSE(r.p2p_sent);
    EXPECT_FALSE(r.rpc_ok);
    EXPECT_FALSE(r.any());              // LOUD "block NOT relayed", never a silent win
    EXPECT_STREQ(r.landed_first, "none");
}

// ── RPC-FIRST GATE for stale / height-race blocks (prefer_rpc_first) ─────────

// 8) HEIGHT-RACE ORDERING: with a dashd RPC arm armed, a race block is validated
//    RPC-FIRST and the coin-P2P relay fires ONLY AFTER dashd accepts. Pins the
//    ordering (RPC call precedes the relay) and that a valid race block still
//    reaches BOTH arms so we race the network.
TEST(DashWonBlockDualPath, HeightRaceIsRpcFirstThenRelaysOnAccept)
{
    const auto block = make_block_bytes();
    const std::string block_hex = to_hex(block);

    int seq = 0;
    int rpc_order = 0, relay_order = 0;
    std::string submitted_hex;

    RpcSubmitSink rpc = [&](const std::string& hex) -> bool {
        rpc_order = ++seq; submitted_hex = hex; return true;   // dashd ACCEPTS
    };
    std::vector<unsigned char> relayed;
    P2pRelaySink p2p = [&](const std::vector<unsigned char>& b) -> bool {
        relay_order = ++seq; relayed = b; return true;
    };

    const auto r = broadcast_won_block(p2p, rpc, block, block_hex,
                                       /*prefer_rpc_first=*/true);

    // ORDER: dashd validated FIRST, then the relay fired.
    ASSERT_EQ(rpc_order, 1);
    ASSERT_EQ(relay_order, 2);
    // Valid race block -> both arms carry it; landed_first is the RPC validation.
    EXPECT_TRUE(r.rpc_ok);
    EXPECT_TRUE(r.p2p_sent);
    EXPECT_EQ(relayed, block);
    EXPECT_EQ(submitted_hex, block_hex);
    EXPECT_STREQ(r.landed_first, "rpc");
    EXPECT_TRUE(r.any());
}

// 9) HEIGHT-RACE INVALID: dashd REJECTS the race block -> the coin-P2P relay is
//    NEVER invoked (no unvalidated block pushed to peers -> no ban exposure).
//    The block is rejected locally for free; any()==false (LOUD not-relayed path).
TEST(DashWonBlockDualPath, HeightRaceRejectedByDashdIsNotRelayedToPeers)
{
    const auto block = make_block_bytes();
    const std::string block_hex = to_hex(block);

    RpcSubmitSink rpc = [&](const std::string&) -> bool {
        return false;   // dashd REJECTS: invalid at the block's real height
    };
    bool relay_attempted = false;
    P2pRelaySink p2p = [&](const std::vector<unsigned char>&) -> bool {
        relay_attempted = true; return true;
    };

    const auto r = broadcast_won_block(p2p, rpc, block, block_hex,
                                       /*prefer_rpc_first=*/true);

    EXPECT_FALSE(relay_attempted);      // GATED: never relayed an invalid race block
    EXPECT_FALSE(r.p2p_sent);
    EXPECT_FALSE(r.rpc_ok);
    EXPECT_FALSE(r.any());              // rejected locally for free
    EXPECT_STREQ(r.landed_first, "none");
}

// 10) HEIGHT-RACE DAEMONLESS: no RPC arm to validate against, so the RPC-first
//     gate does NOT apply -- ARM A relays anyway (it is the ONLY route to the
//     network; dropping a winnable block would be a guaranteed loss).
TEST(DashWonBlockDualPath, HeightRaceDaemonlessStillRelaysPrimary)
{
    const auto block = make_block_bytes();
    const std::string block_hex = to_hex(block);

    std::vector<unsigned char> relayed;
    P2pRelaySink p2p = [&](const std::vector<unsigned char>& b) -> bool {
        relayed = b; return true;
    };

    const auto r = broadcast_won_block(p2p, /*rpc=*/{}, block, block_hex,
                                       /*prefer_rpc_first=*/true);

    EXPECT_TRUE(r.p2p_sent);            // relay-first fallback: the only path
    EXPECT_FALSE(r.rpc_ok);
    EXPECT_EQ(relayed, block);
    EXPECT_STREQ(r.landed_first, "p2p");
    EXPECT_TRUE(r.any());
}

// 8) E5 --coin-p2p-magic override: the embedded coin-P2P wire magic selector.
//    No override -> the mainnet/testnet defaults are returned BYTE-FOR-BYTE
//    unchanged (guards the production ARM A dial from regression). An override
//    (regtest fcc1b7dc) is honoured verbatim so ARM A can dial a regtest dashd
//    for the live-accept harness. Transport-only; the defaults must never move.
TEST(DashWonBlockDualPath, CoinP2pMagicSelectorDefaultsUnchanged)
{
    // No override: canonical dashd pchMessageStart per net, unchanged.
    EXPECT_EQ(dash::coin::select_coin_p2p_magic("", /*testnet=*/false), "bf0c6bbd");
    EXPECT_EQ(dash::coin::select_coin_p2p_magic("", /*testnet=*/true),  "cee2caff");
}

TEST(DashWonBlockDualPath, CoinP2pMagicSelectorOverrideHonoured)
{
    // Explicit override (regtest V1 magic) wins on both net flags -- the E5
    // harness lever that lets ARM A dial a regtest coin daemon.
    EXPECT_EQ(dash::coin::select_coin_p2p_magic("fcc1b7dc", /*testnet=*/true),  "fcc1b7dc");
    EXPECT_EQ(dash::coin::select_coin_p2p_magic("fcc1b7dc", /*testnet=*/false), "fcc1b7dc");
}
