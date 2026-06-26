// ---------------------------------------------------------------------------
// broadcast_convergence_matrix_test.cpp
//
// §5 DELEGATION-EQUIVALENCE CHARACTERIZATION KAT (v37 precondition guard).
//
// PURE CHARACTERIZATION of the CURRENT cross-coin won-block broadcast matrix as
// it behaves TODAY on master. It asserts the PRESENT behaviour only -- it adds
// NO new guard logic and grows NO SSOT. It locks the two distinct broadcast
// POLICIES the v37 "one datastructure, per-instance config" convergence must
// PRESERVE (never silently collapse) when the bucket-1/bucket-2 split becomes a
// per-instance parameter:
//
//   POLICY A -- SHORT-CIRCUIT / no-double-broadcast (single-chain won block):
//     core::broadcast_block_with_fallback (the merged #498 core SSOT). P2P
//     relay is PRIMARY; the submitblock RPC FALLBACK fires ONLY when P2P did
//     not succeed. BTC delegates to it verbatim
//     (btc::coin::broadcast_block_with_fallback).
//
//   POLICY B -- ALWAYS-FIRE fallback (the bucket-2 dual-path dispatchers):
//     NMC / DGB / BCH fire the external-daemon RPC leg ALWAYS, even after a P2P
//     win (a duplicate submit is a harmless daemon rejection, never a silent
//     drop). NMC's always-fire is CONSENSUS-LOAD-BEARING: submitauxblock hits a
//     SEPARATE aux chain (#500 bucket-1 classification) -- short-circuiting it
//     onto Policy A would DROP the aux block. DGB/BCH always-fire is a
//     redundant-duplicate robustness leg on the SAME chain.
//
//   BCH sub-distinction -- sink-ABSENT != sink-FAILED: a leg with no sink wired
//     (have_rpc=false) is NOT attempted; a present-but-throwing sink IS
//     attempted and collapses to rpc_ok=false. Both end at rpc_ok=false but the
//     two are NOT the same event.
//
// NOTE on coverage: DASH carries the same Policy-B always-fire shape
// (broadcaster_full.hpp ARM B submitblock fired regardless; reached_network =
// peers||rpc), but its dispatcher is a stateful class over the dash P2P stack,
// not a header-only pure function -- locking it belongs in a dash-tree test
// (none exists yet), NOT pulled into core_test. Flagged as a follow-up so this
// file stays standalone/SAFE-ADDITIVE.
//
// This is a SAFE-ADDITIVE regression guard on its own merit (it locks the
// present matrix); it is NOT forward-implementation of v37 §5. It references
// only already-merged headers and modifies NO coin tree.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <stdexcept>
#include <string>
#include <vector>

#include <core/block_broadcast.hpp>
#include <core/coin/node_iface.hpp>

#include "../../impl/btc/coin/block_broadcast.hpp"
#include "../../impl/nmc/coin/block_broadcast.hpp"
#include "../../impl/dgb/coin/block_broadcast.hpp"
#include "../../impl/bch/coin/block_broadcast_guard.hpp"

namespace {

// A minimal ICoinNode fake for the DGB seam: counts submitblock calls so we can
// prove the always-fire fallback ran. get_work_view() is unused here.
struct FakeCoinNode : core::coin::ICoinNode {
    int  submit_calls = 0;
    bool rpc_present  = true;
    bool accept       = true;
    core::coin::WorkView get_work_view() override { throw std::runtime_error("unused"); }
    bool submit_block_hex(const std::string&, bool) override { ++submit_calls; return accept; }
    bool is_embedded() const override { return false; }
    bool has_rpc() const override { return rpc_present; }
};

// === POLICY A: BTC delegates to the core short-circuit SSOT =================
// A P2P win MUST NOT fire the submitblock RPC fallback (no double-broadcast),
// and BTC's entry point must behave identically to the core symbol it delegates
// to.

TEST(BroadcastConvergenceMatrix, BtcPolicyA_P2pWinShortCircuitsFallback) {
    bool core_rpc = false, btc_rpc = false;
    bool core_ok = core::broadcast_block_with_fallback(
        [] { return true; }, [&] { core_rpc = true; return true; });
    bool btc_ok = btc::coin::broadcast_block_with_fallback(
        [] { return true; }, [&] { btc_rpc = true; return true; });
    EXPECT_TRUE(core_ok);
    EXPECT_TRUE(btc_ok);
    EXPECT_FALSE(core_rpc) << "core SSOT must short-circuit the RPC after a P2P win";
    EXPECT_FALSE(btc_rpc)  << "BTC must inherit the short-circuit (verbatim delegate)";
}

TEST(BroadcastConvergenceMatrix, BtcPolicyA_P2pFailFiresFallbackExactlyOnce) {
    int rpc_calls = 0;
    EXPECT_TRUE(btc::coin::broadcast_block_with_fallback(
        [] { return false; }, [&] { ++rpc_calls; return true; }));
    EXPECT_EQ(rpc_calls, 1) << "BTC fallback fires ONLY when P2P did not succeed";
}

// === POLICY B (NMC): always-fire, CONSENSUS-LOAD-BEARING aux leg ============
// submitauxblock fires EVEN AFTER a P2P win -- the load-bearing divergence from
// Policy A (#500 bucket-1: a SEPARATE aux chain; short-circuit == aux drop).

TEST(BroadcastConvergenceMatrix, NmcPolicyB_AlwaysFiresAuxRpcAfterP2pWin) {
    int p2p_calls = 0, rpc_calls = 0;
    auto r = nmc::coin::broadcast_won_aux_block(
        [&](const std::vector<unsigned char>&) { ++p2p_calls; },
        [&](const std::string&, const std::string&) { ++rpc_calls; return true; },
        {0x01, 0x02}, "deadbeef", "auxpowhex");
    EXPECT_EQ(p2p_calls, 1);
    EXPECT_EQ(rpc_calls, 1) << "NMC submitauxblock MUST fire even after a P2P win (aux chain)";
    EXPECT_TRUE(r.p2p_sent);
    EXPECT_TRUE(r.rpc_ok);
    EXPECT_STREQ(r.landed_first, "p2p");
}

TEST(BroadcastConvergenceMatrix, NmcPolicyB_ThrowingP2pStillFiresAuxRpc) {
    int rpc_calls = 0;
    auto r = nmc::coin::broadcast_won_aux_block(
        [](const std::vector<unsigned char>&) { throw std::runtime_error("relay blew up"); },
        [&](const std::string&, const std::string&) { ++rpc_calls; return true; },
        {0x01}, "hash", "aux");
    EXPECT_FALSE(r.p2p_sent);
    EXPECT_EQ(rpc_calls, 1) << "throwing P2P must not bypass the always-fire aux RPC";
    EXPECT_TRUE(r.rpc_ok);
    EXPECT_STREQ(r.landed_first, "rpc");
}

TEST(BroadcastConvergenceMatrix, NmcPolicyB_NeitherSinkScreams) {
    auto r = nmc::coin::broadcast_won_aux_block(
        nmc::coin::P2pRelaySink{}, nmc::coin::AuxRpcSink{},
        {0x01}, "hash", "aux");
    EXPECT_FALSE(r.any()) << "no sink wired -> never-silent-drop scream path (any()==false)";
    EXPECT_STREQ(r.landed_first, "none");
}

// === POLICY B (DGB): always-fire redundant submitblock on the SAME chain ====

TEST(BroadcastConvergenceMatrix, DgbPolicyB_AlwaysFiresRpcAfterP2pWin) {
    FakeCoinNode node;
    int p2p_calls = 0;
    auto r = dgb::coin::broadcast_won_block(
        [&](const std::vector<unsigned char>&) { ++p2p_calls; },
        &node, {0x01, 0x02}, "blockhex");
    EXPECT_EQ(p2p_calls, 1);
    EXPECT_EQ(node.submit_calls, 1) << "DGB submitblock fallback fires even after a P2P win";
    EXPECT_TRUE(r.p2p_sent);
    EXPECT_TRUE(r.rpc_ok);
    EXPECT_STREQ(r.landed_first, "p2p");
}

// === POLICY B (BCH): always-fire + sink-ABSENT != sink-FAILED ===============

TEST(BroadcastConvergenceMatrix, BchPolicyB_AlwaysFiresRpcAfterP2pWin) {
    int p2p_calls = 0, rpc_calls = 0;
    auto r = bch::coin::guarded_dual_broadcast(
        /*have_p2p=*/true, [&] { ++p2p_calls; },
        /*have_rpc=*/true, [&] { ++rpc_calls; return true; });
    EXPECT_EQ(p2p_calls, 1);
    EXPECT_EQ(rpc_calls, 1) << "BCH submitblock fallback fires even after a P2P win";
    EXPECT_TRUE(r.p2p_sent);
    EXPECT_TRUE(r.rpc_ok);
}

TEST(BroadcastConvergenceMatrix, BchPolicyB_SinkAbsentIsNotSinkFailed) {
    // ABSENT: have_rpc=false -> the RPC leg is NOT attempted at all.
    int rpc_calls_absent = 0;
    auto absent = bch::coin::guarded_dual_broadcast(
        /*have_p2p=*/true, [] {},
        /*have_rpc=*/false, [&] { ++rpc_calls_absent; return true; });
    EXPECT_EQ(rpc_calls_absent, 0) << "absent sink must NOT be invoked";
    EXPECT_FALSE(absent.rpc_ok);

    // FAILED: have_rpc=true but the sink throws -> it IS attempted, then
    // collapses to rpc_ok=false. Same rpc_ok value as ABSENT, DIFFERENT event.
    int rpc_calls_failed = 0;
    auto failed = bch::coin::guarded_dual_broadcast(
        /*have_p2p=*/true, [] {},
        /*have_rpc=*/true, [&]() -> bool {
            ++rpc_calls_failed; throw std::runtime_error("rpc blew up");
        });
    EXPECT_EQ(rpc_calls_failed, 1) << "present-but-failing sink IS attempted (failed != absent)";
    EXPECT_FALSE(failed.rpc_ok);

    // The recorded P2P win is preserved in BOTH cases (never masked by the RPC
    // leg's absence or failure).
    EXPECT_TRUE(absent.p2p_sent);
    EXPECT_TRUE(failed.p2p_sent);
}

} // namespace
