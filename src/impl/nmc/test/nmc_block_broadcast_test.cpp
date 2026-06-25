// ---------------------------------------------------------------------------
// nmc::coin::broadcast_won_aux_block dual-path dispatcher test (PE item 3,
// broadcaster-gate dispatcher half).
//
// Offline contract slice mirroring src/impl/dgb/test/block_broadcast_test.cpp.
// Locks the dual-path rule the NMC run-loop depends on when it wires the
// won-aux-block trigger to this dispatcher: BOTH the embedded P2P relay
// (PRIMARY) and the external namecoind submitauxblock (FALLBACK, fired ALWAYS)
// are attempted, each leg is guarded, landed_first records the race winner, and
// with NEITHER sink live the call is a safe no-op (any()=false, no throw, no
// silent-drop of a won block). Uses std::function fakes so the dispatch
// contract is verified without the live .140 namecoind submitauxblock client
// (the next PE item-3 slice). p2pool-merged-v36 surface: NONE.
//
// MUST appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist
// or it becomes a #137-style NOT_BUILT sentinel that reds master.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <stdexcept>

#include <string>
#include <vector>

#include "../coin/block_broadcast.hpp"

namespace {

const std::vector<unsigned char> kBytes(120, 0x42);
const std::string                kHashHex   = "47589169f94e3e77bf4da8067e76b4417b021f0eb10760995671856f21b8d4b4";
const std::string                kAuxpowHex = "0011223344556677";

} // namespace

// 1) NEITHER sink live -> safe no-op: any()=false, landed_first="none", no throw,
//    an unset sink is never invoked (no silent-drop, the ERROR scream fires).
TEST(NmcAuxBlockBroadcast, NoSinkLiveIsSafeNoOp) {
    auto r = nmc::coin::broadcast_won_aux_block(/*p2p_relay=*/{}, /*aux_rpc=*/{},
                                                kBytes, kHashHex, kAuxpowHex);
    EXPECT_FALSE(r.p2p_sent);
    EXPECT_FALSE(r.rpc_ok);
    EXPECT_FALSE(r.any());
    EXPECT_STREQ(r.landed_first, "none");
}

// 2) P2P-only: relay sink present, no RPC -> p2p wins, fallback skipped cleanly.
TEST(NmcAuxBlockBroadcast, P2pOnly) {
    bool relayed = false;
    std::vector<unsigned char> seen;
    auto relay = [&](const std::vector<unsigned char>& b) { relayed = true; seen = b; };

    auto r = nmc::coin::broadcast_won_aux_block(relay, /*aux_rpc=*/{},
                                                kBytes, kHashHex, kAuxpowHex);
    EXPECT_TRUE(relayed);
    EXPECT_EQ(seen, kBytes);
    EXPECT_TRUE(r.p2p_sent);
    EXPECT_FALSE(r.rpc_ok);
    EXPECT_TRUE(r.any());
    EXPECT_STREQ(r.landed_first, "p2p");
}

// 3) RPC-only: no embedded P2P sink, submitauxblock accepts -> fallback wins the
//    race, and it is handed the exact (hash, auxpow) payload.
TEST(NmcAuxBlockBroadcast, RpcOnly) {
    int  calls = 0;
    std::string saw_hash, saw_auxpow;
    auto aux_rpc = [&](const std::string& h, const std::string& a) {
        ++calls; saw_hash = h; saw_auxpow = a; return true;
    };

    auto r = nmc::coin::broadcast_won_aux_block(/*p2p_relay=*/{}, aux_rpc,
                                                kBytes, kHashHex, kAuxpowHex);
    EXPECT_FALSE(r.p2p_sent);
    EXPECT_TRUE(r.rpc_ok);
    EXPECT_TRUE(r.any());
    EXPECT_STREQ(r.landed_first, "rpc");
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(saw_hash, kHashHex);
    EXPECT_EQ(saw_auxpow, kAuxpowHex);
}

// 4) DUAL-PATH: both sinks live -> p2p wins landed_first, but the submitauxblock
//    RPC fallback STILL fires (the always-fire rule), and a duplicate accept
//    there is success, not a masked P2P win.
TEST(NmcAuxBlockBroadcast, DualPathAlwaysFiresFallback) {
    bool relayed = false;
    auto relay = [&](const std::vector<unsigned char>&) { relayed = true; };
    int  calls = 0;
    auto aux_rpc = [&](const std::string&, const std::string&) { ++calls; return true; };

    auto r = nmc::coin::broadcast_won_aux_block(relay, aux_rpc,
                                                kBytes, kHashHex, kAuxpowHex);
    EXPECT_TRUE(relayed);
    EXPECT_TRUE(r.p2p_sent);
    EXPECT_TRUE(r.rpc_ok);                // fallback fired even though P2P won
    EXPECT_EQ(calls, 1);                  // ALWAYS-fired, not a P2P-only catch
    EXPECT_STREQ(r.landed_first, "p2p");  // primary won the race
}

// 5) Both sinks present but submitauxblock no-acks (rejected): p2p still carried
//    the block, rpc_ok=false, any()=true (the P2P leg succeeded).
TEST(NmcAuxBlockBroadcast, FallbackNoAckDoesNotMaskP2p) {
    auto relay = [&](const std::vector<unsigned char>&) {};
    int  calls = 0;
    auto aux_rpc = [&](const std::string&, const std::string&) { ++calls; return false; };

    auto r = nmc::coin::broadcast_won_aux_block(relay, aux_rpc,
                                                kBytes, kHashHex, kAuxpowHex);
    EXPECT_TRUE(r.p2p_sent);
    EXPECT_FALSE(r.rpc_ok);
    EXPECT_TRUE(r.any());
    EXPECT_STREQ(r.landed_first, "p2p");
    EXPECT_EQ(calls, 1);
}


// 6) PRIMARY-LEG GUARD: a throwing embedded P2P relay sink must NOT prevent the
//    ALWAYS-fire submitauxblock RPC fallback -- the won aux block still reaches
//    namecoind via the safety net, p2p_sent stays false (the relay never
//    actually sent), any()=true (NOT silent-dropped), and the dispatcher does
//    not propagate the throw. Locks the doc-comment "each leg is guarded so the
//    dispatcher never throws" contract that the un-guarded impl violated.
TEST(NmcAuxBlockBroadcast, ThrowingP2pStillFiresRpcFallback) {
    auto relay = [&](const std::vector<unsigned char>&) {
        throw std::runtime_error("p2p relay down mid-teardown");
    };
    int  calls = 0;
    auto aux_rpc = [&](const std::string&, const std::string&) { ++calls; return true; };

    nmc::coin::AuxBlockBroadcast r;
    EXPECT_NO_THROW(r = nmc::coin::broadcast_won_aux_block(relay, aux_rpc,
                                                           kBytes, kHashHex, kAuxpowHex));
    EXPECT_FALSE(r.p2p_sent);             // relay threw -> never marked sent
    EXPECT_TRUE(r.rpc_ok);                // always-fire fallback STILL fired
    EXPECT_EQ(calls, 1);
    EXPECT_TRUE(r.any());                 // won block was NOT silent-dropped
    EXPECT_STREQ(r.landed_first, "rpc");  // fallback carried it
}

// 7) FALLBACK-LEG GUARD: a throwing submitauxblock RPC sink must not propagate
//    and must not mask a P2P win already recorded -- rpc_ok=false, the P2P win
//    still stands (landed_first="p2p", any()=true).
TEST(NmcAuxBlockBroadcast, ThrowingRpcDoesNotMaskP2pWin) {
    bool relayed = false;
    auto relay = [&](const std::vector<unsigned char>&) { relayed = true; };
    auto aux_rpc = [&](const std::string&, const std::string&) -> bool {
        throw std::runtime_error("submitauxblock client socket reset");
    };

    nmc::coin::AuxBlockBroadcast r;
    EXPECT_NO_THROW(r = nmc::coin::broadcast_won_aux_block(relay, aux_rpc,
                                                           kBytes, kHashHex, kAuxpowHex));
    EXPECT_TRUE(relayed);
    EXPECT_TRUE(r.p2p_sent);
    EXPECT_FALSE(r.rpc_ok);
    EXPECT_TRUE(r.any());
    EXPECT_STREQ(r.landed_first, "p2p");
}
