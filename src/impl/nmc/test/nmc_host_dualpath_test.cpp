// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// nmc host-level dual-path won-aux broadcaster regression-lock (PE item 3,
// HOST-wiring half). NET-NEW vs the helper-level nmc_block_broadcast_test:
// that test hands raw std::function sinks straight to broadcast_won_aux_block
// and only checks sink PRESENCE. This one reconstructs the actual NMC run-loop
// binding -- exactly as src/c2pool/c2pool_refactored.cpp does -- and locks
// DELIVERY through both legs:
//   PRIMARY  : backend->set_block_relay([merged_broadcasters, chain_id]{...})
//              -> merged_broadcasters[chain_id]->submit_block_raw(bytes)
//              (host site c2pool_refactored.cpp:5276, returns relayed peers)
//   FALLBACK : mm_manager->set_fallback_backend(chain_id, AuxChainRPC)
//              -> AuxChainRPC::submit_aux_block(hash_hex, auxpow_hex)
//              (host site c2pool_refactored.cpp:5290 / merged_mining.cpp:454)
//
// Why a separate lock: a future refactor CAN silently drop the RPC fallback
// (delete set_fallback_backend), drop the P2P relay (delete set_block_relay),
// or MIS-KEY merged_broadcasters by chain_id -- and the helper test would stay
// green because the dispatcher's p2p_sent flag is presence-based, not delivery-
// based. host_dual_path_delivered() below asserts both networks were ACTUALLY
// reached, so each of those regressions turns this RED. That is the whole point
// of item 3's host-level lock vs the dispatcher contract slice.
//
// Test-only, fake sinks, zero consensus surface: no PoW hash, share format, aux
// commitment, template, or PPLNS math is touched. p2pool-merged-v36 surface:
// NONE. Per-coin isolation: src/impl/nmc/ only; consumes coin/block_broadcast.hpp
// (core/log.hpp only) -- pulls no btc/ or dgb/ symbol.
//
// MUST appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist
// or it becomes a #137/#143-style NOT_BUILT sentinel that reds master.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "../coin/block_broadcast.hpp"

namespace {

// Canonical won-aux payload (shared across cases).
const std::vector<unsigned char> kBytes(120, 0x42);
const std::string kHashHex   = "47589169f94e3e77bf4da8067e76b4417b021f0eb10760995671856f21b8d4b4";
const std::string kAuxpowHex = "0011223344556677";

// NMC aux chain_id SSOT (NMC_AUXPOW_CHAIN_ID=0x0001) vs DOGE's 0x0062 -- the
// keys the run-loop registers merged_broadcasters under. Used to exercise the
// host map-keying guard (a mis-key relays to nobody).
constexpr uint32_t kNmcChainId  = 0x0001;
constexpr uint32_t kDogeChainId = 0x0062;

// Fake of the embedded multi-peer P2P broadcaster registered in
// merged_broadcasters. The host set_block_relay closure calls submit_block_raw,
// which returns the relayed peer count (host site c2pool_refactored.cpp:5281).
struct FakeP2pBroadcaster {
    std::size_t peers = 4;
    int         calls = 0;
    std::vector<unsigned char> last_block;
    std::size_t submit_block_raw(const std::vector<unsigned char>& b) {
        ++calls;
        last_block = b;
        return peers;
    }
};

// Fake of c2pool::merged::AuxChainRPC, the fallback backend the host binds via
// set_fallback_backend. submit_aux_block fires submitauxblock and returns true
// on daemon accept OR harmless duplicate (merged_mining.cpp:454).
struct FakeAuxChainRpc {
    bool        accept = true;
    int         calls  = 0;
    std::string saw_hash, saw_auxpow;
    bool submit_aux_block(const std::string& h, const std::string& a) {
        ++calls;
        saw_hash   = h;
        saw_auxpow = a;
        return accept;
    }
};

// Reconstruct the NMC host dual-path wiring exactly as the run-loop does, then
// fire a won-aux block through nmc::coin::broadcast_won_aux_block.
//   bind_p2p_relay == false  models a refactor dropping backend->set_block_relay
//   fallback        == nullptr models dropping mm_manager->set_fallback_backend
// The P2P closure mirrors the host's lazy merged_broadcasters[chain_id] lookup
// AND its not-found guard (return 0 / relay to nobody) verbatim.
nmc::coin::AuxBlockBroadcast host_dispatch_won_aux(
    std::map<uint32_t, FakeP2pBroadcaster*>& merged_broadcasters,
    std::uint32_t chain_id,
    bool bind_p2p_relay,
    FakeAuxChainRpc* fallback,
    const std::vector<unsigned char>& bytes,
    const std::string& hash_hex,
    const std::string& auxpow_hex)
{
    nmc::coin::P2pRelaySink p2p;  // empty unless host bound set_block_relay
    if (bind_p2p_relay) {
        p2p = [&merged_broadcasters, chain_id](const std::vector<unsigned char>& b) {
            auto it = merged_broadcasters.find(chain_id);
            if (it == merged_broadcasters.end()) return;  // host guard: no peer reached
            it->second->submit_block_raw(b);
        };
    }
    nmc::coin::AuxRpcSink rpc;  // empty unless host bound set_fallback_backend
    if (fallback) {
        rpc = [fallback](const std::string& h, const std::string& a) {
            return fallback->submit_aux_block(h, a);
        };
    }
    return nmc::coin::broadcast_won_aux_block(p2p, rpc, bytes, hash_hex, auxpow_hex);
}

// The host dual-path invariant: a correctly-wired won-aux dispatch reaches BOTH
// networks. Presence of a sink is NOT enough -- a mis-keyed merged_broadcasters
// lookup leaves bc.p2p_sent==true yet relays to nobody, so we require the
// embedded broadcaster to have been ACTUALLY invoked (>=1 relay call) AND the
// submitauxblock fallback to have been invoked and acked. Dropping either
// binding (or mis-keying the map) flips this false -- that is the lock.
bool host_dual_path_delivered(const nmc::coin::AuxBlockBroadcast& bc,
                              int p2p_relay_calls,
                              int rpc_calls) {
    return bc.p2p_sent && p2p_relay_calls >= 1 && bc.rpc_ok && rpc_calls >= 1;
}

} // namespace

// 1) CANONICAL HOST WIRING -- both legs bound and correctly chain_id-keyed.
//    This is the positive lock: it goes RED if production drops a binding or
//    mis-keys the broadcaster map. Both networks are actually reached and each
//    leg is handed the exact payload.
TEST(NmcHostDualPath, BindsBothLegsAndDeliversToBothNetworks) {
    FakeP2pBroadcaster p2p;
    FakeAuxChainRpc    rpc;
    std::map<std::uint32_t, FakeP2pBroadcaster*> merged_broadcasters{{kNmcChainId, &p2p}};

    auto bc = host_dispatch_won_aux(merged_broadcasters, kNmcChainId,
                                    /*bind_p2p_relay=*/true, &rpc,
                                    kBytes, kHashHex, kAuxpowHex);

    // Both legs DELIVERED -- the host-level invariant.
    EXPECT_TRUE(host_dual_path_delivered(bc, p2p.calls, rpc.calls));

    // Primary P2P leg actually relayed the exact block to the peer broadcaster.
    EXPECT_EQ(p2p.calls, 1);
    EXPECT_EQ(p2p.last_block, kBytes);
    EXPECT_TRUE(bc.p2p_sent);

    // Fallback RPC leg fired ALWAYS with the exact (hash, auxpow) payload.
    EXPECT_EQ(rpc.calls, 1);
    EXPECT_EQ(rpc.saw_hash, kHashHex);
    EXPECT_EQ(rpc.saw_auxpow, kAuxpowHex);
    EXPECT_TRUE(bc.rpc_ok);

    EXPECT_TRUE(bc.any());
    EXPECT_STREQ(bc.landed_first, "p2p");  // primary won the race
}

// 2) REGRESSION: a refactor deletes backend->set_block_relay. The P2P sink is
//    never bound; only the submitauxblock fallback carries the block. The host
//    invariant must catch the missing primary leg.
TEST(NmcHostDualPath, DropP2pRelayBindingIsCaught) {
    FakeP2pBroadcaster p2p;
    FakeAuxChainRpc    rpc;
    std::map<std::uint32_t, FakeP2pBroadcaster*> merged_broadcasters{{kNmcChainId, &p2p}};

    auto bc = host_dispatch_won_aux(merged_broadcasters, kNmcChainId,
                                    /*bind_p2p_relay=*/false, &rpc,
                                    kBytes, kHashHex, kAuxpowHex);

    EXPECT_FALSE(host_dual_path_delivered(bc, p2p.calls, rpc.calls));  // LOCK fires
    EXPECT_FALSE(bc.p2p_sent);
    EXPECT_EQ(p2p.calls, 0);          // embedded peer never reached
    EXPECT_TRUE(bc.rpc_ok);           // fallback alone saved the won block
    EXPECT_EQ(rpc.calls, 1);
    EXPECT_TRUE(bc.any());
    EXPECT_STREQ(bc.landed_first, "rpc");
}

// 3) REGRESSION: a refactor deletes mm_manager->set_fallback_backend. The RPC
//    fallback is never bound; only the embedded P2P relay carries. The host
//    invariant must catch the missing fallback leg.
TEST(NmcHostDualPath, DropFallbackBindingIsCaught) {
    FakeP2pBroadcaster p2p;
    std::map<std::uint32_t, FakeP2pBroadcaster*> merged_broadcasters{{kNmcChainId, &p2p}};

    auto bc = host_dispatch_won_aux(merged_broadcasters, kNmcChainId,
                                    /*bind_p2p_relay=*/true, /*fallback=*/nullptr,
                                    kBytes, kHashHex, kAuxpowHex);

    EXPECT_FALSE(host_dual_path_delivered(bc, p2p.calls, /*rpc_calls=*/0));  // LOCK fires
    EXPECT_FALSE(bc.rpc_ok);
    EXPECT_TRUE(bc.p2p_sent);          // primary alone carried
    EXPECT_EQ(p2p.calls, 1);
    EXPECT_EQ(p2p.last_block, kBytes);
    EXPECT_TRUE(bc.any());
    EXPECT_STREQ(bc.landed_first, "p2p");
}

// 4) REGRESSION (host map-keying): both legs are bound, but the run-loop
//    registers the embedded broadcaster under the wrong chain_id (here DOGE's
//    0x0062 while dispatching the NMC 0x0001 win). The dispatcher's p2p_sent
//    stays TRUE -- the sink is present -- yet submit_block_raw is NEVER reached,
//    so the won block silently fails to relay over P2P. Only a DELIVERY-level
//    invariant catches this; the helper-level presence check cannot. The
//    fallback still saves the block, which is exactly why this is insidious.
TEST(NmcHostDualPath, MiskeyedChainIdSilentlyDropsP2pButLockCatchesIt) {
    FakeP2pBroadcaster p2p;
    FakeAuxChainRpc    rpc;
    std::map<std::uint32_t, FakeP2pBroadcaster*> merged_broadcasters{{kDogeChainId, &p2p}};

    auto bc = host_dispatch_won_aux(merged_broadcasters, kNmcChainId,
                                    /*bind_p2p_relay=*/true, &rpc,
                                    kBytes, kHashHex, kAuxpowHex);

    EXPECT_TRUE(bc.p2p_sent);          // sink PRESENT -- helper test would pass here
    EXPECT_EQ(p2p.calls, 0);           // ...but the peer broadcaster was never hit
    EXPECT_FALSE(host_dual_path_delivered(bc, p2p.calls, rpc.calls));  // LOCK fires
    EXPECT_TRUE(bc.rpc_ok);            // fallback masked the silent P2P drop
    EXPECT_EQ(rpc.calls, 1);
}

// 5) REGRESSION (both bindings dropped): neither leg bound -> never silent-drop.
//    The dispatcher screams (lost-subsidy ERROR) and reports any()==false; no
//    sink is invoked.
TEST(NmcHostDualPath, NeitherLegBoundNeverSilentDrops) {
    FakeP2pBroadcaster p2p;
    std::map<std::uint32_t, FakeP2pBroadcaster*> merged_broadcasters{{kNmcChainId, &p2p}};

    auto bc = host_dispatch_won_aux(merged_broadcasters, kNmcChainId,
                                    /*bind_p2p_relay=*/false, /*fallback=*/nullptr,
                                    kBytes, kHashHex, kAuxpowHex);

    EXPECT_FALSE(host_dual_path_delivered(bc, p2p.calls, /*rpc_calls=*/0));
    EXPECT_FALSE(bc.any());
    EXPECT_FALSE(bc.p2p_sent);
    EXPECT_FALSE(bc.rpc_ok);
    EXPECT_EQ(p2p.calls, 0);
    EXPECT_STREQ(bc.landed_first, "none");
}