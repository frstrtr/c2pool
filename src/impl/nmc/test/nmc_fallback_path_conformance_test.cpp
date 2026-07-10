// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// nmc PF fallback-path conformance lock (Phase PF, external-daemon-fallback half).
//
// V36 per-coin invariant (v36-master-plan external_fallback): "an EXTERNAL-DAEMON
// FALLBACK (RPC to a real coind / MM-Adapter) MUST PERSIST in every coin's c2pool
// -- embedded is default, external is the RETAINED fallback path. Do NOT remove
// external-daemon code paths." For NMC the retained fallback is the .140 testnet
// namecoind `submitauxblock` RPC, bound by the run-loop as the AuxRpcSink.
//
// NET-NEW vs nmc_block_broadcast_test (dispatcher contract) and
// nmc_host_dualpath_test (host wiring DELIVERY): both of those bind the fallback
// leg to a fake that ALWAYS ACKS, so neither distinguishes WHICH backend the
// fallback is. This file locks the one conformance fact PF owns: the fallback
// MUST be the EXTERNAL namecoind RPC (a real daemon that can ack), and MUST NOT
// be the embedded backend's own submit_aux_block -- which is structurally
// daemon-less and returns false unconditionally (aux_chain_embedded.hpp:153,
// "no daemon to submit to; embedded RPC leg cannot broadcast, returning false").
//
// The trap: a refactor that "simplifies" set_fallback_backend to point at the
// embedded AuxChainEmbedded::submit_aux_block leaves the wiring LOOKING present
// (a sink is bound, nmc_host_dualpath stays green on its always-ack fake) but
// turns the retained fallback into a dead path: when the embedded P2P relay is
// down, a won aux block is then SILENTLY LOST. This file makes that regression
// RED. Test-only, std::function fakes, zero consensus surface (no PoW hash,
// share format, aux commitment, template, or PPLNS math). p2pool-merged-v36
// surface: NONE. Per-coin isolation: src/impl/nmc/ only; consumes
// coin/block_broadcast.hpp (core/log.hpp only) -- pulls no btc/ or dgb/ symbol.
//
// MUST appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist
// or it becomes a #137/#143-style NOT_BUILT sentinel that reds master.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../coin/block_broadcast.hpp"

namespace {

const std::vector<unsigned char> kBytes(120, 0x42);
const std::string kHashHex   = "47589169f94e3e77bf4da8067e76b4417b021f0eb10760995671856f21b8d4b4";
const std::string kAuxpowHex = "0011223344556677";

// Models c2pool::merged::AuxChainRPC -- the EXTERNAL .140 namecoind submitauxblock
// client the run-loop binds via set_fallback_backend. A real daemon ACKS (true)
// on accept OR harmless duplicate (merged_mining.cpp:454). This is the RETAINED
// external fallback the V36 invariant requires.
struct ExternalNamecoindRpc {
    int calls = 0;
    bool submit_aux_block(const std::string&, const std::string&) { ++calls; return true; }
};

// Models AuxChainEmbedded::submit_aux_block (aux_chain_embedded.hpp:153): the
// EMBEDDED backend has no daemon to RPC, so its RPC leg cannot broadcast and
// returns false UNCONDITIONALLY. Wiring THIS as the fallback is the conformance
// violation -- it is not the external daemon, it is the embedded self-leg.
struct EmbeddedSelfRpcLeg {
    int calls = 0;
    bool submit_aux_block(const std::string&, const std::string&) { ++calls; return false; }
};

} // namespace

// 1) RETAINED EXTERNAL FALLBACK CARRIES when the embedded P2P relay is down.
//    The external namecoind submitauxblock saves the won aux block: rpc_ok=true,
//    any()=true, it won the race. This is the path the V36 external_fallback
//    invariant says must PERSIST.
TEST(NmcPfFallbackPath, ExternalDaemonFallbackCarriesWhenEmbeddedP2pDown) {
    ExternalNamecoindRpc ext;
    nmc::coin::AuxRpcSink rpc = [&](const std::string& h, const std::string& a) {
        return ext.submit_aux_block(h, a);
    };

    // P2P relay sink empty == embedded relay down / no peers route.
    auto r = nmc::coin::broadcast_won_aux_block(/*p2p_relay=*/{}, rpc,
                                                kBytes, kHashHex, kAuxpowHex);
    EXPECT_FALSE(r.p2p_sent);
    EXPECT_TRUE(r.rpc_ok);                 // external daemon acked
    EXPECT_TRUE(r.any());                  // won block NOT lost
    EXPECT_STREQ(r.landed_first, "rpc");
    EXPECT_EQ(ext.calls, 1);
}

// 2) CONFORMANCE LOCK: the embedded backend's own submit_aux_block CANNOT serve
//    as the fallback. It is daemon-less and returns false unconditionally, so if
//    a refactor mis-wires set_fallback_backend to it, then with the embedded P2P
//    relay also down the won aux block is SILENTLY LOST (any()=false). This is
//    exactly the regression the external_fallback invariant forbids; making it
//    RED is the whole point of PF's fallback-path lock.
TEST(NmcPfFallbackPath, EmbeddedSelfLegCannotServeAsFallback_BlockLost) {
    EmbeddedSelfRpcLeg self;
    nmc::coin::AuxRpcSink mis_wired = [&](const std::string& h, const std::string& a) {
        return self.submit_aux_block(h, a);
    };

    auto r = nmc::coin::broadcast_won_aux_block(/*p2p_relay=*/{}, mis_wired,
                                                kBytes, kHashHex, kAuxpowHex);
    EXPECT_EQ(self.calls, 1);              // the leg was consulted...
    EXPECT_FALSE(r.rpc_ok);               // ...but structurally cannot ack
    EXPECT_FALSE(r.p2p_sent);
    EXPECT_FALSE(r.any());                // WON BLOCK LOST -- the forbidden state
    EXPECT_STREQ(r.landed_first, "none");
}

// 3) PERSISTENCE: the external fallback must stay wired ALONGSIDE a working
//    embedded P2P relay, not be optimized away "because embedded works". With
//    both present the external submitauxblock STILL fires (always-fire rule),
//    so deleting it to "save an RPC" flips calls 1->0 and removes the retained
//    safety net -- the regression this asserts against.
TEST(NmcPfFallbackPath, ExternalFallbackPersistsAlongsideWorkingEmbeddedP2p) {
    bool relayed = false;
    nmc::coin::P2pRelaySink p2p = [&](const std::vector<unsigned char>&) { relayed = true; };
    ExternalNamecoindRpc ext;
    nmc::coin::AuxRpcSink rpc = [&](const std::string& h, const std::string& a) {
        return ext.submit_aux_block(h, a);
    };

    auto r = nmc::coin::broadcast_won_aux_block(p2p, rpc, kBytes, kHashHex, kAuxpowHex);
    EXPECT_TRUE(relayed);
    EXPECT_TRUE(r.p2p_sent);
    EXPECT_TRUE(r.rpc_ok);                 // retained fallback fired anyway
    EXPECT_EQ(ext.calls, 1);               // ALWAYS-fired, not skipped because P2P won
    EXPECT_STREQ(r.landed_first, "p2p");   // primary still won the race
}