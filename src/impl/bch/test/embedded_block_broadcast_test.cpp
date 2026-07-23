// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin::EmbeddedDaemon::broadcast_won_block dual-path contract test
// (M5 -- embedded body; broadcaster-gate A+B).
//
// The gate requires a won block to reach the network down BOTH paths: embedded
// P2P relay (submit_block_p2p_raw, PRIMARY) AND external BCHN submitblock
// (CoinNode::submit_block_hex, FALLBACK -- always fired, not a P2P-only catch).
// broadcast_won_block() is that production dispatcher; the pool node wires
// tracker().m_on_block_found -> this method so an in-operation win emits
// immediately (not only on the init sweep, 30d7f2c2).
//
// This is the OFFLINE contract slice: with no network bring-up (no run()/
// start_p2p), NEITHER sink is live, so the method must hit its guard and report
// any()=false / landed_first="none" WITHOUT throwing. It proves the dispatcher
// is reachable from the daemons real members and its no-sink contract holds.
// Proving both paths actually FIRE+ACCEPT live is the VM300 bchn-bch
// (192.168.86.110:8333) soak (gate criterion C) -- a separate, read-only slice;
// code-exists != fires, so it is NOT claimed here.
//
// Build-INERT / source-only: impl_bch stays unregistered in CMake (bch =
// skip-green). p2pool-merged-v36 surface: NONE (block dispatch, not
// share/PPLNS/coinbase/AuxPoW bytes).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <exception>
#include <iostream>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>

#include "../coin/embedded_daemon.hpp"
#include "../coin/block_broadcast_guard.hpp" // guarded_dual_broadcast (throw-injection KATs)

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

struct TestConfig {
    bool m_testnet = false;
    bool m_testnet4 = false;  // mirror config_coin.hpp: BCH testnet4 selector
    struct P2P { std::vector<std::byte> prefix; };
    struct Coin { P2P m_p2p; };
    Coin m_coin;
    const Coin* coin() const { return &m_coin; }
};


// A sink that throws -- simulates a P2P relay / submitblock that raises mid-send
// (socket error, serialization assert, RPC transport teardown). The dual-path
// guard must contain it so the dispatcher never propagates and never drops the
// won block.
struct SinkThrew : std::exception {
    const char* what() const noexcept override { return "simulated broadcast sink failure"; }
};

} // namespace

int main() {
    boost::asio::io_context ioc;
    TestConfig config;

    bch::coin::EmbeddedDaemon<TestConfig> daemon(&ioc, &config, /*anchor_height=*/955700);
    daemon.assemble();   // network-free: builds the seam, but no P2P/RPC sink live

    // A dummy won block (header||tx_count||coinbase||... shape is opaque to the
    // dispatcher -- it relays bytes and submits hex; no parse/PoW recompute).
    const std::vector<unsigned char> block_bytes(80, 0x00);
    const std::string block_hex(160, 0);

    auto r = daemon.broadcast_won_block(block_bytes, block_hex);

    // Offline contract: no P2P sink (start_p2p never ran), no RPC fallback
    // (run()/init_rpc never ran) -> guard fires, nothing relayed, no throw.
    CHECK(!r.p2p_sent);
    CHECK(!r.rpc_ok);
    CHECK(!r.any());
    CHECK(std::string(r.landed_first) == "none");

    // The seam is still intact after a guarded broadcast attempt.
    CHECK(daemon.seam_ready());
    CHECK(!daemon.coin_node().has_rpc());   // confirms why the fallback leg was skipped
    CHECK(!daemon.node().has_p2p());        // confirms why the primary leg was skipped

    // -----------------------------------------------------------------------
    // Net-new guard KATs (mirror of NMC #468): each leg independently guarded
    // so a throwing leg neither propagates out nor masks the other path. These
    // exercise guarded_dual_broadcast directly -- the SAME helper the production
    // broadcast_won_block dispatcher delegates to -- with injected throwing
    // sinks, which a live-sink-only daemon test cannot reach.
    // -----------------------------------------------------------------------

    // KAT 1 -- throw -> fallback-fires: P2P relay THROWS, submitblock RPC is up
    // and accepts. The throw must be swallowed and the always-fire RPC fallback
    // must still run, so the won block reaches the network via RPC (NOT dropped,
    // fallback NOT runtime-removed).
    {
        bool rpc_called = false;
        auto g = bch::coin::guarded_dual_broadcast(
            /*have_p2p=*/true,  [&]() { throw SinkThrew(); },
            /*have_rpc=*/true,  [&]() { rpc_called = true; return true; });
        CHECK(!g.p2p_sent);                              // P2P threw -> not sent
        CHECK(rpc_called);                               // fallback STILL fired
        CHECK(g.rpc_ok);                                 // and accepted
        CHECK(g.any());                                  // block reached network
        CHECK(std::string(g.landed_first) == "rpc");
    }

    // KAT 2 -- throw -> p2p-win-preserved: P2P relay SUCCEEDS, then the
    // submitblock RPC fallback THROWS. The RPC throw must be a no-ack that does
    // NOT mask or unwind the recorded P2P win.
    {
        auto g = bch::coin::guarded_dual_broadcast(
            /*have_p2p=*/true,  [&]() { /* relay ok */ },
            /*have_rpc=*/true,  [&]() -> bool { throw SinkThrew(); });
        CHECK(g.p2p_sent);                               // P2P win recorded
        CHECK(!g.rpc_ok);                                // RPC threw -> no-ack
        CHECK(g.any());                                  // win preserved
        CHECK(std::string(g.landed_first) == "p2p");     // RPC throw did not mask it
    }

    // KAT 3 -- both legs throw: dispatcher still must not propagate; reports
    // any()=false / landed_first="none" so the caller logs a hard NOT-relayed
    // error rather than crashing the win path.
    {
        bool threw_out = false;
        try {
            auto g = bch::coin::guarded_dual_broadcast(
                /*have_p2p=*/true, [&]() { throw SinkThrew(); },
                /*have_rpc=*/true, [&]() -> bool { throw SinkThrew(); });
            CHECK(!g.any());
            CHECK(std::string(g.landed_first) == "none");
        } catch (...) {
            threw_out = true;
        }
        CHECK(!threw_out);                               // guard never propagates
    }

    // KAT 4 -- P2P throws with NO RPC fallback wired: still no propagation
    // (any()=false), proving the guard holds even when the fallback is absent.
    {
        bool threw_out = false;
        try {
            auto g = bch::coin::guarded_dual_broadcast(
                /*have_p2p=*/true,  [&]() { throw SinkThrew(); },
                /*have_rpc=*/false, [&]() { return true; });
            CHECK(!g.any());
            CHECK(!g.p2p_sent);
            CHECK(!g.rpc_ok);
        } catch (...) {
            threw_out = true;
        }
        CHECK(!threw_out);
    }

    if (failures == 0) {
        std::cout << "embedded_block_broadcast_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "embedded_block_broadcast_test: " << failures << " FAILURE(S)\n";
    return 1;
}