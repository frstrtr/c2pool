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
#include <iostream>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>

#include "../coin/embedded_daemon.hpp"

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

struct TestConfig {
    bool m_testnet = false;
    struct P2P { std::vector<std::byte> prefix; };
    struct Coin { P2P m_p2p; };
    Coin m_coin;
    const Coin* coin() const { return &m_coin; }
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

    if (failures == 0) {
        std::cout << "embedded_block_broadcast_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "embedded_block_broadcast_test: " << failures << " FAILURE(S)\n";
    return 1;
}
