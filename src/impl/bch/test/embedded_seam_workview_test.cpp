// ---------------------------------------------------------------------------
// bch::coin::EmbeddedDaemon production-seam WorkView test (M5 -- embedded body).
//
// Three sibling tests bracket the CoinNode seam but leave ONE production path
// uncovered:
//   * coin_node_seam_test     -- drives get_work_view()/submit_block_hex() but
//                                through a *fake* CoinNodeInterface (synced=true).
//   * embedded_getwork_test   -- drives get_work_view() against the REAL
//                                EmbeddedCoinNode, but via a *test-local*
//                                CoinNode(&emb, nullptr) -- NOT the seam the
//                                daemon actually hands to web_server.
//   * embedded_daemon_assembly_test -- builds the daemon's REAL seam
//                                (daemon.coin_node()) but only inspects its
//                                flags (is_embedded/has_rpc); it never DRIVES
//                                get_work_view()/submit_block_hex() through it.
//
// What none of them assert: the daemon's OWN assembled production seam, DRIVEN,
// at cold start. web_server calls coin_node().get_work_view() the instant the
// daemon is up -- before header sync completes. The contract it depends on is
// that the embedded sync gate PROPAGATES through the seam as a thrown
// std::exception (never a half-built template, never a crash), and that
// submit_block_hex() on the embedded-primary / no-RPC-fallback offline seam is
// the false guard (not a throw). This test closes exactly that gap by driving
// the REAL EmbeddedDaemon<Config>::coin_node() seam (no fake, no test-local
// CoinNode) against the daemon's own genesis-seeded-but-not-yet-synced chain:
//
//   1. ASSEMBLE     -- network-free; production seam built embedded-primary,
//                      RPC fallback absent offline (is_embedded=true,
//                      has_rpc=false) -- the exact shape handed to web_server.
//   2. COLD START   -- daemon.chain().init() seeds genesis (height 0); the
//                      genesis timestamp is decades old so is_synced()=false:
//                      a realistic "daemon up, headers still syncing" state.
//   3. SYNC GATE through the REAL seam -- coin_node().get_work_view() THROWS
//                      (EmbeddedCoinNode::getwork sync gate propagated across
//                      the ICoinNode seam), proving web_server gets an
//                      exception, not a malformed WorkView, at cold start.
//   4. SUBMIT GUARD -- coin_node().submit_block_hex("00", true) == false on the
//                      no-RPC-sink offline seam: the guard, not a throw.
//
// Build-INERT / source-only (matches the sibling tests): impl_bch stays
// unregistered in CMake (bch = skip-green; don't race ci-steward). Verified with
// -fsyntax-only and standalone compile+run. p2pool-merged-v36 surface: NONE --
// pure local seam exercise; no PoW/share/coinbase/AuxPoW/PPLNS/WorkData-shape
// change; the WorkData getwork would emit is the slice the sweep pinned.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <exception>
#include <iostream>
#include <vector>

#include <boost/asio/io_context.hpp>

#include "../coin/embedded_daemon.hpp"

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

// Same duck-typed config the assembly test uses: the ctor + assemble() path
// reads only m_testnet (chain-params / EmbeddedCoinNode / AblaRuntime flag) and,
// via the eagerly-instantiated NodeP2P vtable, coin()->m_p2p.prefix. The
// external RPC/P2P config fields are touched only by Node::run()/init_rpc(),
// which this offline test never calls.
struct TestConfig {
    bool m_testnet = false;
    bool m_testnet4 = false;  // mirror config_coin.hpp: BCH testnet4 selector
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

    // 1) Build the production seam network-free (the seam web_server receives).
    daemon.assemble();
    CHECK(daemon.seam_ready());
    CHECK(daemon.coin_node().is_embedded());      // embedded-primary
    CHECK(!daemon.coin_node().has_rpc());          // RPC fallback absent offline

    // 2) Cold start: seed genesis; the daemon is up but not yet header-synced.
    CHECK(daemon.chain().init());                  // default mainnet -> genesis seed
    CHECK(!daemon.chain().is_synced());            // genesis ts decades old
    CHECK(!daemon.embedded().is_synced());         // REAL embedded node, not a fake

    // 3) Sync gate PROPAGATES through the daemon's REAL seam: web_server gets a
    //    thrown exception, never a half-built WorkView, at cold start.
    {
        bool threw = false;
        try {
            (void)daemon.coin_node().get_work_view();
        } catch (const std::exception&) {
            threw = true;
        }
        CHECK(threw);
    }

    // 4) submit on the embedded-primary / no-RPC-fallback offline seam: the
    //    false guard, NOT a throw (web_server treats false as "no sink").
    CHECK(daemon.coin_node().submit_block_hex("00", /*ignore_failure=*/true) == false);

    if (failures == 0) {
        std::cout << "embedded_seam_workview_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "embedded_seam_workview_test: " << failures << " FAILURE(S)\n";
    return 1;
}
