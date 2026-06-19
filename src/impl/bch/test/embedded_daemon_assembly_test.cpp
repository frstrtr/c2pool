// ---------------------------------------------------------------------------
// bch::coin::EmbeddedDaemon assembly test (M5 -- embedded body).
//
// 95c80402 proved EmbeddedCoinNode::getwork() satisfies the CoinNode (ICoinNode)
// seam via a *test-local* CoinNode(&emb, nullptr). What was still uncovered is
// the EmbeddedDaemon CLUSTER itself: that the daemon, from its OWN real members,
// closes the ABLA loop and builds the embedded-primary CoinNode seam -- the
// wiring that lived buried inside run() behind the network bring-up and so could
// not be instantiated, let alone verified. This test instantiates the REAL
// EmbeddedDaemon<Config> and drives the network-free assemble() seam-build
// against its own real EmbeddedCoinNode (no fake, per integrator scope #1):
//
//   1. PRE-assemble    -- seam_ready()=false, is_wired()=false (nothing built yet).
//   2. assemble()      -- network-free: closes ABLA loop + builds the seam WITHOUT
//                         m_node.run() (no RPC/P2P connect). After it:
//                           - seam_ready()=true, is_wired()=true
//                           - coin_node().is_embedded()=true  (embedded primary)
//                           - coin_node().has_rpc()=false      (RPC fallback absent
//                             offline -- bound live only when run() precedes it)
//   3. REAL not FAKE   -- daemon.embedded().is_synced()=false on a fresh, un-init'd
//                         chain (a FakeEmbedded would report synced=true): the seam
//                         is backed by the daemon's genuine EmbeddedCoinNode.
//   4. IDEMPOTENT      -- a second assemble() is a no-op: the same CoinNode object
//                         (stable address) and no re-wire.
//   5. COLD-START ANCHOR (integrator scope #2: VM300 = build-validation only) --
//                         dry_run_bchn_anchor() reads the STATIC recorded anchor and
//                         logs the floor no-op; the live VM is never touched and the
//                         real reanchor stays operator-gated.
//
// Build-INERT / source-only: impl_bch stays unregistered in CMake (bch =
// skip-green; don't race ci-steward). p2pool-merged-v36 surface: NONE -- pure
// local daemon assembly; no PoW/share/coinbase/AuxPoW/PPLNS/WorkData-shape change.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>
#include <vector>

#include <boost/asio/io_context.hpp>

#include "../coin/embedded_daemon.hpp"

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

// Minimal duck-typed config: EmbeddedDaemon's ctor + assemble() path only reads
// m_testnet (chain-params selection, EmbeddedCoinNode + AblaRuntime testnet flag).
// The external RPC/P2P config fields (coin()->m_p2p / m_rpc) are touched only by
// Node::run()/init_rpc(), which this offline test never calls.
struct TestConfig {
    bool m_testnet = false;
    // Duck-typed coin()->m_p2p.prefix: NodeP2P<Config>::get_prefix() is a virtual
    // override (eagerly instantiated via the vtable) and reads it. Empty here --
    // assemble() never sends a P2P message, so the value is inert.
    struct P2P { std::vector<std::byte> prefix; };
    struct Coin { P2P m_p2p; };
    Coin m_coin;
    const Coin* coin() const { return &m_coin; }
};

} // namespace

int main() {
    boost::asio::io_context ioc;
    TestConfig config;

    // Cold-start floor anchor at a representative mainnet-ish height; assemble()
    // does not consult it (the ABLA tracker is floor-anchored in the ctor), so the
    // exact value only matters once a block-size fold occurs.
    bch::coin::EmbeddedDaemon<TestConfig> daemon(&ioc, &config, /*anchor_height=*/955700);

    // 1) Nothing assembled yet.
    CHECK(!daemon.seam_ready());
    CHECK(!daemon.is_wired());

    // 2) Network-free assembly: ABLA loop closed + embedded-primary seam built.
    daemon.assemble();
    CHECK(daemon.seam_ready());
    CHECK(daemon.is_wired());
    CHECK(daemon.coin_node().is_embedded());     // embedded work source = primary
    CHECK(!daemon.coin_node().has_rpc());         // RPC fallback absent offline

    // 2b) FULL-BLOCK REORG PATH WIRED. assemble() now also instantiates +
    //     attaches the daemon-owned BlockConnector to full_block (so every
    //     received block drives header connect + best-chain-gated UTXO/mempool
    //     reconciliation) and binds its deep-reorg re-request sink to the P2P
    //     download window. has_block_requester()=true proves a reorg deeper than
    //     the remembered-block ring re-getdata's the missing new-branch bodies
    //     instead of stranding the UTXO view at the fork; the sink itself no-ops
    //     offline (m_node.p2p() null until start_p2p()), so this is network-free.
    CHECK(daemon.connector().is_attached());
    CHECK(daemon.connector().has_block_requester());

    // 3) The seam is backed by the daemon's REAL EmbeddedCoinNode, not a fake:
    //    a fresh, un-init'd HeaderChain reports NOT synced (FakeEmbedded=true).
    CHECK(!daemon.embedded().is_synced());

    // 4) assemble() is idempotent: same CoinNode object, no re-wire.
    bch::coin::CoinNode* before = &daemon.coin_node();
    daemon.assemble();
    CHECK(&daemon.coin_node() == before);
    CHECK(daemon.seam_ready());
    CHECK(daemon.connector().is_attached());      // connector wiring stable across re-assemble
    CHECK(daemon.connector().has_block_requester());

    // 5) Cold-start anchor DRY RUN: record-only, VM300 untouched, floor no-op.
    //    (Just exercises the path -- it logs and must not throw or mutate.)
    daemon.dry_run_bchn_anchor();
    CHECK(daemon.is_wired());                      // unchanged by the dry run

    // 6) Cold-start anchor LIVE PIN (operator-approved, decisions@ 2026-06-18,
    //    dry-run -> live flip). The recorded @955700 control state is at the
    //    32 MB floor, so the pin is floor-equivalent: it reanchors but the ABLA
    //    budget stays exactly the 32 MB consensus floor (never undercuts).
    using Rec = bch::coin::BchnAnchorRecord;
    daemon.pin_cold_start_anchor();
    CHECK(daemon.is_wired());                      // still wired after the pin
    CHECK(Rec::is_floor());                        // record provenance: at floor
    CHECK(daemon.abla().tracker().budget_for_tip(Rec::height)
          == Rec::abla_blocksizelimit);          // floor-equivalent: 32 MB

    if (failures == 0) {
        std::cout << "embedded_daemon_assembly_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "embedded_daemon_assembly_test: " << failures << " FAILURE(S)\n";
    return 1;
}
