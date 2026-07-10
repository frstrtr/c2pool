// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin::EmbeddedCoinNode::getwork() contract test (M5 -- embedded body).
//
// build_template() is exercised by abla_floor_invariant_test/abla_block_feed_test,
// and the CoinNode seam by coin_node_seam_test -- but the LATTER drives the seam
// through a *fake* CoinNodeInterface, and nothing covers EmbeddedCoinNode::getwork()
// itself: its sync gate, its no-tip gate, or the fact that the REAL embedded node
// satisfies the core::coin::ICoinNode seam end-to-end. This test closes exactly
// those gaps against an in-memory HeaderChain + empty Mempool:
//
//   1. NOT-SYNCED gate -- a checkpoint-only chain (synthetic tip, ts=0, age huge)
//      makes getwork() THROW (chain not synced), never a half-built template.
//   2. SYNCED happy path -- after adding one recent-timestamp header on top of the
//      fast-start seed, getwork() returns a GBT-shaped WorkData with the expected
//      height (tip+1), previousblockhash (the tip hash), and the 32 MB ABLA floor
//      sizelimit; the empty mempool yields zero template txs.
//   3. ABLA tracker wired at tip vs. STALE -- a tracker whose cursor == tip feeds a
//      per-tip State; a stale (cursor != tip) tracker resolves to nullptr and
//      build_template falls back to the floor. Both keep the budget >= 32 MB floor
//      (ABLA only ever raises): getwork() succeeds and never undercuts in either.
//   4. REAL-NODE seam composition -- CoinNode(&EmbeddedCoinNode, rpc=nullptr) moves
//      getwork()'s agnostic slice (m_data/m_hashes/m_latency) across the WorkView
//      seam: is_embedded()=true, has_rpc()=false, the WorkView carries the height.
//      (coin_node_seam_test proved the contract via a fake; this proves the REAL
//      EmbeddedCoinNode satisfies it.)
//
// The header below the ASERT anchor (height 100k << mainnet anchor 661647) keeps
// build_template on the bits-fallback branch -- no ASERT math, no PoW to mine:
// set_peer_tip_height() puts the new header in the structural-only sync window so
// add_header() trusts its PoW, and validate_difficulty() trusts one block built
// directly on the null-prev fast-start seed.
//
// Build-INERT / source-only (matches the sibling tests): impl_bch stays unregistered
// in CMake (bch = skip-green; don't race ci-steward). Verified with -fsyntax-only and
// standalone compile+run. p2pool-merged-v36 surface: NONE -- getwork emits the same
// coin-agnostic WorkData the sweep already pinned conformant; no PoW/share/coinbase/
// PPLNS math is touched.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <ctime>
#include <iostream>
#include <stdexcept>
#include <string>

#include "../coin/abla.hpp"             // floor_block_size_limit
#include "../coin/abla_tracker.hpp"     // AblaTracker
#include "../coin/block.hpp"            // BlockHeaderType, block_hash
#include "../coin/coin_node.hpp"        // CoinNode (ICoinNode seam)
#include "../coin/header_chain.hpp"     // HeaderChain, BCHChainParams
#include "../coin/mempool.hpp"          // Mempool
#include "../coin/template_builder.hpp" // EmbeddedCoinNode

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

// A block header building on `prev` with a controllable timestamp. Below the
// ASERT anchor + inside the structural-only sync window, so neither PoW nor the
// ASERT retarget is enforced when this is add_header()-ed onto the seed.
bch::coin::BlockHeaderType make_header(const uint256& prev, uint32_t ts) {
    bch::coin::BlockHeaderType h;
    h.m_version = 0x20000000;
    h.m_previous_block = prev;
    h.m_merkle_root.SetHex(
        "2222222222222222222222222222222222222222222222222222222222222222");
    h.m_timestamp = ts;
    h.m_bits = 0x1d00ffff;
    h.m_nonce = 7;
    return h;
}

} // namespace

int main() {
    using bch::coin::AblaTracker;
    using bch::coin::BCHChainParams;
    using bch::coin::CoinNode;
    using bch::coin::EmbeddedCoinNode;
    using bch::coin::HeaderChain;
    using bch::coin::Mempool;

    const uint32_t H = 100000;  // fast-start checkpoint height, << ASERT anchor
    const uint64_t floor = bch::coin::abla::floor_block_size_limit(/*is_testnet=*/false);
    const auto now = static_cast<uint32_t>(std::time(nullptr));

    uint256 cp_hash;
    cp_hash.SetHex("00000000000000000002c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffee00");

    // -- 1) NOT-SYNCED gate ------------------------------------------------
    {
        BCHChainParams params = BCHChainParams::mainnet();
        params.fast_start_checkpoint = BCHChainParams::Checkpoint{H, cp_hash};
        HeaderChain chain(params);
        CHECK(chain.init());
        CHECK(!chain.is_synced());          // synthetic seed: ts=0, age huge

        Mempool pool;
        EmbeddedCoinNode emb(chain, pool, /*testnet=*/false);
        bool threw = false;
        try { (void)emb.getwork(); } catch (const std::exception&) { threw = true; }
        CHECK(threw);                        // getwork refuses an unsynced chain
    }

    // -- 2/3/4) SYNCED happy path + ABLA selection + seam ------------------
    BCHChainParams params = BCHChainParams::mainnet();
    params.fast_start_checkpoint = BCHChainParams::Checkpoint{H, cp_hash};
    HeaderChain chain(params);
    CHECK(chain.init());
    chain.set_peer_tip_height(H + 5000);     // structural-only window: skip PoW
    // One recent header on top of the seed -> tip advances, chain reports synced.
    bch::coin::BlockHeaderType h1 = make_header(cp_hash, now - 60);
    CHECK(chain.add_header(h1));
    const uint256 h1_hash = bch::coin::block_hash(h1);
    CHECK(chain.height() == H + 1);
    CHECK(chain.is_synced());

    Mempool pool;                            // empty: zero template txs
    EmbeddedCoinNode emb(chain, pool, /*testnet=*/false);

    // 2) getwork() on a synced chain returns a GBT-shaped template.
    {
        bch::coin::rpc::WorkData wd = emb.getwork();
        CHECK(wd.m_data["height"].get<int>() == static_cast<int>(H + 2));
        CHECK(wd.m_data["previousblockhash"].get<std::string>() == h1_hash.GetHex());
        CHECK(wd.m_data["sizelimit"].get<int64_t>() == static_cast<int64_t>(floor));
        CHECK(wd.m_data["transactions"].empty());     // empty mempool
        CHECK(wd.m_data["coinbasevalue"].get<int64_t>() > 0);
        CHECK(wd.m_txs.empty());
        CHECK(wd.m_hashes.empty());
    }

    // 3a) ABLA tracker wired AT the tip -> per-tip State feeds build_template;
    //     floor-anchored with no large folds, so the budget stays at the floor.
    {
        AblaTracker at_tip = AblaTracker::floor_anchored(/*is_testnet=*/false, H + 1);
        emb.set_abla_tracker(&at_tip);
        bch::coin::rpc::WorkData wd = emb.getwork();
        CHECK(wd.m_data["sizelimit"].get<int64_t>() >= static_cast<int64_t>(floor));
        CHECK(wd.m_data["height"].get<int>() == static_cast<int>(H + 2));
    }

    // 3b) STALE tracker (cursor != tip) -> state_for_tip()=nullptr -> floor
    //     fallback; getwork() still succeeds and never undercuts the floor.
    {
        AblaTracker stale = AblaTracker::floor_anchored(/*is_testnet=*/false, H); // cursor H != tip H+1
        emb.set_abla_tracker(&stale);
        bch::coin::rpc::WorkData wd = emb.getwork();
        CHECK(wd.m_data["sizelimit"].get<int64_t>() == static_cast<int64_t>(floor));
    }
    emb.set_abla_tracker(nullptr);           // detach test-local tracker

    // 4) REAL EmbeddedCoinNode across the CoinNode (ICoinNode) seam.
    {
        CoinNode n(&emb, /*rpc=*/nullptr);
        CHECK(n.is_embedded());
        CHECK(!n.has_rpc());
        core::coin::WorkView v = n.get_work_view();
        CHECK(v.m_data["height"].get<int>() == static_cast<int>(H + 2));
        CHECK(v.m_data.contains("sizelimit"));
        CHECK(v.m_hashes.empty());           // no txs crossed the seam
        // submit with no RPC sink -> false (guard, not throw): embedded-primary,
        // external-RPC fallback absent here.
        CHECK(n.submit_block_hex("00", /*ignore_failure=*/true) == false);
    }

    if (failures == 0) {
        std::cout << "embedded_getwork_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "embedded_getwork_test: " << failures << " FAILURE(S)\n";
    return 1;
}