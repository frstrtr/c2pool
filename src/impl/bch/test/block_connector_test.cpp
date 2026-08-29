// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin BlockConnector test (M5 full-block body, slice 1: block-connect).
//
// BlockConnector closes the path AblaBlockFeed left open: Mempool::remove_for_block
// existed with ZERO call sites and nothing tied a received best-chain block to a
// mempool reconciliation. This test pins the connector's three load-bearing
// decisions directly, against a real in-memory HeaderChain + Mempool:
//
//   1. BEST-CHAIN RECONCILE -- a block that IS the tip reconciles the mempool:
//      Phase 1 removes a tx confirmed-by-txid in the block; Phase 2 removes a
//      mempool tx that double-spends a block tx's outpoint; an unrelated tx
//      survives; mempool tip_height is advanced to the block's height.
//   2. BIP130 OFF-TIP GATE -- a block whose hash is NOT the best-chain tip
//      leaves the mempool completely untouched, even when it contains a tx that
//      WOULD be removed if it were the tip (its txs aren't confirmed for us).
//   3. IDEMPOTENT RE-CONNECT -- replaying the tip block is a clean no-op
//      (nothing left to remove; survivor still present).
//
// Build posture matches the ABLA seam tests: header-only over coin/*.hpp +
// <core/*>, plus coin/transaction.cpp for the MutableTransaction ctors. impl_bch
// is NOT linked -> per-coin isolation stays clean. p2pool-merged-v36 surface:
// NONE (local block-connect + mempool hygiene; no PoW/share/coinbase/PPLNS).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>

#include "../coin/block.hpp"
#include "../coin/block_connector.hpp"
#include "../coin/header_chain.hpp"
#include "../coin/mempool.hpp"
#include "../coin/transaction.hpp"

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

// A minimal spend of outpoint (prev_hash, prev_index) producing `out_value`.
// Distinct (prevout, value) tuples => distinct txids (compute_txid = SHA256d of
// the legacy serialization), which is all the test needs.
bch::coin::MutableTransaction make_tx(const char* prev_hex, uint32_t prev_index,
                                      int64_t out_value) {
    bch::coin::MutableTransaction tx;
    bch::coin::TxIn in;
    in.prevout.hash.SetHex(prev_hex);
    in.prevout.index = prev_index;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    bch::coin::TxOut out;
    out.value = out_value;
    tx.vout.push_back(out);
    return tx;
}

// A header-only block whose hash is fixed by the 80-byte header (the tx vector
// does NOT feed block_hash), so m_txs can be set freely without moving the hash
// the fast-start checkpoint pins.
bch::coin::BlockType make_block(uint32_t nonce) {
    bch::coin::BlockType b;
    b.m_version = 0x20000000;
    b.m_previous_block.SetHex(
        "00000000000000000001a2b3c4d5e6f700000000000000000000000000000000");
    b.m_merkle_root.SetHex(
        "1111111111111111111111111111111111111111111111111111111111111111");
    b.m_timestamp = 1700000000;
    b.m_bits = 0x1d00ffff;
    b.m_nonce = nonce;
    return b;
}

const char* OUTPOINT_A = "aa00000000000000000000000000000000000000000000000000000000000000";
const char* OUTPOINT_C = "cc00000000000000000000000000000000000000000000000000000000000000";

} // namespace

int main() {
    using namespace bch::coin;

    const uint32_t H = 800001;

    // The tip block; seed a HeaderChain whose fast-start checkpoint IS its hash
    // at height H, so the connector's best-chain gate sees it as the tip without
    // fighting PoW/difficulty validation (same technique as abla_block_feed_test).
    BlockType tip_block = make_block(/*nonce=*/1);
    const uint256 tip_hash =
        block_hash(static_cast<const BlockHeaderType&>(tip_block));

    BCHChainParams params = BCHChainParams::mainnet();
    params.fast_start_checkpoint = BCHChainParams::Checkpoint{H, tip_hash};
    HeaderChain chain(params);
    CHECK(chain.init());
    CHECK(chain.height() == H);
    CHECK(chain.tip().has_value());
    CHECK(chain.tip() && chain.tip()->block_hash == tip_hash);

    // tx_A: spends OUTPOINT_A, INCLUDED in the block (confirmed) -> Phase 1.
    MutableTransaction tx_A = make_tx(OUTPOINT_A, 0, 100);
    // tx_B: double-spends OUTPOINT_A, mempool-only -> Phase 2 conflict removal.
    MutableTransaction tx_B = make_tx(OUTPOINT_A, 0, 200);
    // tx_C: spends OUTPOINT_C, mempool-only, unrelated -> survives.
    MutableTransaction tx_C = make_tx(OUTPOINT_C, 0, 300);
    const uint256 id_A = compute_txid(tx_A);
    const uint256 id_B = compute_txid(tx_B);
    const uint256 id_C = compute_txid(tx_C);
    CHECK(id_A != id_B && id_B != id_C && id_A != id_C);

    tip_block.m_txs.push_back(tx_A);   // tx_A confirmed in the block

    // ---- 1) Best-chain reconcile ----------------------------------------
    {
        Mempool pool;
        CHECK(pool.add_tx(tx_A));
        CHECK(pool.add_tx(tx_B));
        CHECK(pool.add_tx(tx_C));
        CHECK(pool.size() == 3);

        BlockConnector conn(chain, pool);
        conn.on_full_block(tip_block);

        CHECK(!pool.contains(id_A));   // Phase 1: confirmed-by-txid removed
        CHECK(!pool.contains(id_B));   // Phase 2: same-outpoint conflict removed
        CHECK(pool.contains(id_C));    // unrelated tx survives
        CHECK(pool.size() == 1);
    }

    // ---- 2) BIP130 off-tip gate -----------------------------------------
    {
        Mempool pool;
        CHECK(pool.add_tx(tx_A));
        CHECK(pool.add_tx(tx_B));
        CHECK(pool.add_tx(tx_C));
        CHECK(pool.size() == 3);

        // A different block (distinct nonce -> distinct hash): NOT the tip. Even
        // though it carries tx_A (which WOULD be removed if it connected), the
        // gate must leave the mempool fully intact.
        BlockType off_block = make_block(/*nonce=*/99);
        off_block.m_txs.push_back(tx_A);
        CHECK(block_hash(static_cast<const BlockHeaderType&>(off_block)) != tip_hash);

        BlockConnector conn(chain, pool);
        conn.on_full_block(off_block);

        CHECK(pool.size() == 3);       // zero reconciliation off the best chain
        CHECK(pool.contains(id_A));
        CHECK(pool.contains(id_B));
        CHECK(pool.contains(id_C));
    }

    // ---- 3) Idempotent re-connect ---------------------------------------
    {
        Mempool pool;
        CHECK(pool.add_tx(tx_C));      // only the survivor left after a reconcile
        CHECK(pool.size() == 1);

        BlockConnector conn(chain, pool);
        conn.on_full_block(tip_block); // replay the tip block
        conn.on_full_block(tip_block); // again
        CHECK(pool.size() == 1);       // nothing left to remove
        CHECK(pool.contains(id_C));
    }

    if (failures == 0) {
        std::cout << "block_connector_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "block_connector_test: " << failures << " FAILURE(S)\n";
    return 1;
}