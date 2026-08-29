// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin UTXO-connect / Phase-4 revalidate test (M5 full-block body, (a)).
//
// BlockConnector slices 1-2 closed the txid/outpoint reconciliation (Phases
// 1-3) but the Phase-4 stale-input sweep was inert: no UTXO view was ever
// wired, so revalidate_inputs() was a permanent no-op and connect_block() was
// never applied to a UTXO set. This test pins the now-live UTXO-connect leg:
//
//   1. UTXO-CONNECT IS A REAL SWEEP -- with a UTXO view wired via set_utxo(),
//      a best-chain connect runs revalidate_inputs() against it (not a no-op).
//      A mempool tx whose input is still live in the view SURVIVES; a mempool
//      tx whose input has been spent in the authoritative view is REJECTED.
//   2. DOUBLE-SPEND REJECTION ON CONNECT -- tx_F enters the pool with a live
//      input (fee_known=true), is then double-spent + confirmed elsewhere so
//      its coin disappears from the UTXO set, and the next connect evicts it.
//   3. NO-VIEW CONTRACT -- with NO UTXO view wired the same connect leaves the
//      pool untouched on the Phase-4 axis (cold-start / headers-only safe).
//
// Build posture matches block_connector_test: header-only over coin/*.hpp +
// <core/*>, plus coin/transaction.cpp for the MutableTransaction ctors; NO
// impl_bch coin lib -> per-coin isolation stays clean. p2pool-merged-v36
// surface: NONE (local mempool/UTXO hygiene; no PoW/share/coinbase/PPLNS).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>

#include "../coin/block.hpp"
#include "../coin/block_connector.hpp"
#include "../coin/header_chain.hpp"
#include "../coin/mempool.hpp"
#include "../coin/transaction.hpp"

#include <core/coin/utxo_view_cache.hpp>

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

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

// Distinct outpoints (=> distinct txids).
const char* OUTPOINT_A = "aa00000000000000000000000000000000000000000000000000000000000000";
const char* OUTPOINT_F = "ff00000000000000000000000000000000000000000000000000000000000000";
const char* OUTPOINT_G = "0f00000000000000000000000000000000000000000000000000000000000000";

// Seed a HeaderChain whose fast-start checkpoint IS the tip block hash, so the
// connector best-chain gate sees the block as the tip without fighting PoW.
bch::coin::HeaderChain make_chain(const bch::coin::BlockType& tip_block, uint32_t H) {
    using namespace bch::coin;
    const uint256 tip_hash = block_hash(static_cast<const BlockHeaderType&>(tip_block));
    BCHChainParams params = BCHChainParams::mainnet();
    params.fast_start_checkpoint = BCHChainParams::Checkpoint{H, tip_hash};
    return HeaderChain(params);
}

} // namespace

int main() {
    using namespace bch::coin;

    const uint32_t H = 800001;
    BlockType tip_block = make_block(/*nonce=*/1);
    tip_block.m_txs.push_back(make_tx(OUTPOINT_A, 0, 100));  // coinbase-position tx

    // tx_F: live input at add-time -> fee_known=true; double-spent later.
    // tx_G: live input, never disturbed -> survives.
    MutableTransaction tx_F = make_tx(OUTPOINT_F, 0, 4000);
    MutableTransaction tx_G = make_tx(OUTPOINT_G, 0, 4000);
    const uint256 id_F = compute_txid(tx_F);
    const uint256 id_G = compute_txid(tx_G);
    CHECK(id_F != id_G);

    uint256 f_hash; f_hash.SetHex(OUTPOINT_F);
    uint256 g_hash; g_hash.SetHex(OUTPOINT_G);
    const core::coin::Outpoint op_F(f_hash, 0);
    const core::coin::Outpoint op_G(g_hash, 0);

    // ---- 1+2) UTXO-connect is a real sweep; double-spend rejection ------
    {
        HeaderChain chain = make_chain(tip_block, H);
        CHECK(chain.init());
        CHECK(chain.tip().has_value());

        core::coin::UTXOViewCache utxo(nullptr);  // cache-only, no DB backend
        utxo.add_coin(op_F, core::coin::Coin(5000, {}, 1, false));
        utxo.add_coin(op_G, core::coin::Coin(5000, {}, 1, false));

        Mempool pool;
        CHECK(pool.add_tx(tx_F, &utxo));   // input live -> fee_known=true
        CHECK(pool.add_tx(tx_G, &utxo));   // input live -> fee_known=true
        CHECK(pool.size() == 2);

        // tx_F double-spent + confirmed elsewhere (compact/pruned path): its
        // coin vanishes from the authoritative UTXO set.
        CHECK(utxo.spend_coin(op_F).has_value());
        CHECK(!utxo.have_coin(op_F));
        CHECK(utxo.have_coin(op_G));

        BlockConnector conn(chain, pool);
        conn.set_utxo(&utxo);              // Phase-4 view wired -> real sweep
        conn.on_full_block(tip_block);

        CHECK(!pool.contains(id_F));       // stale/double-spent input -> rejected
        CHECK(pool.contains(id_G));        // live input -> survives
        CHECK(pool.size() == 1);
    }

    // ---- 3) No-view contract: Phase 4 inert when no UTXO view wired -----
    {
        HeaderChain chain = make_chain(tip_block, H);
        CHECK(chain.init());

        core::coin::UTXOViewCache utxo(nullptr);
        utxo.add_coin(op_G, core::coin::Coin(5000, {}, 1, false));

        Mempool pool;
        // tx_F added WITHOUT a view -> fee_known=false (quarantined), but the
        // point of this case is that with NO view wired into the connector the
        // Phase-4 sweep never runs at all, so tx_G (a survivor) is untouched.
        CHECK(pool.add_tx(tx_G, &utxo));
        CHECK(pool.size() == 1);

        BlockConnector conn(chain, pool);   // NO set_utxo()
        conn.on_full_block(tip_block);

        CHECK(pool.contains(id_G));         // no Phase-4 sweep -> survivor kept
        CHECK(pool.size() == 1);
    }

    if (failures == 0) {
        std::cout << "utxo_connect_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "utxo_connect_test: " << failures << " FAILURE(S)\n";
    return 1;
}