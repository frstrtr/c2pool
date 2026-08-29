// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin BlockConnector -- REORG / DISCONNECT leg (M5 full-block body).
//
// The forward UTXO-connect leg (utxo_connect_test) only ever moved the view
// forward and DISCARDED the BlockUndo connect_block() returned. This test pins
// the now-retained undo + reorg path: when the best chain switches branches,
// the connector must roll the UTXO view back to the fork point (restore spent
// inputs, remove created outputs), return the orphaned branch's txs to the
// mempool, then re-apply the new branch.
//
// Topology (all equal-work headers; B-branch is 1 block longer => it wins):
//
//        seed(H) --- A1(H+1, spends X)            <- connected first (tip=A1)
//             \
//              `---- B1(H+1, spends Y) --- B2(H+2)  <- becomes best tip => REORG
//
// After the reorg to B2 the connector must have:
//   - DISCONNECTED A1: coin X (spent only by A1) restored live; A1's tx back in
//     the mempool (and, since X is live again, it survives the Phase-4 sweep).
//   - CONNECTED B1+B2: coin Y (spent by B1) now gone; undo depth = 2.
//   - coin Z (never referenced) live throughout (control).
//
// PoW is skipped via a far-ahead peer tip; the checkpoint is seeded BELOW the
// ASERT anchor (661647) so a 2-deep branch is trusted structurally. Build
// posture matches the other connector tests: header-only over coin/*.hpp +
// <core/*> plus transaction.cpp; no impl_bch lib. p2pool-merged-v36 surface: NONE.
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

// A coinbase-position tx (distinct per nonce so blocks don't collide on txid).
bch::coin::MutableTransaction make_coinbase(uint32_t tag) {
    char buf[65];
    std::snprintf(buf, sizeof(buf),
        "%064x", tag);
    return make_tx(buf, 0xffffffff, 5000000000LL);
}

bch::coin::BlockType make_block(const uint256& prev, uint32_t nonce) {
    bch::coin::BlockType b;
    b.m_version = 0x20000000;
    b.m_previous_block = prev;
    b.m_merkle_root.SetHex(
        "1111111111111111111111111111111111111111111111111111111111111111");
    b.m_timestamp = 1500000000 + nonce;   // pre-ASERT-anchor era timestamps
    b.m_bits = 0x1d00ffff;
    b.m_nonce = nonce;
    return b;
}

const char* OUTPOINT_X = "aa00000000000000000000000000000000000000000000000000000000000000";
const char* OUTPOINT_Y = "bb00000000000000000000000000000000000000000000000000000000000000";
const char* OUTPOINT_Z = "cc00000000000000000000000000000000000000000000000000000000000000";

} // namespace

int main() {
    using namespace bch::coin;

    // Checkpoint BELOW the ASERT anchor (661647) -> difficulty trusted
    // structurally for the whole branch (validate_difficulty early-out).
    const uint32_t H = 600000;

    // seed = pre-connector base (checkpoint tip). Not fed to the connector.
    BlockType seed = make_block(uint256{} /*null prev*/, /*nonce=*/0);
    const ::uint256 seed_hash = block_hash(static_cast<const BlockHeaderType&>(seed));

    // Branch A: one block spending X.
    BlockType A1 = make_block(seed_hash, /*nonce=*/1);
    A1.m_txs.push_back(make_coinbase(0xA0));
    A1.m_txs.push_back(make_tx(OUTPOINT_X, 0, 4000));
    const ::uint256 a1_hash = block_hash(static_cast<const BlockHeaderType&>(A1));
    const ::uint256 id_a1_spend = compute_txid(A1.m_txs[1]);

    // Branch B: B1 spends Y, B2 extends B1 (=> B-branch is longer, wins).
    BlockType B1 = make_block(seed_hash, /*nonce=*/2);
    B1.m_txs.push_back(make_coinbase(0xB1));
    B1.m_txs.push_back(make_tx(OUTPOINT_Y, 0, 4000));
    const ::uint256 b1_hash = block_hash(static_cast<const BlockHeaderType&>(B1));

    BlockType B2 = make_block(b1_hash, /*nonce=*/3);
    B2.m_txs.push_back(make_coinbase(0xB2));
    const ::uint256 b2_hash = block_hash(static_cast<const BlockHeaderType&>(B2));

    CHECK(a1_hash != b1_hash && b1_hash != b2_hash && a1_hash != b2_hash);

    // Header chain seeded at the synthetic checkpoint = seed_hash @ H.
    BCHChainParams params = BCHChainParams::mainnet();
    params.fast_start_checkpoint = BCHChainParams::Checkpoint{H, seed_hash};
    HeaderChain chain(params);
    CHECK(chain.init());
    CHECK(chain.tip() && chain.tip()->block_hash == seed_hash);
    chain.set_peer_tip_height(H + 5000);   // far-ahead tip => structural-only (PoW skipped)

    // UTXO view: X, Y, Z all live at start.
    uint256 hx; hx.SetHex(OUTPOINT_X);
    uint256 hy; hy.SetHex(OUTPOINT_Y);
    uint256 hz; hz.SetHex(OUTPOINT_Z);
    const core::coin::Outpoint op_X(hx, 0), op_Y(hy, 0), op_Z(hz, 0);

    core::coin::UTXOViewCache utxo(nullptr);
    utxo.add_coin(op_X, core::coin::Coin(5000, {}, 1, false));
    utxo.add_coin(op_Y, core::coin::Coin(5000, {}, 1, false));
    utxo.add_coin(op_Z, core::coin::Coin(5000, {}, 1, false));

    Mempool pool;
    BlockConnector conn(chain, pool);
    conn.set_utxo(&utxo);

    // ---- 1) Connect branch A (forward extend) ---------------------------
    conn.on_full_block(A1);
    CHECK(chain.tip() && chain.tip()->block_hash == a1_hash);   // A1 is the tip
    CHECK(conn.undo_depth() == 1);
    CHECK(!utxo.have_coin(op_X));   // A1 spent X
    CHECK(utxo.have_coin(op_Y));    // Y untouched
    CHECK(utxo.have_coin(op_Z));

    // ---- 2) B1 arrives as a SIDE branch (equal work, A1 stays tip) ------
    conn.on_full_block(B1);
    CHECK(chain.tip() && chain.tip()->block_hash == a1_hash);   // tip unchanged
    CHECK(conn.undo_depth() == 1);                              // not connected
    CHECK(!utxo.have_coin(op_X));   // still A1's view
    CHECK(utxo.have_coin(op_Y));    // B1 NOT applied

    // ---- 3) B2 extends B1 -> B-branch wins -> REORG ---------------------
    conn.on_full_block(B2);
    CHECK(chain.tip() && chain.tip()->block_hash == b2_hash);   // reorged to B2
    CHECK(conn.undo_depth() == 2);                              // B1 + B2 applied; A1 gone

    CHECK(utxo.have_coin(op_X));    // A1 disconnected -> X restored live
    CHECK(!utxo.have_coin(op_Y));   // B1 connected -> Y now spent
    CHECK(utxo.have_coin(op_Z));    // control: never touched

    // A1's tx was returned to the mempool on disconnect; X is live again so it
    // survives the Phase-4 sweep.
    CHECK(pool.contains(id_a1_spend));

    if (failures == 0) {
        std::cout << "reorg_connect_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "reorg_connect_test: " << failures << " FAILURE(S)\n";
    return 1;
}