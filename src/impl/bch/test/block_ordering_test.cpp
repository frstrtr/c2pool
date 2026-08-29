// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin BlockConnector — BIP130 ORDERING edge cases (M5 full-block body,
// slice 2). The slice-1 test (block_connector_test.cpp) pinned the three
// happy-path decisions against a block that was ALREADY the seeded checkpoint
// tip. It never exercised the two ordering branches the connector's step-1
// add_header() actually has to handle when blocks and headers arrive in the
// "wrong" order on the wire:
//
//   1. OUT-OF-ORDER / ORPHAN block (block arrives before its parent header):
//      the block's m_previous_block is not in the header index, so
//      HeaderChain::add_header() rejects it as an orphan, the tip does NOT
//      move, and the BIP130 best-chain gate must leave the mempool fully
//      intact — even though the orphan carries a tx that WOULD be removed if
//      it ever connected. No reconciliation off an unconnected block.
//
//   2. DIRECT-BLOCK DELIVERY that CONNECTS (block with no prior synced header,
//      e.g. one we mined or a peer `block` msg extending our tip): add_header()
//      indexes it, it becomes the NEW best tip at height+1, the gate then
//      passes, and the mempool is reconciled to the new tip. This is the
//      "indexes the connect on direct-block delivery" path asserted in the
//      connector header but left untested by slice 1 (which relied on the block
//      already being the checkpoint tip). PoW is skipped via a far-ahead
//      peer-tip (structural-only validation, the connector's normal fast-sync
//      contract); difficulty is trusted for the single block building on the
//      synthetic checkpoint seed (null-prev trust branch in validate_difficulty).
//
//   3. IDEMPOTENT RE-DELIVERY of the now-connected tip: replaying it is a clean
//      no-op (header already known -> add_header false; gate still passes but
//      remove_for_block has nothing left to remove).
//
// Build posture is identical to block_connector_test: header-only over
// coin/*.hpp + <core/*> plus coin/transaction.cpp for the MutableTransaction
// ctors. impl_bch is NOT linked -> per-coin isolation stays clean.
// p2pool-merged-v36 surface: NONE.
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

// 80-byte header fully fixes block_hash (the tx vector does not feed it), so
// m_txs can be set freely. `prev` and `nonce` are the only fields the tests
// vary to control connectivity and hash-distinctness.
bch::coin::BlockType make_block(const uint256& prev, uint32_t nonce) {
    bch::coin::BlockType b;
    b.m_version = 0x20000000;
    b.m_previous_block = prev;
    b.m_merkle_root.SetHex(
        "1111111111111111111111111111111111111111111111111111111111111111");
    b.m_timestamp = 1700000000;
    b.m_bits = 0x1d00ffff;
    b.m_nonce = nonce;
    return b;
}

const char* OUTPOINT_A = "aa00000000000000000000000000000000000000000000000000000000000000";
const char* OUTPOINT_C = "cc00000000000000000000000000000000000000000000000000000000000000";

// Params for a fast-start chain whose checkpoint hash IS `tip_hash` at height H,
// the same technique the slice-1 test uses to get a known tip without fighting
// PoW. HeaderChain is non-copyable/non-movable, so callers construct it in place
// from these params (no return-by-value).
bch::coin::BCHChainParams seeded_params(const uint256& tip_hash, uint32_t H) {
    bch::coin::BCHChainParams params = bch::coin::BCHChainParams::mainnet();
    params.fast_start_checkpoint = bch::coin::BCHChainParams::Checkpoint{H, tip_hash};
    return params;
}

} // namespace

int main() {
    using namespace bch::coin;

    const uint32_t H = 800001;

    // The seeded checkpoint tip. Its hash is fixed by an arbitrary header; we
    // only ever use the hash as the index root + the prev of the connecting
    // block, never deliver this block itself. (Seed header content is
    // irrelevant — only the resulting hash matters.)
    uint256 seed_prev;
    seed_prev.SetHex(
        "00000000000000000001a2b3c4d5e6f700000000000000000000000000000000");
    BlockType seed_block = make_block(seed_prev, /*nonce=*/1);
    const uint256 seed_hash =
        block_hash(static_cast<const BlockHeaderType&>(seed_block));

    // tx_A: confirmed in the connecting block -> Phase 1.
    MutableTransaction tx_A = make_tx(OUTPOINT_A, 0, 100);
    // tx_B: double-spends tx_A's outpoint, mempool-only -> Phase 2.
    MutableTransaction tx_B = make_tx(OUTPOINT_A, 0, 200);
    // tx_C: unrelated, mempool-only -> survives.
    MutableTransaction tx_C = make_tx(OUTPOINT_C, 0, 300);
    const uint256 id_A = compute_txid(tx_A);
    const uint256 id_B = compute_txid(tx_B);
    const uint256 id_C = compute_txid(tx_C);
    CHECK(id_A != id_B && id_B != id_C && id_A != id_C);

    // ---- 1) OUT-OF-ORDER / ORPHAN block: prev not in index --------------
    {
        HeaderChain chain(seeded_params(seed_hash, H));
        CHECK(chain.init());
        CHECK(chain.height() == H);
        CHECK(chain.tip() && chain.tip()->block_hash == seed_hash);

        Mempool pool;
        CHECK(pool.add_tx(tx_A));
        CHECK(pool.add_tx(tx_B));
        CHECK(pool.add_tx(tx_C));
        CHECK(pool.size() == 3);

        // prev is an unknown hash (parent header not yet synced). The block even
        // carries tx_A, which WOULD be removed on connect — must NOT be.
        uint256 unknown_prev;
        unknown_prev.SetHex(
            "deadbeef00000000000000000000000000000000000000000000000000000000");
        BlockType orphan = make_block(unknown_prev, /*nonce=*/42);
        orphan.m_txs.push_back(tx_A);
        const uint256 orphan_hash =
            block_hash(static_cast<const BlockHeaderType&>(orphan));
        CHECK(orphan_hash != seed_hash);

        BlockConnector conn(chain, pool);
        conn.on_full_block(orphan);

        // Orphan rejected: tip did not move, nothing reconciled.
        CHECK(chain.height() == H);
        CHECK(chain.tip() && chain.tip()->block_hash == seed_hash);
        CHECK(pool.size() == 3);
        CHECK(pool.contains(id_A));
        CHECK(pool.contains(id_B));
        CHECK(pool.contains(id_C));
    }

    // ---- 2) DIRECT-BLOCK DELIVERY that connects + advances tip ----------
    {
        HeaderChain chain(seeded_params(seed_hash, H));
        CHECK(chain.init());
        // Far-ahead peer tip => structural-only validation (PoW skipped) for a
        // block well below (peer_tip - 2100); difficulty is trusted for the one
        // block building on the null-prev seed.
        chain.set_peer_tip_height(H + 5000);

        Mempool pool;
        CHECK(pool.add_tx(tx_A));
        CHECK(pool.add_tx(tx_B));
        CHECK(pool.add_tx(tx_C));
        CHECK(pool.size() == 3);

        // A real connecting block: prev == current tip (the seed), so add_header
        // indexes it at H+1 and (work = seed_work + block_proof > seed_work) it
        // becomes the new best tip.
        BlockType next = make_block(seed_hash, /*nonce=*/7);
        next.m_txs.push_back(tx_A);   // tx_A confirmed in the connecting block
        const uint256 next_hash =
            block_hash(static_cast<const BlockHeaderType&>(next));
        CHECK(next_hash != seed_hash);

        BlockConnector conn(chain, pool);
        conn.on_full_block(next);

        // Connected: tip advanced to H+1 on this exact block...
        CHECK(chain.height() == H + 1);
        CHECK(chain.tip() && chain.tip()->block_hash == next_hash);
        // ...and the mempool reconciled to the new tip.
        CHECK(!pool.contains(id_A));  // Phase 1
        CHECK(!pool.contains(id_B));  // Phase 2 (same-outpoint conflict)
        CHECK(pool.contains(id_C));   // unrelated survives
        CHECK(pool.size() == 1);

        // ---- 3) IDEMPOTENT RE-DELIVERY of the connected tip -------------
        conn.on_full_block(next);     // header already known; gate still passes
        conn.on_full_block(next);
        CHECK(chain.height() == H + 1);
        CHECK(chain.tip() && chain.tip()->block_hash == next_hash);
        CHECK(pool.size() == 1);      // nothing left to remove
        CHECK(pool.contains(id_C));
    }

    if (failures == 0) {
        std::cout << "block_ordering_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "block_ordering_test: " << failures << " FAILURE(S)\n";
    return 1;
}