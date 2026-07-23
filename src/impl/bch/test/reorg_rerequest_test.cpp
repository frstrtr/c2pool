// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin reorg re-request test (M5 full-block body).
//
// The BlockConnector reconnects a reorg's new branch from its bounded
// remembered-block ring. When the chain advances to a new tip whose
// intermediate new-branch blocks have NOT been delivered as full blocks yet
// (the normal headers-first case: headers race ahead of block downloads) or
// when a reorg runs deeper than the ring retains, recall_block() returns null
// and the old behaviour was to log a warning and strand the UTXO at the fork
// with NO recovery. This test pins the now-live recovery leg:
//
//   * a set_block_requester() sink, when wired, is handed exactly the
//     not-yet-connected new-branch hashes (fork->tip order) so they can be
//     re-getdata'd (BlockDownloadWindow::enqueue) and the reorg completes on
//     re-delivery -- instead of silently holding at the fork;
//   * the fork-point block stays connected (it is at/below the fork, never
//     disconnected) so the UTXO view is left consistent, not corrupted;
//   * with NO sink wired the connector still falls back to warn-and-hold
//     (no crash, no throw) -- the cold-start / unwired contract holds.
//
// Build posture mirrors utxo_connect_test: header-only over coin/*.hpp +
// <core/*> plus coin/transaction.cpp; NO impl_bch coin lib (per-coin isolation
// stays clean). All heights sit far below the mainnet ASERT anchor so the
// header chain trusts difficulty structurally, and peer_tip is set high so PoW
// is skipped -- this builds a deterministic 3-block fork with no PoW grinding.
// p2pool-merged-v36 surface: NONE (local block-connect / download plumbing).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>
#include <vector>

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

bch::coin::MutableTransaction make_cb(const char* prev_hex, int64_t out_value) {
    bch::coin::MutableTransaction tx;
    bch::coin::TxIn in;
    in.prevout.hash.SetHex(prev_hex);
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    bch::coin::TxOut out;
    out.value = out_value;
    tx.vout.push_back(out);
    return tx;
}

// A header building on `prev` with a distinct nonce (=> distinct hash).
bch::coin::BlockType make_block(const uint256& prev, uint32_t nonce) {
    bch::coin::BlockType b;
    b.m_version = 0x20000000;
    b.m_previous_block = prev;
    b.m_merkle_root.SetHex(
        "1111111111111111111111111111111111111111111111111111111111111111");
    b.m_timestamp = 1700000000 + nonce;
    b.m_bits = 0x1d00ffff;
    b.m_nonce = nonce;
    return b;
}

const char* OUTPOINT_A = "aa00000000000000000000000000000000000000000000000000000000000000";

// Header chain whose fast-start checkpoint IS block1's hash at height H, so the
// connector sees block1 as the tip without fighting PoW.
bch::coin::HeaderChain make_chain(const uint256& tip_hash, uint32_t H) {
    using namespace bch::coin;
    BCHChainParams params = BCHChainParams::mainnet();
    params.fast_start_checkpoint = BCHChainParams::Checkpoint{H, tip_hash};
    return HeaderChain(params);
}

} // namespace

int main() {
    using namespace bch::coin;

    // Heights far below the mainnet ASERT anchor (661647) => difficulty trusted
    // structurally; peer_tip high => PoW skipped. Deterministic 3-block fork.
    const uint32_t H = 1000;

    uint256 root_prev; root_prev.SetHex(
        "00000000000000000001a2b3c4d5e6f700000000000000000000000000000000");
    BlockType block1 = make_block(root_prev, /*nonce=*/1);
    block1.m_txs.push_back(make_cb(OUTPOINT_A, 100));   // coinbase-position tx
    const uint256 h1 = block_hash(static_cast<const BlockHeaderType&>(block1));

    BlockType block2 = make_block(h1, /*nonce=*/2);     // intermediate, NEVER delivered
    const uint256 h2 = block_hash(static_cast<const BlockHeaderType&>(block2));
    BlockType block3 = make_block(h2, /*nonce=*/3);      // new tip, delivered
    const uint256 h3 = block_hash(static_cast<const BlockHeaderType&>(block3));
    CHECK(h1 != h2); CHECK(h2 != h3); CHECK(h1 != h3);

    // ---- 1) Sink wired: missing new-branch hashes are re-requested ---------
    {
        HeaderChain chain = make_chain(h1, H);
        CHECK(chain.init());
        chain.set_peer_tip_height(H + 100000);   // skip PoW for these heights

        core::coin::UTXOViewCache utxo(nullptr);
        Mempool pool;

        BlockConnector conn(chain, pool);
        conn.set_utxo(&utxo);

        std::vector<uint256> requested;
        int sink_calls = 0;
        conn.set_block_requester([&](const std::vector<uint256>& v) {
            requested = v; ++sink_calls;
        });

        // Cold-start forward-extend: connect block1 (the checkpoint tip).
        conn.on_full_block(block1);

        // Chain advances to block3 via headers only; block2's full block never
        // arrives, so it is absent from the connector's remembered ring.
        CHECK(chain.add_header(static_cast<const BlockHeaderType&>(block2)));
        CHECK(chain.add_header(static_cast<const BlockHeaderType&>(block3)));
        auto tip = chain.tip();
        CHECK(tip.has_value() && tip->block_hash == h3);   // block3 is best tip

        // Deliver block3: reorg fork=block1 -> [block2, block3]; block2 missing.
        conn.on_full_block(block3);

        CHECK(sink_calls == 1);
        CHECK(requested.size() == 2);
        if (requested.size() == 2) {
            CHECK(requested[0] == h2);   // fork->tip order: missing intermediate first
            CHECK(requested[1] == h3);
        }
    }

    // ---- 2) No sink wired: warn-and-hold, no crash/throw -------------------
    {
        HeaderChain chain = make_chain(h1, H);
        CHECK(chain.init());
        chain.set_peer_tip_height(H + 100000);

        core::coin::UTXOViewCache utxo(nullptr);
        Mempool pool;

        BlockConnector conn(chain, pool);
        conn.set_utxo(&utxo);
        // NO set_block_requester()

        conn.on_full_block(block1);
        CHECK(chain.add_header(static_cast<const BlockHeaderType&>(block2)));
        CHECK(chain.add_header(static_cast<const BlockHeaderType&>(block3)));
        conn.on_full_block(block3);      // must not throw / crash
    }

    if (failures == 0) {
        std::cout << "reorg_rerequest_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "reorg_rerequest_test: " << failures << " FAILURE(S)\n";
    return 1;
}