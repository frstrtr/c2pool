// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin BlockConnector compact-block test (M5 full-block body, slice (b):
// BIP152 compact-block depth on the connector seam) + the compact-block
// reconstruction MERKLE BACKSTOP (milestone bch-cmpct-merkle).
//
// compact_blocks.hpp already carried the BIP152 wire types + ReconstructBlock,
// but nothing tied them to the block-connect path: a received compact block had
// no way to become a connected best-chain tip + mempool reconciliation. This
// slice adds BlockConnector::on_compact_block() / on_block_txn() and this test
// pins the three load-bearing decisions of that seam against a real in-memory
// HeaderChain + Mempool:
//
//   1. COMPLETE-FROM-MEMPOOL -- a compact block whose non-coinbase txs are all
//      already in the mempool reconstructs immediately: on_compact_block returns
//      std::nullopt (no getblocktxn round), drives the normal on_full_block path,
//      and the confirmed tx is reconciled out of the mempool. Nothing is parked.
//   2. MISSING -> getblocktxn -> blocktxn -- a compact block referencing a tx
//      NOT in the mempool returns a BlockTransactionsRequest naming exactly the
//      missing absolute index and parks the block; the matching blocktxn response
//      completes reconstruction, connects, and clears the parked entry.
//   3. UNKNOWN/EXPIRED blocktxn -- a blocktxn for a blockhash we never parked is
//      a clean no-op (returns false, no crash, parked count unchanged).
//
// MERKLE BACKSTOP (bch-cmpct-merkle) -- ReconstructBlock() used to declare a
// block complete the instant every short-ID slot was filled, with NO check that
// the reconstructed txs hash to the header's committed merkle root. BIP 152 short
// IDs are 48-bit SipHash over txid (BCH: wtxid == txid, no SegWit), so a collision
// can silently substitute the WRONG tx into a filled slot. The backstop recomputes
// the merkle root over the reconstructed txids (via the sealed compute_merkle_root
// SSOT) and, on any divergence from header.m_merkle_root, DISCARDS instead of
// delivering -- the p2p handler then re-fetches the full block via getdata. Cases:
//   4. RECONSTRUCT-ON-MATCH  -- honest txs verify: complete=true, no mismatch.
//   5. DISCARD-ON-MISMATCH   -- a slot filled with the wrong tx fails the header
//      commitment: complete=false, merkle_mismatch=true, EMPTY block (no forgery).
//   6. ID-PATH ROUND TRIP    -- BCH keys short IDs by txid in BOTH the build and
//      the reconstruct pass; wtxid == txid, so the two passes cannot diverge.
//
// Because ReconstructBlock now enforces the header commitment, cases 1/2's headers
// must COMMIT to their bodies (m_merkle_root = merkle over the body txids); a
// placeholder root would be correctly discarded. Cases 1-3 therefore build a
// per-case committing header instead of one shared placeholder.
//
// Build posture matches the other connector tests: header-only over coin/*.hpp +
// <core/*>, plus coin/transaction.cpp for the MutableTransaction ctors and the
// btclibs lib for SipHash. impl_bch is NOT linked -> per-coin isolation holds.
// p2pool-merged-v36 surface: NONE (local compact-block reconstruction + the same
// block-connect/mempool hygiene; no PoW/share/coinbase/PPLNS touched).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>
#include <optional>
#include <vector>

#include "../coin/block.hpp"
#include "../coin/block_connector.hpp"
#include "../coin/compact_blocks.hpp"
#include "../coin/header_chain.hpp"
#include "../coin/mempool.hpp"
#include "../coin/merkle.hpp"
#include "../coin/transaction.hpp"

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

// A minimal spend of outpoint (prev_hash, prev_index) producing `out_value`.
// Distinct (prevout, value) tuples => distinct txids.
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

// Base header whose hash is fixed by the 80-byte header (txs do not feed
// block_hash directly, but m_merkle_root does), so it can be pinned as a
// fast-start checkpoint and seen as the best tip.
bch::coin::BlockType make_block(uint32_t nonce) {
    bch::coin::BlockType b;
    b.m_version = 0x20000000;
    b.m_previous_block.SetHex(
        "00000000000000000001a2b3c4d5e6f700000000000000000000000000000000");
    b.m_merkle_root.SetHex(
        "2222222222222222222222222222222222222222222222222222222222222222");
    b.m_timestamp = 1700000000;
    b.m_bits = 0x1d00ffff;
    b.m_nonce = nonce;
    return b;
}

// Header that COMMITS to `body`: m_merkle_root = SHA256d merkle over the body's
// txids (the same SSOT walk ReconstructBlock's backstop uses). Required now that
// reconstruction is checked against the header commitment.
bch::coin::BlockType make_block_committing(
    uint32_t nonce, const std::vector<bch::coin::MutableTransaction>& body) {
    bch::coin::BlockType b = make_block(nonce);
    std::vector<uint256> txids;
    txids.reserve(body.size());
    for (const auto& tx : body)
        txids.push_back(bch::coin::compute_txid(tx));
    b.m_merkle_root = bch::coin::compute_merkle_root(txids);
    return b;
}

const char* OUTPOINT_CB = "c0ffee0000000000000000000000000000000000000000000000000000000000";
const char* OUTPOINT_A  = "aa00000000000000000000000000000000000000000000000000000000000000";
const char* OUTPOINT_M  = "11d1551100000000000000000000000000000000000000000000000000000000";
const char* OUTPOINT_C  = "cc00000000000000000000000000000000000000000000000000000000000000";
const char* OUTPOINT_W  = "44e0000000000000000000000000000000000000000000000000000000000000";

// A HeaderChain whose fast-start checkpoint IS `header`'s hash at height H, so
// the connector's best-chain gate treats that header as the tip without fighting
// PoW/difficulty validation (same technique as the other connector tests).
bch::coin::HeaderChain make_chain_pinning(const bch::coin::BlockHeaderType& header,
                                          uint32_t H) {
    using namespace bch::coin;
    BCHChainParams params = BCHChainParams::mainnet();
    params.fast_start_checkpoint =
        BCHChainParams::Checkpoint{H, block_hash(header)};
    return HeaderChain(params);
}

} // namespace

int main() {
    using namespace bch::coin;

    const uint32_t H = 800002;

    MutableTransaction coinbase = make_tx(OUTPOINT_CB, 0xffffffff, 50);
    MutableTransaction tx_A     = make_tx(OUTPOINT_A, 0, 100);  // mempool-known
    MutableTransaction tx_M     = make_tx(OUTPOINT_M, 0, 200);  // missing from mempool
    MutableTransaction tx_C     = make_tx(OUTPOINT_C, 0, 300);  // unrelated survivor
    MutableTransaction tx_W     = make_tx(OUTPOINT_W, 0, 400);  // "wrong" collision tx
    const uint256 id_A = compute_txid(tx_A);
    const uint256 id_M = compute_txid(tx_M);
    const uint256 id_C = compute_txid(tx_C);
    const uint256 id_W = compute_txid(tx_W);
    CHECK(id_A != id_M && id_A != id_C && id_M != id_C);
    CHECK(id_W != id_A && id_W != id_M);

    // ---- 1) Complete-from-mempool: no getblocktxn round ------------------
    {
        BlockType hdr = make_block_committing(/*nonce=*/7, {coinbase, tx_A});
        const BlockHeaderType& header = static_cast<const BlockHeaderType&>(hdr);
        const uint256 blk_hash = block_hash(header);

        HeaderChain chain = make_chain_pinning(header, H);
        CHECK(chain.init());
        CHECK(chain.tip() && chain.tip()->block_hash == blk_hash);

        Mempool pool;
        CHECK(pool.add_tx(tx_A));
        CHECK(pool.add_tx(tx_C));
        CHECK(pool.size() == 2);

        BlockConnector conn(chain, pool);

        // Block body = [coinbase, tx_A]; tx_A is in the mempool -> reconstructs
        // with no missing txs and passes the header merkle backstop.
        CompactBlock cb = BuildCompactBlock(header, {coinbase, tx_A}, /*nonce=*/99);
        std::optional<BlockTransactionsRequest> req = conn.on_compact_block(cb);

        CHECK(!req.has_value());                  // fully reconstructed, no round-trip
        CHECK(conn.pending_compact_count() == 0); // nothing parked
        CHECK(!pool.contains(id_A));              // tx_A confirmed -> reconciled out
        CHECK(pool.contains(id_C));               // unrelated tx survives
        CHECK(pool.size() == 1);
    }

    // ---- 2) Missing tx -> getblocktxn -> blocktxn completes --------------
    {
        BlockType hdr = make_block_committing(/*nonce=*/7, {coinbase, tx_M});
        const BlockHeaderType& header = static_cast<const BlockHeaderType&>(hdr);
        const uint256 blk_hash = block_hash(header);

        HeaderChain chain = make_chain_pinning(header, H);
        CHECK(chain.init());

        Mempool pool;
        CHECK(pool.add_tx(tx_C));                  // unrelated; tx_M deliberately absent
        CHECK(pool.size() == 1);

        BlockConnector conn(chain, pool);

        // Block body = [coinbase, tx_M]; tx_M not in mempool -> index 1 missing.
        CompactBlock cb = BuildCompactBlock(header, {coinbase, tx_M}, /*nonce=*/99);
        std::optional<BlockTransactionsRequest> req = conn.on_compact_block(cb);

        CHECK(req.has_value());                            // round-trip needed
        CHECK(req && req->blockhash == blk_hash);
        CHECK(req && req->indexes.size() == 1 && req->indexes[0] == 1);
        CHECK(conn.pending_compact_count() == 1);          // parked awaiting blocktxn
        CHECK(pool.contains(id_C));                        // nothing reconciled yet

        // Peer answers with the requested tx (response order == request order).
        BlockTransactionsResponse resp;
        resp.blockhash = blk_hash;
        resp.txs.push_back(tx_M);
        bool connected = conn.on_block_txn(resp);

        CHECK(connected);                                  // reconstruction completed
        CHECK(conn.pending_compact_count() == 0);          // parked entry cleared
    }

    // ---- 3) Unknown/expired blocktxn is a clean no-op --------------------
    {
        BlockType hdr = make_block(/*nonce=*/3);   // no reconstruction here
        const BlockHeaderType& header = static_cast<const BlockHeaderType&>(hdr);
        HeaderChain chain = make_chain_pinning(header, H);
        CHECK(chain.init());
        Mempool pool;
        BlockConnector conn(chain, pool);

        BlockTransactionsResponse resp;
        resp.blockhash.SetHex(
            "dead00000000000000000000000000000000000000000000000000000000beef");
        resp.txs.push_back(tx_M);
        bool connected = conn.on_block_txn(resp);

        CHECK(!connected);                                 // nothing parked -> no-op
        CHECK(conn.pending_compact_count() == 0);
    }

    // ---- 4) Merkle backstop: honest reconstruction verifies + completes --
    {
        // Header commits to [coinbase, tx_A]; the slot tx IS tx_A.
        BlockType hdr = make_block_committing(/*nonce=*/11, {coinbase, tx_A});
        const BlockHeaderType& header = static_cast<const BlockHeaderType&>(hdr);
        CompactBlock cb = BuildCompactBlock(header, {coinbase, tx_A}, /*nonce=*/0x5151);

        std::map<uint256, MutableTransaction> known;
        known[id_A] = tx_A;                                // txid-keyed (BCH: == wtxid)

        auto rec = ReconstructBlock(cb, known);

        CHECK(rec.complete);                               // honest block accepted
        CHECK(!rec.merkle_mismatch);
        CHECK(rec.missing_indexes.empty());
        CHECK(rec.block.m_txs.size() == 2);
        CHECK(compute_txid(rec.block.m_txs[1]) == id_A);
    }

    // ---- 5) Merkle backstop: collision substitutes wrong tx -> DISCARD ----
    {
        // Header commits to the HONEST body [coinbase, tx_A]...
        BlockType hdr = make_block_committing(/*nonce=*/13, {coinbase, tx_A});
        const BlockHeaderType& header = static_cast<const BlockHeaderType&>(hdr);

        // ...but the compact block's single short ID is computed over tx_W (the
        // "wrong" tx), modelling a 48-bit short-ID collision that resolves the
        // slot to tx_W. The reconstructed body [coinbase, tx_W] therefore hashes
        // to a DIFFERENT merkle root than the header committed to.
        CompactBlock cb = BuildCompactBlock(header, {coinbase, tx_W}, /*nonce=*/0x5151);

        std::map<uint256, MutableTransaction> known;
        known[id_W] = tx_W;                                // only the wrong tx is available

        auto rec = ReconstructBlock(cb, known);

        CHECK(!rec.complete);                              // NOT delivered
        CHECK(rec.merkle_mismatch);                        // signals the getdata fallback
        CHECK(rec.block.m_txs.empty());                    // discard-not-deliver: no forgery
        CHECK(rec.missing_indexes.empty());                // all slots filled -> not getblocktxn
    }

    // ---- 6) ID-path round trip: BCH keys BOTH passes by txid --------------
    {
        // BCH has no wtxid (no SegWit). BuildCompactBlock computes the short ID
        // over compute_txid(); the reconstruct pass recomputes the same short ID
        // from the same txid. Pin that the two keys are IDENTICAL, so the
        // cmpctblock and blocktxn passes cannot diverge on BCH.
        BlockType hdr = make_block_committing(/*nonce=*/17, {coinbase, tx_A});
        const BlockHeaderType& header = static_cast<const BlockHeaderType&>(hdr);
        CompactBlock cb = BuildCompactBlock(header, {coinbase, tx_A}, /*nonce=*/0xABCD);

        CHECK(cb.short_ids.size() == 1);
        uint64_t k0, k1; cb.GetSipHashKeys(k0, k1);
        // The reconstruct-pass key (over txid) equals the wire short ID the
        // builder emitted -> one and the same id-path.
        CHECK(CompactBlock::GetShortID(k0, k1, id_A) == cb.short_ids[0]);

        std::map<uint256, MutableTransaction> known;
        known[id_A] = tx_A;
        auto rec = ReconstructBlock(cb, known);
        CHECK(rec.complete && !rec.merkle_mismatch);
        CHECK(rec.block.m_txs.size() == 2);
    }

    if (failures == 0) {
        std::cout << "compact_block_connector_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "compact_block_connector_test: " << failures << " FAILURE(S)\n";
    return 1;
}
