// ---------------------------------------------------------------------------
// bch::coin BlockConnector compact-block test (M5 full-block body, slice (b):
// BIP152 compact-block depth on the connector seam).
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
// Build posture matches the other connector tests: header-only over coin/*.hpp +
// <core/*>, plus coin/transaction.cpp for the MutableTransaction ctors and the
// btclibs lib for SipHash. impl_bch is NOT linked -> per-coin isolation holds.
// p2pool-merged-v36 surface: NONE (local compact-block reconstruction + the same
// block-connect/mempool hygiene; no PoW/share/coinbase/PPLNS touched).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>
#include <optional>

#include "../coin/block.hpp"
#include "../coin/block_connector.hpp"
#include "../coin/compact_blocks.hpp"
#include "../coin/header_chain.hpp"
#include "../coin/mempool.hpp"
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

// Header whose hash is fixed by the 80-byte header (txs do not feed block_hash),
// so it can be pinned as a fast-start checkpoint and seen as the best tip.
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

const char* OUTPOINT_CB = "c0ffee0000000000000000000000000000000000000000000000000000000000";
const char* OUTPOINT_A  = "aa00000000000000000000000000000000000000000000000000000000000000";
const char* OUTPOINT_M  = "11d1551100000000000000000000000000000000000000000000000000000000";
const char* OUTPOINT_C  = "cc00000000000000000000000000000000000000000000000000000000000000";

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

    // Shared header -> shared block hash -> shared checkpoint across cases.
    BlockType hdr_block = make_block(/*nonce=*/7);
    const BlockHeaderType& header = static_cast<const BlockHeaderType&>(hdr_block);
    const uint256 blk_hash = block_hash(header);

    MutableTransaction coinbase = make_tx(OUTPOINT_CB, 0xffffffff, 50);
    MutableTransaction tx_A     = make_tx(OUTPOINT_A, 0, 100);  // mempool-known
    MutableTransaction tx_M     = make_tx(OUTPOINT_M, 0, 200);  // missing from mempool
    MutableTransaction tx_C     = make_tx(OUTPOINT_C, 0, 300);  // unrelated survivor
    const uint256 id_A = compute_txid(tx_A);
    const uint256 id_M = compute_txid(tx_M);
    const uint256 id_C = compute_txid(tx_C);
    CHECK(id_A != id_M && id_A != id_C && id_M != id_C);

    // ---- 1) Complete-from-mempool: no getblocktxn round ------------------
    {
        HeaderChain chain = make_chain_pinning(header, H);
        CHECK(chain.init());
        CHECK(chain.tip() && chain.tip()->block_hash == blk_hash);

        Mempool pool;
        CHECK(pool.add_tx(tx_A));
        CHECK(pool.add_tx(tx_C));
        CHECK(pool.size() == 2);

        BlockConnector conn(chain, pool);

        // Block body = [coinbase, tx_A]; tx_A is in the mempool -> reconstructs
        // with no missing txs.
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

    if (failures == 0) {
        std::cout << "compact_block_connector_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "compact_block_connector_test: " << failures << " FAILURE(S)\n";
    return 1;
}
