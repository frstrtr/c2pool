/// BIP 152 Compact Block unit tests
///
/// Tests:
///   1. ShortTxID: round-trip uint64 ↔ bytes
///   2. ShortTxID: deterministic SipHash computation
///   3. CompactBlock: BuildCompactBlock with coinbase prefilled
///   4. CompactBlock: serialize/deserialize round-trip
///   5. CompactBlock: full reconstruction from mempool
///   6. CompactBlock: partial reconstruction with missing txs
///   7. CompactBlock: short ID collision detection
///   8. BlockTransactionsRequest: differential index encoding round-trip
///   9. BlockTransactionsResponse: serialize/deserialize round-trip
///  10. P2P message: cmpctblock make_raw/parse round-trip
///  11. P2P message: getblocktxn make_raw/parse round-trip
///  12. P2P message: blocktxn make_raw/parse round-trip
///  13. Compression ratio: compact vs full block size

#include <gtest/gtest.h>

#include <impl/ltc/coin/compact_blocks.hpp>
#include <impl/ltc/coin/p2p_messages.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/ltc/coin/block.hpp>
#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <vector>
#include <map>
#include <cstdint>

using namespace ltc::coin;
using namespace ltc::coin::p2p;

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Build a minimal transaction with a unique nonce.
static MutableTransaction make_tx(uint32_t nonce, int64_t value = 50000) {
    MutableTransaction tx;
    tx.version  = 2;
    tx.locktime = 0;

    TxIn in;
    in.prevout.hash.SetNull();
    uint8_t* d = in.prevout.hash.data();
    d[0] = (nonce >> 24) & 0xFF;
    d[1] = (nonce >> 16) & 0xFF;
    d[2] = (nonce >> 8)  & 0xFF;
    d[3] = nonce & 0xFF;
    in.prevout.index = nonce;
    in.sequence = 0xFFFFFFFF;
    tx.vin.push_back(in);

    TxOut out;
    out.value = value;
    out.scriptPubKey.m_data.resize(25, 0x76);  // OP_DUP placeholder
    tx.vout.push_back(out);

    return tx;
}

/// Build a coinbase transaction.
static MutableTransaction make_coinbase(int64_t reward = 1250000000) {
    MutableTransaction tx;
    tx.version  = 2;
    tx.locktime = 0;

    TxIn in;
    in.prevout.hash.SetNull();  // null prevout = coinbase
    in.prevout.index = 0xFFFFFFFF;
    in.sequence = 0xFFFFFFFF;
    // Coinbase script: block height + extra nonce
    in.scriptSig.m_data = {0x03, 0x01, 0x00, 0x00};
    tx.vin.push_back(in);

    TxOut out;
    out.value = reward;
    out.scriptPubKey.m_data.resize(25, 0xa9);  // P2SH placeholder
    tx.vout.push_back(out);

    return tx;
}

/// Build a test block with given transactions.
static BlockType make_block(const std::vector<MutableTransaction>& txs) {
    BlockType block;
    block.m_version = 0x20000000;
    block.m_previous_block.SetNull();
    block.m_merkle_root.SetNull();
    block.m_timestamp = 1700000000;
    block.m_bits = 0x1d00ffff;
    block.m_nonce = 42;
    block.m_txs = txs;
    return block;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

TEST(CompactBlockTest, ShortTxID_RoundTrip) {
    // Verify uint64 ↔ bytes round-trip
    uint64_t original = 0x0102030405060000ULL & 0xFFFFFFFFFFFFULL;
    ShortTxID sid(original);
    EXPECT_EQ(sid.to_uint64(), original);

    ShortTxID sid2(0);
    EXPECT_EQ(sid2.to_uint64(), 0ULL);

    ShortTxID sid3(0xFFFFFFFFFFFFULL);
    EXPECT_EQ(sid3.to_uint64(), 0xFFFFFFFFFFFFULL);
}

TEST(CompactBlockTest, ShortTxID_SerializeDeserialize) {
    ShortTxID sid(0xAABBCCDDEEFFULL);
    PackStream ps;
    ps << sid;
    EXPECT_EQ(ps.size(), 6u);

    ShortTxID sid2;
    ps >> sid2;
    EXPECT_EQ(sid, sid2);
}

TEST(CompactBlockTest, GetShortID_Deterministic) {
    // Same header+nonce+txid should always produce the same short ID
    auto coinbase = make_coinbase();
    auto tx1 = make_tx(1);
    auto block = make_block({coinbase, tx1});

    CompactBlock cb;
    cb.header = static_cast<BlockHeaderType>(block);
    cb.nonce = 12345;

    uint256 txid = compute_txid(tx1);
    ShortTxID sid1 = cb.GetShortID(txid);
    ShortTxID sid2 = cb.GetShortID(txid);
    EXPECT_EQ(sid1, sid2);

    // Different nonce → different short ID
    cb.nonce = 54321;
    ShortTxID sid3 = cb.GetShortID(txid);
    EXPECT_NE(sid1, sid3);
}

TEST(CompactBlockTest, GetShortID_BatchConsistency) {
    auto coinbase = make_coinbase();
    auto block = make_block({coinbase});
    CompactBlock cb;
    cb.header = static_cast<BlockHeaderType>(block);
    cb.nonce = 999;

    auto tx1 = make_tx(1);
    uint256 txid = compute_txid(tx1);

    // Single-call vs batch (pre-computed keys) should match
    ShortTxID single = cb.GetShortID(txid);

    uint64_t k0, k1;
    cb.GetSipHashKeys(k0, k1);
    ShortTxID batch = CompactBlock::GetShortID(k0, k1, txid);

    EXPECT_EQ(single, batch);
}

TEST(CompactBlockTest, BuildCompactBlock_CoinbasePrefilled) {
    auto coinbase = make_coinbase();
    auto tx1 = make_tx(1);
    auto tx2 = make_tx(2);
    auto tx3 = make_tx(3);
    auto block = make_block({coinbase, tx1, tx2, tx3});

    auto cb = BuildCompactBlock(
        static_cast<BlockHeaderType>(block), block.m_txs, 0);

    // Coinbase should be prefilled at index 0
    EXPECT_EQ(cb.prefilled_txns.size(), 1u);
    EXPECT_EQ(cb.prefilled_txns[0].index, 0u);

    // 3 non-coinbase txs → 3 short IDs
    EXPECT_EQ(cb.short_ids.size(), 3u);

    // Verify short IDs match expected
    uint64_t k0, k1;
    cb.GetSipHashKeys(k0, k1);
    for (size_t i = 0; i < 3; ++i) {
        uint256 txid = compute_txid(block.m_txs[i + 1]);
        ShortTxID expected = CompactBlock::GetShortID(k0, k1, txid);
        EXPECT_EQ(cb.short_ids[i], expected);
    }
}

TEST(CompactBlockTest, CompactBlock_SerializeRoundTrip) {
    auto coinbase = make_coinbase();
    auto tx1 = make_tx(1);
    auto tx2 = make_tx(2);
    auto block = make_block({coinbase, tx1, tx2});

    auto cb = BuildCompactBlock(
        static_cast<BlockHeaderType>(block), block.m_txs, 42);

    // Serialize
    PackStream ps;
    cb.Serialize(ps);
    size_t compact_size = ps.size();
    EXPECT_GT(compact_size, 0u);

    // Deserialize
    CompactBlock cb2;
    cb2.Unserialize(ps);

    // Verify fields match
    EXPECT_EQ(cb2.nonce, 42u);
    EXPECT_EQ(cb2.short_ids.size(), cb.short_ids.size());
    EXPECT_EQ(cb2.prefilled_txns.size(), cb.prefilled_txns.size());
    for (size_t i = 0; i < cb.short_ids.size(); ++i)
        EXPECT_EQ(cb2.short_ids[i], cb.short_ids[i]);
    EXPECT_EQ(cb2.prefilled_txns[0].index, 0u);
}

TEST(CompactBlockTest, FullReconstruction) {
    auto coinbase = make_coinbase();
    auto tx1 = make_tx(1);
    auto tx2 = make_tx(2);
    auto tx3 = make_tx(3);
    auto block = make_block({coinbase, tx1, tx2, tx3});

    auto cb = BuildCompactBlock(
        static_cast<BlockHeaderType>(block), block.m_txs, 0);

    // Build known tx map (simulating mempool)
    std::map<uint256, MutableTransaction> known;
    known[compute_txid(tx1)] = tx1;
    known[compute_txid(tx2)] = tx2;
    known[compute_txid(tx3)] = tx3;

    auto result = ReconstructBlock(cb, known);
    EXPECT_TRUE(result.complete);
    EXPECT_TRUE(result.missing_indexes.empty());
    EXPECT_EQ(result.block.m_txs.size(), 4u);
}

TEST(CompactBlockTest, PartialReconstruction_MissingTxs) {
    auto coinbase = make_coinbase();
    auto tx1 = make_tx(1);
    auto tx2 = make_tx(2);
    auto tx3 = make_tx(3);
    auto block = make_block({coinbase, tx1, tx2, tx3});

    auto cb = BuildCompactBlock(
        static_cast<BlockHeaderType>(block), block.m_txs, 0);

    // Only provide tx1, missing tx2 and tx3
    std::map<uint256, MutableTransaction> known;
    known[compute_txid(tx1)] = tx1;

    auto result = ReconstructBlock(cb, known);
    EXPECT_FALSE(result.complete);
    EXPECT_EQ(result.missing_indexes.size(), 2u);
}

TEST(CompactBlockTest, EmptyBlock_OnlyCoinbase) {
    auto coinbase = make_coinbase();
    auto block = make_block({coinbase});

    auto cb = BuildCompactBlock(
        static_cast<BlockHeaderType>(block), block.m_txs, 0);

    EXPECT_EQ(cb.short_ids.size(), 0u);
    EXPECT_EQ(cb.prefilled_txns.size(), 1u);

    // Reconstruction with empty mempool should succeed (coinbase is prefilled)
    std::map<uint256, MutableTransaction> known;
    auto result = ReconstructBlock(cb, known);
    EXPECT_TRUE(result.complete);
    EXPECT_EQ(result.block.m_txs.size(), 1u);
}

TEST(CompactBlockTest, BlockTransactionsRequest_DiffIndexRoundTrip) {
    BlockTransactionsRequest req;
    req.blockhash = uint256S("0000000000000000000aabbccddee00112233445566778899aabbccddeeff00");
    req.indexes = {0, 3, 7, 15, 100};

    PackStream ps;
    req.Serialize(ps);

    BlockTransactionsRequest req2;
    req2.Unserialize(ps);

    EXPECT_EQ(req2.blockhash, req.blockhash);
    EXPECT_EQ(req2.indexes.size(), req.indexes.size());
    for (size_t i = 0; i < req.indexes.size(); ++i)
        EXPECT_EQ(req2.indexes[i], req.indexes[i]);
}

TEST(CompactBlockTest, BlockTransactionsResponse_RoundTrip) {
    BlockTransactionsResponse resp;
    resp.blockhash = uint256S("0000000000000000000aabbccddee00112233445566778899aabbccddeeff00");
    resp.txs.push_back(make_tx(1));
    resp.txs.push_back(make_tx(2));

    PackStream ps;
    resp.Serialize(ps);

    BlockTransactionsResponse resp2;
    resp2.Unserialize(ps);

    EXPECT_EQ(resp2.blockhash, resp.blockhash);
    EXPECT_EQ(resp2.txs.size(), 2u);
}

TEST(CompactBlockTest, Message_CmpctBlock_RoundTrip) {
    auto coinbase = make_coinbase();
    auto tx1 = make_tx(1);
    auto block = make_block({coinbase, tx1});
    auto cb = BuildCompactBlock(
        static_cast<BlockHeaderType>(block), block.m_txs, 77);

    // Build raw message
    auto rmsg = message_cmpctblock::make_raw(cb);
    EXPECT_EQ(rmsg->m_command, "cmpctblock");
    EXPECT_GT(rmsg->m_data.size(), 0u);

    // Parse it back
    auto parsed = message_cmpctblock::make(rmsg->m_data);
    EXPECT_EQ(parsed->m_compact_block.nonce, 77u);
    EXPECT_EQ(parsed->m_compact_block.short_ids.size(), 1u);
    EXPECT_EQ(parsed->m_compact_block.prefilled_txns.size(), 1u);
}

TEST(CompactBlockTest, Message_GetBlockTxn_RoundTrip) {
    BlockTransactionsRequest req;
    req.blockhash = uint256S("00000000000000000011223344556677");
    req.indexes = {1, 5, 10};

    auto rmsg = message_getblocktxn::make_raw(req);
    EXPECT_EQ(rmsg->m_command, "getblocktxn");

    auto parsed = message_getblocktxn::make(rmsg->m_data);
    EXPECT_EQ(parsed->m_request.blockhash, req.blockhash);
    EXPECT_EQ(parsed->m_request.indexes, req.indexes);
}

TEST(CompactBlockTest, Message_BlockTxn_RoundTrip) {
    BlockTransactionsResponse resp;
    resp.blockhash = uint256S("00000000000000000011223344556677");
    resp.txs.push_back(make_tx(42));
    resp.txs.push_back(make_tx(43));

    auto rmsg = message_blocktxn::make_raw(resp);
    EXPECT_EQ(rmsg->m_command, "blocktxn");

    auto parsed = message_blocktxn::make(rmsg->m_data);
    EXPECT_EQ(parsed->m_response.blockhash, resp.blockhash);
    EXPECT_EQ(parsed->m_response.txs.size(), 2u);
}

TEST(CompactBlockTest, CompressionRatio) {
    // Build a realistic block with 50 transactions
    auto coinbase = make_coinbase();
    std::vector<MutableTransaction> txs;
    txs.push_back(coinbase);
    for (uint32_t i = 1; i <= 50; ++i)
        txs.push_back(make_tx(i));

    auto block = make_block(txs);

    // Full block size
    auto full_ps = pack(TX_WITH_WITNESS(block));
    size_t full_size = full_ps.size();

    // Compact block size
    auto cb = BuildCompactBlock(
        static_cast<BlockHeaderType>(block), block.m_txs, 0);
    PackStream compact_ps;
    cb.Serialize(compact_ps);
    size_t compact_size = compact_ps.size();

    // Compact should be significantly smaller
    EXPECT_LT(compact_size, full_size);

    // With 50 txs, expect >50% reduction (short IDs are 6 bytes vs ~100+ byte txs)
    double ratio = static_cast<double>(compact_size) / static_cast<double>(full_size);
    EXPECT_LT(ratio, 0.5) << "Compact block should be <50% of full block size"
                           << " (full=" << full_size << ", compact=" << compact_size
                           << ", ratio=" << ratio << ")";
}
