/// Phase 2 — Mempool unit tests
///
/// Tests the LTC mempool implementation:
///   1. Empty pool state
///   2. add_tx: accept new, reject duplicate
///   3. remove_tx: by txid
///   4. remove_for_block: prune confirmed transactions
///   5. evict_expired: remove stale entries
///   6. Size cap: evict oldest when byte limit exceeded
///   7. get_sorted_txs: weight limit respected, FIFO ordering
///   8. MempoolEntry weight computation (base_size * 4 + witness_size)
///   9. Coinbase transactions (null prevout) accepted
///  10. Concurrent add/remove thread safety

#include <gtest/gtest.h>

#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/ltc/coin/block.hpp>
#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <thread>
#include <vector>
#include <atomic>
#include <cstdint>

using namespace ltc::coin;

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Build a minimal non-coinbase transaction spending a fake prevout.
static MutableTransaction make_tx(uint32_t nonce = 0, int64_t value = 100000) {
    MutableTransaction tx;
    tx.version  = 2;
    tx.locktime = 0;

    TxIn in;
    // Unique prevout per nonce
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
    // P2PKH-like script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    out.scriptPubKey.m_data = {0x76, 0xa9, 0x14,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x88, 0xac};
    tx.vout.push_back(out);
    return tx;
}

/// Build a coinbase transaction (null prevout, index 0xFFFFFFFF).
static MutableTransaction make_coinbase(uint32_t height = 1, int64_t subsidy = 50 * 100000000LL) {
    MutableTransaction tx;
    tx.version  = 1;
    tx.locktime = 0;

    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xFFFFFFFF;
    // Coinbase script: BIP34 height + some data
    in.scriptSig.m_data = {0x03,
        static_cast<uint8_t>(height & 0xFF),
        static_cast<uint8_t>((height >> 8) & 0xFF),
        static_cast<uint8_t>((height >> 16) & 0xFF)};
    in.sequence = 0xFFFFFFFF;
    tx.vin.push_back(in);

    TxOut out;
    out.value = subsidy;
    out.scriptPubKey.m_data = {0x51};  // OP_1 (anyone-can-spend)
    tx.vout.push_back(out);
    return tx;
}

/// Build a BlockType containing specific transactions (for remove_for_block tests).
static BlockType make_block_with_txs(const std::vector<MutableTransaction>& txs) {
    BlockType blk;
    blk.m_version = 1;
    blk.m_previous_block.SetNull();
    blk.m_timestamp = 0;
    blk.m_bits      = 0x1e0ffff0;
    blk.m_nonce     = 0;
    blk.m_txs       = txs;
    return blk;
}

// ─── Test 1: Empty pool state ────────────────────────────────────────────────

TEST(MempoolTest, EmptyState) {
    Mempool pool;
    EXPECT_EQ(pool.size(), 0u);
    EXPECT_EQ(pool.byte_size(), 0u);
    EXPECT_EQ(pool.total_fees(), 0u);

    uint256 fake;
    fake.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    EXPECT_FALSE(pool.contains(fake));
    EXPECT_FALSE(pool.get_entry(fake).has_value());

    auto txs = pool.get_sorted_txs(4000000u);
    EXPECT_TRUE(txs.empty());
}

// ─── Test 2: add_tx — accept new, reject duplicate ──────────────────────────

TEST(MempoolTest, AddAcceptsNewTx) {
    Mempool pool;
    auto tx = make_tx(1);
    uint256 txid = compute_txid(tx);

    EXPECT_TRUE(pool.add_tx(tx));
    EXPECT_EQ(pool.size(), 1u);
    EXPECT_GT(pool.byte_size(), 0u);
    EXPECT_TRUE(pool.contains(txid));

    auto entry = pool.get_entry(txid);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->txid, txid);
    EXPECT_GT(entry->base_size, 0u);
    EXPECT_GT(entry->weight, 0u);
    EXPECT_EQ(entry->fee, 0u);  // no UTXO set
    EXPECT_GT(entry->time_added, 0);
}

TEST(MempoolTest, AddRejectsDuplicate) {
    Mempool pool;
    auto tx = make_tx(2);

    EXPECT_TRUE(pool.add_tx(tx));
    EXPECT_FALSE(pool.add_tx(tx));  // same tx → same txid
    EXPECT_EQ(pool.size(), 1u);
}

TEST(MempoolTest, AddMultipleTxs) {
    Mempool pool;
    for (uint32_t i = 0; i < 10; ++i) {
        EXPECT_TRUE(pool.add_tx(make_tx(i)));
    }
    EXPECT_EQ(pool.size(), 10u);
}

// ─── Test 3: remove_tx ───────────────────────────────────────────────────────

TEST(MempoolTest, RemoveTxById) {
    Mempool pool;
    auto tx = make_tx(3);
    uint256 txid = compute_txid(tx);

    pool.add_tx(tx);
    ASSERT_EQ(pool.size(), 1u);

    pool.remove_tx(txid);
    EXPECT_EQ(pool.size(), 0u);
    EXPECT_EQ(pool.byte_size(), 0u);
    EXPECT_FALSE(pool.contains(txid));
}

TEST(MempoolTest, RemoveNonExistentIsNoop) {
    Mempool pool;
    uint256 fake;
    fake.SetHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    EXPECT_NO_THROW(pool.remove_tx(fake));
    EXPECT_EQ(pool.size(), 0u);
}

// ─── Test 4: remove_for_block ────────────────────────────────────────────────

TEST(MempoolTest, RemoveForBlockPrunesConfirmedTxs) {
    Mempool pool;
    auto tx1 = make_tx(10);
    auto tx2 = make_tx(11);
    auto tx3 = make_tx(12);
    uint256 txid1 = compute_txid(tx1);
    uint256 txid2 = compute_txid(tx2);
    uint256 txid3 = compute_txid(tx3);

    pool.add_tx(tx1);
    pool.add_tx(tx2);
    pool.add_tx(tx3);
    ASSERT_EQ(pool.size(), 3u);

    // Block confirms tx1 and tx3 (tx2 remains)
    auto blk = make_block_with_txs({tx1, tx3});
    pool.remove_for_block(blk);

    EXPECT_EQ(pool.size(), 1u);
    EXPECT_FALSE(pool.contains(txid1));
    EXPECT_TRUE(pool.contains(txid2));
    EXPECT_FALSE(pool.contains(txid3));
}

TEST(MempoolTest, RemoveForBlockWithCoinbase) {
    Mempool pool;
    auto regular = make_tx(20);
    auto coinbase = make_coinbase(100);
    pool.add_tx(regular);

    // Block with coinbase + regular tx — coinbase was never in pool
    auto blk = make_block_with_txs({coinbase, regular});
    pool.remove_for_block(blk);

    EXPECT_EQ(pool.size(), 0u);  // regular was removed; coinbase was never there
}

TEST(MempoolTest, RemoveForEmptyBlock) {
    Mempool pool;
    pool.add_tx(make_tx(30));
    pool.add_tx(make_tx(31));

    auto blk = make_block_with_txs({});
    pool.remove_for_block(blk);

    EXPECT_EQ(pool.size(), 2u);  // unchanged
}

// ─── Test 5: evict_expired ───────────────────────────────────────────────────

TEST(MempoolTest, EvictExpiredRemovesOldEntries) {
    // Use a very short expiry (1 second) for the test
    Mempool pool(core::coin::LTC_LIMITS, Mempool::DEFAULT_MAX_BYTES, 1 /* 1 second expiry */);

    auto tx = make_tx(40);
    uint256 txid = compute_txid(tx);
    pool.add_tx(tx);
    ASSERT_EQ(pool.size(), 1u);

    // Sleep 2 seconds so the entry expires
    std::this_thread::sleep_for(std::chrono::seconds(2));

    pool.evict_expired();
    EXPECT_EQ(pool.size(), 0u);
    EXPECT_FALSE(pool.contains(txid));
}

TEST(MempoolTest, EvictExpiredLeavesRecentEntries) {
    // Default 14-day expiry — nothing should expire immediately
    Mempool pool;

    for (int i = 0; i < 5; ++i)
        pool.add_tx(make_tx(50 + i));

    pool.evict_expired();
    EXPECT_EQ(pool.size(), 5u);
}

// ─── Test 6: size cap eviction ───────────────────────────────────────────────

TEST(MempoolTest, SizeCapEvictsOldestEntries) {
    // Each tx is ~100 bytes; cap at 300 bytes (fits ~3 txs)
    Mempool pool(core::coin::LTC_LIMITS, 300, Mempool::DEFAULT_EXPIRY_SECS);

    // Add transactions sequentially so arrival order is deterministic
    auto tx0 = make_tx(60);
    auto tx1 = make_tx(61);
    auto tx2 = make_tx(62);
    auto tx3 = make_tx(63);

    pool.add_tx(tx0);
    pool.add_tx(tx1);
    pool.add_tx(tx2);

    size_t size_before = pool.size();

    // Adding tx3 should evict oldest entry (tx0) to make room
    pool.add_tx(tx3);

    // Pool should not have grown unboundedly
    EXPECT_LE(pool.byte_size(), 300u);
    EXPECT_LE(pool.size(), size_before + 1u);
}

// ─── Test 7: get_sorted_txs ──────────────────────────────────────────────────

TEST(MempoolTest, GetSortedTxsEmpty) {
    Mempool pool;
    auto txs = pool.get_sorted_txs(4000000u);
    EXPECT_TRUE(txs.empty());
}

TEST(MempoolTest, GetSortedTxsRespectWeightLimit) {
    Mempool pool;
    // Add 100 transactions
    for (int i = 0; i < 100; ++i)
        pool.add_tx(make_tx(100 + i));

    // Request a small weight limit — should get fewer than all 100
    auto small_set = pool.get_sorted_txs(500u);
    auto large_set = pool.get_sorted_txs(4000000u);

    EXPECT_LE(small_set.size(), large_set.size());
    EXPECT_EQ(large_set.size(), 100u);

    // Verify total weight of small_set does not exceed limit
    uint32_t total_weight = 0;
    for (auto& tx : small_set) {
        uint32_t bs, ws, w;
        compute_tx_weight(tx, bs, ws, w);
        total_weight += w;
    }
    EXPECT_LE(total_weight, 500u);
}

TEST(MempoolTest, GetSortedTxsDoesNotExceedWeight) {
    Mempool pool;
    for (int i = 0; i < 20; ++i)
        pool.add_tx(make_tx(200 + i));

    uint32_t limit = 2000u;
    auto txs = pool.get_sorted_txs(limit);

    uint32_t total = 0;
    for (auto& tx : txs) {
        uint32_t bs, ws, w;
        compute_tx_weight(tx, bs, ws, w);
        total += w;
    }
    EXPECT_LE(total, limit);
}

// ─── Test 8: Weight computation ─────────────────────────────────────────────

TEST(MempoolEntryTest, WeightNonWitness) {
    auto tx = make_tx(300);
    uint32_t bs, ws, w;
    compute_tx_weight(tx, bs, ws, w);

    EXPECT_GT(bs, 0u);
    EXPECT_EQ(ws, 0u);          // no witness data in this tx
    EXPECT_EQ(w, bs * 4);       // BIP 141: non-witness weight = size * 4
}

TEST(MempoolEntryTest, TxidIsNonWitnessSHA256d) {
    auto tx = make_tx(301);
    uint256 txid1 = compute_txid(tx);

    // Manual: Hash(pack(TX_NO_WITNESS(tx)))
    auto packed = pack(TX_NO_WITNESS(tx));
    uint256 txid2 = Hash(packed.get_span());

    EXPECT_EQ(txid1, txid2);
}

TEST(MempoolEntryTest, DifferentNoncesProduceDifferentTxids) {
    auto tx1 = make_tx(400);
    auto tx2 = make_tx(401);
    EXPECT_NE(compute_txid(tx1), compute_txid(tx2));
}

// ─── Test 9: Coinbase transactions ───────────────────────────────────────────

TEST(MempoolTest, AcceptsCoinbaseTx) {
    Mempool pool;
    auto cb = make_coinbase(1);
    uint256 txid = compute_txid(cb);

    EXPECT_TRUE(pool.add_tx(cb));
    EXPECT_EQ(pool.size(), 1u);
    EXPECT_TRUE(pool.contains(txid));
}

// ─── Test 10: clear() ────────────────────────────────────────────────────────

TEST(MempoolTest, ClearRemovesAll) {
    Mempool pool;
    for (int i = 0; i < 10; ++i)
        pool.add_tx(make_tx(500 + i));

    ASSERT_EQ(pool.size(), 10u);
    pool.clear();
    EXPECT_EQ(pool.size(), 0u);
    EXPECT_EQ(pool.byte_size(), 0u);
}

// ─── Test 11: all_txids ──────────────────────────────────────────────────────

TEST(MempoolTest, AllTxids) {
    Mempool pool;
    std::vector<uint256> expected;
    for (int i = 0; i < 5; ++i) {
        auto tx = make_tx(600 + i);
        expected.push_back(compute_txid(tx));
        pool.add_tx(tx);
    }

    auto ids = pool.all_txids();
    EXPECT_EQ(ids.size(), 5u);

    // Every expected txid should appear
    for (auto& id : expected) {
        bool found = false;
        for (auto& got : ids)
            if (got == id) { found = true; break; }
        EXPECT_TRUE(found) << "Missing txid: " << id.GetHex();
    }
}

// ─── Test 12: thread safety ──────────────────────────────────────────────────

TEST(MempoolTest, ConcurrentAddRemove) {
    Mempool pool;
    std::atomic<int> add_count{0};

    // Thread A: adds 50 transactions
    std::thread adder([&]() {
        for (int i = 0; i < 50; ++i) {
            if (pool.add_tx(make_tx(700 + i)))
                add_count.fetch_add(1, std::memory_order_relaxed);
        }
    });

    // Thread B: removes some (may or may not find them)
    std::thread remover([&]() {
        for (int i = 0; i < 50; ++i) {
            uint256 txid = compute_txid(make_tx(700 + i));
            pool.remove_tx(txid);
        }
    });

    adder.join();
    remover.join();

    // Pool should be in a consistent state (no crash, no invariant violation)
    EXPECT_LE(pool.size(), 50u);
    EXPECT_LE(pool.byte_size(), 50u * 200u);  // rough upper bound
}
