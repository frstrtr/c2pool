/// Phase C-MEMPOOL step 1+2 — Dash in-memory mempool unit tests
///
/// Exercises the storage layer, UTXO-fee computation, LRU size-cap
/// eviction, double-spend conflict removal on block-connect, and the
/// feerate-sorted selection used by the embedded GBT template builder
/// (Phase C-TEMPLATE prerequisite, S7).
///
/// The mempool was adapted from src/impl/ltc/coin/mempool.hpp with the
/// Dash simplifications (no segwit, no weight, no wtxid index). These
/// tests pin the behaviour that the embedded_gbt builder depends on:
///   - add/dup-reject/remove
///   - fee = sum(inputs) - sum(outputs) from the UTXO view
///   - fee_known=false when inputs are not in the UTXO (kept out of the
///     sorted view so they cannot poison coinbasevalue)
///   - size-cap eviction is LRU (oldest time_added first)
///   - remove_for_block evicts confirmed txs AND their double-spend
///     conflicts
///   - get_sorted_txs_with_fees returns highest-feerate-first

#include <gtest/gtest.h>

#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/mempool.hpp>

#include <core/uint256.hpp>
#include <core/coin/utxo_view_cache.hpp>

#include <algorithm>
#include <cstdint>
#include <vector>

using dash::coin::Mempool;
using dash::coin::MutableTransaction;
using dash::coin::dash_txid;
using dash::coin::BlockType;
using ::core::coin::UTXOViewCache;
using ::core::coin::Outpoint;
using ::core::coin::Coin;
using ::bitcoin_family::coin::TxIn;
using ::bitcoin_family::coin::TxOut;

// ─── Fixture helpers ─────────────────────────────────────────────────────────

// A distinct uint256 minted from a small integer (via the canonical
// pack+Hash of a locktime-varied empty tx), used as a prevout hash.
static uint256 mint_hash(uint32_t seed) {
    MutableTransaction t;
    t.version = 1;
    t.type = 0;
    t.locktime = 0x51000000u ^ seed;   // keep the seeds out of the tx-fixture range
    auto ps = ::pack(t);
    return ::Hash(ps.get_span());
}

static TxIn make_input(const uint256& prev_hash, uint32_t prev_index) {
    TxIn in;
    in.prevout.hash = prev_hash;
    in.prevout.index = prev_index;
    in.sequence = 0xffffffffu;
    return in;
}

static TxOut make_output(int64_t value) {
    TxOut out;
    out.value = value;
    return out;
}

// Build a spending tx: one input (prev_hash:prev_index) and one output
// of `out_value`. `salt` perturbs the locktime so otherwise-identical
// txs get distinct txids.
static MutableTransaction make_spend(const uint256& prev_hash,
                                     uint32_t prev_index,
                                     int64_t out_value,
                                     uint32_t salt = 0) {
    MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = salt;
    tx.vin.push_back(make_input(prev_hash, prev_index));
    tx.vout.push_back(make_output(out_value));
    return tx;
}

static MutableTransaction make_empty(uint32_t locktime) {
    MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = locktime;
    return tx;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

TEST(DashMempool, AddContainsAndSize)
{
    Mempool mp;
    auto tx = make_empty(1);
    uint256 txid = dash_txid(tx);

    EXPECT_TRUE(mp.add_tx(tx));
    EXPECT_TRUE(mp.contains(txid));
    EXPECT_EQ(mp.size(), 1u);
    EXPECT_GT(mp.byte_size(), 0u);
}

TEST(DashMempool, DuplicateRejected)
{
    Mempool mp;
    auto tx = make_empty(2);
    EXPECT_TRUE(mp.add_tx(tx));
    EXPECT_FALSE(mp.add_tx(tx))
        << "second add of the same txid must be rejected";
    EXPECT_EQ(mp.size(), 1u);
}

TEST(DashMempool, RemoveTx)
{
    Mempool mp;
    auto tx = make_empty(3);
    uint256 txid = dash_txid(tx);
    mp.add_tx(tx);
    ASSERT_TRUE(mp.contains(txid));

    mp.remove_tx(txid);
    EXPECT_FALSE(mp.contains(txid));
    EXPECT_EQ(mp.size(), 0u);
    EXPECT_EQ(mp.byte_size(), 0u);
}

TEST(DashMempool, FeeUnknownWithoutUtxo)
{
    Mempool mp;
    uint256 prev = mint_hash(10);
    auto tx = make_spend(prev, 0, 90'000, /*salt=*/1);

    EXPECT_TRUE(mp.add_tx(tx));                 // no UTXO set
    auto entry = mp.get_entry(dash_txid(tx));
    ASSERT_TRUE(entry.has_value());
    EXPECT_FALSE(entry->fee_known)
        << "without a UTXO view the input value is unknown";
    EXPECT_EQ(mp.total_known_fees(), 0u);
}

TEST(DashMempool, FeeComputedFromUtxo)
{
    UTXOViewCache utxo(nullptr);
    uint256 prev = mint_hash(20);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, /*height=*/1, /*cb=*/false));

    Mempool mp;
    mp.set_utxo(&utxo);

    auto tx = make_spend(prev, 0, 90'000, /*salt=*/1);
    EXPECT_TRUE(mp.add_tx(tx));

    auto entry = mp.get_entry(dash_txid(tx));
    ASSERT_TRUE(entry.has_value());
    EXPECT_TRUE(entry->fee_known);
    EXPECT_EQ(entry->fee, 10'000u)            // 100000 in - 90000 out
        << "fee must equal sum(inputs) - sum(outputs)";
    EXPECT_EQ(mp.total_known_fees(), 10'000u);
}

TEST(DashMempool, RecomputeUnknownFeesAfterUtxoArrives)
{
    Mempool mp;
    uint256 prev = mint_hash(30);
    auto tx = make_spend(prev, 0, 80'000, /*salt=*/1);
    EXPECT_TRUE(mp.add_tx(tx));               // fee unknown (no UTXO yet)
    ASSERT_FALSE(mp.get_entry(dash_txid(tx))->fee_known);

    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));

    EXPECT_EQ(mp.recompute_unknown_fees(&utxo), 1)
        << "the now-resolvable input must flip exactly one entry to known";
    EXPECT_TRUE(mp.get_entry(dash_txid(tx))->fee_known);
    EXPECT_EQ(mp.total_known_fees(), 20'000u); // 100000 - 80000
}

TEST(DashMempool, LruEvictionOnSizeCap)
{
    // Empty txs serialize to a handful of bytes each; cap the pool so
    // the third add forces eviction of the oldest entry.
    auto t1 = make_empty(101);
    auto t2 = make_empty(102);
    auto probe = ::pack(t1).size();
    ASSERT_GT(probe, 0u);

    // Room for exactly two of these txs, not three.
    Mempool mp(/*max_bytes=*/probe * 2 + 1);
    uint256 id1 = dash_txid(t1), id2 = dash_txid(t2);

    EXPECT_TRUE(mp.add_tx(t1));
    EXPECT_TRUE(mp.add_tx(t2));
    auto t3 = make_empty(103);
    uint256 id3 = dash_txid(t3);
    EXPECT_TRUE(mp.add_tx(t3));

    EXPECT_EQ(mp.size(), 2u) << "size cap must hold the pool at two entries";
    EXPECT_LE(mp.byte_size(), probe * 2 + 1);
    EXPECT_FALSE(mp.contains(id1)) << "oldest (t1) must be evicted first (LRU)";
    EXPECT_TRUE(mp.contains(id2));
    EXPECT_TRUE(mp.contains(id3));
}

TEST(DashMempool, RemoveForBlockEvictsConfirmedAndConflicts)
{
    Mempool mp;
    uint256 prev = mint_hash(40);

    // Two txs that spend the SAME outpoint — a double-spend pair.
    auto tx_a = make_spend(prev, 0, 90'000, /*salt=*/1);
    auto tx_b = make_spend(prev, 0, 80'000, /*salt=*/2);
    EXPECT_TRUE(mp.add_tx(tx_a));
    EXPECT_TRUE(mp.add_tx(tx_b));
    EXPECT_EQ(mp.size(), 2u);

    // A block confirms tx_a. tx_b spends the same input → conflict.
    BlockType block;
    block.m_version = 1;
    block.m_bits = 0x1d00ffff;
    block.m_timestamp = 1700000000;
    block.m_nonce = 1;
    block.m_txs.push_back(tx_a);

    mp.remove_for_block(block);
    EXPECT_FALSE(mp.contains(dash_txid(tx_a))) << "confirmed tx removed";
    EXPECT_FALSE(mp.contains(dash_txid(tx_b))) << "double-spend conflict removed";
    EXPECT_EQ(mp.size(), 0u);
}

TEST(DashMempool, SortedSelectionHighestFeerateFirst)
{
    UTXOViewCache utxo(nullptr);
    uint256 prev_hi = mint_hash(50);
    uint256 prev_lo = mint_hash(51);
    utxo.add_coin(Outpoint(prev_hi, 0), Coin(100'000, {}, 1, false));
    utxo.add_coin(Outpoint(prev_lo, 0), Coin(100'000, {}, 1, false));

    Mempool mp;
    mp.set_utxo(&utxo);

    // Same input value, same shape ⇒ same base_size; the larger fee is
    // the higher feerate.
    auto tx_hi = make_spend(prev_hi, 0, 90'000, /*salt=*/1); // fee 10000
    auto tx_lo = make_spend(prev_lo, 0, 99'000, /*salt=*/2); // fee  1000
    EXPECT_TRUE(mp.add_tx(tx_lo));   // add low-fee first to prove sorting, not insertion order
    EXPECT_TRUE(mp.add_tx(tx_hi));

    auto [selected, total_fees] = mp.get_sorted_txs_with_fees(/*max_bytes=*/1u << 20);
    ASSERT_EQ(selected.size(), 2u);
    EXPECT_EQ(dash_txid(selected[0].tx), dash_txid(tx_hi))
        << "highest feerate must come first";
    EXPECT_EQ(dash_txid(selected[1].tx), dash_txid(tx_lo));
    EXPECT_EQ(total_fees, 11'000u);
}

// ─── G1 byte-parity: equal-feerate selection is deterministic ────────────────
//
// The embedded GBT template builder serializes txs in the order
// get_sorted_txs_with_fees() returns them. For txs sharing the SAME
// feerate the old std::multimap<double,uint256> kept them in mempool
// INSERTION order, so two nodes with the same mempool contents but a
// different arrival order produced different template bytes — a
// non-deterministic seam that breaks G1 byte-parity against the
// p2pool-dash / dashcore oracle. FeeKey now breaks feerate ties by txid
// ascending (matches dashcore CompareTxMemPoolEntryByAncestorFee's
// GetHash() tiebreak), so the projection is byte-reproducible.
//
// This KAT pins that: identical equal-feerate sets added in OPPOSITE
// orders must yield the SAME selection, ordered by txid ascending.
static std::vector<uint256> equal_feerate_selection(bool reverse_insertion)
{
    UTXOViewCache utxo(nullptr);
    // 5 distinct prevouts, identical value ⇒ identical fee & base_size
    // ⇒ identical feerate for every spend below.
    constexpr int N = 5;
    std::vector<MutableTransaction> txs;
    for (int i = 0; i < N; ++i) {
        uint256 prev = mint_hash(200 + i);
        utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));
        txs.push_back(make_spend(prev, 0, /*out=*/95'000, /*salt=*/300 + i)); // fee 5000
    }

    Mempool mp;
    mp.set_utxo(&utxo);
    if (reverse_insertion)
        for (auto it = txs.rbegin(); it != txs.rend(); ++it) EXPECT_TRUE(mp.add_tx(*it));
    else
        for (auto& t : txs) EXPECT_TRUE(mp.add_tx(t));

    auto [selected, total_fees] = mp.get_sorted_txs_with_fees(/*max_bytes=*/1u << 20);
    EXPECT_EQ(total_fees, static_cast<uint64_t>(N) * 5'000u);
    std::vector<uint256> out;
    for (auto& s : selected) out.push_back(dash_txid(s.tx));
    return out;
}

TEST(DashMempool, EqualFeerateSelectionIsTxidAscendingAndInsertionOrderIndependent)
{
    auto forward = equal_feerate_selection(/*reverse_insertion=*/false);
    auto reverse = equal_feerate_selection(/*reverse_insertion=*/true);

    ASSERT_EQ(forward.size(), 5u);
    ASSERT_EQ(reverse.size(), 5u);

    // Insertion order must not affect the projected order.
    EXPECT_EQ(forward, reverse)
        << "equal-feerate tx order must be independent of mempool arrival order";

    // And that stable order is txid ascending (dashcore GetHash() tiebreak).
    auto sorted = forward;
    std::sort(sorted.begin(), sorted.end());
    EXPECT_EQ(forward, sorted)
        << "equal-feerate ties must resolve to txid-ascending, oracle-conformant order";
}
