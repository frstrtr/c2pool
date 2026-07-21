// SPDX-License-Identifier: AGPL-3.0-or-later
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
#include <set>
#include <vector>

using dash::coin::Mempool;
using dash::coin::MutableTransaction;
using dash::coin::dash_txid;
using dash::coin::BlockType;
using dash::coin::FeeKey;
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


// --- G1 byte-parity: feerate compare is dashcore division-free cross-multiply
//
// dashcore CompareTxMemPoolEntryByAncestorFee compares two entries by
// cross-multiplication -- f1 = a.fee * b.size vs f2 = b.fee * a.size --
// explicitly to "avoid division by rewriting (a/b > c/d) as (a*d > c*b)".
// c2pool previously keyed the sorted index on a PRE-DIVIDED double
// (fee / base_size). That division rounds, so it can collapse a strict
// dashcore order into a tie -- or split a dashcore tie into a strict
// order -- making the two representations disagree on the selection
// order of certain (fee, size) pairs. A different selection order is a
// different template byte-serialization: a latent G1 byte-parity seam
// against the p2pool-dash / dashcore oracle. FeeKey now carries
// (fee, base_size) and reproduces the exact double cross-multiply.
//
// Divergence vector (found by exhaustive search). The disagreement only
// manifests at fee magnitudes >~1e14 sat, where the fee/size division
// loses ULPs the cross-multiply keeps -- for realistic magnitudes the
// two representations agree, so this fix is exact-oracle-conformance
// hardening, not a realistic-value bug:
//   A = (fee 182912374030878, size 3535)
//   B = (fee 4415613369921651, size 85337)
// Pre-divided doubles: A -> 51743245836.174819946 < B -> 51743245836.174827576,
//   i.e. the OLD code ranks B strictly ABOVE A.
// Cross-multiply: A.fee*B.size == B.fee*A.size exactly -> a genuine
//   feerate TIE, resolved by txid ascending (dashcore GetHash()).
TEST(DashMempool, FeerateCompareIsDivisionFreeCrossMultiplyNotPreDividedDouble)
{
    // Independent dashcore-style reference (division-free cross-multiply).
    auto oracle_less = [](uint64_t fa, uint32_t sa, const uint256& ta,
                          uint64_t fb, uint32_t sb, const uint256& tb) {
        const double f1 = static_cast<double>(fa) * sb;
        const double f2 = static_cast<double>(fb) * sa;
        if (f1 != f2) return f1 > f2;   // higher feerate first
        return ta < tb;                 // txid ascending
    };

    // Two distinct txids; assign the SMALLER to A so a correct
    // (cross-multiply => tie => txid-asc) key orders A before B, whereas
    // the old pre-divide code would have put B first ("B higher feerate").
    const uint256 t0 = mint_hash(9001);
    const uint256 t1 = mint_hash(9002);
    const uint256 ta = std::min(t0, t1);
    const uint256 tb = std::max(t0, t1);
    ASSERT_TRUE(ta < tb);

    const uint64_t fa = 182912374030878ULL;
    const uint32_t sa = 3535u;
    const uint64_t fb = 4415613369921651ULL;
    const uint32_t sb = 85337u;

    // Precondition on the vector: a genuine cross-multiply tie that the
    // buggy pre-divide would (wrongly) have seen as a strict order.
    EXPECT_EQ(static_cast<double>(fa) * sb, static_cast<double>(fb) * sa)
        << "vector must be a genuine cross-multiply feerate tie";
    EXPECT_LT(static_cast<double>(fa) / sa, static_cast<double>(fb) / sb)
        << "vector must be a strict (wrong) order under the old pre-divide";

    const FeeKey A{fa, sa, ta};
    const FeeKey B{fb, sb, tb};

    // FeeKey resolves the cross-multiply tie by txid ascending => A first.
    EXPECT_TRUE(A < B) << "cross-multiply tie must fall to txid-ascending (A<B)";
    EXPECT_FALSE(B < A);

    // FeeKey ordering must agree with the independent oracle on this pair.
    EXPECT_EQ(A < B, oracle_less(fa, sa, ta, fb, sb, tb));
    EXPECT_EQ(B < A, oracle_less(fb, sb, tb, fa, sa, ta));

    // The real index type (std::set<FeeKey>) must iterate A best-first.
    std::set<FeeKey> idx{B, A};
    ASSERT_EQ(idx.size(), 2u);
    EXPECT_EQ(idx.begin()->txid, ta)
        << "best-first iteration must yield A (smaller txid) on the tie";

    // Sanity: the feerate arm still dominates. Strictly higher feerate
    // must precede regardless of a smaller-txid competitor.
    const FeeKey hi{20000u, 250u, tb};   // 80 sat/byte
    const FeeKey lo{10000u, 250u, ta};   // 40 sat/byte, but smaller txid
    EXPECT_TRUE(hi < lo) << "higher feerate must precede regardless of txid";
    EXPECT_FALSE(lo < hi);
}
// ═══ E2b (#738) — the live UTXO/fee lane KATs ════════════════════════════════
//
// utxo_lane.hpp is the Phase U capstone: the transliterated LTC wiring
// (main_ltc.cpp UTXOViewDB/UTXOViewCache construction + set_utxo + block-
// connect leg + 288-window cold-start) that finally gives the dash mempool a
// live UTXO view. These KATs feed SYNTHETIC blocks through the exact seam the
// E1/E2a live feed will fire (on_block_connected == Node::block_connected)
// and pin:
//   (a) connect_block resolves fee_known and makes txs selectable
//   (b) coinbasevalue = subsidy + summed REAL fees (hand oracle; never over)
//   (c) a DIP-0027 type-9 asset-unlock is priced from payload.fee
//   (d) an unknown-fee ordinary tx stays EXCLUDED (guard untouched)
//   (e) recompute_unknown_fees after a block-connect flips unknown -> known
// plus the 288-window bootstrap request plan and the 106-deep maturity gate.

#include <impl/dash/coin/utxo_lane.hpp>
#include <impl/dash/coin/vendor/assetlock.hpp>
#include <impl/dash/coin/subsidy.hpp>

using dash::coin::UtxoLane;
using dash::coin::DASH_MIN_BLOCKS_TO_KEEP;
using dash::coin::DASH_MINING_GATE_DEPTH;

// Synthetic coinbase: no inputs, the given output values, salt-distinct txid.
static MutableTransaction make_coinbase(std::vector<int64_t> values,
                                        uint32_t salt) {
    MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = 0x0cb00000u ^ salt;
    for (int64_t v : values) tx.vout.push_back(make_output(v));
    return tx;
}

// Synthetic block: header salted for a distinct block hash, txs[0] = coinbase.
static dash::coin::BlockType make_block(
    std::vector<MutableTransaction> txs, uint32_t salt) {
    dash::coin::BlockType b;
    b.m_nonce = salt;
    b.m_previous_block = mint_hash(0xb10c0000u ^ salt);
    b.m_txs = std::move(txs);
    return b;
}

// Wire-serialize a CAssetUnlockPayload into extra_payload bytes.
static std::vector<unsigned char> pack_unlock_payload(
    const dash::coin::vendor::CAssetUnlockPayload& pl) {
    auto ps = ::pack(pl);
    auto span = ps.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(span.data()),
        reinterpret_cast<const unsigned char*>(span.data()) + span.size());
}

// Type-9 asset-unlock: NO inputs; outputs mint from the credit pool; the
// miner fee lives ONLY in the payload.
static MutableTransaction make_asset_unlock(int64_t out_value, uint32_t fee,
                                            uint32_t salt) {
    dash::coin::vendor::CAssetUnlockPayload pl;
    pl.index = salt;
    pl.fee = fee;
    pl.requestedHeight = 1000 + salt;
    MutableTransaction tx;
    tx.version = 1;
    tx.type = dash::coin::vendor::CAssetUnlockPayload::SPECIALTX_TYPE;  // 9
    tx.locktime = 0;
    tx.vout.push_back(make_output(out_value));
    tx.extra_payload = pack_unlock_payload(pl);
    return tx;
}

// (a) A UTXOViewCache fed a known UTXO set (via a connected block) resolves
//     fee_known=true and the tx becomes selectable.
TEST(DashUtxoLane, ConnectBlockResolvesFeeAndMakesSelectable)
{
    UtxoLane lane;
    ASSERT_TRUE(lane.open(""));   // ephemeral cache-only (synthetic-block mode)
    Mempool mp;
    lane.attach(mp);              // the set_utxo call the dash arm never made

    auto cb = make_coinbase({100'000, 60'000}, /*salt=*/1);
    lane.on_block_connected(make_block({cb}, /*salt=*/1), /*height=*/1);
    EXPECT_EQ(lane.cache()->blocks_connected(), 1u);

    // Spend the coinbase output: 100000 in - 90000 out = 10000 fee, priced
    // IMMEDIATELY at add_tx because the mempool now holds a live UTXO view.
    auto spend = make_spend(dash_txid(cb), 0, 90'000, /*salt=*/11);
    EXPECT_TRUE(mp.add_tx(spend));
    auto entry = mp.get_entry(dash_txid(spend));
    ASSERT_TRUE(entry.has_value());
    EXPECT_TRUE(entry->fee_known)
        << "with the lane attached, add_tx must price from UTXO";
    EXPECT_EQ(entry->fee, 10'000u);

    auto [sel, fees] = mp.get_sorted_txs_with_fees(1'000'000);
    ASSERT_EQ(sel.size(), 1u) << "the priced tx must be selectable";
    EXPECT_EQ(fees, 10'000u);
    EXPECT_EQ(dash_txid(sel[0].tx), dash_txid(spend));
}

// (c) A type-9 asset-unlock tx is priced from payload.fee and selected —
//     no UTXO view needed (the fee is explicit in the payload, exactly what
//     dashd's GBT reports). Malformed payloads and input-carrying type-9
//     bodies stay on the conservative unknown-fee path.
TEST(DashMempool, AssetUnlockType9PricedFromPayloadFee)
{
    Mempool mp;                    // deliberately NO set_utxo
    auto t9 = make_asset_unlock(500'000, /*fee=*/7'000, /*salt=*/1);
    EXPECT_TRUE(mp.add_tx(t9));
    auto entry = mp.get_entry(dash_txid(t9));
    ASSERT_TRUE(entry.has_value());
    EXPECT_TRUE(entry->fee_known)
        << "type-9 fee comes from payload.fee, independent of UTXO";
    EXPECT_EQ(entry->fee, 7'000u);

    auto [sel, fees] = mp.get_sorted_txs_with_fees(1'000'000);
    ASSERT_EQ(sel.size(), 1u) << "the asset-unlock must be selectable";
    EXPECT_EQ(fees, 7'000u);

    // Malformed payload: conservative — stays unknown, stays excluded.
    MutableTransaction bad;
    bad.version = 1;
    bad.type = 9;
    bad.vout.push_back(make_output(1'000));
    bad.extra_payload = {0x01};   // truncated
    EXPECT_TRUE(mp.add_tx(bad));
    EXPECT_FALSE(mp.get_entry(dash_txid(bad))->fee_known);

    // Type-9 WITH inputs is not an asset-unlock shape: generic path
    // (which, with no UTXO view here, stays conservatively unknown).
    auto odd = make_asset_unlock(2'000, 500, /*salt=*/2);
    odd.vin.push_back(make_input(mint_hash(40), 0));
    EXPECT_TRUE(mp.add_tx(odd));
    EXPECT_FALSE(mp.get_entry(dash_txid(odd))->fee_known);

    auto [sel2, fees2] = mp.get_sorted_txs_with_fees(1'000'000);
    EXPECT_EQ(sel2.size(), 1u);
    EXPECT_EQ(fees2, 7'000u) << "only the well-formed unlock is priced";
}

// C-3 special-tx filter: the embedded-template selection (exclude_special=true)
// drops every Dash special tx (tx.type != 0) while keeping standard fee-paying
// txs, so an embedded block is special-tx-free (its CbTx creditPool accrual then
// reduces to the platform-reward term). The DEFAULT path (exclude_special=false)
// still prices+selects the asset-unlock, preserving the general capability.
TEST(DashMempool, EmbeddedSelectionExcludesSpecialTxs)
{
    Mempool mp;
    // A standard fee-paying tx priced from payload (type-9 uses payload.fee),
    // plus a type-9 asset-unlock. The default selector takes both; the
    // embedded selector must drop the type-9 special tx.
    auto std_spend = make_asset_unlock(300'000, /*fee=*/5'000, /*salt=*/61);
    std_spend.type = 0;                       // force a standard tx (fee still from payload path? no)
    // Give the standard tx a real UTXO-priced fee instead.
    UtxoLane lane; ASSERT_TRUE(lane.open("")); lane.attach(mp);
    auto cb = make_coinbase({80'000}, /*salt=*/62);
    lane.on_block_connected(make_block({cb}, /*salt=*/62), /*height=*/1);
    auto ord = make_spend(dash_txid(cb), 0, 70'000, /*salt=*/63);   // fee 10000, type 0
    ASSERT_TRUE(mp.add_tx(ord));
    auto t9 = make_asset_unlock(400'000, /*fee=*/7'000, /*salt=*/64); // type 9
    ASSERT_TRUE(mp.add_tx(t9));

    // Default: both priced txs selectable.
    auto [all, all_fees] = mp.get_sorted_txs_with_fees(1'000'000);
    EXPECT_EQ(all.size(), 2u);
    EXPECT_EQ(all_fees, 17'000u);

    // Embedded (C-3): the type-9 special tx is excluded; only the standard tx.
    auto [emb, emb_fees] = mp.get_sorted_txs_with_fees(1'000'000, /*exclude_special=*/true);
    ASSERT_EQ(emb.size(), 1u) << "embedded template must be special-tx-free";
    EXPECT_EQ(emb[0].tx.type, 0);
    EXPECT_EQ(emb_fees, 10'000u);
}

// (b)+(d) coinbasevalue = subsidy + summed real fees, matching a hand-
//     computed oracle; unknown-fee ordinary txs contribute NOTHING, so the
//     value can never overstate what dashd's GBT would report.
TEST(DashUtxoLane, CoinbasevalueConservativeOracle)
{
    UtxoLane lane;
    ASSERT_TRUE(lane.open(""));
    Mempool mp;
    lane.attach(mp);

    auto cb = make_coinbase({100'000, 60'000}, /*salt=*/2);
    lane.on_block_connected(make_block({cb}, /*salt=*/2), /*height=*/1);

    // Priced ordinary spend: fee 10000.
    auto spend = make_spend(dash_txid(cb), 0, 90'000, /*salt=*/21);
    EXPECT_TRUE(mp.add_tx(spend));
    // Priced type-9 unlock: fee 7000 from payload.
    auto t9 = make_asset_unlock(400'000, 7'000, /*salt=*/22);
    EXPECT_TRUE(mp.add_tx(t9));
    // (d) Unknown-fee ordinary tx (input never in UTXO): must stay excluded.
    auto unknown = make_spend(mint_hash(50), 0, 30'000, /*salt=*/23);
    EXPECT_TRUE(mp.add_tx(unknown));
    ASSERT_FALSE(mp.get_entry(dash_txid(unknown))->fee_known);

    auto [sel, fees] = mp.get_sorted_txs_with_fees(1'000'000);
    ASSERT_EQ(sel.size(), 2u)
        << "exactly the two priced txs — the unknown-fee tx is EXCLUDED";
    EXPECT_EQ(fees, 17'000u) << "hand oracle: 10000 + 7000";
    for (const auto& s : sel)
        EXPECT_NE(dash_txid(s.tx), dash_txid(unknown));

    // coinbasevalue oracle at the live-validated subsidy pin (h=2459985,
    // test_dash_subsidy.cpp): 177022505 sat subsidy + 17000 sat real fees.
    const int64_t subsidy =
        dash::coin::compute_dash_block_reward_post_v20(2459985);
    ASSERT_EQ(subsidy, 177'022'505LL);
    EXPECT_EQ(subsidy + static_cast<int64_t>(fees), 177'039'505LL)
        << "coinbasevalue = subsidy + summed REAL fees, never inflated by "
           "unknown-fee entries";
}

// (e) recompute_unknown_fees after a block-connect flips previously-unknown
//     fees to known — the lane drives it automatically on the connect leg.
TEST(DashUtxoLane, BlockConnectFlipsPreviouslyUnknownFees)
{
    UtxoLane lane;
    ASSERT_TRUE(lane.open(""));
    Mempool mp;
    lane.attach(mp);

    auto cb1 = make_coinbase({100'000}, /*salt=*/3);
    lane.on_block_connected(make_block({cb1}, /*salt=*/3), /*height=*/1);

    // Funding tx F confirms in block 2 (it is never in the mempool);
    // spender S rides the mempool and references F's output.
    auto funding = make_spend(dash_txid(cb1), 0, 95'000, /*salt=*/31);
    auto spender = make_spend(dash_txid(funding), 0, 90'000, /*salt=*/32);
    EXPECT_TRUE(mp.add_tx(spender));
    ASSERT_FALSE(mp.get_entry(dash_txid(spender))->fee_known)
        << "F is neither in UTXO nor in the mempool yet";
    EXPECT_EQ(mp.get_sorted_txs_with_fees(1'000'000).first.size(), 0u)
        << "unknown-fee tx must not be selectable";

    auto cb2 = make_coinbase({50'000}, /*salt=*/4);
    lane.on_block_connected(make_block({cb2, funding}, /*salt=*/4),
                            /*height=*/2);

    auto entry = mp.get_entry(dash_txid(spender));
    ASSERT_TRUE(entry.has_value()) << "S must survive remove_for_block";
    EXPECT_TRUE(entry->fee_known)
        << "the connect leg must run recompute_unknown_fees";
    EXPECT_EQ(entry->fee, 5'000u);  // 95000 - 90000
    auto [sel, fees] = mp.get_sorted_txs_with_fees(1'000'000);
    ASSERT_EQ(sel.size(), 1u);
    EXPECT_EQ(fees, 5'000u);
}

// Confirmed txs leave the mempool on the connect leg (remove_for_block).
TEST(DashUtxoLane, ConnectLegEvictsConfirmedTxs)
{
    UtxoLane lane;
    ASSERT_TRUE(lane.open(""));
    Mempool mp;
    lane.attach(mp);

    auto cb = make_coinbase({100'000}, /*salt=*/5);
    lane.on_block_connected(make_block({cb}, /*salt=*/5), /*height=*/1);

    auto spend = make_spend(dash_txid(cb), 0, 90'000, /*salt=*/51);
    EXPECT_TRUE(mp.add_tx(spend));
    ASSERT_EQ(mp.size(), 1u);

    auto cb2 = make_coinbase({50'000}, /*salt=*/6);
    lane.on_block_connected(make_block({cb2, spend}, /*salt=*/6),
                            /*height=*/2);
    EXPECT_EQ(mp.size(), 0u) << "confirmed tx must be evicted";
}

// Cold start: the first connected block above the 288 window triggers the
// ordered-download bootstrap (block_bootstrapper.hpp) instead of connecting
// the tip out of order, and requests exactly the 16-wide sliding window from
// tip-288 upward through the E1/E2a request seam.
TEST(DashUtxoLane, ColdStartBootstrapWindowPlan)
{
    UtxoLane lane;
    ASSERT_TRUE(lane.open(""));
    Mempool mp;
    lane.attach(mp);

    std::vector<uint32_t> requested;
    lane.set_request_block_fn(
        [&requested](uint32_t h) { requested.push_back(h); });

    const uint32_t tip = 500;
    auto cbt = make_coinbase({100'000}, /*salt=*/7);
    lane.on_block_connected(make_block({cbt}, /*salt=*/7), tip);

    // 500 > 288 => bootstrap: start = 500 - 288 = 212, window 212..227.
    const uint32_t start = tip - DASH_MIN_BLOCKS_TO_KEEP;
    ASSERT_EQ(start, 212u);
    ASSERT_EQ(requested.size(), 16u) << "initial sliding window = 16";
    for (uint32_t i = 0; i < 16; ++i)
        EXPECT_EQ(requested[i], start + i);
    EXPECT_EQ(lane.cache()->blocks_connected(), 0u)
        << "the tip must NOT connect out of order";

    // Drain in strict height order: 212 connects, the window refills.
    auto cb212 = make_coinbase({70'000}, /*salt=*/8);
    lane.on_block_connected(make_block({cb212}, /*salt=*/8), start);
    EXPECT_EQ(lane.cache()->blocks_connected(), 1u);
    ASSERT_GT(requested.size(), 16u) << "window must refill after a drain";
    EXPECT_EQ(requested.back(), start + 16);

    // Out-of-order arrival buffers without connecting.
    auto cb214 = make_coinbase({70'000}, /*salt=*/9);
    lane.on_block_connected(make_block({cb214}, /*salt=*/9), start + 2);
    EXPECT_EQ(lane.cache()->blocks_connected(), 1u)
        << "height-order drain must stall on the missing block";
}

// The 106-deep coinbase-maturity mining gate (100 + 6, utxo_adapter.hpp).
TEST(DashUtxoLane, MiningMaturityGateAt106)
{
    ASSERT_EQ(DASH_MINING_GATE_DEPTH, 106u);
    UtxoLane lane;
    ASSERT_TRUE(lane.open(""));
    EXPECT_FALSE(lane.mining_utxo_ready());

    for (uint32_t h = 1; h <= DASH_MINING_GATE_DEPTH; ++h) {
        auto cb = make_coinbase({10'000}, /*salt=*/1000 + h);
        lane.on_block_connected(make_block({cb}, /*salt=*/1000 + h), h);
        if (h < DASH_MINING_GATE_DEPTH)
            EXPECT_FALSE(lane.mining_utxo_ready())
                << "gate must hold below " << DASH_MINING_GATE_DEPTH
                << " (h=" << h << ")";
    }
    EXPECT_TRUE(lane.mining_utxo_ready())
        << "gate must open at exactly " << DASH_MINING_GATE_DEPTH;
}
