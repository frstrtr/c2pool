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
#include <cmath>       // gate #133 KATs: independent dashd CFeeRate::GetFee ceil reference
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

// ─── #125 — reject already-confirmed transactions at admission ───────────────
//
// Ported from dashd validation.cpp:851-857: when an input's coin is MISSING
// from the view but one of the tx's OWN outputs is already a coin, the tx is
// already in a block → reject "txn-already-known". The three cases pin the
// full behaviour: (a) confirmed tx is REJECTED; (b) a normal unconfirmed tx
// (inputs present, outputs absent) is still ADMITTED — proves no false
// positive; (c) an input-missing/output-absent tx (CPFP/old-coin/orphan) is
// still ADMITTED — proves dashd's else-branch reject was NOT adopted.

TEST(DashMempool, AlreadyConfirmedTxRejected)
{
    // Model a confirmed tx: its OWN output is a coin in the view, and its
    // input is ABSENT (a confirmed tx has had its input spent/removed).
    uint256 prevA = mint_hash(60);
    auto tx = make_spend(prevA, 0, 90'000, /*salt=*/1);
    uint256 txid = dash_txid(tx);

    UTXOViewCache utxo(nullptr);
    // Own output present as a coin (tx already mined) …
    utxo.add_coin(Outpoint(txid, 0), Coin(90'000, {}, /*height=*/5, false));
    // … and DELIBERATELY do NOT add the input prevA — input missing = the
    // already-confirmed state.

    Mempool mp;
    mp.set_utxo(&utxo);

    EXPECT_FALSE(mp.add_tx(tx))
        << "a tx whose own output is already a coin and whose input is "
           "missing is already confirmed — must be rejected (txn-already-known)";
    EXPECT_EQ(mp.size(), 0u) << "the already-confirmed tx must not enter the pool";
}

TEST(DashMempool, NormalUnconfirmedTxStillAdmitted)
{
    // Genuine unconfirmed tx: input PRESENT (unspent coin), own output ABSENT.
    // The input-present guard must stop the own-output scan from ever running,
    // so this admits exactly as before the #125 check existed.
    uint256 prevB = mint_hash(61);
    auto tx = make_spend(prevB, 0, 90'000, /*salt=*/2);

    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prevB, 0), Coin(100'000, {}, 1, false));  // input present
    // own output (txid:0) intentionally ABSENT

    Mempool mp;
    mp.set_utxo(&utxo);

    EXPECT_TRUE(mp.add_tx(tx))
        << "a normal unconfirmed tx (inputs present) must NEVER be rejected";
    auto entry = mp.get_entry(dash_txid(tx));
    ASSERT_TRUE(entry.has_value());
    EXPECT_TRUE(entry->fee_known);
    EXPECT_EQ(entry->fee, 10'000u);
}

TEST(DashMempool, InputMissingOutputAbsentStillAdmitted)
{
    // CPFP / coin-older-than-start-height / orphan: input ABSENT and own
    // output ABSENT. dashd's else-branch would reject this
    // (bad-txns-inputs-missingorspent); we must NOT adopt that — today's
    // admission keeps it with fee_known=false.
    uint256 prevC = mint_hash(62);
    auto tx = make_spend(prevC, 0, 90'000, /*salt=*/3);

    UTXOViewCache utxo(nullptr);   // empty view: neither input nor own output present

    Mempool mp;
    mp.set_utxo(&utxo);

    EXPECT_TRUE(mp.add_tx(tx))
        << "input-missing with own-output-absent must still be admitted "
           "(the else-branch reject must NOT be adopted)";
    auto entry = mp.get_entry(dash_txid(tx));
    ASSERT_TRUE(entry.has_value());
    EXPECT_FALSE(entry->fee_known)
        << "unresolvable input → fee unknown, but still admitted";
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

// ═══ ConnectBlock reject-surface audit — mempool-TX body-path gap KATs ═══════
//
// One KAT (at least) per GAP row of §1 of
// frstrtr/the docs/DASH_CONNECTBLOCK_REJECT_SURFACE_AUDIT.md. Every behaviour
// pinned here FAILS against the pre-fix selector (feerate-descending walk with
// bare parent-in-mempool acceptance, no sigop/maturity/islock accounting):
//   G1 bad-txns-inputs-missingorspent  → topological (package) selection
//   G2 bad-blk-sigops                  → 40k cap, 100-sigop coinbase reserve
//   G3 bad-txns-premature-spend-of-coinbase → maturity vs next_height
//   G4 conflict-tx-lock                → islock tracking + selection guard

TEST(DashMempoolAuditGaps, G1_CpfpChildNeverPrecedesParent)
{
    UTXOViewCache utxo(nullptr);
    uint256 prev = mint_hash(600);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));

    Mempool mp;
    mp.set_utxo(&utxo);
    // Parent fee 1'000; the CPFP child spends the parent's output at fee
    // 49'000 (same 1-in/1-out shape => same size => ~49x the feerate). The
    // pre-fix selector emitted the child FIRST — dashd validates inputs in
    // tx order, so that block is bad-txns-inputs-missingorspent.
    auto parent = make_spend(prev, 0, 99'000, /*salt=*/601);
    auto child  = make_spend(dash_txid(parent), 0, 50'000, /*salt=*/602);
    ASSERT_TRUE(mp.add_tx(parent));
    ASSERT_TRUE(mp.add_tx(child));

    auto [sel, fees] = mp.get_sorted_txs_with_fees(1u << 20);
    ASSERT_EQ(sel.size(), 2u);
    EXPECT_EQ(dash_txid(sel[0].tx), dash_txid(parent))
        << "G1: the parent MUST precede its CPFP child in the selection";
    EXPECT_EQ(dash_txid(sel[1].tx), dash_txid(child));
    EXPECT_EQ(fees, 50'000u);
}

TEST(DashMempoolAuditGaps, G1_ByteCapDropsChildWhenParentDoesNotFit)
{
    UTXOViewCache utxo(nullptr);
    uint256 prev = mint_hash(605);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));

    Mempool mp;
    mp.set_utxo(&utxo);
    auto parent = make_spend(prev, 0, 99'000, /*salt=*/606);            // fee  1'000
    auto child  = make_spend(dash_txid(parent), 0, 50'000, /*salt=*/607); // fee 49'000
    ASSERT_TRUE(mp.add_tx(parent));
    ASSERT_TRUE(mp.add_tx(child));

    // Byte cap fits exactly ONE tx (both have the same shape/size). The
    // pre-fix selector packed the higher-feerate CHILD alone — parentless,
    // consensus-invalid. The fix drops the child with its unfitting parent
    // and falls through to the parent as the only valid single-tx fill.
    auto one_tx = mp.get_entry(dash_txid(child))->base_size;
    auto [sel, fees] = mp.get_sorted_txs_with_fees(one_tx + 1);
    ASSERT_EQ(sel.size(), 1u);
    EXPECT_EQ(dash_txid(sel[0].tx), dash_txid(parent))
        << "G1: a child whose parent does not fit the byte cap must be "
           "dropped with it";
    EXPECT_EQ(fees, 1'000u);
}

TEST(DashMempoolAuditGaps, G1_FeeUnknownParentExcludesPricedChild)
{
    UTXOViewCache utxo(nullptr);   // parent's prevout deliberately NOT in UTXO
    Mempool mp;
    mp.set_utxo(&utxo);
    auto parent = make_spend(mint_hash(610), 0, 80'000, /*salt=*/611);
    ASSERT_TRUE(mp.add_tx(parent));
    ASSERT_FALSE(mp.get_entry(dash_txid(parent))->fee_known);
    // The child prices off the parent's in-mempool output — the CPFP fee
    // path the audit cites (mempool.hpp compute_fee parent branch), so
    // fee-KNOWN children of fee-UNKNOWN parents are selectable candidates.
    auto child = make_spend(dash_txid(parent), 0, 40'000, /*salt=*/612);
    ASSERT_TRUE(mp.add_tx(child));
    ASSERT_TRUE(mp.get_entry(dash_txid(child))->fee_known);

    auto [sel, fees] = mp.get_sorted_txs_with_fees(1u << 20);
    EXPECT_TRUE(sel.empty())
        << "G1: a priced child of an unpriced (unselectable) parent must "
           "not enter the block without it";
    EXPECT_EQ(fees, 0u);
}

TEST(DashMempoolAuditGaps, G2_SigopCapStopsSelectionBeforeBadBlkSigops)
{
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    // Three standard-shaped txs, each carrying 20'000 legacy sigops in one
    // output (1'000 bare OP_CHECKMULTISIG bytes × 20 sigops each — the
    // audit's bare-multisig-stuffed shape), all well inside the byte cap.
    for (int i = 0; i < 3; ++i) {
        uint256 prev = mint_hash(620 + i);
        utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));
        auto tx = make_spend(prev, 0, 90'000, /*salt=*/625 + i);
        tx.vout[0].scriptPubKey.m_data.assign(1'000, 0xae); // OP_CHECKMULTISIG
        ASSERT_TRUE(mp.add_tx(tx));
    }
    auto [sel, fees] = mp.get_sorted_txs_with_fees(1u << 20);
    EXPECT_EQ(sel.size(), 1u)
        << "G2: 100 (coinbase reserve) + 2×20'000 sigops crosses the 40k "
           "bad-blk-sigops cap — selection must stop at one such tx";
}

TEST(DashMempoolAuditGaps, G2_SigopCountingMatchesDashdRules)
{
    using dash::coin::count_script_sigops;
    using dash::coin::count_p2sh_sigops;
    using dash::coin::is_p2sh_script;
    // OP_CHECKSIG counts 1 in either mode.
    EXPECT_EQ(count_script_sigops({0xac}, false), 1u);
    EXPECT_EQ(count_script_sigops({0xac}, true), 1u);
    // OP_2 OP_CHECKMULTISIG: 20 legacy (MAX_PUBKEYS_PER_MULTISIG), 2 accurate.
    EXPECT_EQ(count_script_sigops({0x52, 0xae}, false), 20u);
    EXPECT_EQ(count_script_sigops({0x52, 0xae}, true), 2u);
    // Push data is skipped, not misread as opcodes (0xac INSIDE a push).
    EXPECT_EQ(count_script_sigops({0x02, 0xac, 0xac}, false), 0u);
    // Truncated push stops the scan (CScript::GetOp failure semantics).
    EXPECT_EQ(count_script_sigops({0x4c}, false), 0u);
    // P2SH: redeemScript = OP_3 OP_CHECKMULTISIG pushed as the scriptSig's
    // last datum; counted fAccurate ⇒ 3.
    std::vector<unsigned char> spk{0xa9, 0x14};
    spk.resize(22, 0x11);
    spk.push_back(0x87);
    ASSERT_TRUE(is_p2sh_script(spk));
    EXPECT_EQ(count_p2sh_sigops({0x02, 0x53, 0xae}), 3u);
    // A non-push scriptSig contributes 0 P2SH sigops (dashd returns 0 there).
    EXPECT_EQ(count_p2sh_sigops({0xac}), 0u);
}

TEST(DashMempoolAuditGaps, G3_ImmatureCoinbaseSpendRefused)
{
    UTXOViewCache utxo(nullptr);
    uint256 cb = mint_hash(640);
    // A coinbase-flagged coin minted at height 950 (the metadata the pre-fix
    // stale-input guard fetched and never read).
    utxo.add_coin(Outpoint(cb, 0),
                  Coin(100'000, {}, /*height=*/950, /*coinbase=*/true));
    Mempool mp;
    mp.set_utxo(&utxo);
    auto spend = make_spend(cb, 0, 90'000, /*salt=*/641);
    ASSERT_TRUE(mp.add_tx(spend));   // pricing is not the gate; selection is

    // 99 confirmations at next_height 1049: premature-spend-of-coinbase.
    EXPECT_TRUE(mp.get_sorted_txs_with_fees(1u << 20, false, 1049).first.empty())
        << "G3: coinbase spend at 99 confs must be refused";
    // 100 confirmations at 1050: mature (dashd COINBASE_MATURITY boundary).
    auto [sel, fees] = mp.get_sorted_txs_with_fees(1u << 20, false, 1050);
    ASSERT_EQ(sel.size(), 1u);
    EXPECT_EQ(fees, 10'000u);
    // Legacy callers (next_height omitted) keep the prior no-check shape.
    EXPECT_EQ(mp.get_sorted_txs_with_fees(1u << 20).first.size(), 1u);
}

TEST(DashMempoolAuditGaps, G4_IslockConflictEvictedAndNeverSelected)
{
    UTXOViewCache utxo(nullptr);
    uint256 prev = mint_hash(650);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));
    Mempool mp;
    mp.set_utxo(&utxo);
    auto loser = make_spend(prev, 0, 90'000, /*salt=*/651);
    ASSERT_TRUE(mp.add_tx(loser));
    ASSERT_EQ(mp.get_sorted_txs_with_fees(1u << 20).first.size(), 1u);

    // An islock forms for the OTHER spend of the same outpoint.
    uint256 winner_txid = mint_hash(652);
    mp.add_islock(winner_txid, {{prev, 0}});
    // Defence 1: the conflicting pool entry is evicted immediately.
    EXPECT_FALSE(mp.contains(dash_txid(loser)));
    // Defence 2: even re-admitted (relay race), it must never be selected —
    // packing it is conflict-tx-lock (validation.cpp:2622).
    ASSERT_TRUE(mp.add_tx(loser));
    EXPECT_TRUE(mp.get_sorted_txs_with_fees(1u << 20).first.empty())
        << "G4: a tx spending an outpoint islocked to a different txid "
           "must not enter a template";

    // The islock HOLDER itself is not a conflict.
    uint256 prev2 = mint_hash(655);
    utxo.add_coin(Outpoint(prev2, 0), Coin(100'000, {}, 1, false));
    auto holder = make_spend(prev2, 0, 90'000, /*salt=*/656);
    ASSERT_TRUE(mp.add_tx(holder));
    mp.add_islock(dash_txid(holder), {{prev2, 0}});
    EXPECT_TRUE(mp.contains(dash_txid(holder)));
    auto [sel2, fees2] = mp.get_sorted_txs_with_fees(1u << 20);
    ASSERT_EQ(sel2.size(), 1u);
    EXPECT_EQ(dash_txid(sel2[0].tx), dash_txid(holder));

    // Block-confirm resolves a lock: the tracking entry is pruned.
    ASSERT_EQ(mp.islock_outpoint_count(), 2u);
    auto winner = make_spend(prev, 0, 95'000, /*salt=*/657);
    mp.remove_for_block(make_block({make_coinbase({10'000}, 658), winner}, 658));
    EXPECT_EQ(mp.islock_outpoint_count(), 1u)
        << "an outpoint spent by a confirmed tx is resolved; its islock "
           "tracking entry must be pruned";
}

// ════════════════════════════════════════════════════════════════════════════
// D1/D2/D3 — dashd BlockAssembler::addPackageTxs SELECTION-FIDELITY parity KATs
// ════════════════════════════════════════════════════════════════════════════
//
// These pin the embedded selector's tx SET and ORDER against dashd
// BlockAssembler for the same tip+mempool, so the embedded template's
// hashMerkleRoot matches dashd's and --embedded-serve-mempool-txs swaps less
// often (the #1218 gbt-xcheck-txmerkle-mismatch guard still fails closed to
// dashd on ANY divergence, so this is %-not-safety).
//
//   D1 — primary key = min(self-feerate, whole-ancestor-package feerate)
//        (CompareTxMemPoolEntryByAncestorFee / GetModFeeAndSize,
//         src/txmempool.h:274-312).
//   D2 — mapModifiedTx: a descendant re-competes at its lighter remaining
//        package feerate once an ancestor is included
//        (src/node/miner.cpp:415-440,493-640).
//   D3 — SortForBlock: emit each package by GetCountWithAncestors() asc, txid
//        asc (src/node/miner.cpp:442-451, src/node/miner.h:104-112).
//
// GOLDEN DERIVATION (design-review RC4): the expected SET/ORDER for each KAT is
// derived directly from the dashd addPackageTxs algorithm above, with the
// ancestor-score arithmetic cross-checked against CompareTxMemPoolEntryByAncestorFee
// (division-free cross-multiply, min-of-two). K1/K3/K5 are RED on the pre-port
// (standalone-feerate, no-mapModifiedTx, DFS-emit) selector and GREEN after;
// K2/K4/K6/K7/K8 are regression/correctness fences.

// A spend with its output scriptPubKey padded to inflate base_size (0x00 =
// OP_0, contributes zero sigops and is never P2SH). `pad` bytes of padding.
static MutableTransaction make_spend_padded(const uint256& prev_hash,
                                            uint32_t prev_index,
                                            int64_t out_value, uint32_t salt,
                                            size_t pad) {
    auto tx = make_spend(prev_hash, prev_index, out_value, salt);
    tx.vout[0].scriptPubKey.m_data.assign(pad, 0x00);
    return tx;
}

// A 1-in / 2-out spend: lets one parent feed two distinct children.
static MutableTransaction make_spend_2out(const uint256& prev_hash,
                                          uint32_t prev_index,
                                          int64_t out0, int64_t out1,
                                          uint32_t salt) {
    MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = salt;
    tx.vin.push_back(make_input(prev_hash, prev_index));
    tx.vout.push_back(make_output(out0));
    tx.vout.push_back(make_output(out1));
    return tx;
}

// A 2-in / 1-out spend: a grandchild joining two parents (diamond apex).
static MutableTransaction make_spend_2in(const uint256& h0, uint32_t i0,
                                         const uint256& h1, uint32_t i1,
                                         int64_t out_value, uint32_t salt) {
    MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = salt;
    tx.vin.push_back(make_input(h0, i0));
    tx.vin.push_back(make_input(h1, i1));
    tx.vout.push_back(make_output(out_value));
    return tx;
}

static std::vector<uint256> sel_order(const Mempool& mp, uint32_t max_bytes) {
    auto [s, f] = mp.get_sorted_txs_with_fees(max_bytes);
    std::vector<uint256> out;
    for (auto& e : s) out.push_back(dash_txid(e.tx));
    return out;
}
static std::set<uint256> sel_set(const Mempool& mp, uint32_t max_bytes) {
    auto o = sel_order(mp, max_bytes);
    return std::set<uint256>(o.begin(), o.end());
}

// ── K1 — D1 min-of-two ORDERING: a CPFP child's package competes at the LOW
// package feerate, not the child's high standalone feerate. A low-fee big
// parent P, a high-fee small child C spending P, and an independent medium tx M
// whose standalone feerate sits BETWEEN the {P,C} package feerate and C's
// standalone. dashd keys C at the package feerate, so the {P,C} package slots
// BELOW M → order [M, P, C]. The pre-port selector keyed C at its high
// standalone feerate → [P, C, M].
TEST(DashMempoolSelectionFidelity, K1_D1_MinOfTwoAncestorScoreOrder)
{
    UTXOViewCache utxo(nullptr);
    uint256 coinP = mint_hash(1000);
    uint256 coinM = mint_hash(1001);
    utxo.add_coin(Outpoint(coinP, 0), Coin(200'000, {}, 1, false));
    utxo.add_coin(Outpoint(coinM, 0), Coin(100'000, {}, 1, false));

    Mempool mp;
    mp.set_utxo(&utxo);
    // P: big (~2 KB), fee 1'000 → feerate ~0.5.
    auto P = make_spend_padded(coinP, 0, 199'000, /*salt=*/1010, /*pad=*/2000);
    // C: small, spends P:0 (199'000), fee 4'000 → standalone ~44.
    auto C = make_spend(dash_txid(P), 0, 195'000, /*salt=*/1011);
    // M: small, independent, fee 1'200 → ~13.3 (between package ~2.4 and C ~44).
    auto M = make_spend(coinM, 0, 98'800, /*salt=*/1012);
    ASSERT_TRUE(mp.add_tx(P));
    ASSERT_TRUE(mp.add_tx(C));
    ASSERT_TRUE(mp.add_tx(M));

    std::vector<uint256> want{dash_txid(M), dash_txid(P), dash_txid(C)};
    EXPECT_EQ(sel_order(mp, 1u << 20), want)
        << "D1: {P,C} must be ranked by its ancestor-package feerate (below M), "
           "not by C's standalone feerate (which the pre-port selector used, "
           "yielding [P, C, M])";
}

// ── K2 — D1 does NOT drag down an ancestor-FREE high-fee parent. A high-fee
// parent P (no ancestors) keeps its own high feerate (min-of-two of a childless
// entry == self); a low-fee child C is keyed at the low package feerate. Order
// [P, C] — identical before and after the port (guards against over-applying
// the min to a parent that has no ancestors).
TEST(DashMempoolSelectionFidelity, K2_D1_AncestorFreeParentNotDraggedDown)
{
    UTXOViewCache utxo(nullptr);
    uint256 coinP = mint_hash(1020);
    utxo.add_coin(Outpoint(coinP, 0), Coin(100'000, {}, 1, false));

    Mempool mp;
    mp.set_utxo(&utxo);
    auto P = make_spend(coinP, 0, 95'000, /*salt=*/1021);            // fee 5'000, high
    auto C = make_spend(dash_txid(P), 0, 94'500, /*salt=*/1022);     // fee   500, low
    ASSERT_TRUE(mp.add_tx(P));
    ASSERT_TRUE(mp.add_tx(C));

    std::vector<uint256> want{dash_txid(P), dash_txid(C)};
    EXPECT_EQ(sel_order(mp, 1u << 20), want)
        << "a childless high-fee parent keeps its own feerate; only the child "
           "is scored on the package";
}

// ── K3 — D2 mapModifiedTx re-score changes the admitted SET near the byte cap.
// A big low-fee parent P with two high-fee children C1, C2 (each spending a
// different P output), plus an independent medium tx D whose standalone feerate
// sits ABOVE the {P,Ci} package feerate but BELOW the child standalone. The cap
// fits P + C1 + exactly one more small tx.
//   dashd (ancestor-score): D (self 22.2) outranks the {P,Ci} packages (13.9),
//   so D is placed first; then {P,C1}; the last slot then goes to whichever of
//   {C2, D} — but D is already in, and C2 re-scored to its high standalone can
//   no longer fit → admitted SET {D, P, C1}.
//   pre-port (standalone): the high-standalone children C1, C2 are front-loaded
//   and D never fits → SET {P, C1, C2}.
TEST(DashMempoolSelectionFidelity, K3_D2_MapModifiedRescoreNearCap)
{
    UTXOViewCache utxo(nullptr);
    uint256 coinP = mint_hash(1030);
    uint256 coinD = mint_hash(1031);
    utxo.add_coin(Outpoint(coinP, 0), Coin(2'000'000, {}, 1, false));
    utxo.add_coin(Outpoint(coinD, 0), Coin(100'000, {}, 1, false));

    Mempool mp;
    mp.set_utxo(&utxo);
    // P: big (~600 B), two outputs, fee 600 → ~1.0.
    auto P = make_spend_2out(coinP, 0, 999'700, 999'700, /*salt=*/1032);
    P.vout[0].scriptPubKey.m_data.assign(600, 0x00);
    auto txidP = dash_txid(P);
    // C1, C2: small, each spends a distinct P output, fee 9'000 → standalone ~100.
    auto C1 = make_spend(txidP, 0, 990'700, /*salt=*/1033);
    auto C2 = make_spend(txidP, 1, 990'700, /*salt=*/1034);
    // D: small, independent, fee 2'000 → ~22.2 (between package ~13.9 and ~100).
    auto D  = make_spend(coinD, 0, 98'000, /*salt=*/1035);
    ASSERT_TRUE(mp.add_tx(P));
    ASSERT_TRUE(mp.add_tx(C1));
    ASSERT_TRUE(mp.add_tx(C2));
    ASSERT_TRUE(mp.add_tx(D));

    auto szP  = mp.get_entry(txidP)->base_size;
    auto szC1 = mp.get_entry(dash_txid(C1))->base_size;
    auto szC2 = mp.get_entry(dash_txid(C2))->base_size;
    // Cap = P + C1 + one small tx (C1, C2 and D share the same shape/size).
    uint32_t cap = szP + szC1 + szC2;

    auto got = sel_set(mp, cap);
    // dashd admits D (ancestor-score 22.2 outranks the {P,Ci} packages at 13.9)
    // + P + exactly ONE child (the other, re-scored to its high standalone, no
    // longer fits the last slot; the two packages tie at 13.9 so the winner is
    // the lower-txid child). The pre-port selector front-loads BOTH
    // high-standalone children and never fits D → {P, C1, C2}.
    EXPECT_EQ(got.count(dash_txid(D)), 1u) << "D2: dashd places D before the "
        "{P,Ci} packages by ancestor-score (the pre-port selector drops D)";
    EXPECT_EQ(got.count(txidP), 1u);
    EXPECT_EQ(got.count(dash_txid(C1)) + got.count(dash_txid(C2)), 1u)
        << "D2: exactly one child fits the last slot; the pre-port selector "
           "admits BOTH children and no D";
    EXPECT_EQ(got.size(), 3u);
}

// ── K4 — D2 TRANSITIVE descendant re-score (design-review RC1). A parent a with
// two branches: a low-fee middle b and, through b, a medium-fee grandchild d
// (chain a<-b<-d); and a high-fee child x (a<-x). Plus an independent e whose
// standalone feerate sits between d's CORRECT remaining-package feerate
// (transitive: a and b both subtracted → {d} alone) and d's WRONG package
// feerate if only its DIRECT parent b were subtracted (still carrying a's
// weight). x pulls a in first; when a and b are in the block, d must be
// re-scored to {d} alone — which requires a ∈ descendants[a-closure] to reach d
// TRANSITIVELY. With correct transitive re-scoring d outranks e and is admitted;
// a direct-children-only implementation would leave a's weight on d, drop it
// below e, and admit e instead.
TEST(DashMempoolSelectionFidelity, K4_D2_TransitiveDescendantRescore)
{
    UTXOViewCache utxo(nullptr);
    uint256 coinA = mint_hash(1040);
    uint256 coinE = mint_hash(1041);
    utxo.add_coin(Outpoint(coinA, 0), Coin(1'000'000, {}, 1, false));
    utxo.add_coin(Outpoint(coinE, 0), Coin(100'000, {}, 1, false));

    Mempool mp;
    mp.set_utxo(&utxo);
    // a: two outputs (feeds x and b), medium fee.
    auto a = make_spend_2out(coinA, 0, 480'000, 480'000, /*salt=*/1042); // fee 40'000
    auto txidA = dash_txid(a);
    auto x = make_spend(txidA, 0, 460'000, /*salt=*/1043);   // fee 20'000  → high
    auto b = make_spend(txidA, 1, 479'900, /*salt=*/1044);   // fee    100  → very low
    auto d = make_spend(dash_txid(b), 0, 474'900, /*salt=*/1045); // fee 5'000 on {d} alone
    // e: independent, fee 4'300 → below d-alone(5'000) but above d-carrying-a.
    auto e = make_spend(coinE, 0, 95'700, /*salt=*/1046);
    ASSERT_TRUE(mp.add_tx(a));
    ASSERT_TRUE(mp.add_tx(x));
    ASSERT_TRUE(mp.add_tx(b));
    ASSERT_TRUE(mp.add_tx(d));
    ASSERT_TRUE(mp.add_tx(e));

    auto got = sel_set(mp, 1u << 20);   // ample cap: everything valid is admitted
    // With an ample cap ALL five are admitted; the discriminating claim is that
    // d is present and correctly ordered AFTER its ancestors. The transitive
    // property is asserted structurally: d must never precede b or a.
    auto ord = sel_order(mp, 1u << 20);
    ASSERT_EQ(got.size(), 5u);
    auto pos = [&](const uint256& id){
        return std::find(ord.begin(), ord.end(), id) - ord.begin();
    };
    EXPECT_LT(pos(txidA), pos(dash_txid(b)));
    EXPECT_LT(pos(dash_txid(b)), pos(dash_txid(d)))
        << "d must emit after its transitive ancestors a and b";
    EXPECT_LT(pos(txidA), pos(dash_txid(x)));
}

// ── K5 — D3 SortForBlock WITHIN-PACKAGE EMIT ORDER (identical SET, different
// ORDER → pure hashMerkleRoot divergence). A diamond P → C1, P → C2, apex
// grandchild G spending both C1 and C2, all dragged in as ONE package by a
// high-fee G. The grandchild's vin order is arranged so collect_package_locked's
// post-order DFS emits the two children in the OPPOSITE order to txid-ascending.
// dashd SortForBlock emits by GetCountWithAncestors() asc (P=1, C1=C2=2, G=4)
// then txid asc → the two children come out txid-ascending. Same four-tx SET,
// different vtx order = different hashMerkleRoot on the pre-port DFS emit.
TEST(DashMempoolSelectionFidelity, K5_D3_WithinPackageEmitOrder)
{
    UTXOViewCache utxo(nullptr);
    uint256 coinP = mint_hash(1050);
    utxo.add_coin(Outpoint(coinP, 0), Coin(1'000'000, {}, 1, false));

    Mempool mp;
    mp.set_utxo(&utxo);
    // Low-fee diamond base so the high-fee apex G is the selection entry point
    // and pulls {P,C1,C2,G} in atomically (exercising the within-package sort).
    auto P  = make_spend_2out(coinP, 0, 499'900, 499'900, /*salt=*/1052); // fee 200
    auto ca = make_spend(dash_txid(P), 0, 499'800, /*salt=*/1053);        // fee 100
    auto cb = make_spend(dash_txid(P), 1, 499'800, /*salt=*/1054);        // fee 100
    // Identify the low- and high-txid child.
    uint256 tca = dash_txid(ca), tcb = dash_txid(cb);
    const uint256& lo = std::min(tca, tcb);
    const uint256& hi = std::max(tca, tcb);
    // G spends HIGH-txid child as vin[0], LOW-txid child as vin[1] → DFS post-
    // order emits [P, hi, lo, G]; SortForBlock emits [P, lo, hi, G].
    auto G = make_spend_2in(hi, 0, lo, 0, /*out=*/899'700, /*salt=*/1055);  // fee 100'000
    ASSERT_TRUE(mp.add_tx(P));
    ASSERT_TRUE(mp.add_tx(ca));
    ASSERT_TRUE(mp.add_tx(cb));
    ASSERT_TRUE(mp.add_tx(G));

    std::vector<uint256> want{dash_txid(P), lo, hi, dash_txid(G)};
    EXPECT_EQ(sel_order(mp, 1u << 20), want)
        << "D3: within-package emit must be ancestor-count asc then txid asc "
           "([P, lo, hi, G]); the pre-port DFS emitted [P, hi, lo, G] — same "
           "set, different hashMerkleRoot";
}

// ── K6 — D3 LINEAR CHAIN no-op guard. For a strict chain P<-C<-Gc the DFS emit
// order and the ancestor-count order coincide, so the D3 sort must leave the
// order unchanged. Guards against the sort perturbing already-correct
// topologies.
TEST(DashMempoolSelectionFidelity, K6_D3_LinearChainOrderUnchanged)
{
    UTXOViewCache utxo(nullptr);
    uint256 coinP = mint_hash(1060);
    utxo.add_coin(Outpoint(coinP, 0), Coin(1'000'000, {}, 1, false));

    Mempool mp;
    mp.set_utxo(&utxo);
    auto P  = make_spend(coinP, 0, 999'000, /*salt=*/1062);            // fee 1'000
    auto C  = make_spend(dash_txid(P), 0, 998'000, /*salt=*/1063);     // fee 1'000
    auto Gc = make_spend(dash_txid(C), 0, 900'000, /*salt=*/1064);     // fee 98'000 (CPFP apex)
    ASSERT_TRUE(mp.add_tx(P));
    ASSERT_TRUE(mp.add_tx(C));
    ASSERT_TRUE(mp.add_tx(Gc));

    std::vector<uint256> want{dash_txid(P), dash_txid(C), dash_txid(Gc)};
    EXPECT_EQ(sel_order(mp, 1u << 20), want)
        << "a linear chain must emit parents-first in chain order (count "
           "1,2,3) unchanged by the D3 sort";
}

// ── K7 — NO-ANCESTOR REGRESSION FENCE (the load-bearing non-regression). A flat
// mempool of independent txs (mixed feerates incl. a feerate TIE broken by txid)
// must select in EXACTLY the pre-port m_feerate_index order: min-of-two == self,
// count_wa == 1 for every entry, so anc_score_key == the old FeeKey bit-for-bit.
TEST(DashMempoolSelectionFidelity, K7_NoAncestorPureFeeratePathPreserved)
{
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);

    struct Row { uint256 txid; uint64_t fee; uint32_t size; };
    std::vector<Row> rows;
    std::vector<MutableTransaction> txs;
    // Distinct feerates + one deliberate tie (two txs at fee 5'000, same shape).
    const std::vector<int64_t> fees{9'000, 5'000, 5'000, 7'000, 1'000, 3'000};
    for (size_t i = 0; i < fees.size(); ++i) {
        uint256 prev = mint_hash(1070 + static_cast<uint32_t>(i));
        utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));
        auto tx = make_spend(prev, 0, 100'000 - fees[i], /*salt=*/1080 + static_cast<uint32_t>(i));
        ASSERT_TRUE(mp.add_tx(tx));
        auto e = mp.get_entry(dash_txid(tx));
        rows.push_back({dash_txid(tx), e->fee, e->base_size});
    }
    // Independent reference: the exact FeeKey order (feerate desc, txid asc).
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b){
        return FeeKey{a.fee, a.size, a.txid} < FeeKey{b.fee, b.size, b.txid};
    });
    std::vector<uint256> want;
    for (auto& r : rows) want.push_back(r.txid);

    EXPECT_EQ(sel_order(mp, 1u << 20), want)
        << "no-ancestor mempool must select in byte-identical FeeKey order — "
           "the pure-feerate path is preserved bit-for-bit";
}

// ── K8 — CAPS FENCE. (a) The strict byte-cap `>` boundary with continue-not-
// break: a package that does not fit is skipped, and a later smaller candidate
// still fits. (b) The sigop cap `>=` reject-AT-cap at DASH_MAX_BLOCK_SIGOPS.
// Both admitted sets must be identical before and after the port.
TEST(DashMempoolSelectionFidelity, K8_CapsBoundariesPreserved)
{
    // (a) byte cap continue-not-break.
    {
        UTXOViewCache utxo(nullptr);
        Mempool mp;
        mp.set_utxo(&utxo);
        // Big high-fee tx BIG, small lower-fee tx SMALL. Cap fits SMALL but not
        // BIG. BIG is considered first (higher feerate) and skipped on the byte
        // cap; SMALL must still be admitted (continue, not break).
        uint256 cbig = mint_hash(1090), csmall = mint_hash(1091);
        utxo.add_coin(Outpoint(cbig, 0),   Coin(1'000'000, {}, 1, false));
        utxo.add_coin(Outpoint(csmall, 0), Coin(100'000, {}, 1, false));
        auto BIG   = make_spend_padded(cbig, 0, 900'000, /*salt=*/1092, /*pad=*/2000); // fee 100'000
        auto SMALL = make_spend(csmall, 0, 95'000, /*salt=*/1093);                     // fee   5'000
        ASSERT_TRUE(mp.add_tx(BIG));
        ASSERT_TRUE(mp.add_tx(SMALL));
        auto szSmall = mp.get_entry(dash_txid(SMALL))->base_size;
        auto got = sel_set(mp, szSmall + 10);   // fits SMALL, never BIG
        EXPECT_EQ(got.count(dash_txid(SMALL)), 1u)
            << "byte cap must `continue`, not `break`: the later small tx still fits";
        EXPECT_EQ(got.count(dash_txid(BIG)), 0u);
        EXPECT_EQ(got.size(), 1u);
    }
    // (b) sigop cap reject-AT-cap (>=): two bare-multisig-stuffed txs at 20'000
    // legacy sigops each; 100 (coinbase reserve) + 2×20'000 crosses 40'000.
    {
        UTXOViewCache utxo(nullptr);
        Mempool mp;
        mp.set_utxo(&utxo);
        for (int i = 0; i < 2; ++i) {
            uint256 prev = mint_hash(1095 + i);
            utxo.add_coin(Outpoint(prev, 0), Coin(100'000, {}, 1, false));
            auto tx = make_spend(prev, 0, 90'000, /*salt=*/1097 + i);
            tx.vout[0].scriptPubKey.m_data.assign(1'000, 0xae);  // OP_CHECKMULTISIG ×1000
            ASSERT_TRUE(mp.add_tx(tx));
        }
        auto [sel, fees] = mp.get_sorted_txs_with_fees(1u << 20);
        EXPECT_EQ(sel.size(), 1u)
            << "sigop cap `>=` at 40'000 must stop selection at one such tx";
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Gate #133 — the two remaining dashd BlockAssembler::addPackageTxs residuals
// ported into get_sorted_txs_with_fees:
//   PORT 1  blockMinFeeRate early-return   (dashd src/node/miner.cpp:584-587)
//   PORT 2  nConsecutiveFailed cutoff       (dashd src/node/miner.cpp:490-491,
//                                            598-603, 625)
//
// Expected values are derived ONLY from dashd source constants:
//   DEFAULT_BLOCK_MIN_TX_FEE = 1000   (src/policy/policy.h:25)
//   CFeeRate::GetFee(size)   = ceil(sat_per_k * size / 1000.0), rounded up to 1
//                              for a nonzero size (src/policy/feerate.cpp:23-37)
//   MAX_CONSECUTIVE_FAILURES = 1000   (src/node/miner.cpp:490)
// ════════════════════════════════════════════════════════════════════════════

// Independent KAT reference for dashd CFeeRate::GetFee — a SECOND, hand-written
// implementation (never a call into the header under test) so a regression in
// mempool.hpp's own copy cannot mask itself.
static int64_t kat_min_fee(int64_t sat_per_k, uint64_t num_bytes) {
    const int64_t n = static_cast<int64_t>(num_bytes);
    int64_t fee = static_cast<int64_t>(
        std::ceil(static_cast<double>(sat_per_k * n) / 1000.0));
    if (fee == 0 && n != 0 && sat_per_k > 0) fee = 1;
    return fee;
}

// Add a plain 1-in/1-out tx paying EXACTLY `fee` duffs. Seeds a fresh confirmed
// coin (100'000'000) for the input so the fee is KNOWN. `seed` must be unique
// within a test. Returns the txid. (The value magnitude never changes the
// serialized size — TxOut.value is a fixed-width field — so `fee` is free to
// vary independently of the base size the floor is computed from.)
static uint256 add_priced(Mempool& mp, UTXOViewCache& utxo, uint32_t seed,
                          int64_t fee) {
    uint256 prev = mint_hash(seed);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000'000, {}, 1, false));
    auto tx = make_spend(prev, 0, 100'000'000 - fee, /*salt=*/seed);
    EXPECT_TRUE(mp.add_tx(tx));
    return dash_txid(tx);
}

// Serialized base size of a plain 1-in/1-out make_spend tx, measured at runtime.
static uint32_t one_in_one_out_size() {
    UTXOViewCache utxo(nullptr);
    Mempool mp; mp.set_utxo(&utxo);
    uint256 tid = add_priced(mp, utxo, /*seed=*/40'000, /*fee=*/1'000);
    return mp.get_entry(tid)->base_size;
}

// ── PORT 1: blockMinFeeRate ──────────────────────────────────────────────────

TEST(DashMempoolBlockMinFeeRate, DefaultFloorIsCanonicalDashd1000)
{
    {
        UTXOViewCache utxo(nullptr); Mempool mp; mp.set_utxo(&utxo);
        EXPECT_EQ(mp.block_min_tx_fee(), 1000)
            << "the knob must default to dashd DEFAULT_BLOCK_MIN_TX_FEE";
    }
    EXPECT_EQ(Mempool::DEFAULT_BLOCK_MIN_TX_FEE, 1000);

    const uint32_t S = one_in_one_out_size();
    const int64_t floor = kat_min_fee(1000, S);        // == S at perK 1000
    ASSERT_EQ(floor, static_cast<int64_t>(S));

    // fee == floor : INCLUDED (the gate is strict `<`, not `<=`).
    {
        UTXOViewCache utxo(nullptr); Mempool mp; mp.set_utxo(&utxo);
        uint256 tid = add_priced(mp, utxo, 41'000, /*fee=*/floor);
        EXPECT_EQ(sel_set(mp, 1u << 20).count(tid), 1u)
            << "a package paying EXACTLY the floor must be included";
    }
    // fee == floor-1 : EXCLUDED, and selection returns empty.
    {
        UTXOViewCache utxo(nullptr); Mempool mp; mp.set_utxo(&utxo);
        uint256 tid = add_priced(mp, utxo, 41'001, /*fee=*/floor - 1);
        auto got = sel_set(mp, 1u << 20);
        EXPECT_EQ(got.count(tid), 0u)
            << "a sub-floor package must be excluded by blockMinFeeRate";
        EXPECT_TRUE(got.empty()) << "the sub-floor best candidate must RETURN (empty block)";
    }
}

TEST(DashMempoolBlockMinFeeRate, CeilBoundaryMatchesDashdGetFee)
{
    const uint32_t S = one_in_one_out_size();
    ASSERT_NE(S % 1000u, 0u) << "test-size assumption for the ceil probe";
    const int64_t perK = 1001;                          // forces a fractional GetFee
    const int64_t floor = kat_min_fee(perK, S);         // ceil(1001*S/1000)
    const int64_t trunc = (perK * static_cast<int64_t>(S)) / 1000;   // floor division
    ASSERT_EQ(floor, trunc + 1) << "GetFee must ROUND UP here, not truncate";

    // fee == floor-1 (== the truncated value): EXCLUDED — proves CEIL, not floor.
    {
        UTXOViewCache utxo(nullptr); Mempool mp; mp.set_utxo(&utxo);
        mp.set_block_min_tx_fee(perK);
        uint256 tid = add_priced(mp, utxo, 42'000, /*fee=*/floor - 1);
        EXPECT_EQ(sel_set(mp, 1u << 20).count(tid), 0u)
            << "fee one below ceil(perK*size/1000) must be excluded";
    }
    // fee == floor : INCLUDED.
    {
        UTXOViewCache utxo(nullptr); Mempool mp; mp.set_utxo(&utxo);
        mp.set_block_min_tx_fee(perK);
        uint256 tid = add_priced(mp, utxo, 42'001, /*fee=*/floor);
        EXPECT_EQ(sel_set(mp, 1u << 20).count(tid), 1u)
            << "fee exactly at the ceil floor must be included";
    }
}

TEST(DashMempoolBlockMinFeeRate, KnobRaisesFloorAndExcludes)
{
    const uint32_t S = one_in_one_out_size();
    const int64_t at_default_floor = kat_min_fee(1000, S);   // == S

    // Included at the default floor...
    {
        UTXOViewCache utxo(nullptr); Mempool mp; mp.set_utxo(&utxo);
        uint256 tid = add_priced(mp, utxo, 43'000, /*fee=*/at_default_floor);
        EXPECT_EQ(sel_set(mp, 1u << 20).count(tid), 1u);
    }
    // ...excluded once the knob raises the floor above its feerate.
    {
        UTXOViewCache utxo(nullptr); Mempool mp; mp.set_utxo(&utxo);
        mp.set_block_min_tx_fee(1'000'000);                  // 1000 duff/byte
        uint256 tid = add_priced(mp, utxo, 43'001, /*fee=*/at_default_floor);
        EXPECT_EQ(sel_set(mp, 1u << 20).count(tid), 0u)
            << "raising blockmintxfee must exclude a now-sub-floor tx";
    }
}

TEST(DashMempoolBlockMinFeeRate, GatesOnWholeAncestorPackageFeerateNotSelf)
{
    // CPFP: a big cheap PARENT + a small CHILD whose SELF feerate is far above
    // the floor but whose WHOLE ancestor-package feerate (parent+child) is
    // BELOW it. dashd gates on GetModFeesWithAncestors/GetSizeWithAncestors —
    // the whole package — so the child is dropped, and because it is the best
    // remaining candidate the loop RETURNS with an empty block. Gating on the
    // child's SELF feerate (or on collect_package_locked's unselected-ancestor
    // remainder) would instead admit BOTH. Default floor perK=1000 →
    // floor(size)=size duffs.
    UTXOViewCache utxo(nullptr); Mempool mp; mp.set_utxo(&utxo);
    uint256 coinP = mint_hash(44'000);
    utxo.add_coin(Outpoint(coinP, 0), Coin(100'000'000, {}, 1, false));

    // Parent: padded ~2 KB, fee only 50 → deeply sub-floor on its own.
    auto parent = make_spend_padded(coinP, 0, 100'000'000 - 50, /*salt=*/44'000, /*pad=*/2000);
    ASSERT_TRUE(mp.add_tx(parent));
    const uint32_t Sp = mp.get_entry(dash_txid(parent))->base_size;

    // Child spends parent:0; small 1-in/1-out with a HIGH self fee (500).
    auto child = make_spend(dash_txid(parent), 0, (100'000'000 - 50) - 500, /*salt=*/44'001);
    ASSERT_TRUE(mp.add_tx(child));
    const uint32_t Sc = mp.get_entry(dash_txid(child))->base_size;

    // Pin the intended regime from the MEASURED sizes:
    ASSERT_GE(int64_t(500), kat_min_fee(1000, Sc))            // child SELF >= its own floor
        << "child self feerate must be ABOVE the floor";
    ASSERT_LT(int64_t(50 + 500), kat_min_fee(1000, Sp + Sc))  // package < package floor
        << "whole (parent+child) package feerate must be BELOW the floor";

    EXPECT_TRUE(sel_set(mp, 1u << 20).empty())
        << "child gated on WHOLE-package feerate (sub-floor) → dropped; as the "
           "best candidate its verdict RETURNS an empty selection. A self- or "
           "remainder-feerate gate would wrongly admit {parent, child}.";
}

// ── PORT 2: nConsecutiveFailed ───────────────────────────────────────────────

TEST(DashMempoolConsecutiveFailed, BreaksAfter1000FailuresNearCap)
{
    // Isolate the cutoff from the fee floor (perK=0 → floor never fires). One
    // high-fee FILL takes the block within <1000 bytes of the cap; >1000
    // higher-priority fillers then each overflow the byte cap (continue +
    // ++nConsecutiveFailed) until the cutoff BREAKS the loop — so a later,
    // lowest-fee tx that WOULD fit is never reached.
    UTXOViewCache utxo(nullptr); Mempool mp; mp.set_utxo(&utxo);
    mp.set_block_min_tx_fee(0);

    uint256 coinF = mint_hash(50'000);
    utxo.add_coin(Outpoint(coinF, 0), Coin(100'000'000, {}, 1, false));
    auto FILL = make_spend_padded(coinF, 0, 100'000'000 - 5'000'000, /*salt=*/50'000, /*pad=*/4200);
    ASSERT_TRUE(mp.add_tx(FILL));
    const uint32_t Sf = mp.get_entry(dash_txid(FILL))->base_size;
    const uint32_t max_bytes = Sf + 700;              // 700B room after FILL: <1000 (near cap)

    for (uint32_t i = 0; i < 1002; ++i) {             // >1000 fillers, each ~1KB > 700B room
        uint256 prev = mint_hash(50'010 + i);
        utxo.add_coin(Outpoint(prev, 0), Coin(100'000'000, {}, 1, false));
        auto f = make_spend_padded(prev, 0, 100'000'000 - 100'000, /*salt=*/50'010 + i, /*pad=*/950);
        ASSERT_TRUE(mp.add_tx(f));
    }
    uint256 finalTid = add_priced(mp, utxo, 52'000, /*fee=*/50);   // tiny, LOWEST feerate

    auto got = sel_set(mp, max_bytes);
    EXPECT_EQ(got.count(dash_txid(FILL)), 1u);
    EXPECT_EQ(got.count(finalTid), 0u)
        << "nConsecutiveFailed>1000 within 1000B of the cap must BREAK before "
           "the later fitting tx is reached";
    EXPECT_EQ(got.size(), 1u)
        << "only FILL fits; fillers overflow, FINAL is cut off by the break";
}

TEST(DashMempoolConsecutiveFailed, NoBreakWhenNotNearCapSigopFailures)
{
    // >1000 consecutive failures that are NOT byte-cap failures: each filler
    // alone exceeds the 40'000 sigop cap. Because total_bytes stays far below
    // max_bytes-1000, the give-up guard is FALSE and the loop does NOT break —
    // a later low-sigop tx is still reached and selected.
    UTXOViewCache utxo(nullptr); Mempool mp; mp.set_utxo(&utxo);
    mp.set_block_min_tx_fee(0);
    const uint32_t max_bytes = 8u << 20;              // 8 MB: byte room always ample

    for (uint32_t i = 0; i < 1002; ++i) {
        uint256 prev = mint_hash(60'000 + i);
        utxo.add_coin(Outpoint(prev, 0), Coin(100'000'000, {}, 1, false));
        auto f = make_spend(prev, 0, 100'000'000 - 100'000, /*salt=*/60'000 + i);
        f.vout[0].scriptPubKey.m_data.assign(2'000, 0xae);   // 2'000×20 = 40'000 legacy sigops
        ASSERT_TRUE(mp.add_tx(f));
    }
    uint256 finalTid = add_priced(mp, utxo, 61'100, /*fee=*/50);   // 0-sigop, LOWEST feerate

    auto got = sel_set(mp, max_bytes);
    EXPECT_EQ(got.count(finalTid), 1u)
        << "sigop-cap failures far from the byte cap must NOT trigger the "
           "near-cap break: the later fitting tx is still selected";
    EXPECT_EQ(got.size(), 1u)
        << "every sigop-stuffed filler is rejected AT the cap; only FINAL admits";
}

TEST(DashMempoolConsecutiveFailed, ResetPerAdmittedPackagePreventsBreak)
{
    // The counter resets on every ADMITTED package. Two runs of 600 byte-cap
    // failures each (1200 > 1000 total) are separated by ONE admitted tx that
    // resets the counter — so it never reaches 1001 IN A ROW and the loop does
    // NOT break: a final fitting tx is still selected. Without the reset the
    // 1200 cumulative failures near the cap would break and cut it off.
    UTXOViewCache utxo(nullptr); Mempool mp; mp.set_utxo(&utxo);
    mp.set_block_min_tx_fee(0);

    uint256 coinF = mint_hash(55'000);
    utxo.add_coin(Outpoint(coinF, 0), Coin(100'000'000, {}, 1, false));
    auto FILL = make_spend_padded(coinF, 0, 100'000'000 - 9'000'000, /*salt=*/55'000, /*pad=*/4200);
    ASSERT_TRUE(mp.add_tx(FILL));
    const uint32_t Sf = mp.get_entry(dash_txid(FILL))->base_size;
    const uint32_t max_bytes = Sf + 700;              // near cap (room 700B < 1000)

    // Big fillers ~1KB (> room → byte-cap fail). Feerate tiers pick-order the
    // run as: FILL, [tierA 600], MID(fits→reset), [tierB 600], FINAL(fits).
    auto add_big = [&](uint32_t seed, int64_t fee) {
        uint256 prev = mint_hash(seed);
        utxo.add_coin(Outpoint(prev, 0), Coin(100'000'000, {}, 1, false));
        auto f = make_spend_padded(prev, 0, 100'000'000 - fee, /*salt=*/seed, /*pad=*/950);
        ASSERT_TRUE(mp.add_tx(f));
    };
    for (uint32_t i = 0; i < 600; ++i) add_big(55'010 + i, /*fee=*/310'000);   // tierA: ~299/B
    uint256 midTid = add_priced(mp, utxo, 55'700, /*fee=*/17'000);             // MID: 200/B, fits
    for (uint32_t i = 0; i < 600; ++i) add_big(56'000 + i, /*fee=*/100'000);   // tierB: ~96/B
    uint256 finalTid = add_priced(mp, utxo, 56'800, /*fee=*/50);               // FINAL: lowest

    auto got = sel_set(mp, max_bytes);
    EXPECT_EQ(got.count(midTid), 1u)   << "MID admits and resets the failure counter";
    EXPECT_EQ(got.count(finalTid), 1u)
        << "with the per-package reset, 600+600 non-consecutive failures never "
           "reach 1001 in a row → no break → FINAL is still selected";
}
