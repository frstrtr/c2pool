// SPDX-License-Identifier: AGPL-3.0-or-later
//
// W5-A KATs: FoldFeeSource (src/impl/dash/coin/fold_fee_source.hpp) — the
// graduated full-history UTXO fold as the mempool's THIRD coin source.
//
// The red/green pair the PR stands on:
//   * UngraduatedFoldDoesNotPrice — the RED shape: a tx spending a coin the
//     forward view cannot hold stays fee_known=false and excluded, exactly
//     master's behaviour, even with the fold WIRED and holding the coin —
//     because the fold has not passed the graduation gate.
//   * GraduatedFoldPricesOldCoinAndSelectsIt — the GREEN: after a PASSING
//     gate at a synthetic anchor, the same tx is priced with the exact fee
//     and SELECTED into the template (both compute_fee_locked and the
//     selection-time vin resolution consult the fold).
// Everything else pins the fail-toward-exclusion faces: spent coin, immature
// coinbase, gate FAIL (poison + disarm), tip lag, graduation restore across
// reopen (incl. the operator-restatement refusal), and the prev-hash linkage
// reorg tripwire.

#include <gtest/gtest.h>

#include <impl/dash/coin/fold_fee_source.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/replay_utxo_fold.hpp>

#include <core/hash.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <filesystem>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

using dash::coin::BlockType;
using dash::coin::FoldFeeSource;
using dash::coin::Mempool;
using dash::coin::MutableTransaction;
using dash::coin::TxIn;
using dash::coin::TxOut;
using dash::coin::dash_txid;
using dash::coin::replay::ReplayUtxoFold;
using dash::coin::replay::ReplayUtxoFoldOptions;
using dash::coin::replay::write_dashd_varint;

namespace {

struct TmpDir {
    std::filesystem::path root;
    TmpDir()
    {
        root = std::filesystem::temp_directory_path() /
               ("c2pool_fold_fee_" + std::to_string(::getpid()) + "_" +
                std::to_string(reinterpret_cast<uintptr_t>(this)));
        std::filesystem::create_directories(root);
    }
    ~TmpDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }
    std::string sub(const char* name) const { return (root / name).string(); }
};

uint256 fake_block_hash(uint32_t height)
{
    std::vector<uint8_t> seed = {'f', 'f', 's'};
    write_dashd_varint(seed, height);
    return ::Hash(seed);
}

std::vector<uint8_t> p2pkh(uint8_t tag)
{
    std::vector<uint8_t> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(tag);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

MutableTransaction make_coinbase(
    uint32_t height,
    const std::vector<std::pair<int64_t, std::vector<uint8_t>>>& outs)
{
    MutableTransaction tx;
    TxIn cin;
    cin.prevout.hash = uint256();
    cin.prevout.index = 0xFFFFFFFF;
    write_dashd_varint(cin.scriptSig.m_data, height);
    cin.sequence = 0xFFFFFFFF;
    tx.vin.push_back(cin);
    for (const auto& [value, script] : outs) {
        TxOut o;
        o.value = value;
        o.scriptPubKey.m_data = script;
        tx.vout.push_back(o);
    }
    return tx;
}

MutableTransaction make_spend(
    const std::vector<std::pair<uint256, uint32_t>>& ins,
    const std::vector<std::pair<int64_t, std::vector<uint8_t>>>& outs)
{
    MutableTransaction tx;
    for (const auto& [txid, n] : ins) {
        TxIn in;
        in.prevout.hash = txid;
        in.prevout.index = n;
        in.sequence = 0xFFFFFFFF;
        tx.vin.push_back(in);
    }
    for (const auto& [value, script] : outs) {
        TxOut o;
        o.value = value;
        o.scriptPubKey.m_data = script;
        tx.vout.push_back(o);
    }
    return tx;
}

BlockType make_block(std::vector<MutableTransaction> txs)
{
    BlockType b;
    b.m_txs = std::move(txs);
    return b;
}

// The synthetic 3-block chain every test below folds:
//   b1: cb1 (50 DASH → tag 1)                         [coinbase coin @1]
//   b2: cb2 (50 DASH → tag 2), spend1(cb1:0 → 49 DASH → tag 3)
//       — spend1:0 is THE OLD COIN: non-coinbase, height 2
//   b3: cb3 (50 DASH → tag 5)
struct Chain {
    MutableTransaction cb1, cb2, spend1, cb3;
    uint256 cb1_id, cb2_id, spend1_id;
    BlockType b1, b2, b3;
    Chain()
    {
        cb1 = make_coinbase(1, {{50'0000'0000LL, p2pkh(1)}});
        cb1_id = dash_txid(cb1);
        cb2 = make_coinbase(2, {{50'0000'0000LL, p2pkh(2)}});
        cb2_id = dash_txid(cb2);
        spend1 = make_spend({{cb1_id, 0}}, {{49'0000'0000LL, p2pkh(3)}});
        spend1_id = dash_txid(spend1);
        cb3 = make_coinbase(3, {{50'0000'0000LL, p2pkh(5)}});
        b1 = make_block({cb1});
        b2 = make_block({cb2, spend1});
        b3 = make_block({cb3});
    }
};

// Fold the chain to height `upto` (2 or 3) in a throwaway store and return
// hash_serialized_2 at h=2 — the synthetic anchor value the gate tests
// demand. Computed by the SAME module the gate uses, in a separate store, so
// the gate test proves the LATCH mechanics (write/restore/refuse), while the
// hash CONSTRUCTION itself is pinned against an independent preimage in
// test_dash_replay_utxo_fold.cpp.
std::string anchor_hash_at_2(const Chain& c)
{
    TmpDir tmp;
    ReplayUtxoFold f;
    EXPECT_TRUE(f.open(tmp.sub("probe")));
    EXPECT_TRUE(f.on_replay_block(1, fake_block_hash(1), c.b1));
    EXPECT_TRUE(f.on_replay_block(2, fake_block_hash(2), c.b2));
    auto h = f.hash_serialized_2();
    EXPECT_TRUE(h.has_value());
    return h->hash.GetHex();
}

ReplayUtxoFoldOptions gate_at_2(const std::string& expect_hex)
{
    ReplayUtxoFoldOptions o;
    o.gate_anchor_height = 2;
    o.gate_anchor_expect = expect_hex;
    return o;
}

} // namespace

// ── KAT (c): an UNGRADUATED fold prices NOTHING (the red shape) ────────────
TEST(FoldFeeSource, UngraduatedFoldDoesNotPrice)
{
    Chain c;
    TmpDir tmp;
    // Anchor far beyond the chain: the gate can never fire.
    ReplayUtxoFoldOptions o;
    o.gate_anchor_height = 100;
    ReplayUtxoFold fold(o);
    ASSERT_TRUE(fold.open(tmp.sub("db")));
    FoldFeeSource::Options so;
    so.operator_expect = std::string(64, 'a');
    FoldFeeSource src(fold, so);
    ASSERT_TRUE(src.feed(1, fake_block_hash(1), c.b1));
    ASSERT_TRUE(src.feed(2, fake_block_hash(2), c.b2));
    ASSERT_TRUE(src.feed(3, fake_block_hash(3), c.b3));
    src.note_tip(3);
    EXPECT_FALSE(src.graduated());
    EXPECT_FALSE(src.trusted());

    Mempool pool;
    ::core::coin::UTXOViewCache view(nullptr);   // forward view: EMPTY
    pool.set_utxo(&view);
    pool.set_fee_coin_lookup(
        [&src](const ::core::coin::Outpoint& op, ::core::coin::Coin& out) {
            return src.lookup(op, out);
        });
    // Spends the old coin (spend1:0) the fold HOLDS — but the fold is not
    // graduated, so the tx must stay fee-unknown and excluded (master's
    // behaviour, byte-identical).
    auto tx = make_spend({{c.spend1_id, 0}},
                         {{49'0000'0000LL - 100000, p2pkh(9)}});
    ASSERT_TRUE(pool.add_tx(tx));
    auto e = pool.get_entry(dash_txid(tx));
    ASSERT_TRUE(e.has_value());
    EXPECT_FALSE(e->fee_known);
    auto [sel, fees] = pool.get_sorted_txs_with_fees(1'000'000, false, 4, 0);
    EXPECT_TRUE(sel.empty());
    EXPECT_EQ(fees, 0u);
}

// ── KAT (a): a GRADUATED fold prices the old coin and it gets SELECTED ─────
TEST(FoldFeeSource, GraduatedFoldPricesOldCoinAndSelectsIt)
{
    Chain c;
    const std::string expect = anchor_hash_at_2(c);

    TmpDir tmp;
    ReplayUtxoFold fold(gate_at_2(expect));
    ASSERT_TRUE(fold.open(tmp.sub("db")));
    FoldFeeSource::Options so;
    so.operator_expect = expect;
    FoldFeeSource src(fold, so);
    ASSERT_TRUE(src.feed(1, fake_block_hash(1), c.b1));
    ASSERT_TRUE(src.feed(2, fake_block_hash(2), c.b2));   // ← gate fires, PASS
    EXPECT_TRUE(src.graduated());
    ASSERT_TRUE(src.feed(3, fake_block_hash(3), c.b3));
    src.note_tip(3);
    EXPECT_TRUE(src.trusted());

    Mempool pool;
    ::core::coin::UTXOViewCache view(nullptr);
    pool.set_utxo(&view);
    pool.set_fee_coin_lookup(
        [&src](const ::core::coin::Outpoint& op, ::core::coin::Coin& out) {
            return src.lookup(op, out);
        });
    const uint64_t kFee = 100000;
    auto tx = make_spend({{c.spend1_id, 0}},
                         {{49'0000'0000LL - static_cast<int64_t>(kFee),
                           p2pkh(9)}});
    ASSERT_TRUE(pool.add_tx(tx));
    auto e = pool.get_entry(dash_txid(tx));
    ASSERT_TRUE(e.has_value());
    EXPECT_TRUE(e->fee_known);
    EXPECT_EQ(e->fee, kFee);
    // The selection-time vin resolution must ALSO resolve through the fold —
    // pricing alone would be undone by the stale-input guard.
    auto [sel, fees] = pool.get_sorted_txs_with_fees(1'000'000, false, 4, 0);
    ASSERT_EQ(sel.size(), 1u);
    EXPECT_EQ(dash_txid(sel[0].tx), dash_txid(tx));
    EXPECT_EQ(fees, kFee);
}

// ── Spent-in-fold ⇒ excluded (a spent coin never becomes an input value) ───
TEST(FoldFeeSource, SpentCoinInFoldNotPriced)
{
    Chain c;
    const std::string expect = anchor_hash_at_2(c);
    TmpDir tmp;
    ReplayUtxoFold fold(gate_at_2(expect));
    ASSERT_TRUE(fold.open(tmp.sub("db")));
    FoldFeeSource::Options so;
    so.operator_expect = expect;
    FoldFeeSource src(fold, so);
    ASSERT_TRUE(src.feed(1, fake_block_hash(1), c.b1));
    ASSERT_TRUE(src.feed(2, fake_block_hash(2), c.b2));
    ASSERT_TRUE(src.feed(3, fake_block_hash(3), c.b3));
    src.note_tip(3);
    ASSERT_TRUE(src.trusted());

    Mempool pool;
    ::core::coin::UTXOViewCache view(nullptr);
    pool.set_utxo(&view);
    pool.set_fee_coin_lookup(
        [&src](const ::core::coin::Outpoint& op, ::core::coin::Coin& out) {
            return src.lookup(op, out);
        });
    // cb1:0 was SPENT by spend1 in block 2 — the fold answers false.
    auto tx = make_spend({{c.cb1_id, 0}}, {{10'0000'0000LL, p2pkh(9)}});
    ASSERT_TRUE(pool.add_tx(tx));
    auto e = pool.get_entry(dash_txid(tx));
    ASSERT_TRUE(e.has_value());
    EXPECT_FALSE(e->fee_known);
}

// ── Immature coinbase in the fold ⇒ excluded (dashd would not pool it) ─────
TEST(FoldFeeSource, ImmatureCoinbaseInFoldNotPriced)
{
    Chain c;
    const std::string expect = anchor_hash_at_2(c);
    TmpDir tmp;
    ReplayUtxoFold fold(gate_at_2(expect));
    ASSERT_TRUE(fold.open(tmp.sub("db")));
    FoldFeeSource::Options so;
    so.operator_expect = expect;
    FoldFeeSource src(fold, so);
    ASSERT_TRUE(src.feed(1, fake_block_hash(1), c.b1));
    ASSERT_TRUE(src.feed(2, fake_block_hash(2), c.b2));
    ASSERT_TRUE(src.feed(3, fake_block_hash(3), c.b3));
    src.note_tip(3);
    ASSERT_TRUE(src.trusted());

    Mempool pool;
    ::core::coin::UTXOViewCache view(nullptr);
    pool.set_utxo(&view);
    pool.set_fee_coin_lookup(
        [&src](const ::core::coin::Outpoint& op, ::core::coin::Coin& out) {
            return src.lookup(op, out);
        });
    // cb2:0 is a COINBASE coin at h=2; spend height 4 << 2+100.
    auto tx = make_spend({{c.cb2_id, 0}}, {{49'0000'0000LL, p2pkh(9)}});
    ASSERT_TRUE(pool.add_tx(tx));
    auto e = pool.get_entry(dash_txid(tx));
    ASSERT_TRUE(e.has_value());
    EXPECT_FALSE(e->fee_known);
}

// ── Gate FAIL: fold poisoned, lane stopped, source disarmed, no record ─────
TEST(FoldFeeSource, GateFailPoisonsAndDisarms)
{
    Chain c;
    TmpDir tmp;
    const std::string wrong(64, 'e');
    ReplayUtxoFold fold(gate_at_2(wrong));
    ASSERT_TRUE(fold.open(tmp.sub("db")));
    FoldFeeSource::Options so;
    so.operator_expect = wrong;   // operator agrees with the (wrong) anchor
    FoldFeeSource src(fold, so);
    ASSERT_TRUE(src.feed(1, fake_block_hash(1), c.b1));
    // The gate fires at h=2 and FAILS: feed refuses (stops a bulk lane),
    // the fold is poisoned, nothing is written, the source is disarmed.
    EXPECT_FALSE(src.feed(2, fake_block_hash(2), c.b2));
    EXPECT_TRUE(fold.poisoned());
    EXPECT_FALSE(src.graduated());
    EXPECT_TRUE(src.disarmed());
    EXPECT_FALSE(fold.graduation().has_value());
    // Poison latches: further blocks refuse.
    EXPECT_FALSE(src.feed(3, fake_block_hash(3), c.b3));
    src.note_tip(3);
    EXPECT_FALSE(src.trusted());
    ::core::coin::Coin out;
    EXPECT_FALSE(src.lookup(
        ::core::coin::Outpoint(c.spend1_id, 0), out));
}

// ── Trust condition 2: a fold behind the tip prices nothing ────────────────
TEST(FoldFeeSource, TipLagDropsTrust)
{
    Chain c;
    const std::string expect = anchor_hash_at_2(c);
    TmpDir tmp;
    ReplayUtxoFold fold(gate_at_2(expect));
    ASSERT_TRUE(fold.open(tmp.sub("db")));
    FoldFeeSource::Options so;
    so.operator_expect = expect;
    FoldFeeSource src(fold, so);
    ASSERT_TRUE(src.feed(1, fake_block_hash(1), c.b1));
    ASSERT_TRUE(src.feed(2, fake_block_hash(2), c.b2));
    ASSERT_TRUE(src.feed(3, fake_block_hash(3), c.b3));
    src.note_tip(3);
    ASSERT_TRUE(src.trusted());
    ::core::coin::Coin out;
    EXPECT_TRUE(src.lookup(::core::coin::Outpoint(c.spend1_id, 0), out));
    // The chain advances without the fold: trust drops, lookups go dark.
    src.note_tip(10);
    EXPECT_FALSE(src.trusted());
    EXPECT_FALSE(src.lookup(::core::coin::Outpoint(c.spend1_id, 0), out));
}

// ── Graduation survives a reopen — ONLY with the matching restatement ──────
TEST(FoldFeeSource, GraduationRestoreAcrossReopen)
{
    Chain c;
    const std::string expect = anchor_hash_at_2(c);
    TmpDir tmp;
    const std::string db = tmp.sub("db");
    {
        ReplayUtxoFold fold(gate_at_2(expect));
        ASSERT_TRUE(fold.open(db));
        FoldFeeSource::Options so;
        so.operator_expect = expect;
        FoldFeeSource src(fold, so);
        ASSERT_TRUE(src.feed(1, fake_block_hash(1), c.b1));
        ASSERT_TRUE(src.feed(2, fake_block_hash(2), c.b2));
        ASSERT_TRUE(src.feed(3, fake_block_hash(3), c.b3));
        ASSERT_TRUE(src.graduated());
        fold.close();
    }
    {
        // Same DB, correct restatement: trust restores WITHOUT re-measuring.
        ReplayUtxoFold fold(gate_at_2(expect));
        ASSERT_TRUE(fold.open(db));
        FoldFeeSource::Options so;
        so.operator_expect = expect;
        FoldFeeSource src(fold, so);
        EXPECT_TRUE(src.graduated());
        src.note_tip(3);
        EXPECT_TRUE(src.trusted());
        fold.close();
    }
    {
        // Same DB, WRONG restatement: the record is ignored — a foreign or
        // stale DB cannot graduate on its own say-so.
        ReplayUtxoFold fold(gate_at_2(expect));
        ASSERT_TRUE(fold.open(db));
        FoldFeeSource::Options so;
        so.operator_expect = std::string(64, 'd');
        FoldFeeSource src(fold, so);
        EXPECT_FALSE(src.graduated());
        src.note_tip(3);
        EXPECT_FALSE(src.trusted());
    }
}

// ── Reorg tripwire: prev-hash linkage refusal (opt-in, adapter arms it) ────
TEST(ReplayUtxoFoldGate, PrevLinkageRefusesOrphanFold)
{
    Chain c;
    TmpDir tmp;
    ReplayUtxoFoldOptions o;
    o.check_prev_linkage = true;
    o.gate_anchor_height = 100;
    ReplayUtxoFold fold(o);
    ASSERT_TRUE(fold.open(tmp.sub("db")));
    ASSERT_TRUE(fold.on_replay_block(1, fake_block_hash(1), c.b1));
    // b2 with the CORRECT prev link folds fine.
    BlockType linked = c.b2;
    linked.m_previous_block = fake_block_hash(1);
    ASSERT_TRUE(fold.on_replay_block(2, fake_block_hash(2), linked));
    // b3 claiming a DIFFERENT parent (an orphaned h=2) is REFUSED — silently
    // folding across a reorg is structurally impossible.
    BlockType orphan_child = c.b3;
    orphan_child.m_previous_block = fake_block_hash(99);
    EXPECT_FALSE(fold.on_replay_block(3, fake_block_hash(3), orphan_child));
    EXPECT_NE(fold.refusal().find("replay-utxo-prev-mismatch"),
              std::string::npos);
    // The correctly-linked child is still accepted afterwards.
    BlockType good_child = c.b3;
    good_child.m_previous_block = fake_block_hash(2);
    EXPECT_TRUE(fold.on_replay_block(3, fake_block_hash(3), good_child));
}
