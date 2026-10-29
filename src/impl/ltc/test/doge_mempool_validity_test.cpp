// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// DOGE mempool validity (rides share_test): a tx reaches a DOGE template
// only when every input is shown unspent and spendable (DESIGN doge-underfill
// §3.4, §3.6 invariant clauses (b) and (c)).
//   - ImmatureCoinbaseSpendIsNeverSelected: an input the view holds that is a
//     coinbase 10 blocks deep (DOGE maturity 240) is refused at admission
//     (inputs_invalid, Core bad-txns-premature-spend-of-coinbase) and, forced
//     into the pool anyway, never selected. Before, its fee stayed unknown and
//     the DOGE Pass 2 packed it with fee=null: a whole DOGE block lost.
//   - NoViewSelectsNothing: with no UTXO view nothing is selected and the
//     template says why (utxo-incomplete). Before, every tx was packed on
//     trust.
//   - OrphanIsParkedAndPromotedWhenParentArrives: with a set built from
//     genesis a child relayed before its parent waits in the orphan set and
//     enters the pool, priced, the moment the parent does (or the block
//     confirming it connects). Before, the child was admitted fee-unknown and
//     priced only at the next block.
// ---------------------------------------------------------------------------
#include "doge_utxo_lane_harness.hpp"

namespace {

constexpr uint32_t TIP = 5'000'001;
constexpr uint32_t WEIGHT = doge::coin::TemplateBuilder::MAX_BLOCK_WEIGHT
                          - doge::coin::TemplateBuilder::COINBASE_RESERVE;

uint256 hash_tag(uint8_t a, uint8_t b)
{
    uint256 h;
    h.data()[0] = a;
    h.data()[1] = b;
    h.data()[31] = 0x6e;
    return h;
}

/// A set built from genesis, complete at the tip, holding `coins`.
void complete_set(TempDb& t, const DogeTip& tip, const core::coin::UTXOViewDB::ChangeMap& coins)
{
    ASSERT_TRUE(t.db->write_batch(coins, tip.hash(), tip.height()));
    core::coin::SyncState s;
    s.anchor_height = 0;
    s.strict = 1;
    s.synced = 1;
    ASSERT_TRUE(t.cache->set_sync_state(s));
    ASSERT_TRUE(t.cache->complete(tip.height()));
}

} // namespace

// KAT 5 (§3.6 (c)): a coinbase 10 blocks below the tip is not spendable.
TEST(DogeMempool, ImmatureCoinbaseSpendIsNeverSelected)
{
    DogeTip tip(DogeTip::header_at(TIP), TIP);
    core::coin::UTXOViewCache view(nullptr);
    const Outpoint cb(hash_tag(0x51, 1), 0);
    view.add_coin(cb, coin_of(DOGE_SUBSIDY, TIP - 10, /*coinbase=*/true));
    Mempool pool(core::coin::DOGE_LIMITS);
    pool.set_utxo(&view);
    pool.set_tip_height(TIP);

    const auto tx = spend(cb.txid, cb.index, DOGE_SUBSIDY - 100000000, 0x52);
    const uint256 txid = txid_of(tx);
    const auto r = pool.admit(tx, &view);
    EXPECT_TRUE(r.has_value()) << "a premature coinbase spend was admitted";
    if (r)
        EXPECT_STREQ(Mempool::reject_code_name(r->code), "inputs_invalid");
    EXPECT_FALSE(pool.contains(txid));

    // Past admission anyway: the template side never selects it.
    pool.add_tx_unchecked(tx, &view);
    ASSERT_TRUE(pool.contains(txid));
    tip.clean(pool);
    const auto t = tip.build(pool);
    EXPECT_TRUE(t["transactions"].empty()) << "a premature coinbase spend reached the template (fee=null)";
    EXPECT_EQ(t["coinbasevalue"].get<int64_t>(), tip.subsidy());
}

// KAT 6 (§2.2): no view, no selection.
TEST(DogeMempool, NoViewSelectsNothing)
{
    DogeTip tip(DogeTip::header_at(TIP), TIP);
    Mempool pool(core::coin::DOGE_LIMITS);
    pool.set_utxo(nullptr);
    const auto a = spend(hash_tag(0x61, 1), 0, 500000000, 0x61);
    const auto b = spend(hash_tag(0x61, 2), 0, 500000000, 0x62);
    const auto c = spend(hash_tag(0x61, 3), 0, 500000000, 0x63);
    for (const auto* tx : {&a, &b, &c})
        ASSERT_TRUE(pool.add_tx(*tx));
    pool.set_tx_fee(txid_of(a), 1000000);  // priced without a view (a test hook)
    tip.clean(pool);

    const auto sel = pool.get_sorted_txs_with_fees(WEIGHT);
    EXPECT_TRUE(sel.first.empty()) << sel.first.size() << " tx(s) selected with no UTXO view";
    EXPECT_EQ(sel.second, 0u);

    const auto t = tip.build(pool);
    EXPECT_TRUE(t["transactions"].empty()) << t["transactions"].size() << " tx(s) in a template with no UTXO view";
    EXPECT_EQ(t.value("degraded", std::string()), doge::coin::kUtxoIncomplete);
    EXPECT_EQ(t["coinbasevalue"].get<int64_t>(), tip.subsidy());
}

// KAT 7 (§3.4): orphans as in Core.
TEST(DogeMempool, OrphanIsParkedAndPromotedWhenParentArrives)
{
    TempDb t;
    DogeTip tip(DogeTip::header_at(TIP), TIP);
    const Outpoint x(hash_tag(0x71, 1), 0);   // P's input
    const Outpoint y(hash_tag(0x71, 2), 0);   // Q's input
    complete_set(t, tip, {{x, coin_of(10'000'000'000LL, TIP - 50, false)},
                          {y, coin_of(10'000'000'000LL, TIP - 50, false)}});
    Mempool pool(core::coin::DOGE_LIMITS);
    pool.set_utxo(t.cache.get());
    pool.set_tip_height(TIP);

    const auto p = spend(x.txid, 0, 9'900'000'000LL, 0x72);           // fee 1 DOGE
    const auto c = spend(txid_of(p), 0, 9'850'000'000LL, 0x73);       // fee 0.5 DOGE
    const uint256 pid = txid_of(p), cid = txid_of(c);

    // The child first: an orphan, not a pool entry.
    const auto rc = pool.admit(c, t.cache.get());
    ASSERT_TRUE(rc.has_value());
    EXPECT_STREQ(Mempool::reject_code_name(rc->code), "missing_inputs");
    EXPECT_FALSE(pool.contains(cid));
    EXPECT_TRUE(pool.is_orphan(cid));
    EXPECT_EQ(pool.orphan_count(), 1u);
    tip.clean(pool);
    EXPECT_TRUE(pool.get_sorted_txs_with_fees(WEIGHT).first.empty());

    // The parent: both in the pool, both priced, selectable together, parent first.
    EXPECT_FALSE(pool.admit(p, t.cache.get()).has_value());
    EXPECT_TRUE(pool.contains(cid));
    EXPECT_FALSE(pool.is_orphan(cid));
    EXPECT_EQ(pool.orphan_count(), 0u);
    const auto ce = pool.get_entry(cid);
    ASSERT_TRUE(ce.has_value());
    EXPECT_TRUE(ce->fee_known);
    EXPECT_EQ(ce->fee, 50'000'000u);
    const auto [sel, fees] = pool.get_sorted_txs_with_fees(WEIGHT);
    ASSERT_EQ(sel.size(), 2u);
    EXPECT_EQ(txid_of(sel[0].tx), pid) << "parent first";
    EXPECT_EQ(txid_of(sel[1].tx), cid);
    EXPECT_EQ(fees, 150'000'000u);

    // A child whose parent is confirmed instead: it waits until the block
    // connects, then the block's pass admits it.
    const auto q = spend(y.txid, 0, 9'900'000'000LL, 0x74);
    const auto d = spend(txid_of(q), 0, 9'800'000'000LL, 0x75);
    ASSERT_TRUE(pool.admit(d, t.cache.get()).has_value());
    EXPECT_TRUE(pool.is_orphan(txid_of(d)));
    core::coin::UTXOViewDB::ChangeMap block_effects;
    block_effects[y] = std::nullopt;                                          // Q spent y
    block_effects[Outpoint(txid_of(q), 0)] = coin_of(9'900'000'000LL, TIP + 1, false);
    ASSERT_TRUE(t.db->write_batch(block_effects, hash_tag(0x7f, 1), TIP + 1));
    pool.set_tip_height(TIP + 1);
    pool.recompute_unknown_fees(t.cache.get());
    EXPECT_FALSE(pool.is_orphan(txid_of(d)));
    const auto de = pool.get_entry(txid_of(d));
    ASSERT_TRUE(de.has_value());
    EXPECT_TRUE(de->fee_known);
    EXPECT_EQ(de->fee, 100'000'000u);
}

// The orphan set is bounded (Core DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100):
// the oldest goes first.
TEST(DogeMempool, OrphanSetIsBounded)
{
    TempDb t;
    DogeTip tip(DogeTip::header_at(TIP), TIP);
    complete_set(t, tip, {});
    Mempool pool(core::coin::DOGE_LIMITS);
    pool.set_utxo(t.cache.get());
    for (int i = 0; i < 130; ++i)
        EXPECT_TRUE(pool.admit(spend(hash_tag(0x81, static_cast<uint8_t>(i)), 0, 100000000, 0x81),
                               t.cache.get()).has_value());
    EXPECT_EQ(pool.orphan_count(), Mempool::MAX_ORPHANS);
    EXPECT_EQ(pool.size(), 0u);
}

// A partial (accrual) view cannot tell a coin it never saw from a spent one:
// there a tx with a missing input is admitted unpriced, as before the full
// set (the dual-DB transition keeps today's admission).
TEST(DogeMempool, PartialViewAdmitsUnpricedAsBefore)
{
    core::coin::UTXOViewCache view(nullptr);
    Mempool pool(core::coin::DOGE_LIMITS);
    pool.set_utxo(&view);
    const auto tx = spend(hash_tag(0x91, 1), 0, 100000000, 0x91);
    EXPECT_FALSE(pool.admit(tx, &view).has_value());
    EXPECT_TRUE(pool.contains(txid_of(tx)));
    EXPECT_FALSE(pool.get_entry(txid_of(tx))->fee_known);
    EXPECT_EQ(pool.orphan_count(), 0u);
}
