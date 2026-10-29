// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// doge_template_underfill_test.cpp -- the [EMB-DOGE] TemplateBuilder
// UNDERFILL gate on a clean template (contabo v36 cutover CODE gate (a);
// rides share_test).
//
// History: the live journal 2026-07-25 had 24 priced and 11 unpriced txs
// (5298 of 105766 B selected). A Pass 2 then packed the unpriced txs with
// fee=null to fill the template. Unpriced meant an input outside a partial
// (accrual) UTXO view, so Pass 2 packed txs nothing showed to spend unspent
// coins: a premature coinbase spend, a spend of a missing coin, every tx when
// there was no view at all (DESIGN doge-underfill §2.2).
//
// Now the view is the DOGE set built from genesis: an unpriced tx is an
// orphan (it waits outside the pool) or invalid (refused at admission).
// Same 35-tx fixture: 24 txs spend coins of the set; 6 spend coins nobody
// has (orphans) and 5 spend coinbases 10 blocks deep (premature: refused).
// The template carries the 24 priced txs and nothing else, and the guard
// does not trip: the pool's bytes are the priced backlog only.
// ---------------------------------------------------------------------------
#include "doge_utxo_lane_harness.hpp"

namespace {

constexpr int      KNOWN      = 24;
constexpr int      ORPHANS    = 6;
constexpr int      IMMATURE   = 5;
constexpr int      UNKNOWN    = ORPHANS + IMMATURE;
constexpr int      TOTAL      = KNOWN + UNKNOWN;   // 35, matching the live journal
constexpr uint32_t BIG_WEIGHT = 4000000u;
constexpr uint32_t TIP        = 5'000'001;

uint256 tag_hash(uint8_t kind, uint32_t i)
{
    uint256 h;
    h.data()[0] = kind;
    h.data()[1] = static_cast<uint8_t>(i);
    h.data()[2] = static_cast<uint8_t>(i >> 8);
    h.data()[31] = 0x5d;
    return h;
}

MutableTransaction pay_from(const uint256& prev, int64_t value)
{
    MutableTransaction tx = spend(prev, 0, value, 0x40);
    tx.vin[0].scriptSig.m_data.assign(107, 0x30);  // ~ a signature and a key
    return tx;
}

/// A DOGE set built from genesis, complete at TIP, holding the coins the
/// priced txs spend and the coinbases the premature ones spend.
struct Fixture {
    TempDb t;
    DogeTip tip{DogeTip::header_at(TIP), TIP};
    Mempool pool{core::coin::DOGE_LIMITS};
    std::vector<MutableTransaction> txs;
    uint64_t known_fee_sum{0};

    Fixture()
    {
        core::coin::UTXOViewDB::ChangeMap coins;
        for (int i = 0; i < KNOWN; ++i)
            coins[Outpoint(tag_hash(0xa0, i), 0)] = coin_of(1'000'000'000LL, TIP - 500, /*coinbase=*/false);
        for (int i = 0; i < IMMATURE; ++i)
            coins[Outpoint(tag_hash(0xc0, i), 0)] = coin_of(DOGE_SUBSIDY, TIP - 10, /*coinbase=*/true);
        EXPECT_TRUE(t.db->write_batch(coins, tip.hash(), TIP));
        core::coin::SyncState s;
        s.anchor_height = 0;
        s.strict = 1;
        s.synced = 1;
        EXPECT_TRUE(t.cache->set_sync_state(s));
        EXPECT_TRUE(t.cache->complete(TIP));

        pool.set_utxo(t.cache.get());
        pool.set_tip_height(TIP);
        for (int i = 0; i < TOTAL; ++i) {
            if (i < KNOWN) {
                const int64_t fee = 100000 + i;
                txs.push_back(pay_from(tag_hash(0xa0, i), 1'000'000'000LL - fee));
                known_fee_sum += static_cast<uint64_t>(fee);
            } else if (i < KNOWN + ORPHANS) {
                txs.push_back(pay_from(tag_hash(0xb0, i), 500'000'000LL));  // nobody has this coin
            } else {
                txs.push_back(pay_from(tag_hash(0xc0, i - KNOWN - ORPHANS), DOGE_SUBSIDY - 1'000'000));
            }
        }
    }

    void admit_all()
    {
        for (const auto& tx : txs)
            pool.admit(tx, t.cache.get());
        tip.clean(pool);
    }
};

} // namespace

// The 24 priced txs fill the template; the 11 never enter the pool (6
// orphans, 5 refused), so the template carries no unpriced tx and the guard
// sees no backlog.
TEST(DogeTemplateUnderfill, PricedTxsFillTheTemplateUnpricedNeverDo)
{
    Fixture f;
    f.admit_all();
    EXPECT_EQ(f.pool.size(), static_cast<size_t>(KNOWN));
    EXPECT_EQ(f.pool.orphan_count(), static_cast<size_t>(ORPHANS));
    const auto rej = f.pool.reject_stats_json()["rejected"];
    EXPECT_EQ(rej["inputs_invalid"], IMMATURE);
    EXPECT_EQ(rej["missing_inputs"], ORPHANS);

    const auto t = f.tip.build(f.pool);
    EXPECT_FALSE(t.contains("degraded"));
    const auto& sel = t["transactions"];
    ASSERT_EQ(sel.size(), static_cast<size_t>(KNOWN));
    uint64_t selected_bytes = 0;
    for (const auto& e : sel) {
        ASSERT_TRUE(e["fee"].is_number()) << "an unpriced tx (fee=null) reached the template";
        selected_bytes += e["data"].get<std::string>().size() / 2;
    }
    EXPECT_EQ(t["coinbasevalue"].get<int64_t>(), f.tip.subsidy() + static_cast<int64_t>(f.known_fee_sum));
    EXPECT_EQ(f.pool.byte_size(), selected_bytes) << "the pool holds priced txs only";
    EXPECT_FALSE(doge::coin::TemplateBuilder::underfill(selected_bytes, f.pool.byte_size(), f.pool.total_fees()));
}

// Unpriced txs forced past admission (add_tx_unchecked) are still never
// selected: selection takes priced txs only, and the fees and coinbase value
// stay those of the priced ones.
TEST(DogeTemplateUnderfill, UnpricedTxsPastAdmissionAreNeverSelected)
{
    Fixture f;
    for (int i = 0; i < TOTAL; ++i)
        EXPECT_TRUE(f.pool.add_tx_unchecked(f.txs[i], f.t.cache.get()));
    EXPECT_EQ(f.pool.size(), static_cast<size_t>(TOTAL));
    f.tip.clean(f.pool);

    auto [selected, total_fees] = f.pool.get_sorted_txs_with_fees(BIG_WEIGHT);
    EXPECT_EQ(selected.size(), static_cast<size_t>(KNOWN));
    EXPECT_EQ(total_fees, f.known_fee_sum);
    for (const auto& s : selected)
        EXPECT_TRUE(s.fee_known);
    const auto t = f.tip.build(f.pool);
    EXPECT_EQ(t["transactions"].size(), static_cast<size_t>(KNOWN));

    // The next block's pass moves them out: orphans to the orphan set, the
    // premature spends out of the pool.
    f.pool.recompute_unknown_fees(f.t.cache.get());
    EXPECT_EQ(f.pool.size(), static_cast<size_t>(KNOWN));
    EXPECT_EQ(f.pool.orphan_count(), static_cast<size_t>(ORPHANS));
}

// The selection honours the weight budget.
TEST(DogeTemplateUnderfill, SelectionRespectsWeightBudget)
{
    Fixture f;
    f.admit_all();
    auto [full, full_fees] = f.pool.get_sorted_txs_with_fees(BIG_WEIGHT);
    (void)full_fees;
    ASSERT_EQ(full.size(), static_cast<size_t>(KNOWN));
    auto [capped, capped_fees] = f.pool.get_sorted_txs_with_fees(1u);
    (void)capped_fees;
    EXPECT_TRUE(capped.empty());
}
