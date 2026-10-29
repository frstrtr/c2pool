// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The full DOGE UTXO set's wiring rules (rides share_test): what main_ltc's
// DOGE handlers decide through doge::coin::UtxoFullState, and the mempool
// guards they rely on.
//   - EveryCopyOfADeepBodyIsPlaced / ImmatureSpendAfterDuplicateDeepBodyIs-
//     NeverSelected (VERIFY M2): a body below the header checkpoint has no
//     header; every copy of it (a stalled height is asked from every peer) is
//     placed by the full lane's request and goes to the full lane only. A
//     copy that lost its height reached the accrual path as height 0 and set
//     the pool's tip to 0: every coinbase mature, a premature spend priced
//     and selected, the DOGE block lost. The pool ignores a tip of 0, its
//     selection and revalidation check maturity again.
//   - StartLiveOnlyNearTheTip, ScheduleReadyPastTheCheckpoint (S4): a restart
//     far behind the tip (or mid-rebuild) lets the accrual set price while
//     the full set catches up; a set past the checkpoint needs no schedule.
//   - EveryCompletionRepricesThePool (S5): the swap runs on every completion
//     (after a rebuild too), not once per process.
// ---------------------------------------------------------------------------
#include "doge_utxo_lane_harness.hpp"

#include <impl/doge/coin/utxo_full_state.hpp>

namespace {

using doge::coin::UtxoFullState;

constexpr uint32_t TIP = 5'000'001;
constexpr uint32_t WEIGHT = doge::coin::TemplateBuilder::MAX_BLOCK_WEIGHT
                          - doge::coin::TemplateBuilder::COINBASE_RESERVE;

uint256 tag(uint8_t a, uint8_t b)
{
    uint256 h;
    h.data()[0] = a;
    h.data()[1] = b;
    h.data()[31] = 0x7c;
    return h;
}

bool selected(const Mempool& pool, const uint256& txid)
{
    for (const auto& s : pool.get_sorted_txs_with_fees(WEIGHT).first)
        if (compute_txid(s.tx) == txid)
            return true;
    return false;
}

} // namespace

TEST(DogeUtxoFullWiring, EveryCopyOfADeepBodyIsPlaced)
{
    UtxoFullState st;
    const uint256 deep = tag(0x01, 1), at_tip = tag(0x01, 2), unknown = tag(0x01, 3);
    st.note_request(deep, 1000);
    st.note_request(at_tip, TIP);
    for (int copy = 0; copy < 20; ++copy) {
        const auto p = st.place(deep, 0, TIP);
        EXPECT_EQ(p.height, 1000u) << "copy " << copy << " lost its height";
        EXPECT_TRUE(p.full_only) << "copy " << copy << " reached the accrual path";
    }
    const auto t = st.place(at_tip, TIP, TIP);
    EXPECT_EQ(t.height, TIP);
    EXPECT_FALSE(t.full_only) << "the tip's body serves both lanes";
    const auto u = st.place(unknown, 0, TIP);
    EXPECT_EQ(u.height, 0u);
    EXPECT_FALSE(u.full_only);
}

TEST(DogeUtxoFullWiring, ImmatureSpendAfterDuplicateDeepBodyIsNeverSelected)
{
    // A view with a coinbase 50 blocks deep (maturity 240), the pool at TIP.
    core::coin::UTXOViewCache view(nullptr);
    const Outpoint cb(tag(0x02, 1), 0);
    view.add_coin(cb, coin_of(DOGE_SUBSIDY, TIP - 50, /*coinbase=*/true));
    Mempool pool(core::coin::DOGE_LIMITS);
    pool.set_utxo(&view);
    pool.set_tip_height(TIP);

    // A duplicate copy of a deep body: placed, full lane only. Even a caller
    // that could not place it and passed height 0 leaves the tip alone.
    UtxoFullState st;
    st.note_request(tag(0x02, 9), 1234);
    (void)st.place(tag(0x02, 9), 0, TIP);
    ASSERT_TRUE(st.place(tag(0x02, 9), 0, TIP).full_only);
    pool.set_tip_height(0);
    EXPECT_EQ(pool.tip_height(), TIP) << "a tip of 0 turns every maturity check off";

    // A peer relays a spend of that coinbase.
    const auto tx = spend(cb.txid, 0, DOGE_SUBSIDY - 100000000, 0x22);
    const uint256 txid = txid_of(tx);
    const auto r = pool.admit(tx, &view);
    EXPECT_TRUE(r.has_value()) << "a premature coinbase spend was admitted";
    EXPECT_FALSE(selected(pool, txid));

    // Priced anyway (as a wrong tip once let it be): selection refuses the
    // immature input, and revalidation takes its price away.
    pool.add_tx_unchecked(tx, &view);
    pool.set_tx_fee(txid, 100000000);
    EXPECT_FALSE(selected(pool, txid)) << "a premature coinbase spend reached the template";
    pool.revalidate_inputs(&view);
    const auto e = pool.get_entry(txid);
    ASSERT_TRUE(e.has_value());
    EXPECT_FALSE(e->fee_known);
}

TEST(DogeUtxoFullWiring, StartLiveOnlyNearTheTip)
{
    core::coin::SyncState s;
    s.anchor_height = 0;
    s.strict = 1;
    s.synced = 1;
    EXPECT_TRUE(UtxoFullState::start_live(s, TIP, TIP));
    EXPECT_TRUE(UtxoFullState::start_live(s, TIP - 1440, TIP)) << "a day behind: catches up in minutes";
    EXPECT_FALSE(UtxoFullState::start_live(s, TIP - 1441, TIP)) << "further behind: the accrual set serves";
    EXPECT_FALSE(UtxoFullState::start_live(s, 1000, TIP)) << "a rebuild cut short by a restart";
    s.synced = 0;
    EXPECT_FALSE(UtxoFullState::start_live(s, TIP, TIP)) << "never synced";
    s.synced = 1;
    s.anchor_height = 900;
    EXPECT_FALSE(UtxoFullState::start_live(s, TIP, TIP)) << "not built from genesis";
    EXPECT_FALSE(UtxoFullState::start_live(core::coin::SyncState{}, TIP, TIP)) << "an accrual DB";
}

TEST(DogeUtxoFullWiring, ScheduleReadyPastTheCheckpoint)
{
    constexpr uint32_t ROOT = 6'160'000;
    EXPECT_TRUE(UtxoFullState::schedule_ready_for(false, 0, 0)) << "a header chain from genesis";
    EXPECT_TRUE(UtxoFullState::schedule_ready_for(true, ROOT, 0));
    EXPECT_FALSE(UtxoFullState::schedule_ready_for(false, ROOT, ROOT - 1));
    EXPECT_TRUE(UtxoFullState::schedule_ready_for(false, ROOT, ROOT)) << "a header DB reset under a synced set";
}

TEST(DogeUtxoFullWiring, EveryCompletionRepricesThePool)
{
    TempDb t;
    const DogeTip tip(DogeTip::header_at(TIP), TIP);
    const Outpoint x(tag(0x05, 1), 0);
    ASSERT_TRUE(t.db->write_batch({{x, coin_of(10'000'000'000LL, TIP - 100, false)}}, tip.hash(), TIP));
    core::coin::SyncState s;
    s.anchor_height = 0;
    s.strict = 1;
    s.synced = 1;
    ASSERT_TRUE(t.cache->set_sync_state(s));

    core::coin::UTXOViewCache accrual(nullptr);   // knows nothing of x
    Mempool pool(core::coin::DOGE_LIMITS);
    pool.set_utxo(&accrual);
    pool.set_tip_height(TIP);
    const auto tx = spend(x.txid, 0, 9'900'000'000LL, 0x55);
    const uint256 txid = txid_of(tx);
    EXPECT_FALSE(pool.admit(tx, &accrual).has_value());
    EXPECT_FALSE(pool.get_entry(txid)->fee_known);

    UtxoFullState st;
    auto a = st.adopt(pool, t.cache.get(), t.db.get());
    EXPECT_TRUE(a.first);
    EXPECT_EQ(pool.utxo(), t.cache.get());
    EXPECT_TRUE(pool.get_entry(txid)->fee_known) << "priced against the full set";
    EXPECT_EQ(st.explorer_db.load(), t.db.get());

    // A rebuild: the pool loses its prices (host.wiped), then the set
    // completes again: the swap runs again.
    pool.requarantine_all();
    EXPECT_FALSE(pool.get_entry(txid)->fee_known);
    a = st.adopt(pool, t.cache.get(), t.db.get());
    EXPECT_FALSE(a.first) << "the accrual lane left the feed once";
    EXPECT_TRUE(pool.get_entry(txid)->fee_known) << "not re-priced after the second completion";
    EXPECT_EQ(st.adoptions.load(), 2u);
}
