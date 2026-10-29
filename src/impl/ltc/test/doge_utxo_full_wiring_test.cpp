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
//   - RecentBodiesServeBothLanes (VERIFY2 S-D): a body both lanes asked for
//     within the accrual lane's last 1,440 blocks reaches both.
//   - QueueToTheFullSetIsBounded (S-A, VERIFY3 S4): unplaceable bodies are
//     not queued while the full set is not live; a queued hash is not queued
//     again; while the queue holds its bound only the header chain's tip
//     itself passes. UnsolicitedPlaceableBodiesAreBounded: the verifier's
//     probe (4,096 copies of a recent body).
//   - InvAsksTheAnnouncingPeerOnly (VERIFY3 S3): the inv path's getheaders.
//   - HeaderSyncAsksAsCoreDoes (S-B): follow-up getheaders only to the peer
//     that sent new headers, none for a batch with nothing new; the periodic
//     poll asks one peer while catching up, every peer once synced.
// ---------------------------------------------------------------------------
#include "doge_utxo_lane_harness.hpp"

#include <impl/doge/coin/header_sync.hpp>
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

// The S4 restart (the full set > 1,440 behind, the accrual set bootstrapping
// the last 1,440 blocks) and the IBD's last blocks: both lanes ask for the
// same recent bodies. Before, every copy was the full lane's alone and the
// accrual set never filled (the mining gate stayed closed until adoption).
TEST(DogeUtxoFullWiring, RecentBodiesServeBothLanes)
{
    UtxoFullState st;
    const uint256 recent = tag(0x06, 1), edge = tag(0x06, 2), deep = tag(0x06, 3);
    st.note_request(recent, TIP - 100);
    st.note_request(edge, TIP - 1440);
    st.note_request(deep, TIP - 1441);
    EXPECT_FALSE(st.place(recent, TIP - 100, TIP).full_only) << "a body the accrual lane wants too";
    EXPECT_FALSE(st.place(edge, TIP - 1440, TIP).full_only);
    EXPECT_TRUE(st.place(deep, 0, TIP).full_only);
    EXPECT_EQ(st.place(deep, 0, TIP).height, TIP - 1441);
}

TEST(DogeUtxoFullWiring, QueueToTheFullSetIsBounded)
{
    UtxoFullState st;
    UtxoFullState::Placement unplaced;  // height 0
    unplaced.hash = tag(0x08, 1);
    EXPECT_FALSE(st.enqueue(unplaced, 1000)) << "nothing can use it while the full set is not live";
    st.live.store(true);
    EXPECT_TRUE(st.enqueue(unplaced, 1000)) << "live: its header may come from it";
    EXPECT_FALSE(st.enqueue(unplaced, 1000)) << "a copy of a queued body: one slot";
    st.dequeued(unplaced.hash, 1000);
    EXPECT_EQ(st.queued_bytes.load(), 0u);
    constexpr uint64_t MB = 1024 * 1024;
    uint64_t queued = 0;
    std::vector<uint256> hashes;
    for (uint32_t n = 0; n < 400; ++n) {
        UtxoFullState::Placement deep;
        deep.height = 1000 + n;
        deep.full_only = true;
        deep.hash = tag(0x09, static_cast<uint8_t>(n & 0xFF));
        deep.hash.data()[2] = static_cast<uint8_t>(n >> 8);
        if (!st.enqueue(deep, MB))
            break;
        hashes.push_back(deep.hash);
        queued += MB;
    }
    EXPECT_LE(queued, UtxoFullState::QUEUE_BYTES_MAX);
    EXPECT_GT(queued, UtxoFullState::QUEUE_BYTES_MAX - MB);
    // The queue is full: a recent body (both lanes') is dropped too; only
    // the header chain's tip itself passes, once.
    const auto recent = st.place(tag(0x0a, 1), TIP - 1, TIP, tag(0x0a, 2));
    EXPECT_FALSE(recent.tip);
    EXPECT_FALSE(st.enqueue(recent, MB)) << "a full queue takes no body but the tip";
    const auto tip = st.place(tag(0x0a, 2), TIP, TIP, tag(0x0a, 2));
    EXPECT_TRUE(tip.tip);
    EXPECT_TRUE(st.enqueue(tip, MB)) << "the tip's body always passes";
    EXPECT_FALSE(st.enqueue(tip, MB)) << "but a copy of it does not";
    for (const auto& h : hashes)
        st.dequeued(h, MB);
    st.dequeued(tip.hash, MB);
    EXPECT_EQ(st.queued_bytes.load(), 0u);
    EXPECT_TRUE(st.enqueue(recent, MB)) << "room again once the full set's thread took them";
}

TEST(DogeUtxoFullWiring, HeaderSyncAsksAsCoreDoes)
{
    using doge::coin::HeadersFollowUp;
    using doge::coin::HeadersPoll;
    EXPECT_EQ(doge::coin::headers_follow_up(0), HeadersFollowUp::None) << "a batch with nothing new asks nothing";
    EXPECT_EQ(doge::coin::headers_follow_up(1), HeadersFollowUp::AskSender);
    EXPECT_EQ(doge::coin::headers_follow_up(2000), HeadersFollowUp::AskSender);
    EXPECT_EQ(doge::coin::headers_poll(false), HeadersPoll::OnePeer) << "catching up: one peer per tick";
    EXPECT_EQ(doge::coin::headers_poll(true), HeadersPoll::EveryPeer) << "synced: the tip's headers from every peer";
}

// VERIFY3 S3: a block announcement asks the announcing peer only, at once;
// not while it has a getheaders unanswered (Core's 2 min); while the chain
// catches up one announcer per new block, once synced every announcer.
TEST(DogeUtxoFullWiring, InvAsksTheAnnouncingPeerOnly)
{
    using Asks = doge::coin::HeaderAsks;
    Asks asks;
    const auto t = Asks::Clock::time_point{} + std::chrono::hours(1);
    const uint256 x = tag(0x0b, 1), y = tag(0x0b, 2), z = tag(0x0b, 3);
    // Catching up.
    EXPECT_TRUE(asks.on_inv("a", x, false, t)) << "the first announcer, at once";
    EXPECT_FALSE(asks.on_inv("b", x, false, t)) << "one announcer per block while catching up";
    EXPECT_FALSE(asks.on_inv("a", y, false, t)) << "a has a getheaders unanswered";
    EXPECT_TRUE(asks.on_inv("b", y, false, t)) << "a new block brings one more peer";
    asks.answered("a");
    EXPECT_TRUE(asks.on_inv("a", z, false, t)) << "answered: asked again";
    EXPECT_TRUE(asks.on_inv("b", tag(0x0b, 4), false, t + Asks::RESPONSE_TIME))
        << "an answer that never came frees the peer after RESPONSE_TIME";
    asks.sent("c", t);
    EXPECT_FALSE(asks.on_inv("c", tag(0x0b, 5), false, t)) << "a poll or follow-up getheaders counts";
    // Synced: every announcer of a block the chain lacks, at once.
    Asks synced;
    const uint256 w = tag(0x0b, 6);
    EXPECT_TRUE(synced.on_inv("a", w, true, t));
    EXPECT_TRUE(synced.on_inv("b", w, true, t)) << "synced: the tip's headers from every announcer";
    EXPECT_FALSE(synced.on_inv("b", w, true, t)) << "not twice while unanswered";
    EXPECT_FALSE(synced.on_inv("", w, true, t)) << "no peer: nothing";
}

// V3-S4: a peer streaming copies of a recent block the full lane never asked
// for (placeable, not full_only) is bounded: one queue slot per hash.
TEST(DogeUtxoFullWiring, UnsolicitedPlaceableBodiesAreBounded)
{
    UtxoFullState st;
    st.live.store(true);
    const UtxoFullState::Placement recent = st.place(tag(0x07, 1), TIP - 100, TIP);
    ASSERT_EQ(recent.height, TIP - 100);
    ASSERT_FALSE(recent.full_only);
    constexpr uint64_t MB = 1024 * 1024;
    uint64_t queued = 0;
    int n = 0;
    while (n < 4096 && st.enqueue(recent, MB)) {
        queued += MB;
        ++n;
    }
    EXPECT_LE(queued, UtxoFullState::QUEUE_BYTES_MAX + MB)
        << "a peer streaming copies of a recent block is never dropped: " << queued / MB
        << " MB queued, " << st.queue_dropped.load() << " dropped";
}
