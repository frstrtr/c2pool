// SPDX-License-Identifier: AGPL-3.0-or-later
/// The cold-start Bootstrap of a partial UTXO view (ltc/coin/utxo_order.hpp
/// cold_start_plan / cold_start_rearm / fill_ask, with
/// core::coin::BlockDownload), FRESH-NODE §2.2 / §6.2 (LTC). The helpers are
/// driven in the order main_ltc's 1-s cold-start tick and full-block handler
/// call them; peers and the clock are faked.

#include <gtest/gtest.h>

#include <core/coin/block_bootstrapper.hpp>
#include <core/coin/block_download.hpp>
#include <impl/ltc/coin/utxo_order.hpp>
#include <impl/ltc/coin/cold_start_tick.hpp>

#include <algorithm>
#include <chrono>
#include <map>
#include <string>
#include <vector>

using core::coin::BlockBootstrapState;
using core::coin::BlockDownload;
using ltc::coin::ColdStart;

namespace {

using Clock = std::chrono::steady_clock;
using Fill = BlockBootstrapState<int>;

constexpr uint32_t LTC_COLD_BLOCKS = 4320;        // 5 * 15 * 8640 / 150 (the score backlog)
constexpr uint32_t LTC_CHECKPOINT = 3088000;       // the fresh run's header checkpoint
constexpr uint32_t LTC_TIP = 3204244;              // the network tip then (116 k above it)

struct FakePeers {
    std::vector<std::string> peers;
    std::map<uint32_t, std::vector<std::string>> asked;  // height -> peers asked
    std::vector<uint32_t> all;                           // heights asked of every peer
    Clock::time_point t = Clock::time_point{} + std::chrono::hours(1);

    explicit FakePeers(size_t n)
    {
        for (size_t i = 0; i < n; ++i)
            peers.push_back("peer" + std::to_string(i));
    }

    BlockDownload::Host host()
    {
        BlockDownload::Host h;
        h.peers = [this]() { return peers; };
        h.request_from = [this](const std::string& p, uint32_t height) {
            asked[height].push_back(p);
            return true;
        };
        h.request_all = [this](uint32_t height) { all.push_back(height); };
        h.now = [this]() { return t; };
        return h;
    }
};

/// main_ltc's tick: plan, then arm.
bool arm_from_plan(Fill& f, uint32_t blocks, bool synced, uint32_t tip, uint32_t best)
{
    const ColdStart p = ltc::coin::cold_start_plan(blocks, synced, tip, best);
    if (p.action != ColdStart::Action::Arm)
        return false;
    ltc::coin::cold_start_arm(f, p.from, p.to);
    return true;
}

} // namespace

// The header chain catches up from its checkpoint in 2,000-header steps: no
// fill while it is not synced; at the synced tip T the fill is the last 4,320
// heights [T-4319, T]. Before, the first block above keep armed 289 blocks at
// the checkpoint-era tip and the 116 k blocks to the real tip extended it
// (114,549 at 10:22Z in the fresh run).
TEST(LtcColdStart, TheColdStartBootstrapArmsAtTheSyncedTip)
{
    Fill f;
    uint32_t armed_at = 0, armed_total = 0;
    for (uint32_t tip = LTC_CHECKPOINT + 2000; tip < LTC_TIP; tip += 2000) {
        if (!f.active) {
            if (arm_from_plan(f, LTC_COLD_BLOCKS, false, tip, 0)) {
                armed_at = tip;
                armed_total = f.total;
            }
        } else {
            ltc::coin::ordered_extend(f, tip);
        }
    }
    EXPECT_EQ(armed_at, 0u) << "armed " << armed_total << " blocks at tip " << armed_at
                            << " while the header chain was not synced";
    if (!f.active)
        ASSERT_TRUE(arm_from_plan(f, LTC_COLD_BLOCKS, true, LTC_TIP, 0));
    else
        ltc::coin::ordered_extend(f, LTC_TIP);
    EXPECT_EQ(f.next_height, LTC_TIP - 4319);
    EXPECT_EQ(f.end_height, LTC_TIP);
    EXPECT_EQ(f.total, 4320u);
    EXPECT_LE(f.total, LTC_COLD_BLOCKS + f.window);
}

// Where the synced cold start starts: an empty set at the window's first
// height; a set within the window catches up from best + 1; a set further
// behind jumps (the one deliberate jump); a set at the tip needs no fill.
TEST(LtcColdStart, TheColdStartPlanByUtxoBest)
{
    const uint32_t T = LTC_TIP;
    ColdStart p = ltc::coin::cold_start_plan(LTC_COLD_BLOCKS, true, T, 0);
    ASSERT_EQ(p.action, ColdStart::Action::Arm);
    EXPECT_EQ(p.from, T - 4319);
    EXPECT_EQ(p.to, T);
    EXPECT_EQ(p.jump_from, 0u);

    p = ltc::coin::cold_start_plan(LTC_COLD_BLOCKS, true, T, T - 100);
    ASSERT_EQ(p.action, ColdStart::Action::Arm);
    EXPECT_EQ(p.from, T - 99);
    EXPECT_EQ(p.jump_from, 0u);

    p = ltc::coin::cold_start_plan(LTC_COLD_BLOCKS, true, T, T - 10000);
    ASSERT_EQ(p.action, ColdStart::Action::Arm);
    EXPECT_EQ(p.from, T - 4319);
    EXPECT_EQ(p.jump_from, T - 4319);

    // One block behind (a restart between a header and its body): a
    // one-block fill for the tip, not "warm" (nothing else asks for it).
    p = ltc::coin::cold_start_plan(LTC_COLD_BLOCKS, true, T, T - 1);
    ASSERT_EQ(p.action, ColdStart::Action::Arm);
    EXPECT_EQ(p.from, T);
    EXPECT_EQ(p.to, T);
    EXPECT_EQ(p.jump_from, 0u);
    EXPECT_EQ(ltc::coin::cold_start_plan(LTC_COLD_BLOCKS, true, T, T).action, ColdStart::Action::Warm);
    EXPECT_EQ(ltc::coin::cold_start_plan(LTC_COLD_BLOCKS, false, T, T - 100).action, ColdStart::Action::Wait);
}

// A Bootstrap that falls behind (nothing arrives while the tip moves 116 k):
// it is armed again at the tip, so the range still to fetch never exceeds
// 4,320 + its window.
TEST(LtcColdStart, TheColdStartBootstrapNeverRunsFarBehindTheTip)
{
    Fill f;
    ASSERT_TRUE(arm_from_plan(f, LTC_COLD_BLOCKS, true, LTC_TIP, 0));
    uint32_t rearms = 0;
    uint64_t widest = 0;
    for (uint32_t tip = LTC_TIP + 1; tip <= LTC_TIP + 116000; ++tip) {
        if (auto r = ltc::coin::cold_start_rearm(f, tip, LTC_COLD_BLOCKS)) {
            ltc::coin::cold_start_arm(f, r->first, r->second);
            ++rearms;
        } else {
            ltc::coin::ordered_extend(f, tip);
        }
        widest = std::max<uint64_t>(widest, uint64_t(f.end_height) - f.next_height + 1);
    }
    EXPECT_GT(rearms, 0u);
    EXPECT_LE(widest, uint64_t(LTC_COLD_BLOCKS) + f.window + 1);
    EXPECT_LE(f.total, LTC_COLD_BLOCKS + f.window + 1);
    EXPECT_EQ(f.end_height, LTC_TIP + 116000);
}

// The cold start asks one peer per height (FillAsk::Download): 4,320 heights
// from 20 peers that answer, each asked once, no all-peer request; a height
// whose peer is silent goes to another peer on the fill's stall timer, and to
// every peer only on its third stall. Before, every height went to all 20
// peers (113,551 bodies for 52,062 heights).
TEST(LtcColdStart, TheColdStartBootstrapAsksOnePeerPerBlock)
{
    EXPECT_EQ(ltc::coin::fill_ask("Bootstrap"), ltc::coin::FillAsk::Download);
    EXPECT_EQ(ltc::coin::fill_ask("UTXO gap fill"), ltc::coin::FillAsk::Targeted);

    FakePeers net(20);
    BlockDownload dl(net.host(), "[test]");
    Fill f;
    ASSERT_TRUE(arm_from_plan(f, LTC_COLD_BLOCKS, true, LTC_TIP, 0));
    dl.refill(f);
    // Every peer answers at once: deliver what was asked, drain, refill.
    for (int round = 0; round < 10000 && f.active; ++round) {
        std::vector<uint32_t> out;
        for (uint32_t h = f.next_height; h < f.next_height + f.window && h <= f.end_height; ++h)
            if (!dl.asked_peer(h).empty())
                out.push_back(h);
        for (uint32_t h : out) {
            dl.delivered(h, dl.asked_peer(h));
            ltc::coin::ordered_buffer(f, h, int(h), uint256());
        }
        const auto drained = ltc::coin::ordered_drain(
            f, [](int, const uint256&, uint32_t) { return ltc::coin::ConnectCheck::Ok; },
            [](int, const uint256&, uint32_t) {});
        dl.drained(drained.connected);
        if (ltc::coin::ordered_done(f))
            f.active = false;
        else
            dl.refill(f);
    }
    ASSERT_FALSE(f.active);
    EXPECT_EQ(f.processed, 4320u);
    EXPECT_TRUE(net.all.empty()) << net.all.size() << " heights asked of every peer";
    size_t max_asks = 0;
    for (const auto& [h, peers] : net.asked)
        max_asks = std::max(max_asks, peers.size());
    EXPECT_EQ(net.asked.size(), 4320u);
    EXPECT_EQ(max_asks, 1u);

    // A silent peer holds a height: another peer twice, every peer the third time.
    FakePeers net2(20);
    BlockDownload dl2(net2.host(), "[test]");
    Fill g;
    ASSERT_TRUE(arm_from_plan(g, LTC_COLD_BLOCKS, true, LTC_TIP, 0));
    dl2.refill(g);
    const uint32_t h0 = g.next_height;
    EXPECT_FALSE(dl2.on_fill_stall(g, h0));
    EXPECT_FALSE(dl2.on_fill_stall(g, h0));
    EXPECT_TRUE(net2.all.empty());
    EXPECT_TRUE(dl2.on_fill_stall(g, h0));
    EXPECT_EQ(net2.all, std::vector<uint32_t>{h0});
    EXPECT_EQ(net2.asked[h0].size(), 3u);
}

// ─── The DOGE accrual set's cold start (FRESH-NODE §2.3 / §6.3) ──────────────

namespace {

constexpr uint32_t DOGE_COLD_BLOCKS = 1441;          // [tip - 1440, tip] (keep + 1)
constexpr uint32_t DOGE_FIRST_BATCH_TIP = 6162000;   // the tip chain's first batch above its checkpoint
constexpr uint32_t DOGE_TIP = 6436623;               // the real tip then (274 k above it)
constexpr size_t   MB = 1024 * 1024;

} // namespace

// The first body above keep arrives while the tip chain is 274 k blocks behind
// (tip age > 24 h): no fill. Synced at T: [T-1440, T], 1,441 blocks. Before, it
// armed at that first batch's tip ([6,160,560..6,162,000]).
TEST(DogeAccrualColdStart, TheAccrualBootstrapWaitsForTheSyncedChain)
{
    Fill f;
    EXPECT_FALSE(arm_from_plan(f, DOGE_COLD_BLOCKS, false, DOGE_FIRST_BATCH_TIP, 0))
        << "armed at [" << f.next_height << ".." << f.end_height << "] with the tip chain unsynced";
    EXPECT_FALSE(f.active);
    if (f.active)
        f = Fill{};
    ASSERT_TRUE(arm_from_plan(f, DOGE_COLD_BLOCKS, true, DOGE_TIP, 0));
    EXPECT_EQ(f.next_height, DOGE_TIP - 1440);
    EXPECT_EQ(f.end_height, DOGE_TIP);
    EXPECT_EQ(f.total, 1441u);
}

// 276 k best-chain bodies after arming while nothing drains (the fresh run's
// 37 blocks a minute against 60 minted, at the extreme): the fill is armed
// again at tip - keep, never more than keep + its window deep; bodies past the
// window are not kept. Before, every body extended it: total 276 k.
TEST(DogeAccrualColdStart, TheAccrualBootstrapNeverGrowsPastKeep)
{
    FakePeers net(20);
    BlockDownload dl(net.host(), "[test]");
    Fill f;
    ASSERT_TRUE(arm_from_plan(f, DOGE_COLD_BLOCKS, true, DOGE_TIP, 0));
    uint32_t rearms = 0;
    uint32_t widest = f.total;
    for (uint32_t tip = DOGE_TIP + 1; tip <= DOGE_TIP + 276000; ++tip) {
        // The tick: arm again when too far behind, else the tip joins the range.
        if (auto r = ltc::coin::cold_start_rearm(f, tip, DOGE_COLD_BLOCKS)) {
            ltc::coin::cold_start_arm(f, r->first, r->second);
            dl.reset();
            ++rearms;
        }
        // The tip's body arrives.
        ltc::coin::ordered_buffer_bounded(f, dl, tip, int(tip), uint256(), 30000);
        widest = std::max(widest, f.total);
    }
    EXPECT_GT(rearms, 0u);
    EXPECT_LE(widest, DOGE_COLD_BLOCKS + f.window + 1) << "the Bootstrap grew to " << widest << " blocks";
    EXPECT_LE(f.buffer.size(), f.window);
}

// A new tip from peer A: one getdata, to A. A gone: one other peer; no peer
// one at a time: every peer. Nothing during the initial header sync or while
// the cold start runs. Before, every peer was asked for every new tip.
TEST(DogeAccrualColdStart, ATipAnnouncementAsksTheAnnouncer)
{
    using ltc::coin::TipBodyAsk;
    std::vector<std::string> from;
    int one = 0, all = 0;
    auto ask = [&](bool synced, bool cold_start_runs, const std::string& announcer,
                   bool from_ok, bool one_ok) {
        return ltc::coin::ask_tip_body(
            synced, cold_start_runs, announcer,
            [&](const std::string& p) { from.push_back(p); return from_ok; },
            [&]() { ++one; return one_ok; },
            [&]() { ++all; });
    };
    EXPECT_EQ(ask(true, false, "A", true, true), TipBodyAsk::Announcer);
    EXPECT_EQ(from, std::vector<std::string>{"A"});
    EXPECT_EQ(one, 0);
    EXPECT_EQ(all, 0) << "every peer asked for a tip its announcer was asked for";

    from.clear();
    EXPECT_EQ(ask(true, false, "A", false, true), TipBodyAsk::OnePeer);
    EXPECT_EQ(one, 1);
    EXPECT_EQ(all, 0);
    EXPECT_EQ(ask(true, false, "", false, false), TipBodyAsk::EveryPeer);
    EXPECT_EQ(all, 1);

    one = all = 0;
    from.clear();
    EXPECT_EQ(ask(false, false, "A", true, true), TipBodyAsk::None);
    EXPECT_EQ(ask(true, true, "A", true, true), TipBodyAsk::None);
    EXPECT_TRUE(from.empty());
    EXPECT_EQ(one + all, 0);
}

// 300 MB of 1-MB bodies arrive ahead of a missing next height: with a wide
// window (the full lane's 1,024) the buffer stops at the 256 MB bound and the
// download asks nothing but the next height (window_waits); with the accrual
// window (16) bodies past it are not kept at all. Before, the accrual buffer
// took every body at or above its next height.
TEST(DogeAccrualColdStart, TheAccrualBufferIsBounded)
{
    FakePeers net(20);
    BlockDownload dl(net.host(), "[test]");
    Fill f;
    ASSERT_TRUE(arm_from_plan(f, DOGE_COLD_BLOCKS, true, DOGE_TIP, 0));
    f.window = 1024;
    for (uint32_t h = f.next_height + 1; h <= f.next_height + 300; ++h)
        ltc::coin::ordered_buffer_bounded(f, dl, h, int(h), uint256(), 1 * MB);
    EXPECT_LE(dl.buffer_bytes(), 256 * MB);
    EXPECT_LE(f.buffer.size(), 256u);
    dl.refill(f);
    EXPECT_GE(dl.stats().window_waits.load(), 1u);
    EXPECT_EQ(dl.in_flight(), 1u) << "only the next height";
    EXPECT_FALSE(dl.asked_peer(f.next_height).empty());

    FakePeers net2(20);
    BlockDownload dl2(net2.host(), "[test]");
    Fill g;
    ASSERT_TRUE(arm_from_plan(g, DOGE_COLD_BLOCKS, true, DOGE_TIP, 0));
    for (uint32_t h = g.next_height + 1; h <= g.next_height + 300; ++h)
        ltc::coin::ordered_buffer_bounded(g, dl2, h, int(h), uint256(), 1 * MB);
    EXPECT_LT(g.buffer.size(), g.window);
    EXPECT_LE(dl2.buffer_bytes(), g.window * MB);
}

// The cold start is decided on a synced AND caught-up header chain: the
// first synced tip of the fresh run was 46,016 s old (314 blocks short), and
// arming there re-armed the Bootstrap a second later. Caught up = tip under
// 2 h old, or synced for 60 s already (a network without a block for 2 h).
TEST(LtcColdStart, TheColdStartWaitsForTheCaughtUpChain)
{
    EXPECT_FALSE(ltc::coin::cold_start_ready(true, 46016, 0));
    EXPECT_FALSE(ltc::coin::cold_start_ready(true, 46016, 59));
    EXPECT_TRUE(ltc::coin::cold_start_ready(true, 46016, 60));
    EXPECT_TRUE(ltc::coin::cold_start_ready(true, 300, 0));
    EXPECT_FALSE(ltc::coin::cold_start_ready(false, 300, 600));

    // In the fresh run's sequence: synced at 3,204,000 (46,016 s old), then
    // the last batch to 3,204,314 (minutes old): one arm, at the real tip.
    Fill f;
    const bool ready0 = ltc::coin::cold_start_ready(true, 46016, 0);
    if (ready0)
        ASSERT_TRUE(arm_from_plan(f, LTC_COLD_BLOCKS, true, 3204000, 0));
    ASSERT_TRUE(ltc::coin::cold_start_ready(true, 120, 1));
    if (!f.active)
        ASSERT_TRUE(arm_from_plan(f, LTC_COLD_BLOCKS, true, 3204314, 0));
    EXPECT_FALSE(ltc::coin::cold_start_rearm(f, 3204314, LTC_COLD_BLOCKS).has_value());
    EXPECT_EQ(f.end_height, 3204314u);
}


// ─── The DOGE accrual tick (cold_start_tick.hpp): a tip body is never lost ───
// FRESH-VERIFY M1. The DOGE lane on master has no gap fill and nothing else
// re-asks a body: a block whose body never arrives would stay a hole, its
// transactions in the DOGE mempool and in every merged template for two
// weeks (invalid DOGE blocks).

namespace {

struct FakeAccrual {
    bool synced = true;
    int64_t tip_age = 60;
    uint32_t tip = DOGE_TIP;
    uint32_t best = 0;
    std::vector<uint32_t> one, all;
    std::vector<std::pair<uint32_t, uint32_t>> armed;
    Clock::time_point t = Clock::time_point{} + std::chrono::hours(1);

    ltc::coin::ColdStartTickHost host()
    {
        ltc::coin::ColdStartTickHost h;
        h.synced = [this]() { return synced; };
        h.tip_age_s = [this]() { return tip_age; };
        h.tip = [this]() { return tip; };
        h.utxo_best = [this]() { return best; };
        h.utxo_empty = [this]() { return best == 0; };
        h.wipe = [this]() { best = 0; return true; };
        h.armed = [this](uint32_t from, uint32_t to, uint32_t) { armed.emplace_back(from, to); };
        h.ask_one = [this](uint32_t x) { one.push_back(x); return true; };
        h.ask_all = [this](uint32_t x) { all.push_back(x); };
        h.now = [this]() { return t; };
        return h;
    }

    size_t asks_for(uint32_t h) const
    {
        return std::count(one.begin(), one.end(), h) + std::count(all.begin(), all.end(), h);
    }
};

/// One tick a second for `secs` seconds (both clocks).
void run_ticks(ltc::coin::AccrualColdStart<int>& cs, FakeAccrual& a, FakePeers& net, int secs)
{
    for (int i = 0; i < secs; ++i) {
        cs.tick();
        a.t += std::chrono::seconds(1);
        net.t += std::chrono::seconds(1);
    }
}

} // namespace

// (a) A warm restart one block behind (the node stopped between a header and
// its body): the tip's block is asked for. Before, the plan said "warm", the
// tip handler fires only on a tip change and the peers' inv for it came
// before we connected: nothing ever asked (master armed [best+1, height]).
TEST(DogeAccrualColdStart, AWarmRestartOneBlockBehindFetchesTheTip)
{
    FakeAccrual a;
    a.best = DOGE_TIP - 1;
    FakePeers net(20);
    BlockDownload dl(net.host(), "[test]");
    Fill f;
    ltc::coin::AccrualColdStart<int> cs(f, dl, DOGE_COLD_BLOCKS, a.host());
    run_ticks(cs, a, net, 10);
    EXPECT_TRUE(cs.decided());
    EXPECT_GE(net.asked[DOGE_TIP].size() + a.asks_for(DOGE_TIP), 1u)
        << "the tip's block, one above the set, was never asked for";
}

// (b) A tip body asked of its announcer only, which never answers: after a
// second of lag one peer is asked, three times two seconds apart, then every
// peer. Before, the tip request was one-shot (the fallbacks only when the
// send failed).
TEST(DogeAccrualColdStart, ALostTipBodyIsAskedAgain)
{
    FakeAccrual a;
    a.best = DOGE_TIP;
    FakePeers net(20);
    BlockDownload dl(net.host(), "[test]");
    Fill f;
    ltc::coin::AccrualColdStart<int> cs(f, dl, DOGE_COLD_BLOCKS, a.host());
    run_ticks(cs, a, net, 2);
    ASSERT_TRUE(cs.decided());
    ASSERT_FALSE(f.active);

    a.tip = DOGE_TIP + 1;  // its header came; the announcer's body never does
    run_ticks(cs, a, net, 3);
    EXPECT_GE(std::count(a.one.begin(), a.one.end(), DOGE_TIP + 1), 1) << "not asked again within 2 s";
    EXPECT_TRUE(a.all.empty()) << "every peer asked before one peer was tried";
    run_ticks(cs, a, net, 6);
    EXPECT_GE(std::count(a.all.begin(), a.all.end(), DOGE_TIP + 1), 1) << "not asked of every peer within 8 s";

    // It arrives: nothing more is asked.
    a.best = DOGE_TIP + 1;
    const size_t asked = a.one.size() + a.all.size();
    run_ticks(cs, a, net, 10);
    EXPECT_EQ(a.one.size() + a.all.size(), asked);
}

// (c) The header of T+1 is accepted while the Bootstrap drains its last block
// T: the tip handler asks nobody (the cold start runs), the fill completes at
// T before the tick could take T+1 into its range. T+1 must still be fetched.
TEST(DogeAccrualColdStart, TheLastDrainRacesANewTip)
{
    FakeAccrual a;
    a.best = 0;
    FakePeers net(20);
    BlockDownload dl(net.host(), "[test]");
    Fill f;
    ltc::coin::AccrualColdStart<int> cs(f, dl, DOGE_COLD_BLOCKS, a.host());
    run_ticks(cs, a, net, 1);
    ASSERT_TRUE(f.active);
    ASSERT_EQ(f.end_height, DOGE_TIP);

    a.tip = DOGE_TIP + 1;            // the header thread, mid-drain
    f.next_height = DOGE_TIP + 1;    // the drain connected T: the handler ends the fill
    f.processed = DOGE_COLD_BLOCKS;
    f.buffer.clear();
    f.active = false;
    a.best = DOGE_TIP;
    run_ticks(cs, a, net, 8);
    EXPECT_GE(net.asked[DOGE_TIP + 1].size() + a.asks_for(DOGE_TIP + 1), 1u)
        << "T+1 is in no fill and was never asked for";
}
