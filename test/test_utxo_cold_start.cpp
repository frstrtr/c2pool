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
    ltc::coin::ordered_arm(f, p.from, p.to);
    f.phase = "Bootstrap";
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
// behind jumps (the one deliberate jump); a set at most one block behind
// needs no fill.
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

    EXPECT_EQ(ltc::coin::cold_start_plan(LTC_COLD_BLOCKS, true, T, T - 1).action, ColdStart::Action::Warm);
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
            ltc::coin::ordered_arm(f, r->first, r->second);
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
