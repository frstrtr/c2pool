// SPDX-License-Identifier: AGPL-3.0-or-later
/// core::coin::BlockDownload (core/coin/block_download.hpp): one peer per
/// block for an ordered fill, the DOGE full lane's download rules (request
/// timeout, stalling-peer rotation, cooldown), the fill's stall timer asking
/// another peer and every peer only on the third stall, and the buffer's byte
/// bound. Fill = BlockBootstrapState<int>; peers and the clock are faked.

#include <gtest/gtest.h>

#include <core/coin/block_bootstrapper.hpp>
#include <core/coin/block_download.hpp>

#include <chrono>
#include <map>
#include <set>
#include <string>
#include <vector>

using core::coin::BlockBootstrapState;
using core::coin::BlockDownload;

namespace {

using Clock = std::chrono::steady_clock;
using Fill = BlockBootstrapState<int>;

struct FakePeers {
    std::vector<std::string> peers;
    std::vector<std::pair<std::string, uint32_t>> asked;  // (peer, height)
    std::vector<uint32_t> all;                            // heights asked of every peer
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
            asked.emplace_back(p, height);
            return true;
        };
        h.request_all = [this](uint32_t height) { all.push_back(height); };
        h.now = [this]() { return t; };
        return h;
    }

    size_t asks_for(uint32_t h) const
    {
        size_t n = 0;
        for (const auto& a : asked)
            n += a.second == h;
        return n;
    }
};

void arm(Fill& f, uint32_t from, uint32_t to)
{
    f.active = true;
    f.next_height = from;
    f.end_height = to;
    f.next_request = from;
    f.total = to - from + 1;
    f.buffer.clear();
}

/// Deliver height h (the fill buffers it) and drain what is in order.
void deliver(Fill& f, BlockDownload& dl, uint32_t h, const std::string& peer)
{
    dl.delivered(h, peer);
    f.buffer.try_emplace(h, std::make_pair(int(h), uint256()));
    dl.buffered(h, 1000);
    uint32_t n = 0;
    while (f.buffer.count(f.next_height)) {
        f.buffer.erase(f.next_height);
        ++f.next_height;
        ++n;
    }
    dl.drained(n);
}

} // namespace

// Every height of the window goes to exactly one peer, spread over the peers.
TEST(BlockDownload, EveryHeightGoesToOnePeer)
{
    FakePeers net(20);
    BlockDownload dl(net.host(), "[test]");
    Fill f;
    arm(f, 1000, 5319);
    EXPECT_EQ(dl.refill(f), 16u);
    std::set<std::string> used;
    for (uint32_t h = 1000; h < 1016; ++h) {
        EXPECT_EQ(net.asks_for(h), 1u) << "h=" << h;
        used.insert(dl.asked_peer(h));
    }
    EXPECT_EQ(used.size(), 16u);
    EXPECT_TRUE(net.all.empty());
    // Asked again: nothing new while all of them are in flight.
    EXPECT_EQ(dl.refill(f), 0u);

    // The window moves as the first arrives; the next height goes out.
    deliver(f, dl, 1000, dl.asked_peer(1000));
    EXPECT_EQ(dl.refill(f), 1u);
    EXPECT_EQ(net.asks_for(1016), 1u);
}

// A request unanswered for 60 s goes to another peer; its peer cools down.
TEST(BlockDownload, ARequestTimeoutGoesToAnotherPeer)
{
    FakePeers net(3);
    BlockDownload dl(net.host(), "[test]");
    Fill f;
    arm(f, 1, 3);
    ASSERT_EQ(dl.refill(f), 3u);
    const std::string slow = dl.asked_peer(2);
    deliver(f, dl, 1, dl.asked_peer(1));
    deliver(f, dl, 3, dl.asked_peer(3));
    net.t += std::chrono::seconds(61);
    dl.tick(f);
    EXPECT_EQ(dl.stats().request_timeouts.load(), 1u);
    ASSERT_EQ(net.asks_for(2), 2u);
    EXPECT_NE(dl.asked_peer(2), slow);
}

// The window cannot move: its first height's peer is rotated out after the
// stall timeout and its requests go to other peers.
TEST(BlockDownload, AStallingPeerIsRotatedOut)
{
    FakePeers net(16);
    BlockDownload dl(net.host(), "[test]");
    Fill f;
    arm(f, 100, 1000);
    ASSERT_EQ(dl.refill(f), 16u);
    const std::string staller = dl.asked_peer(100);
    for (uint32_t h = 101; h < 116; ++h)
        deliver(f, dl, h, dl.asked_peer(h));
    ASSERT_EQ(f.next_height, 100u);
    net.t += std::chrono::milliseconds(2500);
    dl.tick(f);
    EXPECT_EQ(dl.stats().stalls.load(), 1u);
    EXPECT_EQ(net.asks_for(100), 2u);
    EXPECT_FALSE(dl.asked_peer(100).empty());
    EXPECT_NE(dl.asked_peer(100), staller);
    EXPECT_TRUE(net.all.empty());
}

// The fill's 30-s stall timer: another peer twice, every peer on the third
// stall of the same height.
TEST(BlockDownload, TheThirdFillStallAsksEveryPeer)
{
    FakePeers net(20);
    BlockDownload dl(net.host(), "[test]");
    Fill f;
    arm(f, 500, 600);
    ASSERT_EQ(dl.refill(f), 16u);
    const std::string first = dl.asked_peer(500);
    EXPECT_FALSE(dl.on_fill_stall(f, 500));
    const std::string second = dl.asked_peer(500);
    EXPECT_NE(second, first);
    EXPECT_FALSE(dl.on_fill_stall(f, 500));
    EXPECT_NE(dl.asked_peer(500), second);
    EXPECT_TRUE(net.all.empty());
    EXPECT_TRUE(dl.on_fill_stall(f, 500));
    ASSERT_EQ(net.all.size(), 1u);
    EXPECT_EQ(net.all[0], 500u);
    EXPECT_EQ(net.asks_for(500), 3u);
}

// Bodies ahead of the window are not kept; past the byte bound only the next
// height is asked (window_waits) and the buffer stays under it.
TEST(BlockDownload, TheBufferIsBoundedInBytes)
{
    FakePeers net(20);
    BlockDownload dl(net.host(), "[test]", 4000);
    Fill f;
    arm(f, 10, 1000);
    f.window = 64;
    EXPECT_FALSE(dl.keep(f, 10 + 64, 1000)) << "ahead of the window";
    EXPECT_TRUE(dl.keep(f, 10, 1000)) << "the next height always";
    for (uint32_t h = 11; h < 20; ++h) {
        if (dl.keep(f, h, 1000)) {
            f.buffer.try_emplace(h, std::make_pair(int(h), uint256()));
            dl.buffered(h, 1000);
        }
    }
    EXPECT_LE(dl.buffer_bytes(), 4000u);
    EXPECT_EQ(f.buffer.size(), 4u);
    // At the bound only the next height (the drain waits for it) is asked.
    EXPECT_EQ(dl.refill(f), 1u);
    EXPECT_GE(dl.stats().window_waits.load(), 1u);
    EXPECT_EQ(dl.in_flight(), 1u);
    EXPECT_FALSE(dl.asked_peer(10).empty());
}
