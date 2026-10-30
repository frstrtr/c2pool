// SPDX-License-Identifier: AGPL-3.0-or-later
/// Embedded LTC header sync (ltc/coin/header_sync.hpp), FRESH-NODE §2.1 / §3:
/// one sync peer, no re-ask on a batch with nothing new, a batch the chain
/// already has (or has queued) dropped before the header thread's queue, and
/// that queue bounded. The host is faked: a set of known hashes stands in for
/// the HeaderChain, the two queues are run by hand, and every getheaders is
/// counted (an all-peer round counts each of the 20 peers).

#include <gtest/gtest.h>

#include <impl/ltc/coin/header_sync.hpp>
#include <impl/ltc/coin/header_chain.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <vector>

using namespace ltc::coin;

namespace {

using Clock = std::chrono::steady_clock;

/// `n` distinct headers (the fake chain does not link them).
std::vector<BlockHeaderType> make_batch(uint32_t first, size_t n)
{
    std::vector<BlockHeaderType> out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        BlockHeaderType h;
        h.m_version = 0x20000000;
        h.m_timestamp = 1700000000 + first + static_cast<uint32_t>(i);
        h.m_bits = 0x1e0ffff0;
        h.m_nonce = first + static_cast<uint32_t>(i);
        out.push_back(h);
    }
    return out;
}

struct FakeLtcNet {
    static constexpr size_t PEERS = 20;
    std::set<uint256> known;
    std::vector<std::function<void()>> worker_q, io_q;
    bool synced = false;
    std::vector<std::string> one_asks;  // peers asked one at a time
    size_t all_rounds = 0;              // rounds that asked every peer
    Clock::time_point t = Clock::time_point{} + std::chrono::hours(1);

    size_t getheaders() const { return one_asks.size() + all_rounds * PEERS; }
    void clear_asks() { one_asks.clear(); all_rounds = 0; }

    void know(const std::vector<BlockHeaderType>& b)
    {
        for (const auto& h : b)
            known.insert(block_hash(h));
    }

    HeaderSyncHost host()
    {
        HeaderSyncHost h;
        h.has_header = [this](const uint256& x) { return known.count(x) > 0; };
        h.add_headers = [this](const std::vector<BlockHeaderType>& b) {
            int n = 0;
            for (const auto& hd : b)
                if (known.insert(block_hash(hd)).second)
                    ++n;
            return n;
        };
        h.post_worker = [this](std::function<void()> fn) { worker_q.push_back(std::move(fn)); };
        h.post_io = [this](std::function<void()> fn) { io_q.push_back(std::move(fn)); };
        h.locator = []() { return std::vector<uint256>{uint256::ONE}; };
        h.synced = [this]() { return synced; };
        h.ask_one = [this](const std::vector<uint256>&, size_t rr, const std::string& peer) {
            const std::string p = peer.empty() ? "peer" + std::to_string(rr % PEERS) : peer;
            one_asks.push_back(p);
            return p;
        };
        h.ask_all = [this](const std::vector<uint256>&) { ++all_rounds; };
        h.now = [this]() { return t; };
        return h;
    }

    /// Run the header thread's queue, then ioc's, until both are empty.
    void run()
    {
        while (!worker_q.empty() || !io_q.empty()) {
            auto w = std::move(worker_q);
            worker_q.clear();
            for (auto& f : w)
                f();
            auto i = std::move(io_q);
            io_q.clear();
            for (auto& f : i)
                f();
        }
    }
};

uint64_t stat(const HeaderSync& s, const char* key)
{
    return s.to_json().at(key).get<uint64_t>();
}

} // namespace

// 20 peers each send the same 2,000 headers, all known: nobody is asked
// again (the fresh node re-asked all 20 for every one: 22,500 duplicate
// batches in 25 minutes). The poll asks one peer later.
TEST(LtcHeaderSync, AFullDuplicateBatchAsksNoPeer)
{
    FakeLtcNet net;
    const auto batch = make_batch(0, 2000);
    net.know(batch);
    auto sync = std::make_shared<HeaderSync>(net.host());
    for (size_t p = 0; p < FakeLtcNet::PEERS; ++p)
        sync->on_headers("peer" + std::to_string(p), batch);
    net.run();
    EXPECT_EQ(net.getheaders(), 0u) << net.all_rounds << " all-peer rounds after 20 duplicate batches";

    net.t += std::chrono::seconds(60);
    sync->poll();
    net.run();
    EXPECT_EQ(net.getheaders(), 1u);
    EXPECT_EQ(net.all_rounds, 0u);
}

// A batch with new headers from A: exactly one getheaders, to A. The poll
// while the chain catches up asks one peer, and nobody while follow-ups
// carry the sync.
TEST(LtcHeaderSync, TheHeaderSyncHasOneSyncPeer)
{
    FakeLtcNet net;
    auto sync = std::make_shared<HeaderSync>(net.host());
    sync->poll();
    net.run();
    EXPECT_EQ(net.getheaders(), 1u) << "the first poll while unsynced";
    EXPECT_EQ(net.all_rounds, 0u);

    net.clear_asks();
    sync->on_headers("A", make_batch(0, 2000));
    net.run();
    ASSERT_EQ(net.getheaders(), 1u) << net.all_rounds << " all-peer rounds after one new batch";
    ASSERT_EQ(net.one_asks.size(), 1u);
    EXPECT_EQ(net.one_asks[0], "A");

    // New headers since the last poll: the follow-ups carry the sync.
    net.clear_asks();
    net.t += std::chrono::seconds(10);
    sync->poll();
    net.run();
    EXPECT_EQ(net.getheaders(), 0u);
    // Nothing new for a poll interval: one peer.
    net.t += std::chrono::seconds(10);
    sync->poll();
    net.run();
    EXPECT_EQ(net.getheaders(), 1u);
    EXPECT_EQ(net.all_rounds, 0u);
}

// The same new batch from 20 peers before the header thread got to the first:
// one copy is queued, 19 are dropped on the IO thread; a copy after the
// chain took it is dropped too.
TEST(LtcHeaderSync, AKnownBatchIsDroppedBeforeThePool)
{
    FakeLtcNet net;
    auto sync = std::make_shared<HeaderSync>(net.host());
    const auto batch = make_batch(0, 2000);
    for (size_t p = 0; p < FakeLtcNet::PEERS; ++p)
        sync->on_headers("peer" + std::to_string(p), batch);
    EXPECT_EQ(net.worker_q.size(), 1u);
    EXPECT_EQ(stat(*sync, "batches_queued"), 1u);
    EXPECT_EQ(stat(*sync, "hdr_batches_dropped"), 19u);

    net.run();
    sync->on_headers("late", batch);
    EXPECT_TRUE(net.worker_q.empty());
    EXPECT_EQ(stat(*sync, "batches_queued"), 1u);
    EXPECT_EQ(stat(*sync, "hdr_batches_dropped"), 20u);
    EXPECT_EQ(net.getheaders(), 1u) << "one follow-up, to the first sender";
}

// The header thread stalls while 1,000 distinct batches arrive: at most 8
// wait for it, the rest are dropped and counted.
TEST(LtcHeaderSync, TheHeaderPoolQueueIsBounded)
{
    FakeLtcNet net;
    auto sync = std::make_shared<HeaderSync>(net.host());
    for (uint32_t i = 0; i < 1000; ++i)
        sync->on_headers("peer" + std::to_string(i % FakeLtcNet::PEERS), make_batch(i * 10, 10));
    EXPECT_LE(stat(*sync, "hdr_pool_queued"), 8u);
    EXPECT_LE(stat(*sync, "hdr_pool_queued_max"), 8u);
    EXPECT_LE(net.worker_q.size(), 8u);
    EXPECT_EQ(stat(*sync, "batches_queued") + stat(*sync, "hdr_batches_dropped"), 1000u);

    net.run();
    EXPECT_EQ(stat(*sync, "hdr_pool_queued"), 0u);
}

// Synced: block announcements bring the tip; the minute poll asks one peer
// (2 h of a tip moving every 3 minutes: 0 all-peer rounds, against 120 before),
// and every peer only once the tip has not moved for 30 minutes.
TEST(LtcHeaderSync, TheSyncedPollAsksOnePeer)
{
    FakeLtcNet net;
    net.synced = true;
    auto sync = std::make_shared<HeaderSync>(net.host());
    for (uint32_t minute = 0; minute < 120; ++minute) {
        if (minute % 3 == 0) {
            sync->on_headers("A", make_batch(minute * 10, 1));
            net.run();
        }
        net.t += std::chrono::seconds(60);
        sync->poll();
        net.run();
    }
    EXPECT_EQ(net.all_rounds, 0u);
    EXPECT_LE(net.getheaders(), 120u + 40u);

    net.clear_asks();
    for (uint32_t minute = 0; minute < 40; ++minute) {
        net.t += std::chrono::seconds(60);
        sync->poll();
        net.run();
    }
    EXPECT_EQ(net.all_rounds, 1u) << "a 40-minute stale tip";
}
