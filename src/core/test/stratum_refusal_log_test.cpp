// SPDX-License-Identifier: AGPL-3.0-or-later
//
// core::RefusalLogLimiter (core/stratum_refusal_log.hpp): the rate limit on
// the stratum server's "connection refused" WARN lines. A client reconnecting
// three times a second against a full LTC node wrote 264k such lines. The
// first refusal after a quiet window is logged at once; later ones are
// counted into at most one summary line per window, which names the peer that
// sent the most. A window of 0 logs every refusal.

#include <gtest/gtest.h>

#include <core/stratum_refusal_log.hpp>

#include <chrono>
#include <string>

namespace {

using Clock = core::RefusalLogLimiter::clock;

Clock::time_point at(double s)
{
    return Clock::time_point{} + std::chrono::hours(1)
         + std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(s));
}

const std::string kCap = "node at miner cap 100/100 (max_stratum_connections)";

}  // namespace

TEST(StratumRefusalLog, FirstRefusalAtOnceThenOneSummaryPerWindow)
{
    core::RefusalLogLimiter lim(std::chrono::seconds(10));
    EXPECT_TRUE(lim.record(at(0), "203.0.113.7", kCap)) << "the first refusal is logged at once";
    EXPECT_FALSE(lim.due()) << "nothing pending";

    // Three a second for ten seconds, two of them from another address.
    for (int i = 1; i < 30; ++i) {
        EXPECT_FALSE(lim.flush(at(i / 3.0)));
        EXPECT_FALSE(lim.record(at(i / 3.0), i % 10 ? "203.0.113.7" : "198.51.100.1", kCap))
            << "refusal " << i << " is counted, not logged";
    }
    EXPECT_EQ(lim.pending(), 29u);
    ASSERT_TRUE(lim.due());
    EXPECT_EQ(*lim.due(), at(10));
    EXPECT_FALSE(lim.flush(at(9.9))) << "no summary before the window ends";
    const auto summary = lim.flush(at(10));
    ASSERT_TRUE(summary);
    EXPECT_EQ(*summary, "29 more in the last 10 s (" + kCap + ", top peer 203.0.113.7 x27)");
    EXPECT_EQ(lim.pending(), 0u);

    // The storm goes on: still one line per window.
    EXPECT_FALSE(lim.record(at(10.3), "203.0.113.7", kCap));
    EXPECT_FALSE(lim.flush(at(15)));
    const auto second = lim.flush(at(20));
    ASSERT_TRUE(second);
    EXPECT_EQ(*second, "1 more in the last 10 s (" + kCap + ", top peer 203.0.113.7 x1)");

    // Quiet for a window: the next refusal is logged at once again.
    EXPECT_FALSE(lim.flush(at(25)));
    EXPECT_FALSE(lim.due());
    EXPECT_FALSE(lim.record(at(29.9), "203.0.113.7", kCap)) << "inside the window of the last line";
    ASSERT_TRUE(lim.flush(at(30)));
    EXPECT_TRUE(lim.record(at(40.5), "203.0.113.7", kCap)) << "after a quiet window: logged at once";
}

TEST(StratumRefusalLog, ZeroWindowLogsEveryRefusal)
{
    core::RefusalLogLimiter lim(std::chrono::seconds(0));
    for (int i = 0; i < 5; ++i)
        EXPECT_TRUE(lim.record(at(i * 0.01), "203.0.113.7", kCap));
    EXPECT_EQ(lim.pending(), 0u);
}

TEST(RefusalLogLimiter, PendingPeersAreCappedTheRestCountedAsOther)
{
    using clock = core::RefusalLogLimiter::clock;
    core::RefusalLogLimiter lim(std::chrono::seconds(10));
    const auto t0 = clock::now();
    ASSERT_TRUE(lim.record(t0, "first", "d"));   // logged in full
    const std::size_t n = core::RefusalLogLimiter::kMaxPendingPeers + 500;
    for (std::size_t i = 0; i < n; ++i)
        EXPECT_FALSE(lim.record(t0, "2001:db8:" + std::to_string(i) + "::", "d"));
    lim.record(t0, "2001:db8:0::", "d");   // a known peer is still told apart
    EXPECT_EQ(lim.pending(), n + 1);
    EXPECT_EQ(lim.pending_peers(), core::RefusalLogLimiter::kMaxPendingPeers);
    const auto summary = lim.flush(t0 + std::chrono::seconds(10));
    ASSERT_TRUE(summary);
    EXPECT_NE(summary->find("top peer 2001:db8:0:: x2"), std::string::npos) << *summary;
    EXPECT_NE(summary->find(", 500 from other peers"), std::string::npos) << *summary;
    EXPECT_EQ(lim.pending_peers(), 0u);
    // The next window starts clean.
    EXPECT_FALSE(lim.record(t0 + std::chrono::seconds(11), "x", "d"));
    const auto next = lim.flush(t0 + std::chrono::seconds(21));
    ASSERT_TRUE(next);
    EXPECT_EQ(next->find("other peers"), std::string::npos) << *next;
}
