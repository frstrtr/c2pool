// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// LTC embedded: tip full-block fetch retry driver + MWEB window metrics KAT
// (rides share_test).
//
// MwebFetchRetry is the pure state machine main_ltc drives every 250 ms and
// on each tip change: attempts at t = 0, 1, 3, 7, 15, 30, 45 ... s, the first
// three to one peer, then to all; the state for the armed hash cancels; a new
// tip re-arms at attempt 0; after 600 s it reports "gave up" once and keeps
// asking every 60 s. MwebWindowStats measures tip change -> state for that
// tip. SeenBlocks is the dedup LRU.
// Folded into the allowlisted share_test target (no new executable: #769).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <chrono>
#include <optional>
#include <vector>

#include <core/uint256.hpp>
#include <impl/ltc/coin/mweb_fetch_retry.hpp>

namespace {

using ltc::coin::MwebFetchRetry;
using ltc::coin::MwebWindowStats;
using ltc::coin::SeenBlocks;
using clk = std::chrono::steady_clock;
using std::chrono::milliseconds;
using std::chrono::seconds;

uint256 h(const char* hex)
{
    uint256 v;
    v.SetHex(hex);
    return v;
}

const uint256 TIP_A = h("00000000000000000000000000000000000000000000000000000000000000a1");
const uint256 TIP_B = h("00000000000000000000000000000000000000000000000000000000000000b2");

// Drive the machine second by second over [from, to] and collect the actions.
std::vector<std::pair<int, MwebFetchRetry::Action>> run(MwebFetchRetry& r, clk::time_point t0,
                                                        int from, int to)
{
    std::vector<std::pair<int, MwebFetchRetry::Action>> out;
    for (int s = from; s <= to; ++s)
        if (auto a = r.due(t0 + seconds(s)))
            out.emplace_back(s, *a);
    return out;
}

} // namespace

TEST(LtcMwebFetchRetry, Schedule)
{
    EXPECT_EQ(MwebFetchRetry::next_delay(0), seconds(1));
    EXPECT_EQ(MwebFetchRetry::next_delay(1), seconds(2));
    EXPECT_EQ(MwebFetchRetry::next_delay(2), seconds(4));
    EXPECT_EQ(MwebFetchRetry::next_delay(3), seconds(8));
    EXPECT_EQ(MwebFetchRetry::next_delay(4), seconds(15));
    EXPECT_EQ(MwebFetchRetry::next_delay(40), seconds(15));

    MwebFetchRetry r;
    const auto t0 = clk::now();
    EXPECT_FALSE(r.due(t0)) << "nothing armed";
    ASSERT_TRUE(r.arm(TIP_A, t0));
    auto acts = run(r, t0, 0, 46);
    std::vector<int> times;
    for (auto& [t, a] : acts) {
        times.push_back(t);
        EXPECT_EQ(a.hash, TIP_A);
        EXPECT_EQ(a.broadcast, a.attempt >= 3) << "attempts 0..2 one peer, then all";
        EXPECT_FALSE(a.gave_up);
    }
    EXPECT_EQ(times, (std::vector<int>{0, 1, 3, 7, 15, 30, 45}));
    for (size_t i = 0; i < acts.size(); ++i)
        EXPECT_EQ(acts[i].second.attempt, i);
    EXPECT_EQ(r.attempts(), 7u);
    EXPECT_TRUE(r.armed());
}

TEST(LtcMwebFetchRetry, ArmingTheSameHashKeepsTheSchedule)
{
    MwebFetchRetry r;
    const auto t0 = clk::now();
    ASSERT_TRUE(r.arm(TIP_A, t0));
    ASSERT_TRUE(r.due(t0));
    EXPECT_FALSE(r.arm(TIP_A, t0 + milliseconds(500))) << "tick re-arm for the same tip is a no-op";
    EXPECT_FALSE(r.due(t0 + milliseconds(900)));
    auto a = r.due(t0 + seconds(1));
    ASSERT_TRUE(a);
    EXPECT_EQ(a->attempt, 1u);
}

TEST(LtcMwebFetchRetry, StateCancelsOnlyTheArmedHash)
{
    MwebFetchRetry r;
    const auto t0 = clk::now();
    r.arm(TIP_A, t0);
    ASSERT_TRUE(r.due(t0));
    ASSERT_TRUE(r.due(t0 + seconds(1)));

    EXPECT_FALSE(r.on_state(TIP_B)) << "state for another block does not cancel";
    EXPECT_TRUE(r.armed());
    EXPECT_TRUE(r.due(t0 + seconds(3)));

    EXPECT_EQ(r.attempts_for(TIP_A), 3u);
    EXPECT_TRUE(r.on_state(TIP_A));
    EXPECT_FALSE(r.armed());
    EXPECT_FALSE(r.due(t0 + seconds(100)));
    EXPECT_EQ(r.attempts_for(TIP_A), 3u) << "kept for the window log line";
    EXPECT_FALSE(r.last_was_broadcast(TIP_A));
}

TEST(LtcMwebFetchRetry, TipChangeRearmsAtAttemptZero)
{
    MwebFetchRetry r;
    const auto t0 = clk::now();
    r.arm(TIP_A, t0);
    run(r, t0, 0, 7);  // attempts 0..3
    EXPECT_EQ(r.attempts(), 4u);
    EXPECT_TRUE(r.last_was_broadcast(TIP_A));

    // Next block (or a reorg to a sibling): attempt 0 again, one peer, now.
    const auto t1 = t0 + seconds(8);
    ASSERT_TRUE(r.arm(TIP_B, t1));
    EXPECT_EQ(r.armed_hash(), TIP_B);
    auto a = r.due(t1);
    ASSERT_TRUE(a);
    EXPECT_EQ(a->hash, TIP_B);
    EXPECT_EQ(a->attempt, 0u);
    EXPECT_FALSE(a->broadcast);
    EXPECT_EQ(r.attempts_for(TIP_A), 0u) << "the old tip is forgotten once another is armed";
}

TEST(LtcMwebFetchRetry, DeferredFirstAttempt)
{
    // A compact block for the tip is mid-flight: attempt 0 waits a second.
    MwebFetchRetry r;
    const auto t0 = clk::now();
    r.arm(TIP_A, t0, seconds(1));
    EXPECT_FALSE(r.due(t0));
    EXPECT_FALSE(r.due(t0 + milliseconds(999)));
    auto a = r.due(t0 + seconds(1));
    ASSERT_TRUE(a);
    EXPECT_EQ(a->attempt, 0u);
}

TEST(LtcMwebFetchRetry, GiveUpFlagThenOneMinuteCadence)
{
    MwebFetchRetry r;
    const auto t0 = clk::now();
    r.arm(TIP_A, t0);
    auto acts = run(r, t0, 0, 900);
    int gave_up_at = -1;
    std::vector<int> after;
    for (auto& [t, a] : acts) {
        if (a.gave_up) {
            EXPECT_EQ(gave_up_at, -1) << "reported once";
            gave_up_at = t;
        }
        if (gave_up_at >= 0 && t > gave_up_at)
            after.push_back(t);
        EXPECT_TRUE(a.attempt < 3 || a.broadcast);
    }
    ASSERT_EQ(gave_up_at, 600) << "30 + 15k reaches 600 s exactly";
    EXPECT_EQ(after, (std::vector<int>{660, 720, 780, 840, 900})) << "keeps asking every minute";
    EXPECT_TRUE(r.gave_up());
    EXPECT_TRUE(r.armed()) << "never stops on its own";
}

TEST(LtcMwebWindowStats, WindowOpensAtTipChangeClosesOnState)
{
    MwebWindowStats st;
    const auto t0 = clk::now();
    EXPECT_FALSE(st.open(TIP_A, 100, t0));
    // State for another block does not close it.
    EXPECT_FALSE(st.note_state(TIP_B, MwebWindowStats::Source::FullBlockTargeted, 0, t0 + milliseconds(10)));
    auto c = st.note_state(TIP_A, MwebWindowStats::Source::CmpctV3Reconstructed, 0, t0 + milliseconds(400));
    ASSERT_TRUE(c);
    EXPECT_EQ(c->tip, TIP_A);
    EXPECT_EQ(c->height, 100u);
    EXPECT_EQ(c->ms, 400);
    EXPECT_EQ(st.window_count(), 1u);
    EXPECT_EQ(st.window_last_ms(), 400);
    EXPECT_EQ(st.hist_bucket(MwebWindowStats::bucket_for_ms(400)), 1u);
    EXPECT_EQ(MwebWindowStats::bucket_for_ms(400), 1u) << "<= 0.5 s";
    EXPECT_EQ(st.source_count(MwebWindowStats::Source::CmpctV3Reconstructed), 1u);

    // State that lands before the tip change (compact block reconstructed
    // before the header thread reported the tip): a 0 ms window.
    EXPECT_FALSE(st.note_state(TIP_B, MwebWindowStats::Source::CmpctV3Blocktxn, 0, t0 + seconds(1)));
    auto c2 = st.open(TIP_B, 101, t0 + seconds(2));
    ASSERT_TRUE(c2);
    EXPECT_EQ(c2->ms, 0);
    EXPECT_EQ(c2->source, MwebWindowStats::Source::CmpctV3Blocktxn);
    EXPECT_EQ(st.window_count(), 2u);

    // A window that never closed is counted when the next one opens.
    const uint256 tip_c = h("00000000000000000000000000000000000000000000000000000000000000c3");
    const uint256 tip_d = h("00000000000000000000000000000000000000000000000000000000000000d4");
    EXPECT_FALSE(st.open(tip_c, 102, t0 + seconds(3)));
    EXPECT_FALSE(st.open(tip_c, 102, t0 + seconds(3))) << "same tip twice: no double count";
    EXPECT_FALSE(st.open(tip_d, 103, t0 + seconds(4)));
    EXPECT_EQ(st.window_unclosed(), 1u);
    auto c3 = st.note_state(tip_d, MwebWindowStats::Source::FullBlockBroadcast, 4, t0 + seconds(74));
    ASSERT_TRUE(c3);
    EXPECT_EQ(c3->attempts, 4u);
    EXPECT_EQ(MwebWindowStats::bucket_for_ms(c3->ms), MwebWindowStats::BUCKETS - 1) << "> 60 s";

    const auto j = st.to_json();
    EXPECT_EQ(j["window_count"].get<uint64_t>(), 3u);
    EXPECT_EQ(j["window_unclosed"].get<uint64_t>(), 1u);
    EXPECT_EQ(j["window_hist"]["le_0.5"].get<uint64_t>(), 1u);
    EXPECT_EQ(j["window_hist"]["le_0.25"].get<uint64_t>(), 1u);
    EXPECT_EQ(j["window_hist"]["gt_60"].get<uint64_t>(), 1u);
    EXPECT_EQ(j["state_source"]["full_block_broadcast"].get<uint64_t>(), 1u);
    EXPECT_EQ(j["state_source"]["bootstrap"].get<uint64_t>(), 0u);
    for (const char* k : {"cmpct_received", "cmpct_v3_with_mweb", "cmpct_no_hogex", "cmpct_dup",
                          "fetch_retries", "fetch_gave_up", "block_dups", "full_blocks_received",
                          "cmpct_rejected", "cmpct_fallback", "window_last_ms"})
        EXPECT_TRUE(j.contains(k)) << k;
}

TEST(LtcMwebWindowStats, Counters)
{
    MwebWindowStats st;
    st.cmpct_received += 3;
    st.note_cmpct_rejected("prev-unknown");
    st.note_cmpct_rejected("prev-unknown");
    st.note_cmpct_fallback("not-v3");
    const auto j = st.to_json();
    EXPECT_EQ(j["cmpct_received"].get<uint64_t>(), 3u);
    EXPECT_EQ(j["cmpct_rejected"]["prev-unknown"].get<uint64_t>(), 2u);
    EXPECT_EQ(j["cmpct_fallback"]["not-v3"].get<uint64_t>(), 1u);
}

TEST(LtcSeenBlocks, LruEvictsOldest)
{
    SeenBlocks seen(3);
    const uint256 a = TIP_A, b = TIP_B;
    const uint256 c = h("0c"), d = h("0d");
    seen.insert(a);
    seen.insert(b);
    seen.insert(c);
    EXPECT_TRUE(seen.contains(a));
    seen.insert(a);  // refresh a
    seen.insert(d);  // evicts b, the oldest
    EXPECT_FALSE(seen.contains(b));
    EXPECT_TRUE(seen.contains(a));
    EXPECT_TRUE(seen.contains(c));
    EXPECT_TRUE(seen.contains(d));
    EXPECT_EQ(seen.size(), 3u);
}
