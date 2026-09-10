// desired_request_pacer_test.cpp — KAT for the desired-request futility backoff.
//
// RED on master semantics (no backoff at all: every desired hash is re-requested
// every think() cycle regardless of how many empty replies it just produced),
// GREEN with the pacer.
//
// Models the failure measured on the public LTC node after the #1556 cutover:
// 5137 DISTINCT desired hashes, replies ~1:1 empty, io thread pinned at 98% CPU
// and :8080 unreachable for 12.7 minutes.

#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "../desired_request_pacer.hpp"

using Pacer = ltc::DesiredRequestPacer<std::string>;

// An unseen hash is always requestable — the pacer only damps proven failures.
TEST(DesiredPacer, unknown_hash_is_eligible)
{
    Pacer p;
    EXPECT_TRUE(p.eligible("H", 0.0));
    EXPECT_EQ(p.attempts("H"), 0);
}

// One empty reply holds the hash back for the base interval, then releases it.
TEST(DesiredPacer, empty_reply_backs_off_then_releases)
{
    Pacer p;
    p.record_empty("H", 100.0);
    EXPECT_FALSE(p.eligible("H", 100.0));
    EXPECT_FALSE(p.eligible("H", 104.9));
    EXPECT_TRUE(p.eligible("H", 105.0));  // base = 5s
}

// Repeated empties double the interval, and the doubling stops at the ceiling —
// this is what keeps a permanently-unservable hash from being asked 30x/minute.
TEST(DesiredPacer, backoff_doubles_and_clamps_to_cap)
{
    Pacer p;
    double t = 0.0;
    p.record_empty("H", t);
    EXPECT_TRUE(p.eligible("H", t + 5.0));    // 5
    p.record_empty("H", t);
    EXPECT_FALSE(p.eligible("H", t + 9.9));
    EXPECT_TRUE(p.eligible("H", t + 10.0));   // 10
    p.record_empty("H", t);
    EXPECT_TRUE(p.eligible("H", t + 20.0));   // 20

    for (int i = 0; i < 20; ++i)
        p.record_empty("H", t);
    // Clamped: never longer than the cap, so the hash is never banned outright.
    EXPECT_FALSE(p.eligible("H", t + Pacer::kMaxBackoff - 0.1));
    EXPECT_TRUE(p.eligible("H", t + Pacer::kMaxBackoff));
}

// A served hash is forgotten, so a later failure starts from the base delay
// instead of resuming a stale exponent.
TEST(DesiredPacer, success_resets_the_exponent)
{
    Pacer p;
    p.record_empty("H", 0.0);
    p.record_empty("H", 0.0);
    p.record_empty("H", 0.0);
    ASSERT_EQ(p.attempts("H"), 3);

    p.record_success("H");
    EXPECT_EQ(p.attempts("H"), 0);
    EXPECT_TRUE(p.eligible("H", 0.0));

    p.record_empty("H", 200.0);
    EXPECT_TRUE(p.eligible("H", 205.0));  // base again, not 40s
}

// EXPIRY IS THE CONTRACT: a hash nobody could serve must return to the normal
// request path once a peer carrying that history can connect. Without this the
// damper would turn a transient gap into a permanent chain hole.
TEST(DesiredPacer, entries_expire_and_never_ban_permanently)
{
    Pacer p;
    for (int i = 0; i < 20; ++i)
        p.record_empty("H", 0.0);
    ASSERT_EQ(p.size(), 1u);
    ASSERT_FALSE(p.eligible("H", 10.0));

    // Long after it became eligible again, the entry is dropped entirely.
    p.prune(Pacer::kMaxBackoff + Pacer::kForgetAfter + 1.0);
    EXPECT_EQ(p.size(), 0u);
    EXPECT_TRUE(p.eligible("H", Pacer::kMaxBackoff + Pacer::kForgetAfter + 1.0));
    EXPECT_EQ(p.attempts("H"), 0);
}

// Pruning must NOT release a hash whose backoff is still running.
TEST(DesiredPacer, prune_keeps_live_backoffs)
{
    Pacer p;
    p.record_empty("H", 1000.0);
    p.prune(1001.0);
    EXPECT_EQ(p.size(), 1u);
    EXPECT_FALSE(p.eligible("H", 1001.0));
}

// THE RATE KAT the fix exists for. Replay the measured failure shape — a desired
// set where every reply is empty, recomputed by think() every cycle — and count
// the requests that would actually be issued over the window.
//
// Without the pacer every hash is re-requested on every cycle: N * cycles.
// With it, a hash is asked only when its backoff has expired, so the count grows
// logarithmically in the window instead of linearly.
TEST(DesiredPacer, all_empty_replies_collapse_the_request_count)
{
    constexpr int kHashes = 500;
    constexpr double kThinkInterval = 10.0;
    constexpr double kWindow = 300.0;

    std::vector<std::string> hashes;
    hashes.reserve(kHashes);
    for (int i = 0; i < kHashes; ++i)
        hashes.push_back("hash-" + std::to_string(i));

    Pacer p;
    long paced = 0;
    long unpaced = 0;

    for (double now = 0.0; now < kWindow; now += kThinkInterval) {
        p.prune(now);
        for (const auto& h : hashes) {
            ++unpaced;  // master: recomputed desired set, asked unconditionally
            if (p.eligible(h, now)) {
                ++paced;
                p.record_empty(h, now);  // the reply comes back empty, as measured
            }
        }
    }

    const int cycles = static_cast<int>(kWindow / kThinkInterval);
    EXPECT_EQ(unpaced, static_cast<long>(kHashes) * cycles);

    // Every hash is still tried repeatedly — this is a damper, not a mute.
    EXPECT_GT(paced, static_cast<long>(kHashes));
    // ...but the storm is gone: at least a 3x cut over this window, and the
    // margin widens the longer the futile set persists.
    EXPECT_LT(paced * 3, unpaced);
}
