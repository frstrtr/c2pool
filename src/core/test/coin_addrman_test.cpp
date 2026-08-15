// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// core::CoinAddrMan — KATs for the dashd CAddrMan port (bucketed new/tried
// address DB behind every per-coin CoinPeerManager).
//
// Covers the four properties the port promises:
//   1. BUCKETING DETERMINISM — coordinates are a pure function of the
//      persisted SipHash key + address/netgroup: identical across instances
//      with the same key, reshuffled under a different key, and an entire
//      /16 is confined to <= TRIED_BUCKETS_PER_GROUP tried buckets (the
//      anti-Sybil table-slice bound).
//   2. SELECT QUALITY BIAS — the stochastic draw prefers a clean entry over
//      one with a failed-attempt history (GetChance = 0.66^attempts).
//   3. PERSIST/RELOAD ROUND-TRIP — entries, tried membership, and the bucket
//      key survive save()+load().
//   4. FAIL-SAFE COLD/CORRUPT DB — absent or corrupt files load EMPTY and
//      never throw, so the seed ladder bootstraps exactly as on first run.
// Plus the tried-collision protocol (park -> feeler -> resolve) and the
// new-table growth beyond the legacy 20-peer working-set ceiling.
//
// FOLDED into the EXISTING allowlisted core_test target (never a new
// add_executable — the #769 "Not Run" trap).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <set>
#include <string>

#include <core/coin_addrman.hpp>

using core::CoinAddrMan;

namespace {

NetService ns(const std::string& host, uint16_t port = 9999)
{
    return NetService(host, port);
}

std::string tmp_db_path(const std::string& tag)
{
    return "/tmp/c2pool_addrman_kat_" + tag + "_" +
           std::to_string(::getpid()) + ".json";
}

} // namespace

TEST(CoinAddrMan, BucketingDeterministicUnderTheKey)
{
    CoinAddrMan a(/*k0=*/1, /*k1=*/2);
    CoinAddrMan b(/*k0=*/1, /*k1=*/2);
    CoinAddrMan c(/*k0=*/3, /*k1=*/4);

    int moved = 0;
    for (int i = 0; i < 50; ++i) {
        const auto addr = ns("51." + std::to_string(i) + ".7.9");
        const int tb = a.test_tried_bucket(addr);
        const int nb = a.test_new_bucket(addr, "");
        // Same key => identical coordinates on an independent instance.
        EXPECT_EQ(tb, b.test_tried_bucket(addr));
        EXPECT_EQ(nb, b.test_new_bucket(addr, ""));
        EXPECT_EQ(a.test_bucket_position(addr, false, tb),
                  b.test_bucket_position(addr, false, tb));
        // Ranges.
        EXPECT_GE(tb, 0);
        EXPECT_LT(tb, CoinAddrMan::TRIED_BUCKET_COUNT);
        EXPECT_GE(nb, 0);
        EXPECT_LT(nb, CoinAddrMan::NEW_BUCKET_COUNT);
        EXPECT_LT(a.test_bucket_position(addr, true, nb), CoinAddrMan::BUCKET_SIZE);
        // Different key => coordinates reshuffle (count how many move).
        if (tb != c.test_tried_bucket(addr)) ++moved;
    }
    // With 256 tried buckets, a different key must move nearly all of them.
    EXPECT_GT(moved, 40);
}

TEST(CoinAddrMan, TriedBucketsPerGroupBoundConfinesASlash16)
{
    CoinAddrMan a(11, 22);
    std::set<int> buckets;
    // 100 addresses all inside 51.77/16 — one netgroup.
    for (int i = 1; i <= 100; ++i)
        buckets.insert(a.test_tried_bucket(ns("51.77.0." + std::to_string(i))));
    EXPECT_LE(static_cast<int>(buckets.size()),
              CoinAddrMan::TRIED_BUCKETS_PER_GROUP);

    // And one source group can spray at most 64 distinct new buckets.
    std::set<int> new_buckets;
    for (int i = 1; i <= 200; ++i)
        new_buckets.insert(a.test_new_bucket(
            ns("52." + std::to_string(i) + ".3.4"), "198.51.100.7"));
    EXPECT_LE(static_cast<int>(new_buckets.size()),
              CoinAddrMan::NEW_BUCKETS_PER_SOURCE_GROUP);
}

TEST(CoinAddrMan, AddDedupsAndCapsNewBucketReferences)
{
    CoinAddrMan a(5, 6);
    const auto addr = ns("51.68.10.20");
    EXPECT_TRUE(a.add(addr));
    EXPECT_EQ(a.size(), 1u);
    // Re-announcing from many sources never duplicates the entry.
    for (int i = 0; i < 100; ++i)
        a.add(addr, "60." + std::to_string(i) + ".1.1");
    EXPECT_EQ(a.size(), 1u);
    EXPECT_EQ(a.new_count(), 1u);
}

TEST(CoinAddrMan, GrowsFarBeyondTheLegacyWorkingSetCeiling)
{
    CoinAddrMan a(7, 8);
    // 500 addresses across 500 distinct /16 groups — the flat working set
    // capped out at ~20; the bucketed DB must bank essentially all of them.
    for (int i = 0; i < 500; ++i)
        a.add(ns("51." + std::to_string(i % 250) + "." +
                 std::to_string(i / 250) + ".9"));
    EXPECT_GT(a.size(), 450u);
    EXPECT_EQ(a.tried_count(), 0u);
}

TEST(CoinAddrMan, GoodPromotesToTriedAndAttemptCountsFailures)
{
    CoinAddrMan a(9, 10);
    const auto addr = ns("51.15.30.40");
    ASSERT_TRUE(a.add(addr));
    EXPECT_FALSE(a.is_tried(addr));

    a.good(addr);
    EXPECT_TRUE(a.is_tried(addr));
    EXPECT_EQ(a.tried_count(), 1u);
    EXPECT_EQ(a.new_count(), 0u);

    // Attempt() on an unknown address is a silent no-op.
    a.attempt(ns("51.99.99.99"));
    EXPECT_EQ(a.size(), 1u);
}

TEST(CoinAddrMan, SelectPrefersCleanOverFailureHistory)
{
    CoinAddrMan a(13, 37);
    a.seed_rng(42);
    const auto clean = ns("51.10.1.1");
    const auto flaky = ns("52.20.2.2");
    ASSERT_TRUE(a.add(clean));
    ASSERT_TRUE(a.add(flaky));

    const int64_t now = 1700000000;
    // Both fresh (not terrible), both outside the 10-minute recent-try
    // deprioritizer; the flaky one carries 8 counted failed attempts, so its
    // GetChance is 0.66^8 ~ 3.6% of the clean one's.
    ASSERT_TRUE(a.test_set_times(clean, now, now - 3600, 0, 0));
    ASSERT_TRUE(a.test_set_times(flaky, now, now - 3600, 0, 8));

    int clean_draws = 0, flaky_draws = 0;
    for (int i = 0; i < 300; ++i) {
        auto pick = a.select(/*new_only=*/false, now);
        ASSERT_TRUE(pick.has_value());
        if (pick->to_string() == clean.to_string()) ++clean_draws;
        else if (pick->to_string() == flaky.to_string()) ++flaky_draws;
    }
    EXPECT_EQ(clean_draws + flaky_draws, 300);
    // Expected flaky share ~ q/(1+q) with q ~ 0.036 => ~3-4%. Allow head
    // room: it must stay far below parity.
    EXPECT_GT(clean_draws, flaky_draws * 4);
}

TEST(CoinAddrMan, PersistReloadRoundTrip)
{
    const std::string path = tmp_db_path("roundtrip");
    std::remove(path.c_str());

    CoinAddrMan a(21, 43);
    std::vector<NetService> tried_addrs;
    for (int i = 0; i < 20; ++i) {
        const auto addr = ns("51." + std::to_string(100 + i) + ".5.6");
        ASSERT_TRUE(a.add(addr));
        if (i < 10) {
            a.good(addr);
            tried_addrs.push_back(addr);
        }
    }
    ASSERT_EQ(a.size(), 20u);
    ASSERT_EQ(a.tried_count(), 10u);
    ASSERT_TRUE(a.save(path));

    CoinAddrMan b;   // fresh random key — load() must restore the saved one
    EXPECT_TRUE(b.load(path));
    EXPECT_EQ(b.size(), 20u);
    EXPECT_EQ(b.tried_count(), 10u);
    EXPECT_EQ(b.bucket_key(), a.bucket_key());
    for (const auto& addr : tried_addrs) {
        EXPECT_TRUE(b.contains(addr)) << addr.to_string();
        EXPECT_TRUE(b.is_tried(addr)) << addr.to_string();
    }
    std::remove(path.c_str());
}

TEST(CoinAddrMan, ColdAndCorruptDbLoadEmptyNeverThrow)
{
    CoinAddrMan a(3, 9);
    // Absent file: cold start, empty DB, false (seeds bootstrap).
    EXPECT_FALSE(a.load("/tmp/c2pool_addrman_kat_definitely_absent.json"));
    EXPECT_EQ(a.size(), 0u);

    // Corrupt file: garbage bytes.
    const std::string garbage = tmp_db_path("garbage");
    { std::ofstream ofs(garbage); ofs << "{not json at all"; }
    EXPECT_FALSE(a.load(garbage));
    EXPECT_EQ(a.size(), 0u);
    std::remove(garbage.c_str());

    // Valid JSON, wrong shape/version: same fail-safe.
    const std::string wrong = tmp_db_path("wrongshape");
    { std::ofstream ofs(wrong); ofs << "{\"version\": 99}"; }
    EXPECT_FALSE(a.load(wrong));
    EXPECT_EQ(a.size(), 0u);
    std::remove(wrong.c_str());
}

TEST(CoinAddrMan, TriedCollisionParksFeelerAndResolves)
{
    CoinAddrMan a(77, 88);
    a.seed_rng(7);

    // Incumbent takes its tried slot.
    const auto incumbent = ns("51.30.1.1");
    ASSERT_TRUE(a.add(incumbent));
    a.good(incumbent);
    const int bucket = a.test_tried_bucket(incumbent);
    const int pos = a.test_bucket_position(incumbent, false, bucket);

    // Find a challenger whose tried coordinates collide with the incumbent.
    NetService challenger;
    bool found = false;
    for (int i = 0; i < 200000 && !found; ++i) {
        NetService cand = ns("52." + std::to_string(i % 256) + "." +
                             std::to_string((i / 256) % 256) + "." +
                             std::to_string(1 + i / 65536));
        if (a.test_tried_bucket(cand) == bucket &&
            a.test_bucket_position(cand, false, bucket) == pos) {
            challenger = cand;
            found = true;
        }
    }
    ASSERT_TRUE(found) << "no colliding address in the search space";

    ASSERT_TRUE(a.add(challenger));
    a.good(challenger);
    // Parked as a collision, NOT tried yet; the feeler leg hands out the
    // incumbent for a re-test.
    EXPECT_FALSE(a.is_tried(challenger));
    EXPECT_EQ(a.collision_count(), 1u);
    auto feeler = a.select_tried_collision();
    ASSERT_TRUE(feeler.has_value());
    EXPECT_EQ(feeler->to_string(), incumbent.to_string());

    // Incumbent just proved alive (good() stamped last_success=now):
    // resolution keeps it and drops the challenge.
    a.resolve_collisions();
    EXPECT_EQ(a.collision_count(), 0u);
    EXPECT_TRUE(a.is_tried(incumbent));
    EXPECT_FALSE(a.is_tried(challenger));

    // Challenge again, but now the incumbent's last re-test FAILED recently
    // (last_try 2 minutes ago, last success long past): dashd's rules evict
    // it in favour of the challenger.
    a.good(challenger);
    EXPECT_EQ(a.collision_count(), 1u);
    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    ASSERT_TRUE(a.test_set_times(incumbent, now, /*last_try=*/now - 120,
                                 /*last_success=*/now - 6 * 3600));
    a.resolve_collisions();
    EXPECT_EQ(a.collision_count(), 0u);
    EXPECT_TRUE(a.is_tried(challenger));
    EXPECT_FALSE(a.is_tried(incumbent));
    // The evicted incumbent is demoted to new — history kept, not erased.
    EXPECT_TRUE(a.contains(incumbent));
}

TEST(CoinAddrMan, GetAddrSamplesAndHonorsTriedOnly)
{
    CoinAddrMan a(15, 16);
    a.seed_rng(3);
    const int64_t now = 1700000000;
    for (int i = 0; i < 40; ++i) {
        const auto addr = ns("51." + std::to_string(i) + ".8.8");
        ASSERT_TRUE(a.add(addr, "", CoinAddrMan::DEFAULT_TIME_PENALTY, now));
        if (i % 2 == 0) a.good(addr, now);
    }
    auto all = a.get_addr(/*max_pct=*/100, /*max_count=*/2500,
                          /*tried_only=*/false, now);
    EXPECT_EQ(all.size(), 40u);
    auto tried = a.get_addr(100, 2500, /*tried_only=*/true, now);
    EXPECT_EQ(tried.size(), 20u);
    // 23%/2500 default shape.
    auto sample = a.get_addr(23, 2500, false, now);
    EXPECT_EQ(sample.size(), 40u * 23 / 100);
}
