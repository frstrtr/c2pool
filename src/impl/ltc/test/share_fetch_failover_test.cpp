// share_fetch_failover_test.cpp — KAT for the parent-fetch failover memory
// (p2pool-merged-v36 kr1z1s convergence hotfix #25(C)).
//
// RED on master semantics (peer-BLIND per-hash counter: any failure on a hash
// skips it for the whole peer set), GREEN after the per-peer failover fix.
//
// Mirrors p2pool test_minority_fork_livelock.py:459-505.

#include <gtest/gtest.h>
#include <string>
#include "../share_fetch_failover.hpp"

using Mem = ltc::FetchFailureMemory<std::string, std::string>;

namespace {
// Deterministic index picker for the KAT (production injects the RNG).
auto first = [](std::size_t) -> std::size_t { return 0; };
}

// RED on master: peerA failed hash H, peerB has not. choose() must return peerB.
// Master's peer-blind counter skips H for everyone once it has failed -> nullopt.
TEST(FetchFailover, choose_skips_recently_failed_peer)
{
    Mem m;
    m.record("H", "A", /*now=*/100.0);
    auto pick = m.choose("H", /*advertiser=*/std::nullopt,
                         /*peers=*/{"A", "B"}, /*now=*/110.0, first);
    ASSERT_TRUE(pick.has_value());
    EXPECT_EQ(*pick, "B");
}

// GREEN on both: with no failures the advertiser is preferred.
TEST(FetchFailover, choose_prefers_the_advertiser)
{
    Mem m;
    auto pick = m.choose("H", /*advertiser=*/std::optional<std::string>{"B"},
                         /*peers=*/{"A", "B", "C"}, /*now=*/100.0, first);
    ASSERT_TRUE(pick.has_value());
    EXPECT_EQ(*pick, "B");
}

// GREEN on both: the advertiser is skipped if IT is the one that failed the hash.
TEST(FetchFailover, choose_skips_advertiser_when_it_failed)
{
    Mem m;
    m.record("H", "B", 100.0);
    auto pick = m.choose("H", /*advertiser=*/std::optional<std::string>{"B"},
                         /*peers=*/{"A", "B"}, /*now=*/110.0, first);
    ASSERT_TRUE(pick.has_value());
    EXPECT_EQ(*pick, "A");
}

// GREEN on both: once EVERY peer has failed the hash, back off (nullopt).
TEST(FetchFailover, choose_returns_none_when_all_peers_failed)
{
    Mem m;
    m.record("H", "A", 100.0);
    m.record("H", "B", 100.0);
    auto pick = m.choose("H", std::nullopt, {"A", "B"}, 110.0, first);
    EXPECT_FALSE(pick.has_value());
}

// RED on master: a single black-hole peer (answers "empty" forever) must never
// wedge a two-peer fetch. Record its failure repeatedly; choose() must keep
// returning the good peer. Master skips the hash for everyone -> nullopt (wedge).
TEST(FetchFailover, single_blackhole_never_wedges_multi_peer_fetch)
{
    Mem m;
    const std::vector<std::string> peers{"blackhole", "good"};
    // The black-hole advertised the hash and was tried once — it failed (empty).
    m.record("H", "blackhole", /*now=*/100.0);
    // From here on, even with the black-hole re-advertising, every fetch must fail
    // over to the good peer. Master's peer-blind counter would skip H entirely.
    for (double t = 101.0; t < 130.0; t += 1.0) {
        auto pick = m.choose("H", /*advertiser=*/std::optional<std::string>{"blackhole"},
                             peers, t, first);
        ASSERT_TRUE(pick.has_value()) << "wedged at t=" << t;
        EXPECT_EQ(*pick, "good");
        // the black-hole fails again on every attempt, refreshing its failure ts
        m.record("H", "blackhole", t);
    }
}

// GREEN on both: a per-peer failure ages out after the TTL, and that peer becomes
// eligible again.
TEST(FetchFailover, failure_memory_expires_after_ttl)
{
    Mem m(/*ttl=*/90.0);
    m.record("H", "A", /*now=*/0.0);
    // Within the TTL: A is ineligible.
    EXPECT_EQ(m.failed_keys("H", 10.0).count("A"), 1u);
    // Past the TTL: A is eligible again.
    EXPECT_EQ(m.failed_keys("H", 100.0).count("A"), 0u);
    auto pick = m.choose("H", std::nullopt, {"A"}, 100.0, first);
    ASSERT_TRUE(pick.has_value());
    EXPECT_EQ(*pick, "A");
}

// GREEN on both: prune() drops aged entries and empties the bucket.
TEST(FetchFailover, prune_bounds_memory)
{
    Mem m(/*ttl=*/90.0);
    m.record("H", "A", 0.0);
    EXPECT_EQ(m.tracked_hashes(), 1u);
    m.prune(/*now=*/200.0);
    EXPECT_EQ(m.tracked_hashes(), 0u);
}

// GREEN on both (invariant): a head's parent is abandoned only once EVERY peer
// has failed it. Mirrors clean_tracker Guard 2b's `parent_abandoned` input.
TEST(FetchFailover, parent_abandoned_requires_every_peer_to_have_failed)
{
    Mem m;
    const std::vector<std::string> peers{"A", "B"};
    m.record("H", "A", 100.0);
    EXPECT_FALSE(m.abandoned("H", peers, 110.0));   // B has not failed
    m.record("H", "B", 100.0);
    EXPECT_TRUE(m.abandoned("H", peers, 110.0));     // both failed
}

// GREEN on both: with no connected peers a parent is NOT abandoned (the download
// is merely waiting for a peer, not unfetchable).
TEST(FetchFailover, no_peers_is_not_abandoned)
{
    Mem m;
    m.record("H", "A", 100.0);
    EXPECT_FALSE(m.abandoned("H", /*peers=*/{}, 110.0));
}

// GREEN on both: a success clears the whole failure record for that hash.
TEST(FetchFailover, success_clears_failure_memory)
{
    Mem m;
    m.record("H", "A", 100.0);
    m.clear_hash("H");
    EXPECT_TRUE(m.failed_keys("H", 110.0).empty());
    EXPECT_FALSE(m.abandoned("H", {"A"}, 110.0));
}
