// FENCED, additive KAT pinning the think() Phase-3 per-tail best-head
// selection in think_p3_best_head.hpp vs the p2pool data.py think() oracle
// (max(verified.tails[t], key=verified.get_work), first-max tiebreak).
// Non-circular: winners are hand-derived, plus an independent reference scan
// (the verbatim pre-delegation inline loop) anchors against drift in either
// comparison direction. Lightweight int/uint64 stand-ins -> no ShareTracker
// standup, no uint256 dependency.
#include <gtest/gtest.h>
#include "../think_p3_best_head.hpp"
#include <vector>
#include <set>
#include <map>
#include <cstdint>

using dgb::think_p3_best_head_by_work;

namespace {
struct Fixture {
    std::set<int> verified;
    std::map<int, uint64_t> work;
    auto contains() const { return [this](int h){ return verified.count(h) != 0; }; }
    auto worker()   const { return [this](int h){ return work.at(h); }; }
};
}

// Empty candidate set -> not found.
TEST(ThinkP3BestHead, EmptyCandidatesNotFound) {
    Fixture fx;
    std::vector<int> heads;
    auto r = think_p3_best_head_by_work(heads, fx.contains(), fx.worker());
    EXPECT_FALSE(r.found);
}

// All candidates unverified -> not found (get_work never consulted).
TEST(ThinkP3BestHead, AllUnverifiedNotFound) {
    Fixture fx;
    fx.work = {{1,100},{2,200}};   // present but NOT in verified set
    std::vector<int> heads{1,2};
    auto r = think_p3_best_head_by_work(heads, fx.contains(), fx.worker());
    EXPECT_FALSE(r.found);
}

// Single verified head -> that head and its work.
TEST(ThinkP3BestHead, SingleVerified) {
    Fixture fx;
    fx.verified = {7};
    fx.work = {{7,42}};
    std::vector<int> heads{7};
    auto r = think_p3_best_head_by_work(heads, fx.contains(), fx.worker());
    EXPECT_TRUE(r.found);
    EXPECT_EQ(r.head, 7);
    EXPECT_EQ(r.work, 42u);
}

// Strict max among verified; a higher-work UNVERIFIED head is ignored.
TEST(ThinkP3BestHead, StrictMaxSkipsUnverified) {
    Fixture fx;
    fx.verified = {1,3};           // 2 NOT verified
    fx.work = {{1,100},{2,999},{3,300}};
    std::vector<int> heads{1,2,3};
    auto r = think_p3_best_head_by_work(heads, fx.contains(), fx.worker());
    // Hand-derived: among verified {1:100, 3:300} the max is head 3.
    EXPECT_TRUE(r.found);
    EXPECT_EQ(r.head, 3);
    EXPECT_EQ(r.work, 300u);
}

// Tie -> FIRST verified head in iteration order wins (first-max semantics).
TEST(ThinkP3BestHead, TieFirstSeenWins) {
    Fixture fx;
    fx.verified = {5,8,9};
    fx.work = {{5,250},{8,250},{9,250}};
    std::vector<int> heads{5,8,9};
    auto r = think_p3_best_head_by_work(heads, fx.contains(), fx.worker());
    // All equal: strictly-greater replace never fires -> first seen (5) wins.
    EXPECT_TRUE(r.found);
    EXPECT_EQ(r.head, 5);
}

// Non-circular anchor: re-derive the winner with the verbatim pre-delegation
// inline loop and assert the SSOT agrees (arbitrary order, unverified mixed in).
TEST(ThinkP3BestHead, MatchesIndependentReferenceScan) {
    Fixture fx;
    fx.verified = {1,2,4,6};
    fx.work = {{1,10},{2,70},{3,80},{4,70},{5,5},{6,40}};
    std::vector<int> heads{6,4,2,1,3,5};   // incl. unverified 3,5
    int best_head = 0; uint64_t best_work = 0; bool first = true;
    for (int hh : heads) {
        if (!fx.verified.count(hh)) continue;
        uint64_t w = fx.work.at(hh);
        if (first || w > best_work) { best_work = w; best_head = hh; first = false; }
    }
    auto r = think_p3_best_head_by_work(heads, fx.contains(), fx.worker());
    EXPECT_TRUE(r.found);
    EXPECT_EQ(r.head, best_head);   // = 4 (first 70-work head, 6:40 superseded)
    EXPECT_EQ(r.work, best_work);
}
