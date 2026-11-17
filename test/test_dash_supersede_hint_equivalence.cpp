// SPDX-License-Identifier: AGPL-3.0-or-later
// compute_supersede_hint: the cheaper filter order gives the IDENTICAL hint.
//
// The restart-reorg detector (dash::ShareTracker::compute_supersede_hint) runs
// under the exclusive tracker lock in every think() cycle and twice per
// clean_tracker. It used to call chain.is_child_of() first for every head; that
// walks the chain four times per head (get_height and get_last of both ends,
// O(chain) each), which made it most of a think hold on a full tracker. The
// filters now run cheapest first, is_child_of last, plus a work pre-check (a
// head that cannot out-work the incumbent can never be the active target).
//
// What is pinned: on hundreds of random share forests (rooted incumbent chain,
// extensions of it, forks off it at random depths, disconnected challenger
// segments, mixed per-share work, partly verified) and on full-length chains
// (the acc_height >= CHAIN_LENGTH filter), the new function returns a hint
// field-for-field equal to the previous implementation, kept below verbatim as
// the reference. A timing comparison on a full-length chain with stale fork
// heads is printed (not asserted). descends_from (the cheap descendant walk
// that replaced is_child_of there) equals is_child_of on every pair of a forest.
//
// Folded into test_dash_p2p_node (beside test_dash_restart_reorg_supersede_kat).

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <core/uint256.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/share_tracker.hpp>

namespace {

uint256 hx(const std::string& tail) {
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}

constexpr uint32_t kBitsNormal = 0x1e0fffff;
constexpr uint32_t kBitsHarder = 0x1d0fffff;   // more work per share
constexpr uint32_t kBitsEasier = 0x1e3fffff;   // less work per share

struct Builder {
    dash::ShareTracker& t;
    size_t salt{1};
    // `count` shares on top of `prev` (null = rooted; a hash not in the chain
    // = a segment with a missing parent). Returns the segment's tip hashes,
    // oldest first.
    std::vector<uint256> run(int32_t count, const uint256& prev0, uint32_t bits) {
        std::vector<uint256> out;
        uint256 prev = prev0;
        const size_t s = salt++;
        for (int32_t i = 0; i < count; ++i) {
            char buf[40];
            std::snprintf(buf, sizeof(buf), "%zx", (s << 24) + 0x5e00 + static_cast<size_t>(i));
            const uint256 h = hx(buf);
            auto* sh = new dash::DashShare();
            sh->m_hash = h;
            sh->m_prev_hash = prev;
            sh->m_desired_version = 16;
            sh->m_bits = bits;
            sh->m_max_bits = bits;
            dash::ShareType st;
            st = sh;
            t.add(st);
            out.push_back(h);
            prev = h;
        }
        return out;
    }
};

// Verify the shares of `seg` (oldest first) that are in the chain.
void verify(dash::ShareTracker& t, const std::vector<uint256>& seg, size_t upto) {
    for (size_t i = 0; i < upto && i < seg.size(); ++i)
        if (t.chain.contains(seg[i]) && !t.verified.contains(seg[i]))
            t.verified.add(t.chain.get_share(seg[i]));
}

// THE PREVIOUS IMPLEMENTATION, verbatim (origin/master before this change).
dash::SupersedeHint reference_hint(dash::ShareTracker& t, const uint256& incumbent_best, int budget)
{
    auto& chain = t.chain;
    auto& verified = t.verified;
    dash::SupersedeHint hint;
    if (incumbent_best.IsNull() || !verified.contains(incumbent_best))
        return hint;
    const auto CL = static_cast<int32_t>(dash::SharechainConfig::chain_length());
    const uint288 incumbent_work = verified.get_work(incumbent_best);

    uint256 best_ch;
    uint288 best_ch_work;
    bool found = false;
    for (auto& [head, tail] : chain.get_heads())
    {
        if (head == incumbent_best) continue;
        if (!chain.contains(head)) continue;
        try { if (chain.is_child_of(incumbent_best, head)) continue; }
        catch (...) { }
        if (verified.get_acc_height(head) >= CL) continue;
        uint288 w;
        try { w = chain.get_work(head); } catch (...) { continue; }
        if (!found || w > best_ch_work) { best_ch_work = w; best_ch = head; found = true; }
    }

    if (found && incumbent_work < best_ch_work)
    {
        hint.active = true;
        hint.target_head = best_ch;
        try { hint.target_segment_last = chain.get_last(best_ch); } catch (...) {}
        hint.budget = budget;
        hint.challenger_work = best_ch_work;
        hint.incumbent_work = incumbent_work;
    }
    return hint;
}

::testing::AssertionResult same_hint(const dash::SupersedeHint& a, const dash::SupersedeHint& b)
{
    if (a.active != b.active) return ::testing::AssertionFailure() << "active differs";
    if (a.target_head != b.target_head) return ::testing::AssertionFailure() << "target_head differs";
    if (a.target_segment_last != b.target_segment_last)
        return ::testing::AssertionFailure() << "target_segment_last differs";
    if (a.budget != b.budget) return ::testing::AssertionFailure() << "budget differs";
    if (!(a.challenger_work == b.challenger_work)) return ::testing::AssertionFailure() << "challenger_work differs";
    if (!(a.incumbent_work == b.incumbent_work)) return ::testing::AssertionFailure() << "incumbent_work differs";
    return ::testing::AssertionSuccess();
}

uint32_t pick_bits(std::mt19937& rng) {
    switch (rng() % 3) {
    case 0:  return kBitsNormal;
    case 1:  return kBitsHarder;
    default: return kBitsEasier;
    }
}

} // namespace

// Hundreds of random forests: the hint is identical, field for field, and the
// active case is actually exercised (not only the inactive one). The reference
// and the new function each run on their OWN identically built tracker, so
// neither sees a height/work memo the other one warmed.
namespace {
struct Forest {
    uint256 incumbent;
    bool    other_incumbent{false};   ///< not the rooted verified tip
    std::vector<uint256> all;         ///< every share hash added
    std::vector<uint256> parents;     ///< the missing parents used
};
Forest build_forest(dash::ShareTracker& t, uint32_t seed, int round)
{
    std::mt19937 rng(seed);
    Builder b{t};
    auto inc = b.run(10 + static_cast<int32_t>(rng() % 50), uint256(), kBitsNormal);
    verify(t, inc, inc.size());
    std::vector<std::vector<uint256>> segs{inc};
    const int extra = static_cast<int>(rng() % 10);
    for (int k = 0; k < extra; ++k) {
        const int32_t n = 1 + static_cast<int32_t>(rng() % 60);
        const uint32_t bits = pick_bits(rng);
        std::vector<uint256> seg;
        switch (rng() % 4) {
        case 0:  // extension of the incumbent tip (a child, not a fork)
            seg = b.run(n, inc.back(), bits);
            break;
        case 1: {  // fork off a random incumbent ancestor
            const auto& base = inc[rng() % inc.size()];
            seg = b.run(n, base, bits);
            break;
        }
        case 2: {  // disconnected segment: its parent is missing
            char buf[24];
            std::snprintf(buf, sizeof(buf), "dead%04x%04x", round, k);
            seg = b.run(n, hx(buf), bits);
            break;
        }
        default: {  // extension of an earlier segment
            const auto& sg = segs[rng() % segs.size()];
            seg = b.run(n, sg.back(), bits);
            break;
        }
        }
        if (rng() % 3 == 0)
            verify(t, seg, rng() % (seg.size() + 1));
        segs.push_back(std::move(seg));
    }
    // Incumbent: usually our verified tip; one round in four another segment,
    // fully verified first, so the "incumbent is not the rooted tip" case runs.
    Forest f;
    f.incumbent = inc.back();
    if (rng() % 4 == 0) {
        const auto& sg = segs[rng() % segs.size()];
        verify(t, sg, sg.size());
        if (t.verified.contains(sg.back()) && sg.back() != inc.back()) {
            f.incumbent = sg.back();
            f.other_incumbent = true;
        }
    }
    for (const auto& sg : segs) f.all.insert(f.all.end(), sg.begin(), sg.end());
    for (const auto& sg : segs)
        if (!sg.empty()) {
            const uint256 prev = t.chain.get_index(sg.front())->tail;
            if (!prev.IsNull() && !t.chain.contains(prev)) f.parents.push_back(prev);
        }
    return f;
}
} // namespace

TEST(DashSupersedeHintEquivalence, RandomForestsGiveTheIdenticalHint)
{
    int active_cases = 0, inactive_cases = 0, other_incumbent = 0;
    for (int round = 0; round < 400; ++round) {
        const uint32_t seed = 20261117u + static_cast<uint32_t>(round);
        dash::ShareTracker t_ref, t_new;
        const auto f_ref = build_forest(t_ref, seed, round);
        const auto f_new = build_forest(t_new, seed, round);
        ASSERT_EQ(f_ref.incumbent, f_new.incumbent);
        const auto ref = reference_hint(t_ref, f_ref.incumbent, 400);
        const auto now = t_new.compute_supersede_hint(f_new.incumbent, 400);
        ASSERT_TRUE(same_hint(ref, now)) << "round " << round;
        (ref.active ? active_cases : inactive_cases)++;
        if (f_ref.other_incumbent) ++other_incumbent;
    }
    EXPECT_GT(active_cases, 20) << "the active path must be exercised";
    EXPECT_GT(inactive_cases, 20);
    EXPECT_GT(other_incumbent, 20) << "an incumbent other than the rooted tip must be exercised";
}

// descends_from (the cheap walk) answers exactly like chain.is_child_of on
// EVERY ordered pair of a forest: shares, the segments' missing parents, a
// hash that is in no segment, and each element with itself.
TEST(DashSupersedeHintEquivalence, DescendsFromEqualsIsChildOfOnEveryPair)
{
    size_t pairs = 0, trues = 0;
    for (int round = 0; round < 25; ++round) {
        dash::ShareTracker t;
        const auto f = build_forest(t, 777u + static_cast<uint32_t>(round), 1000 + round);
        // Shapes build_forest never makes: a SECOND rooted tree (both trees'
        // get_last is null) and two segments off ONE shared missing parent.
        Builder extra{t, 5000 + static_cast<size_t>(round) * 4};
        const auto root2 = extra.run(8, uint256(), kBitsNormal);
        char shared[24];
        std::snprintf(shared, sizeof(shared), "5ead%04x", round);
        const auto sib1 = extra.run(5, hx(shared), kBitsNormal);
        const auto sib2 = extra.run(7, hx(shared), kBitsNormal);
        // The special nodes FIRST, so the bound below never cuts them: the
        // null hash, every missing parent, a hash in no segment, the new shapes.
        std::vector<uint256> nodes{uint256(), hx("beef1234"), hx(shared)};
        nodes.insert(nodes.end(), f.parents.begin(), f.parents.end());
        for (const auto* seg : {&root2, &sib1, &sib2})
            nodes.insert(nodes.end(), seg->begin(), seg->end());
        nodes.insert(nodes.end(), f.all.begin(), f.all.end());
        if (nodes.size() > 120) nodes.resize(120);   // keep the pair count bounded
        for (const auto& a : nodes)
            for (const auto& b : nodes) {
                const bool slow = t.chain.is_child_of(a, b);
                const bool fast = t.descends_from(a, b);
                ASSERT_EQ(fast, slow) << "round " << round << " item=" << a.GetHex().substr(48)
                                      << " possible_child=" << b.GetHex().substr(48);
                ++pairs;
                trues += slow ? 1 : 0;
            }
    }
    EXPECT_GT(trues, pairs / 50) << "the true case must be well exercised";
}

// Deterministic edge cases the random forests reach only by chance.
TEST(DashSupersedeHintEquivalence, TiesAndChildPlusForkCases)
{
    struct Case {
        const char* name;
        std::function<uint256(Builder&, dash::ShareTracker&, const std::vector<uint256>&)> extra;
        bool active;
    };
    // Each case starts from a 30-share verified incumbent; `extra` adds the
    // rest and returns the expected target head (null when inactive).
    const std::vector<Case> cases = {
        {"fork with work EQUAL to the incumbent -> inactive",
         [](Builder& b, dash::ShareTracker&, const std::vector<uint256>&) {
             b.run(30, hx("dead0101"), kBitsNormal);
             return uint256();
         }, false},
        {"two equal-work forks above the incumbent -> the same (first) one wins",
         [](Builder& b, dash::ShareTracker&, const std::vector<uint256>&) {
             b.run(40, hx("dead0201"), kBitsNormal);
             b.run(40, hx("dead0202"), kBitsNormal);
             return uint256();   // target checked by equality with the reference only
         }, true},
        {"higher-work child + lower-work fork -> inactive",
         [](Builder& b, dash::ShareTracker&, const std::vector<uint256>& inc) {
             b.run(5, inc.back(), kBitsNormal);
             b.run(3, inc[10], kBitsNormal);
             return uint256();
         }, false},
        {"higher-work child + higher-work fork -> the fork wins",
         [](Builder& b, dash::ShareTracker&, const std::vector<uint256>& inc) {
             b.run(5, inc.back(), kBitsNormal);
             return b.run(60, inc[5], kBitsNormal).back();
         }, true},
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(c.name);
        dash::ShareTracker t_ref, t_new;
        uint256 target_ref, target_new, inc_ref, inc_new;
        for (auto* t : {&t_ref, &t_new}) {
            Builder b{*t};
            auto inc = b.run(30, uint256(), kBitsNormal);
            verify(*t, inc, inc.size());
            const uint256 target = c.extra(b, *t, inc);
            (t == &t_ref ? target_ref : target_new) = target;
            (t == &t_ref ? inc_ref : inc_new) = inc.back();
        }
        const auto ref = reference_hint(t_ref, inc_ref, 400);
        const auto now = t_new.compute_supersede_hint(inc_new, 400);
        EXPECT_TRUE(same_hint(ref, now));
        EXPECT_EQ(now.active, c.active);
        if (!target_new.IsNull()) EXPECT_EQ(now.target_head, target_new);
    }
}

// The acc_height >= CHAIN_LENGTH filter: a full-length verified head with more
// work (Phase-3 scoring handles it) is skipped in both, and a disconnected
// challenger behind it is still found.
TEST(DashSupersedeHintEquivalence, FullLengthVerifiedHeadsGiveTheIdenticalHint)
{
    const auto CL = static_cast<int32_t>(dash::SharechainConfig::chain_length());
    dash::ShareTracker t;
    Builder b{t};
    auto inc = b.run(CL + 10, uint256(), kBitsNormal);
    verify(t, inc, inc.size());
    // A second rooted, fully verified chain that OUT-WORKS the challenger: only
    // the acc_height >= CHAIN_LENGTH filter keeps it from being the target.
    auto full = b.run(CL + 60, uint256(), kBitsNormal);
    verify(t, full, full.size());
    auto ch = b.run(CL + 40, hx("dead7777"), kBitsNormal);   // unverified challenger
    ASSERT_GE(t.verified.get_acc_height(full.back()), CL);
    ASSERT_TRUE(t.chain.get_work(ch.back()) < t.chain.get_work(full.back()));
    {
        const auto ref = reference_hint(t, inc.back(), 400);
        const auto now = t.compute_supersede_hint(inc.back(), 400);
        EXPECT_TRUE(same_hint(ref, now));
        EXPECT_TRUE(now.active);
        EXPECT_EQ(now.target_head, ch.back()) << "the full-length verified head is never the target";
    }
    {   // incumbent = the full chain: nothing out-works it
        const auto ref = reference_hint(t, full.back(), 400);
        const auto now = t.compute_supersede_hint(full.back(), 400);
        EXPECT_TRUE(same_hint(ref, now));
        EXPECT_FALSE(now.active);
    }
}

// Cost on a full-length incumbent with stale fork heads (the healthy-node case
// the filter order targets). Printed, not asserted (timing).
TEST(DashSupersedeHintEquivalence, CostOnAFullTrackerWithStaleForks)
{
    const auto CL = static_cast<int32_t>(dash::SharechainConfig::chain_length());
    dash::ShareTracker t;
    Builder b{t};
    auto inc = b.run(2 * CL + 10, uint256(), kBitsNormal);
    verify(t, inc, inc.size());
    std::mt19937 rng(7);
    for (int k = 0; k < 20; ++k)   // stale forks a few shares long, off older shares
        b.run(1 + static_cast<int32_t>(rng() % 3), inc[inc.size() - 50 - rng() % 2000], kBitsNormal);
    b.run(2, inc.back(), kBitsNormal);   // one unverified extension of the tip
    const uint256 incumbent = inc.back();

    // Warm the height/work memo with both once, then alternate 5 timed runs
    // each and report the fastest, so neither side pays the other's cold cache.
    using clk = std::chrono::steady_clock;
    const auto us = [](auto d) { return std::chrono::duration_cast<std::chrono::microseconds>(d).count(); };
    auto ref = reference_hint(t, incumbent, 400);
    auto now = t.compute_supersede_hint(incumbent, 400);
    EXPECT_TRUE(same_hint(ref, now));
    EXPECT_FALSE(now.active);
    long long best_prev = -1, best_now = -1;
    for (int i = 0; i < 5; ++i) {
        const auto a0 = clk::now();
        ref = reference_hint(t, incumbent, 400);
        const auto a1 = clk::now();
        now = t.compute_supersede_hint(incumbent, 400);
        const auto a2 = clk::now();
        EXPECT_TRUE(same_hint(ref, now));
        const long long p = us(a1 - a0), n = us(a2 - a1);
        if (best_prev < 0 || p < best_prev) best_prev = p;
        if (best_now < 0 || n < best_now) best_now = n;
    }
    std::cout << "[supersede-hint cost] heads=" << t.chain.get_heads().size()
              << " chain=" << t.chain.size() << " previous=" << best_prev
              << "us now=" << best_now << "us (fastest of 5, warm)\n";
    RecordProperty("previous_us", std::to_string(best_prev));
    RecordProperty("now_us", std::to_string(best_now));
}
