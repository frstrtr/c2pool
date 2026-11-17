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
// heads is printed (not asserted).
//
// Folded into test_dash_p2p_node (beside test_dash_restart_reorg_supersede_kat).

#include <chrono>
#include <cstdint>
#include <cstdio>
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
// active case is actually exercised (not only the inactive one).
TEST(DashSupersedeHintEquivalence, RandomForestsGiveTheIdenticalHint)
{
    std::mt19937 rng(20261117);
    int active_cases = 0, inactive_cases = 0;
    for (int round = 0; round < 400; ++round) {
        dash::ShareTracker t;
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
                const auto& s = segs[rng() % segs.size()];
                seg = b.run(n, s.back(), bits);
                break;
            }
            }
            if (rng() % 3 == 0)
                verify(t, seg, rng() % (seg.size() + 1));
            segs.push_back(std::move(seg));
        }
        // Incumbent: usually our verified tip, sometimes another verified head.
        uint256 incumbent = inc.back();
        if (rng() % 5 == 0) {
            const auto& s = segs[rng() % segs.size()];
            if (t.verified.contains(s.back())) incumbent = s.back();
        }
        const auto ref = reference_hint(t, incumbent, 400);
        const auto now = t.compute_supersede_hint(incumbent, 400);
        ASSERT_TRUE(same_hint(ref, now)) << "round " << round;
        (ref.active ? active_cases : inactive_cases)++;
    }
    EXPECT_GT(active_cases, 20) << "the active path must be exercised";
    EXPECT_GT(inactive_cases, 20);
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
    auto full = b.run(CL + 20, uint256(), kBitsNormal);   // a second rooted chain, more work
    verify(t, full, full.size());
    auto ch = b.run(CL + 40, hx("dead7777"), kBitsNormal);   // unverified challenger
    ASSERT_GE(t.verified.get_acc_height(full.back()), CL);
    for (const uint256& incumbent : {inc.back(), full.back()}) {
        const auto ref = reference_hint(t, incumbent, 400);
        const auto now = t.compute_supersede_hint(incumbent, 400);
        EXPECT_TRUE(same_hint(ref, now));
        EXPECT_TRUE(now.active);
        EXPECT_EQ(now.target_head, ch.back());
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

    using clk = std::chrono::steady_clock;
    const auto t0 = clk::now();
    const auto ref = reference_hint(t, incumbent, 400);
    const auto t1 = clk::now();
    const auto now = t.compute_supersede_hint(incumbent, 400);
    const auto t2 = clk::now();
    EXPECT_TRUE(same_hint(ref, now));
    EXPECT_FALSE(now.active);
    const auto us = [](auto d) { return std::chrono::duration_cast<std::chrono::microseconds>(d).count(); };
    std::cout << "[supersede-hint cost] heads=" << t.chain.get_heads().size()
              << " chain=" << t.chain.size() << " previous=" << us(t1 - t0)
              << "us now=" << us(t2 - t1) << "us\n";
    RecordProperty("previous_us", std::to_string(us(t1 - t0)));
    RecordProperty("now_us", std::to_string(us(t2 - t1)));
}
