// SPDX-License-Identifier: AGPL-3.0-or-later
// clean_tracker Step 3 restart-reorg exemption: dash::supersede_exempt_tail.
//
// THE DEFECT this pins: Step 3 (drop tails) must keep the converging
// challenger segment's bottom while the supersede hint is active. The check
// was `chain.contains(tail_hash) && chain.get_last(tail_hash) == segment_last`,
// but a key of the tails map is a segment's MISSING PARENT, never a share in
// the chain, so contains() was always false and the exemption never fired: the
// challenger's bottom was trimmed mid-convergence. The fix matches the segment
// by plain equality (the tails key IS get_last(target_head)).
//
// Asserted, through the real ShareTracker (compute_supersede_hint) and
// dash::drop_tails:
//   * the root cause: on random forests, before and after drop passes, no tails
//     key is ever a chain share, so the old predicate is false for every tail;
//   * replays of the two VM504 restart convergences (11-18 05:26, 804 shares
//     dropped; 00:06, 688), scaled: 5 heads, a verified incumbent, a heavier
//     unverified challenger segment with that many droppable bottom layers.
//     The old predicate trims the challenger (RED on master); the fixed one
//     keeps every challenger share, capped and uncapped, while the incumbent's
//     side is trimmed as before;
//   * convergence still completes: once the challenger is verified and wins,
//     the hint clears, the exemption lapses, and the tracker reaches the same
//     state as with no exemption at all;
//   * no unbounded growth: a challenger that keeps growing stays exempt only
//     while the hint is active; once the hint clears (stall/denylist or win),
//     trimming catches up to the no-exemption state.
//
// Folded into test_dash_p2p_node (beside test_dash_clean_drop_tails).

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <random>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <core/uint256.hpp>
#include <impl/dash/clean_drop_tails.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/share_tracker.hpp>

namespace {

uint256 hx(const std::string& tail) {
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}
uint256 mk(uint64_t id) {
    char buf[40];
    std::snprintf(buf, sizeof(buf), "e5e7%012llx", static_cast<unsigned long long>(id));
    return hx(buf);
}

constexpr uint32_t kBitsNormal = 0x1e0fffff;
constexpr uint32_t kBitsHarder = 0x1d0fffff;   // ~16x the work per share

std::vector<uint256> run(dash::ShareTracker& t, const uint256& prev0, int32_t n, uint32_t bits, uint64_t& id) {
    std::vector<uint256> out;
    uint256 prev = prev0;
    for (int32_t i = 0; i < n; ++i) {
        const uint256 h = mk(id++);
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
void verify_all(dash::ShareTracker& t, const std::vector<uint256>& seg) {
    for (const auto& h : seg)
        if (t.chain.contains(h) && !t.verified.contains(h))
            t.verified.add(t.chain.get_share(h));
}

// THE CHECK ON MASTER, verbatim (node.cpp clean_tracker Step 3 before the fix).
bool master_exempt(dash::ShareTracker& t, const dash::SupersedeHint& hint, const uint256& tail_hash) {
    if (hint.active) {
        try {
            if (t.chain.contains(tail_hash) &&
                t.chain.get_last(tail_hash) == hint.target_segment_last)
                return true;
        } catch (...) {}
    }
    return false;
}

// A restart convergence: verified incumbent I (+3 stale forks = 5 heads with
// the challenger) and a heavier, unverified challenger C with `droppable`
// bottom layers beyond `threshold`.
struct Replay {
    std::vector<uint256> inc, ch;
    uint256 inc_missing, ch_missing;
    int32_t threshold{0};
    void build(dash::ShareTracker& t, int32_t threshold_, int32_t droppable) {
        threshold = threshold_;
        uint64_t id = 1;
        inc_missing = mk(0xfffffff001ULL);
        ch_missing  = mk(0xfffffff002ULL);
        inc = run(t, inc_missing, threshold + 50, kBitsNormal, id);
        verify_all(t, inc);
        for (int k = 0; k < 3; ++k)
            verify_all(t, run(t, inc[inc.size() - 6 - 3 * k], 2 + k, kBitsNormal, id));
        ch = run(t, ch_missing, threshold + droppable, kBitsHarder, id);
    }
    int ch_present(dash::ShareTracker& t) const {
        int n = 0;
        for (const auto& h : ch) n += t.chain.contains(h) ? 1 : 0;
        return n;
    }
};

int drain(dash::ShareTracker& t, int32_t threshold, int cap, const std::function<bool(const uint256&)>& ex) {
    int total = 0;
    for (int pass = 0; pass < 10000; ++pass) {
        const auto r = dash::drop_tails(t, threshold, cap, ex);
        total += r.dropped;
        if (r.dropped == 0) break;
    }
    return total;
}

std::vector<uint256> present_sorted(dash::ShareTracker& t, const Replay& r) {
    std::vector<uint256> v;
    for (const auto* seg : {&r.inc, &r.ch})
        for (const auto& h : *seg) if (t.chain.contains(h)) v.push_back(h);
    std::sort(v.begin(), v.end());
    return v;
}

} // namespace

TEST(DashSupersedeExemptTail, TailsKeysAreNeverChainShares)
{
    // The root cause: every tails key is a missing parent, before and after removals.
    for (uint32_t seed = 1; seed <= 100; ++seed) {
        std::mt19937 rng(seed);
        dash::ShareTracker t;
        uint64_t id = 1;
        const int nseg = 1 + static_cast<int>(rng() % 3);
        for (int s = 0; s < nseg; ++s) {
            auto seg = run(t, mk(0xfffffff100ULL + s), 30 + static_cast<int32_t>(rng() % 80), kBitsNormal, id);
            if (rng() % 2) run(t, mk(0xfffffff100ULL + s), 1 + static_cast<int32_t>(rng() % 40), kBitsNormal, id);
            for (int f = 0, nf = static_cast<int>(rng() % 4); f < nf; ++f)
                run(t, seg[rng() % seg.size()], 1 + static_cast<int32_t>(rng() % 30), kBitsNormal, id);
        }
        dash::SupersedeHint any;
        any.active = true;
        for (int pass = 0; pass < 6; ++pass) {
            for (const auto& [key, heads] : t.chain.get_tails()) {
                ASSERT_FALSE(t.chain.contains(key)) << "seed " << seed << " pass " << pass;
                any.target_segment_last = t.chain.get_last(key);   // == key itself
                EXPECT_EQ(any.target_segment_last, key);
                EXPECT_FALSE(master_exempt(t, any, key)) << "the old check can never fire";
                EXPECT_TRUE(dash::supersede_exempt_tail(any, key));
            }
            dash::drop_tails(t, 20, 7, [](const uint256&) { return false; });
        }
    }
}

class DashSupersedeExemptTailReplay : public ::testing::TestWithParam<int32_t> {};

TEST_P(DashSupersedeExemptTailReplay, ChallengerKeptWhileHintActiveAndConvergenceCompletes)
{
    const int32_t droppable = GetParam();
    constexpr int32_t kThr = 60;

    // The hint the node would hold: the real detector on the real tracker.
    dash::ShareTracker probe;
    Replay rp;
    rp.build(probe, kThr, droppable);
    const auto hint = probe.compute_supersede_hint(rp.inc.back(), 400);
    ASSERT_TRUE(hint.active) << "the replay must be a genuine restart-reorg";
    ASSERT_EQ(hint.target_head, rp.ch.back());
    ASSERT_EQ(hint.target_segment_last, rp.ch_missing);

    // MASTER: the challenger's bottom is trimmed mid-convergence (the defect).
    {
        dash::ShareTracker t; Replay r; r.build(t, kThr, droppable);
        drain(t, kThr, 0, [&](const uint256& k) { return master_exempt(t, hint, k); });
        EXPECT_EQ(r.ch_present(t), kThr - 1)
            << "master trims " << (droppable + 1) << " challenger shares (the lab dropped " << droppable << ")";
    }
    // FIX: every challenger share kept, uncapped and capped; the incumbent side
    // is trimmed exactly as with no exemption.
    for (int cap : {0, dash::kCleanDropTailsMaxPerPass}) {
        dash::ShareTracker t; Replay r; r.build(t, kThr, droppable);
        dash::ShareTracker ref; Replay rr; rr.build(ref, kThr, droppable);
        drain(t, kThr, cap, [&](const uint256& k) { return dash::supersede_exempt_tail(hint, k); });
        drain(ref, kThr, 0, [&](const uint256& k) { return k == rr.ch_missing; });
        EXPECT_EQ(r.ch_present(t), static_cast<int>(r.ch.size())) << "cap " << cap;
        EXPECT_EQ(present_sorted(t, r), present_sorted(ref, rr)) << "cap " << cap;
    }
    // CONVERGENCE COMPLETES: the elevated budget verifies the challenger, it
    // wins (it is now the incumbent), the hint clears, the exemption lapses, and
    // trimming reaches the same state as never exempting at all.
    {
        dash::ShareTracker t; Replay r; r.build(t, kThr, droppable);
        auto h1 = t.compute_supersede_hint(r.inc.back(), 400);
        ASSERT_TRUE(h1.active);
        drain(t, kThr, dash::kCleanDropTailsMaxPerPass,
              [&](const uint256& k) { return dash::supersede_exempt_tail(h1, k); });
        ASSERT_EQ(r.ch_present(t), static_cast<int>(r.ch.size()));
        verify_all(t, r.ch);
        const auto h2 = t.compute_supersede_hint(r.ch.back(), 400);   // flipped: C is best
        EXPECT_FALSE(h2.active);
        drain(t, kThr, dash::kCleanDropTailsMaxPerPass,
              [&](const uint256& k) { return dash::supersede_exempt_tail(h2, k); });

        dash::ShareTracker ref; Replay rr; rr.build(ref, kThr, droppable);
        verify_all(ref, rr.ch);
        drain(ref, kThr, 0, [](const uint256&) { return false; });
        EXPECT_EQ(present_sorted(t, r), present_sorted(ref, rr));
        EXPECT_TRUE(t.chain.contains(r.ch.back())) << "the winning head and its window stay";
        EXPECT_EQ(r.ch_present(t), kThr - 1);
    }
}

INSTANTIATE_TEST_SUITE_P(Lab, DashSupersedeExemptTailReplay,
                         ::testing::Values(804 /* 11-18 05:26 */, 688 /* 11-18 00:06 */));

TEST(DashSupersedeExemptTail, ExemptionLapsesSoTheSegmentCannotGrowUnbounded)
{
    constexpr int32_t kThr = 60;
    dash::ShareTracker t; Replay r; r.build(t, kThr, 100);
    dash::ShareTracker ref; Replay rr; rr.build(ref, kThr, 100);
    const auto hint = t.compute_supersede_hint(r.inc.back(), 400);
    ASSERT_TRUE(hint.active);
    uint64_t id = 5'000'000, id_ref = 5'000'000;
    uint256 tip = r.ch.back(), tip_ref = rr.ch.back();

    // While the hint is active the challenger is kept whole, even as it grows.
    for (int pass = 0; pass < 20; ++pass) {
        auto more = run(t, tip, 3, kBitsHarder, id);
        r.ch.insert(r.ch.end(), more.begin(), more.end());
        tip = more.back();
        auto more_ref = run(ref, tip_ref, 3, kBitsHarder, id_ref);
        rr.ch.insert(rr.ch.end(), more_ref.begin(), more_ref.end());
        tip_ref = more_ref.back();
        dash::drop_tails(t, kThr, dash::kCleanDropTailsMaxPerPass,
                         [&](const uint256& k) { return dash::supersede_exempt_tail(hint, k); });
        ASSERT_EQ(r.ch_present(t), static_cast<int>(r.ch.size()));
    }
    // The hint clears (gate_supersede_convergence: stall -> denylist, or the
    // challenger wins). An inactive hint exempts nothing...
    const dash::SupersedeHint cleared{};
    for (const auto& [key, heads] : t.chain.get_tails())
        EXPECT_FALSE(dash::supersede_exempt_tail(cleared, key));
    // ...and a hint on ANOTHER segment does not exempt this one.
    dash::SupersedeHint other = hint;
    other.target_segment_last = r.inc_missing;
    EXPECT_FALSE(dash::supersede_exempt_tail(other, r.ch_missing));
    // Trimming catches up to the never-exempted state.
    drain(t, kThr, dash::kCleanDropTailsMaxPerPass,
          [&](const uint256& k) { return dash::supersede_exempt_tail(cleared, k); });
    drain(ref, kThr, 0, [](const uint256&) { return false; });
    EXPECT_EQ(present_sorted(t, r), present_sorted(ref, rr));
    EXPECT_EQ(r.ch_present(t), kThr - 1);
}
