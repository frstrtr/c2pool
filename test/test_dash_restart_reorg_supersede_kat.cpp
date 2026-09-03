// SPDX-License-Identifier: AGPL-3.0-or-later
// Restart-reorg supersede detector -- KAT, exercised through DASH's REAL
// ShareTracker API (dash::ShareTracker::compute_supersede_hint /
// prioritize_challenger_heads). C++ analog of the LTC restart-reorg fix ported
// to DASH (live money on the hotel sharechain).
//
// THE DEFECT this pins: a node that loads its persisted, fully-verified
// sharechain then peers with a higher-work network STICKS on the old head.
// TailScore compares chain_len FIRST and score() short-circuits to
// {verified_height,0} below CHAIN_LENGTH, so a warm-loaded full-CL verified tail
// beats any challenger whose VERIFIED height is still short -- and the challenger
// never verifies to CHAIN_LENGTH because think() never backfills the unrooted
// segment to the ~2*CL depth a CHAIN_LENGTH-tall verified tail needs. A node with
// local hashrate then keeps extending its own verified incumbent = self-sustained
// minority fork.
//
// compute_supersede_hint is the visibility fix: it fires an ACTIVE hint iff a
// GENUINE competing fork exists whose RECEIVED cumulative work is STRICTLY
// greater than the incumbent best's VERIFIED work and whose verified height is
// still below CHAIN_LENGTH. think() then deepens that segment's backfill to
// 2*CL+10 and spends a bounded elevated verification budget on it, so it verifies
// to CHAIN_LENGTH and the EXISTING Phase-3 TailScore argmax flips on its own.
// This KAT drives the DECISION through the real chain/verified work accounting
// (get_work over ShareIndex.work) -- the exact mechanism -- without needing real
// PoW verification: the detector is a pure read over chain + verified.
//
// GUARDRAILS asserted here (mirror of the LTC KAT):
//   * strictly-higher-work only  -> a lower-work or equal-work fork never fires;
//   * genuine-fork only          -> an extension of the incumbent's own chain
//                                   (freshly-mined-but-unverified local shares)
//                                   never masquerades as a challenger;
//   * no-op when incumbent is best (healthy single-head node) -> inactive;
//   * no incumbent (bootstrap)   -> inactive;
//   * challenger-first scheduling -> the shorter higher-verified-work
//                                    non-challenger head does not starve it.
//
// Folded into the EXISTING allowlisted `test_dash_p2p_node` gtest target (the
// #154 test_dash_bulk_local_primary_kat.cpp precedent), never a standalone
// add_executable -- the #769 NOT_BUILT trap.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <core/uint256.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/share_tracker.hpp>

namespace {

// Short hex tail -> uint256 (zero-padded).
uint256 hx(const std::string& tail) {
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}

constexpr uint32_t kBits = 0x1e0fffff;  // uniform per-share work

// Build a linear run of `count` uniform DASH shares into `tracker.chain`.
//   root_prev : m_prev_hash of the DEEPEST share (share 0). Null -> rooted
//               chain end (get_last == null); non-null-and-absent -> UNROOTED
//               segment (get_last == root_prev), the challenger shape.
//   salt      : disjoint hash space so independent runs never collide.
// Returns the tip hash. Every share carries equal work, so total received work
// is monotone in `count`.
uint256 build_run(dash::ShareTracker& tracker, int32_t count,
                  const uint256& root_prev, size_t salt) {
    uint256 prev = root_prev;
    uint256 tip;
    tip.SetNull();
    for (int32_t i = 0; i < count; ++i) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%zx",
                      static_cast<size_t>((salt << 20) + 0x5b70 + i));
        uint256 h = hx(buf);
        auto* sh = new dash::DashShare();
        sh->m_hash = h;
        sh->m_prev_hash = prev;   // share 0 uses root_prev
        sh->m_desired_version = 16;
        sh->m_bits = kBits;
        sh->m_max_bits = kBits;
        dash::ShareType st;
        st = sh;
        tracker.add(st);
        prev = h;
        tip = h;
    }
    return tip;
}

// Mark a whole in-chain run [share 0 .. tip] as verified, as
// load_persisted_shares() does (ascending so parent-before-child holds).
void mark_verified(dash::ShareTracker& tracker, const uint256& tip) {
    std::vector<uint256> chainward;
    uint256 cur = tip;
    while (!cur.IsNull() && tracker.chain.contains(cur)) {
        chainward.push_back(cur);
        auto* idx = tracker.chain.get_index(cur);
        cur = idx ? idx->tail : uint256();
    }
    for (auto it = chainward.rbegin(); it != chainward.rend(); ++it) {
        if (tracker.chain.contains(*it) && !tracker.verified.contains(*it)) {
            auto& sv = tracker.chain.get_share(*it);
            tracker.verified.add(sv);
        }
    }
}

// Verify only the DEEPEST `n` shares of an in-chain run (root .. root+n-1),
// ascending -- the partial "verified frontier" a challenger segment has
// mid-catch-up. Returns the frontier verified head (shallowest verified share).
uint256 verify_deep_prefix(dash::ShareTracker& tracker, const uint256& tip, int n) {
    std::vector<uint256> chainward;  // tip -> root
    uint256 cur = tip;
    while (!cur.IsNull() && tracker.chain.contains(cur)) {
        chainward.push_back(cur);
        auto* idx = tracker.chain.get_index(cur);
        cur = idx ? idx->tail : uint256();
    }
    const int sz = static_cast<int>(chainward.size());
    if (n > sz) n = sz;
    uint256 frontier;
    for (int i = 0; i < n; ++i) {
        const uint256& h = chainward[sz - 1 - i];  // root first (ascending)
        if (tracker.chain.contains(h) && !tracker.verified.contains(h)) {
            auto& sv = tracker.chain.get_share(h);
            tracker.verified.add(sv);
        }
        frontier = h;
    }
    return frontier;
}

// Faithful in-test model of think()'s Phase-2 OUTER per-head budget gate.
// `elevated_aware` selects the gate: false = the pre-fix `budget<=0` break;
// true = the fix's `budget<=0 && !(is_challenger && elevated>0)` break.
bool challenger_iteration_entered(
        const std::vector<uint256>& order, const uint256& challenger_head,
        const std::function<bool(const uint256&)>& is_challenger,
        int normal_budget, int elevated_budget, bool elevated_aware) {
    int budget = normal_budget, elevated = elevated_budget;
    for (const auto& h : order) {
        const bool ch = is_challenger(h);
        const bool brk = elevated_aware
                             ? (budget <= 0 && !(ch && elevated > 0))
                             : (budget <= 0);
        if (brk) break;
        if (h == challenger_head) return true;
        if (!ch) budget = 0;  // worst-case normal-budget spend
    }
    return false;
}

constexpr int kBudget = 400;
constexpr int kNormalBudget = 100;  // THINK_VERIFY_BUDGET in think()

}  // namespace

// --- Higher-work genuine fork -> ACTIVE, targeted at the challenger ----------
TEST(DashRestartReorgSupersede, HigherWorkForkActivates) {
    dash::ShareTracker t;
    const uint256 inc_tip = build_run(t, 30, uint256() /*rooted*/, 1);
    mark_verified(t, inc_tip);
    const uint256 missing_parent = hx("dead0001");
    const uint256 ch_tip = build_run(t, 50, missing_parent, 2);

    ASSERT_TRUE(t.verified.contains(inc_tip));
    ASSERT_FALSE(t.verified.contains(ch_tip));
    EXPECT_TRUE(t.verified.get_work(inc_tip) < t.chain.get_work(ch_tip));

    auto hint = t.compute_supersede_hint(inc_tip, kBudget);
    EXPECT_TRUE(hint.active);
    EXPECT_EQ(hint.target_head, ch_tip);
    EXPECT_EQ(hint.target_segment_last, missing_parent);
    EXPECT_EQ(hint.budget, kBudget);
    EXPECT_TRUE(hint.incumbent_work < hint.challenger_work);
}

// --- Lower-work fork -> INACTIVE (strictly-greater guard) --------------------
TEST(DashRestartReorgSupersede, LowerWorkForkStaysInactive) {
    dash::ShareTracker t;
    const uint256 inc_tip = build_run(t, 30, uint256(), 1);
    mark_verified(t, inc_tip);
    const uint256 ch_tip = build_run(t, 10, hx("dead0002"), 2);

    EXPECT_TRUE(t.chain.get_work(ch_tip) < t.verified.get_work(inc_tip));
    auto hint = t.compute_supersede_hint(inc_tip, kBudget);
    EXPECT_FALSE(hint.active);
}

// --- Equal-work fork -> INACTIVE (tie can never displace the head) ----------
TEST(DashRestartReorgSupersede, EqualWorkForkStaysInactive) {
    dash::ShareTracker t;
    const uint256 inc_tip = build_run(t, 30, uint256(), 1);
    mark_verified(t, inc_tip);
    const uint256 ch_tip = build_run(t, 30, hx("dead0003"), 2);

    EXPECT_TRUE(t.chain.get_work(ch_tip) == t.verified.get_work(inc_tip));
    auto hint = t.compute_supersede_hint(inc_tip, kBudget);
    EXPECT_FALSE(hint.active);
}

// --- Healthy single head -> INACTIVE (no-op when incumbent IS the best) ------
TEST(DashRestartReorgSupersede, HealthySingleHeadIsNoOp) {
    dash::ShareTracker t;
    const uint256 inc_tip = build_run(t, 40, uint256(), 1);
    mark_verified(t, inc_tip);
    auto hint = t.compute_supersede_hint(inc_tip, kBudget);
    EXPECT_FALSE(hint.active);
}

// --- Own-chain extension (unverified) -> INACTIVE (genuine-fork guard) -------
TEST(DashRestartReorgSupersede, OwnChainExtensionIsNotAChallenger) {
    dash::ShareTracker t;
    const uint256 inc_tip = build_run(t, 30, uint256(), 1);
    mark_verified(t, inc_tip);
    const uint256 ext_tip = build_run(t, 25, inc_tip /*extends incumbent*/, 2);

    EXPECT_TRUE(t.verified.get_work(inc_tip) < t.chain.get_work(ext_tip));
    EXPECT_TRUE(t.chain.is_child_of(inc_tip, ext_tip));

    auto hint = t.compute_supersede_hint(inc_tip, kBudget);
    EXPECT_FALSE(hint.active);  // is_child_of guard excludes it
}

// --- No incumbent (bootstrap / empty verified) -> INACTIVE ------------------
TEST(DashRestartReorgSupersede, NoIncumbentIsInactive) {
    dash::ShareTracker t;
    const uint256 ch_tip = build_run(t, 50, hx("dead0004"), 2);
    (void)ch_tip;
    auto hint = t.compute_supersede_hint(uint256() /*null incumbent*/, kBudget);
    EXPECT_FALSE(hint.active);
}

// --- Backfill-depth target is the fresh-bootstrap load depth 2*CL+10 --------
TEST(DashRestartReorgSupersede, BackfillTargetIsTwiceChainLengthPlusTen) {
    const int32_t CL = static_cast<int32_t>(dash::SharechainConfig::chain_length());
    EXPECT_GT(CL, 0);
    const int32_t challenger_target = 2 * CL + 10;
    EXPECT_GT(challenger_target, CL);
    EXPECT_EQ(challenger_target, 2 * CL + 10);
}

// --- STARVATION: a shorter, higher-verified-work non-challenger head must NOT
//     starve the challenger's elevated budget within a think() tick -----------
TEST(DashRestartReorgSupersede, ChallengerNotStarvedByShorterHigherWorkHead) {
    dash::ShareTracker t;

    const uint256 inc_tip = build_run(t, 30, uint256() /*rooted*/, 1);
    mark_verified(t, inc_tip);

    // Non-challenger SIDE fork: rooted, fully verified, but SHORT (12 shares).
    const uint256 nc_tip = build_run(t, 12, uint256() /*rooted, own root*/, 3);
    mark_verified(t, nc_tip);

    // Challenger: UNROOTED segment of 50 received shares (highest RECEIVED work),
    // only a SHORT verified frontier (deepest 3) -> sorts LOW by verified work.
    const uint256 missing_parent = hx("dead0005");
    const uint256 ch_tip = build_run(t, 50, missing_parent, 2);
    const uint256 ch_frontier = verify_deep_prefix(t, ch_tip, 3);

    ASSERT_TRUE(t.verified.contains(inc_tip));
    ASSERT_TRUE(t.verified.contains(nc_tip));
    ASSERT_TRUE(t.verified.contains(ch_frontier));
    EXPECT_TRUE(t.verified.get_work(ch_frontier) < t.verified.get_work(nc_tip));
    EXPECT_TRUE(t.verified.get_work(nc_tip)      < t.verified.get_work(inc_tip));

    auto hint = t.compute_supersede_hint(inc_tip, kBudget);
    ASSERT_TRUE(hint.active);
    EXPECT_EQ(hint.target_head, ch_tip);
    EXPECT_EQ(hint.target_segment_last, missing_parent);
    EXPECT_EQ(t.chain.get_last(ch_frontier), missing_parent);

    auto build_sorted = [&]() {
        std::vector<std::pair<uint256, uint256>> v(
            t.verified.get_heads().begin(), t.verified.get_heads().end());
        std::sort(v.begin(), v.end(), [&](const auto& a, const auto& b) {
            auto wa = t.verified.contains(a.first) ? t.verified.get_work(a.first) : uint288{};
            auto wb = t.verified.contains(b.first) ? t.verified.get_work(b.first) : uint288{};
            return wa > wb;
        });
        return v;
    };
    auto index_of = [](const std::vector<std::pair<uint256, uint256>>& v,
                       const uint256& h) -> int {
        for (int i = 0; i < static_cast<int>(v.size()); ++i)
            if (v[i].first == h) return i;
        return -1;
    };
    auto is_ch = [&](const uint256& h) -> bool {
        return t.chain.get_last(h) == hint.target_segment_last;
    };

    // PRE-fix order: the challenger frontier sorts AFTER the shorter
    // non-challenger head, and the pre-fix gate never enters its iteration.
    auto pre = build_sorted();
    ASSERT_GE(index_of(pre, ch_frontier), 0);
    ASSERT_GE(index_of(pre, nc_tip), 0);
    EXPECT_GT(index_of(pre, ch_frontier), index_of(pre, nc_tip));
    std::vector<uint256> pre_order;
    for (auto& hv : pre) pre_order.push_back(hv.first);
    EXPECT_FALSE(challenger_iteration_entered(
        pre_order, ch_frontier, is_ch, kNormalBudget, kBudget,
        /*elevated_aware=*/false));

    // FIX: prioritize the challenger segment to the front.
    auto post = build_sorted();
    const size_t n_challengers = t.prioritize_challenger_heads(post, hint);
    EXPECT_EQ(n_challengers, 1u);
    EXPECT_EQ(index_of(post, ch_frontier), 0);
    EXPECT_LT(index_of(post, ch_frontier), index_of(post, nc_tip));

    std::vector<uint256> post_order;
    for (auto& hv : post) post_order.push_back(hv.first);
    EXPECT_TRUE(challenger_iteration_entered(
        post_order, ch_frontier, is_ch, kNormalBudget, kBudget,
        /*elevated_aware=*/true));

    EXPECT_LE(kNormalBudget + kBudget, 500);
}

// --- Healthy node: prioritize is a NO-OP (order byte-identical) --------------
TEST(DashRestartReorgSupersede, PrioritizeIsNoOpWhenInactive) {
    dash::ShareTracker t;
    const uint256 inc_tip = build_run(t, 30, uint256(), 1);
    mark_verified(t, inc_tip);
    const uint256 side_tip = build_run(t, 12, uint256(), 3);
    mark_verified(t, side_tip);

    dash::SupersedeHint inactive;  // active == false
    ASSERT_FALSE(inactive.active);

    std::vector<std::pair<uint256, uint256>> v(
        t.verified.get_heads().begin(), t.verified.get_heads().end());
    std::sort(v.begin(), v.end(), [&](const auto& a, const auto& b) {
        auto wa = t.verified.contains(a.first) ? t.verified.get_work(a.first) : uint288{};
        auto wb = t.verified.contains(b.first) ? t.verified.get_work(b.first) : uint288{};
        return wa > wb;
    });
    const auto before = v;
    const size_t moved = t.prioritize_challenger_heads(v, inactive);
    EXPECT_EQ(moved, 0u);
    ASSERT_EQ(v.size(), before.size());
    for (size_t i = 0; i < v.size(); ++i) {
        EXPECT_EQ(v[i].first, before[i].first);
        EXPECT_EQ(v[i].second, before[i].second);
    }
}
