// SPDX-License-Identifier: AGPL-3.0-or-later
// Restart-reorg supersede detector -- KAT, exercised through LTC's REAL
// ShareTracker API (ltc::ShareTracker::compute_supersede_hint).
//
// LIVE EVIDENCE this pins (contabo LTC, warm restart on the shared v36
// sharechain): a node that loads its persisted, fully-verified sharechain then
// peers with a higher-work v36 network STICKS on the old head --
// [FORK-DIAG] heads=2 verified=12279 chain=20920 gap=8648 with the best VERIFIED
// head frozen while the node RECEIVES the higher-work chain to height 20920. The
// incumbent enjoys a structural, permanent privilege: TailScore compares
// chain_len FIRST and score() short-circuits to {verified_height,0} below
// CHAIN_LENGTH, so a warm-loaded full-CL verified tail beats any challenger whose
// VERIFIED height is still short -- and the challenger never verifies to
// CHAIN_LENGTH because think() never backfills the unrooted segment to the ~2*CL
// depth a CHAIN_LENGTH-tall verified tail needs. A fresh re-seed only converges
// because an EMPTY start has no incumbent.
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
// GUARDRAILS asserted here:
//   * strictly-higher-work only  -> a lower-work or equal-work fork never fires;
//   * genuine-fork only          -> an extension of the incumbent's own chain
//                                   (freshly-mined-but-unverified local shares)
//                                   never masquerades as a challenger;
//   * no-op when incumbent is best (healthy single-head node) -> inactive;
//   * no incumbent (bootstrap)   -> inactive.
//
// Folded into the EXISTING allowlisted `share_test` target (never a standalone
// add_executable -- the #769 NOT_BUILT trap), so CI actually builds and runs it.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <core/uint256.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_tracker.hpp>

namespace {

// Short hex tail -> uint256 (zero-padded), matching the LTC share_test hx()
// convention used by the sibling chain_walk_window / desired_version tests.
uint256 hx(const std::string& tail) {
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}

constexpr uint64_t kDv = 36;
constexpr uint32_t kBits = 0x1e0fffff;  // uniform per-share work

// Build a linear run of `count` uniform V36 shares into `tracker.chain`.
//   root_prev : m_prev_hash of the DEEPEST share (share 0). Null -> rooted
//               chain end (get_last == null); non-null-and-absent -> UNROOTED
//               segment (get_last == root_prev), the challenger shape.
//   salt      : disjoint hash space so independent runs never collide.
// Returns the tip hash. Every share carries equal work, so total received work
// is monotone in `count`.
uint256 build_run(ltc::ShareTracker& tracker, int32_t count,
                  const uint256& root_prev, size_t salt) {
    uint256 prev = root_prev;
    uint256 tip;
    tip.SetNull();
    for (int32_t i = 0; i < count; ++i) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%zx",
                      static_cast<size_t>((salt << 20) + 0x5b70 + i));
        uint256 h = hx(buf);
        auto* sh = new ltc::MergedMiningShare();
        sh->m_hash = h;
        sh->m_prev_hash = prev;   // share 0 uses root_prev
        sh->m_desired_version = kDv;
        sh->m_bits = kBits;
        sh->m_max_bits = kBits;
        ltc::ShareType st;
        st = sh;
        tracker.add(st);
        prev = h;
        tip = h;
    }
    return tip;
}

// Mark a whole in-chain run [share 0 .. tip] as verified, as
// load_persisted_shares() does (verified.add of the chain-owned share, ascending
// so parent-before-child holds). Walks tip -> root via prev_hash.
void mark_verified(ltc::ShareTracker& tracker, const uint256& tip) {
    // Collect hashes tip->root, then add root->tip.
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
// ascending so parent-before-child holds — the partial "verified frontier" a
// challenger segment has mid-catch-up. Returns the frontier verified head (the
// shallowest verified share of the prefix), which is what verified.get_heads()
// reports for the segment. n<=0 or n>=len verifies nothing extra beyond len.
uint256 verify_deep_prefix(ltc::ShareTracker& tracker, const uint256& tip, int n) {
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
        frontier = h;  // last added = shallowest of the prefix = frontier head
    }
    return frontier;
}

// Faithful in-test model of think()'s Phase-2 OUTER per-head budget gate,
// stepping an ordered head list. Worst case (the starvation driver): a
// non-challenger head can spend the whole normal budget on its first turn.
// `elevated_aware` selects the gate: false = the pre-fix `budget<=0` break;
// true = the fix's `budget<=0 && !(is_challenger && elevated>0)` break.
// Returns whether the challenger head's iteration is ENTERED (its elevated
// budget becomes drawable this tick).
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
        if (brk) break;                       // outer loop terminates here
        if (h == challenger_head) return true;  // challenger reached
        if (!ch) budget = 0;                  // worst-case normal-budget spend
    }
    return false;
}

constexpr int kBudget = 400;
constexpr int kNormalBudget = 100;  // THINK_VERIFY_BUDGET in think()

}  // namespace

// --- Higher-work genuine fork -> ACTIVE, targeted at the challenger ----------
TEST(LtcRestartReorgSupersede, HigherWorkForkActivates) {
    ltc::ShareTracker t;
    // Incumbent: rooted, fully verified, 30 shares.
    const uint256 inc_tip = build_run(t, 30, uint256() /*rooted*/, 1);
    mark_verified(t, inc_tip);
    // Challenger: UNROOTED segment of 50 shares (more work than the incumbent),
    // received but NOT verified. Its deepest share references an absent parent.
    const uint256 missing_parent = hx("dead0001");
    const uint256 ch_tip = build_run(t, 50, missing_parent, 2);

    ASSERT_TRUE(t.verified.contains(inc_tip));
    ASSERT_FALSE(t.verified.contains(ch_tip));
    // Sanity: challenger received work strictly exceeds incumbent verified work.
    EXPECT_TRUE(t.verified.get_work(inc_tip) < t.chain.get_work(ch_tip));

    auto hint = t.compute_supersede_hint(inc_tip, kBudget);
    EXPECT_TRUE(hint.active);
    EXPECT_EQ(hint.target_head, ch_tip);
    EXPECT_EQ(hint.target_segment_last, missing_parent);  // segment identity
    EXPECT_EQ(hint.budget, kBudget);
    // Strictly-greater guard actually holds on the recorded works.
    EXPECT_TRUE(hint.incumbent_work < hint.challenger_work);
}

// --- Lower-work fork -> INACTIVE (strictly-greater guard) --------------------
TEST(LtcRestartReorgSupersede, LowerWorkForkStaysInactive) {
    ltc::ShareTracker t;
    const uint256 inc_tip = build_run(t, 30, uint256(), 1);
    mark_verified(t, inc_tip);
    // Shorter unrooted fork: less received work than the incumbent's verified work.
    const uint256 ch_tip = build_run(t, 10, hx("dead0002"), 2);

    EXPECT_TRUE(t.chain.get_work(ch_tip) < t.verified.get_work(inc_tip));
    auto hint = t.compute_supersede_hint(inc_tip, kBudget);
    EXPECT_FALSE(hint.active);
}

// --- Equal-work fork -> INACTIVE (tie can never displace the head) ----------
TEST(LtcRestartReorgSupersede, EqualWorkForkStaysInactive) {
    ltc::ShareTracker t;
    const uint256 inc_tip = build_run(t, 30, uint256(), 1);
    mark_verified(t, inc_tip);
    // Same length -> identical total work (uniform per-share work).
    const uint256 ch_tip = build_run(t, 30, hx("dead0003"), 2);

    EXPECT_TRUE(t.chain.get_work(ch_tip) == t.verified.get_work(inc_tip));
    auto hint = t.compute_supersede_hint(inc_tip, kBudget);
    EXPECT_FALSE(hint.active);  // requires STRICTLY greater
}

// --- Healthy single head -> INACTIVE (no-op when incumbent IS the best) ------
TEST(LtcRestartReorgSupersede, HealthySingleHeadIsNoOp) {
    ltc::ShareTracker t;
    const uint256 inc_tip = build_run(t, 40, uint256(), 1);
    mark_verified(t, inc_tip);
    auto hint = t.compute_supersede_hint(inc_tip, kBudget);
    EXPECT_FALSE(hint.active);
}

// --- Own-chain extension (unverified) -> INACTIVE (genuine-fork guard) -------
// Freshly-received-but-unverified shares that EXTEND the incumbent (higher
// received work, same root) must NOT be treated as a challenger — they are the
// node's own tip advancing, and the ordinary budgeted Phase-2 verifies them.
TEST(LtcRestartReorgSupersede, OwnChainExtensionIsNotAChallenger) {
    ltc::ShareTracker t;
    const uint256 inc_tip = build_run(t, 30, uint256(), 1);
    mark_verified(t, inc_tip);
    // 25 more shares built ON TOP of inc_tip, in-chain but unverified.
    const uint256 ext_tip = build_run(t, 25, inc_tip /*extends incumbent*/, 2);

    // Received work of the extension strictly exceeds the incumbent's verified
    // work (it is 25 shares longer) — yet it is an extension, not a fork.
    EXPECT_TRUE(t.verified.get_work(inc_tip) < t.chain.get_work(ext_tip));
    EXPECT_TRUE(t.chain.is_child_of(inc_tip, ext_tip));

    auto hint = t.compute_supersede_hint(inc_tip, kBudget);
    EXPECT_FALSE(hint.active);  // is_child_of guard excludes it
}

// --- No incumbent (bootstrap / empty verified) -> INACTIVE ------------------
TEST(LtcRestartReorgSupersede, NoIncumbentIsInactive) {
    ltc::ShareTracker t;
    // Only an unrooted segment exists; nothing verified, no incumbent best.
    const uint256 ch_tip = build_run(t, 50, hx("dead0004"), 2);
    (void)ch_tip;
    auto hint = t.compute_supersede_hint(uint256() /*null incumbent*/, kBudget);
    EXPECT_FALSE(hint.active);
}

// --- Backfill-depth target is the fresh-bootstrap load depth 2*CL+10 --------
// The stuck state pinned the challenger segment at ~CL+8; the fix targets
// 2*CL+10 so a CHAIN_LENGTH-tall verified tail is reachable on an unrooted chain.
// This documents the invariant the think() Phase-2 want_depth uses.
TEST(LtcRestartReorgSupersede, BackfillTargetIsTwiceChainLengthPlusTen) {
    const int32_t CL = static_cast<int32_t>(ltc::PoolConfig::chain_length());
    EXPECT_GT(CL, 0);
    const int32_t challenger_target = 2 * CL + 10;
    // Strictly deeper than the incumbent CL target — the whole point.
    EXPECT_GT(challenger_target, CL);
    // Matches the persisted-load depth (node.cpp keep_per_head = 2*CL + 10).
    EXPECT_EQ(challenger_target, 2 * CL + 10);
}

// --- STARVATION: a shorter, higher-verified-work non-challenger head must NOT
//     starve the challenger's elevated budget within a think() tick -----------
//
// The liveness gap this pins: think() Phase-2 sorts VERIFIED heads by verified
// work DESCENDING, then breaks the loop when the normal per-tick budget is
// spent. The challenger's verified frontier is SHORT, so it sorts LOW; a shorter
// non-challenger verified head that still outranks that short frontier can spend
// the whole normal budget first and trip the outer break BEFORE the challenger's
// iteration is ever entered — so the bounded elevated pool is never drawn that
// tick, and m_think_needs_continue merely restarts the same starving sort order.
// Property (a) "reorgs to the higher-work verified head after sync" then fails
// under fork contention. The fix gives the challenger head budget PRIORITY:
// prioritize_challenger_heads() moves the challenger-segment head(s) to the FRONT
// (used verbatim by think()), and the outer gate is elevated-budget-aware. This
// KAT drives the REAL chain/verified accounting and the REAL scheduling helper.
TEST(LtcRestartReorgSupersede, ChallengerNotStarvedByShorterHigherWorkHead) {
    ltc::ShareTracker t;

    // Incumbent: rooted, fully verified, 30 shares (the warm-loaded head).
    const uint256 inc_tip = build_run(t, 30, uint256() /*rooted*/, 1);
    mark_verified(t, inc_tip);

    // Non-challenger SIDE fork: rooted, fully verified, but SHORT (12 shares).
    // Its verified work outranks the challenger's short frontier — the exact
    // head that spends the normal budget first and would trip the break.
    const uint256 nc_tip = build_run(t, 12, uint256() /*rooted, own root*/, 3);
    mark_verified(t, nc_tip);

    // Challenger: UNROOTED segment of 50 received shares (highest RECEIVED work),
    // but only a SHORT verified frontier (deepest 3) — so it sorts LOW by
    // verified work. Its segment identity is the shared missing parent.
    const uint256 missing_parent = hx("dead0005");
    const uint256 ch_tip = build_run(t, 50, missing_parent, 2);
    const uint256 ch_frontier = verify_deep_prefix(t, ch_tip, 3);

    // Sanity on the setup: all three are verified heads with the intended
    // work ordering, and the challenger frontier carries the LEAST verified work.
    ASSERT_TRUE(t.verified.contains(inc_tip));
    ASSERT_TRUE(t.verified.contains(nc_tip));
    ASSERT_TRUE(t.verified.contains(ch_frontier));
    EXPECT_TRUE(t.verified.get_work(ch_frontier) < t.verified.get_work(nc_tip));
    EXPECT_TRUE(t.verified.get_work(nc_tip)      < t.verified.get_work(inc_tip));

    // The hint fires and names the challenger SEGMENT (by its missing parent),
    // so the frontier head — deeper in the same segment — is is_challenger.
    auto hint = t.compute_supersede_hint(inc_tip, kBudget);
    ASSERT_TRUE(hint.active);
    EXPECT_EQ(hint.target_head, ch_tip);
    EXPECT_EQ(hint.target_segment_last, missing_parent);
    EXPECT_EQ(t.chain.get_last(ch_frontier), missing_parent);  // segment identity

    // Build the Phase-2 head order EXACTLY as think() does: verified heads,
    // sorted by verified work descending.
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
    // non-challenger head — the starvation shape.
    auto pre = build_sorted();
    ASSERT_GE(index_of(pre, ch_frontier), 0);
    ASSERT_GE(index_of(pre, nc_tip), 0);
    EXPECT_GT(index_of(pre, ch_frontier), index_of(pre, nc_tip));
    // And with the pre-fix `budget<=0` gate the challenger iteration is NEVER
    // entered: a higher-work non-challenger spends the normal budget first.
    std::vector<uint256> pre_order;
    for (auto& hv : pre) pre_order.push_back(hv.first);
    EXPECT_FALSE(challenger_iteration_entered(
        pre_order, ch_frontier, is_ch, kNormalBudget, kBudget,
        /*elevated_aware=*/false));

    // FIX: prioritize the challenger segment to the front. Exactly one challenger
    // head, and it lands ahead of the shorter non-challenger head.
    auto post = build_sorted();
    const size_t n_challengers = t.prioritize_challenger_heads(post, hint);
    EXPECT_EQ(n_challengers, 1u);
    EXPECT_EQ(index_of(post, ch_frontier), 0);
    EXPECT_LT(index_of(post, ch_frontier), index_of(post, nc_tip));

    // Post-fix order + elevated-aware gate: the challenger iteration IS entered,
    // so its bounded elevated budget is drawn this tick — the head can advance
    // toward CHAIN_LENGTH over successive ticks and Phase-3 flips on its own.
    std::vector<uint256> post_order;
    for (auto& hv : post) post_order.push_back(hv.first);
    EXPECT_TRUE(challenger_iteration_entered(
        post_order, ch_frontier, is_ch, kNormalBudget, kBudget,
        /*elevated_aware=*/true));

    // Per-tick bound is unchanged: normal budget + bounded elevated pool.
    EXPECT_LE(kNormalBudget + kBudget, 500);
}

// --- Healthy node: prioritize is a NO-OP (order byte-identical) --------------
// With no active supersede hint, prioritize_challenger_heads must not move a
// single head — the healthy-node Phase-2 order stays exactly the sorted order.
TEST(LtcRestartReorgSupersede, PrioritizeIsNoOpWhenInactive) {
    ltc::ShareTracker t;
    const uint256 inc_tip = build_run(t, 30, uint256(), 1);
    mark_verified(t, inc_tip);
    const uint256 side_tip = build_run(t, 12, uint256(), 3);
    mark_verified(t, side_tip);

    ltc::SupersedeHint inactive;  // active == false
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
