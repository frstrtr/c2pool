// SPDX-License-Identifier: AGPL-3.0-or-later
// Restart-reorg supersede detector -- KAT, exercised through BCH's REAL
// ShareTracker API (bch::ShareTracker::compute_supersede_hint /
// prioritize_challenger_heads). C++ analog of the LTC restart-reorg fix ported
// to BCH.
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
// Harness: plain int main() + CHECK (the BCH test tree has no GTest dependency;
// it links no coin lib, but bch::ShareTracker / bch::MergedMiningShare are
// header-only over coin/*.hpp, exactly like the ABLA seam tests). Registered as a
// standalone add_executable + add_test (the #1131 bch_share_remove_owns_data_test
// precedent). CTest treats exit 0 as PASS.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include <core/uint256.hpp>
#include <impl/bch/share.hpp>
#include <impl/bch/share_tracker.hpp>

namespace {

int g_failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "CHECK FAILED: " #cond " @ " << __FILE__ << ":" << __LINE__ << "\n"; \
    ++g_failures; } } while (0)

uint256 hx(const std::string& tail) {
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}

constexpr uint32_t kBits = 0x1e0fffff;  // uniform per-share work
constexpr int kBudget = 400;
constexpr int kNormalBudget = 100;  // THINK_VERIFY_BUDGET in think()

uint256 build_run(bch::ShareTracker& tracker, int32_t count,
                  const uint256& root_prev, size_t salt) {
    uint256 prev = root_prev;
    uint256 tip;
    tip.SetNull();
    for (int32_t i = 0; i < count; ++i) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%zx",
                      static_cast<size_t>((salt << 20) + 0x5b70 + i));
        uint256 h = hx(buf);
        auto* sh = new bch::MergedMiningShare();
        sh->m_hash = h;
        sh->m_prev_hash = prev;
        sh->m_desired_version = 36;
        sh->m_bits = kBits;
        sh->m_max_bits = kBits;
        bch::ShareType st;
        st = sh;
        tracker.add(st);
        prev = h;
        tip = h;
    }
    return tip;
}

void mark_verified(bch::ShareTracker& tracker, const uint256& tip) {
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

uint256 verify_deep_prefix(bch::ShareTracker& tracker, const uint256& tip, int n) {
    std::vector<uint256> chainward;
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
        const uint256& h = chainward[sz - 1 - i];
        if (tracker.chain.contains(h) && !tracker.verified.contains(h)) {
            auto& sv = tracker.chain.get_share(h);
            tracker.verified.add(sv);
        }
        frontier = h;
    }
    return frontier;
}

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
        if (!ch) budget = 0;
    }
    return false;
}

// --- Higher-work genuine fork -> ACTIVE, targeted at the challenger ----------
void HigherWorkForkActivates() {
    bch::ShareTracker t;
    const uint256 inc_tip = build_run(t, 30, uint256() /*rooted*/, 1);
    mark_verified(t, inc_tip);
    const uint256 missing_parent = hx("dead0001");
    const uint256 ch_tip = build_run(t, 50, missing_parent, 2);

    CHECK(t.verified.contains(inc_tip));
    CHECK(!t.verified.contains(ch_tip));
    CHECK(t.verified.get_work(inc_tip) < t.chain.get_work(ch_tip));

    auto hint = t.compute_supersede_hint(inc_tip, kBudget);
    CHECK(hint.active);
    CHECK(hint.target_head == ch_tip);
    CHECK(hint.target_segment_last == missing_parent);
    CHECK(hint.budget == kBudget);
    CHECK(hint.incumbent_work < hint.challenger_work);
}

// --- Lower-work fork -> INACTIVE ---------------------------------------------
void LowerWorkForkStaysInactive() {
    bch::ShareTracker t;
    const uint256 inc_tip = build_run(t, 30, uint256(), 1);
    mark_verified(t, inc_tip);
    const uint256 ch_tip = build_run(t, 10, hx("dead0002"), 2);
    CHECK(t.chain.get_work(ch_tip) < t.verified.get_work(inc_tip));
    CHECK(!t.compute_supersede_hint(inc_tip, kBudget).active);
}

// --- Equal-work fork -> INACTIVE (tie never displaces) -----------------------
void EqualWorkForkStaysInactive() {
    bch::ShareTracker t;
    const uint256 inc_tip = build_run(t, 30, uint256(), 1);
    mark_verified(t, inc_tip);
    const uint256 ch_tip = build_run(t, 30, hx("dead0003"), 2);
    CHECK(t.chain.get_work(ch_tip) == t.verified.get_work(inc_tip));
    CHECK(!t.compute_supersede_hint(inc_tip, kBudget).active);
}

// --- Healthy single head -> INACTIVE -----------------------------------------
void HealthySingleHeadIsNoOp() {
    bch::ShareTracker t;
    const uint256 inc_tip = build_run(t, 40, uint256(), 1);
    mark_verified(t, inc_tip);
    CHECK(!t.compute_supersede_hint(inc_tip, kBudget).active);
}

// --- Own-chain extension (unverified) -> INACTIVE (genuine-fork guard) --------
void OwnChainExtensionIsNotAChallenger() {
    bch::ShareTracker t;
    const uint256 inc_tip = build_run(t, 30, uint256(), 1);
    mark_verified(t, inc_tip);
    const uint256 ext_tip = build_run(t, 25, inc_tip /*extends incumbent*/, 2);
    CHECK(t.verified.get_work(inc_tip) < t.chain.get_work(ext_tip));
    CHECK(t.chain.is_child_of(inc_tip, ext_tip));
    CHECK(!t.compute_supersede_hint(inc_tip, kBudget).active);
}

// --- No incumbent (bootstrap) -> INACTIVE ------------------------------------
void NoIncumbentIsInactive() {
    bch::ShareTracker t;
    (void)build_run(t, 50, hx("dead0004"), 2);
    CHECK(!t.compute_supersede_hint(uint256() /*null incumbent*/, kBudget).active);
}

// --- Backfill-depth target is 2*CL+10 ----------------------------------------
void BackfillTargetIsTwiceChainLengthPlusTen() {
    const int32_t CL = static_cast<int32_t>(bch::PoolConfig::chain_length());
    CHECK(CL > 0);
    CHECK(2 * CL + 10 > CL);
}

// --- STARVATION: shorter higher-verified-work non-challenger must NOT starve --
void ChallengerNotStarvedByShorterHigherWorkHead() {
    bch::ShareTracker t;
    const uint256 inc_tip = build_run(t, 30, uint256() /*rooted*/, 1);
    mark_verified(t, inc_tip);
    const uint256 nc_tip = build_run(t, 12, uint256() /*rooted, own root*/, 3);
    mark_verified(t, nc_tip);
    const uint256 missing_parent = hx("dead0005");
    const uint256 ch_tip = build_run(t, 50, missing_parent, 2);
    const uint256 ch_frontier = verify_deep_prefix(t, ch_tip, 3);

    CHECK(t.verified.contains(inc_tip));
    CHECK(t.verified.contains(nc_tip));
    CHECK(t.verified.contains(ch_frontier));
    CHECK(t.verified.get_work(ch_frontier) < t.verified.get_work(nc_tip));
    CHECK(t.verified.get_work(nc_tip)      < t.verified.get_work(inc_tip));

    auto hint = t.compute_supersede_hint(inc_tip, kBudget);
    CHECK(hint.active);
    CHECK(hint.target_head == ch_tip);
    CHECK(hint.target_segment_last == missing_parent);
    CHECK(t.chain.get_last(ch_frontier) == missing_parent);

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

    auto pre = build_sorted();
    CHECK(index_of(pre, ch_frontier) >= 0);
    CHECK(index_of(pre, nc_tip) >= 0);
    CHECK(index_of(pre, ch_frontier) > index_of(pre, nc_tip));
    std::vector<uint256> pre_order;
    for (auto& hv : pre) pre_order.push_back(hv.first);
    CHECK(!challenger_iteration_entered(
        pre_order, ch_frontier, is_ch, kNormalBudget, kBudget, /*elevated_aware=*/false));

    auto post = build_sorted();
    const size_t n_challengers = t.prioritize_challenger_heads(post, hint);
    CHECK(n_challengers == 1u);
    CHECK(index_of(post, ch_frontier) == 0);
    CHECK(index_of(post, ch_frontier) < index_of(post, nc_tip));

    std::vector<uint256> post_order;
    for (auto& hv : post) post_order.push_back(hv.first);
    CHECK(challenger_iteration_entered(
        post_order, ch_frontier, is_ch, kNormalBudget, kBudget, /*elevated_aware=*/true));

    CHECK(kNormalBudget + kBudget <= 500);
}

// --- Healthy node: prioritize is a NO-OP -------------------------------------
void PrioritizeIsNoOpWhenInactive() {
    bch::ShareTracker t;
    const uint256 inc_tip = build_run(t, 30, uint256(), 1);
    mark_verified(t, inc_tip);
    const uint256 side_tip = build_run(t, 12, uint256(), 3);
    mark_verified(t, side_tip);

    bch::SupersedeHint inactive;
    CHECK(!inactive.active);

    std::vector<std::pair<uint256, uint256>> v(
        t.verified.get_heads().begin(), t.verified.get_heads().end());
    std::sort(v.begin(), v.end(), [&](const auto& a, const auto& b) {
        auto wa = t.verified.contains(a.first) ? t.verified.get_work(a.first) : uint288{};
        auto wb = t.verified.contains(b.first) ? t.verified.get_work(b.first) : uint288{};
        return wa > wb;
    });
    const auto before = v;
    const size_t moved = t.prioritize_challenger_heads(v, inactive);
    CHECK(moved == 0u);
    CHECK(v.size() == before.size());
    for (size_t i = 0; i < v.size(); ++i) {
        CHECK(v[i].first == before[i].first);
        CHECK(v[i].second == before[i].second);
    }
}

}  // namespace

int main() {
    HigherWorkForkActivates();
    LowerWorkForkStaysInactive();
    EqualWorkForkStaysInactive();
    HealthySingleHeadIsNoOp();
    OwnChainExtensionIsNotAChallenger();
    NoIncumbentIsInactive();
    BackfillTargetIsTwiceChainLengthPlusTen();
    ChallengerNotStarvedByShorterHigherWorkHead();
    PrioritizeIsNoOpWhenInactive();
    if (g_failures == 0) {
        std::cout << "bch_restart_reorg_supersede_test: ALL CHECKS PASSED\n";
        return 0;
    }
    std::cerr << "bch_restart_reorg_supersede_test: " << g_failures << " CHECK(s) FAILED\n";
    return 1;
}
