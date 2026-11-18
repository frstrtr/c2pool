// SPDX-License-Identifier: AGPL-3.0-or-later
// clean_tracker Step 3 (drop tails) with a per-pass cap: dash::drop_tails.
//
// Step 3 runs under the exclusive tracker lock and one removal costs
// milliseconds on a full tracker, so a pass now drops at most
// kCleanDropTailsMaxPerPass shares and leaves the rest to the next clean tick.
// What is pinned here:
//   - Uncapped drop_tails removes the SAME hashes in the SAME order as the
//     previous inline loop (kept below verbatim as the reference).
//   - Capped passes repeated until nothing is left reach the IDENTICAL tracker
//     state as one uncapped pass: present/verified sets, heads, tails, reverse,
//     and the chain + TrackerView answers (height, last, work) of every share.
//     On the recorded incident shape (an 800-share droppable bottom under 5
//     heads, scaled: the threshold is a parameter, so the chain stays short)
//     and on many random forests (forks at random depths including the very
//     bottom, several disconnected segments, partly verified, the restart-
//     reorg exemption on and off).
//   - Every pass drops <= the cap.
//   - With shares arriving between passes, the capped chain is never larger
//     than the uncapped twin by more than the starting backlog, and the
//     difference drains to 0.
//   - The PPLNS input never changes: for every head, its newest
//     min_head_height-1 ancestors are present and identical at every pass and
//     in both trackers (the rule only ever removes shares beyond them; in
//     production the PPLNS window is CHAIN_LENGTH < 2*CHAIN_LENGTH+9).
//
// Folded into test_dash_p2p_node (beside test_dash_supersede_hint_equivalence).

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <core/uint256.hpp>
#include <impl/dash/clean_drop_tails.hpp>
#include <impl/dash/config_pool.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/share_tracker.hpp>

namespace {

uint256 hx(const std::string& tail) {
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}

constexpr uint32_t kBits = 0x1e0fffff;

// Deterministic forest builder: the same calls on two trackers build the same
// forest (same hashes), so one can be dropped uncapped and the other capped.
struct Forest {
    struct Seg { uint256 prev; int32_t count; };
    std::vector<uint256> all;      // every hash ever added, in order
};

uint256 make_hash(uint64_t id) {
    char buf[40];
    std::snprintf(buf, sizeof(buf), "d7a1%012llx", static_cast<unsigned long long>(id));
    return hx(buf);
}

// Adds `count` shares on top of `prev`; ids from `next_id`. Returns hashes oldest first.
std::vector<uint256> add_run(dash::ShareTracker& t, const uint256& prev0, int32_t count,
                             uint64_t& next_id, std::vector<uint256>& all)
{
    std::vector<uint256> out;
    uint256 prev = prev0;
    for (int32_t i = 0; i < count; ++i) {
        const uint256 h = make_hash(next_id++);
        auto* sh = new dash::DashShare();
        sh->m_hash = h;
        sh->m_prev_hash = prev;
        sh->m_desired_version = 16;
        sh->m_bits = kBits;
        sh->m_max_bits = kBits;
        dash::ShareType st;
        st = sh;
        t.add(st);
        out.push_back(h);
        all.push_back(h);
        prev = h;
    }
    return out;
}

void verify_upto(dash::ShareTracker& t, const std::vector<uint256>& seg, size_t upto) {
    for (size_t i = 0; i < upto && i < seg.size(); ++i)
        if (t.chain.contains(seg[i]) && !t.verified.contains(seg[i]))
            t.verified.add(t.chain.get_share(seg[i]));
}

// THE PREVIOUS INLINE LOOP (node.cpp clean_tracker Step 3 before the cap), verbatim
// except that the exemption is the same callable drop_tails takes.
std::vector<uint256> reference_drop(dash::ShareTracker& t, int32_t min_head_height,
                                    const std::function<bool(const uint256&)>& exempt)
{
    std::vector<uint256> removed;
    for (int iter = 0; iter < 1000; ++iter)
    {
        std::vector<uint256> to_remove;
        auto tails_copy = t.chain.get_tails();
        for (auto& [tail_hash, head_hashes] : tails_copy)
        {
            if (exempt(tail_hash)) continue;
            int32_t min_height = 0;
            for (auto& hh : head_hashes) {
                if (!t.chain.contains(hh)) continue;
                auto h = t.chain.get_height(hh);
                if (min_height == 0 || h < min_height)
                    min_height = h;
            }
            if (min_height < min_head_height) continue;
            auto& rev = t.chain.get_reverse();
            auto rev_it = rev.find(tail_hash);
            if (rev_it != rev.end())
                for (const auto& child : rev_it->second)
                    to_remove.push_back(child);
        }
        if (to_remove.empty()) break;
        for (const auto& aftertail : to_remove)
        {
            try {
                if (!t.chain.contains(aftertail)) continue;
                auto* idx = t.chain.get_index(aftertail);
                if (!idx) continue;
                if (!t.chain.get_tails().count(idx->tail)) continue;
                if (t.verified.contains(aftertail))
                    t.verified.remove(aftertail, /*owns_data=*/false);
                t.chain.remove(aftertail);
                removed.push_back(aftertail);
            } catch (...) {}
        }
    }
    return removed;
}

// Full observable state over every hash the forest ever had.
struct State {
    std::vector<uint256> present, verified;
    std::vector<std::pair<uint256, uint256>> heads;                 // head -> tail
    std::vector<std::pair<uint256, std::vector<uint256>>> tails;    // tail -> heads
    std::vector<std::pair<uint256, std::vector<uint256>>> reverse;  // parent -> children
    std::vector<std::pair<uint256, std::vector<uint256>>> vreverse;
    std::vector<std::string> answers;                               // per present hash
    bool operator==(const State&) const = default;
};

template <typename M>
std::vector<std::pair<uint256, std::vector<uint256>>> sorted_setmap(const M& m) {
    std::vector<std::pair<uint256, std::vector<uint256>>> out;
    for (const auto& [k, s] : m) {
        if (s.empty()) continue;   // p2pool treats an empty set as absent
        std::vector<uint256> v(s.begin(), s.end());
        std::sort(v.begin(), v.end());
        out.emplace_back(k, std::move(v));
    }
    std::sort(out.begin(), out.end());
    return out;
}

State snapshot(dash::ShareTracker& t, const std::vector<uint256>& all) {
    State s;
    for (const auto& h : all) {
        if (!t.chain.contains(h)) continue;
        s.present.push_back(h);
        const bool v = t.verified.contains(h);
        if (v) s.verified.push_back(h);
        std::string a = h.GetHex().substr(48) + " h=" + std::to_string(t.chain.get_height(h))
            + " last=" + t.chain.get_last(h).GetHex().substr(48)
            + " work=" + t.chain.get_work(h).GetHex()
            + " vh=" + std::to_string(t.chain.get_delta_to_last(h).height);
        if (v) a += " verified_h=" + std::to_string(t.verified.get_height(h))
                  + " verified_work=" + t.verified.get_work(h).GetHex();
        s.answers.push_back(std::move(a));
    }
    std::sort(s.present.begin(), s.present.end());
    std::sort(s.verified.begin(), s.verified.end());
    std::sort(s.answers.begin(), s.answers.end());
    for (const auto& [h, tl] : t.chain.get_heads()) s.heads.emplace_back(h, tl);
    std::sort(s.heads.begin(), s.heads.end());
    s.tails = sorted_setmap(t.chain.get_tails());
    s.reverse = sorted_setmap(t.chain.get_reverse());
    s.vreverse = sorted_setmap(t.verified.get_reverse());
    return s;
}

::testing::AssertionResult same_state(const State& a, const State& b) {
    if (a.present != b.present) return ::testing::AssertionFailure() << "present sets differ (" << a.present.size() << " vs " << b.present.size() << ")";
    if (a.verified != b.verified) return ::testing::AssertionFailure() << "verified sets differ";
    if (a.heads != b.heads) return ::testing::AssertionFailure() << "heads differ";
    if (a.tails != b.tails) return ::testing::AssertionFailure() << "tails differ";
    if (a.reverse != b.reverse) return ::testing::AssertionFailure() << "reverse differs";
    if (a.vreverse != b.vreverse) return ::testing::AssertionFailure() << "verified reverse differs";
    if (a.answers != b.answers) return ::testing::AssertionFailure() << "chain/TrackerView answers differ";
    return ::testing::AssertionSuccess();
}

// For every head: its `window` most recent ancestors (head included), walked by
// prev hash. The rule drops a tail's children only while EVERY head above it is
// >= min_head_height tall, so it stops with the shortest head min_head_height-1
// tall: any window <= min_head_height-1 is untouched. In production that is the
// PPLNS window CHAIN_LENGTH against 2*CHAIN_LENGTH+9.
std::map<uint256, std::vector<uint256>> windows(dash::ShareTracker& t, int32_t window) {
    std::map<uint256, std::vector<uint256>> out;
    for (const auto& [head, tl] : t.chain.get_heads()) {
        std::vector<uint256> w;
        uint256 cur = head;
        for (int32_t i = 0; i < window && t.chain.contains(cur); ++i) {
            w.push_back(cur);
            cur = t.chain.get_index(cur)->tail;
        }
        out[head] = std::move(w);
    }
    return out;
}

auto no_exempt = [](const uint256&) { return false; };

// The incident shape (VM504 11-18 05:26, scaled): one unrooted segment whose
// bottom 800 shares are droppable, 5 heads (4 short forks near the top).
struct Incident {
    std::vector<uint256> all;
    uint256 tip;                   // the main chain's tip
    int32_t threshold{0};
    void build(dash::ShareTracker& t, int32_t threshold_, int32_t droppable, int forks = 4) {
        threshold = threshold_;
        uint64_t id = 1;
        const uint256 missing = make_hash(0xfffffffff0ULL);    // missing parent = the tail
        auto main = add_run(t, missing, threshold + droppable + 20, id, all);
        tip = main.back();
        verify_upto(t, main, main.size() - 5);
        for (int k = 0; k < forks; ++k)   // forks off 6..15 below the tip, 3-6 long
            add_run(t, main[main.size() - 6 - 3 * k], 3 + k, id, all);
    }
};

} // namespace

TEST(DashCleanDropTails, UncappedEqualsPreviousLoopExactly)
{
    for (int32_t drop : {1, 7, 120, 800}) {
        dash::ShareTracker a, b;
        Incident ia, ib;
        ia.build(a, 60, drop);
        ib.build(b, 60, drop);
        const auto ref = reference_drop(a, 60, no_exempt);
        std::vector<uint256> got;
        const auto r = dash::drop_tails(b, 60, /*max_drop=*/0, no_exempt, &got);
        EXPECT_EQ(got, ref) << "removed-hash sequence differs, drop=" << drop;
        EXPECT_EQ(r.dropped, static_cast<int>(ref.size()));
        EXPECT_FALSE(r.capped);
        EXPECT_TRUE(same_state(snapshot(a, ia.all), snapshot(b, ib.all)));
    }
}

TEST(DashCleanDropTails, RecordedShape800CappedReachesUncappedState)
{
    dash::ShareTracker un, cap;
    Incident iu, ic;
    iu.build(un, 60, 800);
    ic.build(cap, 60, 800);
    const auto ref = reference_drop(un, 60, no_exempt);
    ASSERT_GE(ref.size(), 800u);

    const auto win_before = windows(cap, 60 - 1);
    int passes = 0, total = 0;
    for (;;) {
        const auto r = dash::drop_tails(cap, 60, dash::kCleanDropTailsMaxPerPass, no_exempt);
        ASSERT_LE(r.dropped, dash::kCleanDropTailsMaxPerPass);
        EXPECT_EQ(windows(cap, 60 - 1), win_before) << "PPLNS window changed at pass " << passes;
        ++passes;
        total += r.dropped;
        if (r.dropped == 0) break;
        ASSERT_LT(passes, 1000);
    }
    EXPECT_EQ(total, static_cast<int>(ref.size()));
    const int expected_passes = (static_cast<int>(ref.size()) + dash::kCleanDropTailsMaxPerPass - 1)
                                / dash::kCleanDropTailsMaxPerPass + 1;   // + the empty pass
    EXPECT_EQ(passes, expected_passes);
    EXPECT_TRUE(same_state(snapshot(un, iu.all), snapshot(cap, ic.all)));
    EXPECT_EQ(windows(un, 60 - 1), win_before);
}

TEST(DashCleanDropTails, RandomForestsCappedReachUncappedState)
{
    int checked = 0;
    for (uint32_t seed = 1; seed <= 300; ++seed) {
        std::mt19937 rng(seed);
        const int32_t threshold = 20 + static_cast<int32_t>(rng() % 30);
        const int cap = 1 + static_cast<int>(rng() % 40);
        const bool hint_on = (rng() % 3) == 0;

        // The same random script builds the forest on both trackers.
        auto build = [&](dash::ShareTracker& t, std::vector<uint256>& all) {
            std::mt19937 r2(seed * 7919u);
            uint64_t id = 1;
            std::vector<std::vector<uint256>> segs;
            const int nseg = 1 + static_cast<int>(r2() % 3);
            for (int s = 0; s < nseg; ++s) {
                const uint256 missing = make_hash(0xfffffff000ULL + s);
                const int32_t len = threshold + static_cast<int32_t>(r2() % 120);
                auto seg = add_run(t, missing, len, id, all);
                verify_upto(t, seg, r2() % (seg.size() + 1));
                segs.push_back(seg);
                if (r2() % 2 == 0) {
                    // a sibling of the bottom share: the tail itself has two
                    // children (chain.remove branch 4 on the first removal)
                    auto sib = add_run(t, missing, 1 + static_cast<int32_t>(r2() % (threshold + 60)), id, all);
                    verify_upto(t, sib, r2() % (sib.size() + 1));
                }
                const int forks = static_cast<int>(r2() % 5);
                for (int f = 0; f < forks; ++f) {
                    // fork from any depth, including the very bottom share
                    const size_t at = r2() % seg.size();
                    auto fk = add_run(t, seg[at], 1 + static_cast<int32_t>(r2() % (threshold + 40)), id, all);
                    verify_upto(t, fk, r2() % (fk.size() + 1));
                }
            }
            return segs;
        };
        dash::ShareTracker un, cp;
        std::vector<uint256> all_u, all_c;
        auto segs_u = build(un, all_u);
        (void)build(cp, all_c);
        ASSERT_EQ(all_u, all_c);

        // An exemption on a random segment, by segment id: its missing parent,
        // which is exactly the key of its entry in the tails map. (drop_tails
        // takes any predicate; this one really exempts, so the exempt path is
        // exercised on both sides. NOTE: node.cpp's own predicate never fires
        // today — it requires chain.contains(tails key), which is always false;
        // tracked in #2263 — so this pins drop_tails' plumbing, not production
        // exemption behaviour.)
        uint256 exempt_last;
        if (hint_on) {
            const auto& seg = segs_u[rng() % segs_u.size()];
            exempt_last = un.chain.get_last(seg.back());
        }
        auto exempt_for = [&](dash::ShareTracker&) {
            return [hint_on, exempt_last](const uint256& tail) -> bool {
                return hint_on && tail == exempt_last;
            };
        };

        const auto ref = reference_drop(un, threshold, exempt_for(un));
        {   // uncapped drop_tails (head-height cache) == the previous loop, step for step
            dash::ShareTracker sq;
            std::vector<uint256> all_s, seq;
            (void)build(sq, all_s);
            const auto r = dash::drop_tails(sq, threshold, 0, exempt_for(sq), &seq);
            ASSERT_EQ(seq, ref) << "removed-hash sequence differs, seed " << seed;
            EXPECT_EQ(r.dropped, static_cast<int>(ref.size()));
            EXPECT_TRUE(same_state(snapshot(un, all_u), snapshot(sq, all_s))) << "seed " << seed;
        }
        const auto win_before = windows(cp, threshold - 1);
        int total = 0, passes = 0;
        for (;;) {
            const auto r = dash::drop_tails(cp, threshold, cap, exempt_for(cp));
            ASSERT_LE(r.dropped, cap) << "seed " << seed;
            ASSERT_EQ(windows(cp, threshold - 1), win_before) << "seed " << seed << " pass " << passes;
            total += r.dropped;
            ++passes;
            if (r.dropped == 0) break;
            ASSERT_LT(passes, 5000) << "seed " << seed;
        }
        EXPECT_EQ(total, static_cast<int>(ref.size())) << "seed " << seed;
        EXPECT_TRUE(same_state(snapshot(un, all_u), snapshot(cp, all_c))) << "seed " << seed
            << " threshold " << threshold << " cap " << cap << " hint " << hint_on;
        ++checked;
    }
    EXPECT_EQ(checked, 300);
}

TEST(DashCleanDropTails, BacklogBoundedAndDrainsWithInflow)
{
    // Shares keep arriving on the main tip between clean passes (single head,
    // so every new share makes one more bottom layer eligible on both sides).
    // The capped chain never exceeds the uncapped twin by more than the
    // starting backlog, and the difference drains to 0.
    dash::ShareTracker un, cp;
    Incident iu, ic;
    iu.build(un, 60, 800, /*forks=*/0);
    ic.build(cp, 60, 800, /*forks=*/0);
    uint64_t id_u = 1'000'000, id_c = 1'000'000;
    uint256 tip_u = iu.tip, tip_c = ic.tip;

    std::size_t backlog0 = 0;
    std::size_t prev_diff = SIZE_MAX;
    for (int pass = 0; pass < 200; ++pass) {
        dash::drop_tails(un, 60, 0, no_exempt);
        dash::drop_tails(cp, 60, dash::kCleanDropTailsMaxPerPass, no_exempt);
        const std::size_t diff = cp.chain.size() - un.chain.size();
        ASSERT_GE(cp.chain.size(), un.chain.size());
        if (pass == 0) backlog0 = diff;
        ASSERT_LE(diff, backlog0) << "backlog grew at pass " << pass;
        ASSERT_LE(diff, prev_diff) << "backlog not monotone at pass " << pass;
        prev_diff = diff;
        // 2 new shares per pass (prod: ~7.5/min vs 128/min drained at 32 per 15 s)
        tip_u = add_run(un, tip_u, 2, id_u, iu.all).back();
        tip_c = add_run(cp, tip_c, 2, id_c, ic.all).back();
    }
    dash::drop_tails(un, 60, 0, no_exempt);
    for (int i = 0; i < 100; ++i)
        if (dash::drop_tails(cp, 60, dash::kCleanDropTailsMaxPerPass, no_exempt).dropped == 0) break;
    EXPECT_EQ(cp.chain.size(), un.chain.size());
    EXPECT_TRUE(same_state(snapshot(un, iu.all), snapshot(cp, ic.all)));
    EXPECT_GT(backlog0, 700u);   // the recorded backlog was really there
}

TEST(DashCleanDropTails, ExemptSegmentNeverDropped)
{
    // drop_tails honours whatever predicate it is given (node.cpp's is dead
    // today, #2263): this pins the plumbing only.
    dash::ShareTracker t;
    Incident inc;
    inc.build(t, 60, 300);
    // The segment id: its missing parent = the key of its tails entry.
    const uint256 last = t.chain.get_last(inc.all.front());
    ASSERT_TRUE(t.chain.get_tails().count(last));
    auto exempt = [&](const uint256& tail) { return tail == last; };
    // The whole incident forest is one segment: with the exemption on, nothing goes,
    // capped or not.
    EXPECT_EQ(dash::drop_tails(t, 60, dash::kCleanDropTailsMaxPerPass, exempt).dropped, 0);
    EXPECT_EQ(dash::drop_tails(t, 60, 0, exempt).dropped, 0);
    EXPECT_TRUE(t.chain.contains(inc.all.front()));
    // Without it, the same pass drops (so the zero above is the exemption's doing).
    EXPECT_GT(dash::drop_tails(t, 60, dash::kCleanDropTailsMaxPerPass, no_exempt).dropped, 0);
}

TEST(DashCleanDropTails, RealChainLengthIncidentSequenceIdentity)
{
    // Production size: threshold 2*CHAIN_LENGTH+10, 200 droppable under 5 heads
    // (the 11-18 lab incident shape; the full 800 is in the DISABLED bench). Same removed-hash sequence and state as the
    // previous loop; the cached pass is also timed against it (printed).
    const auto CL = static_cast<int32_t>(dash::SharechainConfig::chain_length());
    const int32_t thr = 2 * CL + 10;
    dash::ShareTracker a, b;
    Incident ia, ib;
    ia.build(a, thr, 200);   // 200 droppable keeps the reference loop short in sanitizer builds
    ib.build(b, thr, 200);
    const auto t0 = std::chrono::steady_clock::now();
    const auto ref = reference_drop(a, thr, no_exempt);
    const auto t1 = std::chrono::steady_clock::now();
    std::vector<uint256> got;
    const auto r = dash::drop_tails(b, thr, 0, no_exempt, &got);
    const auto t2 = std::chrono::steady_clock::now();
    ASSERT_GE(ref.size(), 200u);
    EXPECT_EQ(got, ref);
    EXPECT_EQ(r.dropped, static_cast<int>(ref.size()));
    EXPECT_TRUE(same_state(snapshot(a, ia.all), snapshot(b, ib.all)));
    std::printf("[DashCleanDropTails] real-CL 200-drop: previous loop %.1f ms, drop_tails %.1f ms (%zu shares)\n",
                std::chrono::duration<double, std::milli>(t1 - t0).count(),
                std::chrono::duration<double, std::milli>(t2 - t1).count(), ref.size());
}

// Out-of-order arrival (children before parents, as backfill delivers them):
// the forest is generated first, then added in a random permutation. The
// cached drop_tails must still match the previous loop step for step, and so
// must the uncached fallback (cache switched off).
TEST(DashCleanDropTails, OutOfOrderArrivalSequenceIdentityCachedAndUncached)
{
    struct Item { uint256 h, prev; };
    for (uint32_t seed = 1; seed <= 200; ++seed) {
        std::mt19937 rng(seed * 104729u);
        const int32_t threshold = 15 + static_cast<int32_t>(rng() % 30);
        std::vector<Item> items;
        uint64_t id = 1;
        const int nseg = 1 + static_cast<int>(rng() % 3);
        for (int s = 0; s < nseg; ++s) {
            uint256 prev = make_hash(0xfffffff400ULL + s);
            const uint256 root = prev;
            std::vector<uint256> seg;
            const int32_t len = threshold + static_cast<int32_t>(rng() % 80);
            for (int32_t i = 0; i < len; ++i) { const uint256 h = make_hash(id++); items.push_back({h, prev}); seg.push_back(h); prev = h; }
            if (rng() % 2) {   // bottom sibling
                uint256 p2 = root;
                for (int32_t i = 0, n = 1 + static_cast<int32_t>(rng() % (threshold + 30)); i < n; ++i) { const uint256 h = make_hash(id++); items.push_back({h, p2}); p2 = h; }
            }
            for (int f = 0, nf = static_cast<int>(rng() % 4); f < nf; ++f) {
                uint256 p3 = seg[rng() % seg.size()];
                for (int32_t i = 0, n = 1 + static_cast<int32_t>(rng() % (threshold + 20)); i < n; ++i) { const uint256 h = make_hash(id++); items.push_back({h, p3}); p3 = h; }
            }
        }
        std::vector<size_t> order(items.size());
        for (size_t i = 0; i < order.size(); ++i) order[i] = i;
        std::shuffle(order.begin(), order.end(), rng);
        const uint32_t vseed = rng();
        auto build = [&](dash::ShareTracker& t, std::vector<uint256>& all) {
            for (size_t k : order) {
                auto* sh = new dash::DashShare();
                sh->m_hash = items[k].h; sh->m_prev_hash = items[k].prev; sh->m_desired_version = 16;
                sh->m_bits = kBits; sh->m_max_bits = kBits;
                dash::ShareType st; st = sh;
                t.add(st);
                all.push_back(items[k].h);
            }
            std::mt19937 vr(vseed);   // the same random partial verification on every tracker
            for (const auto& it : items)
                if (vr() % 3 == 0 && t.chain.contains(it.h) && !t.verified.contains(it.h))
                    t.verified.add(t.chain.get_share(it.h));
        };
        dash::ShareTracker ref_t, cached_t, uncached_t;
        std::vector<uint256> all_r, all_c, all_u;
        build(ref_t, all_r); build(cached_t, all_c); build(uncached_t, all_u);
        const auto ref = reference_drop(ref_t, threshold, no_exempt);
        std::vector<uint256> got_c, got_u;
        const auto rc = dash::drop_tails(cached_t, threshold, 0, no_exempt, &got_c);
        dash::drop_tails_height_cache_disabled().store(true);
        dash::drop_tails(uncached_t, threshold, 0, no_exempt, &got_u);
        dash::drop_tails_height_cache_disabled().store(false);
        ASSERT_EQ(got_c, ref) << "cached: seed " << seed;
        ASSERT_EQ(got_u, ref) << "uncached: seed " << seed;
        EXPECT_FALSE(rc.cache_mismatch) << "seed " << seed;
        EXPECT_TRUE(same_state(snapshot(ref_t, all_r), snapshot(cached_t, all_c))) << "seed " << seed;
    }
    EXPECT_FALSE(dash::drop_tails_height_cache_disabled().load());
}
