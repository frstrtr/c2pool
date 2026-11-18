// SPDX-License-Identifier: AGPL-3.0-or-later
// MEASUREMENT (M) for the tail-drop removal cost (design note
// DESIGN-TAIL-DROP-COST.md): where does one dropped share's 5-11 ms go?
//
// DISABLED by default (it builds a production-size tracker and takes seconds);
// run with --gtest_also_run_disabled_tests --gtest_filter='*DropTailsBench*'.
// Prints, asserts nothing but sanity.
//
// The loop below is clean_tracker Step 3 (dash::drop_tails, uncapped) with a
// timer around each part:
//   (1) chain.get_height(head) for every head of every tail (uncached walk);
//   (2) the exemption check (the hint is active on a DIFFERENT segment, so the
//       predicate runs for every tail, as in a restart convergence);
//   (3) verified.remove + chain.remove (incl. remove() branch logic);
//   (4) the rest (tails copy, reverse lookup, tails().count checks).
// The watchers (TrackerView invalidation, skip lists) run inside (3); a second
// run with no verified shares separates verified.remove from chain.remove.
// Shapes: CL-real threshold 2*CHAIN_LENGTH+10 with 800 droppable layers under
// 5 heads (the 11-18 05:26 lab incident), plus 1 head, and a forked bottom.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <core/uint256.hpp>
#include <impl/dash/clean_drop_tails.hpp>
#include <impl/dash/config_pool.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/share_tracker.hpp>

namespace {

using clk = std::chrono::steady_clock;
double ms(clk::duration d) { return std::chrono::duration<double, std::milli>(d).count(); }

uint256 hx(const std::string& tail) {
    uint256 v;
    v.SetHex(std::string(64 - tail.size(), '0') + tail);
    return v;
}
uint256 mk(uint64_t id) {
    char buf[40];
    std::snprintf(buf, sizeof(buf), "be7c%012llx", static_cast<unsigned long long>(id));
    return hx(buf);
}
constexpr uint32_t kBits = 0x1e0fffff;

std::vector<uint256> run(dash::ShareTracker& t, const uint256& prev0, int32_t n, uint64_t& id) {
    std::vector<uint256> out;
    out.reserve(n);
    uint256 prev = prev0;
    for (int32_t i = 0; i < n; ++i) {
        const uint256 h = mk(id++);
        auto* sh = new dash::DashShare();
        sh->m_hash = h; sh->m_prev_hash = prev; sh->m_desired_version = 16;
        sh->m_bits = kBits; sh->m_max_bits = kBits;
        dash::ShareType st; st = sh;
        t.add(st);
        out.push_back(h);
        prev = h;
    }
    return out;
}

// The exemption check exactly as node.cpp runs it on this branch (master's):
// contains() is false for every tails key, so it short-circuits.
bool master_exempt(const dash::SupersedeHint& hint, dash::ShareTracker& t, const uint256& tail_hash) {
    if (!hint.active) return false;
    try {
        return t.chain.contains(tail_hash) && t.chain.get_last(tail_hash) == hint.target_segment_last;
    } catch (...) {}
    return false;
}

struct Split { double height{0}, exempt{0}, removes{0}, verified_removes{0}, rest{0}; int dropped{0}; double total{0}; };

Split timed_drop(dash::ShareTracker& t, int32_t min_head_height, const dash::SupersedeHint& hint) {
    Split s;
    const auto t_all = clk::now();
    for (int iter = 0; iter < 1000; ++iter) {
        auto t0 = clk::now();
        std::vector<uint256> to_remove;
        auto tails_copy = t.chain.get_tails();
        s.rest += ms(clk::now() - t0);
        for (auto& [tail_hash, head_hashes] : tails_copy) {
            auto te = clk::now();
            const bool ex = master_exempt(hint, t, tail_hash);
            s.exempt += ms(clk::now() - te);
            if (ex) continue;
            auto th = clk::now();
            int32_t min_height = 0;
            for (auto& hh : head_hashes) {
                if (!t.chain.contains(hh)) continue;
                auto h = t.chain.get_height(hh);
                if (min_height == 0 || h < min_height) min_height = h;
            }
            s.height += ms(clk::now() - th);
            if (min_height < min_head_height) continue;
            auto tr = clk::now();
            auto& rev = t.chain.get_reverse();
            auto rev_it = rev.find(tail_hash);
            if (rev_it != rev.end())
                for (const auto& child : rev_it->second) to_remove.push_back(child);
            s.rest += ms(clk::now() - tr);
        }
        if (to_remove.empty()) break;
        for (const auto& aftertail : to_remove) {
            auto tr = clk::now();
            if (!t.chain.contains(aftertail)) continue;
            auto* idx = t.chain.get_index(aftertail);
            if (!idx || !t.chain.get_tails().count(idx->tail)) continue;
            s.rest += ms(clk::now() - tr);
            auto tv = clk::now();
            if (t.verified.contains(aftertail)) t.verified.remove(aftertail, /*owns_data=*/false);
            s.verified_removes += ms(clk::now() - tv);
            auto tc = clk::now();
            t.chain.remove(aftertail);
            s.removes += ms(clk::now() - tc);
            ++s.dropped;
        }
    }
    s.total = ms(clk::now() - t_all);
    return s;
}

void report(const char* name, const Split& s) {
    const double per = s.dropped ? s.total / s.dropped : 0;
    std::printf("[DropTailsBench] %-34s dropped=%d total=%.1fms (%.2f ms/share) | get_height=%.1f (%.0f%%) "
                "exempt=%.1f chain.remove=%.1f verified.remove=%.1f rest=%.1f\n",
                name, s.dropped, s.total, per, s.height, s.total > 0 ? 100.0 * s.height / s.total : 0.0,
                s.exempt, s.removes, s.verified_removes, s.rest);
    std::fflush(stdout);
}

struct Shape { int heads; bool forked_bottom; bool verified; };

void bench(const char* name, const Shape& sh, int32_t droppable) {
    const auto CL = static_cast<int32_t>(dash::SharechainConfig::chain_length());
    const int32_t thr = 2 * CL + 10;
    dash::ShareTracker t;
    uint64_t id = 1;
    const uint256 missing = mk(0xfffffff0ULL);
    auto main = run(t, missing, thr + droppable + 20, id);
    if (sh.forked_bottom) run(t, missing, thr + droppable, id);  // a sibling of the bottom share
    for (int k = 0; k + 1 < sh.heads; ++k) run(t, main[main.size() - 6 - 3 * k], 3 + k, id);
    if (sh.verified)
        for (const auto& h : main) t.verified.add(t.chain.get_share(h));
    // A restart convergence: the hint is active on ANOTHER segment.
    dash::SupersedeHint hint; hint.active = true; hint.target_segment_last = mk(0xfffffff1ULL);
    run(t, hint.target_segment_last, 50, id);
    const auto s = timed_drop(t, thr, hint);
    report(name, s);
    EXPECT_GT(s.dropped, droppable - 1);
}

} // namespace

TEST(DashDropTailsBench, DISABLED_Breakdown)
{
    std::printf("[DropTailsBench] CHAIN_LENGTH=%u threshold=%u\n", dash::SharechainConfig::chain_length(),
                2 * dash::SharechainConfig::chain_length() + 10);
    bench("800 under 5 heads, verified", {5, false, true}, 800);
    bench("800 under 5 heads, unverified", {5, false, false}, 800);
    bench("800 under 1 head, verified", {1, false, true}, 800);
    bench("800 under 5 heads, forked bottom", {5, true, true}, 800);
    bench("200 under 5 heads, verified", {5, false, true}, 200);
}
