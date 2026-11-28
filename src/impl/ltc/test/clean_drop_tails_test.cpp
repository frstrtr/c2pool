// SPDX-License-Identifier: AGPL-3.0-or-later
//
// clean_tracker's drop-tails step with a per-pass head-height cache
// (clean_drop_tails.hpp, X1 stage A3): each head's height is walked once per
// pass instead of once per layer, and the step removes exactly what master's
// loop removes.
//
// THE incident (a live LTC node's log): one clean pass dropped 1000 shares
// layer by layer and held the exclusive tracker lock ~91 s; every layer walked
// every head of the tail to the chain's end (5 heads, ~24k shares).
//
// Pinned here:
//   * old_drop_tails() below is master's Step 3 verbatim (node.cpp
//     clean_tracker, logs removed, a removal record added). Over seeded random
//     forests (draining shapes with several tails, sibling first layers, forks
//     below heads, segments added children first, stale heads removed and
//     re-added; forests inserted in shuffled order with forks at every depth
//     and head removals before the drop; and the generic random forest from
//     random_forest.hpp), a random verified subset and a small CHAIN_LENGTH so
//     the forests reach the threshold, ltc::drop_tails with the cache (and
//     with it switched off) removes the same shares in the same order and
//     leaves the same chain and verified (shares, heads, tails, reverse, head
//     heights); also on a multi-tail forest that hits the 1000-layer cap, on a
//     tail with two children each carrying its own head (remove() branch 4,
//     then 3), and with no cache mismatch anywhere.
//   * The restart-reorg exemption in Step 3 never fires (a tail key is a
//     missing hash, so chain.contains(tail) is false), in master as in the new
//     step: pinned, so the random forests' hint-on variant is not read as
//     coverage of it.
//   * The safety net: a tracker change the cache does not model (a removed
//     share re-added mid-pass) is caught at the end of the call and switches
//     the cache off for the process.
//   * On a 20k-share forest (5 heads, one tail, CHAIN_LENGTH 8640) the cached
//     drain walks each head once instead of once per layer.
//   * The REAL NodeImpl::clean_tracker on a 20k chain draining 1000 layers
//     removes what master's loop removes, cache on and off; the exclusive
//     hold and the pass duration of both are printed.
//   * The [CLEAN] pass line (held_ms, drop_ms, total_ms, removed, layers,
//     cache): its format and when it is due, one line from a real pass, and
//     the timing guard at the clean pass's exclusive lock.
//   * With $C2POOL_REPLAY_STORE_LTC naming a copy of a recorded LTC store
//     (<dir>/litecoin/sharechain_leveldb, copied again before it is opened):
//     master's loop against the cached one on the loaded tracker at the
//     node's threshold and at one that drains 1000 layers, and a real clean
//     pass draining 1000 layers, cache off (master's work) against on: the
//     same removal sequence and final chain; the hold and duration printed.
//     Skipped when the variable is unset.
//
// Folded into the existing allowlisted `share_test` target (the #769 trap).

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <random>
#include <regex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include <boost/asio.hpp>
#include <boost/log/core.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/make_shared.hpp>
#include <boost/shared_ptr.hpp>

#include <c2pool/storage/sharechain_storage.hpp>
#include <core/filesystem.hpp>
#include <core/uint256.hpp>
#include <impl/ltc/clean_drop_tails.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_tracker.hpp>
#include <sharechain/test/random_forest.hpp>

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define C2POOL_SANITIZED 1
#else
#define C2POOL_SANITIZED 0
#endif

namespace {

using forest_test::make_hash;
using forest_test::make_share;

struct QuietLog {
    bool was;
    QuietLog() : was(boost::log::core::get()->get_logging_enabled())
    {
        boost::log::core::get()->set_logging_enabled(false);
    }
    ~QuietLog() { boost::log::core::get()->set_logging_enabled(was); }
};

// The cache switched off for a scope (master's work: every height walked).
struct CacheOff {
    CacheOff() { ltc::drop_tails_height_cache_disabled().store(true); }
    ~CacheOff() { ltc::drop_tails_height_cache_disabled().store(false); }
};

// ── Master's Step 3, verbatim (node.cpp clean_tracker) ───────────────────────
// m_tracker -> tracker, m_supersede_hint -> hint; the [drop-tails-QUALIFY]
// warning and the [drop-tails-PRE] stderr marker removed; `removed` records
// each share chain.remove() took.
void old_drop_tails(ltc::ShareTracker& tracker, const ltc::SupersedeHint& hint, int32_t CL,
                    std::vector<uint256>* removed)
{
    int total_dropped = 0;
    for (int iter = 0; iter < 1000; ++iter)
    {
        std::vector<uint256> to_remove;
        auto tails_copy = tracker.chain.get_tails();
        for (auto& [tail_hash, head_hashes] : tails_copy)
        {
            if (hint.active) {
                try {
                    if (tracker.chain.contains(tail_hash) &&
                        tracker.chain.get_last(tail_hash) == hint.target_segment_last)
                        continue;
                } catch (...) {}
            }

            int32_t min_height = 0;  // default 0 → skip if no valid heads
            for (auto& hh : head_hashes) {
                if (!tracker.chain.contains(hh)) continue;
                auto h = tracker.chain.get_height(hh);
                if (min_height == 0 || h < min_height)
                    min_height = h;
            }
            if (min_height < 2 * CL + 10) continue;

            // p2pool node.py:386: to_remove.update(tracker.reverse.get(tail, set()))
            auto& rev = tracker.chain.get_reverse();
            auto rev_it = rev.find(tail_hash);
            if (rev_it != rev.end()) {
                for (const auto& child : rev_it->second)
                    to_remove.push_back(child);
            }
        }

        if (to_remove.empty()) break;

        // p2pool node.py:392-398
        size_t _drop_idx = 0;
        for (const auto& aftertail : to_remove)
        {
            try {
                ++_drop_idx;

                if (!tracker.chain.contains(aftertail)) continue;
                // p2pool node.py:393: if items[aftertail].previous_hash not in tails: continue
                auto* idx = tracker.chain.get_index(aftertail);
                if (!idx) continue;
                if (!tracker.chain.get_tails().count(idx->tail)) {
                    continue;
                }
                if (tracker.verified.contains(aftertail))
                    tracker.verified.remove(aftertail, /*owns_data=*/false);
                const bool ok = tracker.chain.remove(aftertail);
                ++total_dropped;
                if (removed && ok)
                    removed->push_back(aftertail);
            } catch (...) {}
        }
    }
    (void)total_dropped;
}

// ── Tracker snapshots ────────────────────────────────────────────────────────

struct ChainState {
    std::set<uint256> shares;
    std::map<uint256, uint256> heads;
    std::map<uint256, std::set<uint256>> tails;
    std::map<uint256, std::set<uint256>> reverse;
    std::map<uint256, int32_t> head_heights;
    bool operator==(const ChainState&) const = default;
};

ChainState snapshot(ltc::ShareChain& c, const std::vector<uint256>& universe)
{
    ChainState s;
    for (const auto& h : universe)
        if (c.contains(h))
            s.shares.insert(h);
    for (const auto& [h, t] : c.get_heads()) {
        s.heads[h] = t;
        s.head_heights[h] = c.contains(h) ? c.get_height(h) : -1;
    }
    for (const auto& [t, hs] : c.get_tails())
        s.tails[t] = hs;
    for (const auto& [p, cs] : c.get_reverse())
        s.reverse[p] = cs;
    return s;
}

// ── Forests on a tracker ─────────────────────────────────────────────────────

// Grows a random forest on `tracker.chain` (random_forest.hpp), then marks a
// random subset verified, parents before children as the warm load does.
// Returns every hash ever made (the universe for snapshots).
std::vector<uint256> grow_tracker_forest(ltc::ShareTracker& tracker, uint64_t seed, int ops,
                                         int verified_pct)
{
    forest_test::ForestGrower<ltc::ShareChain> g(tracker.chain, seed);
    auto add = [&](const uint256& h, const uint256& p, uint32_t bits) {
        tracker.add(make_share(h, p, bits));
    };
    auto remove = [&](const uint256& h) {
        if (tracker.verified.contains(h))
            tracker.verified.remove(h, /*owns_data=*/false);
        return tracker.chain.remove(h);
    };
    for (int op = 0; op < ops; ++op) {
        if (op > 30 && g.chance(10))
            g.remove_step(remove);
        else
            g.grow_step(add);
    }
    // Verified: walk each present share's ancestry bottom-up and verify a
    // random-length prefix of it (keeps verified a parent-closed subset, the
    // shape think() builds, plus some isolated ones).
    std::mt19937_64 rng(seed ^ 0x5eed);
    auto present = g.present_hashes();
    std::vector<std::pair<int32_t, uint256>> by_height;
    for (const auto& h : present)
        by_height.emplace_back(tracker.chain.get_height(h), h);
    std::sort(by_height.begin(), by_height.end());
    for (const auto& [ht, h] : by_height) {
        if (std::uniform_int_distribution<int>(0, 99)(rng) >= verified_pct)
            continue;
        if (!tracker.verified.contains(h))
            tracker.verified.add(tracker.chain.get_share(h));
    }
    std::vector<uint256> universe;
    for (const auto& [h, p] : g.prev_of)
        universe.push_back(h);
    return universe;
}

// A forest that drains: 1-4 tails (a missing parent or the null genesis
// parent), each with 1-3 children on its first layer (remove() branch 4, then
// 3), grown to about the threshold 2*CL+10 by extending a random head (85%) or
// forking a few shares below one (15%), some segments added children first
// (calculate_head_tail's merges), a few stale heads removed (branches 1/2) and
// a removed head re-added. Heights straddle the threshold, so some tails drain
// a few layers, some many and some none. A random parent-closed verified
// subset as think() builds it.
std::vector<uint256> grow_draining_forest(ltc::ShareTracker& tracker, uint64_t seed, int32_t CL)
{
    std::mt19937_64 rng(seed);
    auto rnd = [&](int lo, int hi) { return std::uniform_int_distribution<int>(lo, hi)(rng); };
    uint64_t id = 0;
    std::vector<uint256> universe;
    std::map<uint256, uint256> prev_of;
    auto add = [&](const uint256& h, const uint256& p) {
        tracker.add(make_share(h, p, forest_test::bits_for(forest_test::mix64(h.GetLow64()))));
        prev_of[h] = p;
        universe.push_back(h);
    };
    const int n_tails = rnd(1, 4);
    for (int t = 0; t < n_tails; ++t) {
        const uint256 root = (t == 0 && rnd(0, 1) == 0) ? uint256() : make_hash(seed * 977 + 13, id++);
        std::vector<uint256> heads;
        // children of the root: siblings on the first layer
        for (int k = rnd(1, 3); k > 0; --k) {
            const uint256 h = make_hash(seed * 977 + 13, id++);
            add(h, root);
            heads.push_back(h);
        }
        const int target = 2 * CL + 10 + rnd(-6, 40);
        const bool children_first = rnd(0, 3) == 0;
        std::vector<std::pair<uint256, uint256>> pending;   // (hash, prev) added at the end, reversed
        std::map<uint256, int> height;
        for (const auto& h : heads)
            height[h] = 1;
        // Grow until every head of this tail is `target` tall.
        for (int step = 0; step < target * 16 && !heads.empty(); ++step) {
            std::vector<size_t> short_heads;
            for (size_t k = 0; k < heads.size(); ++k)
                if (height[heads[k]] < target)
                    short_heads.push_back(k);
            if (short_heads.empty())
                break;
            const size_t hi = short_heads[static_cast<size_t>(rnd(0, static_cast<int>(short_heads.size()) - 1))];
            uint256 parent = heads[hi];
            const bool fork = heads.size() < 6 && rnd(0, 99) < 15;
            if (fork) {
                // a few shares below this head
                for (int d = rnd(1, 4); d > 0 && prev_of.count(parent) && !prev_of[parent].IsNull()
                                         && height.count(prev_of[parent]); --d)
                    parent = prev_of[parent];
            }
            const uint256 h = make_hash(seed * 977 + 13, id++);
            if (children_first && step > target / 2) {
                pending.emplace_back(h, parent);
                prev_of[h] = parent;
            } else {
                add(h, parent);
            }
            height[h] = height[parent] + 1;
            if (fork)
                heads.push_back(h);
            else
                heads[hi] = h;
        }
        for (auto it = pending.rbegin(); it != pending.rend(); ++it) {
            tracker.add(make_share(it->first, it->second,
                                   forest_test::bits_for(forest_test::mix64(it->first.GetLow64()))));
            universe.push_back(it->first);
        }
    }
    // stale heads removed (branches 1/2), one re-added
    std::vector<uint256> hs;
    for (const auto& [h, tl] : tracker.chain.get_heads())
        hs.push_back(h);
    std::sort(hs.begin(), hs.end());
    uint256 readd;
    for (const auto& h : hs) {
        if (rnd(0, 99) < 12 && tracker.chain.contains(h) && tracker.chain.remove(h))
            readd = h;
    }
    if (!readd.IsNull())
        tracker.add(make_share(readd, prev_of[readd], forest_test::bits_for(forest_test::mix64(readd.GetLow64()))));
    // verified: a random-length bottom-up prefix of the shares, by height
    std::vector<std::pair<int32_t, uint256>> by_height;
    for (const auto& h : universe)
        if (tracker.chain.contains(h))
            by_height.emplace_back(tracker.chain.get_height(h), h);
    std::sort(by_height.begin(), by_height.end());
    const int pct = rnd(30, 100);
    for (const auto& [ht, h] : by_height) {
        if (rnd(0, 99) >= pct)
            continue;
        if (!tracker.verified.contains(h))
            tracker.verified.add(tracker.chain.get_share(h));
    }
    return universe;
}

// A long chain on a missing parent with extra branches on top: `depths` are
// how far below the main tip each 2-share fork starts. Heights of the heads
// are known, so the drain length is: layers = min(1000, min_head_height - (2*CL+10) + 1).
std::vector<uint256> build_long_forest(ltc::ShareTracker& tracker, uint64_t salt, int length,
                                       const std::vector<int>& depths, uint256* main_tip = nullptr)
{
    std::vector<uint256> universe, main;
    uint256 prev = make_hash(salt, 0xffffff);   // missing parent: one tail
    for (int i = 0; i < length; ++i) {
        const uint256 h = make_hash(salt, static_cast<uint64_t>(i));
        tracker.add(make_share(h, prev, forest_test::bits_for(static_cast<uint64_t>(i))));
        tracker.verified.add(tracker.chain.get_share(h));
        main.push_back(h);
        universe.push_back(h);
        prev = h;
    }
    uint64_t id = 10000000;
    for (int d : depths) {
        uint256 p = main[static_cast<size_t>(length - 1 - d)];
        for (int k = 0; k < 2; ++k) {
            const uint256 h = make_hash(salt, id++);
            tracker.add(make_share(h, p, 0x1e0fffff));
            tracker.verified.add(tracker.chain.get_share(h));
            universe.push_back(h);
            p = h;
        }
    }
    if (main_tip)
        *main_tip = main.back();
    return universe;
}

// The hint for a tracker: off, or on with the segment of one of its tails.
ltc::SupersedeHint hint_for(ltc::ShareTracker& tracker, bool active, std::mt19937_64& rng)
{
    ltc::SupersedeHint hint;
    if (!active)
        return hint;
    hint.active = true;
    std::vector<uint256> tails;
    for (const auto& [t, hs] : tracker.chain.get_tails())
        tails.push_back(t);
    std::sort(tails.begin(), tails.end());
    if (!tails.empty())
        hint.target_segment_last = tails[std::uniform_int_distribution<size_t>(0, tails.size() - 1)(rng)];
    return hint;
}


// ── Shuffled-insert forests (forks at every depth) ───────────────────────────

struct ShuffledModel {
    std::vector<std::pair<uint256, uint256>> order;   // (hash, prev) insertion order
    std::map<uint256, uint256> prev_of;
    std::vector<uint256> universe;
};

// 1-4 roots (at most one null), each with 1-3 sibling first-layer children;
// 1-7 trunks per root forking at a random existing node (half of them in the
// bottom two thirds), extended to a height in [thr-6, thr+30]; then inserted
// in order, shuffled, reversed or in shuffled blocks of 7.
ShuffledModel make_shuffled_model(uint64_t seed, int32_t thr)
{
    std::mt19937_64 rng(seed);
    auto rnd = [&](int lo, int hi) { return std::uniform_int_distribution<int>(lo, hi)(rng); };
    ShuffledModel m;
    uint64_t id = 0;
    const uint64_t salt = 0xadu * 1000003u + seed;
    const int n_roots = rnd(1, 4);
    std::vector<std::pair<uint256, uint256>> edges;
    for (int r = 0; r < n_roots; ++r) {
        const uint256 root = (r == 0 && rnd(0, 2) == 0) ? uint256() : make_hash(salt, id++);
        std::vector<std::pair<uint256, int>> nodes;   // (hash, depth)
        for (int k = rnd(1, 3); k > 0; --k) {
            const uint256 h = make_hash(salt, id++);
            edges.emplace_back(h, root);
            nodes.emplace_back(h, 1);
        }
        const int trunks = rnd(1, 7);
        for (int t = 0; t < trunks; ++t) {
            const int target = std::max(2, thr + rnd(-6, 30));
            size_t pick;
            if (rnd(0, 1) == 0) {
                std::vector<size_t> low;
                for (size_t i = 0; i < nodes.size(); ++i)
                    if (nodes[i].second <= std::max(1, 2 * thr / 3)) low.push_back(i);
                pick = low.empty() ? 0 : low[static_cast<size_t>(rnd(0, static_cast<int>(low.size()) - 1))];
            } else {
                pick = static_cast<size_t>(rnd(0, static_cast<int>(nodes.size()) - 1));
            }
            uint256 p = nodes[pick].first;
            int d = nodes[pick].second;
            while (d < target) {
                const uint256 h = make_hash(salt, id++);
                edges.emplace_back(h, p);
                nodes.emplace_back(h, d + 1);
                p = h;
                ++d;
            }
        }
        // extend the first-layer siblings left childless (a height-1 head
        // keeps its tail from ever qualifying)
        if (rnd(0, 1) == 0) {
            std::set<uint256> has_child;
            for (const auto& [h, pp] : edges) has_child.insert(pp);
            const size_t n0 = nodes.size();
            for (size_t i = 0; i < n0; ++i) {
                if (nodes[i].second != 1 || has_child.count(nodes[i].first)) continue;
                uint256 p = nodes[i].first;
                const int target = std::max(2, thr + rnd(-6, 30));
                for (int d = 1; d < target; ++d) {
                    const uint256 h = make_hash(salt, id++);
                    edges.emplace_back(h, p);
                    p = h;
                }
            }
        }
    }
    for (const auto& [h, p] : edges) { m.prev_of[h] = p; m.universe.push_back(h); }
    const int mode = rnd(0, 3);
    m.order = edges;
    if (mode == 1) {
        std::shuffle(m.order.begin(), m.order.end(), rng);
    } else if (mode == 2) {
        std::reverse(m.order.begin(), m.order.end());
    } else if (mode == 3) {
        std::vector<std::vector<std::pair<uint256, uint256>>> blocks;
        for (size_t i = 0; i < m.order.size(); i += 7)
            blocks.emplace_back(m.order.begin() + static_cast<long>(i),
                                m.order.begin() + static_cast<long>(std::min(m.order.size(), i + 7)));
        std::shuffle(blocks.begin(), blocks.end(), rng);
        m.order.clear();
        for (auto& bl : blocks) m.order.insert(m.order.end(), bl.begin(), bl.end());
    }
    return m;
}

// Inserts the model, removes some heads over three rounds (remove() branches
// 1/2: a parent promoted or a sibling left), puts half of them back parents
// first, and verifies a random subset bottom-up.
void build_shuffled(ltc::ShareTracker& t, const ShuffledModel& m, uint64_t seed)
{
    for (const auto& [h, p] : m.order)
        t.add(make_share(h, p, forest_test::bits_for(forest_test::mix64(h.GetLow64()))));
    std::mt19937_64 rng(seed ^ 0xbeef);
    auto rnd = [&](int lo, int hi) { return std::uniform_int_distribution<int>(lo, hi)(rng); };
    std::vector<uint256> hs;
    for (const auto& [h, tl] : t.chain.get_heads()) hs.push_back(h);
    std::sort(hs.begin(), hs.end());
    std::vector<uint256> gone;
    for (int round = 0; round < 3; ++round) {
        for (const auto& h : hs)
            if (rnd(0, 99) < 10 && t.chain.contains(h) && t.chain.remove(h))
                gone.push_back(h);
        hs.clear();
        for (const auto& [h, tl] : t.chain.get_heads()) hs.push_back(h);
        std::sort(hs.begin(), hs.end());
    }
    for (auto it = gone.rbegin(); it != gone.rend(); ++it)
        if (rnd(0, 1) == 0 && !t.chain.contains(*it))
            t.add(make_share(*it, m.prev_of.at(*it), forest_test::bits_for(forest_test::mix64(it->GetLow64()))));
    std::vector<std::pair<int32_t, uint256>> by_h;
    for (const auto& h : m.universe)
        if (t.chain.contains(h)) by_h.emplace_back(t.chain.get_height(h), h);
    std::sort(by_h.begin(), by_h.end());
    const int pct = rnd(0, 100);
    for (const auto& [ht, h] : by_h)
        if (rnd(0, 99) < pct && !t.verified.contains(h))
            t.verified.add(t.chain.get_share(h));
}

// A real clean pass, timed from the io thread (this thread): the exclusive
// hold is the longest stretch over which a shared try-lock kept failing, the
// pass duration runs from clean_tracker() to the end of its io phase.
struct PassTiming {
    int64_t max_hold_us{0};
    int64_t pass_us{0};
};

template <typename Node>
::testing::AssertionResult run_clean_pass(Node& node, boost::asio::io_context& ioc, PassTiming& t)
{
    using clock = std::chrono::steady_clock;
    const auto t0 = clock::now();
    node.clean_tracker();
    auto last_free = t0;
    bool pass_over = false;
    int quiet = 0;
    const auto deadline = t0 + std::chrono::seconds(900);
    while (clock::now() < deadline) {
        ioc.restart();
        const std::size_t ran = ioc.poll();
        {
            std::shared_lock<std::shared_mutex> lk(node.tracker_mutex(), std::try_to_lock);
            if (lk.owns_lock()) {
                const auto now = clock::now();
                t.max_hold_us = std::max<int64_t>(t.max_hold_us,
                    std::chrono::duration_cast<std::chrono::microseconds>(now - last_free).count());
                last_free = now;
            }
        }
        if (!pass_over && !node.m_clean_running.load()) {
            pass_over = true;
            t.pass_us = std::chrono::duration_cast<std::chrono::microseconds>(clock::now() - t0).count();
        }
        if (pass_over && ran == 0 && !node.m_think_running.load()) {
            if (++quiet >= 40)
                return ::testing::AssertionSuccess();
        } else {
            quiet = 0;
        }
        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }
    return ::testing::AssertionFailure() << "the clean pass did not finish";
}

}  // namespace

// The cache-off flag is process-wide and sticky (a mismatch sets it for good):
// every test starts and ends with the cache on, so a failing test cannot turn
// it off for the ones after it.
class LtcCleanDropTails : public ::testing::Test
{
protected:
    void SetUp() override { ltc::drop_tails_height_cache_disabled().store(false); }
    void TearDown() override { ltc::drop_tails_height_cache_disabled().store(false); }
};
class LtcCleanDropTailsStore : public LtcCleanDropTails
{
};

// ── Equivalence over random forests ──────────────────────────────────────────

TEST_F(LtcCleanDropTails, RandomForestsCachedRemovesWhatTheMasterLoopRemoves)
{
    QuietLog quiet;
    ASSERT_FALSE(ltc::drop_tails_height_cache_disabled().load());
    size_t total_removed = 0, drained_cases = 0;
    // 48 seeds x 3 variants (24 under the sanitizers: the same forests, fewer).
    const uint64_t kSeeds = C2POOL_SANITIZED ? 24 : 48;
    for (uint64_t seed = 1; seed <= kSeeds; ++seed) {
        for (int variant = 0; variant < 3; ++variant) {
            // Odd seeds: the draining shape; even seeds: the generic random
            // forest, which mostly does not qualify (short forks anywhere
            // keep the minimum head low).
            const int32_t CL = 3 + static_cast<int32_t>(seed % 9) * 4;
            const bool draining = seed % 2 == 1;
            ltc::ShareTracker a, b, c;
            auto grow = [&](ltc::ShareTracker& t) {
                return draining ? grow_draining_forest(t, seed, CL) : grow_tracker_forest(t, seed, 420, 70);
            };
            const auto ua = grow(a);
            const auto ub = grow(b);
            const auto uc = grow(c);
            ASSERT_EQ(snapshot(a.chain, ua), snapshot(b.chain, ub)) << "seed " << seed;
            // Variant 2 runs with the supersede hint on, naming one of the
            // forest's tails; the exemption cannot fire in Step 3 (see
            // SupersedeExemptionIsDeadInStep3), so this checks only that an
            // active hint changes nothing.
            std::mt19937_64 ra(seed * 31 + variant), rb(seed * 31 + variant), rc(seed * 31 + variant);
            const ltc::SupersedeHint ha = hint_for(a, variant == 2, ra);
            const ltc::SupersedeHint hb = hint_for(b, variant == 2, rb);
            const ltc::SupersedeHint hc = hint_for(c, variant == 2, rc);

            std::vector<uint256> rem_old, rem_cached, rem_uncached;
            old_drop_tails(a, ha, CL, &rem_old);
            const auto res = ltc::drop_tails(b, hb, CL, /*diag_log=*/false, &rem_cached);
            ltc::DropTailsResult res_off;
            {
                CacheOff off;
                res_off = ltc::drop_tails(c, hc, CL, /*diag_log=*/false, &rem_uncached);
            }
            ASSERT_FALSE(res.cache_mismatch) << "seed " << seed << " variant " << variant;
            EXPECT_TRUE(res.cached);
            EXPECT_FALSE(res_off.cached);
            ASSERT_EQ(rem_cached, rem_old) << "seed " << seed << " variant " << variant;
            ASSERT_EQ(rem_uncached, rem_old) << "seed " << seed << " variant " << variant;
            EXPECT_EQ(static_cast<size_t>(res.total_dropped), rem_old.size());
            EXPECT_EQ(res_off.total_dropped, res.total_dropped);
            EXPECT_EQ(snapshot(b.chain, ub), snapshot(a.chain, ua)) << "seed " << seed;
            EXPECT_EQ(snapshot(b.verified, ub), snapshot(a.verified, ua)) << "seed " << seed;
            EXPECT_EQ(snapshot(c.chain, uc), snapshot(a.chain, ua)) << "seed " << seed;
            EXPECT_EQ(snapshot(c.verified, uc), snapshot(a.verified, ua)) << "seed " << seed;
            total_removed += rem_old.size();
            drained_cases += rem_old.empty() ? 0 : 1;
        }
    }
    EXPECT_GT(drained_cases, kSeeds / 2) << "the forests must actually drain";
    EXPECT_FALSE(ltc::drop_tails_height_cache_disabled().load());
    std::printf("[LtcCleanDropTails] %zu removals identical across %zu draining cases\n",
                total_removed, drained_cases);
}

// Several tails, some qualifying and some not, branches 3 and 4 (a tail with
// one child and with several), the null genesis tail, and a drain that hits
// the 1000-layer cap.
TEST_F(LtcCleanDropTails, MultiTailAndLayerCap)
{
    QuietLog quiet;
    auto build = [](ltc::ShareTracker& t) {
        std::vector<uint256> u;
        // Tail 1: 1500 shares plus a 1200-share sibling trunk on the same
        // missing parent (two children on layer 0: branch 4, then 3).
        auto x = build_long_forest(t, 11, 1500, {3, 40});
        u.insert(u.end(), x.begin(), x.end());
        {
            uint256 p = make_hash(11, 0xffffff);
            for (int i = 0; i < 1200; ++i) {
                const uint256 h = make_hash(11, 0xaa0000 + static_cast<uint64_t>(i));
                t.add(make_share(h, p, 0x1e07ffff));
                u.push_back(h);
                p = h;
            }
        }
        // Tail 2: 120 shares, below the threshold: never drained.
        auto y = build_long_forest(t, 12, 120, {});
        u.insert(u.end(), y.begin(), y.end());
        // Tail 3: genesis-rooted (null tail), 400 shares.
        uint256 prev;
        for (int i = 0; i < 400; ++i) {
            const uint256 h = make_hash(13, static_cast<uint64_t>(i));
            t.add(make_share(h, prev, 0x1e0fffff));
            u.push_back(h);
            prev = h;
        }
        return u;
    };
    const int32_t CL = 50;   // threshold 110: tail 1 drains to the 1000-layer cap
    ltc::ShareTracker a, b;
    const auto ua = build(a);
    const auto ub = build(b);
    std::vector<uint256> rem_old, rem_new;
    old_drop_tails(a, ltc::SupersedeHint{}, CL, &rem_old);
    const auto res = ltc::drop_tails(b, ltc::SupersedeHint{}, CL, false, &rem_new);
    EXPECT_FALSE(res.cache_mismatch);
    EXPECT_EQ(res.layers, 1000);
    EXPECT_EQ(rem_new, rem_old);
    EXPECT_EQ(snapshot(b.chain, ub), snapshot(a.chain, ua));
    EXPECT_EQ(snapshot(b.verified, ub), snapshot(a.verified, ua));
    EXPECT_GE(rem_old.size(), 1000u);
}

// A tail with two children, each carrying its own head: the first removal of
// the first layer takes remove() branch 4 (siblings: only the heads through
// that child move), the second branch 3, and from then on the two are tails
// of their own and drain independently. The cache must decrement each head
// only for removals in its own ancestry.
TEST_F(LtcCleanDropTails, TwoChildrenEachWithItsOwnHeadDrainIndependently)
{
    QuietLog quiet;
    auto build = [](ltc::ShareTracker& t, uint256* head_a, uint256* head_b) {
        std::vector<uint256> u;
        const uint256 tail = make_hash(51, 0xffffff);
        uint256 p = tail;
        for (int i = 0; i < 100; ++i) {   // child A's line: its head 100 deep
            const uint256 h = make_hash(51, static_cast<uint64_t>(i));
            t.add(make_share(h, p, 0x1e0fffff));
            u.push_back(h);
            p = h;
        }
        *head_a = p;
        p = tail;
        for (int i = 0; i < 120; ++i) {   // child B's line: its head 120 deep
            const uint256 h = make_hash(52, static_cast<uint64_t>(i));
            t.add(make_share(h, p, 0x1e07ffff));
            u.push_back(h);
            p = h;
        }
        *head_b = p;
        return u;
    };
    const int32_t CL = 20;   // threshold 50
    ltc::ShareTracker a, b;
    uint256 ha, hb, ha2, hb2;
    const auto ua = build(a, &ha, &hb);
    const auto ub = build(b, &ha2, &hb2);
    ASSERT_EQ(a.chain.get_tails().size(), 1u);
    ASSERT_EQ(a.chain.get_reverse().at(make_hash(51, 0xffffff)).size(), 2u) << "two children on the tail";
    std::vector<uint256> rem_old, rem_new;
    old_drop_tails(a, ltc::SupersedeHint{}, CL, &rem_old);
    const auto res = ltc::drop_tails(b, ltc::SupersedeHint{}, CL, false, &rem_new);
    EXPECT_FALSE(res.cache_mismatch);
    EXPECT_EQ(rem_new, rem_old);
    EXPECT_EQ(snapshot(b.chain, ub), snapshot(a.chain, ua));
    // Line A drains while its head is >= 50 deep (51 shares), line B the
    // same on its own tail (71 shares): both heads end 49 deep.
    EXPECT_EQ(rem_new.size(), 51u + 71u);
    EXPECT_EQ(b.chain.get_height(ha2), 49);
    EXPECT_EQ(b.chain.get_height(hb2), 49);
    EXPECT_EQ(b.chain.get_tails().size(), 2u);
}

// Pre-existing, in master as in the new step: Step 3's restart-reorg
// exemption cannot fire. A tail key is a missing hash, so
// chain.contains(tail_hash) is false for every tail; a hint naming the only
// tail (exactly what compute_supersede_hint stores) exempts nothing.
TEST_F(LtcCleanDropTails, SupersedeExemptionIsDeadInStep3)
{
    QuietLog quiet;
    auto build = [](ltc::ShareTracker& t) {
        uint256 p = make_hash(0x77, 0xffffff);
        for (int i = 0; i < 60; ++i) {
            const uint256 h = make_hash(0x77, static_cast<uint64_t>(i));
            t.add(make_share(h, p, 0x1e0fffff));
            p = h;
        }
        return p;
    };
    ltc::ShareTracker a, b;
    const uint256 tip_a = build(a);
    build(b);
    ltc::SupersedeHint hint;
    hint.active = true;
    hint.target_segment_last = a.chain.get_last(tip_a);
    ASSERT_EQ(hint.target_segment_last, make_hash(0x77, 0xffffff));
    std::vector<uint256> rem_old, rem_new;
    old_drop_tails(a, hint, /*CL=*/5, &rem_old);
    ltc::drop_tails(b, hint, /*CL=*/5, false, &rem_new);
    EXPECT_GT(rem_old.size(), 0u) << "master's loop exempted the tail: the exemption does fire";
    EXPECT_EQ(rem_new, rem_old);
}

// Forests inserted in shuffled, reversed or block-shuffled order, with trunks
// forking at uniformly random depths (the drained bottom included), heads
// straddling the threshold, several tails and sibling first layers, and head
// removals (remove() branches 1/2, some re-added) before the drop.
TEST_F(LtcCleanDropTails, ShuffledForestsWithForksAtEveryDepth)
{
    QuietLog quiet;
    const uint64_t N = C2POOL_SANITIZED ? 120 : 400;
    size_t drained = 0, removals = 0;
    for (uint64_t seed = 1; seed <= N; ++seed) {
        const int32_t CL = 1 + static_cast<int32_t>(seed % 7);
        const ShuffledModel m = make_shuffled_model(seed, 2 * CL + 10);
        ltc::ShareTracker a, b;
        build_shuffled(a, m, seed);
        build_shuffled(b, m, seed);
        ASSERT_EQ(snapshot(a.chain, m.universe), snapshot(b.chain, m.universe)) << seed;
        std::vector<uint256> ra, rb;
        old_drop_tails(a, ltc::SupersedeHint{}, CL, &ra);
        const auto res = ltc::drop_tails(b, ltc::SupersedeHint{}, CL, false, &rb);
        ASSERT_FALSE(res.cache_mismatch) << "seed " << seed;
        ASSERT_EQ(rb, ra) << "seed " << seed;
        ASSERT_EQ(snapshot(b.chain, m.universe), snapshot(a.chain, m.universe)) << "seed " << seed;
        ASSERT_EQ(snapshot(b.verified, m.universe), snapshot(a.verified, m.universe)) << "seed " << seed;
        removals += ra.size();
        drained += ra.empty() ? 0 : 1;
    }
    std::printf("[LtcCleanDropTails] %llu shuffled forests, %zu drained, %zu removals identical\n",
                static_cast<unsigned long long>(N), drained, removals);
    EXPECT_GT(drained, N / 4);
}

// A change the cache does not model (here a removed share put back mid-pass,
// which raises the heights above it) is caught by the end-of-call walk and
// turns the cache off for the process.
TEST_F(LtcCleanDropTails, SafetyNetCatchesAHeightTheCacheDidNotSee)
{
    QuietLog quiet;
    ASSERT_FALSE(ltc::drop_tails_height_cache_disabled().load());
    ltc::ShareTracker t;
    build_long_forest(t, 41, 400, {3});
    bool readded = false;
    const std::function<void(const uint256&)> put_back = [&](const uint256& h) {
        if (readded)
            return;
        readded = true;
        t.add(make_share(h, make_hash(41, 0xffffff), forest_test::bits_for(0)));
    };
    const auto res = ltc::drop_tails(t, ltc::SupersedeHint{}, /*CL=*/50, false, nullptr, &put_back);
    EXPECT_TRUE(readded);
    EXPECT_TRUE(res.cache_mismatch);
    EXPECT_TRUE(ltc::drop_tails_height_cache_disabled().load()) << "a mismatch switches the cache off";
    ltc::drop_tails_height_cache_disabled().store(false);
}

// The point of the cache: a 200-layer drain of a 20k-share forest (5 heads,
// one tail) walks each head once per pass instead of once per layer.
TEST_F(LtcCleanDropTails, TwentyThousandShareDrainWalksEachHeadOncePerPass)
{
    QuietLog quiet;
    const int32_t CL = 8640;   // LTC mainnet: threshold 17290
    const int length = 20000;
    const std::vector<int> depths = C2POOL_SANITIZED ? std::vector<int>{2, 9, 60, 2653}
                                                     : std::vector<int>{2, 9, 60, 2513};
    ltc::ShareTracker a, b;
    const auto ua = build_long_forest(a, 21, length, depths);
    const auto ub = build_long_forest(b, 21, length, depths);
    std::vector<uint256> rem_old, rem_new;
    const auto t0 = std::chrono::steady_clock::now();
    old_drop_tails(a, ltc::SupersedeHint{}, CL, &rem_old);
    const auto old_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t0).count();
    const auto t1 = std::chrono::steady_clock::now();
    const auto res = ltc::drop_tails(b, ltc::SupersedeHint{}, CL, false, &rem_new);
    const auto new_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t1).count();
    ASSERT_EQ(rem_old.size(), C2POOL_SANITIZED ? 60u : 200u);
    EXPECT_FALSE(res.cache_mismatch);
    EXPECT_EQ(rem_new, rem_old);
    EXPECT_EQ(snapshot(b.chain, ub), snapshot(a.chain, ua));
    EXPECT_EQ(snapshot(b.verified, ub), snapshot(a.verified, ua));
    std::printf("[LtcCleanDropTails] %zu-layer drain of a 20k-share forest, 5 heads: master loop %.1f ms, "
                "cached %.1f ms\n", rem_old.size(), old_us / 1000.0, new_us / 1000.0);
    // Master walks 5 heads per layer; the cache walks each once, plus the
    // end-of-call check: two layers' worth. A factor 5 leaves room for noise.
    EXPECT_LT(new_us * 5, old_us);
}

// ── The REAL NodeImpl::clean_tracker ─────────────────────────────────────────

namespace {

uint256 NH(uint64_t n) { return make_hash(0x5ca1e, n); }

struct CleanNode : public ltc::NodeImpl
{
    explicit CleanNode(boost::asio::io_context& ioc) : ltc::NodeImpl()
    {
        m_chain = &m_tracker.chain;
        m_context = &ioc;
    }
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    using ltc::NodeImpl::m_tracker;
    using ltc::NodeImpl::m_best_share_hash;
    using ltc::NodeImpl::m_think_running;
    using ltc::NodeImpl::m_clean_running;
    using ltc::NodeImpl::m_coin_params;
    using ltc::NodeImpl::m_storage;
    using ltc::NodeImpl::load_persisted_shares;

    // A verified share seen now (head GC keeps it).
    void add_verified(const uint256& h, const uint256& prev, uint32_t bits)
    {
        const auto now = static_cast<uint32_t>(std::time(nullptr));
        auto* sh = new ltc::MergedMiningShare();
        sh->m_hash = h;
        sh->m_prev_hash = prev;
        sh->m_desired_version = 36;
        sh->m_bits = bits;
        sh->m_max_bits = bits;
        sh->m_timestamp = now;
        sh->m_min_header.m_bits = 0x1b0fffff;
        sh->m_min_header.m_timestamp = now;
        ltc::ShareType st;
        st = sh;
        m_tracker.add(st);
        m_tracker.chain.get_index(h)->time_seen = now;
        m_tracker.verified.add(m_tracker.chain.get_share(h));
    }
};

void build_node_trunk(CleanNode& node, int length)
{
    uint256 prev = NH(0xfffffff);   // one tail (missing parent)
    for (int i = 0; i < length; ++i) {
        node.add_verified(NH(static_cast<uint64_t>(i)), prev, 0x1e0fffff);
        prev = NH(static_cast<uint64_t>(i));
    }
    node.m_best_share_hash = prev;
}

}  // namespace

TEST_F(LtcCleanDropTails, RealCleanPassRemovesWhatTheMasterLoopRemoves)
{
    QuietLog quiet;
    // m_coin_params.chain_length is the LTC mainnet 8640: threshold 17290;
    // 20000 shares drain 1000 layers (the cap).
    const int length = 20000;
    ltc::ShareTracker ref;
    {
        uint256 p = NH(0xfffffff);
        for (int i = 0; i < length; ++i) {
            ref.add(make_share(NH(static_cast<uint64_t>(i)), p, 0x1e0fffff));
            ref.verified.add(ref.chain.get_share(NH(static_cast<uint64_t>(i))));
            p = NH(static_cast<uint64_t>(i));
        }
    }
    std::vector<uint256> rem_old;
    old_drop_tails(ref, ltc::SupersedeHint{}, 8640, &rem_old);
    ASSERT_EQ(rem_old.size(), 1000u);

    PassTiming timing[2];
    for (int cached = 0; cached < 2; ++cached) {
        std::vector<uint256> rem;   // outlives the node that writes it
        boost::asio::io_context ioc;
        auto node = std::make_unique<CleanNode>(ioc);
        build_node_trunk(*node, length);
        node->m_tracker.chain.on_removed([&](const uint256& h) { rem.push_back(h); });
        {
            std::unique_ptr<CacheOff> off;
            if (!cached)
                off = std::make_unique<CacheOff>();
            ASSERT_TRUE(run_clean_pass(*node, ioc, timing[cached]));
        }
        EXPECT_EQ(rem, rem_old) << (cached ? "cached" : "uncached")
                                << ": the pass removes what master's loop removes";
        EXPECT_EQ(node->m_tracker.chain.size(), static_cast<size_t>(length) - rem_old.size());
    }
    EXPECT_FALSE(ltc::drop_tails_height_cache_disabled().load());
    std::printf("[LtcCleanDropTails] real clean pass, 20k shares, 1000 layers: cache off (master's work) "
                "hold %.1f ms / pass %.1f ms; cached hold %.1f ms / pass %.1f ms\n",
                timing[0].max_hold_us / 1000.0, timing[0].pass_us / 1000.0,
                timing[1].max_hold_us / 1000.0, timing[1].pass_us / 1000.0);
    EXPECT_LT(timing[1].max_hold_us, timing[0].max_hold_us);
}

// ── The [CLEAN] pass line ────────────────────────────────────────────────────

TEST_F(LtcCleanDropTails, PassLineFormatAndWhenItIsDue)
{
    ltc::CleanPassTiming t;
    t.held_us = 123456;
    t.drop_us = 7890;
    t.total_us = 130000;
    t.removed = 1000;
    t.layers = 1000;
    t.cached = true;
    EXPECT_EQ(ltc::clean_pass_log_line(t),
              "[CLEAN] pass held_ms=123.5 drop_ms=7.9 total_ms=130.0 removed=1000 layers=1000 cache=on");
    t.cached = false;
    EXPECT_NE(ltc::clean_pass_log_line(t).find(" cache=off"), std::string::npos);

    ltc::CleanPassTiming idle;   // nothing removed, held under 1 ms: no line
    idle.held_us = 999;
    EXPECT_FALSE(ltc::clean_pass_log_due(idle));
    idle.held_us = 1000;
    EXPECT_TRUE(ltc::clean_pass_log_due(idle));
    idle.held_us = 100000;      // every hold of 100 ms or more
    EXPECT_TRUE(ltc::clean_pass_log_due(idle));
    ltc::CleanPassTiming quick_drop;   // removed something: always
    quick_drop.removed = 1;
    EXPECT_TRUE(ltc::clean_pass_log_due(quick_drop));
}

namespace {

// Records every Boost.Log line for inspection (LOG_INFO is BOOST_LOG_TRIVIAL).
class PassLogCapture
{
public:
    PassLogCapture() : stream_(boost::make_shared<std::ostringstream>())
    {
        auto backend = boost::make_shared<boost::log::sinks::text_ostream_backend>();
        backend->add_stream(stream_);
        backend->auto_flush(true);
        sink_ = boost::make_shared<sink_t>(backend);
        boost::log::core::get()->add_sink(sink_);
    }
    ~PassLogCapture() { boost::log::core::get()->remove_sink(sink_); }
    std::string str() const { return stream_->str(); }

private:
    using sink_t = boost::log::sinks::synchronous_sink<boost::log::sinks::text_ostream_backend>;
    boost::shared_ptr<std::ostringstream> stream_;
    boost::shared_ptr<sink_t> sink_;
};

}  // namespace

// A real pass that drains (300 shares, threshold 2*50+10: 191 layers) logs
// exactly one [CLEAN] pass line, with every field.
TEST_F(LtcCleanDropTails, RealCleanPassLogsOnePassLine)
{
    const bool was = boost::log::core::get()->get_logging_enabled();
    boost::log::core::get()->set_logging_enabled(true);
    std::string logged;
    {
        boost::asio::io_context ioc;
        auto node = std::make_unique<CleanNode>(ioc);
        build_node_trunk(*node, 300);
        node->m_coin_params.chain_length = 50;
        PassLogCapture cap;
        PassTiming timing;
        ASSERT_TRUE(run_clean_pass(*node, ioc, timing));
        logged = cap.str();
    }
    boost::log::core::get()->set_logging_enabled(was);
    const std::regex line(R"(\[CLEAN\] pass held_ms=[0-9]+\.[0-9] drop_ms=[0-9]+\.[0-9] total_ms=[0-9]+\.[0-9] removed=191 layers=191 cache=on)");
    size_t lines = 0, matching = 0;
    std::istringstream in(logged);
    for (std::string l; std::getline(in, l);) {
        if (l.find("[CLEAN] pass ") == std::string::npos)
            continue;
        ++lines;
        matching += std::regex_search(l, line) ? 1 : 0;
    }
    EXPECT_EQ(lines, 1u) << logged.substr(0, 4000);
    EXPECT_EQ(matching, 1u) << "the line must carry every field";
}

// The guard that times the hold is the first thing in the clean pass's lock
// scope (destroyed just before the lock, on every exit), and the line is
// written after the lock is released, only when due.
TEST_F(LtcCleanDropTails, PassLineIsTimedAroundTheCleanPassLock)
{
    std::ifstream in(std::string(C2POOL_IMPL_DIR) + "/ltc/node.cpp");
    ASSERT_TRUE(in.good());
    std::stringstream ss;
    ss << in.rdbuf();
    const std::string src = ss.str();
    const size_t clean = src.find("void NodeImpl::clean_tracker()");
    ASSERT_NE(clean, std::string::npos);
    const size_t lock = src.find("std::unique_lock lock(m_tracker_mutex);  // exclusive\n", clean);
    ASSERT_NE(lock, std::string::npos);
    const size_t timer = src.find("} hold_timer{pass_timing, pass_held, std::chrono::steady_clock::now(), pass_t0};", lock);
    ASSERT_NE(timer, std::string::npos);
    EXPECT_EQ(src.find("best_at_entry = best_at_exit", lock) > timer, true)
        << "the timing guard comes right after the lock, before Step 1";
    const size_t drop = src.find("ltc::drop_tails(m_tracker, m_supersede_hint, CL);", timer);
    ASSERT_NE(drop, std::string::npos);
    const size_t catch_all = src.find("LOG_ERROR << \"[CLEAN] failed on compute thread: unknown error\";", drop);
    ASSERT_NE(catch_all, std::string::npos);
    const size_t log = src.find("if (pass_held && ltc::clean_pass_log_due(pass_timing))", catch_all);
    ASSERT_NE(log, std::string::npos) << "the line is written after the lock scope";
    EXPECT_NE(src.find("LOG_INFO << ltc::clean_pass_log_line(pass_timing);", log), std::string::npos);
}

// ── The recorded store ───────────────────────────────────────────────────────

namespace {

struct DataDirScope {
    std::filesystem::path saved = core::filesystem::data_dir_override();
    explicit DataDirScope(const std::filesystem::path& d) { core::filesystem::set_data_dir(d); }
    ~DataDirScope() { core::filesystem::set_data_dir(saved); }
};

// Copies <src>/litecoin/sharechain_leveldb file by file to a fresh scratch
// root (the loader prunes below its window); the source is only read.
std::filesystem::path copy_store(const std::filesystem::path& src, const std::string& tag)
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("c2pool_ltc_droptails_" + tag + "_" + std::to_string(::getpid()));
    fs::remove_all(root);
    const fs::path dst = root / "litecoin" / "sharechain_leveldb";
    fs::create_directories(dst);
    for (const auto& e : fs::directory_iterator(src / "litecoin" / "sharechain_leveldb")) {
        if (!e.is_regular_file() || e.path().filename() == "LOCK")
            continue;
        const fs::path to = dst / e.path().filename();
        fs::copy_file(e.path(), to);
        fs::permissions(to, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::add);
    }
    return root;
}

void load_store(CleanNode& node, const std::filesystem::path& root)
{
    DataDirScope dd(root);
    node.m_storage = std::make_unique<c2pool::storage::SharechainStorage>("litecoin");
    ASSERT_TRUE(node.m_storage->is_available());
    node.load_persisted_shares();
    node.m_storage.reset();   // never written again
}

int32_t min_head_height(ltc::ShareTracker& t)
{
    int32_t m = INT32_MAX;
    for (const auto& [h, tl] : t.chain.get_heads())
        if (t.chain.contains(h))
            m = std::min(m, t.chain.get_height(h));
    return m;
}

std::map<uint256, uint256> heads_of(ltc::ShareChain& c)
{
    return {c.get_heads().begin(), c.get_heads().end()};
}

}  // namespace

TEST_F(LtcCleanDropTailsStore, RecordedStoreRemovesWhatTheMasterLoopRemoves)
{
    const char* src = std::getenv("C2POOL_REPLAY_STORE_LTC");
    if (!src || !*src)
        GTEST_SKIP() << "C2POOL_REPLAY_STORE_LTC unset: the recorded-store run is for the build host";
    QuietLog quiet;
    const std::filesystem::path source(src);
    std::vector<std::filesystem::path> roots;

    // 1. The loop alone on the loaded tracker: master's vs the cached one, at
    //    the node's threshold and at one under the shortest head (1000 layers).
    {
        boost::asio::io_context ioc;
        CleanNode na(ioc), nb(ioc);
        roots.push_back(copy_store(source, "loop_a"));
        roots.push_back(copy_store(source, "loop_b"));
        load_store(na, roots[0]);
        load_store(nb, roots[1]);
        ASSERT_GT(na.m_tracker.chain.size(), 1000u);
        std::printf("[LtcCleanDropTailsStore] loaded chain=%zu verified=%zu heads=%zu tails=%zu\n",
                    na.m_tracker.chain.size(), na.m_tracker.verified.size(),
                    na.m_tracker.chain.get_heads().size(), na.m_tracker.chain.get_tails().size());
        const int32_t forced = std::max<int32_t>(1, (min_head_height(na.m_tracker) - 10 - 1000) / 2);
        for (int32_t CL : {8640, forced}) {
            std::vector<uint256> rem_old, rem_new;
            const auto t0 = std::chrono::steady_clock::now();
            old_drop_tails(na.m_tracker, ltc::SupersedeHint{}, CL, &rem_old);
            const auto t1 = std::chrono::steady_clock::now();
            const auto res = ltc::drop_tails(nb.m_tracker, ltc::SupersedeHint{}, CL, false, &rem_new);
            const auto t2 = std::chrono::steady_clock::now();
            ASSERT_FALSE(res.cache_mismatch);
            ASSERT_EQ(rem_new, rem_old) << "CL " << CL;
            ASSERT_EQ(na.m_tracker.chain.size(), nb.m_tracker.chain.size());
            ASSERT_EQ(heads_of(na.m_tracker.chain), heads_of(nb.m_tracker.chain));
            ASSERT_EQ(na.m_tracker.verified.size(), nb.m_tracker.verified.size());
            std::printf("[LtcCleanDropTailsStore] loop, threshold %d: %zu removed, master %.1f ms, cached %.1f ms\n",
                        2 * CL + 10, rem_old.size(),
                        std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() / 1000.0,
                        std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count() / 1000.0);
        }
    }

    // 2. A real clean pass draining 1000 layers: cache off (master's work)
    //    against on, each on its own copy of the store.
    PassTiming timing[2];
    std::vector<uint256> rem[2];
    size_t chain_after[2] = {0, 0};
    std::map<uint256, uint256> heads_after[2];
    for (int cached = 0; cached < 2; ++cached) {
        boost::asio::io_context ioc;
        auto node = std::make_unique<CleanNode>(ioc);
        roots.push_back(copy_store(source, cached ? "pass_on" : "pass_off"));
        load_store(*node, roots.back());
        // The pass's threshold (2*chain_length+10, read from the node's coin
        // parameters) just under the shortest head, set after the load (whose
        // window it also sizes).
        node->m_coin_params.chain_length =
            static_cast<uint32_t>(std::max<int32_t>(1, (min_head_height(node->m_tracker) - 10 - 1000) / 2));
        node->m_tracker.chain.on_removed([&rem, cached](const uint256& h) { rem[cached].push_back(h); });
        {
            std::unique_ptr<CacheOff> off;
            if (!cached)
                off = std::make_unique<CacheOff>();
            ASSERT_TRUE(run_clean_pass(*node, ioc, timing[cached]));
        }
        std::shared_lock<std::shared_mutex> lk(node->tracker_mutex());
        chain_after[cached] = node->m_tracker.chain.size();
        heads_after[cached] = heads_of(node->m_tracker.chain);
    }
    EXPECT_GE(rem[0].size(), 1000u);
    EXPECT_EQ(rem[1], rem[0]) << "the cached pass removes what master's pass removes";
    EXPECT_EQ(chain_after[1], chain_after[0]);
    EXPECT_EQ(heads_after[1], heads_after[0]);
    EXPECT_FALSE(ltc::drop_tails_height_cache_disabled().load());
    std::printf("[LtcCleanDropTailsStore] real clean pass, %zu removed: cache off (master's work) hold %.1f ms / "
                "pass %.1f ms; cached hold %.1f ms / pass %.1f ms\n",
                rem[0].size(), timing[0].max_hold_us / 1000.0, timing[0].pass_us / 1000.0,
                timing[1].max_hold_us / 1000.0, timing[1].pass_us / 1000.0);

    std::error_code ec;
    for (const auto& r : roots)
        std::filesystem::remove_all(r, ec);
}
