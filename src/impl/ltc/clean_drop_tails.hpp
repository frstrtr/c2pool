// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// clean_drop_tails.hpp: clean_tracker's "drop tails" step (node.cpp Step 3,
// p2pool node.py Node.clean_tracker), with a per-call head-height cache.
//
// The step removes, layer by layer, every child of a tail all of whose heads
// are at least 2*CHAIN_LENGTH+10 deep, up to 1000 layers per pass. Each layer
// needs the height of every head of every tail, and chain.get_height(head) is
// an uncached walk to the chain's end: a 1000-layer drain on a 24k-share chain
// with 5 heads is 1000 x 5 x 24k hash lookups under the exclusive tracker lock
// (one live LTC pass held it ~91 s). Here each head's height is walked once
// per call and then kept exact (the port of the DASH lane's cache,
// dash/clean_drop_tails.hpp, without its per-pass cap):
//   * a head's height falls by 1 exactly when a share in its ancestry is
//     removed, and the only shares removed here are children of tails;
//   * after chain.remove(c) succeeds, tails[c] is exactly the set of heads
//     whose ancestry contained c: remove() branch 3 (c the sole child of its
//     tail) moves every head of the old tail to tails[c]; branch 4 (c one of
//     several children) moves the heads through c (is_child_of). Those heads,
//     and only those, are decremented, wherever else they appear;
//   * a removed head (branch 1: c a head on a tail) leaves the cache and
//     decrements nothing (nothing descends from a head); a removal that fails
//     changes nothing and decrements nothing;
//   * the cache lives for one call, which runs under the exclusive tracker
//     lock: nothing but these removals changes the tracker while it lives,
//     and adds (which can raise a height) cannot happen.
// So every height the loop reads equals what get_height(head) would return,
// and the decisions, their order and the final tracker are those of the
// master loop (pinned against it verbatim in clean_drop_tails_test.cpp).
//
// Safety net (as in the DASH lane): after a call that removed anything, every
// cached head still in the chain is walked once more; a disagreement sets
// DropTailsResult::cache_mismatch and turns the cache off for the rest of the
// process (drop_tails_height_cache_disabled), so later passes walk every
// height again, as master does.
//   * The net detects; it cannot undo. The pass that detects a mismatch has
//     already made its removals with the wrong heights, so a broken invariant
//     is limited to that one pass.
//   * The guarantee holds only while removals are the only tracker change
//     inside a call. Wiring ShareChain::trim() (which updates heads and tails
//     outside remove()'s branches) or any new topology mutator into a lane's
//     clean pass voids it.
//   * The net must compare against a real walk. Under a cached get_height
//     (design B1) it must call the walk (walk_height), not get_height.

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include <core/log.hpp>
#include <core/uint256.hpp>

namespace ltc {

/// Set (process-wide, sticky) when the end-of-call check finds a cached height
/// that disagrees with a fresh walk; from then on every height is walked.
inline std::atomic<bool>& drop_tails_height_cache_disabled()
{
    static std::atomic<bool> off{false};
    return off;
}

struct DropTailsResult
{
    int total_dropped{0};
    int layers{0};               // iterations that found something to remove
    bool cached{false};          // the call used the head-height cache
    bool cache_mismatch{false};  // the end-of-call height check failed (cache now off)
};

/// One clean_tracker pass, timed on the compute thread with steady_clock: the
/// pass takes the exclusive tracker lock once (Steps 1-5), so its one hold is
/// both the longest and the total exclusive hold of the pass.
struct CleanPassTiming
{
    int64_t held_us{0};    // the exclusive tracker lock held (lock taken -> released)
    int64_t drop_us{0};    // the drop-tails step inside that hold
    int64_t total_us{0};   // the pass on the compute thread: lock wait + hold
    int removed{0};
    int layers{0};
    bool cached{false};
};

/// The [CLEAN] pass line is due when the pass removed something or held the
/// lock for 1 ms or more (so every hold of 100 ms or more is logged, and an
/// idle 5 s cadence of sub-millisecond passes is not).
inline bool clean_pass_log_due(const CleanPassTiming& t)
{
    return t.removed > 0 || t.held_us >= 1000;
}

/// `[CLEAN] pass held_ms=... drop_ms=... total_ms=... removed=N layers=L cache=on|off`
inline std::string clean_pass_log_line(const CleanPassTiming& t)
{
    char buf[200];
    std::snprintf(buf, sizeof buf,
                  "[CLEAN] pass held_ms=%.1f drop_ms=%.1f total_ms=%.1f removed=%d layers=%d cache=%s",
                  t.held_us / 1000.0, t.drop_us / 1000.0, t.total_us / 1000.0,
                  t.removed, t.layers, t.cached ? "on" : "off");
    return buf;
}

/// The drop-tails step. `Tracker` is ltc::ShareTracker (chain, verified);
/// `Hint` is ltc::SupersedeHint. `diag_log` keeps the node's per-removal stderr
/// markers and the QUALIFY warning (off in the tests). `removed`, if given,
/// receives each share chain.remove() took, in order. `after_remove`, if given,
/// runs after each successful removal (tests: it can break the invariant on
/// purpose to exercise the safety net).
template <typename Tracker, typename Hint>
DropTailsResult drop_tails(Tracker& tracker, const Hint& supersede_hint, int32_t CL,
                           bool diag_log = true, std::vector<uint256>* removed = nullptr,
                           const std::function<void(const uint256&)>* after_remove = nullptr)
{
    DropTailsResult res;
    std::map<uint256, int32_t> head_height;   // see the header comment
    const bool use_cache = !drop_tails_height_cache_disabled().load(std::memory_order_relaxed);
    res.cached = use_cache;
    auto height_of = [&](const uint256& head) -> int32_t {
        if (!use_cache)
            return tracker.chain.get_height(head);
        auto it = head_height.find(head);
        if (it != head_height.end())
            return it->second;
        const int32_t h = tracker.chain.get_height(head);
        head_height.emplace(head, h);
        return h;
    };

    int& total_dropped = res.total_dropped;
    for (int iter = 0; iter < 1000; ++iter)
    {
        std::vector<uint256> to_remove;
        auto tails_copy = tracker.chain.get_tails();
        for (auto& [tail_hash, head_hashes] : tails_copy)
        {
            // Restart-reorg: never drop the tail of the converging challenger
            // segment. An unrooted challenger needs its FULL ~2*CL depth to
            // reach CHAIN_LENGTH verified shares; trimming its bottom mid-
            // verification silently restarts convergence (looks like the
            // original stickiness). The exemption lifts once it verifies to
            // CHAIN_LENGTH and the hint deactivates, when normal drop-tails
            // resumes. Matched by segment id (the shared missing-parent).
            if (supersede_hint.active) {
                try {
                    if (tracker.chain.contains(tail_hash) &&
                        tracker.chain.get_last(tail_hash) == supersede_hint.target_segment_last)
                        continue;
                } catch (...) {}
            }

            int32_t min_height = 0;  // default 0 → skip if no valid heads
            for (auto& hh : head_hashes) {
                if (!tracker.chain.contains(hh)) continue;
                auto h = height_of(hh);
                if (min_height == 0 || h < min_height)
                    min_height = h;
            }
            if (min_height < 2 * CL + 10) continue;

            if (iter == 0 && diag_log) {
                LOG_WARNING << "[drop-tails-QUALIFY] tail=" << tail_hash.GetHex().substr(0,16)
                            << " min_height=" << min_height << " threshold=" << (2*CL+10)
                            << " n_heads=" << head_hashes.size()
                            << " chain_size=" << tracker.chain.size();
            }

            // p2pool node.py:386: to_remove.update(tracker.reverse.get(tail, set()))
            auto& rev = tracker.chain.get_reverse();
            auto rev_it = rev.find(tail_hash);
            if (rev_it != rev.end()) {
                for (const auto& child : rev_it->second)
                    to_remove.push_back(child);
            }
        }

        if (to_remove.empty()) break;
        ++res.layers;

        // p2pool node.py:392-398
        size_t _drop_idx = 0;
        for (const auto& aftertail : to_remove)
        {
            try {
                // DIAG: a node froze 40s on 2026-04-21 inside
                // unordered_map::contains() on an aftertail at bucket 2332.
                // If we spin here again this is the last line flushed —
                // gives us the iter index, which aftertail triggered it,
                // and the queue size to correlate with the freeze.
                if (diag_log) {
                    std::fprintf(stderr,
                        "[drop-tails-PRE] iter=%d drop_idx=%zu/%zu aftertail=%.16s "
                        "chain_size=%zu\n",
                        iter, _drop_idx, to_remove.size(),
                        aftertail.GetHex().c_str(),
                        tracker.chain.size());
                    std::fflush(stderr);
                }
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
                if (ok) {
                    head_height.erase(aftertail);   // it may have been a head
                    const auto& tails = tracker.chain.get_tails();
                    auto above = tails.find(aftertail);
                    if (above != tails.end())
                        for (const auto& h : above->second) {
                            auto c = head_height.find(h);
                            if (c != head_height.end())
                                --c->second;
                        }
                    if (removed)
                        removed->push_back(aftertail);
                    if (after_remove && *after_remove)
                        (*after_remove)(aftertail);
                }
                ++total_dropped;
            } catch (...) {}
        }
    }

    // Safety net: re-walk every cached head still in the chain once (about one
    // uncached layer). A disagreement means the invariant above no longer
    // holds; the caller logs it and every later call walks every height.
    if (use_cache && total_dropped > 0) {
        for (const auto& [head, cached] : head_height) {
            if (!tracker.chain.contains(head))
                continue;
            if (tracker.chain.get_height(head) != cached) {
                res.cache_mismatch = true;
                drop_tails_height_cache_disabled().store(true, std::memory_order_relaxed);
                break;
            }
        }
    }
    return res;
}

}  // namespace ltc
