// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// clean_tracker Step 3 — drop tails (p2pool node.py:382-398), with a per-pass cap.
//
// Removes the children of every tail whose heads are ALL at least
// `min_head_height` (2*CHAIN_LENGTH+10) high: only shares far beyond the PPLNS
// window go. One layer per iteration, exactly as before.
//
// THE CAP (lock-hold bound). This runs under the exclusive tracker lock, and
// one removal costs milliseconds on a full tracker (the 11-17/18 VM504
// measurement: 5-11 ms per share, 688-804 shares in one pass after a supersede
// flip = 8-9 s exclusive; prod drops of 168-422 shares about hourly). A pass
// now removes at most `max_drop` shares (kCleanDropTailsMaxPerPass) and leaves
// the rest to the next clean tick (15 s). Nothing else changes: the same rule
// selects the same shares in the same order, so repeated capped passes reach
// the IDENTICAL tracker state as one uncapped pass (pinned by
// test_dash_clean_drop_tails). The backlog is bounded: 32 per 15 s drains far
// faster than shares arrive. Only shares outside the PPLNS window are ever
// touched, so share acceptance and payout math are unaffected.
//
// max_drop <= 0 means uncapped (the previous behaviour; tests use it as the
// reference).

#include <impl/dash/share_tracker.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <map>
#include <vector>

namespace dash {

/// Shares one clean pass may drop (Step 3). See the header comment.
inline constexpr int kCleanDropTailsMaxPerPass = 32;

struct DropTailsResult {
    int  dropped{0};
    bool capped{false};   // stopped at max_drop with eligible shares possibly left
};

/// `exempt_tail(tail_hash)` -> true keeps that tail's children this pass (the
/// restart-reorg challenger segment). `removed_out`, when given, receives the
/// removed hashes in removal order (tests).
///
/// HEAD-HEIGHT CACHE (the per-share cost). chain.get_height(head) is an
/// uncached O(chain) walk; the loop needs every head's height once per layer,
/// so a full-tracker pass cost heads x chain lookups per dropped share (the
/// 11-18 191 measurement: 99-100% of Step 3). Heights are now computed once per
/// call and kept exact by this invariant:
///   * a head's height falls by 1 exactly when a share in its ancestry is
///     removed, and the only shares removed here are children of tails;
///   * after chain.remove(c) succeeds, tails[c] is precisely the set of heads
///     whose ancestry contained c (remove() branch 3, sole child: all heads of
///     the old tail; branch 4, forked bottom: the heads through c) — so those,
///     and only those, are decremented: keyed per tail -> head set, never
///     globally;
///   * if c was itself a head (branch 1) it leaves the cache; a failed or
///     aborted removal changes nothing and decrements nothing;
///   * the cache lives for one call; nothing else mutates the tracker during it
///     (exclusive lock), so a tail set that changes mid-pass only changes
///     through these removals.
/// The removal decisions, their order and the result are identical to
/// recomputing every height (pinned against the previous loop, verbatim, in
/// test_dash_clean_drop_tails). The exemption predicate needs no cache: the
/// caller's check is O(1).
template <typename ExemptTailFn>
DropTailsResult drop_tails(ShareTracker& tracker, int32_t min_head_height,
                           int max_drop, ExemptTailFn&& exempt_tail,
                           std::vector<uint256>* removed_out = nullptr)
{
    DropTailsResult r;
    std::map<uint256, int32_t> head_height;   // see HEAD-HEIGHT CACHE above
    auto height_of = [&](const uint256& head) -> int32_t {
        auto it = head_height.find(head);
        if (it != head_height.end()) return it->second;
        const int32_t h = tracker.chain.get_height(head);
        head_height.emplace(head, h);
        return h;
    };
    for (int iter = 0; iter < 1000; ++iter)
    {
        if (max_drop > 0 && r.dropped >= max_drop) { r.capped = true; break; }

        std::vector<uint256> to_remove;
        auto tails_copy = tracker.chain.get_tails();
        for (auto& [tail_hash, head_hashes] : tails_copy)
        {
            if (exempt_tail(tail_hash))
                continue;

            int32_t min_height = 0;  // 0 -> skip if no valid heads
            for (auto& hh : head_hashes) {
                if (!tracker.chain.contains(hh)) continue;
                auto h = height_of(hh);
                if (min_height == 0 || h < min_height)
                    min_height = h;
            }
            if (min_height < min_head_height) continue;

            // p2pool node.py:386: to_remove.update(reverse.get(tail))
            auto& rev = tracker.chain.get_reverse();
            auto rev_it = rev.find(tail_hash);
            if (rev_it != rev.end()) {
                for (const auto& child : rev_it->second)
                    to_remove.push_back(child);
            }
        }

        if (to_remove.empty()) break;

        for (const auto& aftertail : to_remove)
        {
            if (max_drop > 0 && r.dropped >= max_drop) { r.capped = true; break; }
            try {
                if (!tracker.chain.contains(aftertail)) continue;
                // p2pool node.py:393: previous_hash must still be a tail.
                auto* idx = tracker.chain.get_index(aftertail);
                if (!idx) continue;
                if (!tracker.chain.get_tails().count(idx->tail))
                    continue;
                if (tracker.verified.contains(aftertail))
                    tracker.verified.remove(aftertail, /*owns_data=*/false);
                const bool removed = tracker.chain.remove(aftertail);
                ++r.dropped;
                if (removed_out) removed_out->push_back(aftertail);
                if (removed) {
                    head_height.erase(aftertail);   // it may have been a head
                    const auto& tails = tracker.chain.get_tails();
                    auto above = tails.find(aftertail);
                    if (above != tails.end())
                        for (const auto& h : above->second) {
                            auto c = head_height.find(h);
                            if (c != head_height.end()) --c->second;
                        }
                }
            } catch (...) {}
        }
        if (r.capped) break;
    }
    return r;
}

} // namespace dash
