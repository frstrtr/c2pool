// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SSOT for the think() Phase-5 BEST-SHARE PUNISH WALK — the pure graph decision
// that, given the highest-scored decorated head, resolves the share the node
// will actually build on and the punishment value it reports.
//
// p2pool punishes a share whose block was found invalid (naughty > 0): such a
// head must NOT be built on directly. The walk is:
//   1. start at the best decorated head;
//   2. while it is naughty, step to its previous share; the moment a NON-naughty
//      ancestor is reached, dive forward to the DEEPEST non-naughty descendant
//      (skipping naughty children, bounded to 20 generations) and stop;
//   3. if the walk runs off the end of the chain (prev missing) while still
//      naughty, stop on that last naughty share;
//   4. punish_val = the naughty count of the share best_idx finally points at
//      (0 unless we stopped ON a naughty share).
//
// This is currently OPEN-CODED inline in share_tracker.hpp think() Phase 5. A
// silent drift here changes which share the pool extends after an invalid block:
// too-eager and we orphan good work; too-lax and we build on a known-bad head.
// No compile error would catch a flipped naughty test or an off-by-one descend
// bound. Lifting the walk to a header-only SSOT lets a KAT pin it on a fake
// chain with no ShareTracker/NodeImpl standup.
//
// Oracle: p2pool data.py:2142-2166  OkayTracker.think() best-share resolution
// (the `while punish ... self.heads ... best_descendent` walk-back loop).
//
// Per-coin isolation: dgb/ only. Header-only, additive; this slice does NOT yet
// rewire share_tracker.hpp (that is the byte-identity-fenced delegation
// follow-on) — it pins the walk as a free function so the KAT exercises it on a
// hand-built graph. Consensus-neutral: pure graph traversal, no value semantics
// changed.

#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

namespace dgb {

// Graph accessors over the sharechain, supplied by the caller (production wires
// these to chain.get_index/get_share/contains/get_reverse; the KAT wires them to
// hand-built maps). All are pure reads.
template <typename Hash>
struct P5ChainAccessors {
    // naughty count of a share (0 if non-naughty OR absent — mirrors the inline
    // `best_idx && best_idx->naughty > 0` guard, where a null index reads as 0).
    std::function<int32_t(const Hash&)> naughty;
    // m_prev_hash of a share (a null/sentinel Hash if none).
    std::function<Hash(const Hash&)> prev_of;
    // whether the chain contains a hash.
    std::function<bool(const Hash&)> contains;
    // reverse-map children of a share (empty if leaf/absent).
    std::function<std::vector<Hash>(const Hash&)> children;
    // whether a Hash is the null/sentinel value.
    std::function<bool(const Hash&)> is_null;
};

template <typename Hash>
struct P5Result {
    Hash best;          // the share to build on
    int32_t punish_val; // self.punish reported out of Phase 5
};

// Deepest non-naughty descendant from `h`, bounded to `limit` generations,
// skipping naughty children. Returns {generations_below_h, deepest_hash}.
// Byte-faithful to the inline `best_desc` lambda (first-strictly-greater wins;
// a node with no eligible kids returns {0, h}).
template <typename Hash>
inline std::pair<int, Hash> think_p5_best_descendant(
    const Hash& h, int limit, const P5ChainAccessors<Hash>& acc)
{
    if (limit < 0) return {0, h};
    auto kids = acc.children(h);
    if (kids.empty()) return {0, h};
    std::pair<int, Hash> best_kid = {-1, h};
    for (const auto& child : kids) {
        if (acc.naughty(child) > 0) continue;
        auto [gen, hash] = think_p5_best_descendant(child, limit - 1, acc);
        if (gen + 1 > best_kid.first) best_kid = {gen + 1, hash};
    }
    return best_kid.first >= 0 ? best_kid : std::pair<int, Hash>{0, h};
}

// The Phase-5 best-share punish walk. `start` is the highest-scored decorated
// head; `start_valid` is the outer `!best.IsNull() && chain.contains(best)`
// guard — when false, the walk is skipped and {start, 0} is returned verbatim.
template <typename Hash>
inline P5Result<Hash> think_p5_best_share_punish(
    const Hash& start, bool start_valid, const P5ChainAccessors<Hash>& acc)
{
    Hash best = start;
    if (!start_valid)
        return {best, 0};

    // idx tracks the share best_idx points at; it can diverge from `best` once
    // we dive to a descendant (the inline code does NOT re-read best_idx there).
    Hash idx = best;
    if (acc.naughty(idx) > 0) {
        while (acc.naughty(idx) > 0) {
            Hash prev = acc.prev_of(best);
            if (acc.is_null(prev) || !acc.contains(prev)) break;
            best = prev;
            idx = prev;
            if (acc.naughty(idx) == 0) {
                best = think_p5_best_descendant(best, 20, acc).second;
                break;
            }
        }
    }
    int32_t punish_val = acc.naughty(idx) > 0 ? acc.naughty(idx) : 0;
    return {best, punish_val};
}

} // namespace dgb