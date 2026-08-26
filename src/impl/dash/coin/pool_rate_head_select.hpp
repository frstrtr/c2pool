// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SSOT for the DASH DASHBOARD POOL-RATE HEAD SELECTION -- the pure decision of
// WHICH sharechain head the pool-hashrate estimator runs over when the dashboard
// samples it.
//
// The estimator itself (ShareTracker::get_pool_attempts_per_second) is
// unchanged: it sums the per-share work over a window and divides by the window
// timespan -- p2pool data.py get_pool_attempts_per_second. What THIS header
// fixes is the head it is anchored to.
//
// PROBLEM (contabo / dash.voidbind.com bootstrap): the dashboard hook previously
// anchored the estimator on best_share_hash() -- the VERIFIED best-share head,
// elected only over tracker.verified. On a node running ZERO local rigs the
// verified chain has no heads (local mint is the only thing that seeds a verified
// head), so best_share_hash() is null and the estimator short-circuits to 0. The
// pool-rate graph then reads flat-zero even though peers have filled the RAW
// sharechain with the whole pool's shares.
//
// p2pool has no such gate: web.py add_point() feeds the pool-rate graph every 5s
// straight off tracker.get_height(best_share) / get_stale_counts over the shared
// chain, independent of any local miner. This header restores that behaviour for
// c2pool's dashboard: prefer the verified best-share head (unchanged when local
// mining seeds it), and when it is absent fall back to the tallest RAW chain
// head -- the same raw-head-by-height rule node.hpp advertised_best_share() uses
// for its pre-sync head advert.
//
// Consensus/reward-NEUTRAL: the value produced here feeds ONLY the web_server
// REST handlers (pool_hash_rate / pool_rates graph series and /global_stats).
// The vardiff retarget runs on the VERIFIED chain over TARGET_LOOKBEHIND
// (data.py:137,140) and never reads this hook. Display/data only.
//
// Pure function over already-collected inputs (the caller walks the tracker under
// its read lock and hands the resolved verified head + the raw heads here), so a
// KAT can pin the selection with no NodeImpl / ShareTracker / socket standup.
// Per-coin isolation: dash/ only, header-only, additive.

#include <cstdint>
#include <vector>

#include <core/uint256.hpp>

namespace dash {

// A raw sharechain head and its height, as read from ShareChain::get_heads() +
// ShareChain::get_height() under the tracker read lock.
struct RawChainHead {
    uint256 hash;
    int32_t height;
};

// Choose the sharechain head to anchor the dashboard pool-rate estimator on.
//
//   1. If the verified best-share head is present (non-null AND still in the
//      chain), use it verbatim -- behaviour is UNCHANGED whenever local mining
//      seeds a verified head.
//   2. Otherwise (zero-local-miner bootstrap: no verified head), fall back to the
//      tallest RAW chain head. Ties keep the FIRST head seen at the maximum
//      height (strictly-greater comparison), mirroring node.hpp
//      advertised_best_share()'s `if (h > best_height)` walk.
//   3. If there are no raw heads either (empty tracker), return null -- the
//      caller then holds the last-good value rather than publishing a spurious 0.
inline uint256 select_pool_rate_head(const uint256& verified_best,
                                     bool verified_best_in_chain,
                                     const std::vector<RawChainHead>& raw_heads)
{
    if (!verified_best.IsNull() && verified_best_in_chain)
        return verified_best;

    uint256 best;              // null until a raw head is found
    int32_t best_height = -1;
    for (const auto& head : raw_heads) {
        if (head.hash.IsNull())
            continue;
        if (head.height > best_height) {
            best_height = head.height;
            best = head.hash;
        }
    }
    return best;
}

}  // namespace dash
