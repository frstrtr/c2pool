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
// SECOND PROBLEM (the FLAT PLATEAU, dash.voidbind.com 2026-08-27): on a zero-
// local-mint relay the verified best-share election can be seeded ONCE (during
// the initial hotel-sharechain backfill/verify) and then FREEZE -- peer-verified
// shares update the verified set but never re-elect the head. Because that frozen
// head is STILL CONTAINED in the raw chain window, the "present AND in chain"
// guard kept trusting it verbatim, so the estimator recomputed the SAME value off
// the SAME frozen anchor every sample and the pool-rate graph drew a perfectly
// flat rectangle (921 bit-identical samples / 15.3 h observed live) even though
// the raw sharechain tip provably kept advancing. The fix below stops trusting a
// verified best that is merely in-chain: if the tallest RAW head is materially
// taller (more than `stale_tolerance` shares) the verified election is stale, so
// anchor on the advancing raw head instead. This is display/data only -- the
// vardiff retarget never reads this hook (see below).
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
//      chain) AND fresh -- i.e. no raw head out-heights it by more than
//      `stale_tolerance` -- use it verbatim. Behaviour is UNCHANGED whenever a
//      live-mining node re-elects its verified head every share.
//   2. If the verified head is present-but-STALE (a raw head is more than
//      `stale_tolerance` shares taller than it), the verified election has
//      frozen: anchor on the tallest RAW head instead so the graph tracks the
//      advancing chain rather than a frozen anchor.
//   3. Otherwise (zero-local-miner bootstrap: no verified head, or it left the
//      chain), fall back to the tallest RAW chain head. Ties keep the FIRST head
//      seen at the maximum height (strictly-greater comparison), mirroring
//      node.hpp advertised_best_share()'s `if (h > best_height)` walk.
//   4. If there are no raw heads either (empty tracker), return null -- the
//      caller then holds the last-good value rather than publishing a spurious 0.
//
// `stale_tolerance` is a small slack (default 2 shares) so ordinary one-share
// lead/lag between the verified election and the raw tip does not flip the
// anchor every sample; only a genuinely stuck election (many shares behind) does.
inline uint256 select_pool_rate_head(const uint256& verified_best,
                                     bool verified_best_in_chain,
                                     int32_t verified_best_height,
                                     const std::vector<RawChainHead>& raw_heads,
                                     int32_t stale_tolerance = 2)
{
    // Tallest raw head (and its height), by the same walk advertised_best_share
    // uses. Null / height -1 when there are no usable raw heads.
    uint256 raw_best;          // null until a raw head is found
    int32_t raw_best_height = -1;
    for (const auto& head : raw_heads) {
        if (head.hash.IsNull())
            continue;
        if (head.height > raw_best_height) {
            raw_best_height = head.height;
            raw_best = head.hash;
        }
    }

    if (!verified_best.IsNull() && verified_best_in_chain) {
        // FRESHNESS: trust the verified election unless the raw tip has pulled
        // materially ahead of it (frozen-election guard). When it has, the
        // verified head is stale -- anchor on the advancing raw head.
        if (!raw_best.IsNull() &&
            raw_best_height > verified_best_height + stale_tolerance)
            return raw_best;
        return verified_best;
    }

    return raw_best;
}

}  // namespace dash
