// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SSOT for the DASHBOARD POOL-RATE HEAD SELECTION -- the pure decision of WHICH
// sharechain head the pool-hashrate estimator (and the pool_stale_prop series)
// anchors on when the dashboard samples them. Coin-generic: the LTC lane wires
// it first (issue #1482); any coin can reuse the same pure rule.
//
// The estimator itself (ShareTracker::get_pool_attempts_per_second) is
// unchanged -- it sums per-share work over a window and divides by the window
// timespan (p2pool data.py get_pool_attempts_per_second). What THIS header
// fixes is the HEAD that estimator is anchored to, and it captures p2pool's
// "best-known LIVE head" rule.
//
// PROBLEM (ltc.voidbind.com, issue #1482): the dashboard feeds anchored on the
// TALLEST RAW head. Between two raw heads at (near-)equal height the anchor
// FLIPS sample-to-sample, so the pool-rate graph draws a rectangle and the
// pool_stale_prop series flaps (0.05 <-> 0.29 <-> 0.40). p2pool's web.py
// add_point() instead feeds the graph off the node's best-known LIVE head --
// the verified best share when it is live, else the fastest live raw head --
// which is stable because it tracks the chain the pool is actually extending,
// not whichever transient fork happens to be one share taller this instant.
//
// THE RULE (mirrors p2pool web.py get_local_rates / get_global_stats feeding
// the graph off tracker.get_pool_attempts_per_second(best_share_hash, ...)):
//   1. If the VERIFIED best-share head is present (non-null) AND LIVE -- its
//      newest share is within `liveness_horizon_s` seconds of now -- anchor on
//      it verbatim. This is the steady state on a live-mining node and matches
//      p2pool feeding the graph off best_share_hash.
//   2. Otherwise (no verified head yet -- the zero-local-miner relay bootstrap
//      -- OR the verified election has frozen so its head is now STALE) anchor
//      on the LIVE raw head with the greatest get_pool_attempts_per_second.
//      Using APS (not raw height) is what makes the choice stable: the head
//      carrying the pool's actual work wins, and a one-share height lead on a
//      near-empty transient fork does not flip the anchor.
//   3. A raw head whose newest share is OLDER than the liveness horizon is
//      DEAD (a stale foreign fork nobody is extending) and is ignored even if
//      its windowed APS looks high -- never anchor the live graph on a dead
//      chain.
//   4. If no head is live at all (empty tracker, or every head dead), return
//      null -- the caller then HOLDS its last-good value rather than publishing
//      a spurious 0.
//
// Consensus/reward-NEUTRAL: the value produced here feeds ONLY the web_server
// REST handlers (pool_hash_rate / pool_rates graph series, pool_stale_prop and
// /global_stats). The vardiff retarget runs on the VERIFIED chain over
// TARGET_LOOKBEHIND (p2pool data.py:137,140) and never reads this hook.
// Display/data only.
//
// Pure function over already-collected inputs (the caller walks the tracker
// under its lock and hands the resolved verified head + the raw heads, each
// with its newest-share age and windowed APS, here), so a KAT can pin the
// selection with no NodeImpl / ShareTracker / socket standup.

#include <cstdint>
#include <vector>

#include <core/uint256.hpp>

namespace sharechain {

// A candidate sharechain head for the dashboard pool-rate estimator. The caller
// fills these from ShareChain::get_heads() + get_height() + the head share's
// timestamp + ShareTracker::get_pool_attempts_per_second(), all under the
// tracker lock.
struct PoolRateHead {
    uint256 hash;
    int32_t height{0};
    // Seconds between now and the newest share on this head. NEGATIVE means
    // "unknown / no datable share" -> treated as NOT live (never anchored on).
    int64_t newest_share_age_s{-1};
    // get_pool_attempts_per_second over the display lookbehind on this head.
    double  aps{0.0};
};

// A head is LIVE when its newest share is datable and within the horizon.
inline bool pool_rate_head_is_live(const PoolRateHead& h, int64_t horizon_s)
{
    return h.newest_share_age_s >= 0 && h.newest_share_age_s <= horizon_s;
}

// Choose the head to anchor the dashboard pool-rate estimator on (see header).
//   verified          : the verified best-share head candidate.
//   verified_present  : false when there is no verified best (null / not in
//                       chain) -- then `verified` is ignored entirely.
//   raw_heads         : every raw chain head, with age + APS filled.
//   liveness_horizon_s: max newest-share age for a head to count as live
//                       (default 600 s, matching the estimator staleness bound).
// Returns the chosen head hash, or a null uint256 when nothing is live.
inline uint256 select_pool_rate_head(const PoolRateHead& verified,
                                     bool verified_present,
                                     const std::vector<PoolRateHead>& raw_heads,
                                     int64_t liveness_horizon_s = 600)
{
    // 1. Verified best-share head, when present AND live, wins outright.
    if (verified_present && !verified.hash.IsNull() &&
        pool_rate_head_is_live(verified, liveness_horizon_s))
        return verified.hash;

    // 2/3. Among the LIVE raw heads, the one with the greatest windowed APS.
    // Ties break to the greater height, then to first-seen (strictly-greater
    // comparisons), so the choice is deterministic sample-to-sample. Dead heads
    // (age past the horizon) are skipped even when their APS is larger.
    uint256 best;              // null until a live raw head is found
    bool    found = false;
    double  best_aps = 0.0;
    int32_t best_height = -1;
    for (const auto& h : raw_heads) {
        if (h.hash.IsNull())
            continue;
        if (!pool_rate_head_is_live(h, liveness_horizon_s))
            continue;
        if (!found || h.aps > best_aps ||
            (h.aps == best_aps && h.height > best_height)) {
            found = true;
            best = h.hash;
            best_aps = h.aps;
            best_height = h.height;
        }
    }

    // 4. Nothing live -> null; the caller holds its last-good value.
    return found ? best : uint256{};
}

// p2pool data.py get_average_stale_prop(share, lookbehind) == an ANCHORED-window
// stale fraction: count the stale (orphan+dead) shares among the `lookbehind`
// shares walking back from the anchor head, then
//     stale_prop = stales / (lookbehind + stales).
// The denominator is the FIXED lookbehind (min(height, 3600/SHARE_PERIOD)) plus
// the stales, NOT the whole chain-length window -- that is what stops the flap
// and the 1/(1-p) gross-up drift the count-over-CL formula produced (#1482).
inline double average_stale_prop(int stales, int lookbehind)
{
    if (stales < 0) stales = 0;
    if (lookbehind < 0) lookbehind = 0;
    const long denom = static_cast<long>(lookbehind) + static_cast<long>(stales);
    return denom > 0 ? static_cast<double>(stales) / static_cast<double>(denom)
                     : 0.0;
}

}  // namespace sharechain
