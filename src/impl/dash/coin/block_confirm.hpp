// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// DASH post-broadcast block confirmation / orphan verdict.
///
/// This is the daemonless resolver behind the dashboard found-block status
/// lane. It answers ONE question about a block we already broadcast: is it
/// still on the best chain at its height (confirmed), did a different block
/// win that height (orphaned), or is the chain not deep enough to tell yet
/// (pending)?
///
/// TELEMETRY ONLY. It runs AFTER submission and can never affect a broadcast
/// — the pre-broadcast payee guard (work_source.cpp) is the consensus gate.
/// Its sole effect is to flip a dashboard row out of "pending".
///
/// It is genuinely daemonless: the only primitive it needs is "which hash is
/// on the best chain at height h" plus the current tip height. The embedded
/// DASH HeaderChain answers both from its X11+DGW-validated, height-indexed
/// on-disk chain (get_header_by_height() reflects the current best branch,
/// rebuilt from the tip via prev_hash on every reorg), so orphan detection
/// does NOT depend on our own orphaned header ever being delivered by peers —
/// we compare the *winner* at our recorded height against our block hash.

#include <core/uint256.hpp>

#include <cstdint>
#include <functional>
#include <limits>
#include <optional>

namespace dash::coin::block_confirm {

// Minimum confirmations (best-chain depth) before a found block is flipped to
// "confirmed". 1 == "accepted into the best chain" (block-acceptance, NOT
// coinbase maturity), matching the LTC embedded verifier's semantics.
inline constexpr uint32_t kDefaultConfirmDepth = 1;

/// Resolve a found block's dashboard status from a best-chain-at-height view.
///
///   best_hash_at_height(h): the hash currently on the BEST chain at height h,
///                           or std::nullopt if the chain has not yet reached
///                           height h (or does not index it).
///   tip_height:   current best-chain tip height.
///   found_hash:   the block we broadcast and are tracking.
///   found_height: the height that block was mined at (from our found-block
///                 record — authoritative even when the block was orphaned and
///                 its header never entered our chain).
///   confirm_depth: min best-chain depth before declaring confirmed (>=1).
///
/// Returns  >0  → confirmed, value == confirmation count (tip - height + 1)
///          <0  → orphaned (a different block occupies found_height)
///           0  → pending (chain not deep enough yet, or on-chain but shallow)
inline int resolve_status(
    const std::function<std::optional<uint256>(uint32_t)>& best_hash_at_height,
    uint32_t tip_height,
    const uint256& found_hash,
    uint32_t found_height,
    uint32_t confirm_depth = kDefaultConfirmDepth)
{
    if (confirm_depth < 1) confirm_depth = 1;

    auto winner = best_hash_at_height(found_height);
    if (!winner.has_value())
        return 0;                       // chain has not reached this height → pending

    if (*winner != found_hash)
        return -1;                      // a different block won this height → orphaned

    // Our block IS the best-chain block at found_height.
    if (tip_height < found_height)
        return 0;                       // inconsistent view (race) → pending

    uint32_t confs = tip_height - found_height + 1;
    if (confs < confirm_depth)
        return 0;                       // on chain but not buried enough yet → pending

    if (confs > static_cast<uint32_t>(std::numeric_limits<int>::max()))
        confs = static_cast<uint32_t>(std::numeric_limits<int>::max());
    return static_cast<int>(confs);
}

// Margin, in header-timestamp seconds, that the header chain must extend on
// BOTH sides of a found block's recorded time before its absence counts as an
// orphan verdict (resolve_unknown_height). 2 h: covers Dash Core's +2 h
// future-time allowance on header timestamps, and ~46 blocks of depth behind
// the found time — far past anything a ChainLocked chain reorganises.
inline constexpr int64_t kUnknownHeightSpanMarginSec = 2 * 60 * 60;

/// Verdict for a found block whose HEIGHT IS UNKNOWN (a row recorded before the
/// work source read the job's height: height 0) and whose hash the header
/// chain does NOT hold, not even on a side branch. resolve_status() cannot run
/// without a height, and such a row used to stay "pending" forever (production
/// 2026-10-25: 000000000000001c9e20…, orphaned per every other node's ledger,
/// pending on the node that found it for a month).
///
///   time_at_height(h): header timestamp of the best-chain header at height h,
///                      or nullopt if the chain does not index h (below its
///                      root, or above its tip).
///   tip_height:        current best-chain tip height.
///   found_ts:          the row's recorded found time (unix seconds).
///
/// Returns -1 (orphaned) only when the header chain demonstrably spans the
/// found time with `margin` on both sides — its root header is at least
/// `margin` older and its tip header at least `margin` newer — so a block that
/// was on the best chain anywhere in that window would be in the index. The
/// caller has already established that the hash is not in the index.
/// Otherwise 0 (pending): the chain is rooted later (cold start from an
/// anchor), has not advanced far enough yet, or cannot be read.
/// Never returns >0: a held block always has a height and goes through
/// resolve_status().
inline int resolve_unknown_height(
    const std::function<std::optional<int64_t>(uint32_t)>& time_at_height,
    uint32_t tip_height,
    int64_t found_ts,
    int64_t margin = kUnknownHeightSpanMarginSec)
{
    if (found_ts <= 0 || margin < 0) return 0;
    const auto tip_time = time_at_height(tip_height);
    if (!tip_time.has_value() || *tip_time < found_ts + margin)
        return 0;                       // chain not yet far enough past the find

    // Lowest indexed height: headers are contiguous from the root to the tip,
    // so "indexed" is monotone in height — binary search for the first one.
    uint32_t lo = 0, hi = tip_height;   // invariant: hi is indexed
    while (lo < hi) {
        const uint32_t mid = lo + (hi - lo) / 2;
        if (time_at_height(mid).has_value()) hi = mid;
        else lo = mid + 1;
    }
    const auto root_time = time_at_height(lo);
    if (!root_time.has_value() || *root_time > found_ts - margin)
        return 0;                       // chain rooted too late to judge

    return -1;                          // spanned on both sides, not held → orphaned
}

}  // namespace dash::coin::block_confirm
