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

}  // namespace dash::coin::block_confirm
