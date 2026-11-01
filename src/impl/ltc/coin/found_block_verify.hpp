// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Found-block verdicts for the dashboard (/recent_blocks) on the embedded
/// LTC node: the parent (LTC) blocks and the merged (DOGE) blocks it found.
/// They feed MiningInterface::set_block_verify_fn / add_chain_verify_fn,
/// whose contract is: > 0 confirmed (the value is the confirmations),
/// < 0 orphaned, 0 pending (keep checking). TELEMETRY ONLY: a verdict never
/// gates a submit, a relay or a payout.
///
/// The verdict is taken at the height the found-block record holds (known
/// even when peers never relayed the block back), against the best chain
/// (BTC's block_confirm contract, impl/btc/coin/block_confirm.hpp, with the
/// orphan verdict held back to the same depth):
///   - our block is the best chain's block there: confirmed once kDepth deep
///     (tip - height + 1 >= kDepth), pending before: it can still be reorged
///     out, and MiningInterface never checks a confirmed row again;
///   - another block is there, or none while the tip is past the height:
///     orphaned once the best chain is kDepth deep from the height, pending
///     before (a sibling race can still go our way);
///   - the chain has not reached the height, or no height is known: pending.
///
/// main_ltc.cpp wires a ChainView over the embedded header chains; the KAT
/// (src/impl/ltc/test/found_block_verify_test.cpp) over maps.

#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <optional>

namespace ltc {
namespace coin {
namespace found_block {

/// What a verdict reads of a header chain.
struct ChainView {
    /// A known header's height, on any branch (nullopt: not known).
    std::function<std::optional<uint32_t>(const uint256&)> height_of;
    /// The best chain's block at a height (nullopt: none there).
    std::function<std::optional<uint256>(uint32_t)> hash_at;
    /// The best chain's tip height.
    std::function<uint32_t()> tip_height;
    /// The chain has a tip at all.
    std::function<bool()> has_tip;
};

/// Depth at which a verdict is final: the conventional 6 confirmations.
inline constexpr uint32_t kDepth = 6;

/// The rule above, for a block mined at `found_height` (the record's; when
/// unknown, the height of its header if the chain knows it).
inline int verdict_at_height(const ChainView& chain, const uint256& hash,
                             std::optional<uint32_t> found_height)
{
    if (!found_height)
        found_height = chain.height_of(hash);
    if (!found_height || !chain.has_tip())
        return 0;
    const uint32_t h = *found_height;
    const uint32_t tip = chain.tip_height();
    if (tip < h)
        return 0;  // the chain has not reached it
    const uint32_t depth = tip - h + 1;
    const auto winner = chain.hash_at(h);
    if (winner && *winner == hash)
        return depth >= kDepth ? static_cast<int>(depth) : 0;
    if (!winner)
        return 0;  // a hole in the height index: cannot judge
    return depth >= kDepth ? -1 : 0;
}

/// A parent (LTC) block.
inline int parent_verdict(const ChainView& chain, const uint256& hash,
                          std::optional<uint32_t> found_height)
{
    return verdict_at_height(chain, hash, found_height);
}

/// A merged (aux) block, against the aux chain's own header chain: a live
/// tip says nothing about whether our block is on it.
inline int aux_verdict(const ChainView& chain, const uint256& hash,
                       std::optional<uint32_t> found_height)
{
    return verdict_at_height(chain, hash, found_height);
}

} // namespace found_block
} // namespace coin
} // namespace ltc
