// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Found-block verdicts for the dashboard (/recent_blocks) on the embedded
/// LTC node: the parent (LTC) blocks and the merged (DOGE) blocks it found.
/// They feed MiningInterface::set_block_verify_fn / add_chain_verify_fn,
/// whose contract is: > 0 confirmed (the value is the confirmations),
/// < 0 orphaned, 0 pending (keep checking). TELEMETRY ONLY: a verdict never
/// gates a submit, a relay or a payout.
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

/// A parent (LTC) block: a header the chain knows is confirmed, with
/// tip - height + 1 confirmations.
inline int parent_verdict(const ChainView& chain, const uint256& hash,
                          std::optional<uint32_t> /*found_height*/)
{
    const auto h = chain.height_of(hash);
    if (!h)
        return 0;  // not in our chain — still pending
    const int32_t tip_h = static_cast<int32_t>(chain.tip_height());
    const int32_t blk_h = static_cast<int32_t>(*h);
    return std::max(1, tip_h - blk_h + 1);
}

/// A merged (aux) block: confirmed while the chain has a tip.
inline int aux_verdict(const ChainView& chain, const uint256& /*hash*/,
                       std::optional<uint32_t> /*found_height*/)
{
    return chain.has_tip() ? 1 : 0;
}

} // namespace found_block
} // namespace coin
} // namespace ltc
