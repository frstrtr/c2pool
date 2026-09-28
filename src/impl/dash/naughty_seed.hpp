// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ============================================================================
// naughty_seed.hpp — the rule that marks a share "naughty" (its block would be
// invalid), for the DASH v36 network.
//
// ORIGIN: this seed is a c2pool design decision for the DASH v36 network
// (operator, 2026-09-28). It revives the pre-v34 p2pool rule from
// share.check(); in the v35+ p2pool lineage that rule is gated
// `if self.VERSION < 34` and is dead code, so no v35/v36 p2pool share is ever
// seeded naughty, and no other c2pool lane seeds it either (the DGB lane only
// has the propagation helper). What is kept from the p2pool lineage:
//   * naughty starts at 0 (data.py Share.__init__);
//   * the seed is the excessive-block-reward rule: when the height of the
//     share's parent block is known, a share whose share_data subsidy
//     exceeds base_subsidy(height) + fees of its transactions is
//     naughty = 1. Under-payment is a valid (if wasteful) block and is not
//     punished; an unknown height leaves the share unseeded;
//   * then a naughty parent overrides it: naughty = 1 + parent.naughty,
//     reset to 0 past 6 generations;
//   * best-head selection deducts one share of work from a naughty head,
//     sorts on -naughty, walks back past naughty shares and picks the best
//     non-naughty descendant (share_tracker.hpp think() Phase 4/5).
//
// Where it applies:
//   * the public v16 network: NEVER. p2pool-dash has no naughty field and no
//     seed at all (data.py should_punish_reason: block solution and oversized
//     blocks only), so a seed there would elect heads p2pool-dash peers do
//     not. SharechainConfig::share_profile().naughty_seed is false.
//   * the DASH v36 network: seeded. It is coinbase-only (no transactions, so
//     fees are 0), so the rule is exactly subsidy > block reward at the
//     share's block height, plus the superblock budget at a superblock height
//     (the treasury payees ride in the same coinbase value; the budget is
//     the cap the schedule can never exceed).
//
// A share that fails check() is not naughty: it is not verified at all (and
// the peer that sent it is dealt with by the receive path).
//
// Header-only, fenced to src/impl/dash/. KAT: test_dash_naughty_seed.cpp,
// test_dash_v36_flip.cpp (node level).
// ============================================================================

#include "config_pool.hpp"
#include "coin/block_reward.hpp"  // block reward, V20 heights, superblock cycle + budget (pure)

#include <cstdint>
#include <optional>

namespace dash {

/// The one place the per-network profile is read for this rule.
inline bool naughty_seed_active()
{
    return SharechainConfig::share_profile().naughty_seed;
}

/// The most a coinbase-only block at `height` may pay: the block reward (the
/// miner + masternode part, dashcore GetBlockSubsidy less the treasury slice)
/// plus, at a superblock height, the superblock budget. nullopt below the
/// network's V20 height, where the reward formula depends on the block bits:
/// the rule is inert there (the DASH v36 network never runs below V20).
inline std::optional<uint64_t> max_coinbase_value(uint32_t height, bool is_testnet)
{
    const int v20 = is_testnet ? coin::DASH_V20_HEIGHT_TESTNET : coin::DASH_V20_HEIGHT_MAINNET;
    if (static_cast<int64_t>(height) < v20)
        return std::nullopt;
    const int cycle = is_testnet ? coin::DASH_SUPERBLOCK_CYCLE_TESTNET
                                 : coin::DASH_SUPERBLOCK_CYCLE_MAINNET;
    uint64_t max = static_cast<uint64_t>(coin::compute_dash_block_reward_post_v20(height));
    if (coin::is_superblock_height(height, cycle))
        max += static_cast<uint64_t>(coin::superblock_budget(height, cycle));
    return max;
}

/// The excessive-reward test (oracle `subsidy > max`, strictly greater).
inline bool excessive_reward(uint64_t subsidy, std::optional<uint64_t> max)
{
    return max.has_value() && subsidy > *max;
}

/// naughty of a child of a naughty parent: 1 + parent, back to 0 past 6
/// generations (the oracle's "to the third and fourth generation" clamp).
inline int32_t naughty_child_generation(int32_t parent)
{
    const int32_t n = 1 + parent;
    return n > 6 ? 0 : n;
}

} // namespace dash
