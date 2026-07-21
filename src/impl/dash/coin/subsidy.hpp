// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-TEMPLATE step 1: block-subsidy + MN-payment formula vendor.
///
/// Direct port of dashcore validation.cpp::GetBlockSubsidyHelper +
/// GetMasternodePayment @ cfad414. The functions are pure (no chain
/// state needed), so we can call them on every observed block to do
/// shadow validation against the actual coinbase outputs.
///
/// We DELIBERATELY simplify by hard-coding the post-V20 / post-BRR
/// path: c2pool-dash's header checkpoint is at h=2,400,000, well past
/// V20Height (1,987,776) and BRRHeight (1,374,912), so we will never
/// observe a block where these aren't active. The pre-V20 / pre-BRR
/// paths (with the 9-step historical MN-payment-increase ladder + the
/// difficulty-driven nSubsidyBase formula) are NOT vendored. If we
/// ever observe a block at h<V20Height we'd log a SHADOW-SKIP and
/// move on; in practice it can't happen post-checkpoint.
///
/// Mainnet constants (chainparams.cpp:162-194):
///   nSubsidyHalvingInterval = 210240
///   nBudgetPaymentsStartBlock = 328008  (always passed by 2.4M)
///   BRRHeight = 1,374,912
///   V20Height = 1,987,776
///   nSuperblockCycle = 16616  (~30 days on mainnet)
///
/// Reference flow at block height H (post-V20 always true):
///   nSubsidyBase = 5  (fixed since V20)
///   nSubsidy     = nSubsidyBase * COIN  (= 500_000_000 sat)
///   for i = 210240; i <= H-1; i += 210240:
///       nSubsidy -= nSubsidy / 14    // ~7.14% yearly decline
///   nSuperblockPart = nSubsidy / 5    // 20% to treasury (V20 active)
///   block_reward    = nSubsidy - nSuperblockPart
///   mn_payment      = block_reward * 3 / 4    // 75% (post-realloc + V20)
///   miner_share     = block_reward / 4         // 25% + tx fees

#include <cstdint>

namespace dash {
namespace coin {

inline constexpr int64_t COIN_SAT = 100'000'000LL;

inline constexpr int DASH_SUBSIDY_HALVING_INTERVAL = 210240;
inline constexpr int DASH_V20_HEIGHT_MAINNET       = 1'987'776;
inline constexpr int DASH_BRR_HEIGHT_MAINNET       = 1'374'912;
inline constexpr int DASH_MN_RR_HEIGHT_MAINNET     = 2'128'896;
inline constexpr int DASH_SUPERBLOCK_CYCLE_MAINNET = 16616;
inline constexpr int DASH_SUPERBLOCK_CYCLE_TESTNET = 24;   // dashcore testnet nSuperblockCycle

/// Returns the BLOCK reward (excluding tx fees) for a block at height
/// `height` on Dash mainnet. Equivalent to dashcore's
/// GetBlockSubsidyInner @ height when V20 is active.
inline int64_t compute_dash_block_reward_post_v20(uint32_t height)
{
    // Mirror dashcore's prev_height-based loop.
    int prev_height = static_cast<int>(height) - 1;
    int64_t nSubsidy = 5 * COIN_SAT;
    for (int i = DASH_SUBSIDY_HALVING_INTERVAL;
         i <= prev_height;
         i += DASH_SUBSIDY_HALVING_INTERVAL) {
        nSubsidy -= nSubsidy / 14;
    }
    int64_t nSuperblockPart = nSubsidy / 5;
    return nSubsidy - nSuperblockPart;
}

/// Returns the MN payment amount given the block reward (excluding
/// fees). Equivalent to dashcore's GetMasternodePayment @ post-realloc
/// + V20-active path: blockValue * 3 / 4.
///
/// Note: dashcore passes blockValue = block_reward + tx_fees (i.e.,
/// MN gets 75% of subsidy + 75% of fees). For shadow validation
/// against observed coinbases we must include fees the same way.
inline int64_t compute_dash_mn_payment_post_v20(int64_t block_value)
{
    return block_value * 3 / 4;
}

/// Platform Credit Pool burn (DIP-0027 / Asset Lock) per-block share.
/// Activates when both V20 AND MN_RR are deployed (mainnet h>=MN_RR=2,128,896,
/// our checkpoint h=2.4M is always past). Mirror of dashcore PlatformShare()
/// at masternode/payments.cpp: PlatformShare(GetMasternodePayment(h, subsidy, true))
/// = (subsidy * 3/4) * 375/1000. Integer-arithmetic order matters: dashcore
/// truncates between the two divisions, so we replicate that order exactly.
/// The result is added as an OP_RETURN coinbase output and DEDUCTED from the
/// MN's portion (miner share is unaffected).
inline int64_t compute_dash_platform_reward_post_v20_mn_rr(uint32_t height)
{
    if (static_cast<int>(height) < DASH_MN_RR_HEIGHT_MAINNET) return 0;
    int64_t mn_subsidy_share = compute_dash_block_reward_post_v20(height) * 3 / 4;
    return mn_subsidy_share * 375 / 1000;
}

/// True if `height` is a superblock height (treasury budget payout).
inline bool is_superblock_height(uint32_t height,
                                 int cycle = DASH_SUPERBLOCK_CYCLE_MAINNET)
{
    return cycle > 0 && (height % static_cast<uint32_t>(cycle)) == 0;
}

} // namespace coin
} // namespace dash

#include "block.hpp"
#include "transaction.hpp"
#include <core/coin/utxo_view_cache.hpp>
#include <map>
#include <optional>

namespace dash {
namespace coin {

/// Sum of all coinbase output values. = block_reward + total_block_fees
/// for any accepted block. Used as one half of the cross-check in
/// Phase C-TEMPLATE step 2 shadow validation.
inline int64_t observed_coinbase_value(const dash::coin::BlockType& block)
{
    if (block.m_txs.empty()) return 0;
    int64_t sum = 0;
    for (const auto& vo : block.m_txs[0].vout) sum += vo.value;
    return sum;
}

/// Compute total block fees from UTXO + same-block parent outputs.
/// Walks non-coinbase txs; for each, sums input values via UTXO
/// lookups (with same-block parent-tx output fallback for chained
/// txs inside the block) and subtracts output values.
///
/// Returns nullopt when ANY input is missing from UTXO + same-block
/// parent. That happens during cold start (rolling-288 UTXO window
/// doesn't cover deeper inputs) or when the block contains txs
/// spending outputs from blocks we've never observed. Caller treats
/// nullopt as "skip the cross-check this block, retry next block".
inline std::optional<int64_t> computed_block_fees(
    const dash::coin::BlockType& block,
    ::core::coin::UTXOViewCache* utxo)
{
    if (!utxo || block.m_txs.size() <= 1) return int64_t{0};

    // Pre-index this block's outputs so chained txs (parent + child
    // in same block) can fall back to the parent's vout values when
    // the parent isn't yet in UTXO.
    std::map<uint256, const dash::coin::MutableTransaction*> in_block_txs;
    for (size_t i = 1; i < block.m_txs.size(); ++i) {
        in_block_txs[dash::coin::dash_txid(block.m_txs[i])] = &block.m_txs[i];
    }

    int64_t total_fees = 0;
    for (size_t i = 1; i < block.m_txs.size(); ++i) {
        const auto& tx = block.m_txs[i];
        int64_t in_sum = 0, out_sum = 0;
        for (const auto& vin : tx.vin) {
            ::core::coin::Outpoint op(vin.prevout.hash, vin.prevout.index);
            ::core::coin::Coin coin;
            if (utxo->get_coin(op, coin)) {
                in_sum += coin.value;
                continue;
            }
            // Same-block parent fallback.
            auto pit = in_block_txs.find(vin.prevout.hash);
            if (pit != in_block_txs.end()
                && vin.prevout.index < pit->second->vout.size()) {
                in_sum += pit->second->vout[vin.prevout.index].value;
                continue;
            }
            // Input missing → can't compute fees this block.
            return std::nullopt;
        }
        for (const auto& vo : tx.vout) out_sum += vo.value;
        if (in_sum < out_sum) return std::nullopt;
        total_fees += (in_sum - out_sum);
    }
    return total_fees;
}

} // namespace coin
} // namespace dash