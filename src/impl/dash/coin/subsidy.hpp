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

#include "block_reward.hpp"   // the pure formulas (moved verbatim)

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