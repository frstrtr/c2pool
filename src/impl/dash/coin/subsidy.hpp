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
inline constexpr int DASH_SUPERBLOCK_CYCLE_MAINNET = 16616;

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

/// True if `height` is a superblock height (treasury budget payout).
inline bool is_superblock_height(uint32_t height,
                                 int cycle = DASH_SUPERBLOCK_CYCLE_MAINNET)
{
    return cycle > 0 && (height % static_cast<uint32_t>(cycle)) == 0;
}

} // namespace coin
} // namespace dash
