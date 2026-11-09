// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The pure DASH block-reward formulas (dashcore GetBlockSubsidy post-V20,
/// GetMasternodePayment, PlatformShare, the superblock height test and
/// CalcSuperblockBudget), with no block/UTXO dependency, so consensus-side
/// code (the sharechain naughty seed, naughty_seed.hpp) can use them without
/// the coin-validation headers. subsidy.hpp and superblock.hpp include this
/// file; their contents and behaviour are unchanged. Derivation notes and
/// constants provenance: subsidy.hpp header comment.

#include <cstdint>

namespace dash {
namespace coin {

inline constexpr int64_t COIN_SAT = 100'000'000LL;

inline constexpr int DASH_SUBSIDY_HALVING_INTERVAL = 210240;
inline constexpr int DASH_V20_HEIGHT_MAINNET       = 1'987'776;
inline constexpr int DASH_BRR_HEIGHT_MAINNET       = 1'374'912;
inline constexpr int DASH_MN_RR_HEIGHT_MAINNET     = 2'128'896;
// Testnet activation heights (dashcore chainparams.cpp CTestNetParams;
// cross-checked live against testnet dashd getblockchaininfo softforks:
// v20 buried @905100, mn_rr buried @1066900). MN_RR gates the DIP-0027
// platform-share credit-pool accrual — using the MAINNET height on testnet
// makes the per-block platform reward evaluate to 0 for every testnet
// height in [1066900, 2128896), i.e. a constant −66,966,830-duff
// creditPoolBalance bias at current testnet heights (E4 re-soak finding).
inline constexpr int DASH_V20_HEIGHT_TESTNET       = 905'100;
inline constexpr int DASH_MN_RR_HEIGHT_TESTNET     = 1'066'900;
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
///
/// `mn_rr_height` is the NETWORK'S MN_RR activation height (dashcore keys this
/// off Params().GetConsensus().MN_RRHeight, i.e. per-chainparams). Defaults to
/// MAINNET; callers on testnet MUST pass DASH_MN_RR_HEIGHT_TESTNET — the E4
/// re-soak proved that gating testnet heights on the mainnet constant returns
/// 0 here and biases every committed creditPoolBalance low by exactly one
/// block's platform reward (66,966,830 duffs at testnet h≈1.519M).
inline int64_t compute_dash_platform_reward_post_v20_mn_rr(
    uint32_t height, int mn_rr_height = DASH_MN_RR_HEIGHT_MAINNET)
{
    if (static_cast<int>(height) < mn_rr_height) return 0;
    int64_t mn_subsidy_share = compute_dash_block_reward_post_v20(height) * 3 / 4;
    return mn_subsidy_share * 375 / 1000;
}

/// True if `height` is a superblock height (treasury budget payout).
inline bool is_superblock_height(uint32_t height,
                                 int cycle = DASH_SUPERBLOCK_CYCLE_MAINNET)
{
    return cycle > 0 && (height % static_cast<uint32_t>(cycle)) == 0;
}

/// The per-superblock budget cap (duffs) — dashcore CSuperblock::
/// GetPaymentsLimit(nBlockHeight) == getsuperblockbudget RPC. It is the
/// accumulated nSuperblockPart over one cycle:
///   budget(H) = nSuperblockPart(H) * nSuperblockCycle
/// where nSuperblockPart(H) = GetBlockSubsidy(H)/5 (V20: the 20% treasury
/// slice compute_dash_block_reward_post_v20 already withholds). This mirrors
/// dashcore validation.cpp CalcSuperblockBudget within a cycle's subsidy
/// (subsidy is flat between halvings, so the per-block part is constant across
/// the cycle). Cross-checked against dashd getsuperblockbudget in the KAT.
inline int64_t superblock_budget(uint32_t height, int cycle)
{
    // Recompute nSubsidy EXACTLY as subsidy.hpp/dashcore does (the halving loop),
    // so nSuperblockPart = nSubsidy/5 is duff-exact rather than inverted from the
    // truncated block reward. part is constant across a cycle (subsidy is flat
    // between halvings), so budget = part * nSuperblockCycle — dashcore
    // CalcSuperblockBudget. Pinned against dashd getsuperblockbudget in the KAT.
    int prev_height = static_cast<int>(height) - 1;
    int64_t nSubsidy = 5 * COIN_SAT;
    for (int i = DASH_SUBSIDY_HALVING_INTERVAL;
         i <= prev_height;
         i += DASH_SUBSIDY_HALVING_INTERVAL) {
        nSubsidy -= nSubsidy / 14;
    }
    const int64_t part = nSubsidy / 5; // nSuperblockPart (V20 20% treasury slice)
    return part * static_cast<int64_t>(cycle > 0 ? cycle : 1);
}

} // namespace coin
} // namespace dash
