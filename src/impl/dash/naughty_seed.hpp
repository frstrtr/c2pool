// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ============================================================================
// naughty_seed.hpp — the excessive-block-reward test (a share whose block
// would pay more than dashd allows) and the naughty machinery it can drive.
//
// STATUS on the DASH v36 network (operator, 2026-09-28): p2pool v35 parity.
// The test is REPORTED ONLY: a log line and a counter
// (ShareTracker::excessive_reward_warnings()); it never seeds naughty and never
// changes head selection. In the v35+ p2pool lineage the pre-v34 seed from
// share.check() is gated `if self.VERSION < 34` and is dead code, so no
// v35/v36 p2pool share is ever seeded naughty, and neither is any c2pool
// share. Why the seed buys nothing a network needs:
//   * a share's subsidy pays only that share's own generation transaction;
//     PPLNS weights come from work, not from earlier shares' subsidies, so an
//     over-paying share inflates nobody else's payout;
//   * an over-paying share that does not solve a block harms no one; one that
//     does is rejected by dashd ("bad-cb-amount"), and the seed cannot bring
//     that block back;
//   * doing it on purpose is block withholding, which a miner can do anyway,
//     undetectably, by not submitting its block solutions;
//   * the seed drives head selection, so any disagreement about it between
//     nodes or builds (fees, heights, rule versions) splits the sharechain.
// What the warning keeps: a build that pays itself too much shows up on every
// node at once.
//
// The naughty machinery (naughty_seed_active(), the generation clamp, the
// think() Phase 4/5 walk-back) is kept, gated off on both networks by
// ShareProfile::naughty_seed = false, as it is in p2pool:
//   * naughty starts at 0 (data.py Share.__init__);
//   * a seeded share would get naughty = 1, a child of a naughty parent
//     1 + parent.naughty, reset to 0 past 6 generations;
//   * best-head selection deducts one share of work from a naughty head,
//     sorts on -naughty and walks back past naughty shares
//     (share_tracker.hpp think() Phase 4/5).
//
// Where the warning applies:
//   * the public v16 network: never (p2pool-dash has no such test; its
//     should_punish_reason is block solution and oversized blocks only).
//   * the DASH v36 network: on, by the rule below.
//
// The dashd rule. A block is valid only if its coinbase pays no more than the
// block reward plus the fees of its transactions, plus the superblock budget
// at a triggered superblock (dashcore v23.1.7):
//   * validation.cpp:2634-2647 ConnectBlock: blockSubsidy = GetBlockSubsidy,
//     feeReward = nFees, IsBlockValueValid(block, height,
//     blockSubsidy + feeReward, ...) else "bad-cb-amount";
//   * masternode/payments.cpp:193-195 IsBlockValueValid:
//     vtx[0]->GetValueOut() <= blockReward; :213-214 superblock max =
//     blockReward + CSuperblock::GetPaymentsLimit; :218-224 a height that
//     cannot be a superblock is held to blockReward; :258-265 a superblock
//     height with no triggered superblock is held to blockReward;
//   * governance/classes.cpp:284-294 CSuperblock::IsValid: payments <= the
//     limit, and GetValueOut() <= blockReward + payments;
//   * the miner's coinbase value is getblocktemplate "coinbasevalue" =
//     vtx[0]->GetValueOut() (rpc/mining.cpp:923), i.e. subsidy + fees as
//     dashd computed them. The share's m_subsidy is that value.
//
// What a peer can evaluate. A v36 share carries no transactions and no
// transaction refs; it commits (PoW-bound: ref_hash -> gentx -> merkle_link
// -> header merkle root) to share_data, share_info, the coinbase merkle_link
// branch, message_data and the DASH coinbase suffix, and to no fee figure. So
// a peer cannot recompute the fees of another node's share, and no committed
// field bounds them: the branch length bounds the transaction COUNT, not the
// fees (one transaction may pay any fee up to MAX_MONEY, consensus/amount.h:26),
// and a fee claimed by the minter (in the masternode payment amount or in
// message_data) is the minter's own statement, so it proves nothing. A
// node-local figure (the verifying node's own template or mempool) is NOT
// used: naughty drives best-head selection (share_tracker.hpp think() Phase
// 4/5), so two honest nodes with different mempools would mark different
// shares naughty and elect different heads.
//
// The test, from committed share content only (its subsidy, its merkle_link
// branch length L, the height of its committed parent block) and the network
// profile, so every node marks every share the same way:
//
//   max(h, L) = reward(h) + [superblock budget, at a superblock height h]
//               + fee_allowance(h, L)
//   fee_allowance(h, 0)   = 0        L = 0: the header commits to the coinbase
//                                    alone, so the block has no transactions
//                                    and its fees are exactly 0;
//   fee_allowance(h, L>0) = reward(h) * naughty_fee_allowance_x_reward
//                                    (ShareProfile; 1 on the DASH v36 network):
//                                    the most fees the rule treats as plausible;
//   excessive  iff  subsidy > max(h, L)            (strictly greater)
//
// It fails open: a share is reported only when no plausible fee total explains
// its coinbase. What the test can and cannot do on a network whose blocks carry
// transactions: it catches accidental over-payment (a build that pays itself
// more than reward + one reward of fees, or any over-payment on a coinbase-only
// block). It cannot stop a hostile node: that node can mine invalid-block
// shares in ways no peer can see (an invalid transaction in its own template),
// so a generous allowance loses nothing real. An honest block whose fees exceed
// one block reward is reported on every node alike (deterministic), and
// nothing else happens to it. Were the seed ever switched on, the allowance
// would become a network-wide head-selection parameter that every node must
// run with the same value.
//
// At a superblock height the full budget is allowed whether or not a
// superblock was triggered (dashd holds a non-triggered one to the reward):
// the rule cannot see governance, so it takes the bound the schedule can never
// exceed.
//
// A share that fails check() is not reported here: it is not verified at all (and
// the peer that sent it is dealt with by the receive path).
//
// Header-only, fenced to src/impl/dash/. KAT: test_dash_naughty_seed.cpp,
// test_dash_v36_flip.cpp (node level).
// ============================================================================

#include "config_pool.hpp"
#include "coin/block_reward.hpp"  // block reward, V20 heights, superblock cycle + budget (pure)

#include <cstddef>
#include <cstdint>
#include <optional>

namespace dash {

/// The one place the per-network profile is read for this rule.
inline bool naughty_seed_active()
{
    return SharechainConfig::share_profile().naughty_seed;
}

/// The report-only form of the same test (DASH v36 network): a log line and a
/// counter, never naughty.
inline bool excessive_reward_warning_active()
{
    return SharechainConfig::share_profile().excessive_reward_warning;
}

/// True when a share's coinbase merkle_link branch is empty: the block header
/// commits to the coinbase alone, so the block has no other transaction and
/// pays no fees.
inline bool commits_only_the_coinbase(size_t committed_merkle_branch_len)
{
    return committed_merkle_branch_len == 0;
}

/// The fees the rule accepts for a block at `height` whose coinbase merkle_link
/// branch has `committed_merkle_branch_len` entries: 0 for a coinbase-only
/// block (its fees are exactly 0), otherwise the block reward at `height` times
/// the profile's naughty_fee_allowance_x_reward (the same for any number of
/// transactions: the count does not bound the fees).
inline uint64_t fee_allowance(uint32_t height, size_t committed_merkle_branch_len)
{
    if (commits_only_the_coinbase(committed_merkle_branch_len))
        return 0;
    return static_cast<uint64_t>(coin::compute_dash_block_reward_post_v20(height))
         * SharechainConfig::share_profile().naughty_fee_allowance_x_reward;
}

/// The most a block at `height` may pay under the rule: the block reward (the
/// miner + masternode part, dashcore GetBlockSubsidy less the treasury slice),
/// plus, at a superblock height, the superblock budget, plus
/// fee_allowance(height, committed_merkle_branch_len). The default branch
/// length 0 is the coinbase-only bound. nullopt below the network's V20 height,
/// where the reward formula depends on the block bits: the rule is inert there
/// (the DASH v36 network never runs below V20).
inline std::optional<uint64_t> max_coinbase_value(uint32_t height, bool is_testnet,
                                                  size_t committed_merkle_branch_len = 0)
{
    const int v20 = is_testnet ? coin::DASH_V20_HEIGHT_TESTNET : coin::DASH_V20_HEIGHT_MAINNET;
    if (static_cast<int64_t>(height) < v20)
        return std::nullopt;
    const int cycle = is_testnet ? coin::DASH_SUPERBLOCK_CYCLE_TESTNET
                                 : coin::DASH_SUPERBLOCK_CYCLE_MAINNET;
    uint64_t max = static_cast<uint64_t>(coin::compute_dash_block_reward_post_v20(height));
    if (coin::is_superblock_height(height, cycle))
        max += static_cast<uint64_t>(coin::superblock_budget(height, cycle));
    max += fee_allowance(height, committed_merkle_branch_len);
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
