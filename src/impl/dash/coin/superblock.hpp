// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Daemonless superblock sourcing — the payee-vector producer (E-SUPERBLOCK).
///
/// Port of dashcore governance/governance-classes.cpp:
///   CSuperblockManager::GetSuperblockPayments(nBlockHeight, ...) — resolve the
///     winning trigger and hand back its ordered (payee, amount) vector.
///   CSuperblockManager::IsValid / CSuperblock::IsValid budget checks — the
///     total scheduled payout must not exceed the block's superblock budget.
///
/// This sits on top of GovernanceStore (winning-trigger selection + funding
/// tally) and returns EXACTLY what the embedded coinbase must pay at a
/// superblock height, or nullopt to signal "no confident superblock schedule"
/// (unfunded OR under-synced) — in which case the caller decides:
///   - unfunded superblock  → serve a NORMAL template (no extra outputs);
///   - under-synced view     → FAIL CLOSED to the dashd fallback.
/// The two are distinguished by the govsync-completeness gate the caller holds,
/// NOT here (this function only knows the store's current view).

#include <impl/dash/coin/governance_store.hpp>
#include <impl/dash/coin/subsidy.hpp>

#include <cstdint>
#include <optional>
#include <vector>

namespace dash {
namespace coin {

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

/// dashcore CSuperblockManager::GetSuperblockPayments equivalent.
/// Returns the ordered (script, amount) vector the coinbase must pay at
/// `height`, or nullopt when no trigger is triggered for this height in the
/// current store view. When a schedule IS returned it is guaranteed:
///   - non-empty, every amount > 0;
///   - total <= budget_cap (IsValidSuperblock budget gate) — a trigger whose
///     scheduled total exceeds the budget is REJECTED (fail closed), matching
///     dashcore's refusal to over-pay the treasury.
inline std::optional<std::vector<SuperblockPayment>> get_superblock_payments(
    const GovernanceStore& store, int32_t height, int64_t budget_cap)
{
    auto best = store.get_best_superblock(height);
    if (!best) return std::nullopt;                 // unfunded / not trigger-confident
    if (best->payments.empty()) return std::nullopt;
    int64_t total = 0;
    for (const auto& p : best->payments) {
        if (p.amount <= 0 || p.script.empty()) return std::nullopt;
        total += p.amount;
    }
    if (budget_cap > 0 && total > budget_cap) return std::nullopt; // over-budget → reject
    return best->payments;
}

} // namespace coin
} // namespace dash
