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
/// (unfunded OR under-synced). NOTE: get_superblock_payments NEVER returns an
/// empty vector — nullopt covers both cases, and the caller cannot tell them
/// apart from here alone, so a nullopt superblock height ALWAYS fails closed
/// to the dashd fallback. Serving a NORMAL template at a confidently-UNFUNDED
/// superblock height would additionally require the govsync-completeness gate
/// (NodeCoinState::set_superblock_sync_complete_fn) to prove the store's view
/// complete; that distinction is a gated follow-up, not implemented here.

#include <impl/dash/coin/governance_store.hpp>
#include <impl/dash/coin/subsidy.hpp>

#include <cstdint>
#include <optional>
#include <vector>

namespace dash {
namespace coin {

// superblock_budget(height, cycle): block_reward.hpp (via subsidy.hpp).

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
