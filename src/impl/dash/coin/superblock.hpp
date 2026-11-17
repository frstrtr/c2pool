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
/// tally) and resolves a superblock height to one of THREE verdicts
/// (resolve_superblock_payments):
///
///   Triggered    — the winning trigger's (script, amount) schedule. Dash Core
///                  v24 masternode/payments.cpp:448-454 FillBlockPayments adds
///                  superblock outputs only when IsSuperblockTriggered, and
///                  IsBlockValueValid/IsBlockPayeeValid (payments.cpp:313-388)
///                  then demand an exact match via CSuperblock::IsValid
///                  (superblock.cpp:248-337).
///   NotTriggered — PROVABLY no trigger is funded at H in the network's view
///                  => a NORMAL coinbase is the valid block (payments.cpp
///                  365-373: synced and not triggered => only value <=
///                  blockReward is checked). Asserted ONLY when the funding
///                  threshold is known, the govsync view is complete (R5), no
///                  non-admitted trigger object / orphan YES vote / unverified
///                  vote applies to H (C2/C3), and every stored trigger at H is
///                  positively voted down (C1 strict absence).
///   Unknown      — anything else: refuse (fail closed). A wrong "not
///                  triggered" omits the treasury outputs and a wrong
///                  "triggered" adds them; every synced validator rejects
///                  either block, so neither is ever guessed.
///
/// get_superblock_payments() is the optional-vector view of the same verdict:
/// payments / {} / nullopt.
#include <impl/dash/coin/governance_store.hpp>
#include <impl/dash/coin/subsidy.hpp>

#include <cstdint>
#include <optional>
#include <string>
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

/// The three superblock verdicts (see the header).
enum class SuperblockVerdict : uint8_t { Triggered, NotTriggered, Unknown };

inline const char* superblock_verdict_name(SuperblockVerdict v)
{
    switch (v) {
        case SuperblockVerdict::Triggered:    return "triggered";
        case SuperblockVerdict::NotTriggered: return "not-triggered";
        case SuperblockVerdict::Unknown:      return "unknown";
    }
    return "unknown";
}

struct SuperblockResolution {
    SuperblockVerdict              verdict{SuperblockVerdict::Unknown};
    std::vector<SuperblockPayment> payments;   // Triggered only (non-empty)
    /// Stable token naming WHY (the refusal value when Unknown):
    ///   govsync-incomplete, trigger-threshold-unknown, trigger-unparsed,
    ///   trigger-store-full, trigger-unverified-pending, trigger-orphan-votes,
    ///   trigger-outstanding-overflow, trigger-unverified-votes,
    ///   trigger-invalid-best, trigger-ambiguous, trigger-latched,
    ///   trigger-ctx-unwired; "triggered" / "not-triggered" otherwise.
    std::string                    reason{"unknown"};

    static SuperblockResolution unknown(std::string why) {
        SuperblockResolution r;
        r.verdict = SuperblockVerdict::Unknown;
        r.reason  = std::move(why);
        return r;
    }
};

/// dashcore SuperblockManager::IsSuperblockTriggered + GetSuperblockPayments
/// (Dash Core v24 governance/superblock.cpp:578-655), resolved against OUR
/// possibly-partial view and therefore tri-state. `sync_complete` is the R5
/// govsync-completeness predicate; it gates the NotTriggered verdict here
/// (the serve path additionally gates BOTH verdicts on it in NodeCoinState).
/// When a schedule IS returned (Triggered) it is guaranteed:
///   - non-empty, every amount > 0, every script non-empty;
///   - total <= budget_cap (CSuperblock::IsValid payments-limit gate,
///     superblock.cpp:280-286) — an over-budget winner is Unknown, never paid.
inline SuperblockResolution resolve_superblock_payments(
    const GovernanceStore& store, int32_t height, int64_t budget_cap,
    bool sync_complete)
{
    if (store.funding_threshold() <= 0)
        return SuperblockResolution::unknown("trigger-threshold-unknown");
    // C2/C3: an object we could not admit may be the network's winner — it
    // blocks the triggered verdict as much as the unfunded one.
    if (auto why = store.outstanding_blocker(height))
        return SuperblockResolution::unknown(*why);
    // A vote we could not verify on a trigger at H: its tally is unknown.
    if (store.unverified_votes_at(height))
        return SuperblockResolution::unknown("trigger-unverified-votes");

    if (auto best = store.get_best_superblock(height)) {
        if (best->payments.empty())
            return SuperblockResolution::unknown("trigger-invalid-best");
        int64_t total = 0;
        for (const auto& p : best->payments) {
            if (p.amount <= 0 || p.script.empty())
                return SuperblockResolution::unknown("trigger-invalid-best");
            total += p.amount;
        }
        if (budget_cap <= 0 || total > budget_cap)        // over budget => reject
            return SuperblockResolution::unknown("trigger-invalid-best");
        SuperblockResolution r;
        r.verdict  = SuperblockVerdict::Triggered;
        r.payments = best->payments;
        r.reason   = "triggered";
        return r;
    }

    // ── no funded trigger in our view: may we PROVE the network has none? ──
    if (auto why = store.ambiguous_at(height))          // C1 strict absence
        return SuperblockResolution::unknown(*why);
    if (!sync_complete)                                 // R5
        return SuperblockResolution::unknown("govsync-incomplete");
    SuperblockResolution r;
    r.verdict = SuperblockVerdict::NotTriggered;
    r.reason  = "not-triggered";
    return r;
}

/// Optional-vector view of resolve_superblock_payments: the winning schedule
/// (Triggered), an EMPTY vector (NotTriggered — a normal coinbase is the valid
/// block), or nullopt (Unknown — refuse). `sync_complete` defaults to false,
/// so a caller that does not pass the R5 predicate can never be handed the
/// unfunded verdict.
inline std::optional<std::vector<SuperblockPayment>> get_superblock_payments(
    const GovernanceStore& store, int32_t height, int64_t budget_cap,
    bool sync_complete = false)
{
    auto r = resolve_superblock_payments(store, height, budget_cap, sync_complete);
    switch (r.verdict) {
        case SuperblockVerdict::Triggered:    return std::move(r.payments);
        case SuperblockVerdict::NotTriggered: return std::vector<SuperblockPayment>{};
        case SuperblockVerdict::Unknown:      break;
    }
    return std::nullopt;
}

} // namespace coin
} // namespace dash
