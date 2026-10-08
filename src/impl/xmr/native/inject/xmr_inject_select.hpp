// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/inject/xmr_inject_select.hpp
//
// INJECT-FIRST template selection: "operator injects first, fill to the cap
// with the good-citizen (variant-B take-all) tail, NEVER overfill".
//
// This is the C4-side realisation of the operator ruling (2026-09-19):
//   * operator-injected txs are ALWAYS included at HIGHEST priority (mined even
//     at zero fee), subject ONLY to the block-size (weight) cap, on which they
//     get FIRST claim;
//   * then variant-B TAKE-ALL of the rest of the mempool up to the SAME cap
//     (no fee floor -- select_good_citizen already takes everything under the
//     median with no fee test), never exceeding the cap;
//   * good-citizen non-empty invariant preserved (empty IFF nothing to take).
//
// It is a PURE function over the pool's fee-ordered selectable backlog and the
// inject order the OperatorInjectPool produced, exactly like select_good_citizen
// (no chain state beyond the miner-data snapshot the caller already holds), so
// it is trivially testable against synthetic backlogs.
//
// PHASE A (injects). The same median clamp / consensus_ceiling / weight_cap
// arithmetic as select_good_citizen. Take injects in the given order with NO
// fee test while the coinbase-inclusive weight stays <= weight_cap. The FIRST
// inject is taken unconditionally (a single tx <= 149400 always fits under any
// real median's cap), so a non-empty inject set never yields an empty block. An
// inject that does not fit is skipped and COUNTED (inject_dropped_by_cap),
// never displacing an earlier one -- a prefix, never a reorder.
//
// PHASE B (citizen tail). select_good_citizen semantics over fee_ordered MINUS
// the inject ids already chosen, CONTINUING from Phase A's accumulated weight.
// "First candidate always taken" (R-CIT-1) applies only when Phase A chose
// nothing, so a non-empty pool still never yields an empty block.
//
// INVARIANT (golden KAT): with ZERO injects, select_inject_first is byte-equal
// to select_good_citizen -- Phase A does nothing and Phase B is the exact same
// loop. Composition with the AGPL assembler's coinbase-aware trim
// (XmrBlockAssembler::trim_to_budget) can only cut from the TAIL, and injects
// are the prefix, so an inject is dropped by the trim ONLY if the injects ALONE
// exceed the assembler budget -- bounded and consensus-safe.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#include "impl/xmr/native/consensus/xmr_reward.hpp"       // get_block_reward, min_block_weight
#include "impl/xmr/native/template/xmr_citizen_select.hpp" // CitizenPolicy, CitizenSelection
#include "impl/xmr/node/xmr_node_types.hpp"                // node::TxBacklogEntry

namespace c2pool::xmr::native {

struct InjectSelection {
    std::vector<node::TxBacklogEntry> chosen;      // inclusion order: injects, then citizen tail
    std::size_t   inject_n              = 0;        // injects placed at the front
    std::size_t   inject_dropped_by_cap = 0;        // injects that did not fit the weight cap
    std::uint64_t total_weight          = 0;        // selected tx weight (no coinbase)
    std::uint64_t total_fee             = 0;
};

// Select injects first (highest priority, no fee test), then the good-citizen
// take-all tail, bounded by the same weight cap select_good_citizen computes.
//
//   injects      -- OperatorInjectPool::ordered(fee_ordered): the injects still
//                   in the selectable set, in (priority, submit) order. Their
//                   weight/fee are the real C3 values.
//   fee_ordered  -- the pool's selection snapshot, fee-rate desc / oldest / id.
//   median_weight, already_generated_coins, version -- as select_good_citizen.
//
// GOOD-CITIZEN INVARIANT: result.chosen is empty IFF (injects and fee_ordered
// are both empty).
inline InjectSelection select_inject_first(
        const std::vector<node::TxBacklogEntry>& injects,
        const std::vector<node::TxBacklogEntry>& fee_ordered,
        std::uint64_t median_weight,
        std::uint64_t already_generated_coins,
        std::uint8_t  version,
        const CitizenPolicy& policy = {}) {
    InjectSelection out;

    // ----- shared cap arithmetic, IDENTICAL to select_good_citizen -----------
    const std::uint64_t zone   = min_block_weight(version);
    const std::uint64_t median = median_weight < zone ? zone : median_weight;
    const std::uint64_t consensus_ceiling =
        (2 * median > policy.coinbase_reserved) ? (2 * median - policy.coinbase_reserved) : median;
    std::uint64_t growth_ceiling =
        static_cast<std::uint64_t>(policy.growth_cap * static_cast<double>(median));
    if (growth_ceiling < median) growth_ceiling = median;
    std::uint64_t weight_cap = growth_ceiling < consensus_ceiling ? growth_ceiling : consensus_ceiling;
    if (weight_cap < median) weight_cap = median;

    const std::uint64_t coinbase_w = policy.coinbase_reserved;
    std::uint64_t total = 0;   // selected tx weight so far (coinbase excluded)

    auto key = [](const node::Hash& h) {
        return std::string(reinterpret_cast<const char*>(h.data()), h.size());
    };

    // ----- PHASE A: injects first, no fee test, bounded by weight_cap --------
    std::unordered_set<std::string> chosen_injects;
    chosen_injects.reserve(injects.size() * 2 + 1);
    for (const node::TxBacklogEntry& inj : injects) {
        // Guard against an inject id appearing twice in the ordered view.
        if (chosen_injects.count(key(inj.id))) continue;
        const std::uint64_t next    = total + inj.weight;
        const std::uint64_t block_w = coinbase_w + next;
        // First inject is always taken (fits under any real median's cap);
        // thereafter take while under the weight cap. An inject that does not
        // fit is skipped and counted -- a prefix, never a reorder.
        if (out.chosen.empty() || block_w <= weight_cap) {
            out.chosen.push_back(inj);
            chosen_injects.insert(key(inj.id));
            total = next;
            out.total_fee += inj.fee;
            ++out.inject_n;
        } else {
            ++out.inject_dropped_by_cap;
        }
    }

    // ----- PHASE B: good-citizen take-all tail over the remaining txs --------
    // Byte-identical to select_good_citizen's loop body, continuing from `total`
    // and out.total_fee, skipping ids already taken as injects. "First candidate
    // always taken" applies only when Phase A took nothing (out.chosen empty).
    for (const node::TxBacklogEntry& tx : fee_ordered) {
        if (chosen_injects.count(key(tx.id))) continue;   // already an inject
        const std::uint64_t next    = total + tx.weight;
        const std::uint64_t block_w = coinbase_w + next;

        if (out.chosen.empty()) {                          // R-CIT-1
            out.chosen.push_back(tx);
            total = next;
            out.total_fee += tx.fee;
            continue;
        }
        if (block_w > consensus_ceiling) continue;         // hard ceiling
        if (block_w <= median) {                           // R-CIT-2 penalty-free
            out.chosen.push_back(tx);
            total = next;
            out.total_fee += tx.fee;
            continue;
        }
        if (block_w > weight_cap) continue;                // R-CIT-3 soft cap

        std::uint64_t reward_before = 0, reward_after = 0;
        get_block_reward(median, coinbase_w + total, already_generated_coins, version, reward_before);
        get_block_reward(median, coinbase_w + next,  already_generated_coins, version, reward_after);
        const std::uint64_t coinbase_before = reward_before + out.total_fee;
        const std::uint64_t coinbase_after  = reward_after  + out.total_fee + tx.fee;
        if (static_cast<double>(coinbase_after)
            >= policy.accept_threshold * static_cast<double>(coinbase_before)) {
            out.chosen.push_back(tx);
            total = next;
            out.total_fee += tx.fee;
        }
    }

    out.total_weight = total;
    return out;
}

} // namespace c2pool::xmr::native
