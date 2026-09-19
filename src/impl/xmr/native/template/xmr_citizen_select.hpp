// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/template/xmr_citizen_select.hpp
//
// GOOD-CITIZEN transaction selection for the daemonless template builder.
//
// The hard rule (operator, emphatic): a c2pool block MUST always include and
// mine transactions when the pool has any valid one. An empty (coinbase-only)
// block earns no fees, drives miners away, and is a poor Monero-network
// citizen. Miner retention and network citizenship OUTWEIGH the marginal
// block-reward penalty of including a small-fee transaction.
//
// So fee-versus-penalty here is an ORDERING / soft-cap heuristic ONLY. It never
// empties or under-fills a block:
//
//   * R-CIT-1 (invariant): the returned set is empty IFF the input backlog is
//     empty. A single transaction (weight <= 149400) always fits under any real
//     median (min block weight 300000 => penalty-free zone alone admits it), so
//     the first candidate is unconditionally taken.
//   * R-CIT-2 (penalty-free zone): every candidate that fits below the median
//     is taken, no fee test -- exactly as monerod's fill_block_template and
//     p2pool do. On mainnet today (median floor 300 kB, typical blocks
//     20-100 kB) this is the whole block.
//   * R-CIT-3 (penalty zone = ordering only): above the median we keep scanning
//     in fee-rate order and include a candidate while the coinbase stays at or
//     above `accept_threshold` of its pre-inclusion value AND the block stays
//     under a soft growth cap AND under the hard consensus ceiling
//     (2*median - reserved). `accept_threshold` defaults to 0.98, strictly
//     below monerod's 1.0: we deliberately include a transaction whose fee does
//     not fully cover its marginal penalty. It can never empty the block
//     because R-CIT-2 already took the first candidates.
//
// This is a PURE function over the pool's already-ordered selectable backlog:
// it re-orders nothing and reads no chain state beyond the miner-data snapshot
// the caller already holds, so it is trivially testable against synthetic
// backlogs (see xmr_citizen_select_kat.cpp) and carries no license entanglement
// with the GPL assembler downstream.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <vector>

#include "impl/xmr/native/consensus/xmr_reward.hpp"   // get_block_reward, min_block_weight
#include "impl/xmr/node/xmr_node_types.hpp"           // node::TxBacklogEntry

namespace c2pool::xmr::native {

// Selection policy. Neither knob can produce an empty or under-filled block:
// R-CIT-2 dominates the common case and the first candidate is always taken.
struct CitizenPolicy {
    // Penalty-zone accept threshold, as a fraction of the pre-inclusion
    // coinbase. monerod uses 1.0 (include only if the coinbase does not drop);
    // 0.98 means "include even if the fee does not fully cover the marginal
    // penalty", biasing toward inclusion. Applies ONLY above the median.
    double accept_threshold = 0.98;

    // Soft cap on block growth past the median, as a multiple of the median.
    // 1.5 => reward stays >= ~75% of base. Clamped to never fall below one
    // median so the penalty-free zone is always reachable; hard-capped by the
    // consensus ceiling below regardless.
    double growth_cap = 1.5;

    // monerod CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE: weight reserved for the
    // coinbase when sizing the block against the median / ceiling.
    std::uint64_t coinbase_reserved = 600;
};

struct CitizenSelection {
    std::vector<node::TxBacklogEntry> chosen;      // in inclusion order
    std::uint64_t total_weight = 0;                // selected tx weight (no coinbase)
    std::uint64_t total_fee    = 0;
};

// Selects the transactions to place into the next block from a fee-rate-ordered
// selectable backlog.
//
//   fee_ordered            -- the pool's selection snapshot, already sorted
//                             fee-rate desc / oldest / id. NOT re-sorted here.
//   median_weight          -- long-term median (penalty knee); clamped up to
//                             the min-block-weight zone as monerod does.
//   already_generated_coins-- for the base-reward / penalty computation.
//   version                -- HF major version (drives get_block_reward math).
//
// GOOD-CITIZEN INVARIANT (R-CIT-1): result.chosen is empty IFF fee_ordered is
// empty.
inline CitizenSelection select_good_citizen(
        const std::vector<node::TxBacklogEntry>& fee_ordered,
        std::uint64_t median_weight,
        std::uint64_t already_generated_coins,
        std::uint8_t  version,
        const CitizenPolicy& policy = {}) {
    CitizenSelection out;
    if (fee_ordered.empty()) return out;   // R-CIT-1 (reverse)

    // Median clamp, as monerod's get_block_reward does internally.
    const std::uint64_t zone   = min_block_weight(version);
    const std::uint64_t median = median_weight < zone ? zone : median_weight;

    // Hard consensus ceiling: get_block_reward returns BlockTooBig above
    // 2*median. Reserve the coinbase. Never crossed.
    const std::uint64_t consensus_ceiling =
        (2 * median > policy.coinbase_reserved) ? (2 * median - policy.coinbase_reserved) : median;

    // Soft growth cap (policy), never below one median so R-CIT-2 always holds.
    std::uint64_t growth_ceiling =
        static_cast<std::uint64_t>(policy.growth_cap * static_cast<double>(median));
    if (growth_ceiling < median) growth_ceiling = median;

    std::uint64_t weight_cap = growth_ceiling < consensus_ceiling ? growth_ceiling : consensus_ceiling;
    if (weight_cap < median) weight_cap = median;

    const std::uint64_t coinbase_w = policy.coinbase_reserved;
    std::uint64_t total = 0;   // selected tx weight so far (coinbase excluded)

    for (const node::TxBacklogEntry& tx : fee_ordered) {
        const std::uint64_t next    = total + tx.weight;
        const std::uint64_t block_w = coinbase_w + next;   // coinbase-inclusive

        // R-CIT-1: the very first candidate is ALWAYS taken -- even if it alone
        // reaches the penalty zone. It always fits (one tx <= 149400 < the
        // consensus ceiling for any real median).
        if (out.chosen.empty()) {
            out.chosen.push_back(tx);
            total = next;
            out.total_fee += tx.fee;
            continue;
        }

        // Hard consensus ceiling: never cross it.
        if (block_w > consensus_ceiling) continue;

        // R-CIT-2: penalty-free zone -- take unconditionally, no fee test.
        if (block_w <= median) {
            out.chosen.push_back(tx);
            total = next;
            out.total_fee += tx.fee;
            continue;
        }

        // R-CIT-3: penalty zone -- soft growth cap, then ordering-only accept.
        if (block_w > weight_cap) continue;             // soft cap; keep scanning

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
        // else: skip this candidate, keep scanning (monerod 'continue', not 'break')
    }

    out.total_weight = total;
    return out;
}

} // namespace c2pool::xmr::native
