// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/consensus/xmr_weight.hpp
//
// BLOCK WEIGHT: the weight of a (possibly pruned) block, the long-term weight
// recursion, the two medians that bound it, and the effective median the reward
// penalty and the template's weight limit are computed from.
//
// This is the second of the design's "hardest unknowns" and the one with the
// least margin: the effective median sets the penalty knee, so a one-byte drift
// in a weight or a one-off in a window changes what a miner is paid.
//
// The rules are monerod's, transcribed from src/cryptonote_core/blockchain.cpp
// (release-v0.18) with the constants from src/cryptonote_config.h. Three of
// them are NOT what a reader of older Monero documentation would write, because
// HF_VERSION_2021_SCALING (v15) changed them:
//
//   * the long-term weight is bounded BELOW as well as above from v15:
//         block_weight <- max(block_weight, ltemw * 10 / 17)
//     so a chain of empty blocks does not drag the long-term median to zero.
//     This is why a stagenet block of weight 87 reports long_term_weight
//     176470 == 300000 * 10 / 17, which is the number this file is pinned on;
//   * the upper constraint is 1.7x from v15 (ltemw + ltemw * 7 / 10) and 1.4x
//     before it (ltemw + ltemw * 2 / 5);
//   * the effective median is clamped BELOW by the long-term effective median
//     from v15, and by the 300 000 penalty-free zone before it.
//
// PRUNED IS ENOUGH. A block's weight is the coinbase blob size plus the
// consensus weight of every transaction in it, and consensus/xmr_tx_weight.hpp
// computes a transaction's weight from its PRUNED bytes (prefix + rct base) by
// predicting the prunable length from structure. So the node can weigh a block
// it only ever received pruned, which is what D-4 (always sync prune=true)
// depends on.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "xmr_median.hpp"
#include "xmr_tx_weight.hpp"

namespace c2pool::xmr::native {

// --- cryptonote_config.h ------------------------------------------------------
inline constexpr std::uint64_t CRYPTONOTE_REWARD_BLOCKS_WINDOW              = 100;
inline constexpr std::uint64_t CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1 = 20000;
inline constexpr std::uint64_t CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2 = 60000;
inline constexpr std::uint64_t CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 = 300000;
inline constexpr std::uint64_t CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE = 100000;
inline constexpr std::uint64_t CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR = 50;

inline constexpr std::uint8_t HF_VERSION_LONG_TERM_BLOCK_WEIGHT = 10;
inline constexpr std::uint8_t HF_VERSION_2021_SCALING           = 15;

// cryptonote_basic_impl.cpp get_min_block_weight -- the penalty-free zone.
inline constexpr std::uint64_t min_block_weight(std::uint8_t version) noexcept {
    if (version < 2) return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1;
    if (version < 5) return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2;
    return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
}

// --- the weight of one block --------------------------------------------------
// monerod's cumulative_block_weight: the coinbase blob size plus every
// transaction's consensus weight. The coinbase carries no rct proof, so its
// weight IS its blob size.
enum class BlockWeightStatus : std::uint8_t {
    Ok = 0,
    TxCountMismatch,   // bodies supplied != tx_hashes in the block
    Overflow,          // the sum does not fit -- a malformed peer block
};

inline const char* to_string(BlockWeightStatus s) noexcept {
    switch (s) {
        case BlockWeightStatus::Ok:              return "Ok";
        case BlockWeightStatus::TxCountMismatch: return "TxCountMismatch";
        case BlockWeightStatus::Overflow:        return "Overflow";
    }
    return "?";
}

// `miner_tx_blob_size` is the coinbase's size in the block blob;
// `tx_weights` are the per-transaction consensus weights, one per tx_hash.
inline BlockWeightStatus block_weight_from_parts(std::uint64_t miner_tx_blob_size,
                                                 const std::vector<std::uint64_t>& tx_weights,
                                                 std::size_t expected_tx_count,
                                                 std::uint64_t& out) {
    out = 0;
    if (tx_weights.size() != expected_tx_count) return BlockWeightStatus::TxCountMismatch;
    std::uint64_t sum = miner_tx_blob_size;
    for (std::uint64_t w : tx_weights) {
        if (sum > UINT64_MAX - w) return BlockWeightStatus::Overflow;
        sum += w;
    }
    out = sum;
    return BlockWeightStatus::Ok;
}

// The same sum straight from the parsed transactions, which is how the index
// calls it: `txs` are the block's non-coinbase bodies in wire order, each
// weighed by consensus/xmr_tx_weight.hpp from its pruned or full bytes.
inline BlockWeightStatus block_weight_from_txs(std::uint64_t miner_tx_blob_size,
                                               const std::vector<TxWeightInfo>& txs,
                                               std::size_t expected_tx_count,
                                               std::uint64_t& out) {
    std::vector<std::uint64_t> weights;
    weights.reserve(txs.size());
    for (const TxWeightInfo& t : txs) weights.push_back(t.weight);
    return block_weight_from_parts(miner_tx_blob_size, weights, expected_tx_count, out);
}

// --- the long-term weight recursion -------------------------------------------
// blockchain.cpp get_next_long_term_block_weight, for a block of `block_weight`
// appended to a chain whose long-term effective median is `ltemw`.
inline std::uint64_t long_term_weight_for(std::uint64_t block_weight,
                                          std::uint64_t ltemw,
                                          std::uint8_t  hf_version) noexcept {
    if (hf_version < HF_VERSION_LONG_TERM_BLOCK_WEIGHT) return block_weight;

    std::uint64_t short_term_constraint;
    if (hf_version >= HF_VERSION_2021_SCALING) {
        // Bounded to [ltemw / 1.7, ltemw * 1.7].
        const std::uint64_t floor_2021 = ltemw * 10 / 17;
        if (block_weight < floor_2021) block_weight = floor_2021;
        short_term_constraint = ltemw + ltemw * 7 / 10;
    } else {
        // Bounded to [0, ltemw * 1.4].
        short_term_constraint = ltemw + ltemw * 2 / 5;
    }
    return block_weight < short_term_constraint ? block_weight : short_term_constraint;
}

// The long-term effective median: the 100 000-block median, floored by the
// penalty-free zone.
inline std::uint64_t long_term_effective_median(std::uint64_t long_term_median) noexcept {
    return long_term_median > CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5
         ? long_term_median : CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
}

// blockchain.cpp update_next_cumulative_weight_limit: the median the reward
// penalty and the template weight limit are computed from.
inline std::uint64_t effective_median_weight(std::uint64_t short_term_median,
                                             std::uint64_t ltemw,
                                             std::uint8_t  hf_version) noexcept {
    std::uint64_t effective;
    if (hf_version < HF_VERSION_LONG_TERM_BLOCK_WEIGHT) {
        effective = short_term_median;
    } else {
        const std::uint64_t lower =
            (hf_version >= HF_VERSION_2021_SCALING)
                ? ltemw                                         // v15+: the long-term median
                : CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5; // before: the flat zone
        std::uint64_t v = short_term_median > lower ? short_term_median : lower;
        const std::uint64_t upper = CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR * ltemw;
        effective = v < upper ? v : upper;
    }
    const std::uint64_t zone = min_block_weight(hf_version);
    return effective <= zone ? zone : effective;
}

// --- the rolling state --------------------------------------------------------
// What a chain must carry to answer the two medians. Both windows are rolled
// forward on connect and backwards on a reorg; the undo record is what makes
// the backwards direction exact rather than approximate.
struct WeightUndo {
    bool          short_evicted = false;
    std::uint64_t short_value   = 0;
    bool          long_evicted  = false;
    std::uint64_t long_value    = 0;
};

class WeightState {
public:
    WeightState()
        : short_(static_cast<std::size_t>(CRYPTONOTE_REWARD_BLOCKS_WINDOW)),
          long_(static_cast<std::size_t>(CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE)) {}

    // Preload from an anchor bundle (oldest first). The two windows are
    // independent lengths; a bundle carries exactly 100 and 100 000.
    void seed(const std::vector<std::uint64_t>& short_term,
              const std::vector<std::uint64_t>& long_term) {
        short_.clear();
        long_.clear();
        for (std::uint64_t w : short_term) short_.push(w);
        for (std::uint64_t w : long_term)  long_.push(w);
    }

    std::size_t short_size() const noexcept { return short_.size(); }
    std::size_t long_size()  const noexcept { return long_.size(); }

    std::uint64_t short_term_median() const { return short_.median(); }
    std::uint64_t long_term_median()  const { return long_.median(); }
    std::uint64_t long_term_effective_median() const {
        return c2pool::xmr::native::long_term_effective_median(long_.median());
    }

    // The weight the NEXT block would be recorded with, given its raw weight.
    // Must be evaluated BEFORE that block is pushed: monerod computes it from
    // the window that ends at the parent.
    std::uint64_t next_long_term_weight(std::uint64_t block_weight,
                                        std::uint8_t hf_version) const {
        return long_term_weight_for(block_weight, long_term_effective_median(), hf_version);
    }

    // The effective median for a block mined ON TOP of the current tip.
    std::uint64_t effective_median(std::uint8_t hf_version) const {
        return effective_median_weight(short_term_median(), long_term_effective_median(),
                                       hf_version);
    }

    // monerod's m_current_block_cumul_weight_limit.
    std::uint64_t block_weight_limit(std::uint8_t hf_version) const {
        return effective_median(hf_version) * 2;
    }

    WeightUndo push(std::uint64_t block_weight, std::uint64_t long_term_weight) {
        WeightUndo u;
        u.short_evicted = short_.push(block_weight, u.short_value);
        u.long_evicted  = long_.push(long_term_weight, u.long_value);
        return u;
    }

    bool pop(const WeightUndo& u) {
        const bool a = long_.pop_back(u.long_evicted, u.long_value);
        const bool b = short_.pop_back(u.short_evicted, u.short_value);
        return a && b;
    }

    const MedianWindow& short_window() const noexcept { return short_; }
    const MedianWindow& long_window()  const noexcept { return long_; }

private:
    MedianWindow short_;
    MedianWindow long_;
};

} // namespace c2pool::xmr::native
