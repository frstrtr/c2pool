// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_caps.hpp
// Path B derived caps and horizons. Every value is a formula over Monero
// symbols and lane parameters:
//
//   w_min        = weight of the smallest valid non-coinbase transaction      (1,459 at hf 16)
//   X(hf)        = 0, or kFcmpContentHashExtraLeaves from HF_VERSION_FCMP_PLUS_PLUS
//   D_max(hf, A) = floor(log2(X(hf) + 1 + floor(2 x SURGE(hf) x max(zone(hf), Z_lt(A)) / w_min)))
//   RECEIPT_CAP  = RECEIPT_MAX(D_max) = 497 + 32 D_max                       (945 at v16, 881 at v17)
//                  (a local buffer bound; a body is judged by the size rules below)
//   size rules   : tx_count - 1 <= floor(2 Z(P_r) / w_min); D == floor(log2(tx_count + X(hf)))
//   blob_cap(Z)  = HDR_max + OVH + floor((Z - OVH) / OUT) x OUT + 32 n + V(n), n = floor(2 Z / w_min)
//   J            = max(P_heal x 3600 / T, F x 120 / T + D_fin)                 (1,164)
//   index_horizon   = F + Fresh + 1                                            (99)
//   backfill        = max(F x 120 / T + D_fin, J)                              (1,164)
//   ctx_window      = ceil(J x T / 120) + Fresh + 1                            (100)
//   ctx_max_depth   = Fresh + 1                                                (3)
//   index_retention = max(SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG,
//                         ceil(J x T / 120) + Fresh + 1 + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW
//                         + DIFFICULTY_WINDOW)                                 (2,112)
//   pending_cap     = F x 120 / T x R_MAX                                      (18,432)
// (values at T 10, F 96, Fresh 2, R_MAX 16, P_heal 3 h). 120 is DIFFICULTY_TARGET_V2.
// Divisions over lane parameters round up.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <optional>

#include "pathb_params.hpp"
#include "pathb_wire_v3.hpp"

namespace c2pool::xmr::pathb {

// ---------------------------------------------------------------------------
// w_min: the smallest valid non-coinbase transaction (one input with a ring of
// hf_ring_size members, two outputs, BP+ range proof, CLSAG, empty extra,
// every varint one byte). Its weight equals its size (no clawback at two
// outputs).
// ---------------------------------------------------------------------------
namespace min_tx {
inline constexpr std::uint64_t kVarint1 = varint_len(0);
inline constexpr std::uint64_t kRing = ::c2pool::xmr::native::hf_ring_size(::c2pool::xmr::native::MAX_IMPLEMENTED_HF_VERSION);
inline constexpr std::uint64_t kInputs = 1;
// HF_VERSION_MIN_2_OUTPUTS: at least two outputs.
inline constexpr std::uint64_t kOutputs = 2;
// rct ecdhTuple amount (v2), bytes.
inline constexpr std::uint64_t kEcdhAmountBytes = kU64Bytes;
// BulletproofPlus fixed elements: A, A1, B, r1, s1, d1.
inline constexpr std::uint64_t kBpPlusFixedElements = 6;
// bulletproofs_plus.cc maxN: bits per amount.
inline constexpr std::uint64_t kBpPlusBitsPerAmount = 64;
// BulletproofPlus round vectors: L, R.
inline constexpr std::uint64_t kBpPlusRoundVectors = 2;
// CLSAG fixed elements: c1, D.
inline constexpr std::uint64_t kClsagFixedElements = 2;

// L and R rounds: log2(maxN x outputs).
inline constexpr std::uint64_t kBpPlusRounds = floor_log2(kBpPlusBitsPerAmount * kOutputs);

// version | unlock_time | vin count | txin_to_key (tag, amount, offset count,
// ring offsets, key image) | vout count | outputs (amount, tag, key, view tag) | extra length
inline constexpr std::uint64_t kPrefixBytes =
        kVarint1 + kVarint1 + kVarint1
        + kInputs * (kU8Bytes + kVarint1 + varint_len(kRing) + kRing * kVarint1 + kHashBytes)
        + kVarint1
        + kOutputs * (kVarint1 + kU8Bytes + kHashBytes + kU8Bytes)
        + kVarint1;
// type | fee | ecdh amounts | output commitments
inline constexpr std::uint64_t kRctBaseBytes = kU8Bytes + kVarint1 + kOutputs * kEcdhAmountBytes + kOutputs * kHashBytes;
// BP+ (count, fixed elements, L, R) | CLSAG per input (s[ring], c1, D) | pseudo outputs
inline constexpr std::uint64_t kPrunableBytes =
        kVarint1 + kBpPlusFixedElements * kHashBytes + kBpPlusRoundVectors * (varint_len(kBpPlusRounds) + kBpPlusRounds * kHashBytes)
        + kInputs * (kRing * kHashBytes + kClsagFixedElements * kHashBytes)
        + kInputs * kHashBytes;
}  // namespace min_tx

inline constexpr std::uint64_t kMinTxWeight = min_tx::kPrefixBytes + min_tx::kRctBaseBytes + min_tx::kPrunableBytes;

// ---------------------------------------------------------------------------
// Monero block-weight symbols by hf
// ---------------------------------------------------------------------------
// Penalty-free zone: get_min_block_weight (FCMP++ branch: ZONE_V17 from hf 17).
inline constexpr std::uint64_t zone(std::uint8_t hf) noexcept {
    return hf >= HF_VERSION_FCMP_PLUS_PLUS ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V17
                                           : ::c2pool::xmr::native::min_block_weight(hf);
}

// Short-term surge factor of the effective median (hf >= 10).
inline constexpr std::uint64_t surge_factor(std::uint8_t hf) noexcept {
    return hf >= HF_VERSION_FCMP_PLUS_PLUS ? CRYPTONOTE_SHORT_TERM_BLOCK_SURGE_FACTOR_V17
                                           : CRYPTONOTE_SHORT_TERM_BLOCK_SURGE_FACTOR_V10;
}

// Extra Merkle leaves after the miner tx.
inline constexpr std::uint64_t tree_extra_leaves(std::uint8_t hf) noexcept {
    return hf >= HF_VERSION_FCMP_PLUS_PLUS ? kFcmpContentHashExtraLeaves : 0;
}

// Merkle leaves of the miner tx.
inline constexpr std::uint64_t kMinerTxLeaves = 1;

// Block weight limit as a multiple of the effective median (blockchain.cpp:
// cumulative weight limit = median x 2).
inline constexpr std::uint64_t kBlockWeightLimitPerMedian = 2;

// ---------------------------------------------------------------------------
// Receipt cap
// ---------------------------------------------------------------------------
// D_max(hf, A); nullopt when 2 x SURGE x max(zone, Z_lt) exceeds u64.
inline constexpr std::optional<std::uint64_t> d_max(std::uint8_t hf, std::uint64_t z_lt) noexcept {
    const std::uint64_t z = std::max(zone(hf), z_lt);
    const std::uint64_t mult = kBlockWeightLimitPerMedian * surge_factor(hf);
    if (z > UINT64_MAX / mult) return std::nullopt;
    const std::uint64_t n_tx = (mult * z) / kMinTxWeight;
    return floor_log2(tree_extra_leaves(hf) + kMinerTxLeaves + n_tx);
}

// RECEIPT_CAP(hf, A) = RECEIPT_MAX(D_max(hf, A)).
inline constexpr std::optional<std::uint64_t> receipt_cap(std::uint8_t hf, std::uint64_t z_lt) noexcept {
    const std::optional<std::uint64_t> d = d_max(hf, z_lt);
    if (!d) return std::nullopt;
    return receipt_max(*d);
}

// Largest non-coinbase transaction count a block of median Z can carry.
inline constexpr std::uint64_t max_tx_count(std::uint64_t z) noexcept {
    return (kBlockWeightLimitPerMedian * z) / kMinTxWeight;
}

// ---------------------------------------------------------------------------
// Size rules of a receipt body judged on its own bytes and its Monero branch:
//   tx_count >= 1 (the hashing-blob count includes the miner tx)
//   tx_count - 1 <= floor(2 Z(P_r) / w_min)
//   D == floor(log2(tx_count + X(hf)))
// ---------------------------------------------------------------------------
inline constexpr std::uint64_t kMinerTxCount = 1;

// The Merkle depth of leaf 0 for a block whose hashing blob counts tx_count transactions.
inline constexpr std::uint64_t receipt_depth_for(std::uint8_t hf, std::uint64_t tx_count) noexcept {
    return floor_log2(tx_count + tree_extra_leaves(hf));
}

enum class SizeRule : std::uint8_t { Ok, TxCount, Depth };

inline constexpr SizeRule receipt_size_rules(std::uint8_t hf, std::uint64_t z_parent, std::uint64_t tx_count,
                                             std::uint64_t depth) noexcept {
    if (tx_count < kMinerTxCount) return SizeRule::TxCount;
    if (z_parent > UINT64_MAX / kBlockWeightLimitPerMedian) return SizeRule::TxCount;
    if (tx_count - kMinerTxCount > max_tx_count(z_parent)) return SizeRule::TxCount;
    if (depth != receipt_depth_for(hf, tx_count)) return SizeRule::Depth;
    return SizeRule::Ok;
}

// ---------------------------------------------------------------------------
// Block blob cap (found block and context block)
// ---------------------------------------------------------------------------
// Coinbase layout of the hf: bytes outside the outputs and bytes per output.
struct CoinbaseLayout {
    std::uint64_t ovh = 0;  // OVH(hf)
    std::uint64_t out = 0;  // OUT(hf, S)
};

// blob_cap(Z); nullopt when OUT is zero or Z is outside the u64 domain of the formula.
inline constexpr std::optional<std::uint64_t> blob_cap(const CoinbaseLayout& l, std::uint64_t z) noexcept {
    if (l.out == 0) return std::nullopt;
    if (z > UINT64_MAX / (kBlockWeightLimitPerMedian * kHashBytes)) return std::nullopt;
    const std::uint64_t n_out = z > l.ovh ? (z - l.ovh) / l.out : 0;
    const std::uint64_t n_tx = max_tx_count(z);
    return kHashingHeaderMaxBytes + l.ovh + n_out * l.out + kHashBytes * n_tx + varint_len(n_tx);
}

// ---------------------------------------------------------------------------
// Journal depth and relay horizons
// ---------------------------------------------------------------------------
// Positions from a carrier to the carrier that folds its bin plus D_fin: F x 120 / T + D_fin.
inline constexpr std::uint64_t fold_crossing_depth(const LaneParams& p) noexcept {
    return positions_for_heights(p, p.open_bins) + seal_depth(p);
}

// J (K27): rewind depth of the journal, in positions.
inline constexpr std::uint64_t journal_depth(const LaneParams& p) noexcept {
    return std::max(ceil_div(p.heal_period_h * kSecondsPerHour, p.carrier_interval_s), fold_crossing_depth(p));
}

struct RelayHorizons {
    std::uint64_t index_horizon = 0;    // heights
    std::uint64_t backfill = 0;         // positions
    std::uint64_t ctx_window = 0;       // heights
    std::uint64_t ctx_max_depth = 0;    // blocks per unsolicited receipt
    std::uint64_t index_retention = 0;  // heights
    std::uint64_t pending_cap = 0;      // receipts

    friend bool operator==(const RelayHorizons&, const RelayHorizons&) = default;
};

inline constexpr RelayHorizons relay_horizons(const LaneParams& p) noexcept {
    const std::uint64_t j = journal_depth(p);
    const std::uint64_t j_heights = heights_for_positions(p, j);
    RelayHorizons h;
    h.index_horizon = p.open_bins + p.fresh_max + 1;
    h.backfill = std::max(fold_crossing_depth(p), j);
    h.ctx_window = j_heights + p.fresh_max + 1;
    h.ctx_max_depth = p.fresh_max + 1;
    h.index_retention = std::max(SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG,
                                 j_heights + p.fresh_max + 1 + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW + DIFFICULTY_WINDOW);
    h.pending_cap = positions_for_heights(p, p.open_bins) * p.r_max;
    return h;
}

}  // namespace c2pool::xmr::pathb
