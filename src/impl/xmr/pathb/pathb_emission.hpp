// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_emission.hpp
// Path B, slice S3: the emission base reward, the coinbase free tier N(B) at the
// frozen Z/2 reserve, OVH / OUT per hf, and the spend floor f_spend.
//
//   base_reward_at(agc, hf) = B(A): Monero's emission-only subsidy from the
//       already_generated_coins at the anchor A_t (60 deep, K_A = M-03). B(A) is
//       the WINDOW input (W_max, f_spend, N(B) via Z(A), OUT via S_A = B(A_t));
//       it is NOT the coinbase amount R. [C28, M-03, M-04; S3.4]
//   n_rule(Z, hf, S_A) = N(B) = max(1, floor((Z - 2 OVH) / (2 OUT)))
//                              = floor((Z/2 - OVH) / OUT) exactly; hf >= 17 capped
//       at FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS. [K10, K25, ruling 25 K-5]
//   ovh(hf)         = 89 (hf 16) / 61 (hf 17).            [K24a]
//   out_size(hf,S)  = 34 + V(S) (hf 16) / 84 + V(S) (hf 17); V = varint length of
//       the base reward S_A. [K24b, ruling 17 H-3 / 20 Q-G]
//   f_spend(S,M,hf) = quantise_up(kInputWeight 659 x get_dynamic_base_fee(S,
//       max(M, zone)), 10^4); reference weight 3,000 (12,500 at hf >= 17);
//       hf 15..16 lo -= lo/20. [K11d, ruling 5, M-05]
//
// hf-17 carve-out (O-01, OWED and external): the AMOUNT rule is not derived. The
// FORMAT (OVH 61, OUT 84 + V) is specified and tested; at hf >= 17 the lane
// FORK-FUSEs for the amount (amount_fork_fused(hf) == true) and builds nothing.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>

#include "impl/xmr/native/consensus/xmr_reward.hpp"  // emission_base_reward, FINAL_SUBSIDY_PER_MINUTE
#include "impl/xmr/native/consensus/xmr_weight.hpp"   // min_block_weight (zone per hf)

#include "pathb_params.hpp"   // varint_len, FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS, HF_VERSION_CARROT
#include "pathb_wide.hpp"     // wide::u128

namespace c2pool::xmr::pathb {

// hf 16 is the only amount rule shipped; the hf 17 amount rule is O-01 (owed).
inline constexpr std::uint8_t kHf16 = 16;

// ---------------------------------------------------------------------------
// FORK-FUSE (S3.1 carve-out): at hf >= 17 (Carrot) the coinbase AMOUNT rule is
// owed (O-01). The lane builds and admits NO amount; it fuses.
// ---------------------------------------------------------------------------
inline constexpr bool amount_fork_fused(std::uint8_t hf) noexcept { return hf >= HF_VERSION_CARROT; }

// ---------------------------------------------------------------------------
// base_reward_at (S3.4 `base_reward_at`; C28, M-04): the emission-only subsidy
// B(A) from already_generated_coins at the anchor. Mainnet tail = 6e11.
// ---------------------------------------------------------------------------
inline std::uint64_t base_reward_at(std::uint64_t already_generated_coins, std::uint8_t hf) noexcept {
    return ::c2pool::xmr::native::emission_base_reward(already_generated_coins, hf);
}

// Mainnet tail subsidy: FINAL_SUBSIDY_PER_MINUTE x 2 (the 2-minute target).
inline constexpr std::uint64_t kTailBaseReward =
        ::c2pool::xmr::native::FINAL_SUBSIDY_PER_MINUTE * 2;  // 6e11

// ---------------------------------------------------------------------------
// OVH / OUT per hf (S3.4 `ovh` / `out_size`; K24a / K24b, ruling 20 Q-G).
// OVH is the fixed coinbase overhead; OUT the per-output byte cost, = base size
// + varint length of the base reward S_A (an upper bound: N(B) is then computable
// in advance and identical on every node).
// ---------------------------------------------------------------------------
inline constexpr std::uint32_t kOvhHf16 = 89;
inline constexpr std::uint32_t kOvhHf17 = 61;
inline constexpr std::uint32_t kOutBaseHf16 = 34;
inline constexpr std::uint32_t kOutBaseHf17 = 84;

inline constexpr std::uint32_t ovh(std::uint8_t hf) noexcept {
    return hf >= HF_VERSION_CARROT ? kOvhHf17 : kOvhHf16;
}

inline constexpr std::uint32_t out_size(std::uint8_t hf, std::uint64_t s_a) noexcept {
    const std::uint32_t base = hf >= HF_VERSION_CARROT ? kOutBaseHf17 : kOutBaseHf16;
    return base + static_cast<std::uint32_t>(varint_len(s_a));
}

// ---------------------------------------------------------------------------
// n_rule (S3.4 `n_rule`; K10 / K25, ruling 25 K-5): N(B) at the frozen Z/2
// reserve. numerator Z - 2 OVH in signed i128 (non-positive -> N = 1).
// ---------------------------------------------------------------------------
inline std::uint64_t n_rule(std::uint64_t z, std::uint8_t hf, std::uint64_t s_a) noexcept {
    const __int128 num = static_cast<__int128>(z) - static_cast<__int128>(2) * ovh(hf);
    std::uint64_t n;
    if (num <= 0) {
        n = 1;
    } else {
        const std::uint64_t den = static_cast<std::uint64_t>(2) * out_size(hf, s_a);
        n = static_cast<std::uint64_t>(num / den);
        if (n < 1) n = 1;
    }
    if (hf >= HF_VERSION_CARROT && n > FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS)
        n = FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS;
    return n;
}

// The second written form, proven equal to n_rule for every integer Z (reserve
// KAT): floor((floor(Z/2) - OVH) / OUT), clamped the same way.
inline std::uint64_t n_rule_half_form(std::uint64_t z, std::uint8_t hf, std::uint64_t s_a) noexcept {
    const std::int64_t num = static_cast<std::int64_t>(z / 2) - static_cast<std::int64_t>(ovh(hf));
    std::uint64_t n;
    if (num <= 0) {
        n = 1;
    } else {
        n = static_cast<std::uint64_t>(num) / out_size(hf, s_a);
        if (n < 1) n = 1;
    }
    if (hf >= HF_VERSION_CARROT && n > FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS)
        n = FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS;
    return n;
}

// ---------------------------------------------------------------------------
// Spend floor (S3.4 `f_spend`; K11d, ruling 5). Monero's own arithmetic: a
// dynamic base fee per byte at the fee median, x kInputWeight (one RingCT/CLSAG
// input at ring 16 = 659), quantised up to the 10^4 piconero step. The caller
// supplies the fee median already floored at max(M, zone(hf)).
// ---------------------------------------------------------------------------
inline constexpr std::uint64_t kInputWeight = 659;              // one RingCT input, ring 16
inline constexpr std::uint64_t kFeeReferenceTxWeight = 3000;    // DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT_V8
inline constexpr std::uint64_t kFeeReferenceTxWeightHf17 = 12500;  // DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT_V17
inline constexpr std::uint64_t kFeeQuantizationStep = 10000;    // 10^(12 - 8)
inline constexpr std::uint8_t kHf2021Scaling = 15;              // HF_VERSION_2021_SCALING

// The penalty-free zone (fee-median floor) per hf: Z_V5 (hf<17) / Z_V17 (hf>=17).
inline constexpr std::uint64_t fee_zone(std::uint8_t hf) noexcept {
    return hf >= HF_VERSION_CARROT ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V17
                                   : CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
}

// The fee reference transaction weight per hf: 3,000 (hf < 17) / 12,500 (hf >= 17).
inline constexpr std::uint64_t fee_reference_weight(std::uint8_t hf) noexcept {
    return hf >= HF_VERSION_CARROT ? kFeeReferenceTxWeightHf17 : kFeeReferenceTxWeight;
}

// get_dynamic_base_fee(reward, median) at `median`, Monero's order of operations
// (reward * ref_weight(hf) / median / median in 128 bits), the 2021 scaling 0.95
// at hf 15 and 16 (none from hf 17), floored at 1.
inline std::uint64_t fee_per_byte(std::uint64_t reward, std::uint64_t median, std::uint8_t hf) noexcept {
    if (median == 0) median = 1;
    wide::u128 v = static_cast<wide::u128>(reward) * fee_reference_weight(hf);
    v /= median;
    v /= median;
    std::uint64_t lo = static_cast<std::uint64_t>(v);
    if (hf >= kHf2021Scaling && hf < HF_VERSION_CARROT) lo -= lo / 20;
    return lo == 0 ? 1 : lo;
}

// f_spend: the cost to spend one coinbase output. median_in = M (the chain fee
// median); the floor at max(M, zone(hf)) is applied here.
inline std::uint64_t f_spend(std::uint64_t s_a, std::uint64_t median_in, std::uint8_t hf) noexcept {
    const std::uint64_t zone = fee_zone(hf);
    const std::uint64_t median = median_in > zone ? median_in : zone;
    const wide::u128 need = static_cast<wide::u128>(kInputWeight) * fee_per_byte(s_a, median, hf);
    const wide::u128 q = (need + kFeeQuantizationStep - 1) / kFeeQuantizationStep * kFeeQuantizationStep;
    return q > ~static_cast<std::uint64_t>(0) ? ~static_cast<std::uint64_t>(0)
                                              : static_cast<std::uint64_t>(q);
}

}  // namespace c2pool::xmr::pathb
