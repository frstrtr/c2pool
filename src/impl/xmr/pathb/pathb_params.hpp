// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_params.hpp
// Path B: lane parameters, the Monero symbols Path B reads, and the integer
// helpers the derived values use.
//
// Every value in this tree is one of:
//   * a Monero symbol, cited by name (monero-project master for hf <= 16, the
//     FCMP++ branch cryptonote_config.h for hf 17);
//   * a lane parameter (LaneParams, K-list id in the field comment);
//   * a formula over the two above.
//
// Header-only. Not included by any running component.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <tuple>

#include "impl/xmr/coin/coin_xmr.hpp"                    // MINED_MONEY_UNLOCK_WINDOW
#include "impl/xmr/coin/xmr_seedheight.hpp"               // SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"  // FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS
#include "impl/xmr/native/consensus/xmr_hf_table.hpp"     // hf_ring_size
#include "impl/xmr/native/consensus/xmr_reward.hpp"       // DIFFICULTY_TARGET_V2_SECONDS
#include "impl/xmr/native/consensus/xmr_weight.hpp"       // zones V1/V2/V5, surge factor, min_block_weight

namespace c2pool::xmr::pathb {

// ---------------------------------------------------------------------------
// Basic types
// ---------------------------------------------------------------------------
using Hash32 = std::array<std::uint8_t, 32>;

// Width of a hash / key field: the size of the hash type.
inline constexpr std::size_t kHashBytes = std::tuple_size_v<Hash32>;

// ---------------------------------------------------------------------------
// Monero symbols already in the tree (monero-project master names).
// ---------------------------------------------------------------------------
inline constexpr std::uint64_t DIFFICULTY_TARGET_V2 = ::c2pool::xmr::native::DIFFICULTY_TARGET_V2_SECONDS;
inline constexpr std::uint64_t SEEDHASH_EPOCH_BLOCKS = ::xmr::coin::SEEDHASH_EPOCH_BLOCKS;
inline constexpr std::uint64_t SEEDHASH_EPOCH_LAG = ::xmr::coin::SEEDHASH_EPOCH_LAG;
inline constexpr std::uint64_t CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 =
        ::c2pool::xmr::native::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
inline constexpr std::uint64_t FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS =
        ::c2pool::xmr::native::FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS;

// cryptonote_config.h CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW.
inline constexpr std::uint64_t CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW = ::xmr::coin::MINED_MONEY_UNLOCK_WINDOW;

// cryptonote_config.h DIFFICULTY_WINDOW, DIFFICULTY_LAG and DIFFICULTY_BLOCKS_COUNT
// (also in native/consensus/xmr_difficulty.hpp, which pulls Boost; pathb_branch.hpp
// includes that header and static_asserts equality).
inline constexpr std::uint64_t DIFFICULTY_WINDOW = 720;
inline constexpr std::uint64_t DIFFICULTY_LAG = 15;
inline constexpr std::uint64_t DIFFICULTY_BLOCKS_COUNT = DIFFICULTY_WINDOW + DIFFICULTY_LAG;

// cryptonote_config.h CRYPTONOTE_SHORT_TERM_BLOCK_SURGE_FACTOR_V10 (named
// CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR in native/consensus/xmr_weight.hpp).
inline constexpr std::uint64_t CRYPTONOTE_SHORT_TERM_BLOCK_SURGE_FACTOR_V10 =
        ::c2pool::xmr::native::CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR;

// ---------------------------------------------------------------------------
// Monero symbols of the FCMP++ / Carrot hard fork (FCMP++ branch
// cryptonote_config.h:61, :64, :204, :205). Not in the tree yet.
// ---------------------------------------------------------------------------
inline constexpr std::uint8_t  HF_VERSION_FCMP_PLUS_PLUS = 17;
inline constexpr std::uint8_t  HF_VERSION_CARROT = 17;
inline constexpr std::uint64_t CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V17 = 625000;
inline constexpr std::uint64_t CRYPTONOTE_SHORT_TERM_BLOCK_SURGE_FACTOR_V17 = 8;

// Leaves the block content hash places after the miner tx from
// HF_VERSION_FCMP_PLUS_PLUS: the tree-layer count and the tree root
// (FCMP++ branch cryptonote_format_utils.cpp get_block_content_hash).
inline constexpr std::uint64_t kFcmpContentHashExtraLeaves = 2;

static_assert(HF_VERSION_FCMP_PLUS_PLUS == ::c2pool::xmr::native::HF_VERSION_REJECT_MANY_MINER_OUTPUTS);

// ---------------------------------------------------------------------------
// Lane parameters (K-list ids). The ruled set is kRuledLaneParams below.
// lane_params_valid covers the fields read by pathb_caps.hpp and
// pathb_catchup.hpp; retarget_params_valid (pathb_retarget.hpp) covers K01,
// K02 and K03.
// ---------------------------------------------------------------------------
struct LaneParams {
    std::uint64_t carrier_interval_s = 0;   // K01 T
    std::uint64_t open_bins = 0;            // K04 F
    std::uint64_t fresh_max = 0;            // K07 Fresh
    std::uint64_t r_max = 0;                // K08 R_MAX
    std::uint64_t heal_period_h = 0;        // P-02 P_heal (hours)
    std::uint64_t d_min = 0;                // K02 d_min
    std::uint64_t retarget_span = 0;        // K03 N_rt (carriers)
    std::uint64_t retarget_growth_num = 0;  // K03 g* = num / den (pathb_retarget.hpp)
    std::uint64_t retarget_growth_den = 0;
};

inline constexpr LaneParams kRuledLaneParams{
    /*carrier_interval_s=*/10,
    /*open_bins=*/96,
    /*fresh_max=*/2,
    /*r_max=*/16,
    /*heal_period_h=*/3,
    /*d_min=*/18180,
    /*retarget_span=*/2160,
    /*retarget_growth_num=*/101,
    /*retarget_growth_den=*/100,
};

inline constexpr std::uint64_t kSecondsPerHour = 3600;

// Basis-point scale of fee_rate p and give_author_bp.
inline constexpr std::uint64_t kBasisPointsScale = 10000;

// ---------------------------------------------------------------------------
// Integer helpers
// ---------------------------------------------------------------------------
inline constexpr std::uint64_t ceil_div(std::uint64_t a, std::uint64_t b) noexcept {
    return a / b + (a % b != 0 ? 1u : 0u);
}

// CryptoNote LEB128 varint: 7 payload bits per byte.
inline constexpr unsigned kVarintPayloadBits = 7;

inline constexpr std::size_t varint_len(std::uint64_t v) noexcept {
    std::size_t n = 1;
    while ((v >> kVarintPayloadBits) != 0) {
        v >>= kVarintPayloadBits;
        ++n;
    }
    return n;
}

// floor(log2(x)) for x >= 1.
inline constexpr std::uint64_t floor_log2(std::uint64_t x) noexcept {
    return std::bit_width(x) - 1u;
}

// D_fin (K06) = 0 at every T.
inline constexpr std::uint64_t kSealDepth = 0;

inline constexpr std::uint64_t seal_depth(const LaneParams&) noexcept {
    return kSealDepth;
}

// Carrier positions per Monero height on average: DIFFICULTY_TARGET_V2 / T,
// applied to a count of heights with rounding up.
inline constexpr std::uint64_t positions_for_heights(const LaneParams& p, std::uint64_t heights) noexcept {
    return ceil_div(heights * DIFFICULTY_TARGET_V2, p.carrier_interval_s);
}

// Monero heights covering a count of carrier positions, rounded up.
inline constexpr std::uint64_t heights_for_positions(const LaneParams& p, std::uint64_t positions) noexcept {
    return ceil_div(positions * p.carrier_interval_s, DIFFICULTY_TARGET_V2);
}

inline constexpr bool lane_params_valid(const LaneParams& p) noexcept {
    return p.carrier_interval_s > 0 && p.open_bins > 0 && p.fresh_max > 0 && p.r_max > 0;
}

}  // namespace c2pool::xmr::pathb
