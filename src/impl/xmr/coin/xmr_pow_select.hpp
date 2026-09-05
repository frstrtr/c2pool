// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/coin/xmr_pow_select.hpp  --  fork-height PoW-algorithm selector
//
// AUTHORED for c2pool (not ported). The single fork-gated switchboard for the
// XMR lane, keyed on the Monero block header's `major_version`. Models
// monero-project's get_block_longhash() dispatch
//   (src/cryptonote_basic/cryptonote_format_utils.cpp @ 3d3920d7):
//     major_version >= RX_BLOCK_VERSION(12)  -> RandomX(seed_hash, blob)
//     else                                   -> CryptoNight variant (historical)
// with two forward fences the lane MUST pin per Monero hard fork.
//
// LANE INVARIANT: the XMR settlement lane exists only from RandomX onward.
// A receipt whose major_version < RX_BLOCK_VERSION is rejected outright
// (pre-RandomX CryptoNight verification is intentionally NOT provided).
//
// FENCE 1 -- RandomX v2 (#8827). RandomX 2.0 released 2026-03-25; monerod's
//   mainnet fork table still tops at v16 (height 2,689,608) and #8827
//   (double-Blake2b finalisation, 32-B intermediate) is UNSCHEDULED. When it
//   activates it will bump major_version; pin RANDOMX_V2_MAJOR_VERSION then and
//   route to a distinct verifier build. Until then every RX block is v1.
//
// FENCE 2 -- CARROT / FCMP++. CARROT redefines address/key derivation; WHETHER
//   coinbase output derivation changes is an open question (scoping OQ-X10/U7,
//   risk (b)). ALL coinbase-output derivation in this tree (xmr_derivation.cpp,
//   the W5 executor) is declared PRE-CARROT and is valid only while
//   coinbase_derivation_is_pre_carrot(major_version) holds. CARROT_MAJOR_VERSION
//   is a sentinel (unassigned) today, so the predicate is true for all current
//   majors; the day it is pinned, receipts at/after it MUST fail the guard until
//   the derivation layer is rewritten (do NOT silently derive with the old rule).
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <limits>

namespace xmr::coin {

// The Monero major_version at which RandomX activates. Value mirrors
// hash-ops.h's `#define RX_BLOCK_VERSION 12` (monero-project @ 3d3920d7); named
// differently on purpose so this typed constant never collides with that macro
// when a TU includes both this header and monerod's hash-ops.h/cryptonote_config.h.
inline constexpr std::uint8_t RX_ACTIVATION_MAJOR = 12;

// UNSCHEDULED fences -> sentinel = "never yet activated". Pin to the real
// activation major_version when Monero schedules them; leaving them at the
// sentinel keeps the lane on the current, audited rules.
inline constexpr std::uint8_t RANDOMX_V2_MAJOR_VERSION =
    std::numeric_limits<std::uint8_t>::max();   // #8827: TBD
inline constexpr std::uint8_t CARROT_MAJOR_VERSION =
    std::numeric_limits<std::uint8_t>::max();   // FCMP++/CARROT: TBD (OQ-X10)

// Current mainnet top fork, for reference / sanity bounds (scoping S: v16 @ h2689608).
inline constexpr std::uint8_t MONERO_CURRENT_TOP_MAJOR = 16;

enum class PowAlgo : std::uint8_t {
    Unsupported = 0,  // pre-RandomX; rejected by the lane
    RandomXv1   = 1,  // RX_ACTIVATION_MAJOR .. (RANDOMX_V2 - 1)
    RandomXv2   = 2,  // #8827 finalisation, once pinned
};

// Which PoW verifier a receipt's major_version selects. get_block_longhash model.
inline constexpr PowAlgo select_pow_algo(std::uint8_t major_version) noexcept {
    if (major_version < RX_ACTIVATION_MAJOR)            return PowAlgo::Unsupported;
    if (major_version >= RANDOMX_V2_MAJOR_VERSION)      return PowAlgo::RandomXv2;
    return PowAlgo::RandomXv1;
}

inline constexpr bool is_supported_major(std::uint8_t major_version) noexcept {
    return select_pow_algo(major_version) != PowAlgo::Unsupported;
}

// FENCE 2 predicate: is the pre-CARROT coinbase-output derivation rule valid at
// this major_version? Must be checked before xmr_derivation.cpp is used to
// re-derive/verify any coinbase output.
inline constexpr bool coinbase_derivation_is_pre_carrot(std::uint8_t major_version) noexcept {
    return major_version < CARROT_MAJOR_VERSION;
}

} // namespace xmr::coin
