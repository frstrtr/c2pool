// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/coin/xmr_seedheight.hpp  --  RandomX seed-height / epoch logic
//
// AUTHORED for c2pool (not ported). Reimplements the RandomX seed-height rule
// as a pure, header-only, consensus-fixed function.
//
// Reference: monero-project src/crypto/rx-slow-hash.c @ 3d3920d7
//   #define SEEDHASH_EPOCH_BLOCKS 2048   // "key should change every ~2.8 d"
//   #define SEEDHASH_EPOCH_LAG      64    // "delay ~2 h between key block and change"
//   rx_seedheight(h) = (h <= EPOCH_BLOCKS+EPOCH_LAG) ? 0
//                      : (h - EPOCH_LAG - 1) & ~(EPOCH_BLOCKS-1);
//
// DELIBERATE DEVIATION FROM monerod: rx-slow-hash.c reads SEEDHASH_EPOCH_LAG /
// SEEDHASH_EPOCH_BLOCKS from the ENVIRONMENT (get_seedhash_epoch_lag/_blocks) as
// a test hook. A consensus verifier MUST NOT inherit an env-tunable epoch, so
// these are hard compile-time constants here. (scoping S1/S8-item-3)
//
// The XMR-lane verifier resolves, per receipt: bin = height(header.prev_id);
// seed_height(bin) picks the mainchain block whose hash keys the 256 MiB cache;
// a receipt within N_CTX=2 bins can straddle an epoch edge only when
// bin mod 2048 in {63,64}, so holding {current, next} caches suffices.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>

namespace xmr::coin {

inline constexpr std::uint64_t SEEDHASH_EPOCH_BLOCKS = 2048; // must equal monerod
inline constexpr std::uint64_t SEEDHASH_EPOCH_LAG    = 64;
static_assert((SEEDHASH_EPOCH_BLOCKS & (SEEDHASH_EPOCH_BLOCKS - 1)) == 0,
              "EPOCH_BLOCKS must be a power of two for the & ~(n-1) mask");

// Mainchain height whose block hash is the RandomX seed for a block at `height`.
inline constexpr std::uint64_t rx_seedheight(std::uint64_t height) noexcept {
    return (height <= SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG)
               ? 0
               : (height - SEEDHASH_EPOCH_LAG - 1) & ~(SEEDHASH_EPOCH_BLOCKS - 1);
}

// Current + next seed heights (next = seed for height+lag), so the verifier can
// pre-build the upcoming epoch's cache across the 64-block lag. Mirrors
// rx-slow-hash.c rx_seedheights().
inline constexpr void rx_seedheights(std::uint64_t height,
                                     std::uint64_t& seed,
                                     std::uint64_t& next) noexcept {
    seed = rx_seedheight(height);
    next = rx_seedheight(height + SEEDHASH_EPOCH_LAG);
}

// True at the two bins where an N_CTX=2 window can span an epoch boundary.
inline constexpr bool is_epoch_edge(std::uint64_t height) noexcept {
    const std::uint64_t m = height & (SEEDHASH_EPOCH_BLOCKS - 1);
    return m == (SEEDHASH_EPOCH_BLOCKS - 1) || m == 0
        || m == SEEDHASH_EPOCH_LAG - 1 || m == SEEDHASH_EPOCH_LAG;
}

} // namespace xmr::coin
