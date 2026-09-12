// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/consensus/xmr_epoch.hpp
//
// The RandomX SEED EPOCH, re-exported for the native node, plus the seed-pair
// rule the wave-0 review pinned as D-15. (The plan's own reconciliation table
// stops at D-14; D-15 is the row this file is the implementation of.)
//
// The epoch arithmetic itself is NOT re-derived here. It already exists as
// xmr::coin::rx_seedheight in src/impl/xmr/coin/xmr_seedheight.hpp, where it
// carries its own deliberate deviation from monerod: monerod reads
// SEEDHASH_EPOCH_LAG and SEEDHASH_EPOCH_BLOCKS from the ENVIRONMENT as a test
// hook, and a consensus verifier must never inherit an env-tunable epoch. That
// file is the single source of the constants; this one adds the scheduling rule
// the node needs on top of it, so the two cannot drift apart.
//
// D-15, the seed-pair rule:
//
//   1. The seed for a block at height h is the id of the block at
//      rx_seedheight(h) = (h - 65) & ~2047, resolved ON THE BRANCH BEING
//      VERIFIED -- not on the current best chain. A reorg that crosses an epoch
//      edge can therefore change which seed a block needs, and the verifier
//      must walk the branch by id rather than index by height.
//   2. The NEXT seed is the seed for h + 64. It differs from the current seed
//      only inside the 64-block lag before an epoch boundary; that lag window
//      is exactly why two resident caches always suffice.
//   3. next_seed_hash is published in the template inputs only while it differs
//      from seed_hash, which is what monerod's get_miner_data does, so a
//      template built from the native arm is field-comparable with one built
//      from the daemon arm.
//   4. On tip-follow there is EXACTLY ONE re-key per epoch: the next epoch's
//      key block is already 64 blocks deep and verified when the rollover
//      happens, so it is prefetched, never waited on.
//   5. Nothing here reads the environment, and nothing here is configurable.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>

#include "impl/xmr/coin/xmr_seedheight.hpp"

namespace c2pool::xmr::native {

// Re-export, so a native-node component never needs to reach into the coin tree
// for the constants and never redefines 2048 / 64 for itself.
inline constexpr std::uint64_t SEEDHASH_EPOCH_BLOCKS = ::xmr::coin::SEEDHASH_EPOCH_BLOCKS;
inline constexpr std::uint64_t SEEDHASH_EPOCH_LAG    = ::xmr::coin::SEEDHASH_EPOCH_LAG;

using ::xmr::coin::rx_seedheight;
using ::xmr::coin::rx_seedheights;

// Which epoch a height belongs to, and where that epoch's key block sits.
inline constexpr std::uint64_t epoch_index(std::uint64_t height) noexcept {
    return rx_seedheight(height) / SEEDHASH_EPOCH_BLOCKS;
}

// The seed heights a block at `height` needs. `in_lag_window` is true exactly
// when the next seed differs from the current one, which is the only time a
// template publishes next_seed_hash (D-15 rule 3).
struct SeedPair {
    std::uint64_t seed_height      = 0;
    std::uint64_t next_seed_height = 0;
    bool          in_lag_window    = false;
};

inline constexpr SeedPair seed_pair_for_height(std::uint64_t height) noexcept {
    SeedPair p{};
    rx_seedheights(height, p.seed_height, p.next_seed_height);
    p.in_lag_window = (p.next_seed_height != p.seed_height);
    return p;
}

// True when advancing from `from_height` to `to_height` changes the seed, i.e.
// the verifier must re-key (D-15 rule 4: at most one re-key per epoch when
// following the tip one block at a time).
inline constexpr bool crosses_seed_edge(std::uint64_t from_height,
                                        std::uint64_t to_height) noexcept {
    return rx_seedheight(from_height) != rx_seedheight(to_height);
}

// The prefetch trigger: at this height the next epoch's key block is already
// buried by the lag and verified, so its cache can be built off the hot path.
inline constexpr bool should_prefetch_next_seed(std::uint64_t height) noexcept {
    return seed_pair_for_height(height).in_lag_window;
}

// How many blocks of chain a verifier must be able to reach behind `height` to
// resolve both seeds of the pair. This is the retention floor the index owes
// the RandomX lifecycle, and it is why the pinned retention window (2048 rows
// plus seed anchors reaching 2112 back) is what it is.
inline constexpr std::uint64_t seed_reach_required(std::uint64_t height) noexcept {
    const std::uint64_t seed = rx_seedheight(height);
    return height > seed ? (height - seed) : 0;
}

// Sanity pins on the geometry, checked at compile time so a future edit to the
// coin-tree constants cannot silently change the schedule.
static_assert(SEEDHASH_EPOCH_BLOCKS == 2048, "RandomX epoch length is consensus-fixed");
static_assert(SEEDHASH_EPOCH_LAG == 64, "RandomX epoch lag is consensus-fixed");
static_assert(rx_seedheight(SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG) == 0,
              "the genesis epoch extends to EPOCH_BLOCKS + LAG");
static_assert(rx_seedheight(SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG + 1) == SEEDHASH_EPOCH_BLOCKS,
              "the first rollover is one block past EPOCH_BLOCKS + LAG");
static_assert(seed_pair_for_height(4096 + 64).in_lag_window,
              "a height 64 short of a rollover must be inside the lag window");
static_assert(!seed_pair_for_height(4096 + 65).in_lag_window,
              "a height just past a rollover must be outside the lag window");

} // namespace c2pool::xmr::native
