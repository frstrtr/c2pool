// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/consensus/xmr_difficulty.hpp
//
// NEXT-DIFFICULTY, as a rolling window plus the R-U128 ADAPTER.
//
// R-U128 (the plan's pinned ruling) says: do NOT re-implement Monero's
// retargeting; keep the vendored src/impl/xmr/coin/vendor/difficulty.cpp
// verbatim -- boost::multiprecision and all -- and put a Difficulty128 adapter
// in front of it. This file is that adapter plus the window bookkeeping the
// vendored function does not do.
//
// WHY THE RULING IS RIGHT, in one number: the retarget is
//
//     next = ceil( (cumdiff[cut_end-1] - cumdiff[cut_begin]) * target
//                  / (ts[cut_end-1] - ts[cut_begin]) )
//
// over a window of 735 rows of which the SORTED middle 600 are used -- and the
// sort is over timestamps ALONE while the cumulative differences are indexed by
// position, which is a subtle mismatch that a reimplementation "cleans up" and
// thereby forks. The vendored code has that quirk; so does the network.
//
// WHAT THE WINDOW IS. monerod (Blockchain::get_difficulty_for_next_block)
// collects the last min(height, DIFFICULTY_BLOCKS_COUNT = 735) blocks, OLDEST
// FIRST, skipping height 0, and passes them in. next_difficulty() then RESIZES
// to the first DIFFICULTY_WINDOW = 720 -- which, on an oldest-first vector,
// drops the NEWEST 15 rows. That is DIFFICULTY_LAG, and it is why the window is
// 735 and not 720. Feeding 720 or 721 rows produces a different, wrong answer;
// the KAT pins 735 against 400+ consecutive stagenet heights and shows the
// other two spellings failing every one of them.
//
// THIS HEADER PULLS BOOST. It is the only file in the native tree that does,
// because the vendored difficulty.h types its difficulty as
// boost::multiprecision::uint128_t. Boost is a repo-wide dependency
// (find_package(Boost REQUIRED) in the root CMakeLists) and the include is
// header-only, but a component that needs medians, weights or rewards and NOT
// retargeting should include those headers and not this one. A target that
// includes this file must link `xmr_coin` (the vendored TU and the compat
// include path live there).
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <vector>

#include "impl/xmr/native/contracts/types.hpp"   // U128 (node::Difficulty128), u128_add
// Resolved through xmr_coin's PUBLIC include directories (coin/ for the vendored
// header, compat/ for the crypto/hash.h and cryptonote_config.h stand-ins it
// reads). A target that includes this file must link xmr_coin.
#include "vendor/difficulty.h"                    // cryptonote::next_difficulty (vendored)

namespace c2pool::xmr::native {

// --- cryptonote_config.h ------------------------------------------------------
inline constexpr std::uint64_t DIFFICULTY_TARGET_V1  = 60;
inline constexpr std::uint64_t DIFFICULTY_TARGET_V2  = 120;
inline constexpr std::size_t   DIFFICULTY_WINDOW     = 720;
inline constexpr std::size_t   DIFFICULTY_LAG        = 15;
inline constexpr std::size_t   DIFFICULTY_CUT        = 60;
inline constexpr std::size_t   DIFFICULTY_BLOCKS_COUNT = DIFFICULTY_WINDOW + DIFFICULTY_LAG;  // 735

// The retarget target in seconds. monerod: version < 2 -> V1, else V2.
inline constexpr std::uint64_t difficulty_target_seconds(std::uint8_t version) noexcept {
    return version < 2 ? DIFFICULTY_TARGET_V1 : DIFFICULTY_TARGET_V2;
}

// --- the adapter ---------------------------------------------------------------
namespace detail {

inline ::cryptonote::difficulty_type to_boost(const U128& d) {
    ::cryptonote::difficulty_type v = d.hi;
    v <<= 64;
    v |= d.lo;
    return v;
}

inline U128 from_boost(const ::cryptonote::difficulty_type& v) {
    ::cryptonote::difficulty_type lo = v & ::cryptonote::difficulty_type(~static_cast<std::uint64_t>(0));
    ::cryptonote::difficulty_type hi = v >> 64;
    U128 out{};
    out.lo = lo.convert_to<std::uint64_t>();
    out.hi = hi.convert_to<std::uint64_t>();
    return out;
}

} // namespace detail

// next_difficulty over an OLDEST-FIRST window, through the vendored function.
// A result of zero is the vendored code's "the retarget overflowed 128 bits"
// signal and is passed through unchanged rather than clamped: a caller that
// meets it is looking at a chain no honest network produced.
inline U128 next_difficulty_from_window(const std::vector<std::uint64_t>& timestamps,
                                        const std::vector<U128>&          cumulative_difficulties,
                                        std::uint64_t                     target_seconds) {
    std::vector<::cryptonote::difficulty_type> cd;
    cd.reserve(cumulative_difficulties.size());
    for (const U128& d : cumulative_difficulties) cd.push_back(detail::to_boost(d));
    return detail::from_boost(::cryptonote::next_difficulty(
        timestamps, cd, static_cast<std::size_t>(target_seconds)));
}

// --- the rolling window ---------------------------------------------------------
// One row per block, oldest first, capped at DIFFICULTY_BLOCKS_COUNT. Push on
// connect, pop on rollback; the undo record carries the row that fell off the
// far end so a reorg restores the window exactly.
struct DifficultyRow {
    std::uint64_t timestamp = 0;
    U128          cumulative_difficulty{};
};

struct DifficultyUndo {
    bool          evicted = false;
    DifficultyRow row{};
};

class DifficultyWindow {
public:
    std::size_t size()  const noexcept { return rows_.size(); }
    bool        empty() const noexcept { return rows_.empty(); }
    void        clear()                { rows_.clear(); }

    // Preload from an anchor bundle: exactly DIFFICULTY_BLOCKS_COUNT rows,
    // oldest first, ending at the anchor height.
    void seed(const std::vector<DifficultyRow>& rows) {
        rows_.assign(rows.begin(), rows.end());
        while (rows_.size() > DIFFICULTY_BLOCKS_COUNT) rows_.pop_front();
    }

    DifficultyUndo push(std::uint64_t timestamp, const U128& cumulative_difficulty) {
        DifficultyUndo u;
        rows_.push_back(DifficultyRow{timestamp, cumulative_difficulty});
        if (rows_.size() > DIFFICULTY_BLOCKS_COUNT) {
            u.evicted = true;
            u.row     = rows_.front();
            rows_.pop_front();
        }
        return u;
    }

    bool pop(const DifficultyUndo& u) {
        if (rows_.empty()) return false;
        rows_.pop_back();
        if (u.evicted) rows_.push_front(u.row);
        return true;
    }

    // The difficulty of the block that would come next.
    U128 next_difficulty(std::uint8_t version) const {
        std::vector<std::uint64_t> ts;
        std::vector<U128>          cd;
        ts.reserve(rows_.size());
        cd.reserve(rows_.size());
        for (const DifficultyRow& r : rows_) {
            ts.push_back(r.timestamp);
            cd.push_back(r.cumulative_difficulty);
        }
        return next_difficulty_from_window(ts, cd, difficulty_target_seconds(version));
    }

    U128 newest_cumulative_difficulty() const {
        return rows_.empty() ? U128{} : rows_.back().cumulative_difficulty;
    }

    const std::deque<DifficultyRow>& rows() const noexcept { return rows_; }

private:
    std::deque<DifficultyRow> rows_;
};

} // namespace c2pool::xmr::native
