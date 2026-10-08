// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/consensus/xmr_timestamp.hpp
//
// The BLOCK TIMESTAMP rule and the 60-block median, which is one of the five
// windows a template needs (TemplateInputs::median_timestamp).
//
// monerod (Blockchain::check_block_timestamp, release-v0.18):
//
//   * a block whose timestamp is more than CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT
//     (2 hours) ahead of LOCAL time is refused;
//   * with fewer than BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW (60) parents there is
//     no median yet and the block passes;
//   * otherwise the timestamp must be >= the median of the last 60 parents.
//
// Note the asymmetry, which is deliberate in Monero: the lower bound is a
// consensus rule (every node computes the same median), the upper bound is a
// LOCAL rule against the node's own clock. Two honest nodes with clocks two
// hours apart can therefore disagree about a block at the edge -- so this file
// keeps `now` a PARAMETER rather than reading the clock. The caller passes the
// time it wants judged against, and a block refused only by the future-time
// rule is refused SOFTLY (retry later), never banned, which is what
// TimestampStatus::TooFarInFuture is for.
//
// The template side uses the same median: a block being built must carry
// max(now, median_timestamp) or the network will refuse it.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <vector>

#include "xmr_median.hpp"

namespace c2pool::xmr::native {

// --- cryptonote_config.h ------------------------------------------------------
inline constexpr std::uint64_t BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW    = 60;
inline constexpr std::uint64_t CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT   = 60 * 60 * 2;  // 2 h

enum class TimestampStatus : std::uint8_t {
    Ok = 0,
    TooFarInFuture,   // local-clock rule: soft, retry, never a ban
    BelowMedian,      // consensus rule: the block is invalid for everyone
};

inline const char* to_string(TimestampStatus s) noexcept {
    switch (s) {
        case TimestampStatus::Ok:             return "Ok";
        case TimestampStatus::TooFarInFuture: return "TooFarInFuture";
        case TimestampStatus::BelowMedian:    return "BelowMedian";
    }
    return "?";
}

// The rolling 60-block window. Push on connect, pop on rollback, with the same
// undo shape as the weight windows.
struct TimestampUndo {
    bool          evicted = false;
    std::uint64_t value   = 0;
};

class TimestampWindow {
public:
    TimestampWindow()
        : w_(static_cast<std::size_t>(BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW)) {}

    void seed(const std::vector<std::uint64_t>& timestamps) {
        w_.clear();
        for (std::uint64_t t : timestamps) w_.push(t);
    }

    std::size_t size() const noexcept { return w_.size(); }

    // Zero until the window is full, exactly as monerod: with fewer than 60
    // parents there is no median and the rule does not apply.
    std::uint64_t median() const {
        return w_.size() < BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW ? 0 : w_.median();
    }

    TimestampUndo push(std::uint64_t timestamp) {
        TimestampUndo u;
        u.evicted = w_.push(timestamp, u.value);
        return u;
    }

    bool pop(const TimestampUndo& u) { return w_.pop_back(u.evicted, u.value); }

    // `now` is the caller's clock, in seconds. Passing 0 skips the future-time
    // rule, which is what a replay over recorded history wants.
    TimestampStatus check(std::uint64_t timestamp, std::uint64_t now) const {
        if (now != 0 && timestamp > now + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT)
            return TimestampStatus::TooFarInFuture;
        if (w_.size() < BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW) return TimestampStatus::Ok;
        if (timestamp < w_.median()) return TimestampStatus::BelowMedian;
        return TimestampStatus::Ok;
    }

    // The timestamp a template must not go below.
    std::uint64_t template_timestamp(std::uint64_t now) const {
        const std::uint64_t m = median();
        return now > m ? now : m;
    }

    const MedianWindow& window() const noexcept { return w_; }

private:
    MedianWindow w_;
};

} // namespace c2pool::xmr::native
