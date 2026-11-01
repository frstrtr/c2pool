// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// The consensus coinbase-maturity rule, stated once for both sides of the air
// gap. std-only (the InjectCaps.hpp pattern): the offline DASH intake
// (UtxoIntake.cpp, c2wallet-dash-common) and the online, key-free companion's
// inject scheduler (src/companion/sched/) include this header, so the scheduler
// never links the key-bearing dash closure to know when an input is spendable.
//
//   * A coinbase output created at height h0 may be spent in the block at
//     height H iff H >= h0 + 100 (dashd CheckTxInputs, COINBASE_MATURITY).
//     An output whose coinbase flag is unknown is held to the same rule.
//   * A known non-coinbase output is spendable in the next block: H >= h0 + 1.
//   * The next template a node builds is for tip + 1, so a tx whose inputs are
//     all spendable from height S may be submitted once tip >= S - 1.

#include <cstdint>

namespace c2w::dash::maturity {

inline constexpr int64_t kCoinbaseMaturity = 100; // consensus COINBASE_MATURITY

// The first block height in which an output created at h0 may be spent.
inline constexpr int64_t spendable_from_height(int64_t h0, bool coinbase_or_unknown)
{
    return h0 + (coinbase_or_unknown ? kCoinbaseMaturity : 1);
}

// One input as the rule sees it: its creation height (<= 0 = unknown) and
// whether it is coinbase or of unknown kind.
struct InputHeight {
    int64_t height = 0;
    bool coinbase_or_unknown = true;
};

// The earliest block height in which EVERY input is spendable: the max of
// spendable_from_height over the inputs. 0 when any input's height is unknown
// (<= 0) or when there are no inputs; the caller reports that as unknown.
// `proj` maps one element of `inputs` to an InputHeight.
template <class Range, class Proj>
inline int64_t safe_from_height(const Range& inputs, Proj proj)
{
    int64_t safe = 0;
    for (const auto& in : inputs) {
        const InputHeight ih = proj(in);
        if (ih.height <= 0) return 0;
        const int64_t s = spendable_from_height(ih.height, ih.coinbase_or_unknown);
        if (s > safe) safe = s;
    }
    return safe;
}

// The lowest tip at which a node's next template (tip + 1) may carry the tx.
inline constexpr int64_t fires_at_tip(int64_t safe_from_height)
{
    return safe_from_height - 1;
}

static_assert(spendable_from_height(2565145, true) == 2565245, "coinbase: h0 + 100");
static_assert(spendable_from_height(2565145, false) == 2565146, "non-coinbase: h0 + 1");
static_assert(fires_at_tip(2565245) == 2565244, "submit at tip >= S - 1");

} // namespace c2w::dash::maturity
