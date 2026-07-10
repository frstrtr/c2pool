// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <cstdint>

namespace core::underfill {

// Underfill near-empty template guard (v36 cutover deploy path) — SSOT.
//
// Detects the "near-empty template on a non-empty mempool" regression: the tx
// selector returns almost no transactions even though the local mempool holds a
// substantial fee-paying backlog that should have filled the block. This is a
// c2pool-side template-fill safety net (WARNING surface for the operator /
// contabo-prod-watch) — NOT a consensus byte-parity axis. It fabricates
// nothing; a genuinely empty mempool never trips it.
//
// The thresholds are a v36-native SHARED structure (bucket-2: standardize
// cross-coin toward the v37 shape), pinned to the legacy p2pool near-empty
// floor (~50 kB). LTC (parent) and DOGE (embedded aux GBT, its own tx-fill)
// both source their per-coin UNDERFILL_* constants from here so the live guard
// and the offline KAT assert on the SAME predicate + defaults — not a
// re-implementation (non-hollow).
inline constexpr std::uint64_t MIN_FILL_BYTES = 50'000ull;  // selected < this = near-empty block
inline constexpr std::uint64_t BACKLOG_SLACK  = 50'000ull;  // unselected fee-paying material that should have filled it

// True iff the template went near-empty while the mempool still held fee-paying
// backlog beyond the selected set + slack. Guard clauses mirror the live call
// sites (ltc/doge template_builder.hpp build_template): zero mempool fees means
// there was nothing to pack, so it is never underfill.
inline bool is_underfill(std::uint64_t selected_bytes,
                         std::uint64_t mempool_bytes,
                         std::uint64_t mempool_fees,
                         std::uint64_t min_fill = MIN_FILL_BYTES,
                         std::uint64_t backlog_slack = BACKLOG_SLACK) noexcept
{
    const bool near_empty  = selected_bytes < min_fill;
    const bool has_backlog = mempool_fees > 0
                          && mempool_bytes > selected_bytes + backlog_slack;
    return near_empty && has_backlog;
}

} // namespace core::underfill
