// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <cstdint>

#include <core/underfill_guard.hpp>

// Offline deterministic KAT for the underfill near-empty template guard SSOT.
//
// The predicate under test is the SAME core::underfill::is_underfill() the live
// build_template() call sites invoke (src/impl/ltc/coin/template_builder.hpp
// build_template ~L271, and src/impl/doge/coin/template_builder.hpp ~L140) --
// both guards now source their per-coin UNDERFILL_MIN_FILL_BYTES /
// UNDERFILL_BACKLOG_SLACK from core::underfill::MIN_FILL_BYTES / BACKLOG_SLACK,
// so this is an SSOT KAT, not a re-implementation (non-hollow).
//
// Pinned constant (integrator, [s=contabo-gate] 2026-07-10): the near-empty
// floor is UNDERFILL_MIN_FILL_BYTES = 50000 -- an operational safety-net
// default, not a consensus byte-parity constant. Ops may retune post-cutover
// with a one-line change and no re-KAT.

using core::underfill::is_underfill;
using core::underfill::MIN_FILL_BYTES;
using core::underfill::BACKLOG_SLACK;

// -- Pinned-value axis -------------------------------------------------------
// Bind the KAT to the shipped default. Both template_builder.hpp guards derive
// their constants from these symbols, so pinning here transitively pins them.
static_assert(MIN_FILL_BYTES == 50'000ull, "underfill near-empty floor pinned at 50 kB");
static_assert(BACKLOG_SLACK  == 50'000ull, "underfill backlog slack pinned at 50 kB");

TEST(UnderfillGuard, PinnedDefaults) {
    EXPECT_EQ(MIN_FILL_BYTES, 50'000ull);
    EXPECT_EQ(BACKLOG_SLACK,  50'000ull);
}

// -- Predicate axis ----------------------------------------------------------

TEST(UnderfillGuard, EmptyMempoolNeverTrips) {
    // Genuinely empty mempool: nothing to pack, zero fees -> never underfill,
    // even though selected_bytes (0) is below the floor.
    EXPECT_FALSE(is_underfill(/*selected=*/0, /*mempool_bytes=*/0, /*fees=*/0));
}

TEST(UnderfillGuard, ZeroFeeBacklogNeverTrips) {
    // A large mempool of strictly zero-fee material is not fee-paying backlog;
    // leaving it unselected is legitimate, so no underfill surface.
    EXPECT_FALSE(is_underfill(/*selected=*/0, /*mempool_bytes=*/1'000'000, /*fees=*/0));
}

TEST(UnderfillGuard, HealthyFullBlockNeverTrips) {
    // Hundreds of kB selected, well above the floor -> not near-empty even with
    // a deep fee-paying backlog behind it.
    EXPECT_FALSE(is_underfill(/*selected=*/300'000, /*mempool_bytes=*/2'000'000, /*fees=*/5'000));
}

TEST(UnderfillGuard, NearEmptyWithFeePayingBacklogTrips) {
    // The regression this guard exists for: a handful of bytes selected while a
    // fee-paying backlog beyond selected + slack sits in the mempool.
    EXPECT_TRUE(is_underfill(/*selected=*/1'200, /*mempool_bytes=*/900'000, /*fees=*/4'200));
}

// -- Boundary axis (tie the pass/fail edges to the named constants) ----------

TEST(UnderfillGuard, NearEmptyBoundaryIsStrictLessThan) {
    // selected == MIN_FILL_BYTES is NOT near-empty (strict <); one byte under is.
    const std::uint64_t mempool = MIN_FILL_BYTES + BACKLOG_SLACK + 1'000;
    EXPECT_FALSE(is_underfill(MIN_FILL_BYTES,     mempool, /*fees=*/1));
    EXPECT_TRUE (is_underfill(MIN_FILL_BYTES - 1, mempool, /*fees=*/1));
}

TEST(UnderfillGuard, BacklogBoundaryIsStrictGreaterThan) {
    // has_backlog requires mempool_bytes > selected + BACKLOG_SLACK (strict).
    const std::uint64_t selected = 1'000;  // near-empty
    EXPECT_FALSE(is_underfill(selected, selected + BACKLOG_SLACK,     /*fees=*/1));
    EXPECT_TRUE (is_underfill(selected, selected + BACKLOG_SLACK + 1, /*fees=*/1));
}
