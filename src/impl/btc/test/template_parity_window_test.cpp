// SPDX-License-Identifier: AGPL-3.0-or-later
// §4.7 B6.2/B6.3 rolling-parity gate — oracle-INDEPENDENT slice.
//
// This is the follow-on to the static-oracle subset (merged PR #1530,
// template_parity_test.cpp: B6.1 + static half of B6.4). It exercises the
// rolling-1000 window bookkeeping (RollingParityWindow) and the per-height
// comparator, seeded with captured / independently-derived oracle values so
// it runs WITHOUT the bitcoind snapshot rig. The live RPC-fed driver
// (B6.2 header-tip parity, B6.3 gettxoutsetinfo, "green for 24h" exit)
// reuses this same window predicate; here we prove the predicate itself.
//
// Folded into the allowlisted btc_share_test target (no new add_executable)
// so it executes as a registered ctest, per the same anti-fake-green rule
// used by template_parity_test.cpp.

#include <impl/btc/coin/template_parity_window.hpp>
#include <impl/btc/coin/template_builder.hpp>

#include <gtest/gtest.h>

#include <cstdint>

using btc::coin::RollingParityWindow;
using btc::coin::get_block_subsidy;

namespace {

// Independent reimplementation of Bitcoin Core GetBlockSubsidy() used as the
// oracle. This is deliberately NOT c2pool's get_block_subsidy — the point of
// a parity gate is to compare two independent implementations of the same
// consensus rule. (validation.cpp GetBlockSubsidy: halve every interval,
// zero after 64 halvings.)
uint64_t oracle_subsidy(uint32_t height, uint32_t interval = 210'000u) {
    const uint64_t initial = 50ULL * 100'000'000ULL;
    unsigned halvings = height / interval;
    if (halvings >= 64) return 0;
    return initial >> halvings;
}

}  // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Window bookkeeping: green only when a full window of contiguous matches.
// ─────────────────────────────────────────────────────────────────────────────
TEST(BtcRollingParityWindow, GreenOnlyWhenFull)
{
    RollingParityWindow w(1000);
    EXPECT_EQ(w.capacity(), 1000u);
    for (uint32_t h = 0; h < 999; ++h) w.record(h, true);
    EXPECT_EQ(w.size(), 999u);
    EXPECT_FALSE(w.is_green()) << "999 of 1000 must not be green";
    w.record(999, true);
    EXPECT_EQ(w.size(), 1000u);
    EXPECT_TRUE(w.is_green()) << "full window of contiguous matches is green";
}

// A single mismatch holds the gate RED until it rolls out the back and the
// window re-fills with clean samples.
TEST(BtcRollingParityWindow, MismatchHoldsRedUntilEvicted)
{
    RollingParityWindow w(4);
    w.record(100, true);
    w.record(101, true);
    w.record(102, false);   // divergence at 102
    w.record(103, true);
    EXPECT_EQ(w.size(), 4u);
    EXPECT_FALSE(w.is_green());
    ASSERT_TRUE(w.last_mismatch_height().has_value());
    EXPECT_EQ(*w.last_mismatch_height(), 102u);
    EXPECT_EQ(w.mismatches(), 1u);

    // Push clean samples; the mismatch at 102 evicts once four newer samples
    // are in. 104,105,106,107 -> window is {104,105,106,107}, all clean.
    w.record(104, true);
    EXPECT_FALSE(w.is_green()) << "102 still in window";
    w.record(105, true);
    w.record(106, true);
    EXPECT_EQ(w.mismatches(), 0u) << "102 evicted";
    w.record(107, true);
    EXPECT_TRUE(w.is_green()) << "window re-filled clean after divergence rolled out";
}

// A non-contiguous height breaks the soak: the window resets.
TEST(BtcRollingParityWindow, GapResetsSoak)
{
    RollingParityWindow w(3);
    w.record(200, true);
    w.record(201, true);
    w.record(202, true);
    EXPECT_TRUE(w.is_green());
    w.record(210, true);          // gap: 203..209 skipped
    EXPECT_EQ(w.size(), 1u) << "gap resets the window";
    EXPECT_FALSE(w.is_green());
}

// ─────────────────────────────────────────────────────────────────────────────
// Comparator over a contiguous fixture range spanning a halving boundary:
// c2pool get_block_subsidy() vs the independent oracle, fed into the window.
// ─────────────────────────────────────────────────────────────────────────────
TEST(BtcRollingParityWindow, SubsidyParityAcrossHalvingBoundary)
{
    // 1000 contiguous heights straddling the epoch-1 halving (210,000).
    const uint32_t start = 209'500;
    RollingParityWindow w(1000);
    for (uint32_t h = start; h < start + 1000; ++h) {
        const bool matched = (get_block_subsidy(h) == oracle_subsidy(h));
        w.record(h, matched);
    }
    EXPECT_EQ(w.size(), 1000u);
    EXPECT_EQ(w.mismatches(), 0u) << "c2pool subsidy diverged from oracle";
    EXPECT_TRUE(w.is_green())
        << "1000-block subsidy parity across the 210,000 halving boundary";
}
