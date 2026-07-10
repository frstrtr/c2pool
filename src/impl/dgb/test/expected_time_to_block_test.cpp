// SPDX-License-Identifier: AGPL-3.0-or-later
// dgb::compute_expected_time_to_block — expected-time-to-block KAT.
//
// FENCED conformance test (no production code touched). Pins the
// EXPECTED-TIME-TO-BLOCK diagnostic arithmetic lifted into
// expected_time_to_block.hpp against the p2pool-dgb-scrypt oracle main.py status
// loop:
//     'Expected time to block: %s' % format_dt(
//         2**256 / current_work.value['bits'].target / real_att_s)
//   == average_attempts(target) / real_att_s, with the uint64-overflow sentinel.
//
// The expected values here are HAND-DERIVED from the oracle formula (not produced
// by calling the helper under test), so the test is non-circular: it
// independently recomputes the oracle expression and asserts the helper matches.
//
// MUST appear in BOTH the ctest registration (this dir CMakeLists.txt) AND the
// build.yml --target allowlist, or it becomes a #143-style NOT_BUILT sentinel
// that reds master.

#include <impl/dgb/expected_time_to_block.hpp>

#include <gtest/gtest.h>

namespace {

// ---- core division ------------------------------------------------------

TEST(DgbExpectedTimeToBlock, EtbIsAverageAttemptsOverRealHashrate) {
    // Oracle: average_attempts / real_pool_hs. Recompute independently.
    const double avg = 1.0e12;
    const double real_hs = 1.0e6;
    const double oracle = avg / real_hs; // 1e6 seconds (hand-derived)
    EXPECT_DOUBLE_EQ(
        dgb::compute_expected_time_to_block(avg, real_hs, false, true), oracle);
    EXPECT_DOUBLE_EQ(
        dgb::compute_expected_time_to_block(avg, real_hs, false, true), 1.0e6);
}

TEST(DgbExpectedTimeToBlock, FasterPoolHasLowerEtb) {
    const double avg = 1.0e12;
    // 10x the hashrate -> 1/10th the expected time.
    EXPECT_DOUBLE_EQ(
        dgb::compute_expected_time_to_block(avg, 1.0e7, false, true), 1.0e5);
}

// ---- no-measured-hashrate guard ----------------------------------------

TEST(DgbExpectedTimeToBlock, NoHashrateIsZeroNotDivByZero) {
    // real_pool_hs <= 0 -> nothing to divide by -> 0.0, never inf/NaN.
    EXPECT_DOUBLE_EQ(
        dgb::compute_expected_time_to_block(1.0e12, 0.0, false, true), 0.0);
    EXPECT_DOUBLE_EQ(
        dgb::compute_expected_time_to_block(1.0e12, -5.0, false, true), 0.0);
}

// ---- overflow sentinel --------------------------------------------------

TEST(DgbExpectedTimeToBlock, OverflowWithNonNullTargetReportsSentinel) {
    // average-attempts count does not fit in uint64 AND target is non-null:
    // the low64 division is meaningless -> 1e18 sentinel.
    EXPECT_DOUBLE_EQ(
        dgb::compute_expected_time_to_block(123.0, 1.0e6, true, true), 1.0e18);
}

TEST(DgbExpectedTimeToBlock, OverflowWithNullTargetDoesNotTriggerSentinel) {
    // block_target_nonzero == false -> sentinel suppressed, plain division stands.
    const double avg = 2.0e9;
    const double real_hs = 1.0e3;
    EXPECT_DOUBLE_EQ(
        dgb::compute_expected_time_to_block(avg, real_hs, true, false),
        avg / real_hs); // 2e6, hand-derived
}

TEST(DgbExpectedTimeToBlock, NoOverflowIgnoresSentinelRegardlessOfTarget) {
    // average_attempts_overflowed == false -> sentinel never applies.
    const double avg = 4.0e9;
    const double real_hs = 2.0e3;
    EXPECT_DOUBLE_EQ(
        dgb::compute_expected_time_to_block(avg, real_hs, false, true),
        avg / real_hs); // 2e6
}

// ---- end-to-end chain mirroring node.cpp diagnostics --------------------

TEST(DgbExpectedTimeToBlock, ChainRealHashrateThenEtbMatchesOracle) {
    // node.cpp path: raw aps -> real_pool_hs (1 - stale_prop scaling) -> etb.
    const double pool_hs = 1.0e6;
    const double stale_prop = 0.05;
    const double real_hs = pool_hs / (1.0 - stale_prop); // pool_efficiency oracle
    const double avg = 1.0e12;
    const double oracle = avg / real_hs;                 // etb oracle
    EXPECT_DOUBLE_EQ(
        dgb::compute_expected_time_to_block(avg, real_hs, false, true), oracle);
}

} // namespace