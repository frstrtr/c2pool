// SPDX-License-Identifier: AGPL-3.0-or-later
// dgb::compute_pool_attempts_per_second -- pool attempts/second KAT.
//
// FENCED conformance test (no production code touched). Pins the pure arithmetic
// core of ShareTracker::get_pool_attempts_per_second, lifted into
// pool_attempts_per_second.hpp, against the p2pool-dgb-scrypt oracle data.py
// get_pool_attempts_per_second:
//       assert dist >= 2
//       attempts = get_delta(near, far).work   # or .min_work
//       time = near.timestamp - far.timestamp
//       if time <= 0: time = 1
//       return attempts//time
//
// All expected values are HAND-DERIVED from that oracle expression (not produced
// by calling the helper under test), so the test is non-circular: it
// independently recomputes the oracle result and asserts the helper matches.
//
// MUST appear in BOTH the ctest registration (this dir CMakeLists.txt) AND the
// build.yml --target allowlist, or it becomes a #143-style NOT_BUILT sentinel
// that reds master.

#include <impl/dgb/coin/pool_attempts_per_second.hpp>

#include <gtest/gtest.h>

namespace {

using dgb::PoolAttemptsInputs;
using dgb::compute_pool_attempts_per_second;

// Convenience: a fully-resolved window (both endpoints present).
PoolAttemptsInputs window(int32_t dist, const uint288& attempts,
                          uint32_t near_ts, uint32_t far_ts) {
    return PoolAttemptsInputs{dist, /*near_in_chain=*/true, /*far_resolved=*/true,
                              attempts, near_ts, far_ts};
}

// ---- dist guard (oracle: assert dist >= 2) ------------------------------

TEST(DgbPoolAttempts, DistBelowTwoIsZero) {
    // dist 1 / 0 / negative -> no window -> 0, even with attempts set.
    EXPECT_EQ(compute_pool_attempts_per_second(window(1, uint288(1000), 100, 90)), uint288(0));
    EXPECT_EQ(compute_pool_attempts_per_second(window(0, uint288(1000), 100, 90)), uint288(0));
    EXPECT_EQ(compute_pool_attempts_per_second(window(-5, uint288(1000), 100, 90)), uint288(0));
}

TEST(DgbPoolAttempts, DistExactlyTwoIsAllowed) {
    // dist == 2 is the minimum valid window; 1000 attempts over 10s -> 100.
    EXPECT_EQ(compute_pool_attempts_per_second(window(2, uint288(1000), 100, 90)), uint288(100));
}

// ---- endpoint-resolution guards -----------------------------------------

TEST(DgbPoolAttempts, NearNotInChainIsZero) {
    PoolAttemptsInputs in{2, /*near_in_chain=*/false, /*far_resolved=*/true,
                          uint288(1000), 100, 90};
    EXPECT_EQ(compute_pool_attempts_per_second(in), uint288(0));
}

TEST(DgbPoolAttempts, FarUnresolvedIsZero) {
    PoolAttemptsInputs in{2, /*near_in_chain=*/true, /*far_resolved=*/false,
                          uint288(1000), 100, 90};
    EXPECT_EQ(compute_pool_attempts_per_second(in), uint288(0));
}

// ---- core divide: attempts / span ---------------------------------------

TEST(DgbPoolAttempts, AttemptsOverSpan) {
    // 6000 work over (200-150)=50s -> 120 (hand-derived).
    EXPECT_EQ(compute_pool_attempts_per_second(window(5, uint288(6000), 200, 150)), uint288(120));
}

TEST(DgbPoolAttempts, IntegerTruncation) {
    // Oracle uses integer division: 1000 // 7 = 142 (142.857... truncated).
    EXPECT_EQ(compute_pool_attempts_per_second(window(3, uint288(1000), 107, 100)), uint288(142));
}

// ---- time-span clamp (oracle: if time <= 0: time = 1) -------------------

TEST(DgbPoolAttempts, ZeroSpanClampsToOne) {
    // near_ts == far_ts -> span 0 -> clamp to 1 -> attempts/1 = attempts.
    EXPECT_EQ(compute_pool_attempts_per_second(window(2, uint288(777), 500, 500)), uint288(777));
}

TEST(DgbPoolAttempts, NegativeSpanClampsToOne) {
    // far newer than near (span -10) -> clamp to 1 -> attempts unchanged.
    EXPECT_EQ(compute_pool_attempts_per_second(window(2, uint288(555), 90, 100)), uint288(555));
}

// ---- attempts is used verbatim (work vs min_work both flow through) -----

TEST(DgbPoolAttempts, AttemptsValuePassedThroughRegardlessOfSource) {
    // The function is agnostic to whether attempts came from delta.work or
    // delta.min_work -- the caller selects; pin that the chosen value divides.
    EXPECT_EQ(compute_pool_attempts_per_second(window(4, uint288(2000), 220, 200)), uint288(100)); // work-like
    EXPECT_EQ(compute_pool_attempts_per_second(window(4, uint288(400),  220, 200)), uint288(20));  // min_work-like
}

// ---- wide numerator: no overflow truncation at 64 bits ------------------

TEST(DgbPoolAttempts, WideAttemptsNoOverflow) {
    // attempts = 2^200, span 2 -> 2^199. Far beyond uint64; uint288 holds it.
    uint288 big = uint288(1); big <<= 200;
    uint288 half = uint288(1); half <<= 199;
    EXPECT_EQ(compute_pool_attempts_per_second(window(2, big, 12, 10)), half);
}

}  // namespace