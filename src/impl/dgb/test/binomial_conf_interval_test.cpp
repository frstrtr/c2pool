// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// dgb_binomial_conf_interval_test -- FENCED, additive KAT pinning the pure
// arithmetic core of the p2pool util/math.py binomial_conf_interval (Wilson
// score interval) lifted into coin/binomial_conf_interval.hpp. The expected
// interval endpoints are NON-CIRCULAR golden values captured by running the
// actual Python oracle (util/math.py:133, with its A&S-7.1.26 erf + 10-step
// Newton ierf) on frstrtr/p2pool-dgb-scrypt -- they are NOT recomputed from
// the C++ port. Diagnostics-only display math; no consensus surface.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>
#include "../coin/binomial_conf_interval.hpp"

using dgb::coin::binomial_conf_interval;
using dgb::coin::ierf;

// Tight tolerance: a faithful double-precision port of the same operations in
// the same order should match the oracle to well under 1e-9.
static constexpr double kEps = 1e-9;

// z = sqrt(2)*ierf(0.95) must reproduce the canonical 1.95996 two-sided 95%
// normal quantile -- a non-circular cross-check the ierf/erf port is correct.
TEST(BinomialConfInterval, IerfZScore95MatchesNormalQuantile)
{
    const double z = std::sqrt(2.0) * ierf(0.95);
    EXPECT_NEAR(z, 1.9599628032746732, kEps);
}

TEST(BinomialConfInterval, IerfZScore6826MatchesOneSigma)
{
    const double z = std::sqrt(2.0) * ierf(0.6826);
    EXPECT_NEAR(z, 0.9998151342295566, kEps);
}

// --- Golden interval endpoints straight from the Python oracle --------------
TEST(BinomialConfInterval, Oracle_5_of_100_95)
{
    auto r = binomial_conf_interval(5.0, 100.0, 0.95);
    EXPECT_NEAR(r[0], 0.021543689574590505, kEps);
    EXPECT_NEAR(r[1], 0.111750420163752220, kEps);
}

// Zero successes: lower endpoint clips to exactly 0, point estimate p=0 is
// inside the (add_to_range-extended) interval.
TEST(BinomialConfInterval, Oracle_0_of_100_95_ClipsLowerToZero)
{
    auto r = binomial_conf_interval(0.0, 100.0, 0.95);
    EXPECT_DOUBLE_EQ(r[0], 0.0);
    EXPECT_NEAR(r[1], 0.036993455264825250, kEps);
}

// Symmetric case p=0.5: interval centred on 0.5.
TEST(BinomialConfInterval, Oracle_50_of_100_95_Symmetric)
{
    auto r = binomial_conf_interval(50.0, 100.0, 0.95);
    EXPECT_NEAR(r[0], 0.403831586182331560, kEps);
    EXPECT_NEAR(r[1], 0.596168413817668400, kEps);
    // Symmetry about 0.5 is the structural invariant of p=0.5.
    EXPECT_NEAR((r[0] + r[1]) / 2.0, 0.5, kEps);
}

// Different confidence level (0.6826 ~ 1 sigma) exercises a distinct ierf root.
TEST(BinomialConfInterval, Oracle_10_of_50_6826)
{
    auto r = binomial_conf_interval(10.0, 50.0, 0.6826);
    EXPECT_NEAR(r[0], 0.149571297975416520, kEps);
    EXPECT_NEAR(r[1], 0.262189143777230850, kEps);
}

// Small-rate, large-n tail.
TEST(BinomialConfInterval, Oracle_3_of_1000_95)
{
    auto r = binomial_conf_interval(3.0, 1000.0, 0.95);
    EXPECT_NEAR(r[0], 0.001020784487127052, kEps);
    EXPECT_NEAR(r[1], 0.008783008879983123, kEps);
}

// --- Structural invariants (non-golden, hold for every valid input) ---------
TEST(BinomialConfInterval, BracketsPointEstimateAndStaysInUnit)
{
    for (double x : {0.0, 1.0, 7.0, 33.0, 99.0}) {
        const double n = 100.0;
        auto r = binomial_conf_interval(x, n, 0.95);
        const double p = x / n;
        EXPECT_GE(p + kEps, r[0]) << "left must not exceed point estimate, x=" << x;
        EXPECT_LE(p - kEps, r[1]) << "right must not be below point estimate, x=" << x;
        EXPECT_GE(r[0], 0.0);
        EXPECT_LE(r[1], 1.0);
        EXPECT_LE(r[0], r[1]);
    }
}