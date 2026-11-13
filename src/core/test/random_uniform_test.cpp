// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// core::random::random_float / random_double are continuous uniform draws on
// [min, max) (p2pool: random.uniform), and the node-fee draw honours its fee
// exactly (rides core_test).
//
// random_float used to be a std::uniform_int_distribution over [min, max]
// divided back down: random_float(0, 100) returned only the 101 integers
// 0..100 and random_float(0, 1) only 0 or 1. The node-fee draw
// `roll < fee` then took the fee with probability ceil(fee)/101 (100% ->
// 100/101, 0.5% -> 0.99%, 1.5% -> 1.98%) and every peer-selection
// `random_float(0, 1) < 0.8` held 50% of the time.
//
// Every statistical case reseeds the generator with a fixed seed, so a run is
// reproducible on a given standard library; the tolerances are many standard
// deviations wide so no standard library's stream can fail them by chance,
// yet they reject the old integer draw (fee 1% is the one case the old draw
// came close to, 0.99%; the half-open/non-integer cases pin that one).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <utility>
#include <vector>

#include <core/random.hpp>
#include <core/web_server.hpp>

namespace {

constexpr uint32_t kSeed = 0x5eed1234u;

std::vector<unsigned char> p2pkh(unsigned char b)
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, b);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

// Fraction of `n` decide_job_payout calls that pay the operator at `fee`%.
double fee_hit_rate(double fee, int n)
{
    core::MiningInterface mi{/*testnet=*/true};
    const auto op = p2pkh(0x0e);
    const auto miner = p2pkh(0x0a);
    mi.set_node_fee(fee, op);
    int hits = 0;
    for (int i = 0; i < n; ++i) {
        auto payout = miner;
        std::vector<std::pair<uint32_t, std::vector<unsigned char>>> merged;
        mi.decide_job_payout(payout, merged);
        if (payout == op)
            ++hits;
        else
            EXPECT_EQ(payout, miner) << "a missed draw keeps the miner's payout";
    }
    return double(hits) / n;
}

} // namespace

TEST(RandomUniform, RandomFloatIsHalfOpenAndContinuous)
{
    core::random::seed(kSeed);
    constexpr int N = 1'000'000;
    int non_integer = 0;
    double sum = 0;
    for (int i = 0; i < N; ++i) {
        const float r = core::random::random_float(0.0f, 100.0f);
        ASSERT_GE(r, 0.0f);
        ASSERT_LT(r, 100.0f) << "max is never returned";
        if (r != std::floor(r))
            ++non_integer;
        sum += r;
    }
    EXPECT_GT(non_integer, N * 99 / 100) << "not the 101 integers 0..100";
    EXPECT_NEAR(sum / N, 50.0, 0.5);
}

TEST(RandomUniform, RandomFloatZeroOneBelowPoint8IsEightyPercent)
{
    core::random::seed(kSeed);
    constexpr int N = 1'000'000;
    int below = 0;
    for (int i = 0; i < N; ++i) {
        const float r = core::random::random_float(0, 1);
        ASSERT_GE(r, 0.0f);
        ASSERT_LT(r, 1.0f);
        if (r < 0.8)
            ++below;
    }
    // sd = sqrt(0.8*0.2/N) = 0.0004; 0.01 = 25 sd. The old draw gave 0.5.
    EXPECT_NEAR(double(below) / N, 0.8, 0.01);
}

TEST(RandomUniform, RandomDoubleIsHalfOpen)
{
    core::random::seed(kSeed);
    constexpr int N = 200'000;
    double lo = 100, hi = -100;
    for (int i = 0; i < N; ++i) {
        const double r = core::random::random_double(-3.0, 7.0);
        ASSERT_GE(r, -3.0);
        ASSERT_LT(r, 7.0);
        lo = std::min(lo, r);
        hi = std::max(hi, r);
    }
    EXPECT_LT(lo, -2.99);
    EXPECT_GT(hi, 6.99);
}

TEST(RandomUniform, OneUlpRangeNeverReturnsMax)
{
    // The only value in [1, nextafter(1)) is 1: the rounding edge of
    // uniform_real_distribution and of the double -> float narrowing.
    core::random::seed(kSeed);
    const float fmax = std::nextafter(1.0f, 2.0f);
    const double dmax = std::nextafter(1.0, 2.0);
    for (int i = 0; i < 100'000; ++i) {
        ASSERT_EQ(core::random::random_float(1.0f, fmax), 1.0f);
        ASSERT_EQ(core::random::random_double(1.0, dmax), 1.0);
    }
}

TEST(RandomUniform, EmptyRangeReturnsMin)
{
    EXPECT_EQ(core::random::random_float(5.0f, 5.0f), 5.0f);
    EXPECT_EQ(core::random::random_double(5.0, 5.0), 5.0);
    EXPECT_EQ(core::random::random_double(5.0, 1.0), 5.0);
}

TEST(NodeFeeDraw, FeeHundredAlwaysTakesFeeZeroNever)
{
    core::random::seed(kSeed);
    EXPECT_EQ(fee_hit_rate(100.0, 100'000), 1.0) << "the old draw took 100/101";
    EXPECT_EQ(fee_hit_rate(0.0, 100'000), 0.0);
}

TEST(NodeFeeDraw, FractionalFeesAreHonoured)
{
    core::random::seed(kSeed);
    constexpr int N = 400'000;
    // sd at 0.5% = sqrt(.005*.995/N) = 0.011%; at 1.5% = 0.019%. Tolerances
    // are about 8 sd or wider (1.5%: 7.8 sd). The old draw gave 0.99% for
    // 0.5% and 1% and 1.98% for 1.5%: the 0.5% and 1.5% cases reject it; the
    // 1% (old 0.990%) and 50% (old 49.5%) cases only pin the new rate.
    EXPECT_NEAR(fee_hit_rate(0.5, N), 0.005, 0.001);
    EXPECT_NEAR(fee_hit_rate(1.0, N), 0.010, 0.0015);
    EXPECT_NEAR(fee_hit_rate(1.5, N), 0.015, 0.0015);
    EXPECT_NEAR(fee_hit_rate(50.0, N), 0.50, 0.01);
}
