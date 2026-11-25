// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// core/pool_luck.hpp: luck as effort, on hand-computed fixtures.
//
// effort = integral of H_gross(t) / (D(t) * 2^32) dt over a round; luck is
// 100 / effort; a period's luck is blocks found over blocks expected with the
// exact Poisson interval. The fixtures below are small enough to check by
// hand; the interval bounds are scipy's (chi2.ppf, scipy 1.18.1).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cmath>
#include <cstdint>
#include <limits>
#include <vector>

#include <core/pool_luck.hpp>

namespace luck = core::luck;

namespace {

constexpr double kT32 = 4294967296.0;

// The round [1000, 5000] with a piecewise-constant rate and difficulty:
//
//   [1000, 2000]  H = 0.25 * 2^32   D = 1000   ->  1000 s * 0.25 / 1000 = 0.250
//   [2000, 3500]  H = 0.50 * 2^32   D = 1000   ->  1500 s * 0.50 / 1000 = 0.750
//   [3500, 5000]  H = 0.50 * 2^32   D = 2000   ->  1500 s * 0.50 / 2000 = 0.375
//                                                           effort     = 1.375
luck::RateHistory fixture_history()
{
    luck::RateHistory h;
    h.add_segment({1000.0, 2000.0, 0.25 * kT32, 1000.0, 1.0});
    h.add_segment({2000.0, 3500.0, 0.50 * kT32, 1000.0, 1.0});
    h.add_segment({3500.0, 5000.0, 0.50 * kT32, 2000.0, 1.0});
    return h;
}

luck::RoundInput row(double ts, uint64_t height, bool main_chain = true,
                     double difficulty = 2000.0, double rate = 0.5 * kT32)
{
    luck::RoundInput r;
    r.ts = ts;
    r.height = height;
    r.main_chain = main_chain;
    r.difficulty = difficulty;
    r.rate_at_find = rate;
    return r;
}

} // namespace

// The integral over the whole round, against the fixture's own arithmetic. A
// single sample at find time (H = 0.5 * 2^32, D = 2000) would say effort 1.0.
TEST(PoolLuck, IntegratedEffortMatchesTheHandComputedFixture)
{
    const auto h = fixture_history();
    const std::vector<luck::RoundInput> rows = {row(1000.0, 10), row(5000.0, 11)};
    const auto res = luck::compute_rounds(rows, h);

    EXPECT_EQ(res[0].method, luck::EffortMethod::first_block);
    const auto& r = res[1];
    EXPECT_EQ(r.method, luck::EffortMethod::integrated);
    EXPECT_EQ(r.prev, 0);
    EXPECT_DOUBLE_EQ(r.time_to_find, 4000.0);
    EXPECT_NEAR(r.effort, 1.375, 1e-12);
    EXPECT_NEAR(r.luck, 100.0 / 1.375, 1e-9);
    EXPECT_NEAR(r.expected_time, 4000.0 / 1.375, 1e-9);
    EXPECT_NEAR(r.coverage, 1.0, 1e-12);
    // (1000 * 0.25 + 3000 * 0.5) / 4000 = 0.4375
    EXPECT_NEAR(r.rate_used, 0.4375 * kT32, 1.0);
    // (2500 * 1000 + 1500 * 2000) / 4000 = 1375
    EXPECT_NEAR(r.difficulty_used, 1375.0, 1e-9);
    EXPECT_EQ(r.samples, 3u);
}

// A round the history covers in part: the covered part's mean intensity
// stands for the rest, and history_coverage says how much was measured.
TEST(PoolLuck, PartlyCoveredRoundIsScaledByItsCoveredShare)
{
    luck::RateHistory h;
    h.add_segment({2000.0, 3500.0, 0.50 * kT32, 1000.0, 1.0});   // 0.75 over 1500 s
    const std::vector<luck::RoundInput> rows = {row(1000.0, 10), row(5000.0, 11)};
    const auto r = luck::compute_rounds(rows, h)[1];
    EXPECT_EQ(r.method, luck::EffortMethod::integrated);
    EXPECT_NEAR(r.effort, 0.75 / 1500.0 * 4000.0, 1e-12);   // 2.0
    EXPECT_NEAR(r.coverage, 1500.0 / 4000.0, 1e-12);
}

// No history over the round: the one sample taken at find time.
TEST(PoolLuck, RoundWithoutHistoryUsesTheSampleAtFind)
{
    const luck::RateHistory empty;
    const std::vector<luck::RoundInput> rows = {row(1000.0, 10), row(5000.0, 11)};
    const auto r = luck::compute_rounds(rows, empty)[1];
    EXPECT_EQ(r.method, luck::EffortMethod::single_sample);
    EXPECT_NEAR(r.effort, 4000.0 * 0.5 / 2000.0, 1e-12);   // 1.0
    EXPECT_DOUBLE_EQ(r.coverage, 0.0);
    EXPECT_EQ(r.samples, 1u);

    // History elsewhere in time does not cover this round either.
    luck::RateHistory later;
    later.add_segment({9000.0, 9500.0, 5.0 * kT32, 1000.0, 1.0});
    EXPECT_EQ(luck::compute_rounds(rows, later)[1].method, luck::EffortMethod::single_sample);
}

// An input that cannot be had leaves no effort and names what is missing.
TEST(PoolLuck, MissingInputsLeaveNoEffort)
{
    const luck::RateHistory empty;
    std::vector<luck::RoundInput> rows = {row(1000.0, 10), row(5000.0, 11, true, 2000.0, 0.0)};
    auto r = luck::compute_rounds(rows, empty)[1];
    EXPECT_EQ(r.method, luck::EffortMethod::none);
    EXPECT_EQ(r.missing, luck::MissingInput::rate);
    EXPECT_DOUBLE_EQ(r.effort, 0.0);
    EXPECT_DOUBLE_EQ(r.luck, 0.0);
    EXPECT_EQ(r.prev, 0) << "the round is known even when its effort is not";
    EXPECT_DOUBLE_EQ(r.time_to_find, 4000.0);

    rows[1] = row(5000.0, 11, true, 0.0, 0.5 * kT32);
    r = luck::compute_rounds(rows, empty)[1];
    EXPECT_EQ(r.method, luck::EffortMethod::none);
    EXPECT_EQ(r.missing, luck::MissingInput::difficulty);

    // The history's own difficulty stands in for a block that has none.
    r = luck::compute_rounds(rows, fixture_history())[1];
    EXPECT_EQ(r.method, luck::EffortMethod::integrated);
    EXPECT_NEAR(r.effort, 1.375, 1e-12);
}

// DASH, 2026-10-25: block 2561418 was timed from orphan 2561316 (15,515 s);
// its round ran from the last MAIN-CHAIN block, 2561265 (23,835 s). Rows are
// handed over newest-first by height, as the ledger keeps them.
TEST(PoolLuck, PredecessorIsThePreviousMainChainBlockByTime)
{
    const double t0 = 1792945704.0;   // 2561265
    const std::vector<luck::RoundInput> rows = {
        row(t0 + 23835.0, 2561418),
        row(t0 + 8320.0, 2561316, /*main_chain=*/false),
        row(t0, 2561265),
    };
    const luck::RateHistory empty;
    const auto res = luck::compute_rounds(rows, empty);
    EXPECT_EQ(res[0].prev, 2) << "an orphan is never a predecessor";
    EXPECT_DOUBLE_EQ(res[0].time_to_find, 23835.0);
    // The orphan itself is timed from the main-chain block before it.
    EXPECT_EQ(res[1].prev, 2);
    EXPECT_DOUBLE_EQ(res[1].time_to_find, 8320.0);
    EXPECT_EQ(res[2].method, luck::EffortMethod::first_block);
}

// Time decides, not height: an LTC row stored at the share ABSHEIGHT
// (27,588,573) sorts above every real height, yet it is the predecessor of
// the block found after it.
TEST(PoolLuck, RowAtABogusHeightKeepsItsPlaceInTime)
{
    const std::vector<luck::RoundInput> rows = {
        row(1000.0, 27588573),
        row(3000.0, 3204796),
        row(500.0, 3160570),
    };
    const luck::RateHistory empty;
    const auto res = luck::compute_rounds(rows, empty);
    EXPECT_EQ(res[1].prev, 0);
    EXPECT_DOUBLE_EQ(res[1].time_to_find, 2000.0);
    EXPECT_EQ(res[0].prev, 2);
    EXPECT_DOUBLE_EQ(res[0].time_to_find, 500.0);
}

// Operator ruling: the first block is effort 1.0 / luck 100 %.
TEST(PoolLuck, FirstBlockIsOneFoundForOneExpected)
{
    const std::vector<luck::RoundInput> rows = {row(5000.0, 11)};
    const auto h = fixture_history();
    const auto r = luck::compute_rounds(rows, h)[0];
    EXPECT_EQ(r.method, luck::EffortMethod::first_block);
    EXPECT_DOUBLE_EQ(r.effort, 1.0);
    EXPECT_DOUBLE_EQ(r.luck, 100.0);
    EXPECT_EQ(r.prev, -1);
    EXPECT_DOUBLE_EQ(r.time_to_find, 0.0);
    // The expected time to a block at the rate and difficulty sampled at find.
    EXPECT_NEAR(r.expected_time, 2000.0 * kT32 / (0.5 * kT32), 1e-9);

    // An orphan first: the first MAIN-CHAIN block is still the first block,
    // and the orphan before it is neither that nor a round: no effort.
    const std::vector<luck::RoundInput> two = {row(900.0, 9, false), row(5000.0, 11)};
    const auto res = luck::compute_rounds(two, h);
    EXPECT_EQ(res[1].method, luck::EffortMethod::first_block);
    EXPECT_EQ(res[0].method, luck::EffortMethod::none);
    EXPECT_EQ(res[0].missing, luck::MissingInput::nothing);
    EXPECT_DOUBLE_EQ(res[0].luck, 0.0);
}

// A merged chain: the pool rate is the parent's, the difficulty is the aux
// block's OWN. The history's difficulty (the parent's, 1000 / 2000 here)
// must not enter: with the aux difficulty 500 the fixture is
//   (1000 * 0.25 + 3000 * 0.5) / 500 = 3.5.
TEST(PoolLuck, MergedChainRunsAgainstItsOwnDifficulty)
{
    const auto h = fixture_history();
    luck::RoundOptions aux;
    aux.history_difficulty = false;
    std::vector<luck::RoundInput> rows = {row(1000.0, 10, true, 500.0),
                                          row(5000.0, 11, true, 500.0)};
    auto r = luck::compute_rounds(rows, h, aux)[1];
    EXPECT_EQ(r.method, luck::EffortMethod::integrated);
    EXPECT_NEAR(r.effort, 3.5, 1e-12);
    EXPECT_NEAR(r.difficulty_used, 500.0, 1e-9);

    // No aux difficulty known: no effort -- never the parent's difficulty.
    rows[1].difficulty = 0.0;
    r = luck::compute_rounds(rows, h, aux)[1];
    EXPECT_EQ(r.method, luck::EffortMethod::none);
    EXPECT_EQ(r.missing, luck::MissingInput::difficulty);
}

// The stat-log samples as the history sees them: a sample speaks for the
// time back to the previous one, at most an hour; the rate is grossed up by
// the stale proportion sampled with it.
TEST(PoolLuck, SamplesBecomeSegmentsOfTheGrossRate)
{
    luck::RateHistory h;
    h.add_sample(10000.0, 0.9 * kT32, 0.1, 1000.0);    // gross 1.0 * 2^32
    h.add_sample(10060.0, 0.0, 0.1, 1000.0);           // the estimator had nothing
    h.add_sample(10120.0, 1.8 * kT32, 0.1, 1000.0);    // gross 2.0 * 2^32
    ASSERT_EQ(h.size(), 2u);
    EXPECT_DOUBLE_EQ(h.segments()[0].t0, 10000.0 - luck::RateHistory::kMaxSampleSpan);
    EXPECT_DOUBLE_EQ(h.segments()[0].t1, 10000.0);
    EXPECT_NEAR(h.segments()[0].rate, kT32, 1.0);
    // The silent sample leaves no hole: the next one reaches back over it.
    EXPECT_DOUBLE_EQ(h.segments()[1].t0, 10000.0);
    EXPECT_DOUBLE_EQ(h.segments()[1].t1, 10120.0);
    EXPECT_NEAR(h.segments()[1].rate, 2.0 * kT32, 1.0);
    EXPECT_DOUBLE_EQ(h.last_stale_prop(), 0.1);

    // 120 s at 2.0 * 2^32 against D = 1000: 0.24 blocks expected.
    const auto in = h.integrate(10000.0, 10120.0, 0.0, 0.0);
    EXPECT_NEAR(in.effort, 0.24, 1e-12);
    EXPECT_NEAR(in.covered, 120.0, 1e-9);

    // A sample after a long gap covers one hour back, no more.
    h.add_sample(30000.0, 0.9 * kT32, 0.1, 1000.0);
    EXPECT_DOUBLE_EQ(h.segments()[2].t0, 30000.0 - 3600.0);
    EXPECT_DOUBLE_EQ(h.at(20000.0).rate, 0.0);
    EXPECT_NEAR(h.at(29000.0).rate, kT32, 1.0);
    EXPECT_FALSE(h.at(29000.0).binned) << "a sample of the moment";
    // The nearest reading in time, for a moment the history does not cover:
    // 20000 is 9880 s after the segment ending at 10120, 6400 s before the
    // one starting at 26400.
    EXPECT_NEAR(h.nearest_rate(20000.0), kT32, 1.0);
    EXPECT_NEAR(h.nearest_rate(12000.0), 2.0 * kT32, 1.0);
    EXPECT_NEAR(h.nearest_rate(1.0), kT32, 1.0);
    EXPECT_NEAR(h.nearest_rate(99999.0), kT32, 1.0);
    // ... if it is near enough to say anything about that moment.
    EXPECT_NEAR(h.nearest_rate(20000.0, 6400.0), kT32, 1.0);
    EXPECT_DOUBLE_EQ(h.nearest_rate(20000.0, 6399.0), 0.0);
    EXPECT_NEAR(h.nearest_rate(29000.0, 0.0), kT32, 1.0) << "covered: no distance at all";
    EXPECT_NEAR(h.at(29000.0).span, 3600.0, 1e-9);
    EXPECT_NEAR(h.at(10100.0).span, 120.0, 1e-9);
    EXPECT_DOUBLE_EQ(luck::RateHistory{}.nearest_rate(5.0), 0.0);

    EXPECT_DOUBLE_EQ(luck::gross_rate(100.0, 0.0), 100.0);
    EXPECT_DOUBLE_EQ(luck::gross_rate(90.0, 0.1), 100.0);
    EXPECT_DOUBLE_EQ(luck::gross_rate(90.0, 1.0), 90.0) << "an all-stale window divides by nothing";
    EXPECT_DOUBLE_EQ(luck::gross_rate(0.0, 0.1), 0.0);
}

// Coarse bins put in front of the fine samples: a bin its samples cover only
// in part weighs in by that part, and whatever overlaps the fine range is cut.
TEST(PoolLuck, OlderBinsAreWeightedAndNeverOverlapTheFineSamples)
{
    luck::RateHistory h;
    h.add_segment({5000.0, 6000.0, 1.0 * kT32, 1000.0, 1.0});
    h.prepend_older({
        {4000.0, 5500.0, 2.0 * kT32, 1000.0, 1.0},     // reaches into the fine range
        {2000.0, 4000.0, 4.0 * kT32, 1000.0, 0.25},    // samples cover a quarter of it
    });
    ASSERT_EQ(h.size(), 3u);
    EXPECT_DOUBLE_EQ(h.segments()[1].t1, 5000.0);
    const auto in = h.integrate(2000.0, 6000.0, 0.0, 0.0);
    // 2000 s * 0.25 covered at 4.0 -> 2.0; 1000 s at 2.0 -> 2.0; 1000 s at 1.0 -> 1.0
    EXPECT_NEAR(in.effort, 5.0, 1e-12);
    EXPECT_NEAR(in.covered, 500.0 + 1000.0 + 1000.0, 1e-9);
}

// Old minute samples are folded into hourly bins so a long-running node
// does not hold 400 days of minute segments. A bin keeps the covered time,
// the mean rate and the difficulty that leaves its effort unchanged: a round
// over whole bins integrates to exactly what the samples gave.
TEST(PoolLuck, CoarseningKeepsTheEffortOfARound)
{
    luck::RateHistory h;
    // Three hours of minute samples, rate and difficulty both moving, with a
    // 20-minute hole in the second hour (no sample covers 4800..6000).
    for (int i = 1; i <= 180; ++i) {
        const double t = 60.0 * i;
        if (t > 4800.0 && t < 6000.0) continue;
        const double rate = (1.0 + 0.5 * std::sin(i * 0.1)) * kT32;
        const double diff = 1000.0 * (1.0 + 0.3 * std::cos(i * 0.07));
        h.add_segment({t - 60.0, t, rate, diff, 1.0});
    }
    const size_t before = h.size();
    const auto hours = h.integrate(0.0, 10800.0, 0.0, 0.0);
    const auto second_hour = h.integrate(3600.0, 7200.0, 0.0, 0.0);
    ASSERT_NEAR(second_hour.covered, 3600.0 - 1200.0 + 60.0, 1e-9);

    // Fold the first two hours (101 minute segments into 2 bins); the third
    // stays at sample resolution.
    const size_t folded = h.coarsen_before(7200.0, 3600.0);
    EXPECT_EQ(folded, 99u);
    EXPECT_EQ(h.size(), before - folded);
    EXPECT_TRUE(h.at(1800.0).binned) << "a mean over the hour, not a reading of the moment";
    EXPECT_TRUE(h.at(4000.0).binned);
    EXPECT_FALSE(h.at(9000.0).binned);
    EXPECT_NEAR(h.fine_start(), 7200.0, 1e-9);

    const auto after = h.integrate(0.0, 10800.0, 0.0, 0.0);
    EXPECT_NEAR(after.effort, hours.effort, hours.effort * 1e-12);
    EXPECT_NEAR(after.covered, hours.covered, 1e-6);
    EXPECT_NEAR(after.hashes, hours.hashes, hours.hashes * 1e-12);
    const auto second_after = h.integrate(3600.0, 7200.0, 0.0, 0.0);
    EXPECT_NEAR(second_after.effort, second_hour.effort, second_hour.effort * 1e-12);
    EXPECT_NEAR(second_after.covered, second_hour.covered, 1e-6)
        << "the hole in the hour is not filled in";

    // Folding again finds nothing left to fold, and nothing moves.
    EXPECT_EQ(h.coarsen_before(7200.0, 3600.0), 0u);
    EXPECT_EQ(h.size(), before - folded);
    // The yardstick readings still work across the seam.
    EXPECT_GT(h.nearest_rate(-50.0), 0.0);
}

// Which reading of the history may vouch for the rate of one moment. A
// minute sample in a run of them that agree does; the first sample after a
// restart does not (it reaches back over the outage, and reads whatever the
// estimator has while its window fills); nor does a one-off the samples
// around it do not repeat; nor a bin.
TEST(PoolLuck, OnlyASteadySampleVouchesForItsMinute)
{
    luck::RateHistory h;
    const double R = kT32, D = 1000.0;
    // Ten steady minutes, [0, 600].
    for (int i = 1; i <= 10; ++i) h.add_sample(60.0 * i, R, 0.0, D);
    // A 240 s outage; the first sample after it reads 0.7 R.
    h.add_sample(840.0, 0.7 * R, 0.0, D);
    // Steady again, but for one minute that reads 150 R.
    for (int i = 1; i <= 10; ++i)
        h.add_sample(840.0 + 60.0 * i, i == 5 ? 150.0 * R : R, 0.0, D);
    // A six-hour outage; the first sample after it reaches one hour back.
    h.add_sample(1440.0 + 6 * 3600.0, 150.0 * R, 0.0, D);

    // at(): the stretch a reading speaks for, and when it was taken.
    EXPECT_NEAR(h.at(330.0).span, 60.0, 1e-9);
    EXPECT_NEAR(h.at(330.0).end, 360.0, 1e-9);
    EXPECT_NEAR(h.at(700.0).span, 240.0, 1e-9);
    EXPECT_NEAR(h.at(700.0).end, 840.0, 1e-9);
    EXPECT_NEAR(h.at(20000.0).span, 3600.0, 1e-9);

    const double span = 300.0, tol = 0.25;
    EXPECT_TRUE(h.steady_at(330.0, span, tol)) << "a minute among minutes that agree";
    EXPECT_FALSE(h.steady_at(30.0, span, tol)) << "the first segment: nothing before it bears it out";
    EXPECT_FALSE(h.steady_at(700.0, span, tol)) << "the restart sample: 0.7 R among R";
    EXPECT_FALSE(h.steady_at(830.0, span, tol)) << "its last minute is still the restart sample";
    EXPECT_FALSE(h.steady_at(870.0, span, tol)) << "the minute after it has it for a neighbour";
    EXPECT_TRUE(h.steady_at(930.0, span, tol));
    EXPECT_FALSE(h.steady_at(1110.0, span, tol)) << "the one-off: 150 R among R";
    EXPECT_FALSE(h.steady_at(1050.0, span, tol)) << "the minute before the one-off";
    EXPECT_FALSE(h.steady_at(1170.0, span, tol)) << "the minute after the one-off";
    EXPECT_TRUE(h.steady_at(1230.0, span, tol));
    EXPECT_FALSE(h.steady_at(1430.0, span, tol))
        << "the last minute before the outage: the sample after it is an hour long";
    EXPECT_FALSE(h.steady_at(20000.0, span, tol)) << "an hour-long reading";
    EXPECT_FALSE(h.steady_at(5000.0, span, tol)) << "not covered";
    // The newest sample has no successor yet: the one before it bears it out.
    {
        luck::RateHistory g;
        for (int i = 1; i <= 3; ++i) g.add_sample(60.0 * i, R, 0.0, D);
        EXPECT_TRUE(g.steady_at(150.0, span, tol));
        g.add_sample(240.0, 2.0 * R, 0.0, D);
        EXPECT_FALSE(g.steady_at(150.0, span, tol)) << "its successor now says otherwise";
    }
    // A bin is a mean, never a sample of a minute.
    {
        luck::RateHistory g;
        for (int i = 1; i <= 240; ++i) g.add_sample(60.0 * i, R, 0.0, D);
        ASSERT_TRUE(g.steady_at(3630.0, span, tol));
        g.coarsen_before(7200.0, 3600.0);
        EXPECT_FALSE(g.steady_at(3630.0, span, tol));
        EXPECT_FALSE(g.steady_at(7230.0, span, tol)) << "the minute after a bin";
        EXPECT_TRUE(g.steady_at(7290.0, span, tol));
    }

    // The yardstick for a recorded rate: the lowest of the nearest reading
    // and its neighbours, so a stray high reading does not make the rates
    // recorded around it look a hundred times too small.
    EXPECT_NEAR(h.yardstick_rate(330.0), R, 1.0);
    EXPECT_NEAR(h.yardstick_rate(1110.0), R, 1.0) << "the one-off minute reads 150 R";
    EXPECT_NEAR(h.nearest_rate(1110.0), 150.0 * R, 150.0);
    EXPECT_NEAR(h.yardstick_rate(20000.0), R, 1.0) << "the hour-long 150 R reading";
    EXPECT_NEAR(h.yardstick_rate(700.0), 0.7 * R, 1.0);
    EXPECT_NEAR(h.yardstick_rate(5000.0, 4000.0), R, 1.0) << "not covered: the nearest, 3560 s back";
    EXPECT_DOUBLE_EQ(h.yardstick_rate(5000.0, 3000.0), 0.0) << "nothing near enough";
    EXPECT_DOUBLE_EQ(luck::RateHistory{}.yardstick_rate(5.0), 0.0);
    // So the rate a block recorded in the stray minute stands, and a node's
    // own 1e-5 of it is still refused.
    EXPECT_TRUE(luck::rate_at_find_plausible(R, 0.0, h.yardstick_rate(1110.0)));
    EXPECT_FALSE(luck::rate_at_find_plausible(R, 0.0, h.nearest_rate(1110.0)));
    EXPECT_FALSE(luck::rate_at_find_plausible(1e-5 * R, 0.0, h.yardstick_rate(1110.0)));
}

// The rate recorded "at find" is used only if it is plausibly a POOL rate.
// The LTC canary holds rows recorded at the node's own ~4 MH/s; the winning
// shares of those very rows (difficulty 500-700) put the pool above
// 100 MH/s: share difficulty * 2^32 / 18000 s.
TEST(PoolLuck, RateAtFindMustBePlausiblyAPoolRate)
{
    using luck::rate_at_find_plausible;
    // The three corrupt rows, by their own share difficulty alone.
    EXPECT_FALSE(rate_at_find_plausible(4030409.5, 693.5440248241151, 0.0));
    EXPECT_FALSE(rate_at_find_plausible(4123391.6, 709.9291624908818, 0.0));
    EXPECT_FALSE(rate_at_find_plausible(3939911.9, 514.3346070441622, 0.0));
    // The same ledger's 14.8 GH/s row, and the rates the pool really had.
    EXPECT_TRUE(rate_at_find_plausible(14818454121.0, 785.1381125177094, 0.0));
    EXPECT_TRUE(rate_at_find_plausible(1.94e11, 693.5440248241151, 0.0));
    // DASH: a share 30x the minimum on a 4.4e13 H/s pool.
    EXPECT_TRUE(rate_at_find_plausible(4.4e13, 240228.0, 0.0));
    // The bound itself: difficulty 18000 puts the floor at exactly 2^32 H/s.
    EXPECT_TRUE(rate_at_find_plausible(kT32, 18000.0, 0.0));
    EXPECT_FALSE(rate_at_find_plausible(kT32 * 0.999, 18000.0, 0.0));

    // No share difficulty on the row: the node's own history is the
    // yardstick. Two orders of magnitude under it is not the pool's rate; a
    // rate that merely moved (DASH at find: 4.4e13 .. 6.06e13) is.
    EXPECT_FALSE(rate_at_find_plausible(4.0e6, 0.0, 1.8e11));
    EXPECT_FALSE(rate_at_find_plausible(1.7e9, 0.0, 1.8e11));
    EXPECT_TRUE(rate_at_find_plausible(1.9e9, 0.0, 1.8e11));
    EXPECT_TRUE(rate_at_find_plausible(4.4e13, 0.0, 6.06e13));
    EXPECT_TRUE(rate_at_find_plausible(6.06e13, 0.0, 4.4e13));

    // Nothing to judge it by: it stands as recorded. No rate: no rate.
    EXPECT_TRUE(rate_at_find_plausible(4.0e6, 0.0, 0.0));
    EXPECT_FALSE(rate_at_find_plausible(0.0, 0.0, 0.0));
    EXPECT_FALSE(rate_at_find_plausible(0.0, 693.5, 1.8e11));
    // ... but under one hash a second there is no pool (1e-300 would be a
    // luck of 1e300 % on a row no yardstick reaches).
    EXPECT_TRUE(rate_at_find_plausible(luck::kMinPoolRate, 0.0, 0.0));
    EXPECT_FALSE(rate_at_find_plausible(0.5, 0.0, 0.0));
    EXPECT_FALSE(rate_at_find_plausible(1e-300, 0.0, 0.0));
}

// What a period counts of one round, row by row: the pair a consumer sums to
// arrive at the server's period luck.
TEST(PoolLuck, PeriodEffortAndCountOfARound)
{
    luck::RateHistory h;
    h.add_segment({3000.0, 5000.0, kT32, 1000.0, 1.0});   // watching [3000, 5000]
    const std::vector<luck::RoundInput> rows = {
        row(1000.0, 1, true, 1000.0, 0.0),     // first block
        row(5000.0, 2, true, 1000.0, 0.0),     // history covers half its round
        row(9000.0, 3, true, 1000.0, kT32),    // found in the dark, 4000 s after the history ends
        row(9500.0, 4, false, 1000.0, kT32),   // orphan
        row(12000.0, 5, true, 1000.0, kT32),   // no history at all: single sample
        row(13000.0, 6, true, 1000.0, 0.0),    // nothing to go by
    };
    const auto res = luck::compute_rounds(rows, h);
    EXPECT_DOUBLE_EQ(luck::period_effort(res[0]), 1.0);
    EXPECT_TRUE(luck::counts_in_period(rows[0], res[0]));

    EXPECT_NEAR(res[1].effort, 4.0, 1e-12);                    // scaled to the round
    EXPECT_NEAR(luck::period_effort(res[1]), 2.0, 1e-12);      // what was watched
    EXPECT_TRUE(luck::counts_in_period(rows[1], res[1]));

    // [5000, 9000]: no history over it at all -> its single sample.
    EXPECT_EQ(res[2].method, luck::EffortMethod::single_sample);
    EXPECT_NEAR(luck::period_effort(res[2]), 4.0, 1e-12);
    EXPECT_TRUE(luck::counts_in_period(rows[2], res[2]));

    EXPECT_FALSE(luck::counts_in_period(rows[3], res[3])) << "an orphan is not a block found";

    EXPECT_EQ(res[4].method, luck::EffortMethod::single_sample);
    EXPECT_NEAR(luck::period_effort(res[4]), 3.0, 1e-12);
    EXPECT_TRUE(luck::counts_in_period(rows[4], res[4]));

    EXPECT_DOUBLE_EQ(luck::period_effort(res[5]), 0.0);
    EXPECT_FALSE(luck::counts_in_period(rows[5], res[5]));

    // The rows sum to the period: sum(counted) / sum(period_effort).
    const luck::RoundOptions opt;
    const auto open = luck::open_round(rows, h, opt, 13000.0, 0.0, 0.0);
    const auto all = luck::period_luck(rows, res, h, opt, open, 0.0, 13000.0);
    uint64_t k = 0;
    double expected = 0.0;
    for (size_t i = 0; i < rows.size(); ++i) {
        if (luck::counts_in_period(rows[i], res[i])) ++k;
        if (rows[i].main_chain) expected += luck::period_effort(res[i]);
    }
    EXPECT_EQ(all.k, k);
    EXPECT_EQ(all.k, 4u);
    EXPECT_NEAR(all.expected, expected, 1e-12);
    EXPECT_NEAR(all.expected, 1.0 + 2.0 + 4.0 + 3.0, 1e-12);
    EXPECT_EQ(all.unmeasured, 1u);
}

// The exact (Garwood) Poisson interval, against scipy:
//   lo = chi2.ppf(0.025, 2k) / 2,  hi = chi2.ppf(0.975, 2k + 2) / 2
TEST(PoolLuck, PoissonIntervalMatchesScipy)
{
    struct Ref { uint64_t k; double lo, hi; };
    const Ref refs[] = {
        {0, 0.0, 3.6888794541139354},
        {1, 0.025317807984289876, 5.571643390938898},
        {2, 0.24220927854396496, 7.22468766772396},
        {3, 0.6186721228956014, 8.767273069742323},
        {5, 1.6234863901184207, 11.66833207932267},
        {10, 4.7953886961324335, 18.39035604201778},
        {30, 20.240874021420915, 42.82686539480766},
        {78, 61.65576320502033, 97.34753005086979},
        {100, 81.36399125092314, 121.62679379242638},
        {229, 200.2985716487404, 260.6598529964897},
        {1000, 938.9730184076952, 1063.952136016302},
        {100000, 99381.15266374472, 100621.74473974388},
    };
    for (const auto& ref : refs) {
        const auto ci = luck::poisson_ci95(ref.k);
        if (ref.k == 0) EXPECT_DOUBLE_EQ(ci.first, 0.0);
        else EXPECT_NEAR(ci.first, ref.lo, ref.lo * 1e-9) << "k=" << ref.k;
        EXPECT_NEAR(ci.second, ref.hi, ref.hi * 1e-9) << "k=" << ref.k;
    }
    // Above 1e5 events the Wilson-Hilferty form takes over.
    const auto big = luck::poisson_ci95(2000000);
    EXPECT_NEAR(big.first, 1997229.1396258022, 1997229.0 * 1e-7);
    EXPECT_NEAR(big.second, 2002773.755372962, 2002773.0 * 1e-7);
}

// Period luck on a known k / expected. Five main-chain blocks, every round
// one sample at lambda = 1e-3 blocks per second (H = 2^32, D = 1000):
//
//   t =  1000  first block                      1 found / 1 expected
//   t =  2000  round 1000 s  effort 1.0
//   t =  5000  round 3000 s  effort 3.0
//   t =  5500  round  500 s  effort 0.5
//   t =  5600  orphan -- no round, not counted
//   t =  7500  round 2000 s  effort 2.0  (timed from 5500, across the orphan)
//   now = 9000 open round 1500 s          effort 1.5
//
// all:  k = 5, expected = 1 + 1 + 3 + 0.5 + 2 + 1.5 = 9
TEST(PoolLuck, PeriodLuckIsBlocksFoundOverBlocksExpected)
{
    const double H = kT32, D = 1000.0;
    const std::vector<luck::RoundInput> rows = {
        row(1000.0, 1, true, D, H), row(2000.0, 2, true, D, H), row(5000.0, 3, true, D, H),
        row(5500.0, 4, true, D, H), row(5600.0, 5, false, D, H), row(7500.0, 6, true, D, H),
    };
    const luck::RateHistory empty;
    const luck::RoundOptions opt;
    const auto res = luck::compute_rounds(rows, empty, opt);
    const double now = 9000.0;
    const auto open = luck::open_round(rows, empty, opt, now, H, D);
    EXPECT_EQ(open.since, 5);
    EXPECT_DOUBLE_EQ(open.elapsed, 1500.0);
    EXPECT_NEAR(open.effort, 1.5, 1e-12);
    EXPECT_NEAR(open.expected_time, 1000.0, 1e-9);
    EXPECT_EQ(open.method, luck::EffortMethod::single_sample);

    const auto all = luck::period_luck(rows, res, empty, opt, open, 0.0, now);
    EXPECT_EQ(all.k, 5u);
    EXPECT_NEAR(all.expected, 9.0, 1e-12);
    ASSERT_TRUE(all.has_luck);
    EXPECT_NEAR(all.luck, 100.0 * 5.0 / 9.0, 1e-9);
    // scipy, k = 5: [1.6234863901184207, 11.66833207932267] / 9
    EXPECT_NEAR(all.ci_low, 100.0 * 1.6234863901184207 / 9.0, 1e-6);
    EXPECT_NEAR(all.ci_high, 100.0 * 11.66833207932267 / 9.0, 1e-6);
    EXPECT_DOUBLE_EQ(all.span, 8000.0);
    EXPECT_EQ(all.unmeasured, 0u);

    // The window [6000, 9000]: one block (7500). Its round is clipped to the
    // window (1500 of its 2000 s -> 1.5) and the open round adds 1.5: the
    // window is 3000 s at 1e-3 / s, 3.0 blocks expected.
    const auto win = luck::period_luck(rows, res, empty, opt, open, 6000.0, now);
    EXPECT_EQ(win.k, 1u);
    EXPECT_NEAR(win.expected, 3.0, 1e-12);
    EXPECT_NEAR(win.luck, 100.0 / 3.0, 1e-9);
    EXPECT_DOUBLE_EQ(win.span, 3000.0);

    // A window with no block in it: 0 found, 1000 s -> 1.0 expected; the
    // interval still has an upper bound.
    const auto dry = luck::period_luck(rows, res, empty, opt, open, 8000.0, now);
    EXPECT_EQ(dry.k, 0u);
    EXPECT_NEAR(dry.expected, 1.0, 1e-12);
    EXPECT_DOUBLE_EQ(dry.luck, 0.0);
    EXPECT_DOUBLE_EQ(dry.ci_low, 0.0);
    EXPECT_NEAR(dry.ci_high, 100.0 * 3.6888794541139354, 1e-6);
}

// A period extrapolates nothing over a gap in the history. lambda = 1e-3
// blocks per second wherever the history is watching:
//
//   history [3000, 5000] only; blocks at 1000 (first) and 5000.
//     The ROW's effort is the best estimate for its round: the covered
//     integral, 2.0, scaled to the 4000 s round = 4.0, coverage 0.5.
//     The PERIOD counts the observed time: the first block 1 / 1, then one
//     block found while the history watched 2000 s -> 1 / 2.0.
//       all: k = 2, expected = 3.0   (scaled it would be 5.0)
TEST(PoolLuck, PeriodCountsObservedTimeAndDoesNotExtrapolateAGap)
{
    luck::RateHistory h;
    h.add_segment({3000.0, 5000.0, kT32, 1000.0, 1.0});
    const std::vector<luck::RoundInput> rows = {row(1000.0, 1, true, 1000.0, 0.0),
                                                row(5000.0, 2, true, 1000.0, 0.0)};
    const luck::RoundOptions opt;
    const auto res = luck::compute_rounds(rows, h, opt);
    EXPECT_NEAR(res[1].effort, 4.0, 1e-12);
    EXPECT_NEAR(res[1].coverage, 0.5, 1e-12);
    EXPECT_NEAR(res[1].covered_effort, 2.0, 1e-12);
    EXPECT_TRUE(res[1].end_covered);

    const auto open = luck::open_round(rows, h, opt, 5000.0, kT32, 1000.0);
    const auto all = luck::period_luck(rows, res, h, opt, open, 0.0, 5000.0);
    EXPECT_EQ(all.k, 2u);
    EXPECT_NEAR(all.expected, 1.0 + 2.0, 1e-12);
    EXPECT_EQ(all.unmeasured, 0u);
}

// The other way round: the history watched [1000, 3000] and then went dark
// (the node was down); the block at 5000 was found in the dark. The watched
// 2000 s still count as time in which no block was found; the block itself
// is not a block the history saw.
//       all: k = 1 (the first block), expected = 1.0 + 2.0, unmeasured = 1
TEST(PoolLuck, BlockFoundInAGapIsLeftOutWithTheGap)
{
    luck::RateHistory h;
    h.add_segment({1000.0, 3000.0, kT32, 1000.0, 1.0});
    const std::vector<luck::RoundInput> rows = {row(1000.0, 1, true, 1000.0, 0.0),
                                                row(5000.0, 2, true, 1000.0, 0.0)};
    const luck::RoundOptions opt;
    const auto res = luck::compute_rounds(rows, h, opt);
    EXPECT_NEAR(res[1].effort, 4.0, 1e-12) << "the row keeps its scaled estimate";
    EXPECT_FALSE(res[1].end_covered);

    const auto open = luck::open_round(rows, h, opt, 5000.0, 0.0, 0.0);
    const auto all = luck::period_luck(rows, res, h, opt, open, 0.0, 5000.0);
    EXPECT_EQ(all.k, 1u);
    EXPECT_EQ(all.unmeasured, 1u);
    EXPECT_NEAR(all.expected, 1.0 + 2.0, 1e-12);

    // A block found a minute after the last sample was still seen: the
    // sample that covers its own time simply has not arrived yet.
    const std::vector<luck::RoundInput> live = {row(1000.0, 1, true, 1000.0, 0.0),
                                                row(3060.0, 2, true, 1000.0, 0.0)};
    const auto live_res = luck::compute_rounds(live, h, opt);
    EXPECT_TRUE(live_res[1].end_covered);
    const auto live_all = luck::period_luck(live, live_res, h, opt,
                                            luck::open_round(live, h, opt, 3060.0, 0.0, 0.0),
                                            0.0, 3060.0);
    EXPECT_EQ(live_all.k, 2u);
    EXPECT_NEAR(live_all.expected, 1.0 + 2.0, 1e-12);
}

// A round whose effort cannot be had is left out of BOTH the count and the
// expectation -- counting the block without its effort would inflate luck.
TEST(PoolLuck, UnmeasuredRoundIsLeftOutOfBothSidesOfThePeriod)
{
    const double H = kT32, D = 1000.0;
    const std::vector<luck::RoundInput> rows = {
        row(1000.0, 1, true, D, H), row(2000.0, 2, true, D, 0.0), row(5000.0, 3, true, D, H),
    };
    const luck::RateHistory empty;
    const luck::RoundOptions opt;
    const auto res = luck::compute_rounds(rows, empty, opt);
    const auto open = luck::open_round(rows, empty, opt, 5000.0, H, D);
    const auto all = luck::period_luck(rows, res, empty, opt, open, 0.0, 5000.0);
    EXPECT_EQ(all.k, 2u);
    EXPECT_EQ(all.unmeasured, 1u);
    EXPECT_NEAR(all.expected, 1.0 + 3.0, 1e-12);
}

// No block yet: nothing to report, and nothing divides by zero.
TEST(PoolLuck, NoBlocksNoLuck)
{
    const std::vector<luck::RoundInput> rows;
    const luck::RateHistory empty;
    const luck::RoundOptions opt;
    const auto res = luck::compute_rounds(rows, empty, opt);
    const auto open = luck::open_round(rows, empty, opt, 1000.0, kT32, 1000.0);
    EXPECT_EQ(open.since, -1);
    const auto all = luck::period_luck(rows, res, empty, opt, open, 0.0, 1000.0);
    EXPECT_EQ(all.k, 0u);
    EXPECT_FALSE(all.has_luck);
    EXPECT_DOUBLE_EQ(all.span, 0.0);
}

// ── Another node's measurement of the same round ─────────────────────────────
// The pool rate is the share chain's, the same on every node: a round another
// node integrated over more of it than this node's history covers is the
// better figure for the round -- where the same two blocks bound it. Here the
// history covers 200 s of the 4000 s round B (5 %), none of round C.
TEST(PoolLuck, ImportedEffortStandsWhereItCoversMoreOfTheSameRound)
{
    luck::RateHistory h;
    h.add_segment({4800.0, 5000.0, 0.5 * kT32, 1000.0, 1.0});
    auto rows = std::vector<luck::RoundInput>{row(1000.0, 10), row(5000.0, 11), row(9000.0, 12)};
    // This node's own: B integrated over 5 % (0.5 * 4000 / 2000 = 1.0), C a
    // single sample at find (4000 * 0.5 / 2000 = 1.0).
    auto own = luck::compute_rounds(rows, h);
    ASSERT_EQ(own[1].method, luck::EffortMethod::integrated);
    EXPECT_NEAR(own[1].coverage, 0.05, 1e-12);
    ASSERT_EQ(own[2].method, luck::EffortMethod::single_sample);

    // The source: B over all of it, C over 60 % of it.
    rows[1].imported_effort = 1.375;  rows[1].imported_coverage = 1.0;  rows[1].imported_prev = 0;
    rows[2].imported_effort = 0.8;    rows[2].imported_coverage = 0.6;  rows[2].imported_prev = 1;
    // A first block keeps its 1.0 whatever it is offered.
    rows[0].imported_effort = 3.0;    rows[0].imported_coverage = 1.0;
    const auto res = luck::compute_rounds(rows, h);
    EXPECT_EQ(res[0].method, luck::EffortMethod::first_block);
    EXPECT_DOUBLE_EQ(res[0].effort, 1.0);

    const auto& b = res[1];
    EXPECT_EQ(b.method, luck::EffortMethod::imported);
    EXPECT_STREQ(luck::effort_method_name(b.method), "imported");
    EXPECT_EQ(b.prev, 0);
    EXPECT_DOUBLE_EQ(b.time_to_find, 4000.0) << "this node's own round";
    EXPECT_DOUBLE_EQ(b.effort, 1.375);
    EXPECT_NEAR(b.luck, 100.0 / 1.375, 1e-12);
    EXPECT_NEAR(b.expected_time, 4000.0 / 1.375, 1e-9);
    EXPECT_DOUBLE_EQ(b.coverage, 1.0);
    EXPECT_DOUBLE_EQ(b.covered_effort, 1.375);
    EXPECT_EQ(b.samples, 0u) << "no rate of this node's is behind it";
    EXPECT_DOUBLE_EQ(b.rate_used, 0.0);

    const auto& c = res[2];
    EXPECT_EQ(c.method, luck::EffortMethod::imported) << "a single sample covers nothing";
    EXPECT_DOUBLE_EQ(c.effort, 0.8);
    EXPECT_NEAR(c.covered_effort, 0.48, 1e-12) << "what the source's history watched";

    // What a period counts: the source's covered integral, and the block.
    EXPECT_DOUBLE_EQ(luck::period_effort(b), 1.375);
    EXPECT_NEAR(luck::period_effort(c), 0.48, 1e-12);
    EXPECT_TRUE(luck::counts_in_period(rows[1], b));
    const auto p = luck::period_luck(rows, res, h, {}, luck::OpenRound{}, 0.0, 9000.0);
    EXPECT_EQ(p.k, 3u);
    EXPECT_NEAR(p.expected, 1.0 + 1.375 + 0.48, 1e-12);
    // Clipped by a window, an imported round is taken linear in time.
    const auto w = luck::period_luck(rows, res, h, {}, luck::OpenRound{}, 3000.0, 9000.0);
    EXPECT_NEAR(w.expected, 1.375 * 2000.0 / 4000.0 + 0.48, 1e-12);
}

TEST(PoolLuck, ImportedEffortNeverReplacesAnEqualOrBetterOwnFigure)
{
    luck::RateHistory h;
    h.add_segment({4800.0, 5000.0, 0.5 * kT32, 1000.0, 1.0});
    auto rows = std::vector<luck::RoundInput>{row(1000.0, 10), row(5000.0, 11)};
    auto with = [&](double effort, double coverage, int prev) {
        auto r = rows;
        r[1].imported_effort = effort;
        r[1].imported_coverage = coverage;
        r[1].imported_prev = prev;
        return luck::compute_rounds(r, h)[1];
    };
    // This node's own: B integrated over 5 % at 2.0 (0.5 / 1000 over 200 s,
    // scaled to 4000 s).
    ASSERT_NEAR(luck::compute_rounds(rows, h)[1].effort, 2.0, 1e-12);
    // The same coverage (a tie, to rounding), or less: this node's own.
    EXPECT_EQ(with(1.375, 0.05, 0).method, luck::EffortMethod::integrated);
    EXPECT_EQ(with(1.375, 0.05 + 1e-9, 0).method, luck::EffortMethod::integrated);
    EXPECT_EQ(with(1.375, 0.04, 0).method, luck::EffortMethod::integrated);
    // More of the round, but under half of it (kImportedCoverageFloor): an
    // extrapolation as well, and it would count its block against almost
    // nothing in a period.
    EXPECT_EQ(with(1.375, 0.06, 0).method, luck::EffortMethod::integrated);
    EXPECT_EQ(with(1.375, 0.49, 0).method, luck::EffortMethod::integrated);
    EXPECT_EQ(with(1.375, luck::kImportedCoverageFloor, 0).method, luck::EffortMethod::imported);
    // Against what this node measured over its 5 %: within 3x either way
    // (kImportedRateBand) it stands, beyond it the node's own does.
    EXPECT_EQ(with(5.9, 1.0, 0).method, luck::EffortMethod::imported);
    EXPECT_EQ(with(0.7, 1.0, 0).method, luck::EffortMethod::imported);
    EXPECT_EQ(with(6.1, 1.0, 0).method, luck::EffortMethod::integrated);
    EXPECT_EQ(with(0.6, 1.0, 0).method, luck::EffortMethod::integrated);
    EXPECT_EQ(with(100.0, 1.0, 0).method, luck::EffortMethod::integrated);
    // Another round: the source timed it from a block this node does not
    // hold (-1) ...
    EXPECT_EQ(with(1.375, 1.0, -1).method, luck::EffortMethod::integrated);
    // ... or from A, where this node holds a block X between A and B: its
    // round runs from X, and the source's figure is of another round.
    {
        auto three = std::vector<luck::RoundInput>{row(1000.0, 10), row(3000.0, 105),
                                                   row(5000.0, 11)};
        three[2].imported_effort = 1.375;
        three[2].imported_coverage = 1.0;
        three[2].imported_prev = 0;
        const auto r3 = luck::compute_rounds(three, h);
        EXPECT_EQ(r3[2].prev, 1);
        EXPECT_EQ(r3[2].method, luck::EffortMethod::integrated);
    }
    // Malformed figures are no figures.
    EXPECT_EQ(with(std::nan(""), 1.0, 0).method, luck::EffortMethod::integrated);
    EXPECT_EQ(with(-1.0, 1.0, 0).method, luck::EffortMethod::integrated);
    EXPECT_EQ(with(1.375, 0.0, 0).method, luck::EffortMethod::integrated);
    EXPECT_EQ(with(1.375, 1.5, 0).method, luck::EffortMethod::integrated);
    EXPECT_FALSE(luck::imported_effort_valid(1e-300, 1.0));
    EXPECT_FALSE(luck::imported_effort_valid(std::numeric_limits<double>::denorm_min(), 1.0));
    EXPECT_FALSE(luck::imported_effort_valid(2e6, 1.0));
    EXPECT_FALSE(luck::imported_effort_valid(1.0, std::numeric_limits<double>::denorm_min()));
    EXPECT_FALSE(luck::imported_effort_valid(std::numeric_limits<double>::infinity(), 1.0));
    EXPECT_TRUE(luck::imported_effort_valid(luck::kImportedEffortMin, 1.0));
    EXPECT_TRUE(luck::imported_effort_valid(luck::kImportedEffortMax, 0.5));

    // No effort of its own at all (no history, no rate at find): any
    // measurement over half the round or more beats it; there is nothing
    // of its own to agree with.
    auto blind = rows;
    blind[1].rate_at_find = 0.0;
    blind[1].imported_effort = 2.0;
    blind[1].imported_coverage = 0.6;
    blind[1].imported_prev = 0;
    const luck::RateHistory none;
    blind[1].imported_effort = 0.0;
    ASSERT_EQ(luck::compute_rounds(blind, none)[1].method, luck::EffortMethod::none);
    blind[1].imported_effort = 2.0;
    EXPECT_EQ(luck::compute_rounds(blind, none)[1].method, luck::EffortMethod::imported);
}

// The bounds a source's effort is held to: the mean pool rate it implies
// over this node's round, effort * D * 2^32 / round, judged as a rate at
// find is (rate_at_find_plausible), and never above the whole network.
TEST(PoolLuck, ImportedEffortMustImplyAPlausiblePoolRate)
{
    const double D = 9.5e7, day = 86400.0;
    const double rate = D * kT32 / day;            // effort 1.0 a day
    const double network = D * kT32 / 150.0;
    EXPECT_TRUE(luck::imported_effort_plausible(1.0, day, D, 500.0, rate, network));
    EXPECT_TRUE(luck::imported_effort_plausible(18.4, day, D, 0.0, rate, network));
    EXPECT_TRUE(luck::imported_effort_plausible(1.0, day, D, 0.0, 0.0, 0.0)) << "no yardstick";
    // The pool above its whole network.
    EXPECT_FALSE(luck::imported_effort_plausible(1.0e6, day, D, 500.0, rate, network));
    // Below what its winning shares allow, or 1 % of the history's rate.
    EXPECT_FALSE(luck::imported_effort_plausible(1.0e-6, day, D, 500.0, 0.0, network));
    EXPECT_FALSE(luck::imported_effort_plausible(0.005, day, D, 0.0, rate, network));
    // Out of its absolute bounds: no yardstick at all is needed for that.
    EXPECT_FALSE(luck::imported_effort_plausible(1e-300, day, D, 0.0, 0.0, 0.0));
    EXPECT_FALSE(luck::imported_effort_plausible(std::numeric_limits<double>::denorm_min(), day,
                                                 D, 0.0, 0.0, 0.0));
    EXPECT_FALSE(luck::imported_effort_plausible(1e7, day, D, 0.0, 0.0, 0.0));
    // Nothing to judge it on.
    EXPECT_FALSE(luck::imported_effort_plausible(1.0, 0.0, D, 0.0, rate, network));
    EXPECT_FALSE(luck::imported_effort_plausible(1.0, day, 0.0, 0.0, rate, network));
    EXPECT_FALSE(luck::imported_effort_plausible(-1.0, day, D, 0.0, rate, network));
    EXPECT_FALSE(luck::imported_effort_plausible(std::nan(""), day, D, 0.0, rate, network));
}

// An effort whose luck is not a finite number is no measurement: never a
// luck of inf, which JSON renders as null under a method claiming a value.
TEST(PoolLuck, EffortWithoutAFiniteLuckIsNoEffort)
{
    const luck::RateHistory none;
    auto rows = std::vector<luck::RoundInput>{row(1000.0, 10), row(5000.0, 11)};
    rows[1].rate_at_find = std::numeric_limits<double>::denorm_min();
    const auto r = luck::compute_rounds(rows, none)[1];
    EXPECT_EQ(r.method, luck::EffortMethod::none);
    EXPECT_EQ(r.missing, luck::MissingInput::rate);
    EXPECT_DOUBLE_EQ(r.effort, 0.0);
    EXPECT_DOUBLE_EQ(r.luck, 0.0);
    EXPECT_EQ(r.prev, 0);
    EXPECT_DOUBLE_EQ(r.time_to_find, 4000.0);
}
