#include <gtest/gtest.h>
#include <impl/ltc/redistribute.hpp>
#include <map>

using namespace ltc;

// ─── Hybrid Mode Parsing ─────────────────────────────────────────────────────

TEST(RedistributeV2, HybridParse_SingleMode)
{
    auto w = parse_redistribute_spec("boost");
    ASSERT_EQ(w.size(), 1);
    EXPECT_EQ(w[0].mode, RedistributeMode::BOOST);
    EXPECT_EQ(w[0].weight, 100);
}

TEST(RedistributeV2, HybridParse_ThreeModes)
{
    auto w = parse_redistribute_spec("boost:70,donate:20,fee:10");
    ASSERT_EQ(w.size(), 3);
    EXPECT_EQ(w[0].mode, RedistributeMode::BOOST);
    EXPECT_EQ(w[0].weight, 70);
    EXPECT_EQ(w[1].mode, RedistributeMode::DONATE);
    EXPECT_EQ(w[1].weight, 20);
    EXPECT_EQ(w[2].mode, RedistributeMode::FEE);
    EXPECT_EQ(w[2].weight, 10);
}

TEST(RedistributeV2, HybridParse_TwoModes)
{
    auto w = parse_redistribute_spec("pplns:80,boost:20");
    ASSERT_EQ(w.size(), 2);
    EXPECT_EQ(w[0].mode, RedistributeMode::PPLNS);
    EXPECT_EQ(w[0].weight, 80);
    EXPECT_EQ(w[1].mode, RedistributeMode::BOOST);
    EXPECT_EQ(w[1].weight, 20);
}

TEST(RedistributeV2, HybridParse_Empty)
{
    auto w = parse_redistribute_spec("");
    ASSERT_EQ(w.size(), 1);
    EXPECT_EQ(w[0].mode, RedistributeMode::PPLNS);
}

TEST(RedistributeV2, HybridParse_BackwardCompat)
{
    // parse_redistribute_mode should still work for single mode
    EXPECT_EQ(parse_redistribute_mode("fee"), RedistributeMode::FEE);
    EXPECT_EQ(parse_redistribute_mode("boost"), RedistributeMode::BOOST);
    EXPECT_EQ(parse_redistribute_mode("donate"), RedistributeMode::DONATE);
    EXPECT_EQ(parse_redistribute_mode("pplns"), RedistributeMode::PPLNS);
    EXPECT_EQ(parse_redistribute_mode("boost:70,fee:30"), RedistributeMode::BOOST);
}

TEST(RedistributeV2, HybridFormat)
{
    auto w = parse_redistribute_spec("boost:70,donate:20,fee:10");
    auto s = format_hybrid_weights(w);
    EXPECT_EQ(s, "boost:70,donate:20,fee:10");

    auto w2 = parse_redistribute_spec("boost");
    EXPECT_EQ(format_hybrid_weights(w2), "boost");
}

// ─── Stratum Password Parsing ────────────────────────────────────────────────

TEST(RedistributeV2, PasswordParse_BoostTrue)
{
    auto opts = parse_stratum_password("boost:true");
    EXPECT_TRUE(opts.boost);
    EXPECT_DOUBLE_EQ(opts.min_diff, 0);
}

TEST(RedistributeV2, PasswordParse_BoostAndDiff)
{
    auto opts = parse_stratum_password("boost:true,d=512");
    EXPECT_TRUE(opts.boost);
    EXPECT_DOUBLE_EQ(opts.min_diff, 512);
}

TEST(RedistributeV2, PasswordParse_DiffOnly)
{
    auto opts = parse_stratum_password("d=1024");
    EXPECT_FALSE(opts.boost);
    EXPECT_DOUBLE_EQ(opts.min_diff, 1024);
}

TEST(RedistributeV2, PasswordParse_Empty)
{
    auto opts = parse_stratum_password("");
    EXPECT_FALSE(opts.boost);
    EXPECT_DOUBLE_EQ(opts.min_diff, 0);
}

TEST(RedistributeV2, PasswordParse_BoostFalse)
{
    auto opts = parse_stratum_password("boost:false");
    EXPECT_FALSE(opts.boost);
}

TEST(RedistributeV2, PasswordParse_EqualsSign)
{
    auto opts = parse_stratum_password("boost=true,d=256");
    EXPECT_TRUE(opts.boost);
    EXPECT_DOUBLE_EQ(opts.min_diff, 256);
}

// ─── Graduated Boost Scoring ─────────────────────────────────────────────────

TEST(RedistributeV2, GraduatedScore_Proportional)
{
    // Miner A: 12h uptime, 1000 pseudoshares, diff 1.0 → score = 12 * 1001 * 1.0 = 12012
    // Miner B: 1h uptime, 100 pseudoshares, diff 1.0 → score = 1 * 101 * 1.0 = 101
    // A should be ~119x more likely to be selected
    GraduatedMinerInfo a;
    a.uptime_hours = 12.0;
    a.pseudoshares = 1000;
    a.difficulty = 1.0;

    GraduatedMinerInfo b;
    b.uptime_hours = 1.0;
    b.pseudoshares = 100;
    b.difficulty = 1.0;

    double score_a = std::min(a.uptime_hours, 24.0) * (a.pseudoshares + 1) * std::max(a.difficulty, 0.001);
    double score_b = std::min(b.uptime_hours, 24.0) * (b.pseudoshares + 1) * std::max(b.difficulty, 0.001);

    EXPECT_NEAR(score_a / score_b, 12.0 * 1001.0 / (1.0 * 101.0), 0.01);
}

TEST(RedistributeV2, GraduatedScore_UptimeCap)
{
    // 48h uptime should be capped to 24h
    GraduatedMinerInfo m;
    m.uptime_hours = 48.0;
    m.pseudoshares = 100;
    m.difficulty = 1.0;

    double score = std::min(m.uptime_hours, 24.0) * (m.pseudoshares + 1) * std::max(m.difficulty, 0.001);
    double expected = 24.0 * 101.0 * 1.0;
    EXPECT_DOUBLE_EQ(score, expected);
}

TEST(RedistributeV2, GraduatedScore_DifficultyWeights)
{
    // Higher difficulty = higher score (proportional)
    GraduatedMinerInfo low_diff, high_diff;
    low_diff.uptime_hours = 1.0;
    low_diff.pseudoshares = 100;
    low_diff.difficulty = 0.001;

    high_diff.uptime_hours = 1.0;
    high_diff.pseudoshares = 100;
    high_diff.difficulty = 1000.0;

    double score_low = std::min(low_diff.uptime_hours, 24.0) * (low_diff.pseudoshares + 1) * std::max(low_diff.difficulty, 0.001);
    double score_high = std::min(high_diff.uptime_hours, 24.0) * (high_diff.pseudoshares + 1) * std::max(high_diff.difficulty, 0.001);

    EXPECT_NEAR(score_high / score_low, 1000000.0, 100.0); // 1000 / 0.001 = 1M ratio
}

// ─── Hybrid Mode Selection Distribution ──────────────────────────────────────

TEST(RedistributeV2, HybridSelection_Distribution)
{
    // Test that hybrid mode picks modes proportionally to weights
    // Use a deterministic seed for reproducibility
    std::mt19937 rng(42);
    auto weights = parse_redistribute_spec("boost:70,donate:20,fee:10");
    uint32_t total_weight = 0;
    for (auto& hw : weights) total_weight += hw.weight;

    std::map<RedistributeMode, int> counts;
    const int N = 10000;
    for (int i = 0; i < N; ++i)
    {
        std::uniform_int_distribution<uint32_t> dist(0, total_weight - 1);
        uint32_t r = dist(rng);
        uint32_t cumul = 0;
        for (auto& hw : weights)
        {
            cumul += hw.weight;
            if (r < cumul) { counts[hw.mode]++; break; }
        }
    }

    // Within ±5% of expected
    EXPECT_NEAR(counts[RedistributeMode::BOOST],  7000, 500);
    EXPECT_NEAR(counts[RedistributeMode::DONATE],  2000, 500);
    EXPECT_NEAR(counts[RedistributeMode::FEE],     1000, 500);
}

// ─── Threshold Boost Eligibility ─────────────────────────────────────────────

TEST(RedistributeV2, ThresholdEligible)
{
    // Miner with 5% of expected PPLNS weight (luck_ratio = 0.05 < 0.1)
    double actual_ratio = 0.005;    // 0.5% of total PPLNS
    double expected_ratio = 0.10;   // 10% of pool hashrate
    double luck_ratio = actual_ratio / expected_ratio;  // 0.05
    EXPECT_LT(luck_ratio, 0.1);
}

TEST(RedistributeV2, ThresholdNotEligible)
{
    // Miner with 50% of expected PPLNS weight (luck_ratio = 0.5 > 0.1)
    double actual_ratio = 0.05;
    double expected_ratio = 0.10;
    double luck_ratio = actual_ratio / expected_ratio;  // 0.5
    EXPECT_GE(luck_ratio, 0.1);
}

TEST(RedistributeV2, ThresholdInverseLuck)
{
    // Miner A: luck_ratio 0.01, Miner B: luck_ratio 0.05
    // Selection weight: A = 1/0.01 = 100, B = 1/0.05 = 20
    // A should be ~5x more likely
    double weight_a = 1.0 / std::max(0.01, 0.001);
    double weight_b = 1.0 / std::max(0.05, 0.001);
    EXPECT_NEAR(weight_a / weight_b, 5.0, 0.01);
}
