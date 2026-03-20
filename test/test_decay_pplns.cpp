#include <gtest/gtest.h>
#include <core/uint256.hpp>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

// Replicate the decay PPLNS computation from share_tracker.hpp
// to verify it matches Python exactly.

struct DecayResult {
    std::map<std::string, uint288> weights;
    uint288 total_weight;
    uint288 total_donation_weight;
};

struct ShareData {
    uint64_t att;
    uint32_t donation;
    std::string address;
};

DecayResult compute_decayed_weights(
    const std::vector<ShareData>& shares,
    int32_t max_shares,
    const uint288& desired_weight,
    uint32_t chain_length)
{
    static constexpr uint64_t DECAY_PRECISION = 40;
    static constexpr uint64_t DECAY_SCALE = uint64_t(1) << DECAY_PRECISION;
    static constexpr uint64_t LN2_MICRO = 693147;

    uint32_t half_life = std::max(chain_length / 4, uint32_t(1));
    uint64_t decay_per = DECAY_SCALE - (DECAY_SCALE * LN2_MICRO) / (uint64_t(1000000) * half_life);

    DecayResult result;
    int32_t share_count = 0;
    uint64_t decay_fp = DECAY_SCALE;

    for (const auto& share : shares)
    {
        if (share_count >= max_shares)
            break;

        uint288 att(share.att);
        uint32_t don = share.donation;

        uint288 decayed_att = (att * uint288(decay_fp)) >> DECAY_PRECISION;

        auto addr_w = decayed_att * static_cast<uint32_t>(65535 - don);
        auto don_w = decayed_att * don;
        auto this_total = addr_w + don_w;

        if (result.total_weight + this_total > desired_weight) {
            auto remaining = desired_weight - result.total_weight;
            if (!this_total.IsNull()) {
                addr_w = addr_w * remaining / this_total;
                don_w = don_w * remaining / this_total;
            }
            this_total = remaining;
        }

        result.weights[share.address] += addr_w;
        result.total_weight += this_total;
        result.total_donation_weight += don_w;

        ++share_count;
        if (result.total_weight >= desired_weight)
            break;

        decay_fp = static_cast<uint64_t>(
            (static_cast<__uint128_t>(decay_fp) * decay_per) >> DECAY_PRECISION);
    }

    return result;
}

TEST(DecayPPLNS, MatchesPythonExactValues)
{
    // Same 10-share test case as Python test_output_for_cpp_comparison
    std::vector<ShareData> shares = {
        {1000000, 50, "addr_A"},
        {2000000, 50, "addr_B"},
        {1500000, 50, "addr_A"},
        {1000000, 50, "addr_B"},
        {3000000, 50, "addr_A"},
        {1000000, 50, "addr_B"},
        {1000000, 50, "addr_A"},
        {2000000, 50, "addr_B"},
        {1000000, 50, "addr_A"},
        {1500000, 50, "addr_B"},
    };

    uint288 unlimited;
    unlimited.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    auto result = compute_decayed_weights(shares, 10, unlimited, 400);

    // Expected values from Python:
    // total_weight=953350555395
    // total_donation_weight=727359850
    // weight[addr_A]=478168850600
    // weight[addr_B]=474454344945
    EXPECT_EQ(result.total_weight.GetLow64(), uint64_t(953350555395));
    EXPECT_EQ(result.total_donation_weight.GetLow64(), uint64_t(727359850));
    EXPECT_EQ(result.weights["addr_A"].GetLow64(), uint64_t(478168850600));
    EXPECT_EQ(result.weights["addr_B"].GetLow64(), uint64_t(474454344945));

    // Verify: weights + donation = total
    uint288 sum_weights = result.weights["addr_A"] + result.weights["addr_B"];
    EXPECT_EQ(sum_weights + result.total_donation_weight, result.total_weight);
}

TEST(DecayPPLNS, TwoMinersAlternating400Shares)
{
    // 400 shares, miners alternate, unlimited weight
    std::vector<ShareData> shares;
    for (int i = 0; i < 400; ++i)
        shares.push_back({1541819, 0, (i % 2 == 0) ? "A" : "B"});

    uint288 unlimited;
    unlimited.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    auto result = compute_decayed_weights(shares, 400, unlimited, 400);

    // Python: A=6861325693665, B=6813766223280, total=13675091916945
    EXPECT_EQ(result.weights["A"].GetLow64(), uint64_t(6861325693665));
    EXPECT_EQ(result.weights["B"].GetLow64(), uint64_t(6813766223280));
    EXPECT_EQ(result.total_weight.GetLow64(), uint64_t(13675091916945));

    // Check payout amounts
    uint64_t subsidy = 156250000;
    uint64_t amt_A = (uint288(subsidy) * result.weights["A"] / result.total_weight).GetLow64();
    uint64_t amt_B = (uint288(subsidy) * result.weights["B"] / result.total_weight).GetLow64();

    // Python: A=78396704, B=77853295
    EXPECT_EQ(amt_A, uint64_t(78396704));
    EXPECT_EQ(amt_B, uint64_t(77853295));
}

TEST(DecayPPLNS, CappedVsUnlimited)
{
    // Verify that capped desired_weight truncates to ~2 shares
    std::vector<ShareData> shares;
    for (int i = 0; i < 400; ++i)
        shares.push_back({1541819, 0, (i % 2 == 0) ? "A" : "B"});

    // Capped: block_att * SPREAD * 65535
    uint64_t block_att = 1048577;
    uint288 capped_desired = uint288(65535) * uint288(3) * uint288(block_att);

    auto result_cap = compute_decayed_weights(shares, 400, capped_desired, 400);

    // Capped total should equal desired_weight exactly (cap was hit)
    EXPECT_EQ(result_cap.total_weight, capped_desired);

    // With unlimited
    uint288 unlimited;
    unlimited.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    auto result_ulim = compute_decayed_weights(shares, 400, unlimited, 400);

    // Unlimited total should be much larger
    EXPECT_TRUE(result_ulim.total_weight > capped_desired);

    // Both should have 2 addresses
    EXPECT_EQ(result_cap.weights.size(), 2u);
    EXPECT_EQ(result_ulim.weights.size(), 2u);

    // Unlimited should give more equal distribution
    uint64_t subsidy = 156250000;
    uint64_t cap_A = (uint288(subsidy) * result_cap.weights["A"] / result_cap.total_weight).GetLow64();
    uint64_t cap_B = (uint288(subsidy) * result_cap.weights["B"] / result_cap.total_weight).GetLow64();
    uint64_t ulim_A = (uint288(subsidy) * result_ulim.weights["A"] / result_ulim.total_weight).GetLow64();
    uint64_t ulim_B = (uint288(subsidy) * result_ulim.weights["B"] / result_ulim.total_weight).GetLow64();

    // Unlimited should be closer to 50/50
    int64_t cap_diff = std::abs(int64_t(cap_A) - int64_t(cap_B));
    int64_t ulim_diff = std::abs(int64_t(ulim_A) - int64_t(ulim_B));
    EXPECT_LT(ulim_diff, cap_diff);

    std::cout << "Capped:    A=" << cap_A << " B=" << cap_B << " diff=" << cap_diff << std::endl;
    std::cout << "Unlimited: A=" << ulim_A << " B=" << ulim_B << " diff=" << ulim_diff << std::endl;
}

TEST(DecayPPLNS, DecayConverges)
{
    // Total weight should converge as we add more shares
    // (decay makes old shares negligible)
    std::vector<ShareData> shares;
    for (int i = 0; i < 4000; ++i)
        shares.push_back({1541819, 50, "miner"});

    uint288 unlimited;
    unlimited.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    auto r400 = compute_decayed_weights(shares, 400, unlimited, 400);
    auto r4000 = compute_decayed_weights(shares, 4000, unlimited, 400);

    // Ratio should be close to 1.0 (within 10%)
    // Python: ratio = 1.065979
    double ratio = static_cast<double>(r4000.total_weight.GetLow64()) /
                   static_cast<double>(r400.total_weight.GetLow64());
    EXPECT_GT(ratio, 1.0);
    EXPECT_LT(ratio, 1.1);

    std::cout << "400 shares:  total_weight=" << r400.total_weight.GetLow64() << std::endl;
    std::cout << "4000 shares: total_weight=" << r4000.total_weight.GetLow64() << std::endl;
    std::cout << "Ratio: " << ratio << std::endl;
}

TEST(DecayPPLNS, PerShareDecayFactors)
{
    // Verify individual decay_fp values match Python
    static constexpr uint64_t DECAY_PRECISION = 40;
    static constexpr uint64_t DECAY_SCALE = uint64_t(1) << DECAY_PRECISION;
    static constexpr uint64_t LN2_MICRO = 693147;

    uint32_t chain_length = 400;
    uint32_t half_life = chain_length / 4; // = 100
    uint64_t decay_per = DECAY_SCALE - (DECAY_SCALE * LN2_MICRO) / (uint64_t(1000000) * half_life);

    // Python: decay_per=1091890395914 (hex: fe39bd3b0a)
    EXPECT_EQ(decay_per, uint64_t(1091890395914));

    // Verify first few decay_fp values
    uint64_t decay_fp = DECAY_SCALE;
    uint64_t expected_fps[] = {
        1099511627776,  // share[0]
        1091890395914,  // share[1]
        1084321990392,  // share[2]
        1076806045045,  // share[3]
        1069342196248,  // share[4]
    };

    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(decay_fp, expected_fps[i]) << "Mismatch at share " << i;
        decay_fp = static_cast<uint64_t>(
            (static_cast<__uint128_t>(decay_fp) * decay_per) >> DECAY_PRECISION);
    }
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
