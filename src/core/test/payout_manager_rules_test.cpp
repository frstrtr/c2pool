// SPDX-License-Identifier: AGPL-3.0-or-later
// payout_manager_rules_test.cpp -- the legacy c2pool::payout module reports
// the fees the way the sharechain actually pays them (V36 rules; external
// review finding 09).
//
//   * the donation is exactly the miner's --give-author percent: no hidden
//     0.5% floor; 0 leaves only the 1-satoshi V36 marker;
//   * the P2P display (calculate_pplns_outputs) passes the PPLNS map through:
//     the donation shares and the node owner's substituted shares are already
//     inside it, so nothing is deducted a second time;
//   * the local/solo split keeps the owner output, with no 50% cap and no
//     rescaling to 51%; the only bound is donation + owner <= 100%;
//   * the LTC donation address is the V36 COMBINED_DONATION_SCRIPT, and the
//     demo coinbase ends in the donation output.
//
// Folded into the existing core_test target (the #769 "Not Run" trap).

#include <gtest/gtest.h>

#include <map>
#include <vector>

#include <c2pool/payout/payout_manager.hpp>

namespace {

using c2pool::payout::PayoutManager;

constexpr uint64_t kReward = 625000000;   // 6.25 LTC

TEST(PayoutRules, NoDonationFloor)
{
    PayoutManager pm(1.0, 86400);
    EXPECT_DOUBLE_EQ(pm.get_developer_config().get_total_developer_fee(), 0.0);
    EXPECT_EQ(pm.get_developer_config().get_developer_amount(kReward), 1u) << "0% leaves only the V36 marker";
    pm.set_developer_donation(0.1);
    EXPECT_DOUBLE_EQ(pm.get_developer_config().get_total_developer_fee(), 0.1) << "no max(0.5%, x) floor";
    EXPECT_EQ(pm.get_developer_config().get_developer_amount(kReward), kReward / 1000);
}

TEST(PayoutRules, LocalSplitHasNoCapOrRescale)
{
    PayoutManager pm(1.0, 86400);
    pm.set_developer_donation(30.0);
    pm.set_node_owner_fee(60.0);   // was refused above 50%
    EXPECT_DOUBLE_EQ(pm.get_node_owner_config().fee_percent, 60.0);
    const auto a = pm.calculate_payout(kReward);
    EXPECT_EQ(a.developer_amount, kReward * 30 / 100);
    EXPECT_EQ(a.node_owner_amount, kReward * 60 / 100) << "no rescaling to a 51% fee total";
    EXPECT_EQ(a.miner_amount + a.developer_amount + a.node_owner_amount, kReward);
}

TEST(PayoutRules, OnlyBoundIsHundredPercent)
{
    PayoutManager pm(1.0, 86400);
    pm.set_developer_donation(60.0);
    pm.set_node_owner_fee(50.0);
    EXPECT_FALSE(pm.validate_configuration()) << "donation + owner > 100% is refused";
}

TEST(PayoutRules, PplnsDisplayDeductsNothing)
{
    PayoutManager pm(1.0, 86400);
    pm.set_developer_donation(5.0);
    pm.set_node_owner_fee(10.0);
    const std::vector<unsigned char> A{0x76, 0xa9, 0x01}, B{0x76, 0xa9, 0x02}, D{0xa9, 0x14, 0x03};
    pm.set_pplns_expected_payouts({{A, 70.0}, {B, 29.0}, {D, 1.0}});
    const auto outs = pm.calculate_pplns_outputs(1000);
    ASSERT_EQ(outs.size(), 3u) << "no extra donation or owner output on top of the PPLNS map";
    std::map<std::vector<unsigned char>, uint64_t> m(outs.begin(), outs.end());
    EXPECT_EQ(m[A], 700u);
    EXPECT_EQ(m[B], 290u);
    EXPECT_EQ(m[D], 10u);
}

TEST(PayoutRules, LtcDonationIsTheV36CombinedScript)
{
    PayoutManager pm(1.0, 86400);
    EXPECT_EQ(pm.get_developer_address(), "MLhSmVQxMusLE3pjGFvp4unFckgjeD8LUA");
}

TEST(PayoutRules, DemoCoinbaseEndsInTheDonation)
{
    PayoutManager pm(1.0, 86400);
    const auto j = pm.build_coinbase_detailed(kReward, "LeD2fnnDJYZuyt8zgDsZ2oBGmuVcxGKCLd");
    ASSERT_TRUE(j.contains("outputs")) << j.dump();
    const auto& o = j["outputs"];
    ASSERT_GE(o.size(), 2u);
    EXPECT_EQ(o.back()["type"], "donation");
    EXPECT_EQ(o.back()["amount_satoshis"].get<uint64_t>(), 1u) << "0% give-author: the 1-satoshi marker, last";
}

TEST(PayoutRules, DemoCoinbaseNeverWrapsOnOverHundredPercent)
{
    PayoutManager pm(1.0, 86400);
    const auto j = pm.build_coinbase_detailed(kReward, "LeD2fnnDJYZuyt8zgDsZ2oBGmuVcxGKCLd", 150.0, 30.0);
    ASSERT_TRUE(j.contains("outputs")) << j.dump();
    uint64_t sum = 0;
    for (const auto& o : j["outputs"]) sum += o["amount_satoshis"].get<uint64_t>();
    EXPECT_EQ(sum, kReward) << "a 150% RPC value is clamped; the outputs still sum to the reward";
    for (const auto& o : j["outputs"]) EXPECT_LE(o["amount_satoshis"].get<uint64_t>(), kReward) << "no output wraps";
}

}  // namespace
