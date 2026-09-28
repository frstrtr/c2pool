// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH naughty seed rule (naughty_seed.hpp) — pure KATs:
//   * max_coinbase_value: nullopt below the network's V20 height (the rule is
//     inert there), the post-V20 block reward otherwise, plus the superblock
//     budget at a superblock height (mainnet cycle 16616, testnet 24). The
//     constants are dashcore GetBlockSubsidy less the 20% treasury slice and
//     CalcSuperblockBudget, computed out of band;
//   * excessive_reward is strict (subsidy == max is honest, under-payment is
//     honest, unknown max never seeds);
//   * naughty_child_generation: 1 + parent, back to 0 past 6 generations;
//   * the rule is active on the DASH v36 network (a custom --network-id) and
//     never on the public v16 network.
// Folded into test_dash_share_hash_link (no new CI target).

#include <gtest/gtest.h>

#include <impl/dash/config_pool.hpp>
#include <impl/dash/naughty_seed.hpp>

#include <cstdint>
#include <optional>

namespace {

using dash::SharechainConfig;

struct IdentityReset {
    IdentityReset()  { SharechainConfig::reset_network_id(); }
    ~IdentityReset() { SharechainConfig::reset_network_id(); }
};

} // namespace

TEST(DashNaughtySeed, MaxCoinbaseValueTable)
{
    using dash::max_coinbase_value;
    // Below V20: inert.
    EXPECT_FALSE(max_coinbase_value(1'987'775, false).has_value());
    EXPECT_FALSE(max_coinbase_value(905'099, true).has_value());
    EXPECT_FALSE(max_coinbase_value(1, false).has_value());
    // First V20 block.
    EXPECT_EQ(max_coinbase_value(1'987'776, false).value_or(0), 205'304'206ull);
    EXPECT_EQ(max_coinbase_value(905'100, true).value_or(0), 297'386'508ull);
    // An ordinary block and a superblock (16616 * 157) on mainnet.
    EXPECT_EQ(max_coinbase_value(2'600'001, false).value_or(0), 164'378'041ull);
    EXPECT_EQ(max_coinbase_value(2'608'712, false).value_or(0), 164'378'041ull + 682'826'378'160ull);
    // Testnet superblock cycle 24.
    EXPECT_EQ(max_coinbase_value(1'000'008, true).value_or(0), 297'386'508ull + 1'784'319'024ull);
    EXPECT_EQ(max_coinbase_value(1'000'009, true).value_or(0), 297'386'508ull);
    // The same height on the other network uses that network's cycle.
    EXPECT_FALSE(max_coinbase_value(1'000'008, false).has_value()) << "below mainnet V20";
}

TEST(DashNaughtySeed, ExcessiveRewardIsStrictAndNeedsAKnownMax)
{
    using dash::excessive_reward;
    const std::optional<uint64_t> max{164'378'041};
    EXPECT_FALSE(excessive_reward(164'378'041, max)) << "paying exactly the reward is honest";
    EXPECT_FALSE(excessive_reward(1, max)) << "under-payment is a valid block";
    EXPECT_TRUE(excessive_reward(164'378'042, max));
    EXPECT_FALSE(excessive_reward(UINT64_MAX, std::nullopt)) << "unknown height: never seeded";
}

TEST(DashNaughtySeed, ChildGenerationClampsAtSix)
{
    for (int32_t p = 1; p <= 5; ++p)
        EXPECT_EQ(dash::naughty_child_generation(p), p + 1);
    EXPECT_EQ(dash::naughty_child_generation(6), 0) << "7th generation is forgiven";
}

TEST(DashNaughtySeed, ProfileGateOnlyOnTheV36Network)
{
    IdentityReset guard;
    EXPECT_FALSE(dash::naughty_seed_active()) << "public v16: p2pool-dash has no naughty seed";
    EXPECT_FALSE(SharechainConfig::PUBLIC_PROFILE.naughty_seed);
    SharechainConfig::set_network_id("d3a5c0920263617", "0badc0ffee11");
    EXPECT_TRUE(dash::naughty_seed_active()) << "the DASH v36 network seeds it";
    EXPECT_TRUE(SharechainConfig::ISOLATED_V36_PROFILE.naughty_seed);
    SharechainConfig::reset_network_id();
    EXPECT_FALSE(dash::naughty_seed_active());
}
