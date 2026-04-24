/// Phase C-TEMPLATE step 1 — Dash subsidy formula unit tests
///
/// Validates compute_dash_block_reward_post_v20 + compute_dash_mn_payment_post_v20
/// against known mainnet values. Live-validated against:
///   h=2459985 → reward=177,022,505 sat (1.77022505 DASH)
///   h=2459992 → reward=177,022,505 sat
///   h=2460022 → reward=177,022,505 sat
///
/// Formula (from dashcore consensus/v20):
///   subsidy = 5 DASH × (13/14)^iterations × 4/5
///   iterations = (height - DEPLOYMENT_V20_HEIGHT) / 210240
///                where 210240 = blocks per ~year at 2.5 min spacing
///   MN payment = block_value × 3/4  (post-MN_RR / DIP-0028)
///
/// Tests:
///   1. Genesis-area pre-V20 height returns the legacy schedule (we
///      skip — pre-V20 is below our checkpoint and out of scope).
///   2. V20 activation height (h=1,987,776) — sanity bound check.
///   3. Live-mainnet reproducible value at h=2459985.
///   4. Halving / decline progression (sanity: h+210240 is smaller).
///   5. MN payment is exactly 3/4 of block_value.

#include <gtest/gtest.h>

// utxo_adapter.hpp must come before subsidy.hpp so dash_txid is
// in scope for subsidy.hpp's computed_block_fees() helper template.
// This test only exercises the pure-arithmetic functions but the
// header still needs to compile cleanly.
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/subsidy.hpp>

#include <cstdint>

using dash::coin::compute_dash_block_reward_post_v20;
using dash::coin::compute_dash_mn_payment_post_v20;

// ─── Tests ──────────────────────────────────────────────────────────────────

TEST(DashSubsidy, MatchesMainnetH2459985)
{
    // Live-validated: dashd-cli getblocktemplate at h=2459985 reported
    // coinbasevalue=177022505 sat (block reward only, no fees).
    int64_t reward = compute_dash_block_reward_post_v20(2459985);
    EXPECT_EQ(reward, 177'022'505LL)
        << "Phase C-TEMPLATE step 1 was live-validated at this height";
}

TEST(DashSubsidy, MNPaymentIs3QuartersOfBlockValue)
{
    int64_t block_value = 200'000'000LL;
    int64_t mn = compute_dash_mn_payment_post_v20(block_value);
    EXPECT_EQ(mn, 150'000'000LL);
    EXPECT_EQ(mn, (block_value * 3) / 4);
}

TEST(DashSubsidy, RewardDeclinesEachYearWindow)
{
    // V20 yearly decline: 13/14 × prev. So h+210240 must be smaller
    // than h. Use heights well past V20 activation (1,987,776 mainnet).
    int64_t r0 = compute_dash_block_reward_post_v20(2'500'000);
    int64_t r1 = compute_dash_block_reward_post_v20(2'500'000 + 210'240);
    EXPECT_LT(r1, r0)
        << "yearly window crossing must reduce subsidy";
    // The reduction factor should be approximately 13/14 (≈ 92.86%)
    double ratio = static_cast<double>(r1) / r0;
    EXPECT_NEAR(ratio, 13.0 / 14.0, 0.005)
        << "yearly subsidy ratio should be ~13/14";
}

TEST(DashSubsidy, RewardPositiveForLongFuture)
{
    // Even far in the future the reward should be positive (not zero).
    int64_t reward = compute_dash_block_reward_post_v20(10'000'000);
    EXPECT_GT(reward, 0)
        << "subsidy should asymptote toward 0 but not actually reach it "
           "in any realistic horizon";
}

TEST(DashSubsidy, SuperblockHeightDetectionMainnet)
{
    // Mainnet superblock cycle = 16616 blocks per dashcore consensus.
    EXPECT_TRUE(dash::coin::is_superblock_height(16616, 16616));
    EXPECT_TRUE(dash::coin::is_superblock_height(16616 * 2, 16616));
    EXPECT_FALSE(dash::coin::is_superblock_height(16615, 16616));
    EXPECT_FALSE(dash::coin::is_superblock_height(16617, 16616));
}
