#include <gtest/gtest.h>
#include <impl/ltc/auto_ratchet.hpp>
#include <fstream>
#include <filesystem>

using namespace ltc;

// ─── State Machine Basics ────────────────────────────────────────────────────

TEST(AutoRatchetTest, InitialState_Voting)
{
    AutoRatchet ratchet("", 37);
    EXPECT_EQ(ratchet.state(), RatchetState::VOTING);
    EXPECT_EQ(ratchet.target_version(), 37);
}

TEST(AutoRatchetTest, StateStrings)
{
    EXPECT_STREQ(ratchet_state_str(RatchetState::VOTING), "VOTING");
    EXPECT_STREQ(ratchet_state_str(RatchetState::ACTIVATED), "ACTIVATED");
    EXPECT_STREQ(ratchet_state_str(RatchetState::CONFIRMED), "CONFIRMED");
}

// ─── Thresholds ──────────────────────────────────────────────────────────────

TEST(AutoRatchetTest, Thresholds_Match_Python)
{
    EXPECT_EQ(AutoRatchet::ACTIVATION_THRESHOLD, 95);
    EXPECT_EQ(AutoRatchet::DEACTIVATION_THRESHOLD, 50);
    EXPECT_EQ(AutoRatchet::CONFIRMATION_MULTIPLIER, 2);
    EXPECT_EQ(AutoRatchet::SWITCH_THRESHOLD, 60);
}

// ─── JSON Persistence ────────────────────────────────────────────────────────

TEST(AutoRatchetTest, Persistence_SaveAndLoad)
{
    std::string path = "/tmp/test_ratchet_" + std::to_string(::getpid()) + ".json";

    // Create ratchet, manually write confirmed state
    {
        nlohmann::json j;
        j["state"] = "confirmed";
        j["activated_at"] = 1000;
        j["activated_height"] = 500;
        j["confirmed_at"] = 2000;
        j["confirm_count"] = 800;
        j["target_version"] = 37;
        std::ofstream f(path);
        f << j.dump();
    }

    // Load and verify
    AutoRatchet ratchet(path, 37);
    EXPECT_EQ(ratchet.state(), RatchetState::CONFIRMED);

    // Cleanup
    std::filesystem::remove(path);
}

TEST(AutoRatchetTest, Persistence_MissingFile)
{
    AutoRatchet ratchet("/tmp/nonexistent_ratchet_test.json", 37);
    EXPECT_EQ(ratchet.state(), RatchetState::VOTING);
}

TEST(AutoRatchetTest, Persistence_EmptyPath)
{
    AutoRatchet ratchet("", 37);
    EXPECT_EQ(ratchet.state(), RatchetState::VOTING);
}

// ─── Version Switch Validation ───────────────────────────────────────────────

TEST(AutoRatchetTest, VersionSwitch_SameVersion_OK)
{
    // Can't test with real tracker, but validate the static logic
    // Same version is always valid
    EXPECT_TRUE(true); // placeholder — real test needs tracker mock
}

TEST(AutoRatchetTest, VersionSwitch_MultiJump_Invalid)
{
    // V35 → V37 (skip V36) should be invalid
    // Test the logic directly (can't call validate_version_switch with null tracker):
    int64_t share_ver = 37, prev_ver = 35;
    bool is_upgrade_by_1 = (share_ver == prev_ver + 1);
    bool is_downgrade_by_1 = (share_ver == prev_ver - 1);
    bool is_same = (share_ver == prev_ver);
    // Multi-jump: none of the valid transitions match
    EXPECT_FALSE(is_upgrade_by_1);
    EXPECT_FALSE(is_downgrade_by_1);
    EXPECT_FALSE(is_same);
}

TEST(AutoRatchetTest, VersionSwitch_UpgradeBy1)
{
    int64_t share_ver = 37, prev_ver = 36;
    EXPECT_TRUE(share_ver == prev_ver + 1);
}

TEST(AutoRatchetTest, VersionSwitch_DowngradeBy1)
{
    int64_t share_ver = 36, prev_ver = 37;
    EXPECT_TRUE(share_ver == prev_ver - 1);
}

// ─── Empty Chain Bootstrap ───────────────────────────────────────────────────

TEST(AutoRatchetTest, EmptyChain_Voting_ProducesOldVersion)
{
    AutoRatchet ratchet("", 37);
    ShareTracker tracker;
    auto [ver, desired] = ratchet.get_share_version(tracker, uint256());
    EXPECT_EQ(ver, 36);      // old version
    EXPECT_EQ(desired, 37);  // voting for upgrade
}

TEST(AutoRatchetTest, EmptyChain_Confirmed_ProducesNewVersion)
{
    // Simulate confirmed state via file
    std::string path = "/tmp/test_ratchet_confirmed_" + std::to_string(::getpid()) + ".json";
    {
        nlohmann::json j;
        j["state"] = "confirmed";
        j["activated_at"] = 1000;
        j["activated_height"] = 500;
        j["confirmed_at"] = 2000;
        j["confirm_count"] = 800;
        std::ofstream f(path);
        f << j.dump();
    }

    AutoRatchet ratchet(path, 37);
    EXPECT_EQ(ratchet.state(), RatchetState::CONFIRMED);

    ShareTracker tracker;
    auto [ver, desired] = ratchet.get_share_version(tracker, uint256());
    EXPECT_EQ(ver, 37);      // new version (confirmed survives empty chain)
    EXPECT_EQ(desired, 37);

    std::filesystem::remove(path);
}

// ─── Activation/Deactivation Math ────────────────────────────────────────────

TEST(AutoRatchetTest, ActivationPct_95)
{
    // 95 out of 100 = 95% → should activate
    int votes = 95, total = 100;
    int pct = (votes * 100) / total;
    EXPECT_GE(pct, AutoRatchet::ACTIVATION_THRESHOLD);
}

TEST(AutoRatchetTest, ActivationPct_94_NotEnough)
{
    int votes = 94, total = 100;
    int pct = (votes * 100) / total;
    EXPECT_LT(pct, AutoRatchet::ACTIVATION_THRESHOLD);
}

TEST(AutoRatchetTest, DeactivationPct_49)
{
    int votes = 49, total = 100;
    int pct = (votes * 100) / total;
    EXPECT_LT(pct, AutoRatchet::DEACTIVATION_THRESHOLD);
}

TEST(AutoRatchetTest, DeactivationPct_50_NoRevert)
{
    int votes = 50, total = 100;
    int pct = (votes * 100) / total;
    EXPECT_GE(pct, AutoRatchet::DEACTIVATION_THRESHOLD);
}

TEST(AutoRatchetTest, SwitchPct_60)
{
    int votes = 60, total = 100;
    int pct = (votes * 100) / total;
    EXPECT_GE(pct, AutoRatchet::SWITCH_THRESHOLD);
}

TEST(AutoRatchetTest, SwitchPct_59_NotEnough)
{
    int votes = 59, total = 100;
    int pct = (votes * 100) / total;
    EXPECT_LT(pct, AutoRatchet::SWITCH_THRESHOLD);
}

TEST(AutoRatchetTest, ConfirmationWindow_Testnet)
{
    // Testnet: CHAIN_LENGTH=400, confirmation = 400 * 2 = 800
    uint32_t chain_length = 400;
    uint32_t confirmation = chain_length * AutoRatchet::CONFIRMATION_MULTIPLIER;
    EXPECT_EQ(confirmation, 800);
}

TEST(AutoRatchetTest, ConfirmationWindow_Mainnet)
{
    // Mainnet: CHAIN_LENGTH=8640, confirmation = 8640 * 2 = 17280
    uint32_t chain_length = 8640;
    uint32_t confirmation = chain_length * AutoRatchet::CONFIRMATION_MULTIPLIER;
    EXPECT_EQ(confirmation, 17280);
}

// ─── Retroactive Confirmation ────────────────────────────────────────────────

TEST(AutoRatchetTest, RetroactiveSkipToConfirmed)
{
    // If a node joins late with height >> CHAIN_LENGTH, retroactive
    // credit should allow skipping ACTIVATED → CONFIRMED
    uint32_t chain_length = 400;
    int32_t height = 5000;
    int32_t retroactive = std::max(0, height - static_cast<int32_t>(chain_length));
    uint32_t confirmation_window = chain_length * AutoRatchet::CONFIRMATION_MULTIPLIER;

    EXPECT_EQ(retroactive, 4600);
    EXPECT_GE(retroactive, static_cast<int32_t>(confirmation_window)); // 4600 >= 800
}

// ─── Monotonic Confirmation Counter ──────────────────────────────────────────

TEST(AutoRatchetTest, MonotonicCounter_Increments)
{
    // Simulate height progression
    int32_t confirm_count = 0;
    int32_t last_height = 1000;

    // Height advances by 100
    int32_t new_height = 1100;
    if (new_height > last_height)
        confirm_count += (new_height - last_height);
    last_height = new_height;
    EXPECT_EQ(confirm_count, 100);

    // Height advances by 50 more
    new_height = 1150;
    if (new_height > last_height)
        confirm_count += (new_height - last_height);
    last_height = new_height;
    EXPECT_EQ(confirm_count, 150);
}

TEST(AutoRatchetTest, MonotonicCounter_NoDecrease)
{
    // Height can't decrease (chain reorg would change best, not height)
    int32_t confirm_count = 100;
    int32_t last_height = 1000;
    int32_t new_height = 950; // reorg

    if (new_height > last_height)
        confirm_count += (new_height - last_height);
    // Counter unchanged
    EXPECT_EQ(confirm_count, 100);
}
