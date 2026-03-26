/// Phase 5.7 — DOGE chain unit tests
///
/// Tests:
///   1. Chain parameters (testnet4alpha defaults)
///   2. DigiShield v3 difficulty calculation
///   3. DOGE subsidy schedule (7 tiers)
///   4. HeaderChain basics (genesis, PoW functions)
///   5. EmbeddedCoinNode interface

#include <gtest/gtest.h>

#include <impl/doge/coin/chain_params.hpp>
#include <impl/doge/coin/header_chain.hpp>
#include <impl/doge/coin/template_builder.hpp>

using namespace doge::coin;

// ─── Chain Params Tests ─────────────────────────────────────────────────────

TEST(DOGEChainParamsTest, Testnet4alphaDefaults) {
    auto p = DOGEChainParams::testnet4alpha();
    EXPECT_EQ(p.digishield_height, 0u);
    EXPECT_EQ(p.auxpow_height, 0u);
    EXPECT_EQ(p.simplified_rewards_height, 0u);
    EXPECT_TRUE(p.allow_min_difficulty);
    EXPECT_TRUE(p.strict_chain_id);
    EXPECT_FALSE(p.pow_limit.IsNull());

    // Genesis hash must match testnet4alpha
    uint256 expected;
    expected.SetHex("de2bcf594a4134cef164a2204ca2f9bce745ff61c22bd714ebc88a7f2bdd8734");
    EXPECT_EQ(p.genesis_hash, expected);
}

TEST(DOGEChainParamsTest, MainnetDefaults) {
    auto p = DOGEChainParams::mainnet();
    EXPECT_EQ(p.digishield_height, 145000u);
    EXPECT_EQ(p.auxpow_height, 371337u);
    EXPECT_FALSE(p.allow_min_difficulty);
    EXPECT_TRUE(p.strict_chain_id);
    EXPECT_EQ(DOGEChainParams::AUXPOW_CHAIN_ID, 0x0062u);
}

TEST(DOGEChainParamsTest, ConsensusEras) {
    auto p = DOGEChainParams::mainnet();
    EXPECT_FALSE(p.is_digishield(0));
    EXPECT_FALSE(p.is_digishield(144999));
    EXPECT_TRUE(p.is_digishield(145000));
    EXPECT_TRUE(p.is_digishield(371337));
    EXPECT_FALSE(p.is_auxpow(371336));
    EXPECT_TRUE(p.is_auxpow(371337));

    // Testnet4alpha: everything from genesis
    auto t = DOGEChainParams::testnet4alpha();
    EXPECT_TRUE(t.is_digishield(0));
    EXPECT_TRUE(t.is_auxpow(0));
}

// ─── Subsidy Tests ──────────────────────────────────────────────────────────

TEST(DOGESubsidyTest, FixedRewardsAfter600k) {
    auto p = DOGEChainParams::mainnet();
    EXPECT_EQ(get_doge_block_subsidy(600000, p), 10000ULL * 100000000ULL);
    EXPECT_EQ(get_doge_block_subsidy(1000000, p), 10000ULL * 100000000ULL);
    EXPECT_EQ(get_doge_block_subsidy(10000000, p), 10000ULL * 100000000ULL);
}

TEST(DOGESubsidyTest, SimplifiedRewardsSchedule) {
    auto p = DOGEChainParams::mainnet();
    // Height 145000-199999: 250,000 DOGE (500000 >> 1)
    EXPECT_EQ(get_doge_block_subsidy(145000, p), 250000ULL * 100000000ULL);
    // Height 200000-299999: 125,000 DOGE (500000 >> 2)
    EXPECT_EQ(get_doge_block_subsidy(200000, p), 125000ULL * 100000000ULL);
    // Height 300000-399999: 62,500 DOGE
    EXPECT_EQ(get_doge_block_subsidy(300000, p), 62500ULL * 100000000ULL);
    // Height 400000-499999: 31,250 DOGE
    EXPECT_EQ(get_doge_block_subsidy(400000, p), 31250ULL * 100000000ULL);
    // Height 500000-599999: 15,625 DOGE
    EXPECT_EQ(get_doge_block_subsidy(500000, p), 15625ULL * 100000000ULL);
}

TEST(DOGESubsidyTest, PreSimplifiedUsesMax) {
    auto p = DOGEChainParams::mainnet();
    // Pre-145000 (not simplified): max possible reward = 1,000,000 >> halvings
    // halving 0 (0-99999): max 1,000,000
    EXPECT_EQ(get_doge_block_subsidy(0, p), 1000000ULL * 100000000ULL);
    // halving 1 (100000-144999): max 500,000
    EXPECT_EQ(get_doge_block_subsidy(100000, p), 500000ULL * 100000000ULL);
}

TEST(DOGESubsidyTest, Testnet4alphaSimplifiedFromGenesis) {
    auto p = DOGEChainParams::testnet4alpha();
    // Testnet4alpha: simplified from height 0
    // halving 0: 500,000 >> 0 = 500,000 DOGE
    EXPECT_EQ(get_doge_block_subsidy(0, p), 500000ULL * 100000000ULL);
    EXPECT_EQ(get_doge_block_subsidy(100, p), 500000ULL * 100000000ULL);
}

// ─── DigiShield v3 Tests ────────────────────────────────────────────────────

TEST(DigiShieldTest, NoChangeAtTargetSpacing) {
    auto p = DOGEChainParams::testnet4alpha();
    // If actual_timespan == target_timespan (60s), difficulty shouldn't change
    uint32_t bits = 0x1e0fffff;
    uint32_t result = calculate_doge_next_work(bits, 1000060, 1000000, 100, p);
    EXPECT_EQ(result, bits) << "Difficulty should not change when block time = target";
}

TEST(DigiShieldTest, FasterThanExpected) {
    auto p = DOGEChainParams::testnet4alpha();
    // Block came 30s after previous (half the target)
    // DigiShield dampens: modulated = 60 + (30-60)/8 = 56.25 → 56
    // Clamped to min=45, so modulated=56 (within bounds)
    // new_target = old_target * 56 / 60 → difficulty increases (target decreases)
    uint32_t bits = 0x1e0fffff;
    uint32_t result = calculate_doge_next_work(bits, 1000030, 1000000, 100, p);
    // Result should be harder (lower target → lower bits)
    uint256 old_target, new_target;
    old_target.SetCompact(bits);
    new_target.SetCompact(result);
    EXPECT_LT(new_target, old_target) << "Faster blocks should increase difficulty";
}

TEST(DigiShieldTest, SlowerThanExpected) {
    auto p = DOGEChainParams::testnet4alpha();
    // Use a non-limit difficulty so the target can increase
    uint32_t bits = 0x1d00ffff; // much harder than pow_limit
    uint32_t result = calculate_doge_next_work(bits, 1000120, 1000000, 100, p);
    uint256 old_target, new_target;
    old_target.SetCompact(bits);
    new_target.SetCompact(result);
    EXPECT_GT(new_target, old_target) << "Slower blocks should decrease difficulty (easier target)";
}

TEST(DigiShieldTest, AmplitudeDampening) {
    auto p = DOGEChainParams::testnet4alpha();
    // Very fast block (1 second) — DigiShield should dampen the response
    // Use non-limit difficulty so we can measure the change
    uint32_t bits = 0x1d00ffff;
    uint32_t digi = calculate_doge_next_work(bits, 1000001, 1000000, 100, p);
    uint256 old_t, new_t;
    old_t.SetCompact(bits);
    new_t.SetCompact(digi);
    // DigiShield dampens: should be within 75%-100% of original
    EXPECT_LT(new_t, old_t) << "Fast block should increase difficulty (lower target)";
    EXPECT_GT(new_t, uint256::ZERO) << "Target should not be zero";
}

// ─── HeaderChain Tests ──────────────────────────────────────────────────────

class DOGEHeaderChainTest : public ::testing::Test {
protected:
    DOGEChainParams params = DOGEChainParams::testnet4alpha();
};

TEST_F(DOGEHeaderChainTest, EmptyChain) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());
    EXPECT_EQ(chain.size(), 0u);
    EXPECT_EQ(chain.height(), 0u);
    EXPECT_FALSE(chain.tip().has_value());
}

TEST_F(DOGEHeaderChainTest, DynamicCheckpoint) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());

    uint256 cp_hash;
    cp_hash.SetHex("5fa04946dfea30cb31f681a176003333b39fefab34a50dac213d33330aaf6e25");
    chain.set_dynamic_checkpoint(23000, cp_hash);
    EXPECT_EQ(chain.height(), 23000u);
    EXPECT_EQ(chain.size(), 1u);
}

TEST_F(DOGEHeaderChainTest, PeerTipHeight) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());
    chain.set_peer_tip_height(23625);
    // Should not crash — just stores the value for fast-sync threshold
}

TEST_F(DOGEHeaderChainTest, EmptyChainLocatorReturnsGenesis) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());
    EXPECT_EQ(chain.size(), 0u);

    // Empty chain should return genesis hash in locator so peers know where to start
    auto locator = chain.get_locator();
    ASSERT_EQ(locator.size(), 1u);
    EXPECT_EQ(locator[0], params.genesis_hash);
}

TEST_F(DOGEHeaderChainTest, SyncGateNotSyncedWhenEmpty) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());
    EXPECT_FALSE(chain.is_synced());
}

// ─── Template Builder Tests ─────────────────────────────────────────────────

TEST(DOGETemplateTest, BlockVersionIsAuxPoW) {
    EXPECT_EQ(TemplateBuilder::BLOCK_VERSION, 6422786);
    // 6422786 = 0x00620002 — AuxPoW with chain ID 98
    EXPECT_EQ(TemplateBuilder::BLOCK_VERSION >> 16, 0x0062);
}
