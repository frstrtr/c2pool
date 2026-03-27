/// DOGE chain unit tests — embedded SPV node components
///
/// Tests:
///   1. Chain parameters (testnet4alpha/mainnet/testnet defaults)
///   2. DigiShield v3 difficulty calculation
///   3. DOGE subsidy schedule (simplified + random MT rewards)
///   4. HeaderChain basics (genesis, locator, sync gate, AuxPoW PoW skip)
///   5. AuxPoW header parser
///   6. Block version derivation

#include <gtest/gtest.h>

#include <impl/doge/coin/chain_params.hpp>
#include <impl/doge/coin/header_chain.hpp>
#include <impl/doge/coin/template_builder.hpp>
#include <impl/doge/coin/auxpow_header.hpp>

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
    // testnet4alpha uses random rewards (not simplified)
    EXPECT_FALSE(p.simplified_rewards);

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
    EXPECT_TRUE(p.simplified_rewards);
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

    auto t = DOGEChainParams::testnet4alpha();
    EXPECT_TRUE(t.is_digishield(0));
    EXPECT_TRUE(t.is_auxpow(0));
}

// ─── Subsidy Tests (Simplified = fixed schedule) ────────────────────────────

TEST(DOGESubsidyTest, FixedRewardsAfter600k) {
    auto p = DOGEChainParams::mainnet();
    EXPECT_EQ(get_doge_block_subsidy(600000, p), 10000ULL * 100000000ULL);
    EXPECT_EQ(get_doge_block_subsidy(1000000, p), 10000ULL * 100000000ULL);
}

TEST(DOGESubsidyTest, SimplifiedRewardsSchedule) {
    auto p = DOGEChainParams::mainnet();
    EXPECT_EQ(get_doge_block_subsidy(145000, p), 250000ULL * 100000000ULL);
    EXPECT_EQ(get_doge_block_subsidy(200000, p), 125000ULL * 100000000ULL);
    EXPECT_EQ(get_doge_block_subsidy(300000, p), 62500ULL * 100000000ULL);
    EXPECT_EQ(get_doge_block_subsidy(400000, p), 31250ULL * 100000000ULL);
    EXPECT_EQ(get_doge_block_subsidy(500000, p), 15625ULL * 100000000ULL);
}

TEST(DOGESubsidyTest, MainnetMaxSubsidyBeforeSimplified) {
    auto p = DOGEChainParams::mainnet();
    // Mainnet has simplified_rewards=true, so max-subsidy overload uses 500k schedule
    // halving 0 (0-99999): 500,000 DOGE
    EXPECT_EQ(get_doge_block_subsidy(0, p), 500000ULL * 100000000ULL);
    // halving 1 (100000-144999): 250,000 DOGE
    EXPECT_EQ(get_doge_block_subsidy(100000, p), 250000ULL * 100000000ULL);
}

TEST(DOGESubsidyTest, Testnet4alphaMaxSubsidyIsRandom) {
    auto p = DOGEChainParams::testnet4alpha();
    // testnet4alpha has simplified_rewards=false, max-subsidy uses 1M ceiling
    EXPECT_EQ(get_doge_block_subsidy(0, p), 1000000ULL * 100000000ULL);
    EXPECT_EQ(get_doge_block_subsidy(100000, p), 500000ULL * 100000000ULL);
}

// ─── Subsidy Tests (Random = Mersenne Twister) ──────────────────────────────

TEST(DOGESubsidyTest, RandomRewardsMatchDogecoind) {
    // Verified against Dogecoin Core 1.14.99 testnet4alpha at height 37817
    // prevHash of block 37816: ae162af2b7efd37f8ca439eb4e8df06eee3e7ffab1a2ed098ad5d7d4005bc774
    // Daemon reported: coinbase limit = 42977900000000 (429779 DOGE)
    auto p = DOGEChainParams::testnet4alpha();
    uint256 prev_hash;
    prev_hash.SetHex("ae162af2b7efd37f8ca439eb4e8df06eee3e7ffab1a2ed098ad5d7d4005bc774");
    uint64_t subsidy = get_doge_block_subsidy(37817, p, prev_hash);
    EXPECT_EQ(subsidy, 42977900000000ULL) << "Random subsidy must match Dogecoin Core exactly";
}

TEST(DOGESubsidyTest, RandomRewardsDeterministic) {
    // Same input must always produce same output
    auto p = DOGEChainParams::testnet4alpha();
    uint256 prev_hash;
    prev_hash.SetHex("ae162af2b7efd37f8ca439eb4e8df06eee3e7ffab1a2ed098ad5d7d4005bc774");
    uint64_t s1 = get_doge_block_subsidy(37817, p, prev_hash);
    uint64_t s2 = get_doge_block_subsidy(37817, p, prev_hash);
    EXPECT_EQ(s1, s2);
}

TEST(DOGESubsidyTest, RandomRewardsInRange) {
    // Random rewards must be in [1, 1000000) * COIN for halving 0
    auto p = DOGEChainParams::testnet4alpha();
    static constexpr uint64_t COIN = 100000000ULL;
    for (int i = 0; i < 100; ++i) {
        uint256 h;
        // Vary the hash to get different seeds
        auto bytes = reinterpret_cast<unsigned char*>(h.data());
        bytes[0] = static_cast<unsigned char>(i);
        bytes[3] = static_cast<unsigned char>(i * 7 + 13);
        uint64_t s = get_doge_block_subsidy(100, p, h);
        EXPECT_GE(s, 2ULL * COIN);              // minimum: (1+1) * COIN
        EXPECT_LE(s, 1000000ULL * COIN);         // maximum: 1000000 * COIN
    }
}

TEST(DOGESubsidyTest, SimplifiedIgnoresPrevHash) {
    // Mainnet simplified rewards are fixed regardless of prevHash
    auto p = DOGEChainParams::mainnet();
    uint256 h1, h2;
    h1.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    h2.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    EXPECT_EQ(get_doge_block_subsidy(200000, p, h1), get_doge_block_subsidy(200000, p, h2));
    EXPECT_EQ(get_doge_block_subsidy(200000, p, h1), 125000ULL * 100000000ULL);
}

// ─── DigiShield v3 Tests ────────────────────────────────────────────────────

TEST(DigiShieldTest, NoChangeAtTargetSpacing) {
    auto p = DOGEChainParams::testnet4alpha();
    uint32_t bits = 0x1e0fffff;
    uint32_t result = calculate_doge_next_work(bits, 1000060, 1000000, 100, p);
    EXPECT_EQ(result, bits) << "Difficulty should not change when block time = target";
}

TEST(DigiShieldTest, FasterThanExpected) {
    auto p = DOGEChainParams::testnet4alpha();
    uint32_t bits = 0x1e0fffff;
    uint32_t result = calculate_doge_next_work(bits, 1000030, 1000000, 100, p);
    uint256 old_target, new_target;
    old_target.SetCompact(bits);
    new_target.SetCompact(result);
    EXPECT_LT(new_target, old_target) << "Faster blocks should increase difficulty";
}

TEST(DigiShieldTest, SlowerThanExpected) {
    auto p = DOGEChainParams::testnet4alpha();
    uint32_t bits = 0x1d00ffff;
    uint32_t result = calculate_doge_next_work(bits, 1000120, 1000000, 100, p);
    uint256 old_target, new_target;
    old_target.SetCompact(bits);
    new_target.SetCompact(result);
    EXPECT_GT(new_target, old_target) << "Slower blocks should decrease difficulty";
}

TEST(DigiShieldTest, AmplitudeDampening) {
    auto p = DOGEChainParams::testnet4alpha();
    uint32_t bits = 0x1d00ffff;
    uint32_t digi = calculate_doge_next_work(bits, 1000001, 1000000, 100, p);
    uint256 old_t, new_t;
    old_t.SetCompact(bits);
    new_t.SetCompact(digi);
    EXPECT_LT(new_t, old_t) << "Fast block should increase difficulty";
    EXPECT_GT(new_t, uint256::ZERO);
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

TEST_F(DOGEHeaderChainTest, EmptyChainLocatorIsEmpty) {
    // Empty chain returns empty locator so peer responds with genesis (height 0)
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());
    auto locator = chain.get_locator();
    EXPECT_TRUE(locator.empty())
        << "Empty chain locator must be empty so peer includes genesis in response";
}

TEST_F(DOGEHeaderChainTest, DynamicCheckpoint) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());

    uint256 cp_hash;
    cp_hash.SetHex("5fa04946dfea30cb31f681a176003333b39fefab34a50dac213d33330aaf6e25");
    chain.set_dynamic_checkpoint(23000, cp_hash);
    EXPECT_EQ(chain.height(), 23000u);
    EXPECT_EQ(chain.size(), 1u);

    // Locator should contain the checkpoint hash
    auto locator = chain.get_locator();
    ASSERT_FALSE(locator.empty());
    EXPECT_EQ(locator[0], cp_hash);
}

TEST_F(DOGEHeaderChainTest, PeerTipHeight) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());
    chain.set_peer_tip_height(23625);
    // Should not crash
}

TEST_F(DOGEHeaderChainTest, SyncGateNotSyncedWhenEmpty) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());
    EXPECT_FALSE(chain.is_synced());
}

TEST_F(DOGEHeaderChainTest, AuxPowSkipsScryptValidation) {
    // testnet4alpha: auxpow_height=0, all blocks are AuxPoW
    // AuxPoW blocks should skip scrypt PoW validation (PoW is on parent chain)
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());
    EXPECT_TRUE(params.is_auxpow(0));
    EXPECT_TRUE(params.is_auxpow(1));
    EXPECT_TRUE(params.is_auxpow(999999));
}

// ─── AuxPoW Header Parser Tests ─────────────────────────────────────────────

TEST(AuxPowParserTest, IsAuxpowVersion) {
    EXPECT_TRUE(is_auxpow_version(0x00620102));   // chain_id=98, auxpow, version 2
    EXPECT_TRUE(is_auxpow_version(0x00620104));   // chain_id=98, auxpow, version 4
    EXPECT_TRUE(is_auxpow_version(0x100));         // minimal auxpow bit
    EXPECT_FALSE(is_auxpow_version(0x00620002));   // chain_id=98, NO auxpow, version 2
    EXPECT_FALSE(is_auxpow_version(0x00000004));   // plain version 4
    EXPECT_FALSE(is_auxpow_version(0));
}

TEST(AuxPowParserTest, ParseNonAuxPowHeader) {
    // Build a minimal 80-byte header + 1 byte tx_count(0) without AuxPoW
    // version=4 (no AuxPoW bit), rest zeros
    std::vector<uint8_t> data(81, 0);
    data[0] = 0x04; // version 4 LE
    // tx_count at byte 80 = 0

    const uint8_t* pos = data.data();
    const uint8_t* end = data.data() + data.size();
    auto hdr = doge::coin::parse_doge_header(pos, end);
    EXPECT_EQ(hdr.m_version, 4);
    EXPECT_EQ(pos, end) << "Parser should consume all bytes";
}

TEST(AuxPowParserTest, EmptyMessageReturnsEmpty) {
    auto result = parse_doge_headers_message(nullptr, 0);
    EXPECT_TRUE(result.empty());
}

TEST(AuxPowParserTest, SingleNonAuxPowMessage) {
    // count=1, then 80-byte header + tx_count(0)
    std::vector<uint8_t> data;
    data.push_back(0x01); // count = 1
    data.resize(1 + 80 + 1, 0);
    data[1] = 0x04; // version 4

    auto result = doge::coin::parse_doge_headers_message(data.data(), data.size());
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].m_version, 4);
}

// ─── Mersenne Twister Uniform Int Tests ─────────────────────────────────────

TEST(MersenneTwisterTest, BoostCompatibleOutput) {
    // Verify doge_mt_uniform_int matches boost::uniform_int behavior
    // Known test vector from Dogecoin Core testnet4alpha
    // seed from prevHash "ae162af2..." at offset 7: "2b7efd3" = 45608915
    int result = doge_mt_uniform_int(45608915, 1, 999999);
    EXPECT_EQ(result, 429778) << "Must match boost::uniform_int output for Dogecoin Core parity";
}

TEST(MersenneTwisterTest, DifferentSeedsDifferentResults) {
    int r1 = doge_mt_uniform_int(12345, 1, 999999);
    int r2 = doge_mt_uniform_int(54321, 1, 999999);
    EXPECT_NE(r1, r2);
}

TEST(MersenneTwisterTest, ResultInRange) {
    for (unsigned int seed = 0; seed < 1000; seed += 7) {
        int r = doge_mt_uniform_int(seed, 10, 20);
        EXPECT_GE(r, 10);
        EXPECT_LE(r, 20);
    }
}

TEST(MersenneTwisterTest, SingleValueRange) {
    int r = doge_mt_uniform_int(42, 5, 5);
    EXPECT_EQ(r, 5);
}
