/// Phase 1 — HeaderChain unit tests
///
/// Tests the LTC header chain implementation:
///   1. Chain parameter creation (mainnet/testnet)
///   2. PoW helper functions (scrypt_hash, check_pow, target_from_bits, get_block_proof)
///   3. Difficulty retarget calculation
///   4. HeaderChain: genesis insertion, header addition, chain tip tracking
///   5. HeaderChain: block locator generation
///   6. HeaderChain: LevelDB persistence round-trip
///   7. HeaderChain: rejection of invalid PoW and orphan headers

#include <gtest/gtest.h>

#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/block.hpp>
#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

#include <filesystem>
#include <vector>
#include <cstdint>

using namespace ltc::coin;

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Construct the LTC testnet genesis block header.
/// Params from Litecoin Core: CreateGenesisBlock(1486949366, 293345, 0x1e0ffff0, 1, 50*COIN)
/// Merkle root: 97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9
static BlockHeaderType make_testnet_genesis() {
    BlockHeaderType hdr;
    hdr.m_version = 1;
    hdr.m_previous_block.SetNull();
    hdr.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    hdr.m_timestamp = 1486949366;
    hdr.m_bits = 0x1e0ffff0;
    hdr.m_nonce = 293345;
    return hdr;
}

/// Construct the LTC mainnet genesis block header.
/// Params: CreateGenesisBlock(1317972665, 2084524493, 0x1e0ffff0, 1, 50*COIN)
static BlockHeaderType make_mainnet_genesis() {
    BlockHeaderType hdr;
    hdr.m_version = 1;
    hdr.m_previous_block.SetNull();
    hdr.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    hdr.m_timestamp = 1317972665;
    hdr.m_bits = 0x1e0ffff0;
    hdr.m_nonce = 2084524493;
    return hdr;
}

// ─── Chain Params Tests ─────────────────────────────────────────────────────

TEST(LTCChainParamsTest, MainnetDefaults) {
    auto p = LTCChainParams::mainnet();
    EXPECT_EQ(p.target_timespan, 302400);
    EXPECT_EQ(p.target_spacing, 150);
    EXPECT_FALSE(p.allow_min_difficulty);
    EXPECT_FALSE(p.no_retargeting);
    EXPECT_EQ(p.difficulty_adjustment_interval(), 2016);
    EXPECT_FALSE(p.pow_limit.IsNull());

    uint256 expected_genesis;
    expected_genesis.SetHex("12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2");
    EXPECT_EQ(p.genesis_hash, expected_genesis);
}

TEST(LTCChainParamsTest, TestnetDefaults) {
    auto p = LTCChainParams::testnet();
    EXPECT_EQ(p.target_timespan, 302400);
    EXPECT_EQ(p.target_spacing, 150);
    EXPECT_TRUE(p.allow_min_difficulty);
    EXPECT_FALSE(p.no_retargeting);
    EXPECT_EQ(p.difficulty_adjustment_interval(), 2016);

    uint256 expected_genesis;
    expected_genesis.SetHex("4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0");
    EXPECT_EQ(p.genesis_hash, expected_genesis);
}

// ─── PoW Function Tests ─────────────────────────────────────────────────────

TEST(PoWFunctionsTest, BlockHashMatchesTestnetGenesis) {
    auto genesis = make_testnet_genesis();
    uint256 hash = block_hash(genesis);

    uint256 expected;
    expected.SetHex("4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0");
    EXPECT_EQ(hash, expected)
        << "SHA256d of testnet genesis header should match known hash"
        << "\n  got: " << hash.GetHex()
        << "\n  exp: " << expected.GetHex();
}

TEST(PoWFunctionsTest, BlockHashMatchesMainnetGenesis) {
    auto genesis = make_mainnet_genesis();
    uint256 hash = block_hash(genesis);

    uint256 expected;
    expected.SetHex("12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2");
    EXPECT_EQ(hash, expected)
        << "SHA256d of mainnet genesis header should match known hash"
        << "\n  got: " << hash.GetHex()
        << "\n  exp: " << expected.GetHex();
}

TEST(PoWFunctionsTest, ScryptHashMeetsTarget) {
    auto genesis = make_testnet_genesis();
    uint256 pow_hash = scrypt_hash(genesis);

    // The scrypt hash of the genesis block must be below the target
    // nBits = 0x1e0ffff0 → very high target (easy difficulty)
    uint256 target = target_from_bits(0x1e0ffff0);

    EXPECT_LE(pow_hash, target)
        << "Scrypt hash of testnet genesis should be below target"
        << "\n  hash:   " << pow_hash.GetHex()
        << "\n  target: " << target.GetHex();
}

TEST(PoWFunctionsTest, CheckPowValid) {
    auto genesis = make_testnet_genesis();
    uint256 pow_hash = scrypt_hash(genesis);
    uint256 pow_limit;
    pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    EXPECT_TRUE(check_pow(pow_hash, genesis.m_bits, pow_limit));
}

TEST(PoWFunctionsTest, CheckPowInvalidHighHash) {
    // A hash of all 0xff should never pass PoW check
    uint256 high_hash;
    high_hash.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    uint256 pow_limit;
    pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    EXPECT_FALSE(check_pow(high_hash, 0x1e0ffff0, pow_limit));
}

TEST(PoWFunctionsTest, TargetFromBitsRoundTrip) {
    uint256 target = target_from_bits(0x1e0ffff0);
    uint32_t bits_back = target.GetCompact();
    // The round-trip should preserve the value (for valid compact representations)
    EXPECT_EQ(bits_back, 0x1e0ffff0u);
}

TEST(PoWFunctionsTest, GetBlockProofPositive) {
    uint256 work = get_block_proof(0x1e0ffff0);
    EXPECT_FALSE(work.IsNull())
        << "Block proof for valid nBits should be non-zero";
}

TEST(PoWFunctionsTest, GetBlockProofInvalid) {
    // nBits = 0 → null target → zero work
    uint256 work = get_block_proof(0);
    EXPECT_TRUE(work.IsNull());
}

// ─── Difficulty Retarget Tests ──────────────────────────────────────────────

TEST(DifficultyRetargetTest, NoChangeWithinInterval) {
    // At heights that are NOT multiples of 2016, difficulty should stay the same
    auto params = LTCChainParams::testnet();
    // Disable min-diff for this test to get deterministic behavior
    params.allow_min_difficulty = false;

    auto get_ancestor = [](uint32_t h) -> std::optional<IndexEntry> {
        return std::nullopt;
    };

    uint32_t tip_bits = 0x1e0ffff0;
    uint32_t tip_height = 100;  // Not a multiple of 2016

    uint32_t result = get_next_work_required(
        get_ancestor, tip_height, tip_bits, 1486949366, 1486949516, params);

    EXPECT_EQ(result, tip_bits)
        << "Difficulty should not change at non-interval heights";
}

TEST(DifficultyRetargetTest, RetargetAtInterval) {
    // At a retarget boundary (multiple of 2016), difficulty should change
    // based on actual vs target timespan
    auto params = LTCChainParams::testnet();
    params.allow_min_difficulty = false;

    uint32_t tip_bits = 0x1e0ffff0;
    uint32_t tip_height = 2015; // Next block is 2016, which is the first retarget
    uint32_t tip_time = 1486949366 + 302400; // exactly target timespan
    uint32_t first_block_time = 1486949366;

    // Build a mock ancestor function that returns the genesis at height 0
    IndexEntry genesis_entry;
    genesis_entry.height = 0;
    genesis_entry.header.m_timestamp = first_block_time;
    genesis_entry.header.m_bits = tip_bits;

    auto get_ancestor = [&](uint32_t h) -> std::optional<IndexEntry> {
        if (h == 0) return genesis_entry;
        return std::nullopt;
    };

    uint32_t result = get_next_work_required(
        get_ancestor, tip_height, tip_bits, tip_time, tip_time + 150, params);

    // With exactly target timespan elapsed, difficulty should stay the same
    EXPECT_EQ(result, tip_bits)
        << "With exact target timespan, difficulty should not change";
}

TEST(DifficultyRetargetTest, RetargetFasterThanExpected) {
    auto params = LTCChainParams::testnet();
    params.allow_min_difficulty = false;

    uint32_t tip_bits = 0x1e0ffff0;
    // If blocks arrived 4x faster than expected, actual timespan = target/4
    // Difficulty should increase (lower target)
    uint32_t actual_timespan = params.target_timespan / 4;

    uint32_t result = calculate_next_work_required(
        tip_bits, actual_timespan, 0, params);

    // Since actual = target/4 (minimum clamp), target stays same
    // (clamped at exactly 1/4, so new_target = old_target * (target/4) / target = old_target / 4... wait)
    // Actually: actual_timespan is clamped to target/4 minimum, so:
    // new_target = old_target * (target/4) / target = old_target * 1/4 ... but target/4 is the clamp
    // So the answer is the same as with 1/4 ratio.
    // The result should be a harder difficulty (lower bits mantissa or lower exponent)

    // Just verify it changed and is harder (smaller compact value means harder)
    // Actually this isn't straightforward with compact encoding. Just verify the target decreased.
    uint256 old_target = target_from_bits(tip_bits);
    uint256 new_target = target_from_bits(result);
    EXPECT_LE(new_target, old_target)
        << "Target should decrease (harder difficulty) when blocks are faster";
}

TEST(DifficultyRetargetTest, RetargetSlowerThanExpected) {
    auto params = LTCChainParams::testnet();
    params.allow_min_difficulty = false;

    uint32_t tip_bits = 0x1e0ffff0;
    // If blocks arrived 4x slower, actual timespan = target*4
    uint32_t actual_timespan = params.target_timespan * 4;

    uint32_t result = calculate_next_work_required(
        tip_bits, actual_timespan, 0, params);

    uint256 old_target = target_from_bits(tip_bits);
    uint256 new_target = target_from_bits(result);
    EXPECT_GE(new_target, old_target)
        << "Target should increase (easier difficulty) when blocks are slower";
}

TEST(DifficultyRetargetTest, NoRetargetingFlag) {
    auto params = LTCChainParams::testnet();
    params.no_retargeting = true;

    uint32_t tip_bits = 0x1e0ffff0;
    uint32_t result = calculate_next_work_required(tip_bits, 999999, 0, params);

    EXPECT_EQ(result, tip_bits)
        << "With no_retargeting=true, difficulty should never change";
}

TEST(DifficultyRetargetTest, TestnetMinDiffRule) {
    // Testnet rule: if >2x target spacing since last block, allow min-diff
    auto params = LTCChainParams::testnet();
    ASSERT_TRUE(params.allow_min_difficulty);

    uint256 pow_limit = params.pow_limit;
    uint32_t pow_limit_bits = pow_limit.GetCompact();

    uint32_t tip_bits = 0x1c00ff00; // some non-trivial difficulty
    uint32_t tip_height = 100;
    uint32_t tip_time = 1486949366;
    uint32_t new_time = tip_time + params.target_spacing * 3; // >2x spacing

    auto get_ancestor = [](uint32_t h) -> std::optional<IndexEntry> {
        return std::nullopt;
    };

    uint32_t result = get_next_work_required(
        get_ancestor, tip_height, tip_bits, tip_time, new_time, params);

    EXPECT_EQ(result, pow_limit_bits)
        << "Should return min-diff when gap exceeds 2x target spacing on testnet";
}

// ─── HeaderChain Tests ──────────────────────────────────────────────────────

class HeaderChainTest : public ::testing::Test {
protected:
    LTCChainParams params = LTCChainParams::testnet();

    void SetUp() override {}
};

TEST_F(HeaderChainTest, EmptyChainState) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());
    EXPECT_EQ(chain.height(), 0u);
    EXPECT_EQ(chain.size(), 0u);
    EXPECT_FALSE(chain.tip().has_value());
    EXPECT_TRUE(chain.cumulative_work().IsNull());
    EXPECT_FALSE(chain.is_synced());
}

TEST_F(HeaderChainTest, AddTestnetGenesis) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());

    auto genesis = make_testnet_genesis();
    EXPECT_TRUE(chain.add_header(genesis));

    EXPECT_EQ(chain.size(), 1u);
    EXPECT_EQ(chain.height(), 0u);

    auto tip = chain.tip();
    ASSERT_TRUE(tip.has_value());
    EXPECT_EQ(tip->height, 0u);
    EXPECT_EQ(tip->block_hash, params.genesis_hash);
    EXPECT_EQ(tip->status, HEADER_VALID_CHAIN);
    EXPECT_FALSE(tip->chain_work.IsNull());
}

TEST_F(HeaderChainTest, RejectsWrongGenesis) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());

    // Construct a genesis with wrong nonce
    auto bad_genesis = make_testnet_genesis();
    bad_genesis.m_nonce = 12345; // wrong nonce

    EXPECT_FALSE(chain.add_header(bad_genesis))
        << "Genesis with wrong hash should be rejected";
    EXPECT_EQ(chain.size(), 0u);
}

TEST_F(HeaderChainTest, RejectsDuplicateGenesis) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());

    auto genesis = make_testnet_genesis();
    EXPECT_TRUE(chain.add_header(genesis));
    EXPECT_FALSE(chain.add_header(genesis))
        << "Duplicate header should be rejected (already known)";
    EXPECT_EQ(chain.size(), 1u);
}

TEST_F(HeaderChainTest, RejectsOrphanHeader) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());

    // Don't add genesis first — try to add a header that points to unknown prev
    BlockHeaderType orphan;
    orphan.m_version = 1;
    orphan.m_previous_block.SetHex("deadbeef00000000000000000000000000000000000000000000000000000000");
    orphan.m_merkle_root.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    orphan.m_timestamp = 1486949500;
    orphan.m_bits = 0x1e0ffff0;
    orphan.m_nonce = 1;

    EXPECT_FALSE(chain.add_header(orphan))
        << "Header with unknown prev_hash should be rejected";
    EXPECT_EQ(chain.size(), 0u);
}

TEST_F(HeaderChainTest, GetHeaderByHash) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());

    auto genesis = make_testnet_genesis();
    chain.add_header(genesis);

    auto entry = chain.get_header(params.genesis_hash);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->height, 0u);
    EXPECT_EQ(entry->block_hash, params.genesis_hash);
}

TEST_F(HeaderChainTest, GetHeaderByHeight) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());

    auto genesis = make_testnet_genesis();
    chain.add_header(genesis);

    auto entry = chain.get_header_by_height(0);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->block_hash, params.genesis_hash);

    // Non-existent height
    auto none = chain.get_header_by_height(1);
    EXPECT_FALSE(none.has_value());
}

TEST_F(HeaderChainTest, HasHeader) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());

    auto genesis = make_testnet_genesis();
    chain.add_header(genesis);

    EXPECT_TRUE(chain.has_header(params.genesis_hash));

    uint256 fake;
    fake.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    EXPECT_FALSE(chain.has_header(fake));
}

TEST_F(HeaderChainTest, IsConnected) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());

    auto genesis = make_testnet_genesis();
    chain.add_header(genesis);

    // Genesis hash is in the chain, so it's "connected"
    EXPECT_TRUE(chain.is_connected(params.genesis_hash));

    uint256 fake;
    fake.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    EXPECT_FALSE(chain.is_connected(fake));
}

TEST_F(HeaderChainTest, LocatorWithGenesis) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());

    auto genesis = make_testnet_genesis();
    chain.add_header(genesis);

    auto locator = chain.get_locator();
    ASSERT_GE(locator.size(), 1u);
    EXPECT_EQ(locator[0], params.genesis_hash);
}

TEST_F(HeaderChainTest, LocatorEmptyChain) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());

    auto locator = chain.get_locator();
    EXPECT_TRUE(locator.empty());
}

TEST_F(HeaderChainTest, AddHeadersBatch) {
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());

    auto genesis = make_testnet_genesis();
    std::vector<BlockHeaderType> batch = {genesis};
    int accepted = chain.add_headers(batch);
    EXPECT_EQ(accepted, 1);
    EXPECT_EQ(chain.size(), 1u);

    // Adding again should accept 0
    accepted = chain.add_headers(batch);
    EXPECT_EQ(accepted, 0);
}

// ─── LevelDB Persistence Tests ─────────────────────────────────────────────

class HeaderChainPersistenceTest : public ::testing::Test {
protected:
    std::string db_path;

    void SetUp() override {
        db_path = "/tmp/c2pool_test_hchain_" + std::to_string(::getpid());
        std::filesystem::remove_all(db_path);
    }
    void TearDown() override {
        std::filesystem::remove_all(db_path);
    }
};

TEST_F(HeaderChainPersistenceTest, PersistAndReload) {
    auto params = LTCChainParams::testnet();

    // Write genesis to DB
    {
        HeaderChain chain(params, db_path);
        ASSERT_TRUE(chain.init());

        auto genesis = make_testnet_genesis();
        EXPECT_TRUE(chain.add_header(genesis));
        EXPECT_EQ(chain.size(), 1u);
        EXPECT_EQ(chain.height(), 0u);

        auto tip = chain.tip();
        ASSERT_TRUE(tip.has_value());
        EXPECT_EQ(tip->block_hash, params.genesis_hash);
    }

    // Reload from DB
    {
        HeaderChain chain(params, db_path);
        ASSERT_TRUE(chain.init());

        EXPECT_EQ(chain.size(), 1u);
        EXPECT_EQ(chain.height(), 0u);

        auto tip = chain.tip();
        ASSERT_TRUE(tip.has_value());
        EXPECT_EQ(tip->block_hash, params.genesis_hash);
        EXPECT_EQ(tip->height, 0u);

        // Can still look up by hash
        auto entry = chain.get_header(params.genesis_hash);
        ASSERT_TRUE(entry.has_value());
        EXPECT_EQ(entry->header.m_timestamp, 1486949366u);
        EXPECT_EQ(entry->header.m_nonce, 293345u);
        EXPECT_EQ(entry->header.m_bits, 0x1e0ffff0u);
    }
}

TEST_F(HeaderChainPersistenceTest, EmptyDBLoadsClean) {
    auto params = LTCChainParams::testnet();

    HeaderChain chain(params, db_path);
    ASSERT_TRUE(chain.init());

    EXPECT_EQ(chain.size(), 0u);
    EXPECT_FALSE(chain.tip().has_value());
}

// ─── IndexEntry Serialization Test ──────────────────────────────────────────

TEST(IndexEntryTest, SerializeRoundTrip) {
    IndexEntry entry;
    entry.header = make_testnet_genesis();
    entry.hash.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    entry.block_hash.SetHex("4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0");
    entry.height = 42;
    entry.chain_work.SetHex("0000000000000000000000000000000000000000000000000000000000001000");
    entry.prev_hash.SetNull();
    entry.status = HEADER_VALID_CHAIN;

    // Serialize
    auto packed = pack(entry);

    // Deserialize
    PackStream ps(std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(packed.data()),
        reinterpret_cast<const unsigned char*>(packed.data()) + packed.size()));
    IndexEntry restored;
    ps >> restored;

    EXPECT_EQ(restored.hash, entry.hash);
    EXPECT_EQ(restored.block_hash, entry.block_hash);
    EXPECT_EQ(restored.height, entry.height);
    EXPECT_EQ(restored.chain_work, entry.chain_work);
    EXPECT_EQ(restored.prev_hash, entry.prev_hash);
    EXPECT_EQ(restored.status, entry.status);
    EXPECT_EQ(restored.header.m_version, entry.header.m_version);
    EXPECT_EQ(restored.header.m_timestamp, entry.header.m_timestamp);
    EXPECT_EQ(restored.header.m_bits, entry.header.m_bits);
    EXPECT_EQ(restored.header.m_nonce, entry.header.m_nonce);
    EXPECT_EQ(restored.header.m_merkle_root, entry.header.m_merkle_root);
}

// ─── Mainnet Genesis Scrypt Test ────────────────────────────────────────────

TEST(PoWFunctionsTest, MainnetGenesisScryptValid) {
    auto genesis = make_mainnet_genesis();
    uint256 pow_hash = scrypt_hash(genesis);
    uint256 pow_limit;
    pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    EXPECT_TRUE(check_pow(pow_hash, genesis.m_bits, pow_limit))
        << "Mainnet genesis scrypt hash should pass PoW check"
        << "\n  hash: " << pow_hash.GetHex();
}
