// SPDX-License-Identifier: AGPL-3.0-or-later
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
///   8. HeaderChain: the genesis header is accepted only into a store with no tip

#include <gtest/gtest.h>

#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/header_sync.hpp>
#include <impl/ltc/test/ltc_mined_headers.hpp>   // easy-limit testnet parameters, mine()
#include <impl/ltc/coin/block.hpp>
#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/leveldb_store.hpp>

#include <chrono>
#include <ctime>
#include <deque>
#include <filesystem>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <thread>
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
    auto p = make_ltc_chain_params_mainnet();
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
    auto p = make_ltc_chain_params_testnet();
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
    auto params = make_ltc_chain_params_testnet();
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
    auto params = make_ltc_chain_params_testnet();
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
    auto params = make_ltc_chain_params_testnet();
    params.allow_min_difficulty = false;

    uint32_t tip_bits = 0x1e0ffff0;
    // If blocks arrived 4x faster than expected, actual timespan = target/4
    // Difficulty should increase (lower target)
    uint32_t actual_timespan = params.target_timespan / 4;

    uint32_t result = ltc::coin::calculate_next_work_required(
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
    auto params = make_ltc_chain_params_testnet();
    params.allow_min_difficulty = false;

    uint32_t tip_bits = 0x1e0ffff0;
    // If blocks arrived 4x slower, actual timespan = target*4
    uint32_t actual_timespan = params.target_timespan * 4;

    uint32_t result = ltc::coin::calculate_next_work_required(
        tip_bits, actual_timespan, 0, params);

    uint256 old_target = target_from_bits(tip_bits);
    uint256 new_target = target_from_bits(result);
    EXPECT_GE(new_target, old_target)
        << "Target should increase (easier difficulty) when blocks are slower";
}

TEST(DifficultyRetargetTest, NoRetargetingFlag) {
    auto params = make_ltc_chain_params_testnet();
    params.no_retargeting = true;

    uint32_t tip_bits = 0x1e0ffff0;
    uint32_t result = ltc::coin::calculate_next_work_required(tip_bits, 999999, 0, params);

    EXPECT_EQ(result, tip_bits)
        << "With no_retargeting=true, difficulty should never change";
}

TEST(DifficultyRetargetTest, TestnetMinDiffRule) {
    // Testnet rule: if >2x target spacing since last block, allow min-diff
    auto params = make_ltc_chain_params_testnet();
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
    LTCChainParams params = make_ltc_chain_params_testnet();

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
    auto params = make_ltc_chain_params_testnet();

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
    auto params = make_ltc_chain_params_testnet();

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

// ─── Fast-Sync Scrypt Skip Tests ────────────────────────────────────────────

// Every header above the checkpoint has its scrypt PoW checked (Litecoin
// Core's CheckBlockHeader), however far ahead a peer says its tip is: the
// reported height only paces the sync.
TEST_F(HeaderChainTest, APeerTipFarAheadDoesNotSkipThePowCheck) {
    const auto easy = ltc_test::easy_testnet_params();
    HeaderChain chain(easy);
    EXPECT_TRUE(chain.init());
    chain.set_peer_tip_height(1000000);

    const auto genesis = ltc_test::easy_testnet_genesis();
    ASSERT_TRUE(chain.add_header(genesis));
    BlockHeaderType h;
    h.m_version = 0x20000000;
    h.m_previous_block = block_hash(genesis);
    h.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
    h.m_timestamp = genesis.m_timestamp + 150;
    h.m_bits = genesis.m_bits;
    h.m_nonce = 0;
    ltc_test::unmine(h, easy);
    EXPECT_FALSE(chain.add_header(h)) << "a header failing its PoW is refused";
    EXPECT_EQ(chain.height(), 0u);
    ltc_test::mine(h, easy);
    EXPECT_TRUE(chain.add_header(h));
    EXPECT_EQ(chain.height(), 1u);
}

TEST_F(HeaderChainTest, FastSyncDefaultIsZeroPeerTip) {
    // With default peer_tip_height=0, all headers should be scrypt-validated.
    // Genesis should still pass (it has valid scrypt PoW).
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());

    auto genesis = make_testnet_genesis();
    EXPECT_TRUE(chain.add_header(genesis));
    EXPECT_EQ(chain.height(), 0u);
}

TEST_F(HeaderChainTest, PeerTipHeightIsAtomic) {
    // set_peer_tip_height should be safe to call from any thread
    HeaderChain chain(params);
    EXPECT_TRUE(chain.init());

    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&chain, i]() {
            chain.set_peer_tip_height(100000 + i * 1000);
        });
    }
    for (auto& t : threads) t.join();

    // No crash, no data race — the final value is one of the written values
    // (no specific ordering guarantee with relaxed atomics)
}
// ─── Known headers cost no yield (FRESH-NODE §3) ────────────────────────────

/// `n` headers linked on top of the easy-limit testnet genesis
/// (ltc_mined_headers.hpp), 150 s apart, the genesis bits, each mined: every
/// header's PoW is checked. Below interval + 10 headers the difficulty is
/// not checked.
static std::vector<BlockHeaderType> make_linked_headers(size_t n) {
    const auto easy = ltc_test::easy_testnet_params();
    std::vector<BlockHeaderType> out;
    out.reserve(n);
    BlockHeaderType prev = ltc_test::easy_testnet_genesis();
    uint256 prev_hash = block_hash(prev);
    for (size_t i = 0; i < n; ++i) {
        BlockHeaderType h;
        h.m_version = 0x20000000;
        h.m_previous_block = prev_hash;
        h.m_merkle_root.SetHex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9");
        h.m_timestamp = prev.m_timestamp + 150;
        h.m_bits = prev.m_bits;
        h.m_nonce = static_cast<uint32_t>(i) << 8;   // a distinct start per header
        ltc_test::mine(h, easy);
        prev_hash = block_hash(h);
        prev = h;
        out.push_back(h);
    }
    return out;
}

// A 2,000-header batch the chain already has, at the tip (50-header
// sub-batches): before, 39 sleeps of 10 ms (~390 ms) per duplicate batch,
// which let 20 peers' duplicates queue up faster than the header thread
// drained them (the fresh node's 2.5 GB).
TEST_F(HeaderChainTest, ADuplicateBatchCostsNoYield) {
    HeaderChain chain(ltc_test::easy_testnet_params());
    ASSERT_TRUE(chain.init());
    chain.set_peer_tip_height(1000000);
    ASSERT_TRUE(chain.add_header(ltc_test::easy_testnet_genesis()));
    const auto batch = make_linked_headers(2000);
    ASSERT_EQ(chain.add_headers(batch), 2000);
    ASSERT_EQ(chain.height(), 2000u);

    chain.set_peer_tip_height(chain.height());  // at the tip: 50-header sub-batches
    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_EQ(chain.add_headers(batch), 0);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    EXPECT_LT(ms, 10) << "a batch of 2,000 known headers at the tip took " << ms << " ms";
}

// The early return is for a known LAST header only: a batch whose head the
// chain has and whose tail is new still connects the tail.
TEST_F(HeaderChainTest, AKnownPrefixStillConnectsTheNewTail) {
    HeaderChain chain(ltc_test::easy_testnet_params());
    ASSERT_TRUE(chain.init());
    chain.set_peer_tip_height(1000000);
    ASSERT_TRUE(chain.add_header(ltc_test::easy_testnet_genesis()));
    const auto batch = make_linked_headers(2000);
    const std::vector<BlockHeaderType> head(batch.begin(), batch.begin() + 1500);
    ASSERT_EQ(chain.add_headers(head), 1500);
    EXPECT_EQ(chain.add_headers(batch), 500);
    EXPECT_EQ(chain.height(), 2000u);
    EXPECT_EQ(chain.add_headers(batch), 0);
}

// ─── The genesis header and a store with no tip ────────────────────────────
//
// The genesis header is accepted only while the store has no tip. A store
// with a tip (a checkpoint root, then headers above it) keeps its tip, height
// and best work.

namespace {

/// Headers by height from the easy-limit testnet genesis
/// (ltc_mined_headers.hpp): timestamps years old up to the checkpoint, within
/// the last hour above it. getheaders returns heights up to `served`.
struct HonestLtcChain {
    std::vector<BlockHeaderType> headers;  // by height
    std::map<uint256, uint32_t> height_of;
    uint32_t cp;
    uint32_t served;

    HonestLtcChain(uint32_t cp_height, uint32_t top, uint32_t served_top)
        : cp(cp_height), served(served_top)
    {
        const auto easy = ltc_test::easy_testnet_params();
        const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
        headers.push_back(ltc_test::easy_testnet_genesis());
        height_of[block_hash(headers[0])] = 0;
        for (uint32_t h = 1; h <= top; ++h) {
            BlockHeaderType x;
            x.m_version = 0x20000000;
            x.m_previous_block = block_hash(headers.back());
            x.m_merkle_root.SetHex(std::to_string(5000 + h));
            x.m_timestamp = h <= cp ? headers[0].m_timestamp + 150 * h : now - 60 - 150 * (top - h);
            x.m_bits = ltc_test::kEasyBits;
            x.m_nonce = h << 8;
            ltc_test::mine(x, easy);
            height_of[block_hash(x)] = h;
            headers.push_back(x);
        }
    }

    const BlockHeaderType& at(uint32_t h) const { return headers.at(h); }
    uint256 hash(uint32_t h) const { return block_hash(headers.at(h)); }

    /// getheaders as Litecoin Core answers it: the headers after the first
    /// locator hash on this chain (none on it: after genesis), at most `max`.
    std::vector<BlockHeaderType> getheaders(const std::vector<uint256>& locator, size_t max) const
    {
        if (locator.empty())
            return {};
        uint32_t from = 0;
        for (const auto& l : locator) {
            auto it = height_of.find(l);
            if (it != height_of.end() && it->second <= served) {
                from = it->second;
                break;
            }
        }
        std::vector<BlockHeaderType> out;
        for (uint32_t h = from + 1; h <= served && out.size() < max; ++h)
            out.push_back(headers[h]);
        return out;
    }

    std::string name(const uint256& h) const
    {
        auto it = height_of.find(h);
        if (it == height_of.end())
            return "(unknown)";
        if (it->second == 0)
            return "genesis";
        return "h" + std::to_string(it->second) + (it->second == cp ? " (checkpoint)" : "");
    }
};

/// Headers per getheaders answer in these tests (Core: 2,000).
constexpr size_t kPeerBatch = 8;

/// A header chain and header sync (ltc/coin/header_sync.hpp) wired as in
/// main_ltc; the header and IO queues are run by hand and each getheaders is
/// answered from HonestLtcChain.
struct LtcNode {
    HeaderChain chain;
    std::shared_ptr<HeaderSync> sync;
    std::vector<std::function<void()>> worker_q, io_q;
    std::deque<std::vector<uint256>> asks;  // the locators of the getheaders sent
    std::chrono::steady_clock::time_point t = std::chrono::steady_clock::time_point{} + std::chrono::hours(1);

    LtcNode(const LTCChainParams& p, const std::string& db) : chain(p, db) {}

    void wire()
    {
        HeaderSyncHost hs;
        hs.has_header = [this](const uint256& h) { return chain.has_header(h); };
        hs.add_headers = [this](const std::vector<BlockHeaderType>& b) { return chain.add_headers(b); };
        hs.post_worker = [this](std::function<void()> fn) { worker_q.push_back(std::move(fn)); };
        hs.post_io = [this](std::function<void()> fn) { io_q.push_back(std::move(fn)); };
        hs.locator = [this]() { return chain.get_locator(); };
        hs.synced = [this]() { return chain.is_synced(); };
        hs.height = [this]() { return chain.height(); };
        hs.ask_one = [this](const std::vector<uint256>& loc, size_t, const std::string& peer) {
            asks.push_back(loc);
            return peer.empty() ? std::string("peer") : peer;
        };
        hs.ask_all = [this](const std::vector<uint256>& loc) { asks.push_back(loc); };
        hs.now = [this]() { return t; };
        sync = std::make_shared<HeaderSync>(std::move(hs));
    }

    void run()
    {
        while (!worker_q.empty() || !io_q.empty()) {
            auto w = std::move(worker_q);
            worker_q.clear();
            for (auto& f : w)
                f();
            auto i = std::move(io_q);
            io_q.clear();
            for (auto& f : i)
                f();
        }
    }

    /// Every getheaders sent, and the ones they lead to, answered from `net`.
    void answer(const HonestLtcChain& net)
    {
        for (int guard = 0; guard < 1000; ++guard) {
            run();
            if (asks.empty())
                return;
            const auto loc = asks.front();
            asks.pop_front();
            sync->on_headers("peer", net.getheaders(loc, kPeerBatch));
        }
        ADD_FAILURE() << "the header sync did not settle";
    }

    /// Two ticks of the periodic getheaders, each answered.
    void poll(const HonestLtcChain& net)
    {
        for (int i = 0; i < 2; ++i) {
            t += std::chrono::minutes(1);
            sync->poll();
            answer(net);
        }
    }
};

/// main_ltc's start of the header chain after init() at its defaults: the
/// checkpoint (pinned; the root when above the tip), then genesis only when
/// the store is empty.
void ltc_start(HeaderChain& chain, const HonestLtcChain& net)
{
    chain.set_dynamic_checkpoint(net.cp, net.hash(net.cp));
    if (chain.size() == 0)
        chain.add_header(net.at(0));
}

/// The step's state, printed; then its tip, height, best work and "synced"
/// checked, and that no genesis entry was stored.
void expect_ltc_tip(const HeaderChain& chain, const HonestLtcChain& net, const std::string& step,
                    uint32_t height, const uint256& work)
{
    const auto tip = chain.tip();
    const bool synced = chain.is_synced();
    std::cout << "[ ltc genesis ] " << step << ": tip=" << (tip ? net.name(tip->block_hash) : "(none)")
              << " height=" << chain.height() << " best_work=" << chain.cumulative_work().GetLow64()
              << " synced=" << synced << " genesis_stored=" << chain.has_header(net.hash(0))
              << " size=" << chain.size() << std::endl;
    ASSERT_TRUE(tip.has_value()) << step;
    EXPECT_EQ(tip->block_hash, net.hash(height)) << step << ": the tip is " << net.name(tip->block_hash);
    EXPECT_EQ(chain.height(), height) << step;
    EXPECT_EQ(chain.cumulative_work(), work) << step;
    EXPECT_TRUE(synced) << step;
    EXPECT_FALSE(chain.has_header(net.hash(0))) << step << ": a genesis entry was stored";
}

struct LtcTempDir {
    std::filesystem::path dir;
    LtcTempDir()
    {
        std::mt19937_64 rng(std::random_device{}());
        dir = std::filesystem::temp_directory_path() / ("ltc_genesis_store_" + std::to_string(rng()));
    }
    ~LtcTempDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

} // namespace

// An empty store accepts the genesis header and extends from it: with no
// checkpoint, and with a pinned checkpoint (--ltc-utxo-full).
TEST(LtcGenesisHeader, AnEmptyStoreStartsFromIt)
{
    HonestLtcChain net(40, 43, 43);
    const auto params = ltc_test::easy_testnet_params();
    const uint256 proof = get_block_proof(ltc_test::kEasyBits);
    for (const bool pinned : {false, true}) {
        SCOPED_TRACE(pinned ? "checkpoint pinned" : "no checkpoint");
        HeaderChain chain(params);
        ASSERT_TRUE(chain.init());
        if (pinned)
            chain.pin_checkpoint(net.cp, net.hash(net.cp));
        ASSERT_EQ(chain.size(), 0u);
        ASSERT_FALSE(chain.tip().has_value());
        EXPECT_TRUE(chain.add_header(net.at(0)));
        ASSERT_TRUE(chain.tip().has_value());
        EXPECT_EQ(chain.tip()->block_hash, net.hash(0));
        EXPECT_EQ(chain.height(), 0u);
        EXPECT_EQ(chain.cumulative_work(), proof);
        const std::vector<BlockHeaderType> next{net.at(1), net.at(2), net.at(3)};
        EXPECT_EQ(chain.add_headers(next), 3);
        EXPECT_EQ(chain.height(), 3u);
    }
    // A batch starting with the genesis header, into an empty store.
    HeaderChain chain(params);
    ASSERT_TRUE(chain.init());
    EXPECT_EQ(chain.add_headers({net.at(0), net.at(1)}), 2);
    EXPECT_EQ(chain.height(), 1u);
}

// A store with a tip (the checkpoint root alone, or with headers above it)
// refuses the genesis header, alone or in a batch; its tip, height and best
// work are unchanged and it extends from its tip.
TEST(LtcGenesisHeader, AnAnchoredStoreRefusesIt)
{
    HonestLtcChain net(40, 46, 46);
    const auto params = ltc_test::easy_testnet_params();
    {
        HeaderChain chain(params);
        ASSERT_TRUE(chain.init());
        ltc_start(chain, net);
        ASSERT_EQ(chain.height(), net.cp);
        EXPECT_FALSE(chain.add_header(net.at(0)));
        EXPECT_EQ(chain.add_headers({net.at(0)}), 0);
        ASSERT_TRUE(chain.tip().has_value());
        EXPECT_EQ(chain.tip()->block_hash, net.hash(net.cp));
        EXPECT_EQ(chain.height(), net.cp);
        EXPECT_EQ(chain.cumulative_work(), uint256::ONE);
        EXPECT_FALSE(chain.has_header(net.hash(0)));
    }
    HeaderChain chain(params);
    ASSERT_TRUE(chain.init());
    ltc_start(chain, net);
    const std::vector<BlockHeaderType> above(net.headers.begin() + 41, net.headers.begin() + 46);
    ASSERT_EQ(chain.add_headers(above), 5);
    ASSERT_EQ(chain.height(), 45u);
    const uint256 work = chain.cumulative_work();

    EXPECT_FALSE(chain.add_header(net.at(0))) << "the genesis header is refused by an anchored store";
    EXPECT_EQ(chain.add_headers({net.at(0)}), 0);
    EXPECT_EQ(chain.add_headers({net.at(0), net.at(1)}), 0);
    ASSERT_TRUE(chain.tip().has_value());
    EXPECT_EQ(chain.tip()->block_hash, net.hash(45)) << "the tip did not move";
    EXPECT_EQ(chain.height(), 45u);
    EXPECT_EQ(chain.cumulative_work(), work);
    EXPECT_TRUE(chain.is_synced());
    EXPECT_FALSE(chain.has_header(net.hash(0)));
    EXPECT_FALSE(chain.has_header(net.hash(1)));

    EXPECT_TRUE(chain.add_header(net.at(46))) << "the chain keeps extending from its tip";
    EXPECT_EQ(chain.height(), 46u);
}

// Setup: the checkpoint root at 40, headers 41..50, a synced tip. Steps: the
// genesis header; getheaders from the locator answered until nothing new
// comes, and the periodic getheaders; the header at 51; a reload with
// main_ltc's start; the header at 52. Expected at each step: the tip, height,
// best work of the anchored chain, extended by each new header; synced.
TEST(LtcGenesisHeader, AnAnchoredTipHoldsThroughResyncLiveHeaderAndRestart)
{
    constexpr uint32_t kCp = 40, kTip = 50;
    HonestLtcChain net(kCp, kTip + 2, kTip);
    const auto params = ltc_test::easy_testnet_params();
    const uint256 proof = get_block_proof(ltc_test::kEasyBits);
    LtcTempDir tmp;
    uint256 w0;
    {
        LtcNode node(params, tmp.dir.string());
        ASSERT_TRUE(node.chain.init());
        ltc_start(node.chain, net);
        const std::vector<BlockHeaderType> above(net.headers.begin() + kCp + 1, net.headers.begin() + kTip + 1);
        ASSERT_EQ(node.chain.add_headers(above), static_cast<int>(kTip - kCp));
        node.wire();
        w0 = node.chain.cumulative_work();
        expect_ltc_tip(node.chain, net, "0 anchored", kTip, w0);

        // 1. A headers message with the genesis header.
        node.sync->on_headers("peer", {net.at(0)});
        node.run();
        expect_ltc_tip(node.chain, net, "1 genesis header", kTip, w0);

        // 2. getheaders from the locator, answered until nothing new comes;
        //    the periodic getheaders.
        node.answer(net);
        node.poll(net);
        expect_ltc_tip(node.chain, net, "2 resync", kTip, w0);

        // 3. The header at the tip + 1.
        net.served = kTip + 1;
        node.sync->on_headers("peer", {net.at(kTip + 1)});
        node.answer(net);
        node.poll(net);
        expect_ltc_tip(node.chain, net, "3 live header", kTip + 1, w0 + proof);
    }
    // 4. Reload, main_ltc's start, the header at the tip + 1.
    {
        LtcNode node(params, tmp.dir.string());
        ASSERT_TRUE(node.chain.init());
        expect_ltc_tip(node.chain, net, "4 reload", kTip + 1, w0 + proof);
        ltc_start(node.chain, net);
        node.wire();
        node.poll(net);
        expect_ltc_tip(node.chain, net, "4 start", kTip + 1, w0 + proof);

        net.served = kTip + 2;
        node.sync->on_headers("peer", {net.at(kTip + 2)});
        node.answer(net);
        expect_ltc_tip(node.chain, net, "5 live header after the restart", kTip + 2, w0 + proof + proof);
    }
}

// The same setup; the header at the tip + 1 arrives before the getheaders
// answers. Expected: the tip extends to it and holds after the answers.
TEST(LtcGenesisHeader, AnAnchoredTipHoldsWhenALiveHeaderComesFirst)
{
    constexpr uint32_t kCp = 40, kTip = 50;
    HonestLtcChain net(kCp, kTip + 1, kTip);
    const auto params = ltc_test::easy_testnet_params();
    const uint256 proof = get_block_proof(ltc_test::kEasyBits);
    LtcNode node(params, "");
    ASSERT_TRUE(node.chain.init());
    ltc_start(node.chain, net);
    const std::vector<BlockHeaderType> above(net.headers.begin() + kCp + 1, net.headers.begin() + kTip + 1);
    ASSERT_EQ(node.chain.add_headers(above), static_cast<int>(kTip - kCp));
    node.wire();
    const uint256 w0 = node.chain.cumulative_work();

    node.sync->on_headers("peer", {net.at(0)});
    node.run();
    expect_ltc_tip(node.chain, net, "T1 genesis header", kTip, w0);

    net.served = kTip + 1;
    node.sync->on_headers("peer", {net.at(kTip + 1)});
    node.run();
    expect_ltc_tip(node.chain, net, "T2 live header before any answer", kTip + 1, w0 + proof);

    node.answer(net);
    node.poll(net);
    expect_ltc_tip(node.chain, net, "T3 the answers", kTip + 1, w0 + proof);
}

// The same setup and genesis header, its getheaders answered; then a reload
// with main_ltc's start, the header at tip + 1 not delivered, the header at
// tip + 2 delivered alone, the periodic getheaders, the header at tip + 3.
// Run with 10 and with 5 headers above the checkpoint (one answer is 8).
// Expected: the tip stays on the anchored chain and reaches tip + 2, then
// tip + 3.
TEST(LtcGenesisHeader, AnAnchoredTipHoldsThroughARestartWithAMissedBlock)
{
    constexpr uint32_t kCp = 40;
    const auto params = ltc_test::easy_testnet_params();
    const uint256 proof = get_block_proof(ltc_test::kEasyBits);
    for (const uint32_t top : {kCp + 10u, kCp + 5u}) {
        const std::string tag = "[" + std::to_string(top - kCp) + " above] ";
        SCOPED_TRACE(tag);
        HonestLtcChain net(kCp, top + 3, top);
        LtcTempDir tmp;
        uint256 w0;
        {
            LtcNode node(params, tmp.dir.string());
            ASSERT_TRUE(node.chain.init());
            ltc_start(node.chain, net);
            const std::vector<BlockHeaderType> above(net.headers.begin() + kCp + 1, net.headers.begin() + top + 1);
            ASSERT_EQ(node.chain.add_headers(above), static_cast<int>(top - kCp));
            node.wire();
            w0 = node.chain.cumulative_work();
            expect_ltc_tip(node.chain, net, tag + "M0 anchored", top, w0);

            node.sync->on_headers("peer", {net.at(0)});
            node.answer(net);
            node.poll(net);
            expect_ltc_tip(node.chain, net, tag + "M1 genesis header, resync", top, w0);
        }
        net.served = top + 1;  // between the two runs
        {
            LtcNode node(params, tmp.dir.string());
            ASSERT_TRUE(node.chain.init());
            expect_ltc_tip(node.chain, net, tag + "M2 reload", top, w0);
            ltc_start(node.chain, net);
            node.wire();
            expect_ltc_tip(node.chain, net, tag + "M2 start", top, w0);

            net.served = top + 2;
            node.sync->on_headers("peer", {net.at(top + 2)});
            node.answer(net);
            expect_ltc_tip(node.chain, net, tag + "M3 live header at tip + 2", top + 2, w0 + proof + proof);
            node.poll(net);
            expect_ltc_tip(node.chain, net, tag + "M4 periodic getheaders", top + 2, w0 + proof + proof);

            net.served = top + 3;
            node.sync->on_headers("peer", {net.at(top + 3)});
            node.answer(net);
            node.poll(net);
            expect_ltc_tip(node.chain, net, tag + "M5 next live header", top + 3, w0 + proof + proof + proof);
        }
    }
}

// A store loaded with entries but without its "tip" key: started with the
// checkpoint, the root is the tip and the genesis header is refused; started
// without a checkpoint, the genesis header is accepted.
TEST(LtcGenesisHeader, AStoreWithEntriesButNoTip)
{
    HonestLtcChain net(40, 45, 45);
    const auto params = ltc_test::easy_testnet_params();
    LtcTempDir tmp;
    const std::string dir = tmp.dir.string();
    {
        HeaderChain chain(params, dir);
        ASSERT_TRUE(chain.init());
        ltc_start(chain, net);
        const std::vector<BlockHeaderType> above(net.headers.begin() + 41, net.headers.begin() + 46);
        ASSERT_EQ(chain.add_headers(above), 5);
    }
    auto drop_tip = [&dir]() {
        core::LevelDBStore db(dir, core::LevelDBOptions{});
        ASSERT_TRUE(db.open());
        db.remove("tip");
        db.remove("height");
    };
    drop_tip();
    {
        HeaderChain chain(params, dir);
        ASSERT_TRUE(chain.init());
        ASSERT_FALSE(chain.tip().has_value());
        ASSERT_EQ(chain.size(), 6u);
        ltc_start(chain, net);  // the checkpoint seeds the root as the tip
        EXPECT_EQ(chain.add_headers({net.at(0)}), 0);
        ASSERT_TRUE(chain.tip().has_value());
        EXPECT_EQ(chain.tip()->block_hash, net.hash(40));
        EXPECT_FALSE(chain.has_header(net.hash(0)));
    }
    drop_tip();
    {
        HeaderChain chain(params, dir);
        ASSERT_TRUE(chain.init());
        ASSERT_FALSE(chain.tip().has_value());
        ASSERT_EQ(chain.size(), 6u);  // not empty: no genesis seed at start
        EXPECT_EQ(chain.add_headers({net.at(0)}), 1);
        ASSERT_TRUE(chain.tip().has_value());
        EXPECT_EQ(chain.tip()->block_hash, net.hash(0));
        EXPECT_EQ(chain.height(), 0u);
        EXPECT_EQ(chain.size(), 7u);
    }
}
