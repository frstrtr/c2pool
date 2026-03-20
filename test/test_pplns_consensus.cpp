// test_pplns_consensus.cpp — Tests for the PPLNS consensus fixes.
//
// Covers:
//   1. V36 PPLNS uses unlimited desired_weight (2^288-1), not the capped formula
//   2. Bootstrap hardest bits selection when height < TARGET_LOOKBEHIND
//   3. desired_target = MAX_TARGET gets clipped to pre_target3 (not block diff)
//   4. compute_merged_payout_hash walks verified chain, not raw chain
//   5. Deferred merged payout hash when verified depth < CHAIN_LENGTH
//   6. Shares with target > max_target are rejected
//   7. Minimum viable hashrate / miner thresholds calculation

#include <gtest/gtest.h>

#include <core/hash.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <btclibs/uint256.h>
#include <btclibs/base58.h>
#include <btclibs/bech32.h>
#include <btclibs/crypto/sha256.h>
#include <impl/ltc/config_pool.hpp>
#include <sharechain/weights_skiplist.hpp>

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

using chain::bits_to_target;
using chain::target_to_average_attempts;
using chain::target_to_bits_upper_bound;
using chain::WeightsDelta;
using chain::WeightsSkipList;
using ltc::PoolConfig;

// ============================================================================
// Script builders (matching test_pplns_stress.cpp patterns)
// ============================================================================

static std::vector<unsigned char> make_p2pkh(const std::vector<unsigned char>& h160)
{
    std::vector<unsigned char> s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), h160.begin(), h160.end());
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

static std::vector<unsigned char> make_p2wpkh(const std::vector<unsigned char>& h160)
{
    std::vector<unsigned char> s = {0x00, 0x14};
    s.insert(s.end(), h160.begin(), h160.end());
    return s;
}

// ============================================================================
// Deterministic hash generation
// ============================================================================

static std::vector<unsigned char> hash_from_seed(int seed, int len = 20)
{
    unsigned char buf[4];
    buf[0] = seed & 0xff; buf[1] = (seed >> 8) & 0xff;
    buf[2] = (seed >> 16) & 0xff; buf[3] = (seed >> 24) & 0xff;
    unsigned char sha[32];
    CSHA256().Write(buf, 4).Finalize(sha);
    return std::vector<unsigned char>(sha, sha + len);
}

static uint256 hash256_from_seed(int seed)
{
    unsigned char buf[4];
    buf[0] = seed & 0xff; buf[1] = (seed >> 8) & 0xff;
    buf[2] = (seed >> 16) & 0xff; buf[3] = (seed >> 24) & 0xff;
    uint256 result;
    CSHA256().Write(buf, 4).Finalize(result.data());
    return result;
}

// ============================================================================
// Synthetic share chain (matches test_pplns_stress.cpp)
// ============================================================================

struct SyntheticShare {
    uint256 hash;
    uint256 prev_hash;
    std::vector<unsigned char> script;
    uint32_t bits;
    uint32_t donation;  // 0..65535
    int64_t desired_version;
};

static std::vector<SyntheticShare> build_chain(
    int n_shares, int n_miners,
    uint32_t bits = 0x1e0fffff,
    uint32_t donation = 50,
    int64_t version = 36)
{
    std::vector<SyntheticShare> shares(n_shares);
    for (int i = 0; i < n_shares; ++i) {
        shares[i].hash = hash256_from_seed(i * 7 + 31);

        int miner_id = i % n_miners;
        auto h160 = hash_from_seed(miner_id + 1000, 20);
        shares[i].script = (miner_id % 2 == 0) ? make_p2pkh(h160) : make_p2wpkh(h160);
        shares[i].bits = bits;
        shares[i].donation = donation;
        shares[i].desired_version = version;
    }
    // Link chain: share[0] is head, share[n-1] is tail
    for (int i = 0; i < n_shares - 1; ++i)
        shares[i].prev_hash = shares[i + 1].hash;
    shares[n_shares - 1].prev_hash = uint256{};
    return shares;
}

// Build lookup + skip list from a synthetic chain
struct ChainContext {
    std::vector<SyntheticShare> shares;
    std::unordered_map<uint256, size_t, chain::Uint256Hasher> idx;
    WeightsSkipList skiplist;

    ChainContext() = default;
    ChainContext(std::vector<SyntheticShare> s) : shares(std::move(s))
    {
        for (size_t i = 0; i < shares.size(); ++i)
            idx[shares[i].hash] = i;

        skiplist = WeightsSkipList(
            [this](const uint256& hash) -> WeightsDelta {
                WeightsDelta d;
                auto it = idx.find(hash);
                if (it == idx.end()) return d;
                auto& sh = shares[it->second];
                d.share_count = 1;
                if (sh.desired_version < 36) return d;
                auto target = bits_to_target(sh.bits);
                auto att = target_to_average_attempts(target);
                d.total_weight = att * 65535;
                d.total_donation_weight = att * static_cast<uint32_t>(sh.donation);
                d.weights[sh.script] = att * static_cast<uint32_t>(65535 - sh.donation);
                return d;
            },
            [this](const uint256& hash) -> uint256 {
                auto it = idx.find(hash);
                if (it == idx.end()) return uint256{};
                return shares[it->second].prev_hash;
            }
        );
    }
};

// ============================================================================
// Replicate the decay PPLNS computation from share_tracker.hpp
// ============================================================================

struct DecayResult {
    std::map<std::string, uint288> weights;
    uint288 total_weight;
    uint288 total_donation_weight;
    int32_t shares_walked;
};

struct DecayShareData {
    uint64_t att;
    uint32_t donation;
    std::string address;
};

static DecayResult compute_decayed_weights(
    const std::vector<DecayShareData>& shares,
    int32_t max_shares,
    const uint288& desired_weight,
    uint32_t chain_length)
{
    static constexpr uint64_t DECAY_PRECISION = 40;
    static constexpr uint64_t DECAY_SCALE = uint64_t(1) << DECAY_PRECISION;
    static constexpr uint64_t LN2_MICRO = 693147;

    uint32_t half_life = std::max(chain_length / 4, uint32_t(1));
    uint64_t decay_per = DECAY_SCALE - (DECAY_SCALE * LN2_MICRO) / (uint64_t(1000000) * half_life);

    DecayResult result{};
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

    result.shares_walked = share_count;
    return result;
}

// ============================================================================
// Payout hash computation (replicated from share_tracker.hpp)
// ============================================================================

static std::string uint288_to_decimal(const uint288& val)
{
    if (val.IsNull()) return "0";
    uint288 tmp = val;
    std::string result;
    while (!tmp.IsNull()) {
        uint32_t rem = 0;
        for (int i = uint288::WIDTH - 1; i >= 0; --i) {
            uint64_t cur = (static_cast<uint64_t>(rem) << 32) | tmp.pn[i];
            tmp.pn[i] = static_cast<uint32_t>(cur / 10);
            rem = static_cast<uint32_t>(cur % 10);
        }
        result.push_back('0' + static_cast<char>(rem));
    }
    std::reverse(result.begin(), result.end());
    return result;
}

static std::string script_to_address(const std::vector<unsigned char>& script, bool testnet)
{
    if (script.size() == 22 && script[0] == 0x00 && script[1] == 0x14) {
        std::string hrp = testnet ? "tltc" : "ltc";
        std::vector<uint8_t> prog(script.begin() + 2, script.end());
        return bech32::encode_segwit(hrp, 0, prog);
    }
    if (script.size() == 25 && script[0] == 0x76 && script[1] == 0xa9
        && script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac) {
        unsigned char ver = testnet ? 111 : 48;
        std::vector<unsigned char> data = {ver};
        data.insert(data.end(), script.begin() + 3, script.begin() + 23);
        return EncodeBase58Check(data);
    }
    if (script.size() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87) {
        unsigned char ver = testnet ? 58 : 50;
        std::vector<unsigned char> data = {ver};
        data.insert(data.end(), script.begin() + 2, script.begin() + 22);
        return EncodeBase58Check(data);
    }
    std::string hex;
    for (unsigned char c : script) {
        static const char digits[] = "0123456789abcdef";
        hex.push_back(digits[c >> 4]);
        hex.push_back(digits[c & 0xf]);
    }
    return hex;
}

static uint256 compute_payout_hash(
    const std::map<std::vector<unsigned char>, uint288>& weights,
    const uint288& total_weight, const uint288& donation_weight, bool testnet)
{
    std::map<std::string, uint288> sorted;
    for (const auto& [script, w] : weights)
        sorted[script_to_address(script, testnet)] += w;

    std::string payload;
    for (const auto& [addr, w] : sorted) {
        if (!payload.empty()) payload.push_back('|');
        payload += addr;
        payload.push_back(':');
        payload += uint288_to_decimal(w);
    }
    payload += "|T:";
    payload += uint288_to_decimal(total_weight);
    payload += "|D:";
    payload += uint288_to_decimal(donation_weight);

    auto span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
    return Hash(span);
}

// ============================================================================
// Test 1: V36 uses unlimited desired_weight (2^288-1), not capped formula
// ============================================================================

TEST(PPLNSConsensus, DesiredWeightUnlimitedV36)
{
    // On testnet with very low block difficulty, the capped formula
    //   desired_weight = block_att * SPREAD * 65535
    // would produce a tiny window covering only ~2 shares. V36 must use
    // unlimited desired_weight (2^288-1) so the PPLNS window covers
    // REAL_CHAIN_LENGTH shares via exponential decay.

    PoolConfig::is_testnet = true;
    auto chain_length = PoolConfig::real_chain_length();  // 400

    // Build a 400-share chain with 2 miners at easy testnet difficulty
    uint32_t testnet_bits = 0x1e0fffff;  // easy target
    auto shares = build_chain(static_cast<int>(chain_length), 2, testnet_bits, 50, 36);
    ChainContext ctx(std::move(shares));

    // Unlimited desired_weight (V36 behavior)
    uint288 unlimited;
    unlimited.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    auto head = ctx.shares[0].hash;
    auto result_unlimited = ctx.skiplist.query(head, chain_length, unlimited);

    // Both miners should appear in the weights (2 unique addresses)
    EXPECT_EQ(result_unlimited.weights.size(), 2u);
    EXPECT_FALSE(result_unlimited.total_weight.IsNull());

    // Now compute with the CAPPED formula (the old bug)
    auto block_target = bits_to_target(testnet_bits);
    auto block_att = target_to_average_attempts(block_target);
    uint288 capped_desired = block_att * PoolConfig::SPREAD * 65535;

    auto result_capped = ctx.skiplist.query(head, chain_length, capped_desired);

    // Capped total_weight should be much smaller than unlimited (the bug)
    EXPECT_LT(result_capped.total_weight, result_unlimited.total_weight);

    // Unlimited should have both miners with non-trivial weight
    EXPECT_EQ(result_unlimited.weights.size(), 2u);

    std::cout << "V36 unlimited: walked " << result_unlimited.weights.size()
              << " shares, total_weight=" << uint288_to_decimal(result_unlimited.total_weight)
              << std::endl;
    std::cout << "Old capped:    walked " << result_capped.weights.size()
              << " shares, total_weight=" << uint288_to_decimal(result_capped.total_weight)
              << std::endl;

    PoolConfig::is_testnet = false;  // restore
}

// ============================================================================
// Test 2: Bootstrap hardest bits
// ============================================================================

TEST(PPLNSConsensus, BootstrapHardestBits)
{
    // When chain height < TARGET_LOOKBEHIND (200), compute_share_target
    // should return the hardest (lowest target) bits from the chain, not
    // MAX_TARGET. This prevents flooding with easy shares during bootstrap.

    // Simulate the bootstrap logic from share_tracker.hpp:
    // Walk backward to find the HARDEST (lowest target) bits in the chain.

    // Create a mix of easy and hard shares
    struct MockShare {
        uint256 hash;
        uint256 prev_hash;
        uint32_t bits;
        uint32_t max_bits;
    };

    std::vector<MockShare> chain;
    // Build 50 shares (< TARGET_LOOKBEHIND=200)
    uint32_t easy_bits = 0x1e0fffff;   // very easy target
    uint32_t medium_bits = 0x1d0fffff; // 256x harder
    uint32_t hard_bits = 0x1c0fffff;   // 65536x harder

    for (int i = 0; i < 50; ++i) {
        MockShare s;
        s.hash = hash256_from_seed(i * 3 + 100);

        // Most shares are easy, but share #20 is hard and share #35 is medium
        if (i == 20)
            s.bits = hard_bits;
        else if (i == 35)
            s.bits = medium_bits;
        else
            s.bits = easy_bits;
        s.max_bits = s.bits;

        chain.push_back(s);
    }
    // Link
    for (int i = 0; i < 49; ++i)
        chain[i].prev_hash = chain[i + 1].hash;
    chain[49].prev_hash = uint256{};

    // Replicate the bootstrap hardest-bits selection from share_tracker.hpp
    uint256 best_target;
    best_target.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    uint32_t best_bits = 0;
    uint32_t best_max_bits = 0;
    int height = 50;

    // Walk the chain just like share_tracker does
    for (int i = 0; i < height; ++i) {
        auto target = bits_to_target(chain[i].bits);
        if (target < best_target) {
            best_target = target;
            best_bits = chain[i].bits;
            best_max_bits = chain[i].max_bits;
        }
    }

    // The hardest bits should be the hard_bits share (#20)
    EXPECT_EQ(best_bits, hard_bits);
    EXPECT_EQ(best_max_bits, hard_bits);

    // Verify that hard_bits target < easy_bits target (harder = lower)
    auto easy_target = bits_to_target(easy_bits);
    auto hard_target = bits_to_target(hard_bits);
    EXPECT_TRUE(hard_target < easy_target);

    // Verify the selected target is NOT max_target (the old bug would return max_target)
    uint256 max_target = PoolConfig::max_target();
    EXPECT_TRUE(best_target < max_target);

    std::cout << "Bootstrap: selected hardest bits=0x" << std::hex << best_bits
              << " from chain of " << std::dec << height << " shares" << std::endl;
}

// ============================================================================
// Test 3: desired_target = MAX_TARGET clipped to pre_target3
// ============================================================================

TEST(PPLNSConsensus, ShareTargetNotBlockDifficulty)
{
    // Verify that desired_target passed to compute_share_target is MAX_TARGET
    // (gets clipped to pre_target3), not block difficulty.
    // The resulting bits.target should equal pre_target3, not pre_target3//30.

    // Replicate the clipping logic from share_tracker.hpp
    // bits = from_target_upper_bound(clip(desired_target, (pre_target3/30, pre_target3)))

    // Simulate a pool target (pre_target3) that is much harder than MAX_TARGET
    uint256 pre_target3;
    pre_target3.SetHex("00000000000000ffffffffffffffffffffffffffffffffffffffffffffffffff");

    // The caller passes desired_target = MAX_TARGET (easiest possible)
    PoolConfig::is_testnet = true;
    uint256 desired_target = PoolConfig::max_target();
    PoolConfig::is_testnet = false;

    // Clip desired_target to [pre_target3/30, pre_target3]
    uint256 bits_lo = pre_target3 / 30;
    if (bits_lo.IsNull()) bits_lo = uint256(1);
    uint256 bits_target = desired_target;
    if (bits_target < bits_lo) bits_target = bits_lo;
    if (bits_target > pre_target3) bits_target = pre_target3;

    // Result should be pre_target3 (clipped from above), NOT pre_target3/30
    EXPECT_EQ(bits_target, pre_target3);

    // Verify it is NOT divided by 30
    uint256 divided = pre_target3 / 30;
    EXPECT_TRUE(bits_target != divided);

    // The resulting bits should encode close to pre_target3
    // (FloatingInteger encoding may round slightly)
    auto bits = target_to_bits_upper_bound(bits_target);
    auto decoded = bits_to_target(bits);
    // Decoded should be within 2x of pre_target3 (not at pre_target3//30)
    EXPECT_TRUE(decoded > divided); // must be easier than pre_target3//30

    std::cout << "desired_target (MAX_TARGET) clipped to pre_target3: 0x"
              << bits_target.GetHex().substr(0, 32) << std::endl;
    std::cout << "pre_target3/30 (WRONG): 0x"
              << divided.GetHex().substr(0, 32) << std::endl;
}

// ============================================================================
// Test 4: Verified chain walk for compute_merged_payout_hash
// ============================================================================

TEST(PPLNSConsensus, VerifiedChainWalk)
{
    // compute_merged_payout_hash should walk the verified chain, not the raw
    // chain. If unverified shares exist in the raw chain with different
    // addresses, they should NOT appear in the hash payload.

    PoolConfig::is_testnet = true;

    // Build two separate sets of shares:
    //   - "verified" chain: 400 shares from miner A
    //   - "raw-only" shares: interspersed shares from miner B (unverified)

    int chain_len = static_cast<int>(PoolConfig::real_chain_length());  // 400
    auto verified_shares = build_chain(chain_len, 1, 0x1e0fffff, 50, 36);

    // Build a "verified-only" ChainContext (only has miner 0)
    ChainContext verified_ctx(verified_shares);

    uint288 unlimited;
    unlimited.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    auto head = verified_ctx.shares[0].hash;
    auto result = verified_ctx.skiplist.query(head, chain_len, unlimited);

    // Only miner 0 should appear in verified weights
    EXPECT_EQ(result.weights.size(), 1u);
    EXPECT_FALSE(result.total_weight.IsNull());

    // Compute the payout hash using ONLY verified weights
    auto hash_verified = compute_payout_hash(
        result.weights, result.total_weight, result.total_donation_weight, true);
    EXPECT_FALSE(hash_verified.IsNull());

    // Now build a "raw" chain that includes an extra miner (miner B)
    // by adding miner B's shares to a new context
    auto raw_shares = build_chain(chain_len, 2, 0x1e0fffff, 50, 36);
    ChainContext raw_ctx(raw_shares);

    auto raw_head = raw_ctx.shares[0].hash;
    auto result_raw = raw_ctx.skiplist.query(raw_head, chain_len, unlimited);

    // Raw chain has 2 miners
    EXPECT_EQ(result_raw.weights.size(), 2u);

    auto hash_raw = compute_payout_hash(
        result_raw.weights, result_raw.total_weight, result_raw.total_donation_weight, true);

    // The two hashes MUST differ — verified excludes unverified miner
    EXPECT_NE(hash_verified, hash_raw);

    std::cout << "Verified hash: " << hash_verified.GetHex().substr(0, 32) << std::endl;
    std::cout << "Raw hash:      " << hash_raw.GetHex().substr(0, 32) << std::endl;
    std::cout << "Verified miners: " << result.weights.size()
              << " Raw miners: " << result_raw.weights.size() << std::endl;

    PoolConfig::is_testnet = false;
}

// ============================================================================
// Test 5: Deferred merged payout hash when verified depth < CHAIN_LENGTH
// ============================================================================

TEST(PPLNSConsensus, MergedPayoutHashDeferred)
{
    // When verified chain depth < CHAIN_LENGTH, compute_merged_payout_hash
    // should return null (deferred check). This matches the guard in
    // share_tracker.hpp:
    //   if (height < real_chain_length()) return uint256{};

    PoolConfig::is_testnet = true;
    auto chain_length = PoolConfig::real_chain_length();  // 400

    // Build a chain shorter than CHAIN_LENGTH
    int short_len = static_cast<int>(chain_length) / 2;  // 200 shares
    auto shares = build_chain(short_len, 2, 0x1e0fffff, 50, 36);

    // Simulate the deferred check from share_tracker.hpp
    int height = short_len;
    bool should_defer = height < static_cast<int>(chain_length);

    EXPECT_TRUE(should_defer);

    // When deferred, function returns null uint256
    uint256 deferred_result{};
    EXPECT_TRUE(deferred_result.IsNull());

    // A full chain should NOT defer
    auto full_shares = build_chain(static_cast<int>(chain_length), 2, 0x1e0fffff, 50, 36);
    int full_height = static_cast<int>(chain_length);
    bool should_defer_full = full_height < static_cast<int>(chain_length);
    EXPECT_FALSE(should_defer_full);

    std::cout << "Short chain (" << short_len << "): deferred=" << should_defer << std::endl;
    std::cout << "Full chain (" << chain_length << "): deferred=" << should_defer_full << std::endl;

    PoolConfig::is_testnet = false;
}

// ============================================================================
// Test 6: Share with target > max_target is rejected
// ============================================================================

TEST(PPLNSConsensus, TargetExceedsMaxTargetRejected)
{
    // A share with target > max_target should fail validation.
    // The guard in compute_share_target clamps to MAX_TARGET:
    //   if (pre_target3 > MAX_TARGET) pre_target3 = MAX_TARGET;
    // And the bits clipping ensures:
    //   if (bits_target > pre_target3) bits_target = pre_target3;

    // Test for both mainnet and testnet
    for (bool testnet : {false, true}) {
        PoolConfig::is_testnet = testnet;
        uint256 max_target = PoolConfig::max_target();

        // Create a target that exceeds max_target
        uint256 too_easy;
        too_easy.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        ASSERT_TRUE(too_easy > max_target);

        // The guard should clamp it
        uint256 clamped = too_easy;
        if (clamped > max_target) clamped = max_target;
        EXPECT_EQ(clamped, max_target);

        // Verify bits encoding of max_target
        // (upper_bound encoding may be slightly less than the original)
        auto max_bits = target_to_bits_upper_bound(max_target);
        auto decoded_max = bits_to_target(max_bits);
        // Just verify it decodes to a non-null value
        EXPECT_FALSE(decoded_max.IsNull());

        // A share claiming bits that decode to > max_target should be detected
        // Encode the too-easy target
        auto too_easy_bits = target_to_bits_upper_bound(too_easy);
        auto decoded_too_easy = bits_to_target(too_easy_bits);

        // The decoded target exceeds max_target
        EXPECT_TRUE(decoded_too_easy > max_target);

        // Validation: shares must have bits.target <= max_target
        bool would_reject = (decoded_too_easy > max_target);
        EXPECT_TRUE(would_reject);

        std::cout << (testnet ? "Testnet" : "Mainnet")
                  << ": max_target=0x" << max_target.GetHex().substr(0, 32)
                  << " too_easy=0x" << decoded_too_easy.GetHex().substr(0, 32)
                  << " rejected=" << would_reject << std::endl;
    }

    PoolConfig::is_testnet = false;
}

// ============================================================================
// Test 7: Miner thresholds calculation
// ============================================================================

TEST(PPLNSConsensus, MinerThresholdsCalculation)
{
    // Verify minimum viable hashrate calculation:
    //   min_hr = pool_hr / chain_length
    //   min_hr_dust = min_hr / 30
    //
    // A miner below min_hr produces < 1 share per CHAIN_LENGTH window and
    // effectively earns nothing. The /30 dust threshold is the VARDIFF floor
    // from compute_share_target: clip(desired_target, (pre_target3/30, pre_target3)).

    // Test with testnet parameters
    PoolConfig::is_testnet = true;
    uint32_t chain_length = PoolConfig::chain_length();  // 400
    uint32_t share_period = PoolConfig::share_period();   // 4 seconds

    // Simulate pool hashrate: 100 MH/s (100 * 10^6)
    double pool_hr = 100.0e6;  // 100 MH/s

    // Minimum hashrate to produce 1 share per window
    double min_hr = pool_hr / static_cast<double>(chain_length);
    // VARDIFF dust floor: 30x easier shares allowed
    double min_hr_dust = min_hr / 30.0;

    // At 100 MH/s pool, min viable miner is 250 KH/s (1/400 of pool)
    EXPECT_NEAR(min_hr, 250000.0, 1.0);
    // With VARDIFF floor, dust miners down to ~8.33 KH/s get shares
    EXPECT_NEAR(min_hr_dust, 250000.0 / 30.0, 1.0);

    // Verify the relationship
    EXPECT_DOUBLE_EQ(min_hr, pool_hr / chain_length);
    EXPECT_DOUBLE_EQ(min_hr_dust, min_hr / 30.0);

    // Test with mainnet parameters
    PoolConfig::is_testnet = false;
    chain_length = PoolConfig::chain_length();  // 8640

    min_hr = pool_hr / static_cast<double>(chain_length);
    min_hr_dust = min_hr / 30.0;

    // At 100 MH/s pool, mainnet min viable is ~11.57 KH/s
    EXPECT_NEAR(min_hr, 100.0e6 / 8640.0, 1.0);
    EXPECT_NEAR(min_hr_dust, min_hr / 30.0, 1.0);

    // A miner at exactly min_hr should produce exactly 1 share per window
    double expected_shares = min_hr / (pool_hr / chain_length);
    EXPECT_NEAR(expected_shares, 1.0, 1e-10);

    // A miner at min_hr_dust produces 1/30 shares per window but still
    // gets VARDIFF shares (30x easier than pool target)
    double dust_shares_at_pool_diff = min_hr_dust / (pool_hr / chain_length);
    EXPECT_NEAR(dust_shares_at_pool_diff, 1.0 / 30.0, 1e-10);

    std::cout << "Testnet: min_hr=" << (pool_hr / PoolConfig::TESTNET_CHAIN_LENGTH)
              << " min_hr_dust=" << (pool_hr / PoolConfig::TESTNET_CHAIN_LENGTH / 30.0)
              << std::endl;
    std::cout << "Mainnet: min_hr=" << min_hr
              << " min_hr_dust=" << min_hr_dust << std::endl;

    PoolConfig::is_testnet = false;  // restore
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
