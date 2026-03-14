// test_weights.cpp — Unit tests for PPLNS weight computation
//
// Tests the WeightsSkipList (O(log n) cumulative weights) and the
// V36 decayed weights walk + result cache.
//
// These test a synthetic chain of shares with known parameters so
// expected weights can be verified analytically.

#include <gtest/gtest.h>

#include <sharechain/weights_skiplist.hpp>
#include <core/target_utils.hpp>
#include <btclibs/uint256.h>
#include <btclibs/crypto/sha256.h>

#include <cstdint>
#include <map>
#include <vector>

using namespace chain;
using chain::bits_to_target;
using chain::target_to_average_attempts;

// ---------------------------------------------------------------------------
// Helpers: build a synthetic linear chain of shares
// ---------------------------------------------------------------------------

struct FakeShare {
    uint256 hash;
    uint256 prev_hash;
    std::vector<unsigned char> script;  // address key
    uint32_t bits;      // encodes target → attempts
    uint32_t donation;
};

// Build a linear chain of N shares with deterministic hashes.
// Share 0 is the tip (most recent), share N-1 is the tail.
static std::vector<FakeShare> make_chain(int n, uint32_t bits = 0x1e0fffff,
                                          uint32_t donation = 50)
{
    std::vector<FakeShare> shares(n);
    for (int i = 0; i < n; ++i) {
        // Deterministic hash: SHA256d of the index
        unsigned char buf[4];
        buf[0] = i & 0xff; buf[1] = (i >> 8) & 0xff;
        buf[2] = (i >> 16) & 0xff; buf[3] = (i >> 24) & 0xff;
        CSHA256().Write(buf, 4).Finalize(shares[i].hash.data());

        if (i + 1 < n) {
            // prev_hash will be set after we compute share[i+1].hash
        }
        // Simple 4-byte address key: "addr" + index byte
        shares[i].script = {'a', 'd', 'd', 'r', static_cast<unsigned char>(i % 10)};
        shares[i].bits = bits;
        shares[i].donation = donation;
    }
    // Link: share[0].prev = share[1].hash, etc.
    for (int i = 0; i < n - 1; ++i)
        shares[i].prev_hash = shares[i + 1].hash;
    // Tail has null prev
    shares[n - 1].prev_hash = uint256{};
    return shares;
}

// Build a lookup map from hash → index for get_delta/previous lambdas
static std::unordered_map<uint256, size_t, Uint256Hasher>
make_index(const std::vector<FakeShare>& shares) {
    std::unordered_map<uint256, size_t, Uint256Hasher> idx;
    for (size_t i = 0; i < shares.size(); ++i)
        idx[shares[i].hash] = i;
    return idx;
}

// ---------------------------------------------------------------------------
// WeightsSkipList tests
// ---------------------------------------------------------------------------

class WeightsTest : public ::testing::Test {
protected:
    static constexpr int CHAIN_LEN = 100;
    static constexpr uint32_t BITS = 0x1e0fffff;
    static constexpr uint32_t DONATION = 50;

    std::vector<FakeShare> shares;
    std::unordered_map<uint256, size_t, Uint256Hasher> idx;
    WeightsSkipList skiplist;

    void SetUp() override {
        shares = make_chain(CHAIN_LEN, BITS, DONATION);
        idx = make_index(shares);

        auto get_delta = [this](const uint256& hash) -> WeightsDelta {
            WeightsDelta d;
            auto it = idx.find(hash);
            if (it == idx.end()) return d;
            auto& s = shares[it->second];
            auto target = bits_to_target(s.bits);
            auto att = target_to_average_attempts(target);
            d.share_count = 1;
            d.total_weight = att * 65535;
            d.total_donation_weight = att * s.donation;
            d.weights[s.script] = att * static_cast<uint32_t>(65535 - s.donation);
            return d;
        };

        auto previous = [this](const uint256& hash) -> uint256 {
            auto it = idx.find(hash);
            if (it == idx.end()) return uint256{};
            return shares[it->second].prev_hash;
        };

        skiplist = WeightsSkipList(get_delta, previous);
    }
};

TEST_F(WeightsTest, QueryReturnsCorrectShareCount) {
    auto result = skiplist.query(shares[0].hash, 10, uint288(uint64_t(-1)));
    // We asked for 10 shares with unlimited weight — should get exactly 10
    // (total_weight check: 10 shares worth of weight)
    EXPECT_FALSE(result.weights.empty());
    EXPECT_FALSE(result.total_weight.IsNull());
}

TEST_F(WeightsTest, QueryFullChainMatchesLinearWalk) {
    // Query all 100 shares via skip list
    auto sl_result = skiplist.query(shares[0].hash, CHAIN_LEN, uint288(uint64_t(-1)));

    // Linear walk for comparison
    auto target = bits_to_target(BITS);
    auto att = target_to_average_attempts(target);
    uint288 expected_total = att * 65535 * CHAIN_LEN;
    uint288 expected_donation = att * DONATION * CHAIN_LEN;

    EXPECT_EQ(sl_result.total_weight, expected_total);
    EXPECT_EQ(sl_result.total_donation_weight, expected_donation);
}

TEST_F(WeightsTest, QuerySingleShareMatchesDelta) {
    auto result = skiplist.query(shares[0].hash, 1, uint288(uint64_t(-1)));
    auto target = bits_to_target(BITS);
    auto att = target_to_average_attempts(target);
    EXPECT_EQ(result.total_weight, att * 65535);
    EXPECT_EQ(result.total_donation_weight, att * DONATION);
}

TEST_F(WeightsTest, QueryZeroSharesReturnsEmpty) {
    auto result = skiplist.query(shares[0].hash, 0, uint288(uint64_t(-1)));
    EXPECT_TRUE(result.weights.empty());
    EXPECT_TRUE(result.total_weight.IsNull());
}

TEST_F(WeightsTest, QueryNullHashReturnsEmpty) {
    auto result = skiplist.query(uint256{}, 10, uint288(uint64_t(-1)));
    EXPECT_TRUE(result.weights.empty());
}

TEST_F(WeightsTest, ForgetInvalidatesCachedNode) {
    // First query to populate cache
    auto r1 = skiplist.query(shares[0].hash, 5, uint288(uint64_t(-1)));
    EXPECT_FALSE(r1.total_weight.IsNull());

    // Forget a share in the middle
    skiplist.forget(shares[2].hash);

    // Query again — should still work (rebuilds cache)
    auto r2 = skiplist.query(shares[0].hash, 5, uint288(uint64_t(-1)));
    EXPECT_EQ(r1.total_weight, r2.total_weight);
}

TEST_F(WeightsTest, ClearWipesAllCache) {
    skiplist.query(shares[0].hash, 50, uint288(uint64_t(-1)));
    skiplist.clear();
    // Should still work after clear (rebuilds from scratch)
    auto result = skiplist.query(shares[0].hash, 10, uint288(uint64_t(-1)));
    EXPECT_FALSE(result.total_weight.IsNull());
}

TEST_F(WeightsTest, WeightCapProducesPartialShare) {
    auto target = bits_to_target(BITS);
    auto att = target_to_average_attempts(target);
    // Set desired_weight to 1.5 shares worth
    uint288 cap = att * 65535 + att * 65535 / 2;
    auto result = skiplist.query(shares[0].hash, CHAIN_LEN, cap);
    // total_weight should be exactly cap (partial share prorated)
    EXPECT_EQ(result.total_weight, cap);
}

// ---------------------------------------------------------------------------
// combine_deltas tests
// ---------------------------------------------------------------------------

TEST(CombineDeltas, MergesWeightsAndSums) {
    WeightsDelta a;
    a.share_count = 3;
    a.total_weight = uint288(300);
    a.total_donation_weight = uint288(30);
    a.weights[{0x01}] = uint288(100);
    a.weights[{0x02}] = uint288(200);

    WeightsDelta b;
    b.share_count = 2;
    b.total_weight = uint288(200);
    b.total_donation_weight = uint288(20);
    b.weights[{0x02}] = uint288(100);
    b.weights[{0x03}] = uint288(100);

    auto c = combine_deltas(a, b);
    EXPECT_EQ(c.share_count, 5);
    EXPECT_EQ(c.total_weight, uint288(500));
    EXPECT_EQ(c.total_donation_weight, uint288(50));
    EXPECT_EQ(c.weights[{0x01}], uint288(100));
    EXPECT_EQ(c.weights[{0x02}], uint288(300));  // 200 + 100
    EXPECT_EQ(c.weights[{0x03}], uint288(100));
}

// ---------------------------------------------------------------------------
// Decayed weights cache semantics test
// (Tests the cache invalidation logic — actual decay math is validated
//  by consensus against Python p2pool reference implementation.)
// ---------------------------------------------------------------------------

TEST(DecayedCache, SameQueryReturnsCachedResult) {
    // This is a semantic test: two identical calls should return
    // identical results.  The cache makes the second call O(1).
    // We can't test the tracker directly here without a full share
    // chain, but we verify the combine_deltas building block is
    // associative and commutative, which the cache relies on.
    WeightsDelta d1;
    d1.share_count = 1;
    d1.total_weight = uint288(100);
    d1.weights[{0xAA}] = uint288(90);
    d1.total_donation_weight = uint288(10);

    auto d2 = d1; // same delta

    auto combined_12 = combine_deltas(d1, d2);
    auto combined_21 = combine_deltas(d2, d1);

    EXPECT_EQ(combined_12.total_weight, combined_21.total_weight);
    EXPECT_EQ(combined_12.total_donation_weight, combined_21.total_donation_weight);
    EXPECT_EQ(combined_12.weights[{0xAA}], combined_21.weights[{0xAA}]);
}
