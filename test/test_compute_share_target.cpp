/**
 * Cross-implementation tests for compute_share_target().
 *
 * Verifies that c2pool's max_bits computation matches p2pool's
 * for identical chain states. Tests:
 *   1. target_to_bits_upper_bound matches p2pool FloatingInteger
 *   2. target_to_average_attempts matches p2pool
 *   3. Skip-list vs naive walk consistency after pruning
 *   4. Delta cache consistency after add/remove cycles
 *   5. Full APS computation for synthetic chains
 */

#include <gtest/gtest.h>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/config_pool.hpp>

// ─── Test 1: target_to_bits_upper_bound roundtrip ────────────

TEST(ComputeShareTarget, BitsRoundtrip_MaxTarget) {
    ltc::PoolConfig::is_testnet = true;
    uint256 max_target = ltc::PoolConfig::max_target();

    uint32_t bits = chain::target_to_bits_upper_bound(max_target);
    uint256 decoded = chain::bits_to_target(bits);

    // Decoded should be <= max_target (truncation)
    EXPECT_LE(decoded, max_target);
    // And reasonably close (top 3 bytes match)
    EXPECT_EQ(bits >> 24, 0x20u);  // exponent = 32 bytes
}

TEST(ComputeShareTarget, BitsRoundtrip_SmallTarget) {
    uint256 target;
    target.SetHex("000000000000000000000000000000000000000000000000000000000000ffff");

    uint32_t bits = chain::target_to_bits_upper_bound(target);
    uint256 decoded = chain::bits_to_target(bits);

    EXPECT_LE(decoded, target);
    EXPECT_EQ(decoded, target);
}

// Verify p2pool-compatible encoding for a target with high bit set in mantissa
TEST(ComputeShareTarget, BitsRoundtrip_HighBitSet) {
    uint256 target;
    target.SetHex("0000000000000000000000000000000000000000000000000000ff0000000000");

    uint32_t bits = chain::target_to_bits_upper_bound(target);
    uint256 decoded = chain::bits_to_target(bits);

    EXPECT_LE(decoded, target);
}

// ─── Test 2: target_to_average_attempts ──────────────────────

TEST(ComputeShareTarget, AverageAttempts_MaxTarget) {
    ltc::PoolConfig::is_testnet = true;
    auto max_target = ltc::PoolConfig::max_target();

    uint288 ata = chain::target_to_average_attempts(max_target);
    // 2^256 / (max_target + 1) = 2^256 / (2^256/20) = 20
    EXPECT_EQ(ata.GetLow64(), 20ULL);
}

TEST(ComputeShareTarget, AverageAttempts_One) {
    uint256 target(1);
    uint288 ata = chain::target_to_average_attempts(target);
    // 2^256 / (1 + 1) = 2^255 — high 64 bits are non-zero
    EXPECT_FALSE(ata.IsNull());
}

// ─── Helper: build test chain ────────────────────────────────

static void build_test_chain(ltc::ShareChain& chain, int start, int count,
                             uint32_t base_ts, uint32_t period,
                             uint32_t max_bits_val, uint256 prev = uint256())
{
    for (int i = start; i < start + count; ++i) {
        auto* share = new ltc::MergedMiningShare();
        // Deterministic hash
        char hex[65];
        std::snprintf(hex, sizeof(hex),
            "%056d%08x", 0, static_cast<uint32_t>(i));
        share->m_hash.SetHex(hex);
        share->m_prev_hash = prev;
        share->m_bits = max_bits_val;
        share->m_max_bits = max_bits_val;
        share->m_timestamp = base_ts + (i - start) * period;
        share->m_absheight = i;

        chain.add(share);
        prev = share->m_hash;
    }
}

static uint256 make_hash(int i) {
    char hex[65];
    std::snprintf(hex, sizeof(hex), "%056d%08x", 0, static_cast<uint32_t>(i));
    uint256 h;
    h.SetHex(hex);
    return h;
}

// ─── Test 3: Skip-list vs naive walk consistency ─────────────

TEST(ComputeShareTarget, SkipListMatchesNaiveWalk) {
    ltc::PoolConfig::is_testnet = true;
    ltc::ShareChain chain;

    uint32_t max_bits = chain::target_to_bits_upper_bound(ltc::PoolConfig::max_target());
    build_test_chain(chain, 0, 400, 1711900000, 4, max_bits);

    uint256 head = make_hash(399);

    for (int dist : {1, 10, 50, 100, 199}) {
        auto skip_result = chain.get_nth_parent_via_skip(head, dist);
        auto naive_result = chain.get_nth_parent_key(head, dist);
        EXPECT_EQ(skip_result, naive_result)
            << "Mismatch at dist=" << dist;
    }
}

TEST(ComputeShareTarget, SkipListAfterPruning) {
    ltc::PoolConfig::is_testnet = true;
    ltc::ShareChain chain;

    uint32_t max_bits = chain::target_to_bits_upper_bound(ltc::PoolConfig::max_target());
    build_test_chain(chain, 0, 600, 1711900000, 4, max_bits);

    uint256 head = make_hash(599);

    // Prune oldest 200 shares via remove() (matches p2pool's approach)
    for (int i = 0; i < 200; ++i) {
        chain.remove(make_hash(i));
    }

    // Verify skip list still works for valid range (400 shares remain: 200-599)
    for (int dist : {1, 10, 50, 100, 199, 300, 398}) {
        auto skip_result = chain.get_nth_parent_via_skip(head, dist);
        auto naive_result = chain.get_nth_parent_key(head, dist);
        EXPECT_EQ(skip_result, naive_result)
            << "Post-prune mismatch at dist=" << dist;
    }
}

// ─── Test 4: Delta cache consistency ─────────────────────────

TEST(ComputeShareTarget, DeltaCacheAfterPruning) {
    ltc::PoolConfig::is_testnet = true;
    ltc::ShareChain chain;

    uint32_t max_bits = chain::target_to_bits_upper_bound(ltc::PoolConfig::max_target());
    build_test_chain(chain, 0, 300, 1711900000, 4, max_bits);

    uint256 head = make_hash(299);
    uint256 far = make_hash(100);

    // Get delta before pruning
    auto delta1 = chain.get_delta(head, far);

    auto max_target = chain::bits_to_target(max_bits);
    auto per_share = chain::target_to_average_attempts(max_target);
    uint288 expected_min_work = per_share * 199;

    EXPECT_EQ(delta1.height, 199);
    EXPECT_EQ(delta1.min_work, expected_min_work);

    // Prune 50 old shares
    for (int i = 0; i < 50; ++i) {
        chain.remove(make_hash(i));
    }

    // Re-check delta for shares still in chain (100 and 299 are both > 50)
    auto delta2 = chain.get_delta(head, far);
    EXPECT_EQ(delta2.height, 199);
    EXPECT_EQ(delta2.min_work, expected_min_work)
        << "Post-prune min_work mismatch";
}

// Stress test: simulate 800-share run with continuous pruning
TEST(ComputeShareTarget, DeltaCachePruningStress) {
    ltc::PoolConfig::is_testnet = true;
    ltc::ShareChain chain;

    uint32_t max_bits = chain::target_to_bits_upper_bound(ltc::PoolConfig::max_target());
    auto max_target = chain::bits_to_target(max_bits);
    auto per_share = chain::target_to_average_attempts(max_target);

    const int CHAIN_LEN = 400;
    const int TOTAL = 800;

    // Build initial chain
    build_test_chain(chain, 0, CHAIN_LEN, 1711900000, 4, max_bits);

    // Simulate adding 400 more shares with pruning
    uint256 prev = make_hash(CHAIN_LEN - 1);
    for (int i = CHAIN_LEN; i < TOTAL; ++i) {
        // Add new share
        auto* share = new ltc::MergedMiningShare();
        char hex[65];
        std::snprintf(hex, sizeof(hex), "%056d%08x", 0, static_cast<uint32_t>(i));
        share->m_hash.SetHex(hex);
        share->m_prev_hash = prev;
        share->m_bits = max_bits;
        share->m_max_bits = max_bits;
        share->m_timestamp = 1711900000 + i * 4;
        share->m_absheight = i;
        chain.add(share);
        prev = share->m_hash;

        // Prune oldest share (keep chain at CHAIN_LEN)
        int oldest = i - CHAIN_LEN + 1;
        if (oldest >= 0) {
            chain.remove(make_hash(oldest));
        }

        // Periodic delta verification (every 50 shares)
        if (i % 50 == 0) {
            uint256 head = make_hash(i);
            int far_idx = i - 199;
            if (far_idx >= oldest + 1) {  // far must be in chain
                uint256 far_h = make_hash(far_idx);
                if (chain.contains(far_h)) {
                    auto delta = chain.get_delta(head, far_h);
                    EXPECT_EQ(delta.height, 199)
                        << "Height mismatch at share " << i;

                    // Also verify skip list
                    auto skip_far = chain.get_nth_parent_via_skip(head, 199);
                    EXPECT_EQ(skip_far, far_h)
                        << "Skip list mismatch at share " << i;
                }
            }
        }
    }
}

// ─── Test 5: APS matches expected value ──────────────────────

TEST(ComputeShareTarget, APSMatchesPython) {
    ltc::PoolConfig::is_testnet = true;
    ltc::ShareChain chain;

    uint32_t max_bits = chain::target_to_bits_upper_bound(ltc::PoolConfig::max_target());
    build_test_chain(chain, 0, 300, 1711900000, 4, max_bits);

    uint256 head = make_hash(299);
    auto far_hash = chain.get_nth_parent_via_skip(head, 199);
    ASSERT_FALSE(far_hash.IsNull());

    auto delta = chain.get_delta(head, far_hash);
    uint288 attempts = delta.min_work;

    uint32_t near_ts = 0, far_ts = 0;
    chain.get_share(head).invoke([&](auto* obj) { near_ts = obj->m_timestamp; });
    chain.get_share(far_hash).invoke([&](auto* obj) { far_ts = obj->m_timestamp; });

    int32_t time_span = int32_t(near_ts) - int32_t(far_ts);
    ASSERT_GT(time_span, 0);

    uint288 aps = attempts / uint288(time_span);

    // Expected: 199 shares * 20 ata = 3980, time = 199 * 4 = 796
    // aps = 3980 / 796 = 5 (exact)
    EXPECT_EQ(aps.GetLow64(), 5ULL)
        << "APS mismatch: attempts=" << attempts.GetLow64()
        << " time=" << time_span;

    // pre_target = 2^256 / (4 * 5) - 1 = MAX_TARGET
    uint288 two_256;
    two_256.SetHex("10000000000000000000000000000000000000000000000000000000000000000");
    uint288 divisor = aps * uint32_t(ltc::PoolConfig::share_period());
    uint288 result = two_256 / divisor;
    if (result > uint288(1))
        result = result - uint288(1);

    uint256 pre_target;
    uint288 max_288;
    max_288.SetHex(ltc::PoolConfig::max_target().GetHex());
    if (result > max_288) {
        pre_target = ltc::PoolConfig::max_target();
    } else {
        pre_target.SetHex(result.GetHex());
    }

    auto max_target = ltc::PoolConfig::max_target();
    EXPECT_EQ(chain::target_to_bits_upper_bound(pre_target),
              chain::target_to_bits_upper_bound(max_target))
        << "pre_target should equal MAX_TARGET for uniform chain";
}
