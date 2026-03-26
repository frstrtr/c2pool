#pragma once

/// Dogecoin chain parameters for embedded SPV node.
///
/// Supports three consensus eras:
///   1. Pre-DigiShield (height 0-144999): standard 4h retarget, random rewards
///   2. DigiShield (height 145000-371336): 1-block retarget, fixed rewards
///   3. AuxPoW (height 371337+): merge-mined with chain ID 0x0062
///
/// Testnet4alpha: DigiShield + AuxPoW from genesis.

#include <core/uint256.hpp>
#include <optional>
#include <cstdint>

namespace doge {
namespace coin {

struct DOGEChainParams
{
    // ─── Consensus timing ─────────────────────────────────────────────
    // Pre-DigiShield: 4h retarget window, 60s block time
    static constexpr int64_t PRE_DIGISHIELD_TARGET_TIMESPAN = 4 * 60 * 60; // 14400s
    static constexpr int64_t TARGET_SPACING = 60;                          // 1 minute blocks

    // DigiShield: 60s retarget window (1 block)
    static constexpr int64_t DIGISHIELD_TARGET_TIMESPAN = 60;

    // Retarget interval (pre-DigiShield only)
    static constexpr int64_t PRE_DIGISHIELD_INTERVAL = PRE_DIGISHIELD_TARGET_TIMESPAN / TARGET_SPACING; // 240

    // Subsidy halving interval
    static constexpr int32_t SUBSIDY_HALVING_INTERVAL = 100000;

    // ─── Activation heights ───────────────────────────────────────────
    uint32_t digishield_height{145000};
    uint32_t simplified_rewards_height{145000};
    uint32_t auxpow_height{371337};

    // ─── AuxPoW ───────────────────────────────────────────────────────
    static constexpr uint32_t AUXPOW_CHAIN_ID = 0x0062; // 98 — "Josh Wise!"
    bool strict_chain_id{true};

    // ─── Rewards ─────────────────────────────────────────────────────
    bool simplified_rewards{true};   // false = random rewards (testnet4alpha)

    // ─── PoW limits ───────────────────────────────────────────────────
    uint256 pow_limit;
    uint256 genesis_hash;
    bool allow_min_difficulty{false};

    // ─── Checkpoint (optional) ────────────────────────────────────────
    struct Checkpoint { uint32_t height{0}; uint256 hash; };
    std::optional<Checkpoint> fast_start_checkpoint;

    // ─── Factory methods ──────────────────────────────────────────────

    static DOGEChainParams mainnet() {
        DOGEChainParams p;
        p.pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        p.genesis_hash.SetHex("1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691");
        p.digishield_height = 145000;
        p.simplified_rewards_height = 145000;
        p.auxpow_height = 371337;
        p.strict_chain_id = true;
        p.allow_min_difficulty = false;
        return p;
    }

    static DOGEChainParams testnet() {
        DOGEChainParams p;
        p.pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        p.genesis_hash.SetHex("bb0a78264637406b6360aad926284d544d7049f45189db5664f3c4d07350559e");
        p.digishield_height = 145000;
        p.simplified_rewards_height = 145000;
        p.auxpow_height = 158100;
        p.strict_chain_id = false;
        p.allow_min_difficulty = true;
        return p;
    }

    static DOGEChainParams testnet4alpha() {
        DOGEChainParams p;
        p.pow_limit.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        p.genesis_hash.SetHex("de2bcf594a4134cef164a2204ca2f9bce745ff61c22bd714ebc88a7f2bdd8734");
        // DigiShield + AuxPoW from genesis on testnet4alpha
        p.digishield_height = 0;
        p.simplified_rewards_height = 0;
        p.auxpow_height = 0;
        p.strict_chain_id = true;
        p.allow_min_difficulty = true;
        // testnet4alpha does NOT set fSimplifiedRewards → random rewards via MT
        p.simplified_rewards = false;
        return p;
    }

    // ─── Helpers ──────────────────────────────────────────────────────

    bool is_digishield(uint32_t height) const { return height >= digishield_height; }
    bool is_auxpow(uint32_t height) const { return height >= auxpow_height; }
    bool is_simplified_rewards(uint32_t height) const { return height >= simplified_rewards_height; }

    int64_t target_timespan(uint32_t height) const {
        return is_digishield(height) ? DIGISHIELD_TARGET_TIMESPAN : PRE_DIGISHIELD_TARGET_TIMESPAN;
    }
};

// ─── DigiShield v3 difficulty calculation ─────────────────────────────────
// Direct port from dogecoin/src/dogecoin.cpp CalculateDogecoinNextWorkRequired()
//
// Args:
//   prev_bits:  nBits of the previous block
//   prev_time:  timestamp of the previous block
//   first_time: timestamp of the block at (prev_height - retarget_interval)
//   height:     height of the NEW block being validated
//   params:     chain parameters
//
// Returns: expected nBits for the new block.
inline uint32_t calculate_doge_next_work(
    uint32_t prev_bits,
    int64_t prev_time,
    int64_t first_time,
    uint32_t height,
    const DOGEChainParams& params)
{
    const int64_t retarget_timespan = params.target_timespan(height);
    const int64_t actual_timespan = prev_time - first_time;
    int64_t modulated = actual_timespan;
    int64_t min_timespan, max_timespan;

    if (params.is_digishield(height)) {
        // DigiShield v3: amplitude filter (dampen oscillations)
        modulated = retarget_timespan + (modulated - retarget_timespan) / 8;
        min_timespan = retarget_timespan - (retarget_timespan / 4);  // 75% of target
        max_timespan = retarget_timespan + (retarget_timespan / 2);  // 150% of target
    } else if (height > 10000) {
        min_timespan = retarget_timespan / 4;
        max_timespan = retarget_timespan * 4;
    } else if (height > 5000) {
        min_timespan = retarget_timespan / 8;
        max_timespan = retarget_timespan * 4;
    } else {
        min_timespan = retarget_timespan / 16;
        max_timespan = retarget_timespan * 4;
    }

    // Clamp
    if (modulated < min_timespan) modulated = min_timespan;
    if (modulated > max_timespan) modulated = max_timespan;

    // Retarget: new_target = old_target * modulated_timespan / retarget_timespan
    bool negative, overflow;
    uint256 target;
    target.SetCompact(prev_bits, &negative, &overflow);
    if (negative || target.IsNull() || overflow)
        return prev_bits;

    // For DigiShield, modulated and retarget_timespan are small values (< 2^32),
    // so we can use uint256's existing *= and /= operators safely.
    // Same approach as LTC's calculate_next_work_required().
    const uint256 bn_pow_limit = params.pow_limit;
    bool shift = target.bits() > bn_pow_limit.bits() - 1;
    if (shift)
        target >>= 1;
    target *= static_cast<uint32_t>(modulated);
    target /= uint256(static_cast<uint64_t>(retarget_timespan));
    if (shift)
        target <<= 1;

    if (target > params.pow_limit)
        target = params.pow_limit;

    return target.GetCompact();
}

// ─── DOGE subsidy schedule ────────────────────────────────────────────────
// Port from dogecoin/src/dogecoin.cpp GetDogecoinBlockSubsidy()
//
// Two modes:
//   fSimplifiedRewards=true  (mainnet ≥145000, testnet3 ≥145000):
//     Height <600000: 500000 * COIN >> halvings (fixed)
//     Height ≥600000: 10000 * COIN (forever)
//   fSimplifiedRewards=false (testnet4alpha, mainnet <145000):
//     Random reward derived from prevHash via Mersenne Twister
//     Range: [1, (1000000 >> halvings) - 1] * COIN
//
// The prevHash overload computes the exact random subsidy.
// The no-prevHash overload returns the MAX for fee estimation.

#include <random>

// Exact port of boost::uniform_int<>::operator()(gen) for range [min, max].
// boost::uniform_int uses rejection sampling: generate a raw value, scale,
// and reject if it falls outside the range.  std::mt19937 and boost::mt19937
// produce identical raw output for the same seed (both are MT19937).
inline int doge_mt_uniform_int(unsigned int seed, int min_val, int max_val)
{
    std::mt19937 gen(seed);
    // boost::uniform_int<int>(min, max)(gen) uses this algorithm:
    // range = max - min, bucket_size = (gen.max() - gen.min() + 1) / (range + 1)
    // loop: val = (gen() - gen.min()) / bucket_size; if val <= range, return min + val
    uint32_t range = static_cast<uint32_t>(max_val - min_val);
    uint64_t bucket_size = (uint64_t(0xFFFFFFFF) + 1) / (uint64_t(range) + 1);
    for (;;) {
        uint32_t raw = gen();
        uint32_t val = static_cast<uint32_t>(raw / bucket_size);
        if (val <= range)
            return min_val + static_cast<int>(val);
    }
}

inline uint64_t get_doge_block_subsidy(uint32_t height, const DOGEChainParams& params,
                                        const uint256& prev_hash)
{
    static constexpr uint64_t COIN = 100000000ULL;
    int halvings = static_cast<int>(height) / DOGEChainParams::SUBSIDY_HALVING_INTERVAL;

    if (params.simplified_rewards) {
        if (height >= 600000) return 10000ULL * COIN;
        if (height < 6u * DOGEChainParams::SUBSIDY_HALVING_INTERVAL)
            return (500000ULL * COIN) >> halvings;
        return 10000ULL * COIN;
    }

    // Random rewards: exact port of dogecoin/src/dogecoin.cpp
    std::string hash_hex = prev_hash.GetHex();
    std::string seed_str = hash_hex.substr(7, 7);
    unsigned int seed = static_cast<unsigned int>(std::strtoul(seed_str.c_str(), nullptr, 16));
    int64_t max_reward = (1000000LL >> halvings) - 1;
    if (max_reward <= 0) return COIN;

    int rand_val = doge_mt_uniform_int(seed, 1, static_cast<int>(max_reward));
    return static_cast<uint64_t>(1 + rand_val) * COIN;
}

// Max-subsidy overload (for fee estimation, no prevHash needed)
inline uint64_t get_doge_block_subsidy(uint32_t height, const DOGEChainParams& params)
{
    static constexpr uint64_t COIN = 100000000ULL;
    int halvings = static_cast<int>(height) / DOGEChainParams::SUBSIDY_HALVING_INTERVAL;
    if (height >= 600000) return 10000ULL * COIN;
    if (params.simplified_rewards)
        return (500000ULL * COIN) >> halvings;
    if (halvings >= 20) return 0;
    return (1000000ULL * COIN) >> halvings;
}

} // namespace coin
} // namespace doge
