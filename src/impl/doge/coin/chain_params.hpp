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

    // Use 512-bit arithmetic to avoid overflow: target * modulated / retarget
    // Since uint256 doesn't have native multiply-by-int64, we use shift+add.
    // For DigiShield, modulated is close to retarget_timespan (45-90 seconds),
    // so we can safely multiply a uint256 by a small int64.
    uint256 new_target = target;
    // Multiply: new_target *= modulated
    {
        uint256 t = new_target;
        new_target.SetNull();
        int64_t m = modulated;
        for (int bit = 0; m > 0 && bit < 64; ++bit) {
            if (m & 1) {
                uint256 shifted = t;
                shifted <<= bit;
                new_target = new_target + shifted;
            }
            m >>= 1;
        }
    }
    // Divide: new_target /= retarget_timespan
    {
        // Simple long division for uint256 / int64
        uint256 quotient;
        uint256 remainder;
        uint64_t divisor = static_cast<uint64_t>(retarget_timespan);
        for (int i = 255; i >= 0; --i) {
            remainder <<= 1;
            if (new_target.IsSet(i))
                remainder = remainder + uint256::ONE;
            if (remainder >= uint256(divisor)) {
                remainder = remainder - uint256(divisor);
                quotient.SetBit(i);
            }
        }
        new_target = quotient;
    }

    if (new_target > params.pow_limit)
        new_target = params.pow_limit;

    return new_target.GetCompact();
}

// ─── DOGE subsidy schedule ────────────────────────────────────────────────
// Port from dogecoin/src/dogecoin.cpp GetDogecoinBlockSubsidy()
//
// Height 0-144999:     random (simplified: use max = 500000 * COIN >> halvings)
// Height 145000-599999: 500000 * COIN >> halvings (fixed schedule)
// Height 600000+:       10000 * COIN (forever)
inline uint64_t get_doge_block_subsidy(uint32_t height, const DOGEChainParams& params)
{
    static constexpr uint64_t COIN = 100000000ULL; // 1 DOGE = 10^8 koinu

    int halvings = static_cast<int>(height) / DOGEChainParams::SUBSIDY_HALVING_INTERVAL;

    if (height >= 600000) {
        return 10000ULL * COIN;
    }

    if (params.is_simplified_rewards(height)) {
        // Fixed schedule: 500000 >> halvings
        return (500000ULL * COIN) >> halvings;
    }

    // Pre-simplified: max possible reward (for template building)
    // Real blocks use Mersenne Twister random, but for templates we use max
    if (halvings >= 20) return 0; // overflow protection
    return (1000000ULL * COIN) >> halvings;
}

} // namespace coin
} // namespace doge
