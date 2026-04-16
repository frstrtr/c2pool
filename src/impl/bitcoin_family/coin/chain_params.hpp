#pragma once

// Generic Bitcoin-family chain parameters for header validation.
// Every coin provides its own constants; the structure is universal.
// Used by HeaderChain for difficulty retargeting and PoW validation.

#include <core/uint256.hpp>
#include <core/pow.hpp>

#include <cstdint>
#include <string>

namespace bitcoin_family
{
namespace coin
{

struct ChainParams
{
    int64_t target_timespan{0};      // difficulty window (LTC: 302400, BTC: 1209600)
    int64_t target_spacing{0};       // target block interval (LTC: 150, BTC: 600, DOGE: 60)
    bool    allow_min_difficulty{false}; // testnet only
    bool    no_retargeting{false};   // regtest only
    uint256 pow_limit;               // easiest allowed PoW target
    uint256 genesis_hash;            // genesis block hash (SHA256d for identification)

    // Optional: checkpoint for fast-sync (skip syncing from genesis)
    struct Checkpoint { uint32_t height{0}; uint256 hash; };
    std::optional<Checkpoint> fast_start_checkpoint;

    // Halving
    uint32_t halving_interval{0};    // LTC: 840000, BTC: 210000, DOGE: 0 (no halving)
    uint64_t initial_subsidy{0};     // LTC: 5000000000, BTC: 5000000000

    // PoW function: computes the hash used for difficulty comparison.
    // LTC/DOGE: scrypt, BTC: sha256d, Dash: X11
    core::PowFunc pow_func;

    // Block identity hash: SHA256d for all Bitcoin-family coins.
    // This is the "real" block hash used for getdata/inv/prev_block references.
    // Differs from pow_func for coins where PoW uses a different algorithm.
    core::BlockHashFunc block_hash_func;

    int64_t difficulty_adjustment_interval() const {
        return (target_spacing > 0) ? (target_timespan / target_spacing) : 1;
    }
};

// Generic difficulty retargeting (Bitcoin/Litecoin algorithm).
// Coins with different retargeting (e.g., DigiShield for DOGE) override this.
inline uint32_t calculate_next_work_required(
    uint32_t tip_bits,
    int64_t  tip_time,
    int64_t  first_block_time,
    const ChainParams& params)
{
    if (params.no_retargeting)
        return tip_bits;

    int64_t actual_timespan = tip_time - first_block_time;

    // Clamp to [timespan/4, timespan*4]
    if (actual_timespan < params.target_timespan / 4)
        actual_timespan = params.target_timespan / 4;
    if (actual_timespan > params.target_timespan * 4)
        actual_timespan = params.target_timespan * 4;

    // Retarget
    uint256 bn_new;
    bn_new.SetCompact(tip_bits);

    // bn_new = bn_new * actual_timespan / target_timespan
    // Use intermediate uint288 to avoid overflow
    uint288 wide = uint288(bn_new);
    wide = wide * static_cast<uint32_t>(actual_timespan);
    wide = wide / static_cast<uint32_t>(params.target_timespan);

    bn_new = uint256(wide.GetLow64());
    // Reconstruct from wide — take lower 256 bits
    for (int i = 0; i < 32; ++i)
        bn_new.data()[i] = reinterpret_cast<const unsigned char*>(&wide)[i];

    if (bn_new > params.pow_limit)
        bn_new = params.pow_limit;

    return bn_new.GetCompact();
}

} // namespace coin
} // namespace bitcoin_family
