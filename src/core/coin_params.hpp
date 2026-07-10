// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// CoinParams: the "net" equivalent from Python p2pool.
// A single struct that carries ALL coin-specific and pool-specific parameters.
// Flows through the entire stack — share verification, tracker, node, stratum.
// Each coin module (ltc, dash, doge, btc) provides a factory function
// that returns a populated CoinParams instance.

#include "pow.hpp"
#include "uint256.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <set>
#include <string>
#include <vector>

namespace core
{

struct CoinParams
{
    // =======================================================================
    // Coin-level parameters (p2pool's net.PARENT)
    // =======================================================================

    std::string symbol;                      // "LTC", "DASH", "BTC", "DOGE"
    uint32_t block_period = 0;               // target block interval (seconds)

    // Address encoding
    uint8_t address_version = 0;             // P2PKH version byte
    uint8_t address_p2sh_version = 0;        // P2SH version byte
    uint8_t address_p2sh_version2 = 0;       // secondary P2SH version (LTC: 5)
    std::string bech32_hrp;                  // bech32 prefix ("ltc1", "bc1", "")

    // PoW
    PowFunc pow_func;                        // scrypt, sha256d, x11, ...
    BlockHashFunc block_hash_func;           // block identity hash (usually sha256d)

    // Block rewards
    SubsidyFunc subsidy_func;                // height -> reward in satoshis

    // Dust
    uint64_t dust_threshold = 0;

    // Softforks
    std::set<std::string> softforks_required;
    uint32_t segwit_activation_version = 0;  // 0 = no segwit (Dash)

    // =======================================================================
    // Pool-level parameters (p2pool's net)
    // =======================================================================

    uint16_t p2p_port = 0;                   // p2pool P2P port
    uint16_t worker_port = 0;                // Stratum port

    uint32_t share_period = 0;               // target share interval (seconds)
    uint32_t chain_length = 0;               // PPLNS window size (shares)
    uint32_t real_chain_length = 0;          // actual chain length for lookups
    uint32_t target_lookbehind = 0;          // shares to look back for target calc
    uint32_t spread = 0;                     // PPLNS spread multiplier
    uint32_t minimum_protocol_version = 0;   // min p2pool protocol version
    uint32_t advertised_protocol_version = 0; // version we ADVERTISE (our capability); >= floor, separate from accept-floor per p2pool
    uint32_t block_max_size = 0;
    uint32_t block_max_weight = 0;

    uint256 max_target;                      // easiest allowed share difficulty

    // Network identification
    std::string identifier_hex;              // 8-byte hex identifier
    std::string prefix_hex;                  // 8-byte hex prefix
    std::string testnet_identifier_hex;
    std::string testnet_prefix_hex;

    // Bootstrap peers
    std::vector<std::string> bootstrap_addrs;

    // Donation scripts (consensus-critical)
    DonationScriptFunc donation_script_func;

    // Share version
    uint32_t current_share_version = 0;      // 36 (LTC), 16 (Dash)

    // =======================================================================
    // Stratum vardiff config (matches upstream ref per coin)
    // =======================================================================
    //
    // LTC defaults match p2pool-merged-v36/bitcoin/stratum.py (jtoomim's
    // two-trigger algorithm with N−1 interval denominator).
    //
    // Dash overrides match p2pool-dash/dash/stratum.py + networks/dash.py
    // (ASIC-tuned three-trigger algorithm with quickup support and tighter
    // clip bounds; uses N interval denominator).
    struct VardiffConfig
    {
        double target_share_rate = 3.0;      // target seconds per pseudoshare
        uint32_t shares_trigger  = 12;       // trigger 1: adjust after this many shares
        double timeout_mult      = 10.0;     // trigger 2: adjust if time > mult * N * rate
        // Quickup trigger (p2pool-dash only; set quickup_shares = 0 to disable):
        uint32_t quickup_shares  = 0;        // trigger 3: need at least N shares
        double quickup_divisor   = 3.0;      // trigger 3: fire if time < target_time/divisor
        double min_adjust        = 0.1;      // clip(ratio, min, max) bounds
        double max_adjust        = 10.0;
        // Denominator policy for actual_rate calculation:
        //   false → N−1 intervals (matches p2pool-merged-v36 LTC: del [0])
        //   true  → N shares      (matches p2pool-dash: no del)
        bool use_full_window     = false;
    };
    VardiffConfig vardiff;

    // Runtime state
    bool is_testnet = false;

    // =======================================================================
    // Convenience accessors (testnet-aware, like PoolConfig:: methods)
    // =======================================================================

    // These are populated by the coin module's factory based on is_testnet.
    // Unlike PoolConfig's static methods, these are already resolved at
    // construction time — no branching needed at call sites.

    const std::string& active_identifier_hex() const
    {
        return is_testnet ? testnet_identifier_hex : identifier_hex;
    }

    const std::string& active_prefix_hex() const
    {
        return is_testnet ? testnet_prefix_hex : prefix_hex;
    }
};

} // namespace core