#pragma once

// DGB CoinParams factory: builds a fully populated core::CoinParams for the
// DigiByte-Scrypt p2pool parent chain.
//
// SOURCE OF TRUTH: the DGB oracle frstrtr/p2pool-dgb-scrypt (operator ruling
// 2026-06-17, "switch-oracle" / Option B). The V36-master byte-compat
// constraint with p2pool-merged-v36 is FORMALLY WAIVED for DGB by that ruling.
//
// CONSENSUS-NEUTRALITY: this factory holds NO hardcoded consensus bytes of its
// own. Every consensus-critical value is sourced from the single-source-of-truth
// static members of dgb::CoinParams (config_coin.hpp) and dgb::PoolConfig
// (config_pool.hpp), so there is exactly one place a DGB constant can drift.
//
// Scrypt-only (V36): pow_func = scrypt; other DGB algos are accept-by-continuity
// per project_v36_dgb_scrypt_only and never reach Scrypt share validation.

#include "config_coin.hpp"
#include "config_pool.hpp"

#include <core/coin_params.hpp>
#include <core/pow.hpp>

namespace dgb
{

inline core::CoinParams make_coin_params(bool testnet)
{
    core::CoinParams p;

    // ===== Coin-level (net.PARENT) — from dgb::CoinParams (config_coin.hpp) =====
    p.symbol       = "DGB";
    p.block_period = CoinParams::BLOCK_PERIOD;  // 75s (Scrypt-only parent period, oracle PARENT.BLOCK_PERIOD)

    // Address encoding
    if (testnet) {
        p.address_version      = CoinParams::TESTNET_ADDRESS_VERSION;  // 126
        p.address_p2sh_version = CoinParams::TESTNET_P2SH_VERSION;     // 140
        p.bech32_hrp           = CoinParams::TESTNET_BECH32_HRP;       // "dgbt"
    } else {
        p.address_version      = CoinParams::ADDRESS_VERSION;          // 30 (D...)
        p.address_p2sh_version = CoinParams::ADDRESS_P2SH_VERSION;     // 63 (S...)
        p.bech32_hrp           = CoinParams::BECH32_HRP;               // "dgb"
    }
    // address_p2sh_version2: secondary P2SH prefix for parse leniency only, NOT
    // block/share validation. The oracle defines a SINGLE P2SH version (63); it
    // is silent on a second prefix, so 5 (DGB legacy) is NOT oracle-sourced.
    // [confirm-vs-oracle] kept open — see oracle-conformance report.
    p.address_p2sh_version2 = testnet ? 0 : 5;

    // PoW: Scrypt work, SHA256d block identity (same shape as LTC)
    p.pow_func        = core::pow::scrypt;
    p.block_hash_func = core::pow::sha256d;

    // Subsidy: DGB 3-phase decay schedule (config_coin.hpp SSOT)
    p.subsidy_func = [](uint32_t height) -> uint64_t {
        return CoinParams::subsidy(height);
    };

    // Dust threshold: 0.001 DGB = 100000 sat. Confirmed vs oracle DUST_THRESHOLD
    // (0.001e8). Local relay policy, not consensus.
    p.dust_threshold = 100000;

    // Softforks — from PoolConfig SSOT (oracle: nversionbips,csv,segwit,reservealgo,odo,taproot)
    p.softforks_required        = PoolConfig::SOFTFORKS_REQUIRED;
    p.segwit_activation_version = PoolConfig::SEGWIT_ACTIVATION_VERSION;  // 35

    // ===== Pool-level (net) — from dgb::PoolConfig (config_pool.hpp) =====
    p.p2p_port    = PoolConfig::P2P_PORT;  // 5024 (DGB sharechain P2P)
    // worker_port: DGB Stratum port. Confirmed vs oracle WORKER_PORT = 5025.
    // Operator-overridable via pool.yaml.
    p.worker_port = 5025;

    if (testnet) {
        p.share_period     = PoolConfig::TESTNET_SHARE_PERIOD;       // 4
        p.chain_length     = PoolConfig::TESTNET_CHAIN_LENGTH;       // 400
        p.real_chain_length = PoolConfig::TESTNET_REAL_CHAIN_LENGTH;  // 400
    } else {
        p.share_period     = PoolConfig::SHARE_PERIOD;              // 15
        p.chain_length     = PoolConfig::CHAIN_LENGTH;             // 2880
        p.real_chain_length = PoolConfig::REAL_CHAIN_LENGTH;        // 2880
    }

    p.target_lookbehind        = PoolConfig::TARGET_LOOKBEHIND;          // 100
    p.spread                   = PoolConfig::SPREAD;                     // 24
    p.minimum_protocol_version = PoolConfig::MINIMUM_PROTOCOL_VERSION;   // 1700 floor
    p.block_max_size           = PoolConfig::BLOCK_MAX_SIZE;
    p.block_max_weight         = PoolConfig::BLOCK_MAX_WEIGHT;

    // Max target (share difficulty floor) — PoolConfig SSOT, testnet-aware
    PoolConfig::is_testnet = testnet;
    p.max_target = PoolConfig::max_target();

    // Network identification — DGB oracle (switch-oracle Option B)
    p.identifier_hex         = PoolConfig::IDENTIFIER_HEX;          // 4b62545b1a631afe
    p.prefix_hex             = PoolConfig::DEFAULT_PREFIX_HEX;      // 1c0553f23ebfcffe
    p.testnet_identifier_hex = PoolConfig::TESTNET_IDENTIFIER_HEX;
    p.testnet_prefix_hex     = PoolConfig::TESTNET_PREFIX_HEX;

    // Bootstrap peers (populated as DGB p2pool nodes come online)
    p.bootstrap_addrs = PoolConfig::DEFAULT_BOOTSTRAP_HOSTS;

    // Donation scripts (consensus-critical) — version-gated selection lives in
    // PoolConfig::get_donation_script (SSOT). v35 = forrestv P2PK (4104ffd0...),
    // v36+ = combined P2SH 1-of-2.
    p.donation_script_func = [](int64_t share_version) -> std::vector<unsigned char> {
        return PoolConfig::get_donation_script(share_version);
    };

    p.current_share_version = 36;
    p.is_testnet            = testnet;

    return p;
}

} // namespace dgb
