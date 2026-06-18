#pragma once

// DASH P2Pool sharechain network configuration (oracle-sourced SSOT).
//
// SOURCE OF TRUTH: the DASH oracle frstrtr/p2pool-dash, networks/dash.py +
// networks/dash_testnet.py (operator 2026-06-17 per-coin re-scope: DASH conforms
// to its OWN older-than-v35 oracle, NOT a v35-uniform baseline).
//
// SCOPE: pins the p2pool *sharechain* framing constants (PREFIX/IDENTIFIER/
// SHARE_PERIOD/CHAIN_LENGTH/TARGET_LOOKBEHIND/SPREAD/P2P_PORT/WORKER_PORT/
// MIN_PROTOCOL/MAX_TARGET) as the single place a DASH sharechain constant can
// drift. Consumed by test_dash_conformance (oracle pin) and is the SSOT the
// dash::make_coin_params factory will read. Factory wiring + Fileconfig/pool.yaml
// runtime-override integration are the S6 follow-on, deliberately out of scope
// here so this header carries no file-loading machinery.
//
// PREFIX/IDENTIFIER are ISOLATION PRIMITIVES (operator v36_standardization_goal
// 2026-06-17): kept per-coin AND per-instance, NEVER unified cross-coin.

#include <cstdint>
#include <string>

#include <core/uint256.hpp>

namespace dash
{

// DASH sharechain p2pool constants. Source of truth: p2pool-dash oracle
// networks/dash.py (mainnet) + networks/dash_testnet.py (testnet).
struct PoolConfig
{
    // ---- mainnet (networks/dash.py) ----
    static constexpr uint16_t P2P_PORT                  = 8999;
    static constexpr uint16_t WORKER_PORT               = 7903;
    static constexpr uint32_t SHARE_PERIOD              = 20;     // seconds
    static constexpr uint32_t CHAIN_LENGTH              = 4320;   // 24*60*60//20
    static constexpr uint32_t REAL_CHAIN_LENGTH         = 4320;
    static constexpr uint32_t TARGET_LOOKBEHIND         = 100;
    static constexpr uint32_t SPREAD                    = 10;     // blocks
    static constexpr uint32_t MINIMUM_PROTOCOL_VERSION  = 1700;   // protocol v1700 floor

    // ---- testnet (networks/dash_testnet.py) ----
    static constexpr uint16_t TESTNET_P2P_PORT          = 18999;
    static constexpr uint16_t TESTNET_WORKER_PORT       = 17903;
    static constexpr uint32_t TESTNET_SHARE_PERIOD      = 20;
    static constexpr uint32_t TESTNET_CHAIN_LENGTH      = 4320;
    static constexpr uint32_t TESTNET_REAL_CHAIN_LENGTH = 4320;

    static inline bool is_testnet = false;

    static uint16_t p2p_port()          { return is_testnet ? TESTNET_P2P_PORT : P2P_PORT; }
    static uint16_t worker_port()       { return is_testnet ? TESTNET_WORKER_PORT : WORKER_PORT; }
    static uint32_t share_period()      { return is_testnet ? TESTNET_SHARE_PERIOD : SHARE_PERIOD; }
    static uint32_t chain_length()      { return is_testnet ? TESTNET_CHAIN_LENGTH : CHAIN_LENGTH; }
    static uint32_t real_chain_length() { return is_testnet ? TESTNET_REAL_CHAIN_LENGTH : REAL_CHAIN_LENGTH; }

    // ISOLATION PRIMITIVES — per-coin AND per-instance, never unified cross-coin.
    static inline const std::string IDENTIFIER_HEX         = "7242ef345e1bed6b";
    static inline const std::string PREFIX_HEX             = "3b3e1286f446b891";
    static inline const std::string TESTNET_IDENTIFIER_HEX = "b6deb1e543fe2427";
    static inline const std::string TESTNET_PREFIX_HEX     = "198b644f6821e3b3";

    static const std::string& identifier_hex() { return is_testnet ? TESTNET_IDENTIFIER_HEX : IDENTIFIER_HEX; }
    static const std::string& prefix_hex()     { return is_testnet ? TESTNET_PREFIX_HEX     : PREFIX_HEX; }

    // MAX_TARGET: easiest allowed share difficulty (share-diff floor).
    //   mainnet : 0xFFFF * 2**208      (standard bdiff difficulty-1 target)
    //   testnet : 2**256 // 2**20 - 1
    static uint256 max_target()
    {
        static const uint256 MAINNET_MAX = [] {
            uint256 t;
            t.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
            return t;
        }();
        static const uint256 TESTNET_MAX = [] {
            uint256 t;
            t.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            return t;
        }();
        return is_testnet ? TESTNET_MAX : MAINNET_MAX;
    }
};

} // namespace dash
