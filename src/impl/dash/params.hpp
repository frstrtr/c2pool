#pragma once

// DASH CoinParams factory: builds a fully populated core::CoinParams for the
// DASH (X11) p2pool parent chain.
//
// SOURCE OF TRUTH: the DASH oracle frstrtr/p2pool-dash, networks/dash.py +
// networks/dash_testnet.py (operator 2026-06-17 per-coin re-scope: DASH conforms
// to its OWN older-than-v35 oracle, NOT a v35-uniform baseline).
//
// POOL-LEVEL FIELDS are sourced exclusively from dash::PoolConfig
// (config_pool.hpp) — the sharechain SSOT shipped in PR #146 — so there is
// exactly one place a DASH sharechain constant can drift. COIN-LEVEL fields are
// inlined here with oracle citations (mirroring ltc/params.hpp; DASH carries no
// separate config_coin.hpp).
//
// PREFIX/IDENTIFIER are ISOLATION PRIMITIVES (operator v36_standardization_goal
// 2026-06-17): kept per-coin AND per-instance, NEVER unified cross-coin.

#include "config_pool.hpp"
#include "crypto/hash_x11.hpp"
#include "share_check.hpp"  // dash::DONATION_SCRIPT (consensus-critical SSOT)

#include <core/coin_params.hpp>
#include <core/pow.hpp>

#include <optional>
#include <string>
#include <vector>

namespace dash
{

// Runtime override seam for pool.yaml (Fileconfig consume-side, S6 follow-on).
// ONLY operationally-tunable, NON-consensus, NON-isolation pool fields may be
// overridden by an operator pool.yaml. Consensus-critical fields (share version,
// max_target, donation script, X11 pow/block identity) and the network ISOLATION
// PRIMITIVES (prefix/identifier) are deliberately ABSENT from this struct and are
// therefore NEVER overridable: they stay pinned to the dash::PoolConfig SSOT
// regardless of any override file, so a mis-edited pool.yaml can retune
// ports/peers but can NEVER fork the sharechain off its oracle-conformant
// identity. The YAML file-load half lands when DASH gains its config_pool.cpp
// Fileconfig (mirrors dgb/btc); this header carries no file IO.
struct PoolOverrides
{
    std::optional<uint16_t>                 p2p_port;
    std::optional<uint16_t>                 worker_port;
    std::optional<std::vector<std::string>> bootstrap_addrs;
};

inline core::CoinParams make_coin_params(bool testnet, const PoolOverrides& overrides)
{
    core::CoinParams p;

    // ===== Coin-level (net.PARENT) — DASH oracle networks/dash.py PARENT =====
    p.symbol       = "DASH";
    p.block_period = 150;  // target_spacing (2.5 min), matches header_chain DGW target_spacing

    // Address encoding (oracle PARENT). DASH has a SINGLE P2SH version; there is
    // no secondary P2SH prefix and no bech32 HRP on the older baseline.
    if (testnet) {
        p.address_version      = 140;  // testnet PUBKEY_ADDRESS (y...)
        p.address_p2sh_version = 19;   // testnet SCRIPT_ADDRESS
    } else {
        p.address_version      = 76;   // mainnet PUBKEY_ADDRESS (X...)
        p.address_p2sh_version = 16;   // mainnet SCRIPT_ADDRESS (7...)
    }
    p.address_p2sh_version2 = 0;  // DASH: no secondary P2SH prefix
    p.bech32_hrp            = "";  // DASH: no segwit / no bech32

    // PoW: X11 work AND X11 block identity (unlike LTC, DASH identifies blocks by
    // X11, not SHA256d — see header_chain.hpp block_hash_func = pow_func = x11).
    p.pow_func        = [](std::span<const unsigned char> d) -> uint256 { return dash::crypto::hash_x11(d); };
    p.block_hash_func = [](std::span<const unsigned char> d) -> uint256 { return dash::crypto::hash_x11(d); };

    // Subsidy: DASH initial 5 DASH, -1/14 (~7.14%) every 210240 blocks (oracle
    // PARENT.SUBSIDY_FUNC; halving_interval/initial_subsidy match header_chain).
    // [confirm-vs-oracle] gradual-decrease rounding to be re-pinned against a
    // captured node corpus in the real-node KAT follow-on.
    p.subsidy_func = [](uint32_t height) -> uint64_t {
        uint64_t subsidy = 500000000ULL;  // 5 DASH
        for (uint32_t period = (height + 1) / 210240; period > 0; --period)
            subsidy -= subsidy / 14;
        return subsidy;
    };

    p.dust_threshold = 5460;  // [confirm-vs-oracle] legacy DASH dust floor (relay policy, not consensus)

    // Softforks: DASH older baseline has NO segwit (segwit_activation_version=0).
    p.softforks_required        = {};
    p.segwit_activation_version = 0;

    // ===== Pool-level (net) — from dash::PoolConfig (config_pool.hpp SSOT) =====
    PoolConfig::is_testnet = testnet;
    p.p2p_port    = PoolConfig::p2p_port();
    p.worker_port = PoolConfig::worker_port();

    p.share_period      = PoolConfig::share_period();
    p.chain_length      = PoolConfig::chain_length();
    p.real_chain_length = PoolConfig::real_chain_length();

    p.target_lookbehind        = PoolConfig::TARGET_LOOKBEHIND;
    p.spread                   = PoolConfig::SPREAD;
    p.minimum_protocol_version = PoolConfig::MINIMUM_PROTOCOL_VERSION;
    p.block_max_size           = 0;  // DASH: no segwit weight accounting
    p.block_max_weight         = 0;

    p.max_target = PoolConfig::max_target();

    // Network identification — DASH oracle (isolation primitives, never unified).
    p.identifier_hex         = PoolConfig::IDENTIFIER_HEX;
    p.prefix_hex             = PoolConfig::PREFIX_HEX;
    p.testnet_identifier_hex = PoolConfig::TESTNET_IDENTIFIER_HEX;
    p.testnet_prefix_hex     = PoolConfig::TESTNET_PREFIX_HEX;

    // Donation script (consensus-critical) — DASH is ALWAYS P2PKH (no segwit, no
    // v36 combined-P2SH on the older baseline). Single SSOT = dash::DONATION_SCRIPT.
    p.donation_script_func = [](int64_t /*share_version*/) -> std::vector<unsigned char> {
        return DONATION_SCRIPT;
    };

    p.current_share_version = 16;  // DASH older-than-v35 baseline (m_desired_version{16})
    p.is_testnet            = testnet;

    // ----- pool.yaml runtime overrides (tunable, non-consensus only) -----
    if (overrides.p2p_port)        p.p2p_port        = *overrides.p2p_port;
    if (overrides.worker_port)     p.worker_port     = *overrides.worker_port;
    if (overrides.bootstrap_addrs) p.bootstrap_addrs = *overrides.bootstrap_addrs;

    return p;
}

// Convenience overload: no operator overrides -> pure SSOT/oracle CoinParams.
inline core::CoinParams make_coin_params(bool testnet)
{
    return make_coin_params(testnet, PoolOverrides{});
}

} // namespace dash
