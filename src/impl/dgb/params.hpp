#pragma once

// DGB CoinParams factory: creates a fully populated CoinParams for DigiByte (Scrypt-only).
// All values must match frstrtr/p2pool-merged-v36 exactly (verified @ 42ccca53):
//   parent net params : p2pool/bitcoin/networks/digibyte.py
//   pool   net params : p2pool/networks/digibyte.py
//   donation (GLOBAL) : p2pool/data.py:118 (P2PK) / :131 (COMBINED)

#include <core/coin_params.hpp>
#include <core/pow.hpp>

#include "config_coin.hpp"

namespace dgb
{

inline core::CoinParams make_coin_params(bool testnet)
{
    core::CoinParams p;

    // ===== Coin-level (net.PARENT — digibyte.py) =====
    p.symbol = "DGB";
    p.block_period = 15;  // 75s / 5 algos = 15s per Scrypt slot

    // Address encoding
    if (testnet) {
        p.address_version       = 126;   // 0x7e
        p.address_p2sh_version  = 140;   // 0x8c
        p.address_p2sh_version2 = 0;     // DGB has no secondary P2SH version
        p.bech32_hrp            = "dgbt";
    } else {
        p.address_version       = 30;    // 0x1e — 'D'
        p.address_p2sh_version  = 63;    // 0x3f — 'S'
        p.address_p2sh_version2 = 0;     // DGB has no secondary P2SH version
        p.bech32_hrp            = "dgb";
    }

    // PoW — DGB-Scrypt identifies blocks by the SCRYPT PoW hash itself
    // (digibyte.py: BLOCKHASH_FUNC = POW_FUNC). This DIFFERS from LTC, which
    // identifies blocks by SHA256d. Do not "fix" this to sha256d.
    p.pow_func        = core::pow::scrypt;
    p.block_hash_func = core::pow::scrypt;

    // Subsidy: DGB 3-phase decay (digibyte.py _dgb_subsidy).
    // NOTE: wired to the existing dgb::CoinParams::subsidy helper. That helper
    // currently diverges from _dgb_subsidy (off-by-one decay period + rounding)
    // and is flagged for a separate consensus fix; params.hpp needs no change
    // once the helper is corrected.
    p.subsidy_func = [](uint32_t height) -> uint64_t {
        return dgb::CoinParams::subsidy(height);
    };

    p.dust_threshold = 3000000;  // 0.03e8 (digibyte.py DUST_THRESHOLD)

    // Softforks
    p.softforks_required = {"csv", "segwit"};
    p.segwit_activation_version = 17;

    // ===== Pool-level (net — p2pool/networks/digibyte.py) =====
    p.p2p_port    = 5024;
    p.worker_port = 5025;

    if (testnet) {
        p.share_period      = 4;
        p.chain_length      = 400;
        p.real_chain_length = 400;
    } else {
        p.share_period      = 25;
        p.chain_length      = 8640;   // 24*60*60//10
        p.real_chain_length = 8640;
    }

    p.target_lookbehind        = 200;
    p.spread                   = 30;
    p.minimum_protocol_version = 3301;   // digibyte.py:27
    p.block_max_size           = 1000000;
    p.block_max_weight         = 4000000;

    // Max target (MAX_TARGET = 2**256//2**20 - 1)
    if (testnet) {
        p.max_target.SetHex("0ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb");
    } else {
        p.max_target.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    }

    // Network identification (digibyte.py IDENTIFIER / PREFIX; no separate testnet net)
    p.identifier_hex          = "1bfe01eff5ba4e38";
    p.prefix_hex              = "1bfe01eff652e4b7";
    p.testnet_identifier_hex  = "1bfe01eff5ba4e38";
    p.testnet_prefix_hex      = "1bfe01eff652e4b7";

    // Bootstrap — DGB sharechain has no external peers yet (digibyte.py BOOTSTRAP_ADDRS = []).
    p.bootstrap_addrs = {};

    // Donation scripts (consensus-critical; GLOBAL script per merged-v36 @ 42ccca53).
    // DGB networks/digibyte.py defines NO per-network donation, so DGB inherits
    // the global script identically to LTC/DOGE (required for v36 gentx parity).
    // Pre-V36: P2PK (data.py:118).  V36+: P2SH 1-of-2 forrestv+maintainer (data.py:131).
    static constexpr uint8_t DONATION_SCRIPT[] = {
        0x41,
        0x04, 0xff, 0xd0, 0x3d, 0xe4, 0x4a, 0x6e, 0x11,
        0xb9, 0x91, 0x7f, 0x3a, 0x29, 0xf9, 0x44, 0x32,
        0x83, 0xd9, 0x87, 0x1c, 0x9d, 0x74, 0x3e, 0xf3,
        0x0d, 0x5e, 0xdd, 0xcd, 0x37, 0x09, 0x4b, 0x64,
        0xd1, 0xb3, 0xd8, 0x09, 0x04, 0x96, 0xb5, 0x32,
        0x56, 0x78, 0x6b, 0xf5, 0xc8, 0x29, 0x32, 0xec,
        0x23, 0xc3, 0xb7, 0x4d, 0x9f, 0x05, 0xa6, 0xf9,
        0x5a, 0x8b, 0x55, 0x29, 0x35, 0x26, 0x56, 0x66,
        0x4b,
        0xac
    };
    static constexpr uint8_t COMBINED_DONATION_SCRIPT[] = {
        0xa9, 0x14,
        0x8c, 0x62, 0x72, 0x62, 0x1d, 0x89, 0xe8, 0xfa,
        0x52, 0x6d, 0xd8, 0x6a, 0xcf, 0xf6, 0x0c, 0x71,
        0x36, 0xbe, 0x8e, 0x85,
        0x87
    };

    p.donation_script_func = [](int64_t share_version) -> std::vector<unsigned char> {
        if (share_version >= 36)
            return {std::begin(COMBINED_DONATION_SCRIPT), std::end(COMBINED_DONATION_SCRIPT)};
        return {std::begin(DONATION_SCRIPT), std::end(DONATION_SCRIPT)};
    };

    p.current_share_version = 36;
    p.is_testnet = testnet;

    return p;
}

} // namespace dgb
