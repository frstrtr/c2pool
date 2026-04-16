#pragma once

// Dash CoinParams factory: creates a fully populated CoinParams for Dash.
// All values must match frstrtr/p2pool-dash exactly.
// Reference: ref/p2pool-dash/p2pool/networks/dash.py
//            ref/p2pool-dash/p2pool/dash/networks/dash.py

#include <core/coin_params.hpp>
#include <core/pow.hpp>
#include <impl/dash/crypto/hash_x11.hpp>

namespace dash
{

inline core::CoinParams make_coin_params(bool testnet)
{
    core::CoinParams p;

    // ===== Coin-level (net.PARENT) =====
    p.symbol = "DASH";
    p.block_period = 150;  // 2.5 min

    // Address encoding
    if (testnet) {
        p.address_version      = 140;  // 'y' prefix
        p.address_p2sh_version = 19;
        p.address_p2sh_version2 = 0;
        p.bech32_hrp           = "";   // Dash has no bech32
    } else {
        p.address_version      = 76;   // 'X' prefix
        p.address_p2sh_version = 16;   // '7' prefix
        p.address_p2sh_version2 = 0;
        p.bech32_hrp           = "";   // Dash has no bech32
    }

    // PoW: X11 (both for PoW check and block identity hash)
    p.pow_func = [](std::span<const unsigned char> header) -> uint256 {
        return dash::crypto::hash_x11(header);
    };
    p.block_hash_func = core::pow::sha256d;  // Block identity is SHA256d

    // Subsidy: 50 DASH halving every 210240 blocks
    // Reference: ref/dashcore/src/chainparams.cpp nSubsidyHalvingInterval=210240
    p.subsidy_func = [](uint32_t height) -> uint64_t {
        // Simplified: 50 DASH → 25 → 12.5 → ...
        // Actual Dash subsidy is more complex (7.14% annual reduction)
        // but for share validation only the getblocktemplate value matters
        return uint64_t(50) * 100000000ULL >> (height / 210240);
    };

    p.dust_threshold = 100000;  // 0.001 DASH

    // Softforks: Dash has no BIP softforks (no segwit, no taproot)
    p.softforks_required = {};
    p.segwit_activation_version = 0;  // no segwit

    // ===== Pool-level (net) =====
    // Reference: ref/p2pool-dash/p2pool/networks/dash.py
    p.p2p_port    = 8999;
    p.worker_port = 7903;

    if (testnet) {
        p.share_period      = 20;
        p.chain_length      = 4320;
        p.real_chain_length  = 4320;
    } else {
        p.share_period      = 20;
        p.chain_length      = 4320;
        p.real_chain_length  = 4320;
    }

    p.target_lookbehind        = 100;
    p.spread                   = 10;
    p.minimum_protocol_version = 1700;
    p.block_max_size           = 2000000;
    p.block_max_weight         = 2000000;  // Dash has no segwit weight

    // Max target: standard bdiff difficulty 1 = 0xFFFF * 2^208
    p.max_target.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    // Network identification
    // Reference: ref/p2pool-dash/p2pool/networks/dash.py
    p.identifier_hex          = "7242ef345e1bed6b";
    p.prefix_hex              = "3b3e1286f446b891";
    p.testnet_identifier_hex  = "6a46ef345e1bed6b";  // testnet identifier
    p.testnet_prefix_hex      = "2b2e1286f446b891";  // testnet prefix

    // Bootstrap
    p.bootstrap_addrs = {
        "rov.p2p-spb.xyz",
    };

    // Donation scripts — Dash p2pool uses original forrestv P2PK donation
    // Reference: ref/p2pool-dash/p2pool/data.py DONATION_SCRIPT
    static constexpr uint8_t DONATION_SCRIPT[] = {
        0x41, // OP_PUSHBYTES_65
        0x04, 0x3f, 0x7c, 0xc0, 0xf9, 0x64, 0x38, 0xbc,
        0x73, 0x37, 0xba, 0x41, 0x5f, 0x70, 0x23, 0x81,
        0x63, 0xf4, 0xe3, 0x65, 0xfc, 0x18, 0x3a, 0x48,
        0x4e, 0x21, 0xa0, 0xa0, 0xbf, 0xf2, 0x9c, 0xa3,
        0xbc, 0xfa, 0x49, 0xee, 0xec, 0x87, 0xee, 0x8c,
        0x44, 0x73, 0x18, 0x97, 0x6a, 0xba, 0x55, 0x83,
        0x4e, 0xb0, 0xbb, 0x0e, 0x22, 0x13, 0x4e, 0x5b,
        0x71, 0x62, 0x7c, 0x07, 0x7f, 0x4b, 0x58, 0x9a,
        0xdf,
        0xac  // OP_CHECKSIG
    };

    p.donation_script_func = [](int64_t /*share_version*/) -> std::vector<unsigned char> {
        return {std::begin(DONATION_SCRIPT), std::end(DONATION_SCRIPT)};
    };

    p.current_share_version = 16;
    p.is_testnet = testnet;

    return p;
}

} // namespace dash
