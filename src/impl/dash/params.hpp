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

    // Donation script: P2PKH for XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u
    // Reference: ref/p2pool-dash/p2pool/data.py line 66
    // DONATION_SCRIPT = '76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac'
    // OP_DUP OP_HASH160 <20 bytes pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    static constexpr uint8_t DONATION_SCRIPT[] = {
        0x76,       // OP_DUP
        0xa9,       // OP_HASH160
        0x14,       // Push 20 bytes
        0x20, 0xcb, 0x5c, 0x22, 0xb1, 0xe4, 0xd5, 0x94,
        0x7e, 0x5c, 0x11, 0x2c, 0x76, 0x96, 0xb5, 0x1a,
        0xd9, 0xaf, 0x3c, 0x61,
        0x88,       // OP_EQUALVERIFY
        0xac        // OP_CHECKSIG
    };

    p.donation_script_func = [](int64_t /*share_version*/) -> std::vector<unsigned char> {
        return {std::begin(DONATION_SCRIPT), std::end(DONATION_SCRIPT)};
    };

    p.current_share_version = 16;
    p.is_testnet = testnet;

    return p;
}

} // namespace dash
