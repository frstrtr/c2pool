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
    p.block_hash_func = p.pow_func;  // Dash: block identity is also X11

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

    // Max target — DIFFERENT for mainnet vs testnet. Discovered via
    // testnet battle-test 2026-04-24 (Bug 7 root cause).
    //
    // Mainnet (p2pool-dash/networks/dash.py:17):
    //   MAX_TARGET = 0xFFFF * 2**208  ≈ 0x00000000ffff0000... (bdiff 1)
    //   Standard Bitcoin/Dash difficulty-1 target.
    //
    // Testnet (p2pool-dash/networks/dash_testnet.py):
    //   MAX_TARGET = 2**256//2**20 - 1 ≈ 0x00000fffffffffff... (~4096× easier)
    //   p2pool-dash testnet allows much-easier shares so CPU miners can
    //   land them quickly during testing. If c2pool uses mainnet's value
    //   on testnet, we clamp the share's bits to mainnet diff-1, then
    //   p2pool computes share.target = mainnet target, then verifies
    //   pow_hash <= target — and cpuminer hashes (which only met testnet's
    //   easier target) reliably fail this check ⇒ 'share PoW invalid'
    //   on every share to a p2pool-dash peer.
    if (testnet) {
        p.max_target.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    } else {
        p.max_target.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
    }

    // Vardiff (matches p2pool-dash/dash/stratum.py:1071-1138 +
    // p2pool-dash/networks/dash.py:25-39):
    //   STRATUM_SHARE_RATE=10, VARDIFF_SHARES_TRIGGER=8,
    //   VARDIFF_TIMEOUT_MULT=5, VARDIFF_QUICKUP_SHARES=2,
    //   VARDIFF_QUICKUP_DIVISOR=3, VARDIFF_MIN_ADJUST=0.5,
    //   VARDIFF_MAX_ADJUST=2.0
    // Uses the full N window (no del[0]) — ASIC-tuned three-trigger algo.
    p.vardiff.target_share_rate = 10.0;
    p.vardiff.shares_trigger    = 8;
    p.vardiff.timeout_mult      = 5.0;
    p.vardiff.quickup_shares    = 2;
    p.vardiff.quickup_divisor   = 3.0;
    p.vardiff.min_adjust        = 0.5;
    p.vardiff.max_adjust        = 2.0;
    p.vardiff.use_full_window   = true;

    // Network identification
    // Reference: ref/p2pool-dash/p2pool/networks/dash.py
    p.identifier_hex          = "7242ef345e1bed6b";
    p.prefix_hex              = "3b3e1286f446b891";
    p.testnet_identifier_hex  = "b6deb1e543fe2427";  // testnet identifier
    p.testnet_prefix_hex      = "198b644f6821e3b3";  // testnet prefix

    // Bootstrap hosts. rov.p2p-spb.xyz is the upstream p2pool-dash default;
    // the others are known live Dash p2pool nodes also listed in the LTC
    // bootstrap set (same operators run multi-chain pools). Multiple hosts
    // are critical because the Dash p2pool network is sparse and a single
    // bootstrap with a stale addr cache leaves us unable to expand peers.
    p.bootstrap_addrs = {
        "rov.p2p-spb.xyz",
        "usa.p2p-spb.xyz",
        "5.188.104.245",
        "31.25.241.224",
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
