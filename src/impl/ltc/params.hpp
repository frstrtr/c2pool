// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// LTC CoinParams factory: creates a fully populated CoinParams for Litecoin.
// All values must match frstrtr/p2pool-merged-v36 exactly.

#include <core/coin_params.hpp>
#include <core/pow.hpp>
#include <core/address_utils.hpp>   // core::CoinAddressAcceptance (issue #961)

namespace ltc
{

// ─── Address-encoding SSOT (issue #961 blocker #3) ───────────────────────────
// The ONE place LTC's payout version bytes / bech32 HRP live (p2pool-merged-v36):
// mainnet PUBKEY 48 (L...) / SCRIPT {50 (M...), 5 (legacy 3...)} / bech32 "ltc";
// testnet PUBKEY 111 / SCRIPT {196, 58 (Q...)} / bech32 "tltc". BOTH make_coin_
// params() and address_acceptance() below read these constants, so the stratum
// money-path acceptance set can NEVER drift from the coin params (the drift risk
// of re-typing the same literals at the call site). HRPs here are BARE; make_coin_
// params() appends the bech32 separator '1' for its own CoinParams.bech32_hrp
// convention. bech32_hrp2 is the secondary P2SH (LTC has two P2SH prefixes).
struct AddressEncoding {
    uint8_t     p2pkh;
    uint8_t     p2sh;
    uint8_t     p2sh2;      // secondary P2SH version (LTC only), 0 = none
    const char* hrp_bare;   // BARE bech32 HRP (no trailing '1')
};
inline constexpr AddressEncoding MAINNET_ADDR{ 48, 50, 5,  "ltc"  };
inline constexpr AddressEncoding TESTNET_ADDR{ 111, 196, 58, "tltc" };
inline constexpr const AddressEncoding& address_encoding(bool testnet)
{ return testnet ? TESTNET_ADDR : MAINNET_ADDR; }

// Registry-sourced payout-address acceptance for LTC on the ACTIVE network
// (issue #961). DERIVED from the AddressEncoding SSOT above — no re-typed
// literals. The legacy 0x05 P2SH is an inherent LTC/BTC collision (both encode
// "3..." at version byte 5): an address at 0x05 maps to the SAME hash160 the
// same key controls, so building an LTC P2SH script for it is a valid own-coin
// payout, not a misdirection. The core stratum server passes this set (via
// StratumConfig.payout_*) so the per-job coinbase payout is validated at the
// parse and never fed a foreign version byte. bech32 HRPs are returned BARE.
inline core::CoinAddressAcceptance address_acceptance(bool testnet)
{
    const auto& e = address_encoding(testnet);
    core::CoinAddressAcceptance a;
    a.p2pkh_versions = { e.p2pkh };
    a.p2sh_versions  = { e.p2sh };
    if (e.p2sh2 != 0) a.p2sh_versions.push_back(e.p2sh2);
    a.bech32_hrps    = { e.hrp_bare };
    return a;
}

inline core::CoinParams make_coin_params(bool testnet)
{
    core::CoinParams p;

    // ===== Coin-level (net.PARENT) =====
    p.symbol = "LTC";
    p.block_period = 150;  // 2.5 min

    // Address encoding — from the AddressEncoding SSOT (issue #961 blocker #3).
    {
        const auto& e = address_encoding(testnet);
        p.address_version       = e.p2pkh;
        p.address_p2sh_version  = e.p2sh;
        p.address_p2sh_version2 = e.p2sh2;
        p.bech32_hrp            = std::string(e.hrp_bare) + "1";  // "ltc1"/"tltc1"
    }

    // PoW
    p.pow_func        = core::pow::scrypt;
    p.block_hash_func = core::pow::sha256d;  // LTC identifies blocks by SHA256d

    // Subsidy: 50 LTC halving every 840,000 blocks
    p.subsidy_func = [](uint32_t height) -> uint64_t {
        return uint64_t(50) * 100000000ULL >> (height / 840000);
    };

    p.dust_threshold = 100000;  // 0.001 LTC

    // Softforks
    p.softforks_required = {"bip65", "csv", "segwit", "taproot", "mweb"};
    p.segwit_activation_version = 17;

    // ===== Pool-level (net) =====
    p.p2p_port    = 9326;
    p.worker_port = 9327;

    if (testnet) {
        p.share_period      = 4;
        p.chain_length      = 400;
        p.real_chain_length  = 400;
    } else {
        p.share_period      = 15;
        p.chain_length      = 8640;
        p.real_chain_length  = 8640;
    }

    p.target_lookbehind        = 200;
    p.spread                   = 3;
    p.minimum_protocol_version = 3301;  // accept v35 (3502) peers for v35->v36 AutoRatchet crossing
    p.advertised_protocol_version = 3600;  // advertise V36 capability; >= .82 latched min (3503) so crossing peers accept us
    p.block_max_size           = 1000000;
    p.block_max_weight         = 4000000;

    // Max target
    if (testnet) {
        // 2^256 / 20 - 1
        p.max_target.SetHex("0ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb");
    } else {
        p.max_target.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    }

    // Network identification
    p.identifier_hex          = "e037d5b8c6923410";
    p.prefix_hex              = "7208c1a53ef629b0";
    p.testnet_identifier_hex  = "cca5e24ec6408b1e";
    p.testnet_prefix_hex      = "ad9614f6466a39cf";

    // Bootstrap
    p.bootstrap_addrs = {
        "ml.toom.im",
        "usa.p2p-spb.xyz",
        "102.160.209.121",
        "5.188.104.245",
        "20.127.82.115",
        "31.25.241.224",
        "20.113.157.65",
        "20.106.76.227",
        "15.218.180.55",
        "173.79.139.224",
        "174.60.78.162",
    };

    // Donation scripts (consensus-critical, must match p2pool data.py)
    // Pre-V36: P2PK (OP_PUSHBYTES_65 <pubkey> OP_CHECKSIG)
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
    // V36+: P2SH 1-of-2 multisig (OP_HASH160 <hash160> OP_EQUAL)
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

} // namespace ltc