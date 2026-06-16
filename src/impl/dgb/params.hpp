#pragma once

// DGB CoinParams factory: creates a fully populated CoinParams for DigiByte (Scrypt-only).
// All values must match frstrtr/p2pool-merged-v36 exactly (verified @ 42ccca53):
//   parent net params : p2pool/bitcoin/networks/digibyte.py
//   pool   net params : p2pool/networks/digibyte.py
// Donation is AXIS-SPLIT by share_version (per-coin isolation, NOT LTC-mirrored):
//   share_version <  36 : DGB-Scrypt LIVE mainnet 2-of-3 P2MS, byte-for-byte from
//                         farsider350/p2pool-dgb-scrypt-350 data.py DONATION_SCRIPT.
//                         Required so v35 shares peer with the running DGB scrypt pool.
//   share_version >= 36 : COMBINED cross-coin V36 P2SH (merged-v36 data.py:131).

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

    // Donation scripts (consensus-critical; AXIS-SPLIT by share_version).
    //
    // V35_DONATION_SCRIPT — DGB-Scrypt LIVE mainnet donation, a 2-of-3 P2MS taken
    // byte-for-byte from farsider350/p2pool-dgb-scrypt-350 data.py:
    //   522102d9...0688 2103b2...df1b 2102911f...d034 53ae
    //   (OP_2, three 33-byte pubkeys, OP_3, OP_CHECKMULTISIG). This is NOT forrestv
    //   P2PK and NOT LTC-mirrored — per-coin isolation: each coin's v35 donation is
    //   its own live mainnet bytes. Mirroring LTC's P2PK here makes every v35 share
    //   we emit REJECTED by the running DGB scrypt pool (connect-or-die failure).
    static constexpr uint8_t V35_DONATION_SCRIPT[] = {
        0x52,
        0x21,
        0x02, 0xd9, 0x22, 0x34, 0x77, 0x7b, 0x63, 0xf6,
        0xdb, 0xc0, 0xa0, 0x38, 0x2b, 0xbc, 0xb5, 0x4e,
        0x0b, 0xef, 0xb0, 0x1f, 0x6a, 0x4b, 0x06, 0x21,
        0x22, 0xfa, 0xda, 0xb0, 0x44, 0xaf, 0x6c, 0x06,
        0x88,
        0x21,
        0x03, 0xb2, 0x7b, 0xbc, 0x50, 0x19, 0xd3, 0x54,
        0x35, 0x86, 0x48, 0x2a, 0x99, 0x5e, 0x8f, 0x57,
        0xc6, 0xad, 0x50, 0x6a, 0x4d, 0xaf, 0xa6, 0xbf,
        0x7c, 0xc8, 0x95, 0x33, 0xb8, 0xdc, 0xb2, 0xdf,
        0x1b,
        0x21,
        0x02, 0x91, 0x1f, 0xf8, 0x7e, 0x79, 0x2e, 0xc7,
        0x5b, 0x3a, 0x30, 0xdc, 0x11, 0x5d, 0xfd, 0x06,
        0xec, 0x27, 0xc9, 0x3b, 0x27, 0x03, 0x4a, 0xa8,
        0xe7, 0xce, 0xfb, 0xee, 0x64, 0x77, 0xe5, 0xd0,
        0x34,
        0x53,
        0xae
    };
    // COMBINED — cross-coin V36 P2SH 1-of-2 (merged-v36 data.py:131); shared across coins.
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
        return {std::begin(V35_DONATION_SCRIPT), std::end(V35_DONATION_SCRIPT)};
    };

    p.current_share_version = 36;
    p.is_testnet = testnet;

    return p;
}

} // namespace dgb
