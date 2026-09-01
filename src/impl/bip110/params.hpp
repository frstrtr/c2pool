// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BIP-110 CoinParams factory: builds a core::CoinParams for the Bitcoin Knots
// BLAKE2b hard-fork chain (BIP-110), a minority hard fork of Bitcoin that
// replaces SHA256d proof-of-work with the BLAKE2b commitment pipeline and caps
// the block weight (RDTS). Live as a mainnet trial since block 961640
// (2026-08-30) under Bitcoin Knots 29.4.1rc4, finalizing under Knots 29.4.1.
//
// SOURCE OF TRUTH: shipped tag v29.4.1.knots20260508rc5
//   - src/primitives/block.cpp  CBlockHeader::GetHash()  (bip110::pow pipeline)
//   - src/kernel/chainparams.cpp CMainParams              (coin identity below)
//
// COIN IDENTITY: BIP-110 shares Bitcoin mainnet's network identity almost
// entirely — network magic f9beb4d9, genesis
// 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f, base58
// P2PKH=0 / P2SH=5 / WIF=128, bech32 HRP "bc", 210000-block halving, and the
// unchanged 2016-block / 14-day retarget. It diverges only at the fork:
//   - consensus.Blake2bHeight = 961640 (first BLAKE2b block)
//   - a one-off difficulty reset at 961640 (Blake2bTargetShift = 22)
//   - RDTS: consensus weight cap = 800000 WU until the parent MTP crosses
//     RdtsExpiryTime 1819756800 (2027-09-01), vs Bitcoin's 4,000,000 WU
//   - block version carries bit31 (VERSION_HEADER_V2_FLAG)
// The magic / genesis / RPC identity is consumed by the coin-network + GBT
// backend layer (Bitcoin Knots 29.4.1 getblocktemplate), which is the live-
// deployment milestone; this factory carries the values the pool-side stack
// needs today plus the BLAKE2b hash binding that makes the lane BIP-110.
//
// PER-COIN ISOLATION: pow_func AND block_hash_func both bind to the lane-local
// bip110::pow::blake2b_block_hash (the pow == block-hash shape, exactly as DASH
// binds X11 to both). No other lane's SHA256d / scrypt / X11 path is touched.

#include "pow.hpp"

#include <core/coin_params.hpp>

namespace bip110
{

// --- Coin-network identity (documented for the GBT/coin-P2P backend) ---------
// These are NOT core::CoinParams fields; they live here as the single place the
// BIP-110 coin-network constants are recorded until the Knots-GBT backend lands.
inline constexpr uint32_t NETWORK_MAGIC       = 0xf9beb4d9;  // == Bitcoin mainnet
inline constexpr uint16_t COIN_P2P_PORT       = 8333;        // == Bitcoin mainnet
inline constexpr uint16_t COIN_RPC_PORT       = 8332;        // == Bitcoin mainnet
inline constexpr uint32_t BLAKE2B_HEIGHT      = 961640;      // first BLAKE2b block
inline constexpr uint32_t BLAKE2B_TARGET_SHIFT = 22;         // one-off reset at 961640
inline constexpr uint32_t RDTS_MAX_BLOCK_WEIGHT = 800000;    // reduced-data weight cap
inline constexpr uint32_t RDTS_EXPIRY_TIME    = 1819756800;  // 2027-09-01 MTP gate
// Conservative block-sigop-cost cap (GAP3). Bitcoin's MAX_BLOCK_SIGOPS_COST is
// 80000 against a 4,000,000-WU block; RDTS caps weight at 800000 WU, so the
// weight-scaled bound is 80000 × 800000/4000000 = 16000. VERIFY against the
// Knots BIP-110 source: if Knots kept 80000 unscaled our cap is merely STRICTER
// (an inclusion-% cost, never a validity risk) — the fail-closed direction.
inline constexpr uint32_t RDTS_MAX_BLOCK_SIGOPS_COST = 16000;
inline constexpr const char* GENESIS_HASH =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
// getblocktemplate rule the pool MUST request against a Knots 29.4.1 backend
// (the RPC rejects the request otherwise); the response reports "!blake2b".
inline constexpr const char* GBT_RULE = "blake2b";

// Standard Bitcoin subsidy: 50 BTC, halving every 210000 blocks. Unchanged by
// BIP-110 (coinbasevalue at the 961640 era = 3.125 BTC + fees).
inline uint64_t subsidy(uint32_t height)
{
    const int halvings = static_cast<int>(height / 210000);
    if (halvings >= 64)
        return 0;
    uint64_t s = 5000000000ULL;  // 50 BTC in satoshis
    s >>= halvings;
    return s;
}

inline core::CoinParams make_coin_params(bool testnet)
{
    core::CoinParams p;

    // ===== Coin-level (net.PARENT) =====
    p.symbol       = "BIP110";
    p.block_period = 600;  // 10-minute target interval (unchanged from Bitcoin)

    // Address encoding — Bitcoin mainnet base58/bech32 (unchanged by BIP-110).
    p.address_version       = 0;    // P2PKH version byte (mainnet "1...")
    p.address_p2sh_version  = 5;    // P2SH version byte (mainnet "3...")
    p.address_p2sh_version2 = 0;    // no secondary P2SH prefix
    p.bech32_hrp            = "bc"; // bech32 HRP

    // PoW: BLAKE2b commitment pipeline as BOTH the work and the block identity
    // (the block hash == PoW hash shape, like DASH's X11). Span-typed, so the
    // 164-byte v2 header flows through without touching any SHA256d path.
    p.pow_func        = [](std::span<const unsigned char> d) -> uint256 { return bip110::pow::blake2b_block_hash(d); };
    p.block_hash_func = [](std::span<const unsigned char> d) -> uint256 { return bip110::pow::blake2b_block_hash(d); };

    // Subsidy — standard Bitcoin schedule.
    p.subsidy_func = [](uint32_t height) -> uint64_t { return bip110::subsidy(height); };

    // Dust: Bitcoin relay-policy dust floor (546 sat for a P2PKH output).
    p.dust_threshold = 546;

    // Softforks / segwit — segwit stays active on the BIP-110 chain.
    p.softforks_required = {"segwit", "blake2b"};  // GBT must request "blake2b"
    p.segwit_activation_version = 4;

    // Block-size rule: RDTS reduced-data weight cap while active (until the
    // 2027-09-01 MTP gate); the classic 1 MB base-size is unchanged.
    p.block_max_size   = 1000000;
    p.block_max_weight = RDTS_MAX_BLOCK_WEIGHT;  // 800000 WU (vs Bitcoin 4,000,000)

    // ===== Pool-level (net) — c2pool sharechain identity =====
    // BIP-110 is a NEW sharechain, distinct from the BTC lane. p2p/worker ports
    // and identifier/prefix are BIP-110-native so the sharechain can never merge
    // with the BTC p2pool sharechain (which uses 9333 / fc70035c7a81bc6f).
    p.p2p_port    = 9335;  // BIP-110 p2pool sharechain P2P port
    p.worker_port = 9336;  // BIP-110 Stratum port

    p.share_period      = 30;
    p.chain_length      = 5760;
    p.real_chain_length = 5760;
    p.target_lookbehind = 200;
    p.spread            = 30;
    p.minimum_protocol_version    = 3500;
    p.advertised_protocol_version = 3501;

    // Max target (easiest share difficulty). Bitcoin powLimit
    // 00000000ffff0000... is unchanged by BIP-110 (CheckProofOfWorkImpl is
    // untouched); the share floor sits at that limit.
    p.max_target = uint256S("00000000ffff0000000000000000000000000000000000000000000000000000");

    // Sharechain network identification — BIP-110-native 8-byte values, chosen
    // distinct from every other lane so no cross-lane sharechain handshake can
    // succeed. (Independent transport constants; prefix is not derived from id.)
    p.identifier_hex         = "b1101100b1a4e2bd";
    p.prefix_hex             = "e2bdb1101100b1a4";
    p.testnet_identifier_hex = "b1101100b1a4e2bd";
    p.testnet_prefix_hex     = "e2bdb1101100b1a4";

    // Bootstrap peers — populated as BIP-110 c2pool nodes come online.
    p.bootstrap_addrs = {};

    // Donation script — reuse the version-gated selection convention. Empty here
    // (populated when the pool-runtime lands); the KAT lane does not mint.
    p.donation_script_func = [](int64_t /*share_version*/) -> std::vector<unsigned char> {
        return {};
    };

    p.current_share_version = 36;
    p.is_testnet            = testnet;

    return p;
}

} // namespace bip110
