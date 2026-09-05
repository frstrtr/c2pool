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
#include <core/address_utils.hpp>   // core::CoinAddressAcceptance (issue #961)

namespace bip110
{

// ─── Address-encoding SSOT (issue #961 blocker #3) ───────────────────────────
// The ONE place BIP-110's payout version bytes / bech32 HRPs live. BIP-110 keeps
// the Bitcoin address formats unchanged (Knots-GBT parent): mainnet PUBKEY 0 /
// SCRIPT 5 / bech32 "bc"; testnet PUBKEY 111 / SCRIPT 196 / bech32 "tb"; regtest
// reuses the testnet base58 bytes with bech32 "bcrt". make_coin_params() reads
// the MAINNET entry (the Knots-GBT parent runs mainnet) and address_acceptance()
// reads all three, so the money-path acceptance set never drifts from the coin
// params. HRPs here are BARE.
struct AddressEncoding { uint8_t p2pkh; uint8_t p2sh; const char* hrp_bare; };
inline constexpr AddressEncoding MAINNET_ADDR{ 0x00, 0x05, "bc"   };
inline constexpr AddressEncoding TESTNET_ADDR{ 0x6f, 0xc4, "tb"   };  // 111 / 196
inline constexpr AddressEncoding REGTEST_ADDR{ 0x6f, 0xc4, "bcrt" };  // testnet bytes, "bcrt"

// Registry-sourced payout-address acceptance for BIP-110 on the ACTIVE network
// (issue #961). DERIVED from the AddressEncoding SSOT above — no re-typed
// literals. Deriving from the true network keeps a --regtest address from being
// rejected as Foreign.
inline core::CoinAddressAcceptance address_acceptance(bool testnet, bool regtest)
{
    const AddressEncoding& e = regtest ? REGTEST_ADDR
                             : testnet ? TESTNET_ADDR
                             : MAINNET_ADDR;
    core::CoinAddressAcceptance a;
    a.p2pkh_versions = { e.p2pkh };
    a.p2sh_versions  = { e.p2sh };
    a.bech32_hrps    = { e.hrp_bare };
    return a;
}

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

// --- Sharechain (pool-P2P) identity — SINGLE SOURCE OF TRUTH ------------------
// These namespace-level constants are the ONE place BIP-110's c2pool sharechain
// identity and pool-lane parameters are defined. BOTH make_coin_params() (below)
// and config_pool.hpp's PoolConfig reference them, so the sharechain identity can
// never drift between the two. Every value is BIP-110-native and distinct from
// every other lane (BTC = 9333 / fc70035c7a81bc6f / 2472ef181efcd37b) so no
// cross-lane sharechain handshake can succeed. IDENTIFIER and PREFIX are TWO
// INDEPENDENT transport constants (p2pool model); PREFIX is never derived from
// IDENTIFIER. This mirrors the DASH lane's single-definition discipline (one
// place owns the identity; the factory and PoolConfig both read it).
// M3 WIRE-GENESIS bump (operator decision card 2026-09-02, IRREVERSIBLE once a
// share is minted): the M2 SPV-follower placeholders (9335 / SPREAD 30 /
// CHAIN_LENGTH 5760 / MIN_PROTO 3500) are replaced by the operator-signed
// wire-genesis constants BEFORE any share exists. Port 9337 (decision #2),
// SHARE-DIFF BTC-verbatim (decision #3: CHAIN_LENGTH 8640, SPREAD 3), v36
// MergedMiningShare requires protocol >= 3600 (python fork data.py:2267). The
// PREFIX / IDENTIFIER stay as already-minted-fresh (no BTC collision). Worker
// port 9336 keeps. Nothing is live on this sharechain yet, so a pre-genesis
// bump is safe; after the first mint these values freeze.
inline constexpr uint16_t SHARECHAIN_P2P_PORT    = 9337;  // BIP-110 sharechain P2P port (decision #2)
inline constexpr uint16_t SHARECHAIN_WORKER_PORT = 9336;  // BIP-110 Stratum/worker port
inline constexpr const char* SHARECHAIN_IDENTIFIER_HEX = "b1101100b1a4e2bd";
inline constexpr const char* SHARECHAIN_PREFIX_HEX     = "e2bdb1101100b1a4";
// Pool-lane tuning constants. SHARE-DIFF = BTC-verbatim (decision #3): CHAIN_LENGTH
// 8640, SPREAD 3, SHARE_PERIOD 30s, TARGET_LOOKBEHIND 200, standard MAX_TARGET
// floor. MIN_PROTO/ADVERTISED = 3600 (v36 MergedMiningShare floor). SEGWIT
// activation 4 (v36 >= 4 => always segwit-active on this v36-genesis chain).
inline constexpr uint32_t SHARECHAIN_SPREAD                    = 3;       // BTC-verbatim (decision #3)
inline constexpr uint32_t SHARECHAIN_CHAIN_LENGTH             = 8640;    // BTC-verbatim (decision #3)
inline constexpr uint32_t SHARECHAIN_TARGET_LOOKBEHIND        = 200;
inline constexpr uint32_t SHARECHAIN_SHARE_PERIOD            = 30;
inline constexpr uint32_t SHARECHAIN_MINIMUM_PROTOCOL_VERSION = 3600;   // v36 floor (data.py:2267)
inline constexpr uint32_t SHARECHAIN_ADVERTISED_PROTOCOL_VERSION = 3600;
inline constexpr uint32_t SHARECHAIN_SEGWIT_ACTIVATION_VERSION = 4;
inline constexpr uint32_t SHARECHAIN_BLOCK_MAX_SIZE          = 1000000;
inline constexpr uint64_t SHARECHAIN_DUST_THRESHOLD          = 546;  // Bitcoin relay dust floor
// Share difficulty floor (easiest allowed share PoW) == Bitcoin powLimit; BIP-110
// leaves CheckProofOfWorkImpl untouched, so the share floor sits at that limit.
inline constexpr const char* SHARECHAIN_MAX_TARGET_HEX =
    "00000000ffff0000000000000000000000000000000000000000000000000000";

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

    // Address encoding — Bitcoin mainnet base58/bech32 (unchanged by BIP-110),
    // from the AddressEncoding SSOT (issue #961 blocker #3). The Knots-GBT parent
    // runs mainnet, so make_coin_params encodes the MAINNET entry; address_
    // acceptance() reads the testnet/regtest entries for --regtest/--testnet.
    p.address_version       = MAINNET_ADDR.p2pkh;   // 0x00 (mainnet "1...")
    p.address_p2sh_version  = MAINNET_ADDR.p2sh;    // 0x05 (mainnet "3...")
    p.address_p2sh_version2 = 0;                    // no secondary P2SH prefix
    p.bech32_hrp            = MAINNET_ADDR.hrp_bare; // "bc"

    // PoW: BLAKE2b commitment pipeline as BOTH the work and the block identity
    // (the block hash == PoW hash shape, like DASH's X11). Span-typed, so the
    // 164-byte v2 header flows through without touching any SHA256d path.
    p.pow_func        = [](std::span<const unsigned char> d) -> uint256 { return bip110::pow::blake2b_block_hash(d); };
    p.block_hash_func = [](std::span<const unsigned char> d) -> uint256 { return bip110::pow::blake2b_block_hash(d); };

    // Subsidy — standard Bitcoin schedule.
    p.subsidy_func = [](uint32_t height) -> uint64_t { return bip110::subsidy(height); };

    // Dust: Bitcoin relay-policy dust floor (546 sat for a P2PKH output).
    p.dust_threshold = SHARECHAIN_DUST_THRESHOLD;

    // Softforks / segwit — segwit stays active on the BIP-110 chain.
    p.softforks_required = {"segwit", "blake2b"};  // GBT must request "blake2b"
    p.segwit_activation_version = SHARECHAIN_SEGWIT_ACTIVATION_VERSION;

    // Block-size rule: RDTS reduced-data weight cap while active (until the
    // 2027-09-01 MTP gate); the classic 1 MB base-size is unchanged.
    p.block_max_size   = SHARECHAIN_BLOCK_MAX_SIZE;
    p.block_max_weight = RDTS_MAX_BLOCK_WEIGHT;  // 800000 WU (vs Bitcoin 4,000,000)

    // ===== Pool-level (net) — c2pool sharechain identity =====
    // BIP-110 is a NEW sharechain, distinct from the BTC lane. p2p/worker ports
    // and identifier/prefix are BIP-110-native so the sharechain can never merge
    // with the BTC p2pool sharechain (which uses 9333 / fc70035c7a81bc6f).
    p.p2p_port    = SHARECHAIN_P2P_PORT;     // BIP-110 p2pool sharechain P2P port
    p.worker_port = SHARECHAIN_WORKER_PORT;  // BIP-110 Stratum port

    p.share_period      = SHARECHAIN_SHARE_PERIOD;
    p.chain_length      = SHARECHAIN_CHAIN_LENGTH;
    p.real_chain_length = SHARECHAIN_CHAIN_LENGTH;
    p.target_lookbehind = SHARECHAIN_TARGET_LOOKBEHIND;
    p.spread            = SHARECHAIN_SPREAD;
    p.minimum_protocol_version    = SHARECHAIN_MINIMUM_PROTOCOL_VERSION;
    p.advertised_protocol_version = SHARECHAIN_ADVERTISED_PROTOCOL_VERSION;

    // Max target (easiest share difficulty). Bitcoin powLimit
    // 00000000ffff0000... is unchanged by BIP-110 (CheckProofOfWorkImpl is
    // untouched); the share floor sits at that limit.
    p.max_target = uint256S(SHARECHAIN_MAX_TARGET_HEX);

    // Sharechain network identification — BIP-110-native 8-byte values, chosen
    // distinct from every other lane so no cross-lane sharechain handshake can
    // succeed. (Independent transport constants; prefix is not derived from id.)
    p.identifier_hex         = SHARECHAIN_IDENTIFIER_HEX;
    p.prefix_hex             = SHARECHAIN_PREFIX_HEX;
    p.testnet_identifier_hex = SHARECHAIN_IDENTIFIER_HEX;
    p.testnet_prefix_hex     = SHARECHAIN_PREFIX_HEX;

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
