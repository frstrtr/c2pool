// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// bip110::pool::PoolConfig — the BIP-110 c2pool SHARECHAIN (pool-P2P) identity
// + tuning, for the M3 v36 sharechain lane. Every value is read from the ONE
// SSOT in src/impl/bip110/params.hpp (the SHARECHAIN_* constants), so the
// sharechain identity can never drift between the coin-params factory and this
// pool config.
//
// ⚠️ CROSS-POLLUTION GUARD (decision card #2, IRREVERSIBLE). This file DELIBERATELY
// does NOT copy the BTC lane's config_pool.hpp, which hard-codes the LIVE BTC
// p2pool sharechain identity (P2P_PORT 9333, PREFIX 2472ef181efcd37b, the
// p2p-spb / jtoomim DEFAULT_BOOTSTRAP_HOSTS) AND — the actual trap — falls back
// to that public seed list even under a custom prefix (btc config_pool.hpp
// SharechainBootstrapMode::PublicDefault). Replicating that here would dial the
// LIVE BTC sharechain and cross-pollute it (the prefix-regression class). The
// BIP-110 bootstrap ladder below has NO PublicDefault arm: with zero explicit
// peers and zero seeds it stays ISOLATED (solo / wire-genesis), never falling
// back to any other lane's list.
//
// This is the pool-lane identity/constants provider consumed by share_types.hpp
// (SEGWIT_ACTIVATION_VERSION) and, in PR-B, by the SharechainNode wiring. The
// runtime Fileconfig (pool.yaml load/get_default) + core::Config<Pool,Coin>
// composition land in PR-B with main_bip110; PR-A only needs the constants that
// the share format + identity are defined against.

#include "../params.hpp"        // SSOT: bip110::SHARECHAIN_* + coin identity
#include <core/donation.hpp>    // chain-agnostic donation SSOT
#include <core/uint256.hpp>     // uint256 / uint256S for max_target()

#include <cstdint>
#include <string>
#include <vector>

namespace bip110::pool
{

class PoolConfig
{
public:
    // ---- Sharechain (pool-P2P) transport identity — from params.hpp SSOT ----
    static constexpr uint16_t P2P_PORT    = SHARECHAIN_P2P_PORT;     // 9337 (decision #2)
    static constexpr uint16_t WORKER_PORT = SHARECHAIN_WORKER_PORT;  // 9336

    // ---- Share-diff / PPLNS window — BTC-verbatim (decision #3) -------------
    static constexpr uint32_t SPREAD                    = SHARECHAIN_SPREAD;                    // 3
    static constexpr uint32_t TARGET_LOOKBEHIND         = SHARECHAIN_TARGET_LOOKBEHIND;         // 200
    static constexpr uint32_t SHARE_PERIOD              = SHARECHAIN_SHARE_PERIOD;              // 30s
    static constexpr uint32_t CHAIN_LENGTH              = SHARECHAIN_CHAIN_LENGTH;              // 8640
    static constexpr uint32_t REAL_CHAIN_LENGTH         = SHARECHAIN_CHAIN_LENGTH;              // 8640

    // ---- Protocol / format floors ------------------------------------------
    // v36 MergedMiningShare requires protocol >= 3600 (python fork data.py:2267);
    // ADVERTISED == MINIMUM so we never speak below the v36 floor.
    static constexpr uint32_t MINIMUM_PROTOCOL_VERSION    = SHARECHAIN_MINIMUM_PROTOCOL_VERSION;    // 3600
    static constexpr uint32_t ADVERTISED_PROTOCOL_VERSION = SHARECHAIN_ADVERTISED_PROTOCOL_VERSION; // 3600
    // v36 >= 4 => segwit ALWAYS active on this v36-genesis chain.
    static constexpr uint32_t SEGWIT_ACTIVATION_VERSION   = SHARECHAIN_SEGWIT_ACTIVATION_VERSION;   // 4
    static constexpr uint32_t BLOCK_MAX_SIZE              = SHARECHAIN_BLOCK_MAX_SIZE;
    static constexpr uint32_t BLOCK_MAX_WEIGHT           = RDTS_MAX_BLOCK_WEIGHT;

    // ---- Reward-safety: mint-freshness (verified-vs-raw gap) ----------------
    // BTC C1 precedent (main_btc.cpp): refuse to mint on top of a share whose
    // verified height trails the raw tip by more than this. Reward-safety, not
    // consensus. Consumed caller-side in PR-B's main_bip110 mint gate.
    static constexpr uint32_t STALE_SHARES = 30;

    // ---- Donation ----------------------------------------------------------
    // Delegated to the chain-agnostic SSOT: v36+ => COMBINED_DONATION_SCRIPT
    // (P2SH a9148c6272...8e8587). The per-share donation u16 default (66 == 0.1%)
    // lives in the money/give_author catalog, applied at mint (PR-B).
    static std::vector<unsigned char> get_donation_script(int64_t share_version)
    {
        return core::donation::get_donation_script(share_version);
    }

    // ---- Verify-path accessors (share_check.hpp / share_tracker.hpp) --------
    // The v36-genesis chain has no separate testnet parameter set: the SSOT in
    // params.hpp defines the single mainnet identity, and is_testnet stays false.
    // These function accessors mirror the BTC lane's PoolConfig call surface so
    // the namespace-copied share_check/share_tracker bind unchanged; every value
    // is read from the params.hpp SHARECHAIN_* SSOT (never drifts).
    static inline bool is_testnet = false;

    static uint32_t share_period()      { return SHARECHAIN_SHARE_PERIOD; }
    static uint32_t chain_length()      { return SHARECHAIN_CHAIN_LENGTH; }
    static uint32_t real_chain_length() { return SHARECHAIN_CHAIN_LENGTH; }

    static uint64_t dust_threshold()    { return SHARECHAIN_DUST_THRESHOLD; }

    // MAX_TARGET: share difficulty floor (easiest allowed share PoW), from the
    // params.hpp SSOT (SHARECHAIN_MAX_TARGET_HEX — standard bdiff-1 2^224 floor).
    static uint256 max_target()
    {
        static const uint256 MAINNET_MAX = uint256S(SHARECHAIN_MAX_TARGET_HEX);
        return MAINNET_MAX;
    }

    // Chain identity — BIP-110-native, from the params.hpp SSOT. No override /
    // XOR-derivation surface (decision #2: this lane never joins another network).
    static const std::string& identifier_hex()
    {
        static const std::string kId = SHARECHAIN_IDENTIFIER_HEX;
        return kId;
    }

    static const std::string& prefix_hex()
    {
        static const std::string kPfx = SHARECHAIN_PREFIX_HEX;
        return kPfx;
    }

    // ---- Bootstrap ladder — FAIL-LOUD, no cross-lane fallback ---------------
    // Precedence: explicit peers > regtest > (custom-id | public) => ISOLATED.
    // There is NO PublicDefault arm on purpose (see the header note): with no
    // explicit peers and no seeds the node runs solo rather than dialing any
    // other sharechain. No public BIP-110 c2pool node exists yet; the operator
    // fills explicit --peer hosts at PR-B / deploy.
    enum class BootstrapMode {
        ExplicitPeers,   // --peer/--sharechain-addnode given: dial ONLY those
        RegtestIsolated, // --regtest: 0 seeds, solo/local
        Isolated,        // default: 0 seeds, wire-genesis / solo (NEVER a fallback list)
    };

    static BootstrapMode select_bootstrap_mode(bool has_explicit_peers, bool regtest)
    {
        if (has_explicit_peers) return BootstrapMode::ExplicitPeers;
        if (regtest)            return BootstrapMode::RegtestIsolated;
        return BootstrapMode::Isolated;
    }

    // EMPTY default seed list. Never falls back to another lane's hosts.
    static const std::vector<std::string>& default_bootstrap_hosts()
    {
        static const std::vector<std::string> kNone{};
        return kNone;
    }
};

} // namespace bip110::pool
