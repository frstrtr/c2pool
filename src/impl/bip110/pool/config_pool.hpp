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
// does NOT copy the BTC lane's config_pool.hpp SEED HOSTS: btc hard-codes the LIVE
// BTC p2pool sharechain identity (P2P_PORT 9333, PREFIX 2472ef181efcd37b, the
// p2p-spb / jtoomim DEFAULT_BOOTSTRAP_HOSTS). BIP-110 carries its OWN, disjoint
// beacon list (DEFAULT_BOOTSTRAP_HOSTS below = our-fork hosts on :9337).
//
// THE GUARD IS THE PREFIX, NOT AN EMPTY LIST. Our beacons speak ONLY the fresh
// SHARECHAIN_PREFIX_HEX (e2bdb110…) on the fresh port 9337, so a btc node on 9333
// (prefix 2472ef…) can NEVER handshake them (read_prefix disconnect). We therefore
// SEED our own beacon list by default — a fresh miner needs a seed to dial or the
// sharechain can never form — while structurally staying off btc's (or any other
// lane's) sharechain. The mistake the empty-ladder made was over-correcting the
// btc PublicDefault trap into "no seeds ever": that guarantees an empty peer set,
// so the broadcaster has nobody to fan shares to. The correct decision #2 is our
// OWN beacon list (OurBeacon), never a cross-lane fallback.
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

    // ---- Bootstrap seed list — OUR bip110 sharechain bootstrap nodes ---------
    // p2pool-style BOOTSTRAP_ADDRS (mirror p2pool-merged-v36 networks/*.py): a
    // named, extensible LIST of our-fork beacons a fresh miner dials to ENTER the
    // sharechain mesh; gossip grows the set from here. These hosts speak ONLY the
    // fresh SHARECHAIN_PREFIX_HEX (e2bdb110…) on port 9337, so a btc node on 9333
    // (prefix 2472ef…) can NEVER handshake them — the "never btc / never
    // cross-pollute" guard is the PREFIX, not an empty list. Append more fork-host
    // beacons here (one place). Mirrors btc/config_pool.hpp DEFAULT_BOOTSTRAP_HOSTS.
    static inline const std::vector<std::string> DEFAULT_BOOTSTRAP_HOSTS = {
        "bip110.voidbind.com:9337",
    };

    // ---- Bootstrap ladder — OurBeacon default, prefix-guarded ---------------
    // Precedence: explicit peers > regtest > OurBeacon (default). With no
    // explicit --sharechain-addnode and not regtest we dial DEFAULT_BOOTSTRAP_HOSTS
    // (our own beacons); the PREFIX (e2bdb110 / :9337) — not an empty list — keeps
    // us off btc's (2472ef / :9333) or any other lane's sharechain. A user or the
    // qt configurator can OVERRIDE/extend the list via --sharechain-addnode (the
    // unified TOML `sharechain.addnodes` key).
    enum class BootstrapMode {
        ExplicitPeers,   // --sharechain-addnode given: dial ONLY those
        RegtestIsolated, // --regtest: 0 seeds, solo/local
        OurBeacon,       // default (non-regtest, no explicit peers): dial DEFAULT_BOOTSTRAP_HOSTS
    };

    static BootstrapMode select_bootstrap_mode(bool has_explicit_peers, bool regtest)
    {
        if (has_explicit_peers) return BootstrapMode::ExplicitPeers;
        if (regtest)            return BootstrapMode::RegtestIsolated;
        return BootstrapMode::OurBeacon;
    }

    // Default seed list = OUR bip110 beacons (never another lane's hosts).
    static const std::vector<std::string>& default_bootstrap_hosts()
    {
        return DEFAULT_BOOTSTRAP_HOSTS;
    }
};

} // namespace bip110::pool
