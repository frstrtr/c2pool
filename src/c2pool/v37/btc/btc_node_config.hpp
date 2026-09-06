// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/btc/btc_node_config.hpp   (Track A2 / Milestone A-BTC — node)
//
// The configuration surface for the single-node testnet-capable c2pool-v37
// BITCOIN-FAMILY daemon (XbtcNode). CONSUMER-tree code: a pure value struct, no
// consensus digest — every consensus knob it carries (LaneParams) is passed
// THROUGH to the merged executor, never redefined here.
//
// EXPERIMENTAL / DEVNET-DEFAULT: `network` defaults to Regtest/Devnet and the
// daemon README posture is do-not-run-in-production. Mainnet is a deliberate,
// loud opt-in (XbtcNode refuses to build a mainnet coinbase / submit a mainnet
// block without an explicit --i-understand-mainnet acknowledgement — HARD
// SAFETY 4). DASH regtest/devnet is the DEFAULT so the controlled falsifier
// (mine-and-settle + reorg-drill) can inject reorgs at will.
// ===========================================================================
#pragma once

#include <cstdint>
#include <string>

#include <sharechain/v37/v37_lane.hpp>       // ::v37::LaneParams
#include <sharechain/v37/v37_roundabout.hpp> // ::v37::ChainId

namespace c2pool::v37n::btc {

// Which BTC-family parent this node settles. Both are SHA-256d/Scrypt native
// V37.0 canon (NO P-1, NO RandomX). DASH is the primary demo coin (X11 PoW,
// embedded-SPV daemonless adapter, reorg-injectable regtest); LTC testnet4 is
// the documented alternate (Scrypt PoW, daemon RPC adapter).
enum class BtcFamilyCoin : std::uint8_t { Dash = 0, Ltc = 1 };

inline const char* to_string(BtcFamilyCoin c) {
    switch (c) {
        case BtcFamilyCoin::Dash: return "dash";
        case BtcFamilyCoin::Ltc:  return "ltc";
    }
    return "dash";
}

// The network the coin adapter binds to. Regtest/Devnet is the shipped default
// — a v37 BTC-family node is prototype-grade and must never default to real
// value. (DASH ships regtest+devnet; LTC ships regtest+testnet4.)
enum class BtcNetwork : std::uint8_t { Regtest = 0, Devnet = 1, Testnet4 = 2, Mainnet = 3 };

inline const char* to_string(BtcNetwork n) {
    switch (n) {
        case BtcNetwork::Regtest:  return "regtest";
        case BtcNetwork::Devnet:   return "devnet";
        case BtcNetwork::Testnet4: return "testnet4";
        case BtcNetwork::Mainnet:  return "mainnet";
    }
    return "regtest";
}

// The <net> path segment used under config_path()/<coin>/<net>/v37_settle_db —
// one isolated settlement store per (coin,network) so a regtest run can never
// read or clobber a mainnet store (mirrors the per-coin datadir isolation the
// mature v36 Bitcoin family uses via core::config).
inline const char* net_dir(BtcNetwork n) { return to_string(n); }

// The coin-daemon RPC/P2P endpoint the v36 adapter talks to. For DASH the
// embedded-SPV adapter needs only the P2P port for header sync + the optional
// submitblock RPC backup (ARM B). For LTC testnet4 the daemonful adapter uses
// the RPC endpoint for getblocktemplate + submitblock.
struct CoinDaemonEndpoint {
    std::string   rpc_host = "127.0.0.1";
    std::uint16_t rpc_port = 0;   // set by default_endpoint()
    std::uint16_t p2p_port = 0;   // DASH embedded-SPV header sync
    std::string   rpc_user;       // LTC daemonful arm (empty for DASH daemonless)
    std::string   rpc_pass;
};

// Default RPC/P2P ports per (coin,network). DASH: regtest 19998/19899, devnet
// 19998/<dynamic>. LTC: regtest 19443, testnet4 19332 (post-testnet4 rollout).
inline CoinDaemonEndpoint default_endpoint(BtcFamilyCoin coin, BtcNetwork net) {
    CoinDaemonEndpoint e;
    e.rpc_host = "127.0.0.1";
    if (coin == BtcFamilyCoin::Dash) {
        switch (net) {
            case BtcNetwork::Regtest:  e.rpc_port = 19998; e.p2p_port = 19899; break;
            case BtcNetwork::Devnet:   e.rpc_port = 19998; e.p2p_port = 19899; break;
            case BtcNetwork::Testnet4: // DASH has no testnet4; fall through to testnet
            case BtcNetwork::Mainnet:  e.rpc_port =  9998; e.p2p_port =  9999; break;
        }
    } else {  // LTC
        switch (net) {
            case BtcNetwork::Regtest:  e.rpc_port = 19443; e.p2p_port = 19444; break;
            case BtcNetwork::Devnet:
            case BtcNetwork::Testnet4: e.rpc_port = 19332; e.p2p_port = 19335; break;
            case BtcNetwork::Mainnet:  e.rpc_port =  9332; e.p2p_port =  9333; break;
        }
    }
    return e;
}

// D_conf floor per coin (>= coinbase maturity so a finalized block's reward is
// spendable and its burial is irreversible under honest-majority). DASH/LTC
// coinbase maturity is 100 blocks; the F1 driver's default D_conf uses this.
inline std::uint64_t default_d_conf(BtcFamilyCoin coin) {
    (void)coin;   // both families: 100-block coinbase maturity
    return 100;
}

struct BtcNodeConfig {
    // --- BTC-family parent --------------------------------------------------
    BtcFamilyCoin      coin    = BtcFamilyCoin::Dash;
    BtcNetwork         network = BtcNetwork::Regtest;
    CoinDaemonEndpoint daemon  = default_endpoint(BtcFamilyCoin::Dash, BtcNetwork::Regtest);

    // Explicit acknowledgement required before the daemon will build a MAINNET
    // coinbase / submit a mainnet block. Prototype safety fence (HARD SAFETY 4).
    bool i_understand_mainnet = false;

    // --- v37 BTC-family lane ------------------------------------------------
    // The ChainId of the single BTC-family-parent lane this node settles.
    // AddLane is issued for exactly this chain at start (single-node, single
    // lane). Distinct kind-space from the XMR lane — this is the NATIVE canon.
    ::v37::ChainId  lane_chain = 0;

    // The digest-committed lane geometry. Defaults to the OQ-5 ratified default
    // (LaneParams{}), the only geometry W4's geometry_is_ratified() admits.
    ::v37::LaneParams lane_params{};

    // --- settlement finality (F1 driver) ------------------------------------
    // D_conf: blocks a found (coinbase-carrying) BTC-family block must be buried
    // on the best chain before its settlement is FINALIZED. The finalize driver
    // advances one coin-height at a time; a block at height h finalizes when the
    // best-chain high-water reaches h + D_conf. >= coinbase maturity (100).
    std::uint64_t   d_conf = default_d_conf(BtcFamilyCoin::Dash);

    // Mainchain-view retention below the tip (>= D_conf so a finalizing block is
    // always resident; the embedded-SPV HeaderChain / daemon index answers the
    // canonicality predicate over this window).
    std::uint64_t   index_retain_recent = 720;

    // --- stratum front-end (v36 core::StratumServer) ------------------------
    std::string     stratum_bind_host = "127.0.0.1";
    std::uint16_t   stratum_bind_port = 3032;   // c2pool BTC-family stratum default

    // --- storage ------------------------------------------------------------
    // When empty, config_path()/<coin>/<net>/v37_settle_db is used. Set to
    // override the settlement-store directory (the smoke sets a temp dir / uses
    // MemSettleStore).
    std::string     settle_db_path;

    // --- PoW verify posture -------------------------------------------------
    // The v36 stratum IWorkSource::compute_share_difficulty encapsulates the
    // per-coin PoW (X11 for DASH, Scrypt for LTC, SHA-256d for BTC). When
    // `pow_verify_enabled` is false (local/OOM smoke), the submit path
    // structural-checks only and does NOT accept a share as a network block
    // (fail-closed — no unverified block is ever submitted to the coin daemon).
    bool            pow_verify_enabled = false;

    // Resolve the on-disk settlement-store directory (settle_db_path override or
    // config_path()/<coin>/<net>/v37_settle_db).
    std::string resolved_settle_db_path() const {
        if (!settle_db_path.empty()) return settle_db_path;
        return std::string("./v37data/") + to_string(coin) + "/" +
               net_dir(network) + "/v37_settle_db";
    }
};

} // namespace c2pool::v37n::btc
