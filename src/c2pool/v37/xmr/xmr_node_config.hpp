// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_node_config.hpp   (Track A2 / Milestone A — live node)
//
// The configuration surface for the single-node stagenet-capable c2pool-v37
// XMR daemon (XmrNode). CONSUMER-tree code: pure value struct, no consensus
// digest — every consensus knob it carries (LaneParams) is passed THROUGH to
// the merged executor, never redefined here.
//
// EXPERIMENTAL / STAGENET-DEFAULT: `network` defaults to Stagenet and the
// daemon README posture is do-not-run-in-production. Mainnet is a deliberate,
// loud opt-in (XmrNode refuses to build a mainnet coinbase without an explicit
// --i-understand-mainnet acknowledgement; see xmr_node.hpp).
// ===========================================================================
#pragma once

#include <cstdint>
#include <string>

#include <sharechain/v37/v37_lane.hpp>       // ::v37::LaneParams
#include <sharechain/v37/v37_roundabout.hpp> // ::v37::ChainId
#include "impl/xmr/node/xmr_node_types.hpp"  // c2pool::xmr::node::DaemonEndpoint

namespace c2pool::v37n::xmr {

// The Monero network the daemon binds to. Stagenet is the shipped default —
// a v37 XMR node is prototype-grade and must never default to real value.
enum class MoneroNetwork : std::uint8_t { Stagenet = 0, Testnet = 1, Mainnet = 2 };

inline const char* to_string(MoneroNetwork n) {
    switch (n) {
        case MoneroNetwork::Stagenet: return "stagenet";
        case MoneroNetwork::Testnet:  return "testnet";
        case MoneroNetwork::Mainnet:  return "mainnet";
    }
    return "stagenet";
}

// The <net> path segment used under config_path()/<net>/v37_settle_db — one
// isolated settlement store per network so a stagenet run can never read or
// clobber a mainnet store (mirrors the per-coin datadir isolation the Bitcoin
// family uses via core::config).
inline const char* net_dir(MoneroNetwork n) { return to_string(n); }

// Default monerod RPC/ZMQ ports per network (monerod >= v0.18.0.0). The X2
// adapter needs get_miner_data + the three ZMQ topics, all >= v0.18.
inline c2pool::xmr::node::DaemonEndpoint default_endpoint(MoneroNetwork n) {
    c2pool::xmr::node::DaemonEndpoint e;
    e.rpc_host = "127.0.0.1";
    switch (n) {
        case MoneroNetwork::Stagenet: e.rpc_port = 38081; e.zmq_port = 38083; break;
        case MoneroNetwork::Testnet:  e.rpc_port = 28081; e.zmq_port = 28083; break;
        case MoneroNetwork::Mainnet:  e.rpc_port = 18081; e.zmq_port = 18083; break;
    }
    return e;
}

struct XmrNodeConfig {
    // --- Monero parent ------------------------------------------------------
    MoneroNetwork                     network = MoneroNetwork::Stagenet;
    c2pool::xmr::node::DaemonEndpoint monerod = default_endpoint(MoneroNetwork::Stagenet);

    // Explicit acknowledgement required before the daemon will build a MAINNET
    // coinbase / submit a mainnet block. Prototype safety fence (HARD SAFETY 5).
    bool i_understand_mainnet = false;

    // --- v37 XMR lane -------------------------------------------------------
    // The ChainId of the single Monero-parent lane this node settles. AddLane
    // is issued for exactly this chain at start (single-node, single lane).
    ::v37::ChainId  lane_chain = 0;

    // The digest-committed lane geometry. Defaults to the OQ-5 ratified default
    // (LaneParams{}), the only geometry W4's geometry_is_ratified() admits.
    ::v37::LaneParams lane_params{};

    // --- settlement finality (F1 driver) ------------------------------------
    // D_conf: blocks a found (coinbase-carrying) Monero block must be buried on
    // the best chain before its settlement is FINALIZED. The finalize driver
    // advances one coin-height at a time; a block at height h finalizes when the
    // best-chain high-water reaches h + D_conf. Coinbase maturity is 60 on XMR,
    // so D_conf >= 60 is the safe floor (XMR_COINBASE_MATURITY, scoping §2.1).
    std::uint64_t   d_conf = 60;

    // MainchainIndex retention below the tip (>= D_conf so a finalizing block is
    // always resident; seed anchors are pinned on top regardless).
    std::uint64_t   index_retain_recent = 720;

    // --- stratum front-end (X5) --------------------------------------------
    std::string     stratum_bind_host = "127.0.0.1";
    std::uint16_t   stratum_bind_port = 3333;   // XMRig default; single-node

    // --- storage ------------------------------------------------------------
    // When empty, config_path()/<net>/v37_settle_db is used (see xmr_node.hpp).
    // Set to override the settlement-store directory (tests set a temp dir).
    std::string     settle_db_path;

    // --- RandomX verify (X pow/) -------------------------------------------
    // Heavy (256 MiB light cache + light VM). Disabled by default for local /
    // OOM-pressured smoke runs; the CI/stagenet build turns it on. When off, the
    // stratum submit path structural-checks only and does NOT accept a share as
    // a network block (fail-closed — no unverified block is ever submitted).
    bool            randomx_enabled = false;
    bool            randomx_large_pages = false;

    // Resolve the on-disk settlement-store directory (settle_db_path override or
    // config_path()/<net>/v37_settle_db). Declared here, defined in xmr_node.hpp
    // to keep this header free of <filesystem>/core includes for cheap inclusion.
    std::string resolved_settle_db_path() const;
};

} // namespace c2pool::v37n::xmr
