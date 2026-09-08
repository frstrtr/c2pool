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
//
// Regtest (monerod --regtest) is FAKECHAIN: it runs the MAINNET config (mainnet
// base58 prefixes, mainnet default ports) on a private chain with
// --fixed-difficulty and in-daemon generateblocks. It carries no value, so it
// does NOT trip the --i-understand-mainnet fence — but it must never be confused
// with Mainnet either (its own settlement store dir, its own label).
enum class MoneroNetwork : std::uint8_t { Stagenet = 0, Testnet = 1, Mainnet = 2, Regtest = 3 };

inline const char* to_string(MoneroNetwork n) {
    switch (n) {
        case MoneroNetwork::Stagenet: return "stagenet";
        case MoneroNetwork::Testnet:  return "testnet";
        case MoneroNetwork::Mainnet:  return "mainnet";
        case MoneroNetwork::Regtest:  return "regtest";
    }
    return "stagenet";
}

// The <net> path segment used under config_path()/<net>/v37_settle_db — one
// isolated settlement store per network so a stagenet run can never read or
// clobber a mainnet store (mirrors the per-coin datadir isolation the Bitcoin
// family uses via core::config).
inline const char* net_dir(MoneroNetwork n) { return to_string(n); }

// Which coinbase the serve side builds, serves and submits.
//   MonerodTemplate (option A, default, PR #1534): monerod's own get_block_template
//     block — a single coinbase to --payout-address, nonce patched. A genuine,
//     monerod-validated block, but NOT the v37 settlement coinbase.
//   V37Settlement (option B): a v37-BUILT Monero block whose miner_tx is the
//     K_fair settlement coinbase (oldest-owed-first EffectiveOwed payees ++
//     mandated fixed outputs ++ exact-sum residual sink), assembled from
//     get_miner_data over the W4 OwedLedger. Requires a torsion-valid residual
//     sink (--residual-sink-spend-hex/--residual-sink-view-hex). Fail-closed:
//     without a valid sink the daemon refuses to serve.
enum class CoinbaseMode : std::uint8_t { MonerodTemplate = 0, V37Settlement = 1 };

inline const char* to_string(CoinbaseMode m) {
    switch (m) {
        case CoinbaseMode::MonerodTemplate: return "monerod-template (option A)";
        case CoinbaseMode::V37Settlement:   return "v37-settlement (option B)";
    }
    return "monerod-template (option A)";
}

// Default monerod RPC/ZMQ ports per network (monerod >= v0.18.0.0). The X2
// adapter needs get_miner_data + the three ZMQ topics, all >= v0.18.
inline c2pool::xmr::node::DaemonEndpoint default_endpoint(MoneroNetwork n) {
    c2pool::xmr::node::DaemonEndpoint e;
    e.rpc_host = "127.0.0.1";
    switch (n) {
        case MoneroNetwork::Stagenet: e.rpc_port = 38081; e.zmq_port = 38083; break;
        case MoneroNetwork::Testnet:  e.rpc_port = 28081; e.zmq_port = 28083; break;
        case MoneroNetwork::Mainnet:  e.rpc_port = 18081; e.zmq_port = 18083; break;
        // FAKECHAIN uses the mainnet defaults; a private regtest monerod should be
        // started with explicit --rpc-bind-port / --zmq-pub and the daemon pointed
        // at them (--rpc-port / --zmq-port) so it can never collide with a mainnet
        // monerod on the same host.
        case MoneroNetwork::Regtest:  e.rpc_port = 18081; e.zmq_port = 18083; break;
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

    // --- O-2 serve side (stratum listener + live submit) --------------------
    // The wallet address monerod's get_block_template pays the block reward to
    // (network-prefixed standard address; regtest = mainnet '4…' format). EMPTY
    // = the stratum port is NOT served and the daemon runs observe-side only
    // (index + settlement + F1 driver), exactly as the X9 bring-up did.
    //
    // HONEST SCOPE (option A): the block bytes served and submitted are
    // monerod's own template — a single coinbase to this address — with the
    // winning nonce patched. That is a genuine, monerod-validated block end to
    // end, but NOT yet the v37 K_fair settlement coinbase (option B follow-on).
    std::string     payout_address;
    // get_block_template reserve_size (tx_extra nonce reservation). 0 = none:
    // one blob for every worker (max_extra_nonces == 1). Per-client extra_nonce
    // (>= 4) is a follow-on of the template source.
    std::uint32_t   template_reserve_size = 0;
    // Share (lane) difficulty served to miners. 0 = solo: the job target IS the
    // network target, so every accepted share is a network block. A lower value
    // (e.g. 1000 on regtest) makes miners report shares between blocks.
    std::uint64_t   stratum_share_diff = 0;
    // Main-loop cadence: tip poll fallback, template refresh, found-queue drain.
    // 5 s suits stagenet; ~1000 ms for a regtest demo.
    std::uint32_t   poll_ms = 5000;
    // Pending-FOUND sidecar (pfound.tsv next to settle.img) so a restart inside
    // the D_conf window does not lose a pending FOUND (D10). --no-found-sidecar.
    bool            found_sidecar = true;
    // Optional payee identity (the address boundary's OUTPUT): the raw public
    // spend + view keys of the payout address, 64 hex each. When both are set,
    // FOUND/FINALIZE records are amount-honest ({identity_key : reward}); when
    // absent the block is recorded as a valueless {}/{} record.
    std::string     payee_spend_key_hex;
    std::string     payee_view_key_hex;
    bool            payee_subaddress = false;
    // Seconds between the main loop's one-line status reports (0 = never).
    std::uint32_t   status_every_s = 30;

    // --- O-2 OPTION B: the v37 K_fair settlement coinbase -------------------
    // --coinbase monerod (option A, default) | v37 (option B). In v37 mode the
    // block the pool assembles + submits is the settlement coinbase, not
    // monerod's get_block_template — so --payout-address is not consulted for
    // the coinbase bytes (it may stay empty; the serve port opens when the
    // residual sink is set, mirroring option A's payout_address gate).
    CoinbaseMode    coinbase = CoinbaseMode::MonerodTemplate;
    // The mandated residual sink (REQUIRED for v37 mode): the raw public spend
    // (B) + view (A) keys, 64 hex each, of the XMR wallet the exact-sum residual
    // is paid to. Torsion-checked at build; the daemon REFUSES v37 mode without
    // a valid sink. --residual-sink-subaddress builds an XMR_SUB (D_i, A_main).
    std::string     residual_sink_spend_hex;
    std::string     residual_sink_view_hex;
    bool            residual_sink_subaddress = false;
    // The v37 lane parameters (consensus once multi-node; explicit here).
    std::uint64_t   settle_h_min      = 0;      // piconero floor per owed output (0 on XMR)
    std::uint32_t   settle_output_cap = 0;      // TOTAL outputs cap; 0 => weight-aware default
    // Optional demo owed entry seeded into the (otherwise empty) proof ledger so
    // the assembled coinbase carries a real K_fair OWED payee alongside the sink
    // (a multi-output settlement coinbase). 0 => empty ledger (sink-only).
    // The owed payee is a distinct torsion-valid payee derived from the sink
    // material with spend/view swapped (see main). Proof-only; no live ledger yet.
    std::uint64_t   owed_demo_amount = 0;

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
