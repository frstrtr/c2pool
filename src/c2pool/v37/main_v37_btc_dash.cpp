// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/main_v37_btc_dash.cpp   (Track A2 follow-on / PR-1 — the LIVE entry)
//
// c2pool-v37-btc-dash: the single live node the A-BTC lifecycle was written
// for (btc_node.hpp:20-38 STEP 2f/2g), against ONE dashd -regtest/-devnet over
// RPC. Sibling of main_v37_btc.cpp (which keeps the Threads-only --selftest);
// this TU is the HEAVY leg (links the src/impl/dash objects: Boost.Asio/Beast,
// jsonrpccxx, nlohmann, LevelDB, X11). Target: master 89325e91.
//
// What it sequences (nothing here is consensus code):
//   open()   FileSettleStore + RecoveryDriver (F2) + BtcFinalizeDriver with
//            CanonicalFn = DashRpcCoinBackend::is_canonical         [btc_node.hpp:104-126]
//   ★ boot   BlockEventDriver::reseed_after_open(): every pending FOUND the
//            store holds (sidecar + FOUND event) is re-driven into the fresh
//            finalize driver — a restart before D_conf burial no longer strands
//            it (verify-round fix 3 / D10)                    [block_event_driver.hpp]
//   start()  V37Engine + AddLane                                    [btc_node.hpp:132-143]
//   2f       DASHWorkSource on the dashd getblocktemplate fallback ONLY (the
//            embedded NodeCoinState is left EMPTY so every template is dashd's:
//            populated()==false → DashdFallback) handed to core::StratumServer
//                                                        [main_dash.cpp:3503-3505, :4218]
//   2g       height-watch: try_best_tip() → D11 reorg re-check → BlockEventDriver::
//            on_tip → refresh template → bump_work_generation + notify_all
//                                                                    [btc_node.hpp:149-154]
//
// THE VERIFY-ROUND FIXES FOLDED HERE (★) --------------------------------------------
//   ★1 D8  H_b FROM THE BLOCK. The v36 SubmitBlockFn's `height` is cached_work()'s
//          template height (src/impl/dash/stratum/work_source.cpp:2698, passed at
//          :2845) — NOT the block's. submit_fn below derives the parent from the
//          80-byte header it is handed (header[4..36) = hashPrevBlock), asks the
//          backend height_of(parent), registers at parent+1; if the parent is
//          unknown at win time it submits first and registers from height_of(bid)
//          after an ACCEPTED submit. Never at the template height, never at 0.
//          Every `height race` line the log prints must agree with
//          `getblockheader <bid> .height` (runbook A7 checks it).
//   ★3 D10 BLOCK-EVENT DRIVER. on_block_found (sidecar write-ahead → FOUND event →
//          announce), on_block_finalized (D_conf burial, off the tip watch),
//          on_block_orphaned (D11 re-check off the tip watch, or at maturity
//          inside the F1 driver) — and the restart re-drive. See
//          block_event_driver.hpp; it needs the one consumer-tree seam
//          BtcFinalizeDriver::reseed_found (consumer_tree_edits.patch).
//   D11    poll-side reorg re-check: tip lowered, or the previous tip left the
//          active chain → canonicality over the pending FOUNDs → ORPHAN `No`
//          at once (Unknown waits). Pre-SETTLED only (S-9 stays open).
//   D12    torn store = FileSettleStore CONSTRUCTOR throw (store_codec::Reader,
//          btc_settle_store.hpp:132 inside load(), :266-276) — mapped to exit 6
//          here, not a SIGABRT.
//   D2/D7  chain-identity fence at start (chain tag + regtest genesis pin) AND
//          per poll (ChainMismatch → FATAL exit 9): a dashd restarted on another
//          chain on the same rpcport is never followed (runbook A9).
//
// SEAMS THIS FILE NAMES (each a follow-on PR):
//   S-1  W5 outputs at TEMPLATE time. A mined block's hash commits to the
//        coinbase DASHWorkSource built for the job (core/stratum_work_source.hpp:
//        125-129), so W5 K_fair outputs assembled in on_block_won AFTER the win
//        (btc_node.hpp:189-190) can never enter the block. Injection point:
//        DASHWorkSource::set_producer_job_fn (dash stratum work_source.hpp:207,
//        :538). Until it lands this node mines the v36 miner-only coinbase; every
//        FOUND carries empty credit/payout and owed_digest stays the empty digest
//        — the bring-up proves SEQUENCING (found→bury→FINALIZE→orphan→recover),
//        not settlement. Stated in the runbook.
//   S-3  Tri-state canonicality IN the F1 driver (Canon-returning CanonicalFn at
//        btc_finalize_driver.hpp:84, "stop stepping on Unknown" at :165) instead
//        of the backend's throw-after-patience. 10-line driver change.
//   S-6  btc_node_config.hpp:87-90 default_endpoint(): 19998 is Dash Core's
//        TESTNET rpc port; regtest is 19898 (dashpay/dash v23.1.7
//        src/chainparamsbase.cpp:48), devnet 19798 (:46). Pinned here explicitly.
//   S-8  btc_node.hpp:185 win-time gate.canonical = m_coin->is_canonical(): with
//        a daemon backend it is ALWAYS false at win time (we register BEFORE
//        submit → dashd answers -5) and, with dashd down, spins oracle_patience
//        on the stratum thread under the driver lock before throwing. The driver
//        catches the throw and main retries after the submit, so nothing is lost;
//        the one-liner `gate.canonical = false` at win time removes the spin.
//
// EXIT CODES: 2 usage · 3 mainnet fence · 4 creds unresolved · 5 dashd not
// ready / chain or genesis fence at start · 6 store refused (torn image, F2) or
// open() refused · 7 start() · 8 stratum bind · 9 FATAL chain mismatch while running
// · 10 W3-B5 wire-freeze selfcheck failed at boot (this build's CarrierWire
// drifted from the frozen v0x01 goldens; refusing to peer, never floods frames).
//
// BUILD (src/c2pool/CMakeLists.txt, target c2pool-v37-btc-dash, next to
// c2pool-v37-btc; c2pool-v37-btc STAYS Threads-only, HARD SAFETY 6).
// DASHWorkSource bodies pull the whole c2pool-dash SCC: this is a FULL heavy
// link — the link set is the DASH library set of c2pool-dash /
// dash_hdr_backfill_window_kat (dash_scriptcheck omitted, as the DASH KATs do).
// `c2pool-v37-btc-dash` is on build.yml's linux-leg --target list (next to
// c2pool-v37-btc) so CI compiles + links it; like c2pool-dash it is not on the
// ASan+UBSan leg (no heavy coin executable is). It registers no CTest, so the
// drift-guard (tools/ci/check_test_target_allowlist.py) has nothing to audit
// for it. The runtime gate is the runbook on VM100 (operator-run):
// src/c2pool/v37/tools/runbook_dash_regtest.sh, A1–A9.
//     cmake --build <build-dir> --target c2pool-v37-btc-dash
// ===========================================================================
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>
#include <util/strencodings.h>                        // HexStr (btclibs; the same include rpc.cpp uses)

#include <core/log.hpp>
#include <core/netaddress.hpp>                        // NetService
#include <core/stratum_server.hpp>                    // core::StratumServer
#include <core/stratum_types.hpp>                     // core::stratum::StratumConfig
#include <core/uint256.hpp>
#include <impl/dash/address_encoding.hpp>             // dash::address_acceptance (main_dash.cpp:3519)
#include <impl/dash/coin/node_coin_state.hpp>         // dash::coin::NodeCoinState
#include <impl/dash/coin/rpc.hpp>                     // dash::coin::NodeRPC
#include <impl/dash/coin/rpc_conf.hpp>                // load_rpc_conf / apply_endpoint_override / resolve_dashd_arm
#include <impl/dash/crypto/hash_x11.hpp>              // dash::crypto::hash_x11 (header-only X11 == DASH block hash)
#include <impl/dash/stratum/work_source.hpp>          // dash::stratum::DASHWorkSource

#include <c2pool/v37/btc/btc_node.hpp>                // XbtcNode, p2pkh_pay_of
#include <c2pool/v37/btc/btc_node_config.hpp>
#include <c2pool/v37/btc/btc_settle_store.hpp>        // FileSettleStore
#include <c2pool/v37/btc/block_event_driver.hpp>      // BlockEventDriver, Canon
#include <c2pool/v37/btc/dash_rpc_coin_backend.hpp>   // DashRpcCoinBackend, parse_block_id, display_hex_of_internal

// Track A2 CONSUMER half — the carrier p2p layer (cross-node share/receipt
// ingestion). Non-consensus: every append rides CarrierRelay -> CarrierIngest
// -> V37Engine (node.engine()), never src/sharechain/v37 canon.
#include <c2pool/v37/carrier_ingest.hpp>              // CarrierIngest, MemShareTracker
#include <c2pool/v37/carrier_index.hpp>               // LiveMainchainIndex / SyntheticMainchainIndex (A2 step-b real index)
#include <c2pool/v37/carrier_net.hpp>                 // CarrierPeerNode (ICarrierTransport over sockets)
#include <c2pool/v37/carrier_send.hpp>                // CarrierSendQueue (A2 send-side: own stratum wins -> carriers, off the hot path)
#include <c2pool/v37/w3_relay.hpp>                    // CarrierRelay
#include <c2pool/v37/w3_wire_freeze.hpp>              // W3-B5 freeze: boot selfcheck + relay policy gate

namespace io = boost::asio;
using namespace c2pool::v37n::btc;
using namespace c2pool::v37n;   // A2 consumer: CarrierRelay/CarrierIngest/CarrierPeerNode/… (parent ns)

static std::atomic<bool> g_stop{false};
static void on_signal(int) { g_stop = true; }

static std::string hex32(const ::v37::bytes32& b) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (const auto x : b) { s.push_back(kHex[x >> 4]); s.push_back(kHex[x & 0x0f]); }
    return s;
}

static void usage() {
    std::printf(
        "c2pool-v37-btc-dash (EXPERIMENTAL; DASH regtest/devnet ONLY; do not run in production)\n"
        "  --network regtest|devnet|mainnet   (default regtest; mainnet REFUSED without --i-understand-mainnet)\n"
        "  --daemon-rpc HOST:PORT             (default 127.0.0.1:19898 — Dash Core REGTEST rpc port)\n"
        "  --coin-rpc-auth PATH               dash.conf-style file with rpcuser/rpcpassword (default ~/.dashcore/dash.conf)\n"
        "  --stratum-bind HOST:PORT           (default 127.0.0.1:3032)\n"
        "  --settle-db PATH                   (default ./v37data/dash/<net>/v37_settle_db)\n"
        "  --d-conf N                         (default 100; regtest drills use 6)\n"
        "  --poll-ms N                        height-watch period (default 500)\n"
        "  --oracle-patience-ms N             is_canonical transport retry budget before deferring (default 30000)\n"
        "  --p2p-bind HOST:PORT               carrier-relay listen addr (A2 consumer; empty = no inbound bind)\n"
        "  --peer HOST:PORT                   dial a carrier-relay peer (A2 consumer; repeatable)\n"
        "  --carrier-synthetic-index N        DEBUG: index carriers against the synthetic {mainchain_hash(h)->h} map with\n"
        "                                     tip=N (the W2/W3 KAT model) instead of live dashd. Under this flag THIS node's\n"
        "                                     own stratum wins (keyed to REAL parent hashes) never resolve -> they are NOT\n"
        "                                     emitted as carriers (counted as unresolved_parent); only synthetic-keyed\n"
        "                                     peers' carriers account\n"
        "  --carrier-index-horizon N          live index: reject carriers keyed further than N blocks behind the tip (default 64)\n"
        "  --carrier-index-patience-ms N      live index: bounded retry budget while dashd answers Unknown (default 2000)\n"
        "  --i-understand-mainnet             loud mainnet opt-in (HARD SAFETY 4)\n");
}

int main(int argc, char** argv) {
    // ── flags ────────────────────────────────────────────────────────────────
    BtcNodeConfig cfg;
    cfg.coin    = BtcFamilyCoin::Dash;
    cfg.network = BtcNetwork::Regtest;
    std::string rpc_hostport = "127.0.0.1:19898";   // S-6: btc_node_config.hpp:87 says 19998 = Dash Core TESTNET;
                                                    // regtest rpc is 19898 (v23.1.7 src/chainparamsbase.cpp:48)
    std::string auth_path;
    std::string stratum_bind = "127.0.0.1:3032";
    std::string p2p_bind;                 // A2: empty = no inbound carrier bind
    std::vector<std::string> peers;       // A2: --peer HOST:PORT, repeatable
    std::optional<std::uint64_t> synthetic_index_tip;   // A2: --carrier-synthetic-index N (KAT model)
    std::uint64_t carrier_index_horizon = 64;           // A2 step-b: LiveMainchainIndex::Options::horizon
    long          carrier_index_patience_ms = 2000;     // A2 step-b: LiveMainchainIndex::Options::unknown_patience
    int  poll_ms = 500;
    long oracle_patience_ms = 30000;
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        auto next = [&](std::string& out) { if (i + 1 < argc) out = argv[++i]; };
        if (!std::strcmp(a, "--network") && i + 1 < argc) {
            const std::string n = argv[++i];
            if      (n == "regtest") cfg.network = BtcNetwork::Regtest;
            else if (n == "devnet")  cfg.network = BtcNetwork::Devnet;
            else if (n == "mainnet") cfg.network = BtcNetwork::Mainnet;
            else { usage(); return 2; }
        }
        else if (!std::strcmp(a, "--daemon-rpc"))                          next(rpc_hostport);
        else if (!std::strcmp(a, "--coin-rpc-auth"))                       next(auth_path);
        else if (!std::strcmp(a, "--stratum-bind"))                        next(stratum_bind);
        else if (!std::strcmp(a, "--p2p-bind"))                            next(p2p_bind);
        else if (!std::strcmp(a, "--peer") && i + 1 < argc)                peers.emplace_back(argv[++i]);
        else if (!std::strcmp(a, "--carrier-synthetic-index") && i + 1 < argc) synthetic_index_tip = std::strtoull(argv[++i], nullptr, 10);
        else if (!std::strcmp(a, "--carrier-index-horizon") && i + 1 < argc)     carrier_index_horizon = std::strtoull(argv[++i], nullptr, 10);
        else if (!std::strcmp(a, "--carrier-index-patience-ms") && i + 1 < argc) carrier_index_patience_ms = std::atol(argv[++i]);
        else if (!std::strcmp(a, "--settle-db"))                           next(cfg.settle_db_path);
        else if (!std::strcmp(a, "--d-conf") && i + 1 < argc)              cfg.d_conf = std::strtoull(argv[++i], nullptr, 10);
        else if (!std::strcmp(a, "--poll-ms") && i + 1 < argc)             poll_ms = std::atoi(argv[++i]);
        else if (!std::strcmp(a, "--oracle-patience-ms") && i + 1 < argc)  oracle_patience_ms = std::atol(argv[++i]);
        else if (!std::strcmp(a, "--i-understand-mainnet"))                cfg.i_understand_mainnet = true;
        else { usage(); return 2; }
    }
    if (cfg.d_conf == 0 || poll_ms <= 0 || oracle_patience_ms < 0 || carrier_index_patience_ms < 0) { usage(); return 2; }
    cfg.pow_verify_enabled = true;   // live: the v36 work source verifies X11 itself
    if (cfg.network == BtcNetwork::Mainnet && !cfg.i_understand_mainnet) {
        std::fprintf(stderr, "REFUSED: mainnet without --i-understand-mainnet (HARD SAFETY 4)\n");
        return 3;   // XbtcNode::open() would refuse too (btc_node.hpp:105); refuse BEFORE dialing dashd
    }

    // ── dashd creds: NEVER on argv (rpc_conf.hpp:9-13) ───────────────────────
    dash::coin::RpcConf conf;
    if (auth_path.empty()) {
        const char* home = std::getenv("HOME");
        auth_path = std::string(home ? home : ".") + "/.dashcore/dash.conf";
    }
    dash::coin::load_rpc_conf(auth_path, conf);
    dash::coin::apply_endpoint_override(rpc_hostport, conf);
    const auto arm = dash::coin::resolve_dashd_arm(/*coin_rpc_requested=*/true, conf.armed());
    if (!arm.construct_rpc) {
        std::fprintf(stderr, "REFUSED: %s (auth file: %s)\n", arm.reason, auth_path.c_str());
        return 4;
    }
    cfg.daemon.rpc_host = conf.host;
    cfg.daemon.rpc_port = conf.port;

    // ── io_context (NodeRPC::connect is async; StratumServer needs it too) ───
    io::io_context ioc;
    auto work_guard = io::make_work_guard(ioc);
    std::thread io_thread([&] { ioc.run(); });
    auto teardown_io = [&] { work_guard.reset(); ioc.stop(); if (io_thread.joinable()) io_thread.join(); };

    // NodeRPC's `dash::interfaces::Node*` is stored and never dereferenced in
    // rpc.cpp (m_coin is only initialised at :31; no other use) — nullptr is
    // safe. IS_TESTNET=true selects the testnet genesis in check(); on regtest
    // check() only fails the genesis probe for chain=="main" (rpc.cpp:337-347),
    // so a regtest daemon passes. The REAL fence is the backend's (below).
    auto rpc = std::make_shared<dash::coin::NodeRPC>(&ioc, /*coin=*/nullptr,
                                                     /*testnet=*/cfg.network != BtcNetwork::Mainnet);
    rpc->connect(NetService(conf.host, conf.port), conf.userpass());

    DashRpcCoinBackend::Options bopt;
    bopt.expect_chain    = (cfg.network == BtcNetwork::Regtest) ? "regtest"
                         : (cfg.network == BtcNetwork::Devnet)  ? "devnet" : "main";
    bopt.expect_genesis  = (cfg.network == BtcNetwork::Regtest) ? kDashRegtestGenesisHex : "";
    bopt.oracle_patience = std::chrono::milliseconds(oracle_patience_ms);
    auto backend = std::make_shared<DashRpcCoinBackend>(rpc, bopt);
    if (!backend->wait_ready(std::chrono::seconds(30))) { teardown_io(); return 5; }
    backend->refresh_template();   // warm the cache so block_reward answers at once

    // ── the v37 node: store (D12) → open() (F2) → ★ reseed → start() ─────────
    std::unique_ptr<FileSettleStore> store;
    try {
        std::filesystem::create_directories(cfg.resolved_settle_db_path());
        store = std::make_unique<FileSettleStore>(cfg.resolved_settle_db_path());
    } catch (const std::exception& e) {
        std::fprintf(stderr, "settle store refused: %s (torn image? F2 fail-closed)\n", e.what());
        teardown_io();
        return 6;
    }
    ISettleStore& store_ref = *store;   // the node owns it from here; lifetime == node's
    XbtcNode node(cfg, std::move(store), backend, p2pkh_pay_of());
    if (!node.open()) { std::fprintf(stderr, "open() refused (torn store or mainnet fence)\n"); teardown_io(); return 6; }

    BlockEventDriver bed(node, store_ref, cfg.lane_chain);
    BlockEventDriver::BootReport boot;
    try {
        boot = bed.reseed_after_open();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "pending-FOUND sidecar refused: %s (torn image? F2 fail-closed)\n", e.what());
        teardown_io();
        return 6;
    }
    if (!node.start()) { std::fprintf(stderr, "start() failed (engine/AddLane)\n"); teardown_io(); return 7; }
    {
        std::lock_guard<std::mutex> g(bed.mutex());
        LOG_INFO << "[v37-dash] boot: ledger_seq=" << node.ledger().ledger_seq()
                 << " pending=" << bed.pending_count_locked()
                 << " owed_digest=" << hex32(node.ledger().owed_digest())
                 << " reseeded=" << boot.reseeded << " stale=" << boot.stale_dropped
                 << " unrecoverable=" << boot.unrecoverable;   // A8 compares this triple with the stop: line
    }

    // ── A2 CONSUMER: the carrier-relay p2p layer (cross-node share ingestion) ─
    // The gap the Phase-B single-node run proved: no --peer, no cross-node
    // ingestion. This stands up the W3 carrier relay on a real socket transport
    // so a peer's carriers are decoded, W2-admitted, and ACCOUNTED in THIS node's
    // engine (node.engine()). NON-CONSENSUS: every append rides
    // CarrierRelay -> CarrierIngest -> V37Engine, never src/sharechain/v37 canon.
    //
    // WIRED HERE = BOTH directions (Track A2 step (b)):
    //   RECEIVE: a carrier arriving over --peer is decoded, gated by the W3-B5
    //     frozen-wire POLICY (tag cap / descriptor validity), W2-admitted, and
    //     accounted in THIS node's engine, its prev_block_hash resolved against
    //     the LIVE dashd via LiveMainchainIndex (carrier_index.hpp: the real
    //     IMainchainIndex — live dashd, context horizon, bounded Unknown retry,
    //     per-hash cache).
    //   SEND (formerly deferred): EVERY own stratum win — share arm AND block
    //     arm — reaches CarrierSendQueue through DASHWorkSource::set_mint_share_fn
    //     (the H-SHARE seam); its worker resolves the REAL parent through the
    //     SAME carrier_index, grinds, admits locally and floods the FROZEN
    //     CarrierWire frame (W3-B5) under the MINER's payout identity — so a
    //     remote node's real index resolves and accounts it.
    // HONEST BOUNDARY: the minted work is still the SYNTHETIC RDWR PoW envelope,
    // not a real DASH X11 share; the real WIRE / real INDEX / real IDENTITY /
    // real cross-node FLOW are what step (b) makes live. Real share-format PoW
    // is S-1+ (a wire version bump with its own goldens).
    // The synthetic in-memory index model (the W2/W3 KAT) stays reachable behind
    // --carrier-synthetic-index N for a self-contained loopback drill.
    std::unique_ptr<MemShareTracker>        carrier_tracker;
    wire_freeze::PolicyStats                carrier_policy_stats;   // W3-B5 gate counters (atomic); outlives carrier_relay
    std::unique_ptr<IMainchainIndex>        carrier_index;
    LiveMainchainIndex*                     live_index = nullptr;   // typed view for observe_tip()/invalidate()/stats(); owned by carrier_index
    std::unique_ptr<CarrierIngest>          carrier_ingest;
    std::unique_ptr<CarrierPeerNode>        carrier_net;
    std::unique_ptr<CarrierRelay>           carrier_relay;
    std::unique_ptr<CarrierSendQueue>       carrier_send;   // declared AFTER carrier_index/carrier_relay: destroyed FIRST (it references both)
    // Inbound telemetry (never consensus): what the peer path did with each
    // frame. Atomic: one reader thread per peer drives set_inbound.
    struct InboundStats {
        std::atomic<std::uint64_t> frames{0}, admitted{0}, echo{0}, wire_rejected{0}, policy_rejected{0}, admit_rejected{0};
    } carrier_inbound;
    // FALLBACK identity ONLY: used for a BLOCK win whose miner has no payout
    // script (foreign/malformed username -> empty script). Every share carries
    // the miner's OWN identity (canonicalize_script(payout_script)); a share
    // without one is declined, not credited to the pool. identity ==
    // descriptor.identity_key() (W3-MUST holds on wire).
    ::v37::PayoutDescriptor pool_desc;
    {
        ::v37::ScriptRef r;
        r.kind = ::v37::ScriptKind::P2PKH;
        r.payload.assign(20, 0xB0);            // fixed pool-payout placeholder
        pool_desc.pay = r;
    }
    if (!p2p_bind.empty() || !peers.empty()) {
        // W3-B5 BOOT SELF-CHECK: the byte-KAT body (goldens A/B/C, size model,
        // decode rules, policy pins) runs BEFORE any listen/dial. A build whose
        // CarrierWire drifted from the frozen v0x01 layout must never flood
        // frames to peers.
        {
            const wire_freeze::SelfCheck sc = wire_freeze::selfcheck();
            if (!sc.ok()) {
                LOG_ERROR << "[v37-dash] W3-B5 wire-freeze SELFCHECK FAILED (" << sc.failures << "/" << sc.checks
                          << "): this build's CarrierWire drifted from the frozen v0x01 golden; refusing to peer\n" << sc.log;
                std::fprintf(stderr, "carrier wire-freeze selfcheck failed\n");
                teardown_io();
                return 10;
            }
            LOG_INFO << "[v37-dash] wire-freeze selfcheck OK [" << wire_freeze::layout_id() << "] "
                     << sc.checks << " checks; tag cap=" << wire_freeze::kTagMaxBytes;
        }
        auto snap = node.lane_snapshot();
        const std::uint64_t incarnation = snap ? snap->incarnation : 1;
        carrier_tracker = std::make_unique<MemShareTracker>();
        if (synthetic_index_tip) {
            // DEBUG: the synthetic RDWR map (mainchain_hash(h) -> h), tip fixed (the W2/W3 KAT model).
            carrier_index = std::make_unique<SyntheticMainchainIndex>(*synthetic_index_tip, /*horizon=*/64);
            LOG_WARNING << "[v37-dash] A2 carrier index = SYNTHETIC (tip=" << *synthetic_index_tip
                        << "); NOT the live chain (--carrier-synthetic-index): own wins keyed to real "
                        << "parent hashes will NOT resolve -> no local carrier is emitted for them";
        } else {
            // The REAL IMainchainIndex: prev_block_hash (internal order) -> display hex
            // (btc::display_hex_of_bytes32, the D6 pin) -> getblockheader via the backend,
            // with the seam's context horizon vs the live tip, a bounded Unknown retry,
            // and a per-hash Have cache (carrier_index.hpp header comment).
            LiveMainchainIndex::Options iopt;
            iopt.horizon          = carrier_index_horizon;
            iopt.unknown_patience = std::chrono::milliseconds(carrier_index_patience_ms);
            auto li = make_live_mainchain_index<DashRpcCoinBackend>(backend, &display_hex_of_bytes32, iopt);
            live_index    = li.get();
            carrier_index = std::move(li);
            // Prime the tip view (nullopt in IBD -> the pull fallback answers). A
            // ChainMismatch here is logged only: the height-watch owns exit 9 and
            // re-checks on its first poll.
            try {
                if (const auto t = backend->try_best_tip()) live_index->observe_tip(t->height);
            } catch (const ChainMismatch& e) {
                LOG_ERROR << "[v37-dash] carrier-index prime: chain mismatch: " << e.what() << " (height-watch exits 9)";
            }
            LOG_INFO << "[v37-dash] A2 carrier index = LIVE dashd (horizon=" << iopt.horizon
                     << " patience_ms=" << iopt.unknown_patience.count() << ")";
        }
        carrier_ingest = std::make_unique<CarrierIngest>(
            node.engine(), cfg.lane_chain, *carrier_index, *carrier_tracker, incarnation);
        carrier_net   = std::make_unique<CarrierPeerNode>();
        carrier_relay = std::make_unique<CarrierRelay>(carrier_ingest->fn(), *carrier_net);
        // W3-B5 F-1/F-2 POLICY GATE on every inbound frame (post-decode, pre-admit).
        carrier_relay->set_frame_policy(wire_freeze::make_relay_policy(&carrier_policy_stats));
        {
            // A2 SEND-SIDE: the dedicated emit worker behind the stratum mint seam.
            // *carrier_index is the SAME IMainchainIndex the receive side admits
            // against (live LiveMainchainIndex or the --carrier-synthetic-index
            // map), so origin and peers agree on horizon / byte order.
            CarrierSendQueue::Options so;
            so.fallback_desc = pool_desc;                 // block-win-without-identity fallback ONLY
            carrier_send = std::make_unique<CarrierSendQueue>(*carrier_relay, *carrier_index, cfg.lane_chain, so);
            carrier_send->set_log([](bool warn, const std::string& line) { if (warn) LOG_WARNING << line; else LOG_INFO << line; });
            carrier_send->start();
        }
        carrier_net->set_inbound([&](const std::vector<std::uint8_t>& f) {
            // decode + W3-B5 policy + W2 admit + account + relay (CarrierRelay
            // serializes; one reader thread per peer lands here).
            const CarrierRelay::Outcome o = carrier_relay->handle_inbound(f);
            carrier_inbound.frames.fetch_add(1, std::memory_order_relaxed);
            if (o.wire == WireStatus::REJECT_POLICY) {
                carrier_inbound.policy_rejected.fetch_add(1, std::memory_order_relaxed);
                LOG_WARNING << "[v37-dash] carrier inbound REJECT_POLICY (tag cap / descriptor validity), " << f.size() << " B";
            } else if (o.wire != WireStatus::OK) {
                carrier_inbound.wire_rejected.fetch_add(1, std::memory_order_relaxed);
                LOG_WARNING << "[v37-dash] carrier inbound wire-rejected status=" << static_cast<int>(o.wire) << ", " << f.size() << " B";
            } else if (o.admitted) {
                carrier_inbound.admitted.fetch_add(1, std::memory_order_relaxed);
                const auto& p0 = o.admission.pushes.front();   // the carrier push (§4.2 step 1) always leads
                LOG_INFO << "[v37-dash] carrier inbound ADMITTED tag=" << p0.tag
                         << " identity=" << hex32(p0.identity).substr(0, 16)
                         << " parent@" << p0.carrier_bin << " w_raw=" << p0.w_raw
                         << " pushes=" << o.admission.pushes.size()
                         << " relayed=" << o.relayed << " peers_reached=" << o.peers_reached;
            } else if (o.admission.carrier_status == CarrierStatus::REJECT_DEDUP) {
                // The flood-fill ECHO (W3 §5.2.1): a peer re-broadcasts what it
                // admitted to ALL its peers, including the one it came from, and
                // the relay admits always — W2's credit-once window is the
                // authority. Expected once per hop per carrier; never a fault.
                carrier_inbound.echo.fetch_add(1, std::memory_order_relaxed);
                LOG_INFO << "[v37-dash] carrier inbound echo (already accounted; W2 REJECT_DEDUP), " << f.size() << " B";
            } else {
                carrier_inbound.admit_rejected.fetch_add(1, std::memory_order_relaxed);
                LOG_WARNING << "[v37-dash] carrier inbound rejected by W2: carrier_status="
                            << static_cast<int>(o.admission.carrier_status)
                            << " (1=RMAX 2=POW/target/chain/unresolvable-parent)";
            }
        });
        if (!p2p_bind.empty()) {
            const auto c = p2p_bind.rfind(':');
            if (c == std::string::npos) { usage(); teardown_io(); return 2; }
            const std::string ph = p2p_bind.substr(0, c);
            const std::uint16_t pp = static_cast<std::uint16_t>(std::stoi(p2p_bind.substr(c + 1)));
            if (!carrier_net->listen(ph, pp)) {
                std::fprintf(stderr, "carrier p2p bind %s failed\n", p2p_bind.c_str());
                teardown_io();
                return 8;
            }
            LOG_INFO << "[v37-dash] carrier-relay listening on " << ph << ":" << carrier_net->listen_port();
        }
        for (const auto& p : peers) {
            const auto c = p.rfind(':');
            if (c == std::string::npos) { LOG_ERROR << "[v37-dash] bad --peer " << p; continue; }
            const std::string ph = p.substr(0, c);
            const std::uint16_t pp = static_cast<std::uint16_t>(std::stoi(p.substr(c + 1)));
            const bool up = carrier_net->add_peer(ph, pp);
            LOG_INFO << "[v37-dash] carrier-relay peer " << p << (up ? " connected" : " UNREACHABLE");
        }
        LOG_INFO << "[v37-dash] A2 carrier-relay up: peers=" << carrier_net->n_peers();
    }

    // ── 2f: stratum front-end on the v36 DASH work source ────────────────────
    dash::coin::NodeCoinState coin_state;   // EMPTY on purpose: no embedded arm; dashd is the template source
    std::function<dash::coin::DashWorkData()> dashd_fallback = [rpc] { return rpc->getwork(); };

    // ★ D8 + D10: real bytes → H_b FROM THE BLOCK → register (sidecar + FOUND
    // write-ahead, W6 §5.2) → submit the real hex. XbtcNode's own placeholder
    // submit is refused by the backend (armed=false) so exactly one real
    // submitblock fires per won block.
    dash::stratum::DASHWorkSource::SubmitBlockFn submit_fn =
        [&](const std::vector<unsigned char>& b, uint32_t wd_height /*template height — NOT the block's*/,
            bool v36_height_race) -> bool {
            if (b.size() < 80) { LOG_ERROR << "[v37-dash] submit_fn: short block (" << b.size() << " bytes)"; return false; }
            const std::string bidh   = dash::crypto::hash_x11(b.data(), 80).GetHex();   // header-only X11 == DASH block hash (hash_x11.hpp:44)
            const std::string parent = display_hex_of_internal(b.data() + 4);          // hashPrevBlock, header[4..36)
            const std::string hex    = HexStr(b);

            std::optional<std::uint64_t> hb;
            if (const auto ph = backend->height_of(parent)) hb = *ph + 1;             // H_b = height(parent) + 1
            if (hb && *hb != wd_height)
                LOG_WARNING << "[v37-dash] height race: block " << bidh << " is at " << *hb
                            << " (parent " << parent << " @" << (*hb - 1) << "), template said " << wd_height
                            << (v36_height_race ? " [v36 HeightRace]" : "");
            if (!hb)
                LOG_WARNING << "[v37-dash] parent " << parent << " of " << bidh
                            << " unknown to dashd at win time — registering after the submit";

            BlockEventDriver::RegisterResult reg;
            std::uint64_t reg_h = 0;
            auto try_register = [&](std::uint64_t h, std::uint64_t conf) {
                reg = bed.on_block_found(bidh, h, conf);
                if (reg.registered) reg_h = h;
                else LOG_ERROR << "[v37-dash] register " << bidh << " @" << h << " failed: " << reg.reason;
            };
            if (hb) try_register(*hb, 0);                                              // FOUND durable BEFORE announce

            const SubmitResult r = backend->submit_block(hex);
            if (!r.accepted) LOG_ERROR << "[v37-dash] block " << bidh << " NOT accepted: " << r.reason;

            if (!reg.registered && r.accepted) {                                       // fallback: dashd now has it
                if (const auto h = backend->height_of(bidh)) try_register(*h, 1);
                else LOG_ERROR << "[v37-dash] accepted block " << bidh << " has no header on dashd yet";
            }
            if (!reg.registered)
                LOG_ERROR << "[v37-dash] UNREGISTERED block " << bidh << " accepted=" << r.accepted
                          << " — never registered at the template height (" << wd_height
                          << ") and never at 0; operator: re-register by hand once H_b is known";
            else
                LOG_INFO << "[v37-dash] FOUND " << bidh << " h=" << reg_h << " accepted=" << r.accepted;

            // A2 SEND-SIDE: NOT here. The won block is ALSO a share: the v36 work source
            // calls mint_solved_share(won_block=true) right after this returns
            // (work_source.cpp:2885), which reaches CarrierSendQueue via set_mint_share_fn
            // below — the single emission point for every own win. Emitting here too would
            // mint + flood the block win twice (W2 dedup would reject the echo, wasted grind).
            return r.accepted;
        };

    auto ws = std::make_shared<dash::stratum::DASHWorkSource>(
        coin_state, dashd_fallback, submit_fn, core::stratum::StratumConfig{},
        /*is_testnet=*/cfg.network != BtcNetwork::Mainnet);                            // main_dash.cpp:3503-3505
    {
        // #961 cross-lane door-reject: DASH regtest reuses the testnet address
        // bytes (y…/8…), so acceptance rides the testnet flag with regtest=false
        // exactly as main_dash.cpp:3516-3521 does.
        const auto acc = dash::address_acceptance(/*testnet=*/cfg.network != BtcNetwork::Mainnet, /*regtest=*/false);
        ws->set_payout_acceptance(acc.p2pkh_versions, acc.p2sh_versions, acc.bech32_hrps);
    }
    ws->set_on_found_block_fn([](uint32_t h, const uint256& bh, const std::string& miner, bool reached) {
        LOG_INFO << "[v37-dash] v36-found " << bh.GetHex() << " template-h~=" << h << " by " << miner
                 << (reached ? " (reached network)" : " (NOT delivered)");   // telemetry only; registration is in submit_fn
    });
    // ── A2 SEND-SIDE: every own stratum win (share arm AND block arm) -> carrier ──
    // H-SHARE seam (work_source.hpp:188 MintShareFn; fires from mint_solved_share on both
    // arms, work_source.cpp:2885/:2896). submit() is O(1) on the stratum io thread; the
    // resolve/grind/admit/flood run on the CarrierSendQueue worker (S-3).
    if (carrier_send) {
        ws->set_mint_share_fn(
            [send = carrier_send.get()](const dash::stratum::DASHWorkSource::MintShareInputs& in) -> uint256 {
                const std::string h16 = in.pow_hash.GetHex().substr(0, 16);
                auto req = own_win_request_of_header(
                    in.header_bytes, in.payout_script, in.won_block,
                    (in.won_block ? "win:" : "share:") + h16);
                if (!req) { LOG_WARNING << "[v37-dash] carrier: short header for " << h16; return uint256(); }
                (void)send->submit(std::move(*req));
                // DEFERRED BY DESIGN (S-3): the worker mints/admits/floods and logs the outcome;
                // null here = the work source's own "accepted (mint deferred/declined)" line
                // (work_source.cpp:2685), which is exact.
                return uint256();
            });
    }
    rpc->set_on_reconnect([ws] { ws->invalidate_template_cache("reconnect"); });

    const auto colon = stratum_bind.rfind(':');
    if (colon == std::string::npos) { usage(); teardown_io(); return 2; }
    const std::string host = stratum_bind.substr(0, colon);
    const uint16_t    port = static_cast<uint16_t>(std::stoi(stratum_bind.substr(colon + 1)));
    core::StratumServer stratum(ioc, host, port, ws);
    if (!stratum.start()) { std::fprintf(stderr, "stratum bind %s failed\n", stratum_bind.c_str()); teardown_io(); return 8; }
    LOG_INFO << "[v37-dash] stratum listening on " << stratum_bind << "; dashd " << conf.host << ":" << conf.port
             << "; d_conf=" << cfg.d_conf << "; store=" << cfg.resolved_settle_db_path();

    // ── 2g: the height-watch (F1 tick) + D11 reorg re-check + the fence ──────
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    int exit_code = 0;
    std::string   last_hash;
    std::uint64_t last_height = 0;
    const CanonProbeFn probe = [&](std::uint64_t h, const std::string& bid) { return backend->canonicality(h, bid); };
    while (!g_stop) {
        std::optional<CoinTip> tip;
        try {
            tip = backend->try_best_tip();
        } catch (const ChainMismatch& e) {
            LOG_ERROR << "[v37-dash] FATAL chain mismatch: " << e.what() << " — exiting, never following it";
            exit_code = 9;
            break;
        }
        if (tip && live_index) live_index->observe_tip(tip->height);   // A2: the reader thread never asks getblockchaininfo
        if (tip && tip->hash != last_hash) {
            try {
                // D11: a lowered tip, or a previous tip that left the active chain,
                // means blocks were dropped — re-check the pending FOUNDs NOW rather
                // than at maturity. Unknown (dashd not answering) = wait.
                const bool lowered = !last_hash.empty() && tip->height <= last_height;
                bool forked = false;
                if (!last_hash.empty() && !lowered) {
                    if (const auto on = backend->on_active_chain(last_hash)) forked = !*on;
                }
                if (lowered || forked) {
                    if (live_index) live_index->invalidate();          // A2: active-chain status of cached headers may have flipped
                    const std::size_t n = bed.recheck_pending(probe);
                    LOG_WARNING << "[v37-dash] reorg signal (" << (lowered ? "tip lowered" : "previous tip off the active chain")
                                << ") at " << tip->height << ": re-checked pending FOUNDs, ORPHAN " << n;
                }
                const std::vector<FinalizeStep> steps = bed.on_tip(*tip);
                last_hash   = tip->hash;
                last_height = tip->height;
                for (const auto& s : steps)
                    LOG_INFO << "[v37-dash] FINALIZE " << s.bid << " h=" << s.coin_height << " bin=" << s.bin_height;
                backend->refresh_template();          // new prev → new template (stale-payee guard)
                ws->invalidate_template_cache("tip");
                ws->bump_work_generation();
                stratum.notify_all();
            } catch (const OracleUnavailable& e) {
                LOG_ERROR << "[v37-dash] height-watch deferred: " << e.what();   // re-driven next tick
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(poll_ms));
    }

    // ── stop: network first, then engine (btc_node.hpp:37-38) ────────────────
    stratum.stop();                                   // no new submits
    if (carrier_send) carrier_send->stop();           // worker may be mid-flood: BEFORE net stop, BEFORE engine drain
    if (carrier_net) {
        carrier_net->stop();   // stop inbound carriers BEFORE the engine drains
        if (carrier_ingest) {
            const auto ss = carrier_send ? carrier_send->stats() : CarrierSendStats{};
            LOG_INFO << "[v37-dash] carrier-relay stop: pushes_forwarded=" << carrier_ingest->pushes_forwarded()
                     << " inbound_frames=" << carrier_inbound.frames.load()
                     << " inbound_admitted=" << carrier_inbound.admitted.load()
                     << " inbound_echo=" << carrier_inbound.echo.load()
                     << " inbound_wire_rejected=" << carrier_inbound.wire_rejected.load()
                     << " inbound_admit_rejected=" << carrier_inbound.admit_rejected.load()
                     << " own_carriers_emitted=" << ss.admitted << " block_winners=" << ss.block_winners
                     << " relayed=" << ss.relayed << " deferred_relay=" << ss.deferred_relay
                     << " unresolved_parent=" << ss.unresolved_parent << " no_identity=" << ss.no_identity
                     << " shed=" << ss.shed_shares << " abandoned=" << ss.abandoned_at_stop
                     << " policy_rejected=" << carrier_policy_stats.frames_rejected.load()
                     << " policy_receipts_dropped=" << carrier_policy_stats.receipts_dropped.load();
        }
        if (live_index) {
            const auto ist = live_index->stats();
            LOG_INFO << "[v37-dash] carrier-index stop: probes=" << ist.probes << " cache_hits=" << ist.cache_hits
                     << " resolved=" << ist.resolved << " missing=" << ist.missing << " inactive=" << ist.inactive
                     << " beyond_horizon=" << ist.beyond_horizon << " future=" << ist.future
                     << " unknown_retries=" << ist.unknown_retries << " unknown_exhausted=" << ist.unknown_exhausted
                     << " tip_pulls=" << ist.tip_pulls;
        }
        // The cross-node observable: which payout identities THIS node's lane
        // accounts (a peer's miner shows up here under its own identity key).
        if (const auto s = node.lane_snapshot()) {
            LOG_INFO << "[v37-dash] lane stop: raw_total=" << static_cast<unsigned long long>(s->raw_total)
                     << " next_pos=" << s->next_pos
                     << " identities=" << (s->identities ? s->identities->size() : 0);
            if (s->identities)
                for (const auto& [mid, ent] : s->identities->entries()) {
                    const auto it = s->payout.find(mid);
                    LOG_INFO << "[v37-dash] lane identity " << hex32(ent.key).substr(0, 16)
                             << " payout=" << ((it != s->payout.end() && !(it->second == ::v37::U256{})) ? "nonzero" : "zero");
                }
        }
    }
    {
        std::lock_guard<std::mutex> g(bed.mutex());
        node.stop();
        LOG_INFO << "[v37-dash] stop: ledger_seq=" << node.ledger().ledger_seq()
                 << " pending=" << bed.pending_count_locked()
                 << " owed_digest=" << hex32(node.ledger().owed_digest());   // A8 compares with the next boot: line
    }
    teardown_io();
    const auto st = backend->stats();
    LOG_INFO << "[v37-dash] exit " << exit_code << ": submits=" << st.submits << "/" << st.submits_accepted
             << " transport_fail=" << st.transport_failures << " oracle_unavail=" << st.oracle_unavailable
             << " withheld_ibd=" << st.withheld_ibd;
    return exit_code;
}
