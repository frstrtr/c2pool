// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/node/xmr_native_node.hpp
//
// M0: THE NODE. The thirteen wave-0/wave-1 components, constructed, wired and
// given the threads they were written against.
//
//   C1b LevinLink ─┐
//   C1c XmrPeerPool ──(io thread)──> VerifyInbound ──(verify thread)──>
//         │                              ChainBoot ──> C2c ChainIndex
//         │                                               │ RandomX (C2c PowGate
//         │                                               │  -> LightVerifier)
//         │                              TxSinkLoop ──(pool thread)──> C3 RelayedTxPool
//         │                                                               │
//         ├── IChainServing  <── C2c (the state_normal obligation)         │
//         ├── IChainFetcher  <── SyncDriver (verify thread) ───────────────┘
//         └── IBroadcastPort ──> C5 LevinBlockRelay
//                                    ▲
//   C4 NativeMinerDataSource (C2c IChainView + C3 ITxpoolSnapshot/ITxBlobSource)
//   C4 MonerodMinerDataSource (RPC, parity/backup arm only)
//        └── C4 ArmResolver ──> C6 ParityOracle (native tip vs monerod tip)
//
// WHAT THIS FILE ADDS THAT NO COMPONENT DID. Four things, and each of them is a
// gap that only shows up when the parts are put together:
//
//   1. THE THREADS. Three component banners demand threads none of them
//      creates; xmr_worker_loops.hpp builds them and this file hands them out.
//      The io thread does sockets and codec, the verify thread does consensus
//      and RandomX, the pool thread does transaction decode and range proofs.
//   2. THE FIRST QUESTION. Nothing in the tree sends NOTIFY_REQUEST_CHAIN
//      (xmr_sync_driver.hpp), and nothing seeds row zero (xmr_chain_boot.hpp).
//   3. THE TWO NETS. A Monero node needs two answers to "which network": the
//      WIRE identity (network id, genesis id, default port -- levin::XmrNet) and
//      the CONSENSUS rules (the hard-fork table -- native::XmrNet). They are
//      separate enums because they are separate facts, and regtest is the case
//      that proves it: monerod's fakechain carries the MAINNET network id and
//      the MAINNET genesis block while running a hard-fork table that starts at
//      v16 from height 1. `resolve_nets()` below is the one place that mapping
//      lives.
//   4. THE ADMISSIONS. The status line reports what a component would otherwise
//      only know internally -- the RandomX witness, the queue depths, the peers
//      that are handshaked but silent, the RPC call count next to the block
//      count -- because the X9 bring-up's lesson was that "connected and
//      receiving nothing" must be answerable without a debugger.
//
// WHAT M3 CONNECTED. C5's relay was CONSTRUCTED and its 2009 responder armed
// from M0 on, but nothing called relay(): a found block comes from the
// stratum/settlement path, which is the consumer's. M3 gave that path two
// seams here -- block_relay(), so the found block can go out over levin, and
// drain_mainchain_events(), so the tip this node verified for itself can drive
// the pool's settlement finality. With both bound and --arm-order p2p-first,
// the find path makes no monerod call at all. C4's arms became the template
// source in M2.
//
// The txpool IS now driven: M1 added the P-POOL seam (txpool_parity_sample()),
// the harness injection port (inject_relayed()), and publish_tx_gate_() -- the
// C2 -> C3 sync gate M0 left unwired, without which the pool refused every
// transaction that ever reached it. Each remaining item is wired to its seam
// and left unexercised ON PURPOSE, so that the milestone that owns it has
// something to prove rather than something to discover.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree is a WORK SOURCE for the pool, not part of the v37 share-chain record;
// nothing here activates v37 consensus and src/sharechain/v37 is not touched.
//
// Header-only. STL plus boost::asio; RandomX only when
// XMR_NATIVE_NODE_HAVE_RANDOMX is defined (the CMake option XMR_BUILD_RANDOMX).
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <fstream>
#include <functional>
#include <iterator>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio.hpp>

#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/chain/xmr_output_set.hpp"
#include "impl/xmr/native/chain/xmr_pow_gate.hpp"
#include "impl/xmr/native/node/xmr_anchor_confirm.hpp"
#include "impl/xmr/native/node/xmr_chain_boot.hpp"
#include "impl/xmr/native/node/xmr_chain_snapshot_store.hpp"
#include "impl/xmr/native/node/xmr_genesis_blob.hpp"
#include "impl/xmr/native/node/xmr_monerod_http.hpp"
#include "impl/xmr/native/node/xmr_sync_driver.hpp"
#include "impl/xmr/native/node/xmr_worker_loops.hpp"
#include "impl/xmr/native/p2p/chain_seeds.hpp"
#include "impl/xmr/native/p2p/xmr_peer_pool.hpp"
#include "impl/xmr/native/parity/xmr_parity_oracle.hpp"
#include "impl/xmr/native/parity/xmr_parity_report.hpp"
#include "impl/xmr/native/parity/xmr_soak_driver.hpp"
#include "impl/xmr/native/parity/xmr_txpool_parity.hpp"
#include "impl/xmr/native/relay/xmr_block_relay.hpp"
#include "impl/xmr/native/template/xmr_monerod_miner_data.hpp"
#include "impl/xmr/native/template/xmr_native_miner_data.hpp"
#include "impl/xmr/native/template/xmr_template_arm.hpp"
#include "impl/xmr/native/txpool/xmr_relayed_txpool.hpp"
#include "impl/xmr/native/txpool/xmr_tx_decode.hpp"           // decode_relayed_tx, DecodedTx
#include "impl/xmr/native/inject/xmr_operator_inject_pool.hpp"  // OperatorInjectPool (M-inject)
#include "impl/xmr/native/inject/xmr_inject_rate_limiter.hpp"   // InjectRateLimiter
#include "impl/xmr/native/inject/xmr_inject_sandbox.hpp"        // InjectSandbox

#if defined(XMR_NATIVE_NODE_HAVE_RANDOMX)
#include "impl/xmr/pow/randomx_verify.hpp"
#endif

namespace c2pool::xmr::native::rt {

namespace levinns = ::c2pool::xmr::native::levin;

// ---------------------------------------------------------------------------
// Which network, twice.
//
// FAKECHAIN (monerod --regtest) is the case that makes the two enums necessary
// rather than redundant: cryptonote::get_config(FAKECHAIN) returns the MAINNET
// config, so a regtest daemon speaks the mainnet network id, listens with the
// mainnet genesis block at height 0, and would drop a peer whose locator
// terminated in anything else -- while its hard-fork table is
// { v16 @ height 1 }, which is neither mainnet's nor any other network's.
// Verified against a live monerod 0.18.5.1 fakechain: get_block(0).hash ==
// 418015bb…32e3 (the mainnet genesis id) and hard_fork_info reports version 16
// at earliest_height 1.
// ---------------------------------------------------------------------------
enum class NativeNet : std::uint8_t { Mainnet = 0, Testnet = 1, Stagenet = 2, Regtest = 3 };

inline const char* to_string(NativeNet n) noexcept {
    switch (n) {
        case NativeNet::Mainnet:  return "mainnet";
        case NativeNet::Testnet:  return "testnet";
        case NativeNet::Stagenet: return "stagenet";
        case NativeNet::Regtest:  return "regtest";
    }
    return "?";
}

inline bool parse_native_net(const std::string& s, NativeNet& out) noexcept {
    if (s == "mainnet")  { out = NativeNet::Mainnet;  return true; }
    if (s == "testnet")  { out = NativeNet::Testnet;  return true; }
    if (s == "stagenet") { out = NativeNet::Stagenet; return true; }
    if (s == "regtest" || s == "fakechain") { out = NativeNet::Regtest; return true; }
    return false;
}

struct NetPair {
    levinns::XmrNet wire;        // network id + genesis id + default p2p port
    XmrNet          consensus;   // hard-fork table
};

inline NetPair resolve_nets(NativeNet n) noexcept {
    switch (n) {
        case NativeNet::Testnet:  return {levinns::XmrNet::Testnet,  XmrNet::Testnet};
        case NativeNet::Stagenet: return {levinns::XmrNet::Stagenet, XmrNet::Stagenet};
        case NativeNet::Regtest:  return {levinns::XmrNet::Mainnet,  XmrNet::Regtest};
        case NativeNet::Mainnet:  break;
    }
    return {levinns::XmrNet::Mainnet, XmrNet::Mainnet};
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
struct NativeNodeConfig {
    NativeNet                net = NativeNet::Stagenet;
    std::vector<std::string> connect;              // operator-pinned "ip:port" peers
    // Source address for outbound levin connections; see XmrPeerPool::Config.
    // On the loopback regtest rig this is what keeps monerod's one-connection-
    // per-remote-IP rule from refusing us before the handshake.
    std::string              p2p_bind_ip;
    bool                     use_seeds = false;    // M0 runs against pinned peers
    std::uint64_t            peer_id   = 0;        // 0 => random, never 0 on the wire

    BootMode                 boot = BootMode::Genesis;
    std::string              anchor_path;          // BootMode::Anchor; "" = embedded
    // Format-2 O-backfill: a ChainOutputSet::serialize() snapshot re-derived to
    // the anchor's committed output/spent roots. When set (and the anchor is a
    // format-2 bundle) the node seeds the historical set so pre-anchor rings
    // resolve; empty leaves pre-anchor rings RingUnresolved (today's behaviour).
    std::string              output_set_path;

    // GATE 4's bound. An anchor is confirmed against the live network before
    // this node serves anything, and that confirm is not allowed to be
    // unbounded: at most `peers` distinct handshaked peers are asked, each gets
    // `per_peer_ms`, and the whole gate expires after `timeout_ms` -- as a
    // REFUSAL, never as a shrug. Defaults are in the struct; the node tool and
    // the pool consumer expose them so an operator on a slow link can widen the
    // window without being able to turn the gate off.
    AnchorConfirmConfig      anchor_confirm{};

    // ── RESUME WITHOUT RE-IBD ────────────────────────────────────────────────
    // Where the chain index's snapshot lives. Empty (the default, and what
    // every run before this shipped) means no persistence: a restart re-walks
    // the chain from the anchor, which is minutes on a fresh bundle and hours
    // of somebody else's bandwidth on a pool that has been up for a month.
    //
    // When set, the file is READ after gate 4 has confirmed the anchor and
    // WRITTEN on a clean stop and every `snapshot_every_s`. It is not a second
    // trust root: node/xmr_chain_snapshot_store.hpp binds the image to the
    // anchor identity the network just vouched for, and any failure -- absent,
    // corrupt, foreign network, different anchor -- falls back to the anchor
    // boot rather than to a weaker check. See that header for why the binding
    // is an envelope rather than a flag.
    std::string              snapshot_path;
    // Periodic save cadence in seconds. 0 = only on a clean stop, which loses
    // the session's progress to a kill -9; 300 is the shipped compromise.
    std::uint64_t            snapshot_every_s = 300;
    // COLD-BOOT-2: ChainIndexOptions::consumer_window (the catch-up download is
    // paced by the settlement's booked frontier). 0 = off.
    std::uint64_t            consumer_window = 0;

    // A build without librandomx cannot check proof of work: the gate answers
    // Skipped, and the index connects blocks it never verified. That is a
    // legitimate thing to want (a build leg that cannot link RandomX, a
    // topology test) and an illegitimate thing to do by accident, so it is
    // opt-in and the status line says so. With RandomX compiled in this flag
    // does nothing: the verifier is always used.
    bool                     allow_unverified_pow = false;

    // The parity / backup arm. Empty host = no daemon at all, which C6 scores as
    // VOID samples rather than as agreement.
    std::string              monerod_rpc_host;
    std::uint16_t            monerod_rpc_port = 0;
    bool                     parity           = true;
    std::string              parity_ledger_path;
    std::string              c2pool_commit;        // one of the four graduation keys

    // M4's NEGATIVE CONTROL, disarmed unless a field is named.
    //
    // A harness that has never been seen to refuse is not a gate, so the M4
    // soak can perturb one required EQUALITY field of the NATIVE tip
    // observation by one unit (or withhold it) and watch the real comparator
    // fail the sample, the real streak reset, and graduation be refused. It
    // wraps the native tip observer only while armed; see
    // parity::PerturbingTipObserver. One consequence is deliberate and is
    // stated here rather than left to be discovered: while wrapped, the
    // oracle's dynamic_cast to ChainViewTipObserver no longer resolves, so the
    // PenaltyZone height class is not claimed during an injection run. An
    // injection run is a refusal experiment, not a coverage one.
    parity::TipFaultInjection tip_fault{};

    // THE BACKLOG REBUILD TRIGGER, in seconds. Non-zero (the default now, 3 s)
    // means the served template is rebuilt when the native POOL moves, not only
    // when the parent tip moves, at most once per this many seconds. 0 is the
    // legacy TIP-ONLY posture (what M0 through M2 shipped).
    //
    // Tip-only is byte-stable for miners already grinding a job, but it is also
    // why a native arm collects almost no fees, and it violates the good-citizen
    // hard rule: a block CONSUMES the pool, so at the instant of the tip move the
    // pool is empty; everything that arrives during the block interval would wait
    // for the NEXT tip move, by which time somebody else has mined it. The
    // template served for the whole interval would be the empty one built at its
    // start. The good-citizen rule requires that txs arriving mid-interval enter
    // the served template, so the default is on.
    //
    // A non-zero value admits the pool's backlog_version as a second rebuild
    // trigger, RATE-LIMITED to at most one admission per this many seconds --
    // which is the same bargain monerod's own get_block_template callers strike.
    // The cost is a rebuild that restamps the header timestamp under miners
    // mid-grind and shortens the retained job ring; the retained-epoch ring
    // absorbs it (in-flight jobs keep resolving from older generations).
    std::uint64_t            backlog_refresh_s = 3;

    TemplateArm              serve_arm = TemplateArm::Native;
    // Serve from the OTHER arm when the configured one is not ready. ON is the
    // production posture (a pool that stops serving templates stops paying its
    // miners). OFF is what makes a native-only claim falsifiable: with no
    // second answer available, "the template path made no daemon call" cannot
    // be satisfied by a quiet fallback.
    bool                     template_fallback = true;
    // R-ARMORDER, ruled SWITCHABLE: DaemonFirst stays the default (monerod
    // validates the block for free before our P2P identity is behind it, which
    // is what a daemon-assisted bring-up wants); the consumer sets P2pOnly for
    // --arm-order p2p-first, where the daemon is not consulted at all.
    ArmOrder                 relay_order = ArmOrder::DaemonFirst;

    // D-14, c2pool#1551: what the fork choice does at EQUAL cumulative
    // difficulty at the same height. PreferOwn adopts our own block (the
    // default, and the "what we build on" lever of the prefer-own rule);
    // FirstSeen is monerod's rule and is what a parity run compares against.
    // The consumer drives this from the SAME --same-height-tiebreak flag the
    // settlement accounting reads, so the two can never disagree.
    TieBreak                 fork_tie = TieBreak::PreferOwn;

    // The own-fork liveness guard (ChainIndexOptions::own_fork_bound_ms): how
    // long an own-mined tip may go unadopted by every peer before the node
    // abandons it and follows the peers' chain. 0 disables.
    std::uint64_t            own_fork_bound_ms = 240'000;

    // READ-ONLY PROBE against somebody else's daemon: handshake, TIMED_SYNC,
    // one NOTIFY_REQUEST_CHAIN, and not one block requested. See
    // SyncDriverConfig::probe_only.
    //
    // ONE EXCEPTION, added with gate 4 and named here rather than discovered:
    // on `boot == Anchor` a probe DOES request exactly one block -- the anchor
    // itself -- because the network confirm is not optional. Making the probe
    // the one mode that skips gate 4 would put a "trust this anchor without
    // asking" switch on the command line, which is the hole the gate exists to
    // close. It is still read-only in the sense the probe means: one 2003 out,
    // one 2004 in, nothing relayed, nothing served.
    bool                     probe_only = false;

    std::uint64_t            driver_tick_ms = 500;
    std::size_t              verify_queue   = 4096;
    std::size_t              txpool_queue   = 2048;

    // OR-C2-8: on a private chain with one pinned peer the cohort test cannot
    // distinguish "at the tip" from "alone", so the publication gate is set
    // rather than inferred -- and the status line says it was forced.
    bool                     force_synced = false;

    // OPERATOR TX-INJECTION (2026-09-19 ruling), default OFF -- arming mirrors
    // Dash's --embedded-tx-inject. When on, submit_operator_inject() admits an
    // operator's ALREADY-SIGNED tx into the C3 pool AND records it in the
    // OperatorInjectPool, so the served template places it FIRST at highest
    // priority (mined even at 0 fee) with first claim on the block-weight cap,
    // and the good-citizen take-all tail fills the rest up to the cap. OFF makes
    // the served template byte-identical to the plain good-citizen path.
    bool                     operator_inject = false;
    // Default TTL (in blocks) applied to an inject submitted with expiry_height
    // == 0, so a pinned 0-fee inject cannot outlive the operator's intent: it is
    // dropped (and unpinned) once the tip passes tip_at_submit + this many
    // blocks. A finite default is required precisely because a pinned inject
    // bypasses C3's age eviction.
    std::uint64_t            operator_inject_ttl_blocks = 720;
    // #1680 lever. Cap on outstanding solicited-reply DoS credits (DosConfig::
    // max_solicited_credits). Default 8 = fix #1 armed: a 2008 answering our own
    // 2009 spends a credit instead of a block token. Set to 0 to DISABLE fix #1
    // (the pre-#1680 behaviour) while leaving fix #2 -- the GET_OBJECTS fallback
    // for a stranded park -- in place, which is exactly what the live fix-2 leg
    // needs to show a dropped missing-tx reply self-heals on its own.
    std::uint32_t            dos_solicited_credits = 8;
};

// One line per tip the node adopted: the M0 evidence record.
struct TipRecord {
    std::uint64_t height = 0;
    Hash          id{};
    Hash          prev_id{};
    U128          difficulty{};
    U128          cumulative_difficulty{};
    std::uint64_t timestamp = 0;
    std::uint64_t reward    = 0;
    std::uint64_t weight    = 0;
    bool          reorg     = false;
    std::uint64_t reorg_depth = 0;
};

struct NodeStatus {
    SyncState                    sync{};
    p2p::PoolTelemetry           pool{};
    SyncDriver::Stats            driver{};
    VerifyInbound::Stats         inbound{};
    TxSinkLoop::Stats            txsink{};
    WorkerLoop::Stats            verify_queue{};
    WorkerLoop::Stats            pool_queue{};
    ThreadWitnessPowSource::Witness randomx{};
    RandomXMode                  randomx_mode = RandomXMode::Disabled;
    ChainBoot::Stats             boot{};
    TxpoolStats                  txpool{};
    // C3's relay gate, as last published by publish_tx_gate_(). A pool that
    // holds nothing because the gate is shut and a pool that holds nothing
    // because the chain is quiet are the same picture without this flag.
    bool                         txpool_gate_open = false;
    std::uint64_t                rpc_calls = 0;
    // Failed round trips on that same transport. A parity arm that is silently
    // failing every call still reports rpc_calls climbing, so the count alone
    // cannot distinguish "the judge is answering" from "the judge is gone".
    std::uint64_t                rpc_failures = 0;
    std::string                  template_arm;
    std::string                  io_threads;
    std::string                  verify_thread;
    // GOOD-CITIZEN sensors from the native miner-data source: the backlog the
    // selector was offered, what it chose (== what the served template carries),
    // and the invariant tripwire (a non-empty pool that yielded an empty
    // selection -- must stay 0).
    std::size_t                  citizen_pool_n = 0;
    std::size_t                  citizen_chosen_n = 0;
    std::uint64_t                good_citizen_violations = 0;
    // Template dup-tx hygiene: selectable txs the template left out because
    // the chain it extends already mined them (the race, caught); own blocks
    // the index refused as invalid (a tx already mined / key image spent /
    // duplicate); own forks the liveness guard abandoned; txs the pool refused
    // at admission because the chain already carries them.
    std::uint64_t                tmpl_dropped_mined = 0;
    std::uint64_t                own_invalid_refused = 0;
    std::uint64_t                own_forks_abandoned = 0;
    std::uint64_t                pool_already_mined = 0;
};

// ---------------------------------------------------------------------------
// NativeNode
// ---------------------------------------------------------------------------
class NativeNode {
public:
    explicit NativeNode(NativeNodeConfig cfg)
        : cfg_(std::move(cfg)),
          nets_(resolve_nets(cfg_.net)),
          verify_loop_("verify", cfg_.verify_queue),
          pool_loop_("txpool", cfg_.txpool_queue),
          index_(make_index_options_(), pow_witness_or_null_()),
          boot_(index_, cfg_.boot, p2p::genesis_id(nets_.wire), nets_.consensus),
          inbound_(verify_loop_, boot_),
          outputs_(/*first_output_index=*/0),
          txpool_(make_txpool_config_()),
          tx_sink_(pool_loop_, txpool_),
          native_src_(index_, txpool_, make_template_policy_(), &txpool_),
          tick_(io_) {}

    NativeNode(const NativeNode&)            = delete;
    NativeNode& operator=(const NativeNode&) = delete;
    ~NativeNode() { stop(); }

    // -----------------------------------------------------------------------
    bool start(std::string& why) {
        why.clear();

        // --- RandomX ---------------------------------------------------------
        if (!init_pow_(why)) return false;

        // --- the trust root, when it does not come off the wire ---------------
        // The SOLO trust root: assembled here, checked by the same gate the
        // levin path uses. A node with no peers cannot ask for the genesis
        // blob, and without row 0 the index has no tip, no difficulty window
        // and therefore no template -- so this is the one thing that has to
        // happen before a peerless node can do anything at all.
        if (cfg_.boot == BootMode::LocalGenesis) {
            if (!boot_.boot_from_local_genesis(local_genesis_blob(nets_.wire), why))
                return false;
        }
        if (cfg_.boot == BootMode::Anchor) {
            // The 60 timestamps are not in the bundle by its own contract; the
            // state treats a short window as "no median", which is why an empty
            // vector is a degraded-but-honest boot rather than a wrong one.
            if (!boot_.boot_from_anchor(cfg_.anchor_path, nets_.consensus, {}, why))
                return false;
            // Gates 1..3 passed. Gate 4 -- the network confirm -- is now ARMED
            // and is settled further down, after the peer pool has peers to ask.
            // Until it settles, ChainBoot forwards nothing and serves nothing,
            // and this function does not return true.
            note_(std::string("[GATE-4] ") + anchor_boot_duty());
            note_(boot_.anchor_confirm().log_line());
        }

        index_.set_clock([] { return unix_seconds_(); });
        if (cfg_.force_synced) index_.force_synced(true);

        // Every tip the index adopts is recorded here and handed to the parity
        // oracle. This runs ON THE VERIFY THREAD (the index flushes its events
        // after releasing its own lock), which is what makes the native
        // observation the oracle takes later safe to read.
        index_.subscribe([this](const node::MainchainEvent& ev) { on_mainchain_(ev); });

        // The txpool's INPUT-consensus step resolves rings and rejects on-chain
        // double-spends against `outputs_`. Wire it before the block stream can
        // feed anything, so the very first connected block's key images land in
        // the spent set the pool consults. On a genesis / regtest chain the set
        // numbers from 0 and is complete. On a FORMAT-2 anchor boot it numbers
        // from the anchor's real rct_output_count and the honest below-anchor gap
        // applies (a ring reaching below the anchor is RingUnresolved, never
        // mis-admitted). On a FORMAT-1 anchor boot the bundle carries no
        // rct_output_count, so the real base is unknown and resolution is disabled
        // below (all rings RingUnresolved) rather than mis-numbered from 0.
        //
        // Seed the numbering base from whatever boot resolved before any block
        // feeds the set (a no-op reseat on the empty set): 0 on genesis /
        // local-genesis, the anchor's rct_output_count on an anchor boot (the
        // chain view carries it through seed_from_anchor). Leaf 0 must be
        // numbered from the right base or every post-anchor ring is misnumbered.
        outputs_.reset_base(index_.view().rct_output_count());

        // Format-2 O-backfill (ruling R1): when the operator supplies an
        // output-set snapshot AND the node anchor-booted from a format-2 bundle,
        // seed the historical amount-0 output set and the spent-key-image set so
        // a ring reaching BELOW the anchor's numbering base resolves + CLSAG
        // runs, and a below-base double-spend is caught. The snapshot is trusted
        // only insofar as it re-derives to the roots the anchor committed
        // (ChainOutputSet::seed_from_snapshot fails closed otherwise). Wired
        // BEFORE the block stream, exactly like reset_base above.
        {
            const AnchorBundle* ab = boot_.anchor();
            if (!cfg_.output_set_path.empty()) {
                if (!ab || !ab->has_output_set()) {
                    why = "--native-output-set was given but the node did not boot from a "
                          "format-2 anchor (nothing to verify the snapshot against)";
                    return false;
                }
                {
                    std::ifstream f(cfg_.output_set_path, std::ios::binary);
                    if (!f) {
                        why = "cannot open output-set snapshot '" + cfg_.output_set_path + "'";
                        return false;
                    }
                }
                // Mapped read-only and served in place (no heap copy of the
                // anchor snapshot); only post-anchor state lives in the heap.
                std::string seed_why;
                if (!outputs_.seed_from_snapshot_file(cfg_.output_set_path, *ab, seed_why)) {
                    why = "output-set snapshot rejected: " + seed_why;
                    return false;
                }
                const std::string line =
                    "[output-set] seeded from format-2 anchor snapshot: base="
                    + std::to_string(outputs_.first_output_index()) + " frontier="
                    + std::to_string(outputs_.frontier()) + " outputs="
                    + std::to_string(outputs_.output_count()) + " spent="
                    + std::to_string(outputs_.spent_count())
                    + " -- pre-anchor rings now RESOLVE";
                note_(line);
                std::fprintf(stderr, "%s\n", line.c_str());
            } else if (ab && ab->has_output_set()) {
                const std::string line =
                    "[output-set] format-2 anchor loaded WITHOUT --native-output-set: "
                    "pre-anchor rings remain RingUnresolved until O-backfill";
                note_(line);
                std::fprintf(stderr, "%s\n", line.c_str());
            } else if (cfg_.boot == BootMode::Anchor) {
                // FORMAT-1 anchor (no committed set, so no rct_output_count): the
                // real output numbering base is UNKNOWN. Numbering post-anchor
                // outputs from base=0 would misnumber an honest ring reaching
                // below the real base -- it would resolve to the WRONG post-anchor
                // output and be scored a forged ring (RingSigFail, a drop offence
                // against an honest peer). Fail closed: disable ring resolution so
                // every ring is RingUnresolved and no honest peer is mis-scored.
                // (The spent-key-image view still advances from connected blocks.)
                outputs_.disable_resolution();
                const std::string line =
                    "[output-set] format-1 anchor (no committed set): ring resolution "
                    "DISABLED -- all rings RingUnresolved (fail-closed) until O-backfill";
                note_(line);
                std::fprintf(stderr, "%s\n", line.c_str());
            }
        }

        txpool_.set_input_consensus_sources(&outputs_, &outputs_);
        // The chain's mined oracle: no path (a reorg re-admit racing the new
        // branch, a late relay) can put a tx the best chain already carries
        // back into the pool.
        txpool_.set_mined_oracle(&index_);

        index_.subscribe_txs([this](const BlockTxEvent& ev) {
            // C2 -> C3, SYNCHRONOUSLY, on the thread that moved the tip and
            // before the index returns to it. Evicting mined ids / spent key
            // images on the pool thread LATER let the template refresh race
            // it: a template built on the new tip in that window still carried
            // a tx the new tip had mined, and a share on it was a block every
            // monerod refused ("transaction already in blockchain") -- the
            // publish-arm verify, 8b2efacf at h=513. The template path also
            // filters against the chain itself (NativeMinerDataSource), so this
            // is the pool keeping itself honest, not the only guard.
            //
            // The output set is fed FIRST: the spent-key-image set must reflect
            // this block before the pool judges (or re-admits) anything against
            // it. on_block_connected also carries the block's RCT outputs when
            // the producer captured them (below-anchor history excepted); with
            // none captured it still advances key images. Both are set updates
            // under their own mutexes, and flush_events_ holds no index lock.
            if (ev.kind == BlockTxEvent::Kind::Connected) {
                outputs_.on_block_connected(ev);
                txpool_.on_block_connected(ev);
            } else {
                outputs_.on_block_disconnected(ev);
                txpool_.note_block_disconnected(ev);
            }
            // Only the re-admission of a rolled-back block's bodies (a full
            // decode + verify each) and the inject upkeep go to the pool thread.
            pool_loop_.post([this, ev] {
                if (ev.kind == BlockTxEvent::Kind::Disconnected)
                    txpool_.readmit_disconnected(ev);
                // OPERATOR INJECT upkeep on a connected block: an inject that was
                // mined leaves C3 (so it would silently stop being offered), but
                // its ledger entry and pin must go too. Forget the mined ids,
                // reap anything the new tip aged out, and refresh the C3 pin to
                // the surviving set (pin() replaces, so this also unpins).
                if (cfg_.operator_inject && ev.kind == BlockTxEvent::Kind::Connected) {
                    for (const Hash& h : ev.tx_hashes) op_injects_.forget(h);
                    op_injects_.reap_expired(ev.height);
                    txpool_.pin(operator_pin_key_(), op_injects_.live_ids());
                }
            });
        });

        // OPERATOR INJECT: hand the served template the inject ledger/order
        // source (nullptr keeps the served template byte-identical to the plain
        // good-citizen path). Wired ONCE here, before any template is served.
        native_src_.set_operator_injects(cfg_.operator_inject ? &op_injects_ : nullptr);

        verify_loop_.start();
        pool_loop_.start();

        // --- the daemon arm (parity / backup only) ---------------------------
        if (!cfg_.monerod_rpc_host.empty() && cfg_.monerod_rpc_port != 0) {
            rpc_    = std::make_unique<MonerodHttp>(cfg_.monerod_rpc_host, cfg_.monerod_rpc_port);
            // Same good-citizen backlog-refresh policy as the native arm, so a
            // fallback onto the daemon arm does not fall back onto tip-only
            // (coinbase-only-with-a-full-pool) templates.
            tmpl::MonerodArmConfig mon_cfg;
            mon_cfg.backlog_refresh_s = cfg_.backlog_refresh_s;
            mon_src_ = std::make_unique<tmpl::MonerodMinerDataSource>(*rpc_, mon_cfg);
            mon_tip_ = std::make_unique<parity::MonerodTipObserver>(*rpc_);
            // M1's P-POOL arm. Constructed whenever a daemon endpoint is, so
            // that "the probe was never armed" is impossible to confuse with
            // "the probe found nothing": without an arm txpool_parity_sample()
            // returns an UNJUDGED report that says so.
            mon_pool_ = std::make_unique<parity::MonerodTxpoolObserver>(*rpc_);
        }

        tmpl::TemplateArmConfig arm_cfg;
        arm_cfg.serve    = cfg_.serve_arm;
        arm_cfg.fallback = cfg_.template_fallback;
        arm_cfg.shadow = (cfg_.serve_arm == TemplateArm::Native)
                             ? (mon_src_ ? std::optional<TemplateArm>(TemplateArm::Monerod)
                                         : std::nullopt)
                             : std::optional<TemplateArm>(TemplateArm::Native);
        arms_ = std::make_unique<tmpl::ArmResolver>(mon_src_.get(), &native_src_, arm_cfg);

        // --- the peer pool ---------------------------------------------------
        p2p::XmrPeerPool::Config pc;
        pc.net                    = nets_.wire;
        pc.link.handshake.net     = nets_.wire;
        pc.link.handshake.our_peer_id = cfg_.peer_id ? cfg_.peer_id : random_peer_id_();
        pc.manual_peers           = cfg_.connect;
        pc.bind_ip                = cfg_.p2p_bind_ip;
        pc.dos.max_solicited_credits = cfg_.dos_solicited_credits;   // #1680 lever
        pc.use_seeds              = cfg_.use_seeds;
        if (cfg_.probe_only) {
            // A READ-ONLY probe dials exactly what it was told to dial. The
            // pool learns addresses from the handshake peerlist and the plan
            // refills toward its target, so a probe left on the default would
            // quietly open connections to strangers on the public network --
            // observed once against stagenet, where the probe dialed a peer it
            // had just learned from the daemon it was probing.
            //
            // "What it was told to dial" is the PINNED peers plus, when the
            // operator asked for --seeds, the network's own seed set: a probe
            // is exactly how an operator checks that a mainnet bootstrap will
            // reach anybody at all, and sizing the budget by connect.size()
            // alone made `--seeds` with no --connect a silent no-op -- zero
            // dials, zero handshakes, and a verdict that read as "mainnet is
            // unreachable" rather than "this probe never dialled". The seed
            // allowance is small and fixed so the plan still cannot wander off
            // into peerlist strangers.
            //
            // The `use_seeds` assignment above is deliberately BEFORE this
            // block: it used to be after, which silently overwrote the probe's
            // own `pc.use_seeds = false` and made that line dead.
            const std::size_t budget =
                cfg_.connect.size() + (cfg_.use_seeds ? kProbeSeedDialBudget : 0);
            pc.dial.target_outbound      = budget;
            pc.dial.max_outbound         = budget;
            pc.dial.max_concurrent_dials = budget;
        }

        p2p::XmrPeerPool::Deps pd;
        pd.serving = &boot_;       // io-thread reads; the state_normal obligation
                                   // (pre-boot it answers for the genesis itself)
        pd.index   = &inbound_;    // enqueue-and-return onto the verify thread
        pd.txpool  = &tx_sink_;    // enqueue-and-return onto the pool thread
        pool_ = p2p::XmrPeerPool::create(io_, pc, pd);

        index_.set_fetcher(pool_.get());
        tx_sink_.set_faults([this](const PeerRef& p, PeerFault f, const std::string& w) {
            if (pool_) pool_->penalize(p, f, w);
        });

        // --- C5, constructed and armed, not driven in M0 ---------------------
        relay::RelayConfig rcfg;
        rcfg.policy.order = cfg_.relay_order;
        block_relay_ = std::make_unique<relay::LevinBlockRelay>(
            *pool_, relay::DaemonSubmitSink{}, &native_src_, &index_, rcfg);

        // --- C6 --------------------------------------------------------------
        if (cfg_.parity) {
            native_tip_ = std::make_unique<parity::ChainViewTipObserver>(index_.view());
            parity::ITipObserver* native_tip_seam = native_tip_.get();
            if (cfg_.tip_fault.armed()) {
                tip_fault_ = std::make_unique<parity::PerturbingTipObserver>(
                    *native_tip_, cfg_.tip_fault);
                native_tip_seam = tip_fault_.get();
                note_("[M4-INJECT] ARMED on the native tip field '" + cfg_.tip_fault.field
                    + (cfg_.tip_fault.absent ? "' (withhold)" : "' (perturb by one unit)")
                    + " after " + std::to_string(cfg_.tip_fault.after_samples)
                    + " observation(s): this run is a REFUSAL EXPERIMENT and its samples "
                      "are not honest parity evidence");
            }
            parity::ParityOracle::Deps od;
            od.native_tip  = native_tip_seam;
            od.monerod_tip = mon_tip_.get();
            od.served_arm  = arms_->arm(cfg_.serve_arm);
            od.shadow_arm  = arms_->shadow();
            GraduationKey key;
            key.c2pool_commit   = cfg_.c2pool_commit;
            key.monerod_version = "unknown";
            key.net             = to_string(cfg_.net);
            parity::ParityOracleConfig oc;
            oc.ledger_path = cfg_.parity_ledger_path;
            oracle_ = std::make_unique<parity::ParityOracle>(
                od, key, parity::GraduationPolicy::regtest_fast(), oc,
                [] { return unix_seconds_(); },
                [this](const std::string& line) { note_(line); });
        }

        // --- the sync driver -------------------------------------------------
        SyncDriverConfig dcfg;
        dcfg.probe_only = cfg_.probe_only;
        driver_ = std::make_unique<SyncDriver>(
            *pool_, boot_, index_, p2p::genesis_id(nets_.wire),
            [this] { return boot_.booted(); },
            [this] { return index_.refetch_wanted(); },
            [this] { return index_.bodies_wanted(); },   // #1680: stranded fluffy parks
            dcfg);

        // --- threads ----------------------------------------------------------
        running_ = true;
        guard_   = std::make_unique<boost::asio::executor_work_guard<
            boost::asio::io_context::executor_type>>(io_.get_executor());
        io_thread_ = std::thread([this] { io_.run(); });
        {
            // The witness has to know which thread must never hash. It is
            // registered from INSIDE the io thread rather than guessed, so it
            // names the thread that actually runs the sockets.
            std::promise<void> ready;
            auto fut = ready.get_future();
            boost::asio::post(io_, [this, &ready] {
                if (witness_) witness_->forbid(std::this_thread::get_id());
                io_thread_id_ = std::this_thread::get_id();
                ready.set_value();
            });
            fut.wait();
        }

        pool_->start();
        for (const std::string& key : cfg_.connect) pool_->dial_now(key);

        // --- the cold-start address set --------------------------------------
        // p2p/xmr_peer_store.hpp's seed_from_tables() plants the compiled-in IP
        // seeds on the dial plan's own schedule, and that is all `--seeds` has
        // ever done: p2p::dns_seeds() existed, was pinned by the locator KAT,
        // and was called by nothing. On MAINNET that is the difference between
        // six fixed addresses -- shared by every c2pool node on earth, and the
        // obvious set to block -- and the live A-records monerod itself
        // bootstraps from. Resolved HERE, before gate 4, because the gate needs
        // handshaked peers to ask and a mainnet node with no --native-connect
        // has none until this runs.
        if (cfg_.use_seeds) seed_from_dns_();

        // --- GATE 4: the anchor, confirmed by the network, before we serve ----
        //
        // It runs HERE and not earlier because it needs handshaked peers, and
        // HERE and not later because the sync driver (armed on the next line)
        // is the thing that would start building on an unconfirmed root. It is
        // the last gate between a loaded bundle and a running node, and it is
        // fail-closed in both directions: a mismatch refuses, and so does an
        // exhausted peer set or an expired deadline.
        if (cfg_.boot == BootMode::Anchor && !run_anchor_confirm_(why)) {
            stop();
            return false;
        }

        // --- RESUME, strictly downstream of gate 4 ----------------------------
        // The snapshot is loaded HERE and nowhere earlier: on an anchor boot the
        // line above has just had the anchor confirmed by live peers, and the
        // envelope this reads is keyed to THAT anchor's height and id. A
        // snapshot can therefore only fast-forward the node along a chain whose
        // root the network vouched for moments ago; it can never stand in for
        // the confirm. If gate 4 refused, the return above means this line is
        // not reached and `snap_armed_` stays false, so the refused session
        // also cannot WRITE a snapshot over a good one.
        //
        // On a GENESIS boot the same line is what discharges the boot: the image
        // IS the trust root, so load_snapshot_() goes through ChainBoot and the
        // node never reaches the line below owed a genesis seed it would later
        // pay by resetting the very index it just resumed.
        //
        // Every failure below is the same failure -- carry on from the anchor,
        // or from the genesis seed -- which is why none of them returns false.
        if (!cfg_.snapshot_path.empty()) {
            load_snapshot_();
            snap_armed_ = true;
            snap_loop_.start();
            snap_next_ms_ = now_ms_() + cfg_.snapshot_every_s * 1000;
        }

        arm_tick_();
        return true;
    }

    void stop() {
        if (!running_.exchange(false)) return;
        // A CLEAN stop is the one moment the on-disk image can be made exactly
        // current, so it is taken before anything is torn down. Armed only
        // after gate 4 settled (see start()), so a refused start never writes.
        if (snap_armed_ && !cfg_.snapshot_path.empty()) save_snapshot_("clean stop");
        snap_loop_.stop();
        tick_.cancel();
        if (pool_) pool_->stop();
        if (guard_) guard_->reset();
        io_.stop();
        if (io_thread_.joinable()) io_thread_.join();
        verify_loop_.stop();
        pool_loop_.stop();
    }

    // -----------------------------------------------------------------------
    // Observation
    // -----------------------------------------------------------------------
    NodeStatus status() {
        NodeStatus s;
        s.sync    = index_.sync_state();
        s.pool    = pool_ ? pool_->telemetry() : p2p::PoolTelemetry{};
        s.inbound = inbound_.stats();
        s.txsink  = tx_sink_.stats();
        s.verify_queue = verify_loop_.stats();
        s.pool_queue   = pool_loop_.stats();
        s.boot         = boot_.stats();
        s.txpool       = txpool_.stats();
        s.txpool_gate_open = tx_gate_.load();
        s.rpc_calls    = rpc_ ? rpc_->calls() : 0;
        s.rpc_failures = rpc_ ? rpc_->failures() : 0;
        if (witness_) s.randomx = witness_->witness();
        s.randomx_mode = index_.pow_gate().mode();
        if (arms_)    s.template_arm = arms_->describe();
        // The driver's counters are only ever written on the verify thread, so
        // they are read there too rather than racing them.
        verify_loop_.call([this, &s] { if (driver_) s.driver = driver_->stats(); });
        s.io_threads   = thread_id_string_(io_thread_id_);
        s.verify_thread = thread_id_string_(verify_loop_.thread_id());
        s.citizen_pool_n          = native_src_.last_pool_n();
        s.citizen_chosen_n        = native_src_.last_chosen_n();
        s.good_citizen_violations = native_src_.good_citizen_violations();
        s.tmpl_dropped_mined      = native_src_.dropped_mined();
        s.own_invalid_refused     = index_.own_blocks_refused_invalid();
        s.own_forks_abandoned     = index_.own_forks_abandoned();
        s.pool_already_mined      = s.txpool.rejected_already_mined;
        return s;
    }

    std::vector<TipRecord> tips() const {
        std::lock_guard<std::mutex> lk(rec_mu_);
        return tips_;
    }

    std::vector<std::string> take_log() {
        std::lock_guard<std::mutex> lk(rec_mu_);
        std::vector<std::string> out;
        out.swap(log_);
        return out;
    }

    // The C6 seam, run in the order the oracle's threading contract requires:
    // the daemon round trip on the CALLER's thread, the comparison on the
    // verify thread (a native observation reads the chain state view, which the
    // verify thread owns).
    std::vector<parity::SeamResult> parity_sample() {
        std::vector<parity::SeamResult> out;
        if (!oracle_) return out;
        if (mon_tip_) (void)mon_tip_->poll();
        verify_loop_.call([this, &out] { out = oracle_->drain(); });
        return out;
    }

    // -----------------------------------------------------------------------
    // M1: the P-POOL seam.
    //
    // ONE SAMPLE IS A COHERENT CAPTURE OR IT IS NOTHING. Three things have to be
    // true of it or the comparison is between two different questions:
    //
    //   * the native index must not have adopted a tip between the two reads --
    //     a connected block drops mined transactions from BOTH pools, but not at
    //     the same instant, so a sample that straddles one manufactures a set
    //     difference out of nothing;
    //   * the daemon must be at the same tip we are, for the same reason;
    //   * both arms must actually have answered.
    //
    // Any of those failing yields an UNJUDGED report with a reason, which the
    // tally counts as unjudged and never as agreement.
    //
    // The daemon round trip happens on the CALLER's thread and the native reads
    // happen where their owners live: the tip on the verify thread, the pool
    // facts under the pool's own mutex. Nothing here touches the io thread.
    parity::TxpoolParityReport txpool_parity_sample() {
        parity::TxpoolParityReport rep;
        if (!mon_pool_) {
            rep.why = "no monerod arm configured (--monerod-rpc)";
            pool_tally_.add(rep);
            return rep;
        }

        auto tip_key = [this](std::uint64_t& h, Hash& prev, Hash& id, bool& synced) {
            verify_loop_.call([&] {
                const ChainRow* t = index_.view().state().tip();
                synced = index_.view().sync_state().synced;
                if (t == nullptr) { h = 0; prev = Hash{}; id = Hash{}; synced = false; return; }
                h = t->height; prev = t->prev_id; id = t->id;
            });
        };

        std::uint64_t h0 = 0, h1 = 0;
        Hash prev0{}, prev1{}, id0{}, id1{};
        bool synced0 = false, synced1 = false;
        tip_key(h0, prev0, id0, synced0);
        if (!synced0) {
            rep.why = "native index has no synced tip yet";
            pool_tally_.add(rep);
            return rep;
        }

        // The daemon's answer carries its own `why` when it could not answer, so
        // the return value is not consulted: an unanswered arm must reach the
        // comparator as an unanswered arm, not as an early return that loses the
        // reason.
        (void)mon_pool_->poll();
        const std::vector<TxpoolFact> ours = txpool_.facts();

        tip_key(h1, prev1, id1, synced1);
        if (h0 != h1 || id0 != id1) {
            rep.height = h1;
            rep.why    = "incoherent capture: the native tip moved from height "
                       + std::to_string(h0) + " to " + std::to_string(h1)
                       + " while the two pools were being read";
            pool_tally_.add(rep);
            return rep;
        }

        if (mon_tip_) {
            // Poll the daemon's tip HERE rather than reading the cache the
            // P-TIP path filled. That cache is refreshed only when a new tip
            // arrives, so between blocks it can be seconds old -- and a stale
            // "the daemon is at our height" standing next to a LIVE read of the
            // daemon's pool is exactly the incoherent capture this guard exists
            // to refuse. Two extra RPCs per sample is what coherence costs.
            (void)mon_tip_->poll();
            const parity::ArmObservation& t = mon_tip_->observe();
            if (!t.have || t.height != h1) {
                rep.height = h1;
                rep.why = t.have
                    ? ("arms are at different tips: native " + std::to_string(h1)
                       + ", monerod " + std::to_string(t.height))
                    : ("monerod tip unknown: " + t.why);
                pool_tally_.add(rep);
                return rep;
            }
        }

        parity::PoolSnapshot native;
        native.arm  = "native";
        native.have = true;
        native.txs.reserve(ours.size());
        for (const TxpoolFact& f : ours) {
            parity::PoolTxObs o;
            o.id        = f.id;
            o.weight    = parity::Obs::u64(f.weight);
            o.fee       = parity::Obs::u64(f.fee);
            o.blob_size = parity::Obs::u64(f.blob_size);
            o.peers     = parity::Obs::u64(f.peers);
            o.evidence  = parity::Obs::u64(static_cast<std::uint64_t>(f.evidence));
            native.txs.push_back(std::move(o));
        }

        const parity::PoolSnapshot& theirs = mon_pool_->observe();

        parity::ClassifierInputs cls;
        cls.height = h1;
        rep = parity::compare_txpools(native, theirs, h1, prev1, cls);
        pool_tally_.add(rep);
        return rep;
    }

    const parity::TxpoolParityTally& txpool_tally() const noexcept { return pool_tally_; }
    bool has_monerod_pool_arm() const noexcept { return mon_pool_ != nullptr; }

    // -----------------------------------------------------------------------
    // HARNESS SEAM (M1). Feed a transaction blob to C3 as if a peer had relayed
    // it, and hand back the verdict.
    //
    // This is not a back door around the levin path: it is the SAME
    // IRelayedTxSink entry point C1 calls, run on the SAME pool thread, with a
    // PeerRef that says where it came from. It exists because two of M1's
    // proofs are about what the pool does with a transaction the daemon will
    // never relay to us -- the key-image twin, and the blob a wallet built with
    // do_not_relay so that the daemon and the native pool can be made to hold
    // DIFFERENT members of one double spend on purpose. There is no way to ask
    // a real peer for that.
    //
    // Nothing in the node calls it; only the harness does.
    TxRelayVerdict inject_relayed(std::vector<std::uint8_t> blob, std::uint64_t peer_id,
                                  bool fluff = true) {
        TxRelayVerdict out;
        PeerRef from;
        from.peer_id = peer_id;
        from.addr    = "harness-injected";
        std::vector<std::vector<std::uint8_t>> batch;
        batch.push_back(std::move(blob));
        pool_loop_.call([&] {
            std::vector<TxRelayVerdict> v = txpool_.on_relayed(from, std::move(batch), fluff);
            if (!v.empty()) out = v[0];
        });
        return out;
    }

    // -----------------------------------------------------------------------
    // OPERATOR TX-INJECTION -- the production gate (mirrors Dash submit_inject).
    //
    // Unlike inject_relayed (a raw harness feed straight into C3), this is the
    // full operator path: it arms behind --native-inject, throttles, sandboxes,
    // and -- the point of the whole subsystem -- records the accepted inject in
    // the OperatorInjectPool AND PINS it in C3, so the served template offers it
    // FIRST at highest priority (mined even at 0 fee) with first claim on the
    // block-weight cap. It never signs, never mutates the blob, and touches no
    // coinbase / settlement state (reward-neutral by construction).
    //
    // ORDER (the Dash contract, ported): enabled? -> oversize refused
    // charged-free (before the limiter) -> rate limiter by origin (charged on
    // attempt) -> decode + sandbox (bounded work, before the heavy BP+ verify)
    // -> reconcile expiry vs tip -> would_admit (cheap ledger gate) -> C3
    // on_relayed -> map the verdict -> admit into the ledger -> pin in C3. A
    // Duplicate from C3 (the network already relayed it) is ACCEPTED with cause
    // ok-already-in-pool, because for XMR priority lives in SELECTION, not in a
    // mempool fee-delta -- there is nothing to refuse. NotSynced refuses, as
    // monerod ignores relayed txs off the tip.
    enum class InjectOrigin : std::uint8_t { Local, Peers };
    struct InjectSubmitResult {
        bool        ok    = false;
        std::string cause = "ok";   // named verdict (Dash DEF3 discipline)
        Hash        id{};
    };

    InjectSubmitResult submit_operator_inject(std::vector<std::uint8_t> blob,
                                              std::uint32_t flags = InjectFlags::PriorityRequest,
                                              std::uint64_t expiry_height = 0,
                                              InjectOrigin  origin = InjectOrigin::Local) {
        std::lock_guard<std::mutex> gate(inject_gate_mu_);
        InjectSubmitResult r;

        // 1) enabled?
        if (!cfg_.operator_inject) { r.cause = "inject-disabled"; return r; }

        // 2) oversize refused charged-free, BEFORE the limiter is charged.
        const std::uint64_t blob_size = blob.size();
        if (blob_size == 0) { r.cause = "inject-empty"; return r; }
        if (blob_size > OperatorInjectPool::kMaxInjectTxBytes) {
            r.cause = "inject-pool-oversize"; return r;
        }

        // 3) rate limiter by origin, charged on the ATTEMPT (DoS placement).
        const std::time_t now = static_cast<std::time_t>(unix_seconds_());
        InjectRateLimiter& lim =
            (origin == InjectOrigin::Peers) ? inject_lim_peers_ : inject_lim_local_;
        auto rl = lim.try_consume(blob_size, now);
        if (!rl.ok()) { r.cause = rl.name(); return r; }

        // 4) decode + sandbox (bounded work before the heavy BP+ verify in C3).
        DecodedTx d;
        if (decode_relayed_tx(blob, d) != TxDecodeStatus::Ok) {
            r.cause = "inject-decode-failed"; return r;
        }
        auto sb = InjectSandbox::vet(d.w);
        if (!sb.ok()) { r.cause = sb.name(); return r; }
        r.id = d.id;

        // 4b) DAEMON-FIRST NAMED-REFUSAL. Under the daemon-first arm the found
        //     block is submitted to monerod, which rejects a 0-fee/un-relayable
        //     tx ("Block not accepted"); refuse it HERE, by name, before it can
        //     pin. The p2p-first arm is the supported home for a 0-fee inject:
        //     its native submit always mines it (proven).
        if (const char* dfr = OperatorInjectPool::daemon_first_refusal(
                /*daemon_first_arm  */ cfg_.relay_order != ArmOrder::P2pOnly,
                /*monerod_configured*/ !cfg_.monerod_rpc_host.empty() && cfg_.monerod_rpc_port != 0,
                /*fee               */ d.w.fee);
            dfr[0] != '\0') {
            r.cause = dfr;
            note_(std::string("[INJECT] refused: ") + dfr
                + " -- a 0-fee operator inject is un-relayable under --arm-order "
                  "daemon-first; run --arm-order p2p-first, where the native submit "
                  "always mines it");
            return r;
        }

        // 5) reconcile: reap injects the tip has aged out, then default a FINITE
        //    expiry so a pinned 0-fee inject cannot live forever.
        std::uint64_t tip = 0;
        if (auto t = index_.tip()) tip = t->height;
        op_injects_.reap_expired(tip);
        if (expiry_height == 0) expiry_height = tip + cfg_.operator_inject_ttl_blocks;

        // 6) would_admit (cheap ledger gate). A Duplicate in the ledger is fine
        //    -- re-submitting an already-tracked inject is a no-op accept.
        auto wa = op_injects_.would_admit(d.id, blob_size);
        if (wa != OperatorInjectPool::Admit::Ok &&
            wa != OperatorInjectPool::Admit::Duplicate) {
            r.cause = OperatorInjectPool::admit_name(wa); return r;
        }

        // 7) into C3 (the body/includability + key-image-conflict authority).
        TxRelayVerdict v = inject_relayed(std::move(blob), OPERATOR_PEER_ID, /*fluff*/true);
        using Reason = TxRelayVerdict::Reason;
        if (v.reason == Reason::NotSynced) { r.cause = "inject-c3-NotSynced"; return r; }
        if (v.reason != Reason::Accepted && v.reason != Reason::Duplicate) {
            r.cause = std::string("inject-c3-") + to_string(v.reason); return r;
        }

        // 8) record in the inject ledger (idempotent on a ledger Duplicate).
        op_injects_.admit(d.id, flags, expiry_height, blob_size, d.w.weight, d.w.fee,
                          static_cast<std::uint64_t>(now));

        // 9) PIN the whole live inject set in C3 under a reserved key, so a
        //    0-fee inject survives cap/age eviction between submit and snapshot.
        //    pin() replaces the set, so re-pinning live_ids() also unpins any id
        //    reap dropped in step 5.
        txpool_.pin(operator_pin_key_(), op_injects_.live_ids());

        r.ok    = true;
        r.cause = (v.reason == Reason::Duplicate) ? "ok-already-in-pool" : "ok";
        return r;
    }

    // Read-only inject sensors for the status line / tests.
    std::size_t inject_pool_size()      const { return op_injects_.size(); }
    std::size_t inject_last_placed()    const { return native_src_.last_inject_n(); }
    std::size_t inject_last_dropped()   const { return native_src_.last_inject_dropped(); }

    // -----------------------------------------------------------------------
    // M4: DRIVING THE P-TPL SEAM.
    //
    // Nothing in M0..M3 called IParityOracle::on_serve. The tip probe fires by
    // itself because the index publishes an event at every height; the template
    // probe only fires when somebody SERVES a template, and in this harness
    // nobody did -- so a soak run on the existing code would have accumulated a
    // long P-TIP streak and never once compared a template, which is half of
    // what the M4 criterion actually asks for.
    //
    // This is that caller. Three things about it are deliberate:
    //
    //   * THE POSTURE IS STRICT. It resolves arm(serve_arm) directly rather
    //     than through ArmResolver::serving(), because serving() falls back to
    //     the other arm when the configured one is not ready. That fallback is
    //     right in production and fatal to a parity claim: a leg that quietly
    //     served monerod for an hour is not evidence about the native arm. An
    //     unready arm therefore yields no sample and says why.
    //
    //   * THE ARTEFACT IS CARRIED. on_serve takes the MinerData that would have
    //     gone out, not an epoch to re-read later, which is what keeps
    //     SERVED-MISMATCH provable (contracts/parity.hpp says why).
    //
    //   * THREADING follows parity_sample(): the daemon round trip happens on
    //     the CALLER's thread, and the native arm's snapshot -- which reads the
    //     chain state view the verify thread owns -- happens on the verify
    //     thread. The oracle's on_serve is enqueue-and-return either way.
    struct ServeProbe {
        bool          served = false;
        std::string   arm;
        std::uint64_t height = 0;
        std::size_t   backlog = 0;
        std::string   why;          // when !served
    };

    ServeProbe m4_serve_probe() {
        ServeProbe p;
        if (!oracle_ || !arms_) { p.why = "no parity oracle on this node"; return p; }
        if (mon_src_) (void)mon_src_->poll();      // the RPC, on the caller's thread
        IMinerDataSource* src = arms_->arm(cfg_.serve_arm);
        if (src == nullptr) {
            p.why = std::string("configured serving arm '") + to_string(cfg_.serve_arm)
                  + "' is not present on this node";
            return p;
        }
        p.arm = src->name();
        verify_loop_.call([&] {
            const MinerDataReadiness rd = src->readiness();
            if (!rd.ok()) { p.why = rd.why.empty() ? std::string("arm not ready") : rd.why; return; }
            std::string why;
            const std::optional<node::MinerData> md = src->snapshot(&why);
            if (!md) { p.why = why.empty() ? std::string("arm produced no snapshot") : why; return; }
            p.height  = md->height;
            p.backlog = md->tx_backlog.size();
            p.served  = true;
            oracle_->on_serve(src->epoch(), *md, src->name());
        });
        return p;
    }

    // The daemon version and nettype, straight from get_info. The M4 ledger's
    // key names the daemon it was judged against, and "unknown" is not a name.
    parity::MonerodTipObserver* monerod_tip() noexcept { return mon_tip_.get(); }
    // Non-null only while the M4 fault injector is armed.
    parity::PerturbingTipObserver* tip_fault() noexcept { return tip_fault_.get(); }

    parity::ParityOracle* oracle() noexcept { return oracle_.get(); }
    ChainIndex&           index()  noexcept { return index_; }
    RelayedTxPool&        txpool() noexcept { return txpool_; }
    tmpl::ArmResolver*    arms()   noexcept { return arms_.get(); }
    // The daemon arm as its CONCRETE type: a consumer that resolves to it owes
    // it the get_miner_data round trip, and poll() is not on the interface.
    // Null when no daemon endpoint was configured.
    tmpl::MonerodMinerDataSource* monerod_source() noexcept { return mon_src_.get(); }
    const NativeNodeConfig& config() const noexcept { return cfg_; }
    const NetPair&          nets()   const noexcept { return nets_; }

    // -----------------------------------------------------------------------
    // M3: THE DAEMONLESS TIP FEED.
    //
    // M0 proved the node follows a live tip; nothing consumed that stream. The
    // pool's settlement finality did -- but from the OTHER index, the
    // monerod-mirroring one the X2 adapter fills from get_miner_data. This is
    // the seam that lets the pool's finalize driver be driven by the chain this
    // node verified itself.
    //
    // WHY A QUEUE AND NOT A CALLBACK. The index flushes its events on the
    // VERIFY thread, and everything downstream of the finalize driver -- the
    // W6 settlement store, the OWED ledger, the V37 engine submission -- is
    // main-thread-owned in this daemon. Handing the verify thread a callback
    // into that would put consensus bookkeeping behind a lock it has never
    // taken. So the events are queued here and the main loop drains them, in
    // arrival order, at exactly the point where it used to call pump_poll().
    //
    // The C5 relay's PREFER-OWN submit_to_own_index feeds this same queue for
    // our OWN found block: we do not wait to hear our block back from a peer.
    std::vector<node::MainchainEvent> drain_mainchain_events() {
        std::lock_guard<std::mutex> lk(rec_mu_);
        std::vector<node::MainchainEvent> out;
        out.swap(chain_events_);
        return out;
    }

    // How many events the feed has produced since start, whether or not anyone
    // drained them. A tip driver that produced nothing and a consumer that
    // dropped everything look identical without this.
    // COLD-BOOT-2 (D4a): snapshot saves written / failed since start (+ the last failure).
    struct SnapshotStats { std::uint64_t ok = 0, failed = 0; std::string last_failure; };
    SnapshotStats snapshot_stats() const {
        std::lock_guard<std::mutex> lk(rec_mu_);
        return SnapshotStats{snap_ok_, snap_failed_, snap_last_fail_};
    }

    std::uint64_t mainchain_events_seen() const {
        std::lock_guard<std::mutex> lk(rec_mu_);
        return chain_events_seen_;
    }

    // C5, for the consumer that actually found a block. Null before start().
    relay::LevinBlockRelay* block_relay() noexcept { return block_relay_.get(); }

    // Force the publication gate after the fact (the regtest / single-peer case).
    void force_synced(bool v) { index_.force_synced(v); }

private:
    // --- construction helpers (called from the member initialiser list) -----
    ChainIndexOptions make_index_options_() const {
        ChainIndexOptions o;
        o.net = nets_.consensus;
        o.tie = cfg_.fork_tie;          // D-14, driven by --same-height-tiebreak
        o.own_fork_bound_ms = cfg_.own_fork_bound_ms;
        o.consumer_window = cfg_.consumer_window;   // COLD-BOOT-2
        return o;
    }

    TxpoolConfig make_txpool_config_() const {
        TxpoolConfig c;
        return c;
    }

    tmpl::NativeTemplatePolicy make_template_policy_() const {
        tmpl::NativeTemplatePolicy p;
        // On a private chain one pinned peer is the correct configuration, so
        // the peer floor is off; it is a flag rather than a refusal anyway.
        p.min_peers = 0;
        p.backlog_refresh_s = cfg_.backlog_refresh_s;
        // GOOD-CITIZEN: the served arm always builds from the good-citizen
        // selection over the admitted backlog (operator hard rule). The default
        // is on; nothing on the node config turns it off (that is a KAT/shadow
        // knob), so the live path always honours the rule.
        p.good_citizen = true;
        return p;
    }

    // The index takes an IPowSource by reference in its constructor, before
    // start() can decide whether RandomX is available. So the witness is
    // constructed first over a placeholder source and re-pointed at the real
    // verifier in init_pow_() through PowGate::set_source() -- which is exactly
    // why that setter exists.
    IPowSource& pow_witness_or_null_() {
        if (!witness_) witness_ = std::make_unique<ThreadWitnessPowSource>(null_pow_);
        return *witness_;
    }

    bool init_pow_(std::string& why) {
#if defined(XMR_NATIVE_NODE_HAVE_RANDOMX)
        verifier_ = std::make_unique<::c2pool::xmr::LightVerifier>();
        if (!verifier_->init()) {
            why = "RandomX LightVerifier init failed (two 256 MiB caches + a light VM)";
            return false;
        }
        rx_source_ = std::make_unique<LightVerifierPowSource<::c2pool::xmr::LightVerifier>>(
            *verifier_, RandomXMode::LightJit);
        // Re-point the witness at the real verifier IN PLACE. The witness object
        // keeps its address on purpose: the index cached the IPowSource* it was
        // constructed with, so replacing the object here would dangle it.
        witness_->set_inner(*rx_source_);
        return true;
#else
        if (!cfg_.allow_unverified_pow) {
            why = "this build has no librandomx, so proof of work cannot be checked: "
                  "every block would connect unverified. Pass --allow-unverified-pow "
                  "to run anyway, or build with -DXMR_BUILD_RANDOMX=ON";
            return false;
        }
        return true;
#endif
    }

    static std::uint64_t random_peer_id_() {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uint64_t v = 0;
        while (v == 0) v = gen();   // a zero peer id is a handshake refusal
        return v;
    }

    static std::string thread_id_string_(const std::thread::id& id) {
        std::ostringstream os;
        os << id;
        return os.str();
    }

    static std::uint64_t unix_seconds_() {
        using namespace std::chrono;
        return static_cast<std::uint64_t>(
            duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
    }

    // A synthetic peer id for operator-injected txs, in the same 0xC200_00xx
    // block the harness inject uses, so the C3 relay attributes them distinctly.
    static constexpr std::uint64_t OPERATOR_PEER_ID = 0xC2000002ull;
    // The reserved C3 pin key under which the whole live operator-inject set is
    // pinned (distinct from the per-generation template pins the miner-data
    // source uses; those key on a template id, this one is a fixed sentinel).
    static Hash operator_pin_key_() { Hash k{}; k.fill(0xC2); return k; }

    void arm_tick_() {
        if (!running_) return;
        tick_.expires_after(std::chrono::milliseconds(cfg_.driver_tick_ms));
        tick_.async_wait([this](const boost::system::error_code& ec) {
            if (ec || !running_) return;
            const std::uint64_t now = now_ms_();
            verify_loop_.post([this, now] {
                                  if (driver_) driver_->tick(now);
                                  // Own-fork liveness guard: an own-mined
                                  // tip no peer adopts past the bound is
                                  // abandoned (ChainIndex::check_own_fork).
                                  {
                                      std::string ofw;
                                      if (index_.check_own_fork(now, &ofw)) {
                                          const std::string line =
                                              "[own-fork] LIVENESS GUARD: " + ofw
                                              + " -- following the peers' chain";
                                          note_(line);
                                          std::fprintf(stderr, "%s\n", line.c_str());
                                      }
                                  }
                                  publish_tx_gate_();
                                  // GOOD-CITIZEN: feed the wall clock (unix
                                  // seconds) to the miner-data source so the
                                  // backlog-refresh rate limit is actually
                                  // honoured on the live node -- without a
                                  // set_now caller the "at most once per
                                  // backlog_refresh_s" clause is inert and the
                                  // cadence collapses to the provider poll.
                                  native_src_.set_now(unix_seconds_());
                              },
                              /*control=*/true);
            // The periodic save. Posted to its OWN loop, never run here: the
            // serialization takes the index lock and the write touches a disk,
            // and neither belongs on the io thread that is servicing sockets or
            // on the verify thread that is connecting blocks.
            if (snap_armed_ && cfg_.snapshot_every_s != 0 && now >= snap_next_ms_) {
                snap_next_ms_ = now + cfg_.snapshot_every_s * 1000;
                snap_loop_.post([this] { save_snapshot_("periodic"); });
            }
            arm_tick_();
        });
    }

    std::uint64_t now_ms_() const {
        using namespace std::chrono;
        return static_cast<std::uint64_t>(
            duration_cast<milliseconds>(steady_clock::now() - epoch_).count());
    }

    // -----------------------------------------------------------------------
    // GATE 4, driven.
    //
    // load_anchor()'s three gates judged the bundle against itself; this one
    // asks the network. The driver issues NOTIFY_REQUEST_GET_OBJECTS for
    // bundle.id to one handshaked peer at a time, ChainBoot::on_objects hands
    // the answering blob to AnchorNetworkConfirm, and the confirm recomputes
    // the id from those bytes (never taking the peer's word) and reads the
    // block's own height out of its coinbase.
    //
    // WHICH THREAD. IChainFetcher's contract puts request_objects on the C2
    // verify thread, and ChainBoot::on_objects already runs there, so the whole
    // gate is driven from that thread via verify_loop_.call() -- while THIS
    // function blocks on the consumer's thread, which is exactly what "refuse
    // to start" has to mean: start() has not returned, so nothing above the
    // node has a running node to serve from.
    //
    // The wait is bounded by AnchorConfirmDriver itself (peers, per-peer turn,
    // wall deadline), so this loop cannot outlive cfg_.anchor_confirm.timeout_ms
    // even if every peer is silent, and every exit sets `why`.
    // -----------------------------------------------------------------------
    bool run_anchor_confirm_(std::string& why) {
        AnchorConfirmDriver drv(*pool_, boot_.anchor_confirm(), cfg_.anchor_confirm,
                                [this] { return now_ms_(); });
        note_("[GATE-4] confirming the anchor against the network: up to "
              + std::to_string(cfg_.anchor_confirm.peers) + " peer(s), "
              + std::to_string(cfg_.anchor_confirm.per_peer_ms) + " ms each, "
              + std::to_string(cfg_.anchor_confirm.timeout_ms) + " ms in total");

        for (;;) {
            AnchorConfirmState st = AnchorConfirmState::Pending;
            verify_loop_.call([&] { st = drv.poll(); });
            if (st == AnchorConfirmState::Confirmed) {
                note_(boot_.anchor_confirm().log_line());
                return true;
            }
            if (st == AnchorConfirmState::Refused) {
                const AnchorNetworkConfirm::Stats s = boot_.anchor_confirm().stats();
                why = "anchor REFUSED by the network confirm (gate 4): " + s.why;
                note_(boot_.anchor_confirm().log_line());
                note_("[GATE-4] REFUSING TO START. " + why);
                return false;
            }
            if (st == AnchorConfirmState::Disarmed) {
                // Unreachable on this path (boot == Anchor armed it), and a
                // silent true here would be the one way this gate could be
                // skipped, so it is a refusal rather than a pass.
                why = "the anchor confirm was never armed; refusing to start";
                note_("[GATE-4] REFUSING TO START. " + why);
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    // ON THE VERIFY THREAD.
    //
    // C3's RELAY GATE. The txpool refuses every transaction with NotSynced
    // until somebody tells it the index reached the tip -- monerod's
    // is_synchronized() rule, and fail-closed by construction so that a node
    // catching up never builds a template on a pool it could not have
    // populated correctly.
    //
    // M0 wired C2 -> C3 for BLOCK events and left this one seam open: nothing
    // in the tree called RelayedTxPool::set_synced(), so the gate was shut for
    // the life of the process and the pool refused every transaction that ever
    // arrived over levin. It is invisible from every angle M0 looked from --
    // the tip follows, the peer is healthy, levin `txs=` counts the frames
    // coming IN -- and the only symptom is a pool that stays empty, which on a
    // quiet chain is also what success looks like. M1 is where the pool is
    // finally asked what it holds, which is why M1 is where this surfaced.
    //
    // Published from the verify thread (which owns the sync state) onto the
    // pool thread (which owns the gate), only on a CHANGE, so the steady state
    // costs one atomic compare per driver tick.
    void publish_tx_gate_() {
        const bool synced = index_.view().sync_state().synced;
        bool expected = !synced;
        if (!tx_gate_.compare_exchange_strong(expected, synced)) return;
        pool_loop_.post([this, synced] { txpool_.set_synced(synced); });
        note_(std::string("[txpool] relay gate ") + (synced ? "OPEN" : "CLOSED")
              + " (index synced=" + (synced ? "1" : "0") + ")");
    }

    void on_mainchain_(const node::MainchainEvent& ev) {
        // M3: the daemonless tip feed. EVERY event is queued, Orphan included,
        // because the consumer's settlement driver has a disposition for an
        // orphan that it has for nothing else -- and it is queued HERE, above
        // the Orphan early-return, which is exactly why it is not folded into
        // the tip record below.
        {
            std::lock_guard<std::mutex> lk(rec_mu_);
            ++chain_events_seen_;
            chain_events_.push_back(ev);
            // Bounded like tips_. A consumer that stopped draining is a bug, and
            // dropping the OLDEST is the right failure: the newest events are
            // the ones a finalize cursor still needs.
            if (chain_events_.size() > 8192) chain_events_.erase(chain_events_.begin());
        }
        if (ev.kind == node::MainchainEventKind::Orphan) return;
        TipRecord r;
        r.height      = ev.block.height;
        r.id          = ev.block.id;
        r.prev_id     = ev.block.prev_id;
        r.difficulty  = ev.block.difficulty;
        r.timestamp   = ev.block.timestamp;
        r.reward      = ev.block.reward;
        r.reorg       = (ev.kind == node::MainchainEventKind::Reorg);
        r.reorg_depth = ev.depth;
        // The event carries the consumer-facing ChainMainBlock, which has no
        // cumulative difficulty and no weight; both live on the index's own row.
        // The row is found BY ID rather than by reading the tip: a backfill
        // connects many blocks and flushes their events afterwards, so by the
        // time this runs the tip is usually several blocks past the one the
        // event is about -- and comparing against the tip silently recorded
        // zeros for every block but the last.
        for (auto it = index_.view().state().rows().rbegin();
             it != index_.view().state().rows().rend(); ++it) {
            if (it->id != ev.block.id) continue;
            r.cumulative_difficulty = it->cumulative_difficulty;
            r.weight                = it->block_weight;
            break;
        }
        {
            std::lock_guard<std::mutex> lk(rec_mu_);
            tips_.push_back(r);
            if (tips_.size() > 8192) tips_.erase(tips_.begin());
        }
        if (oracle_) oracle_->on_tip(ev, "native");
        // The gate is published here as well as on the driver tick so that it
        // opens on the block that closed the sync, not up to a tick later.
        publish_tx_gate_();
    }

    // -----------------------------------------------------------------------
    // The DNS seed round, bounded.
    //
    // monerod's net_node.h lists four A-record hosts and guards them with
    // `if (m_nettype == MAINNET)`; p2p::dns_seeds() reproduces that guard, so
    // the two test networks correctly answer with nothing here and keep their
    // compiled-in IP seeds. Only IPv4 results are taken because the levin peer
    // key everywhere in C1c is a dotted quad, and an IPv6 literal would be
    // parsed as a hostname by split_peer_key and silently never dialed.
    //
    // The wait is bounded. A resolver handler that lands after the deadline is
    // harmless (it writes to shared state the handler owns a reference to) and
    // its addresses are simply not used this round; the cancel is hygiene, not
    // correctness. A cold start must not be able to hang on a broken resolver.
    // -----------------------------------------------------------------------
    static constexpr std::size_t   kProbeSeedDialBudget = 4;
    static constexpr std::uint64_t kDnsSeedResolveMs   = 8000;
    static constexpr std::size_t   kDnsSeedMaxPerHost  = 32;

    void seed_from_dns_() {
        const std::vector<p2p::DnsSeed> seeds = p2p::dns_seeds(nets_.wire);
        if (seeds.empty()) {
            note_("[seeds] this network has no DNS seeds (monerod lists them for MAINNET "
                  "only); the compiled-in IP seeds are the cold-start set");
            return;
        }

        struct Round {
            std::mutex               mu;
            std::vector<std::string> keys;
            std::size_t              outstanding = 0;
            bool                     signalled   = false;
            std::promise<void>       done;
        };
        auto round = std::make_shared<Round>();
        round->outstanding = seeds.size();
        auto fut = round->done.get_future();
        auto res = std::make_shared<boost::asio::ip::tcp::resolver>(io_);

        for (const p2p::DnsSeed& s : seeds) {
            res->async_resolve(
                s.host, std::to_string(s.port),
                [round, res, port = s.port](const boost::system::error_code& ec,
                                            boost::asio::ip::tcp::resolver::results_type r) {
                    std::lock_guard<std::mutex> lk(round->mu);
                    if (!ec) {
                        std::size_t taken = 0;
                        for (const auto& e : r) {
                            if (taken >= kDnsSeedMaxPerHost) break;
                            const auto a = e.endpoint().address();
                            if (!a.is_v4()) continue;
                            round->keys.push_back(
                                p2p::make_peer_key(a.to_v4().to_string(), port));
                            ++taken;
                        }
                    }
                    if (round->outstanding > 0) --round->outstanding;
                    if (round->outstanding == 0 && !round->signalled) {
                        round->signalled = true;
                        round->done.set_value();
                    }
                });
        }

        (void)fut.wait_for(std::chrono::milliseconds(kDnsSeedResolveMs));
        boost::asio::post(io_, [res] { boost::system::error_code ig; res->cancel(); (void)ig; });

        std::vector<std::string> keys;
        {
            std::lock_guard<std::mutex> lk(round->mu);
            keys = round->keys;
        }
        std::sort(keys.begin(), keys.end());
        keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
        if (keys.empty()) {
            note_("[seeds] " + std::to_string(seeds.size())
                + " DNS seed host(s) resolved to no usable IPv4 address in "
                + std::to_string(kDnsSeedResolveMs) + " ms; falling back to the IP seeds");
            return;
        }

        // The store is the io thread's, so the addresses are planted there. The
        // dial plan picks them up on its own next round rather than being
        // forced: its netgroup caps and rotation are the eclipse guard, and a
        // seed round is exactly when they matter most.
        boost::asio::post(io_, [this, keys] {
            if (!pool_) return;
            const auto now = pool_->now_ms();
            for (const std::string& k : keys)
                (void)pool_->store().add(k, p2p::PeerSource::DnsSeed, now);
        });
        note_("[seeds] " + std::to_string(keys.size()) + " address(es) from "
            + std::to_string(seeds.size()) + " mainnet DNS seed host(s), planted as DnsSeed");
    }

    // -----------------------------------------------------------------------
    // The resume file. Both halves key the envelope on the SAME identity: on an
    // anchor boot, the height and id gate 4 just confirmed against live peers;
    // on a genesis boot, height 0 and this network's genesis id. A node can
    // therefore never read an image written by a node on another network, or
    // one pinned to a different anchor bundle.
    // -----------------------------------------------------------------------
    SnapshotKey snapshot_key_() const {
        SnapshotKey k;
        k.net = static_cast<std::uint64_t>(nets_.consensus);
        if (cfg_.boot == BootMode::Anchor) {
            const AnchorNetworkConfirm::Stats s = boot_.anchor_confirm().stats();
            k.anchor_height = s.height;
            k.anchor_id     = s.id;
        } else {
            k.anchor_height = 0;
            k.anchor_id     = p2p::genesis_id(nets_.wire);
        }
        return k;
    }

    // The post-anchor output-set overlay lives NEXT TO the chain snapshot, in
    // its own file: the anchor snapshot (--output-set) is a read-only, pinned
    // input and is never written, and the index envelope keeps its format.
    std::string overlay_path_() const { return cfg_.snapshot_path + ".outset"; }

    void load_snapshot_() {
        std::vector<std::uint8_t> file;
        std::string why;
        // When an output-set was seeded (--native-output-set), that set is
        // numbered from the anchor's base and cannot be re-seated to a resumed
        // (higher) tip. The chain image alone therefore cannot resume it: the
        // post-anchor OVERLAY (outputs, key images, per-block leaves and undo
        // frames the chain added since the anchor) is persisted beside it and
        // replayed onto the seeded snapshot, bound to the same image and
        // verified against its recorded roots. Anything that does not match
        // falls back to the from-anchor re-walk, exactly as before.
        if (outputs_.output_count() > 0) {
            load_snapshot_with_output_set_();
            return;
        }
        if (!read_snapshot_file(cfg_.snapshot_path, file, why)) {
            note_("[snapshot] no resume (" + why + "); starting from the "
                + (cfg_.boot == BootMode::Anchor ? "confirmed anchor" : "genesis"));
            return;
        }
        std::vector<std::uint8_t> image;
        if (!decode_snapshot_envelope(file, snapshot_key_(), image, why)) {
            note_("[snapshot] REFUSED: " + why + "; starting from the "
                + (cfg_.boot == BootMode::Anchor ? "confirmed anchor" : "genesis"));
            return;
        }
        // Through the BOOT, not straight into the index, and on the verify
        // thread, which owns block application.
        //
        // The thread hop was always needed: an inbound blob may already be in
        // flight by now, and a load that raced one would reset the index
        // underneath it. Going through ChainBoot is the other half, and it is
        // the one a live genesis-boot run found missing. A snapshot carries its
        // own trust root, but loading it at the index left ChainBoot still
        // owed a genesis seed, so the first inbound blob after this line ran
        // try_seed_() -> seed_direct() -> reset: the resumed chain was wiped to
        // height 0 and re-walked, PoW and all. resume_from_snapshot() installs
        // the image AND records that the boot is discharged, in that order, on
        // this thread -- so there is no window in which an inbound blob can
        // find a loaded index with an un-booted gate in front of it. It re-
        // checks gate 4 itself and refuses over an unconfirmed anchor.
        bool ok = false;
        std::string load_why;
        verify_loop_.call([&] { ok = boot_.resume_from_snapshot(image, load_why); });
        if (!ok) {
            note_("[snapshot] REFUSED: " + load_why + "; starting from the "
                + (cfg_.boot == BootMode::Anchor ? "confirmed anchor" : "genesis"));
            return;
        }
        // outputs_ (the output-set / spent-key-image view) is NOT in the v1
        // image, so reconcile it fail-closed: re-seat its numbering base to the
        // resumed tip -- legal here because no live block has connected yet and
        // the output-set combination was excluded above, so the set is empty --
        // and DISABLE ring resolution. The outputs below the resume point are
        // not in this image; a ring reaching below it must be RingUnresolved
        // (fail-closed) rather than mis-resolved and an honest peer mis-scored.
        // The spent-key-image view therefore tracks from the resume point
        // forward, and post-resume blocks number from the right base. A future
        // snapshot v2 that persists outputs_ restores full below-resume
        // resolution; until then this is the honest posture for a resumed node.
        verify_loop_.call([&] {
            outputs_.reset_base(index_.view().rct_output_count());
            outputs_.disable_resolution();
        });
        const SyncState st = index_.sync_state();
        note_("[snapshot] RESUMED at height " + std::to_string(st.header_frontier)
            + " from " + cfg_.snapshot_path + " (" + std::to_string(image.size())
            + " bytes); no re-IBD from the anchor -- ring resolution disabled "
              "(spent-set tracks from the resume point; v1 image carries no output set)");
    }

    // Called on snap_loop_ (periodic) or on the caller's thread (clean stop).
    // save_snapshot() takes the index's own lock, so neither needs a hop.
    void save_snapshot_(const char* occasion) {
        std::vector<std::uint8_t> image;
        std::string why;
        if (outputs_.has_anchor_snapshot()) {
            save_snapshot_with_output_set_(occasion);
            return;
        }
        if (!index_.save_snapshot(image, why)) {
            snap_log_(false, std::string("[snapshot] not written (") + occasion + "): " + why);
            return;
        }
        const std::vector<std::uint8_t> file =
            encode_snapshot_envelope(snapshot_key_(), image);
        if (!write_snapshot_file(cfg_.snapshot_path, file, why)) {
            snap_log_(false, std::string("[snapshot] WRITE FAILED (") + occasion + "): " + why);
            return;
        }
        snap_log_(true, std::string("[snapshot] wrote ") + std::to_string(file.size()) + " bytes to "
            + cfg_.snapshot_path + " (" + occasion + ")");
    }

    // sha256 of the decoded chain image: what the overlay file is bound to.
    static Hash image_digest_(const std::vector<std::uint8_t>& image) {
        anchor_hash::Sha256 h;
        h.update(image.data(), image.size());
        const std::array<std::uint8_t, 32> d = h.finish();
        Hash out{};
        std::copy(d.begin(), d.end(), out.begin());
        return out;
    }

    // The output-set flavour of save_snapshot_(). The chain image and the
    // overlay are captured TOGETHER on the verify thread -- the thread that
    // connects blocks and feeds outputs_ synchronously -- so both describe the
    // same tip; the save is refused (the previous pair kept) if they do not.
    // The overlay file is written FIRST and carries sha256(image): a crash
    // between the two writes leaves an overlay bound to an image that is not
    // on disk, which the load refuses (re-walk), never a mismatched pair.
    void save_snapshot_with_output_set_(const char* occasion) {
        std::vector<std::uint8_t> image, ovl;
        std::string why;
        bool ok = false;
        std::uint64_t idx_h = 0, set_h = 0;
        verify_loop_.call([&] {
            const auto t = index_.tip();
            if (!t) { why = "the index has no tip"; return; }
            idx_h = t->height;
            set_h = outputs_.tip_height();
            if (!index_.save_snapshot(image, why)) return;
            if (t->height != set_h || t->id != outputs_.tip_id()) {
                why = "output-set overlay tip does not match the index tip";
                return;
            }
            ok = outputs_.serialize_overlay(ovl, why);
        });
        if (!ok) {
            snap_log_(false, std::string("[snapshot] not written (") + occasion + "): " + why
                + " (index tip " + std::to_string(idx_h) + ", output-set tip "
                + std::to_string(set_h) + ")");
            return;
        }
        const Hash bind = image_digest_(image);
        std::vector<std::uint8_t> ofile;
        ofile.reserve(ovl.size() + 32);
        ofile.insert(ofile.end(), bind.begin(), bind.end());
        ofile.insert(ofile.end(), ovl.begin(), ovl.end());
        if (!write_snapshot_file(overlay_path_(), ofile, why)) {
            snap_log_(false, std::string("[snapshot] WRITE FAILED (") + occasion + "): " + why);
            return;
        }
        const std::vector<std::uint8_t> file =
            encode_snapshot_envelope(snapshot_key_(), image);
        if (!write_snapshot_file(cfg_.snapshot_path, file, why)) {
            snap_log_(false, std::string("[snapshot] WRITE FAILED (") + occasion + "): " + why);
            return;
        }
        snap_log_(true, std::string("[snapshot] wrote ") + std::to_string(file.size()) + " bytes to "
            + cfg_.snapshot_path + " + " + std::to_string(ofile.size())
            + " bytes output-set overlay (" + std::to_string(outputs_.overlay_block_count())
            + " post-anchor blocks, tip " + std::to_string(set_h) + ") (" + occasion + ")");
    }

    // The output-set flavour of load_snapshot_(). Fail-closed at every step:
    // any refusal leaves outputs_ at the bare anchor snapshot and the index at
    // the confirmed anchor, and the node re-walks from the anchor as before.
    void load_snapshot_with_output_set_() {
        const std::string fallback = "; booting from the confirmed anchor (re-walk)";
        std::vector<std::uint8_t> file, image;
        std::string why;
        if (!read_snapshot_file(cfg_.snapshot_path, file, why)) {
            note_("[snapshot] no resume (" + why + ")" + fallback);
            return;
        }
        if (!decode_snapshot_envelope(file, snapshot_key_(), image, why)) {
            note_("[snapshot] REFUSED: " + why + fallback);
            return;
        }
        std::vector<std::uint8_t> ofile;
        {
            std::ifstream f(overlay_path_(), std::ios::binary);
            if (!f) {
                note_("[snapshot] resume REFUSED: no output-set overlay at " + overlay_path_()
                    + " (an output-set was seeded; the chain image alone cannot resume it)"
                    + fallback);
                return;
            }
            ofile.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
        }
        if (ofile.size() < 32) {
            note_("[snapshot] resume REFUSED: output-set overlay is truncated" + fallback);
            return;
        }
        const Hash bind = image_digest_(image);
        if (!std::equal(bind.begin(), bind.end(), ofile.begin())) {
            note_("[snapshot] resume REFUSED: output-set overlay is bound to a different chain "
                  "image (a stale or foreign overlay)" + fallback);
            return;
        }
        const std::vector<std::uint8_t> ovl(ofile.begin() + 32, ofile.end());
        bool ok = false;
        std::string load_why;
        verify_loop_.call([&] { ok = outputs_.load_overlay(ovl, load_why); });
        if (!ok) {
            note_("[snapshot] resume REFUSED: output-set overlay does not verify: " + load_why
                + fallback);
            return;
        }
        // Then the chain image, through the boot, on the verify thread (see the
        // plain load_snapshot_() path for why both) -- and, in the SAME hop so
        // no block can connect in between, the tip check and the re-seat of the
        // index's output counter. The index image does not carry that counter
        // (seed_direct restarts it from 0 plus the replayed tail); without the
        // re-seat the next block's first_output_index would not be the set's
        // frontier and the set would refuse every new block with outputs.
        bool tip_ok = false;
        std::uint64_t idx_h = 0, set_h = 0;
        verify_loop_.call([&] {
            ok = boot_.resume_from_snapshot(image, load_why);
            if (!ok) { outputs_.drop_overlay(); return; }
            const auto t = index_.tip();
            idx_h  = t ? t->height : 0;
            set_h  = outputs_.tip_height();
            tip_ok = t && t->height == set_h && t->id == outputs_.tip_id();
            if (tip_ok) index_.reseat_rct_output_count(outputs_.frontier());
            else        outputs_.disable_resolution();
        });
        if (!ok) {
            note_("[snapshot] REFUSED: " + load_why + fallback);
            return;
        }
        // The pair was captured at one tip and bound by digest, so the resumed
        // index tip must be the overlay's. If it somehow is not, the index can
        // no longer be un-resumed: ring resolution was disabled above (every
        // ring RingUnresolved) rather than resolve against a set at another
        // height.
        if (!tip_ok) {
            note_("[snapshot] ALARM: resumed index tip " + std::to_string(idx_h)
                + " != output-set overlay tip " + std::to_string(set_h)
                + "; ring resolution DISABLED (fail-closed)");
            return;
        }
        const SyncState st = index_.sync_state();
        note_("[snapshot] RESUMED at height " + std::to_string(st.header_frontier)
            + " from " + cfg_.snapshot_path + " (" + std::to_string(image.size())
            + " bytes) + output-set overlay (" + std::to_string(outputs_.overlay_block_count())
            + " post-anchor blocks, frontier " + std::to_string(outputs_.frontier())
            + ", spent " + std::to_string(outputs_.spent_count())
            + "); no re-walk from the anchor -- ring resolution intact");
    }

    void note_(const std::string& line) {
        std::lock_guard<std::mutex> lk(rec_mu_);
        log_.push_back(line);
        if (log_.size() > 4096) log_.erase(log_.begin());
    }

    // COLD-BOOT-2 (D4a): a snapshot save is reported where the operator reads,
    // not only into log_ (which the pool daemon drains only at boot, so every
    // save -- and every FAILED save -- after start-up was silent). A failure is
    // an ALARM line on stderr and is counted (snapshot_stats()).
    void snap_log_(bool ok, const std::string& line) {
        note_(line);
        {
            std::lock_guard<std::mutex> lk(rec_mu_);
            if (ok) ++snap_ok_; else { ++snap_failed_; snap_last_fail_ = line; }
        }
        if (ok) std::fprintf(stderr, "[native] %s\n", line.c_str());
        else    std::fprintf(stderr, "[native] ALARM snapshot save FAILED: %s\n", line.c_str());
        std::fflush(stderr);
    }

    // --- state --------------------------------------------------------------
    NativeNodeConfig cfg_;
    NetPair          nets_;

    NoPowSource                              null_pow_;
    std::unique_ptr<ThreadWitnessPowSource>  witness_;
#if defined(XMR_NATIVE_NODE_HAVE_RANDOMX)
    std::unique_ptr<::c2pool::xmr::LightVerifier> verifier_;
    std::unique_ptr<LightVerifierPowSource<::c2pool::xmr::LightVerifier>> rx_source_;
#endif

    WorkerLoop     verify_loop_;
    WorkerLoop     pool_loop_;
    // Started only when a snapshot path is configured. A third loop rather than
    // a hop onto one of the two above: a save serializes the index and writes a
    // file, and neither the socket thread nor the block-application thread
    // should ever wait on a disk.
    WorkerLoop     snap_loop_{"snapshot", 8};
    ChainIndex     index_;
    ChainBoot      boot_;
    VerifyInbound  inbound_;
    // The global output set / on-chain spent-key-image view the txpool's
    // input-consensus step resolves rings and double-spends against. Fed from
    // the same connected-block stream as the pool. Declared BEFORE txpool_ so
    // it outlives it (the pool borrows a pointer to it). See start().
    ChainOutputSet outputs_;
    RelayedTxPool  txpool_;
    TxSinkLoop     tx_sink_;
    tmpl::NativeMinerDataSource native_src_;

    // OPERATOR TX-INJECTION state (default-constructed; wired in start() only
    // when cfg_.operator_inject). op_injects_ is the DoS/expiry/order ledger
    // (its own mutex); the two rate limiters keep the operator's Local budget
    // separate from a Peers budget (reserved -- no XMR sharechain inject
    // transport exists yet); inject_gate_mu_ serialises the multi-step gate.
    OperatorInjectPool op_injects_;
    InjectRateLimiter  inject_lim_local_{InjectRateLimiter::Scope::Local};
    InjectRateLimiter  inject_lim_peers_{InjectRateLimiter::Scope::Peers};
    std::mutex         inject_gate_mu_;

    boost::asio::io_context    io_;
    boost::asio::steady_timer  tick_;
    std::thread                io_thread_;
    std::thread::id            io_thread_id_{};
    std::unique_ptr<boost::asio::executor_work_guard<
        boost::asio::io_context::executor_type>> guard_;

    std::shared_ptr<p2p::XmrPeerPool>                pool_;
    std::unique_ptr<MonerodHttp>                     rpc_;
    std::unique_ptr<tmpl::MonerodMinerDataSource>    mon_src_;
    std::unique_ptr<parity::MonerodTipObserver>      mon_tip_;
    std::unique_ptr<parity::MonerodTxpoolObserver>   mon_pool_;
    parity::TxpoolParityTally                        pool_tally_;
    std::unique_ptr<parity::ChainViewTipObserver>    native_tip_;
    // M4 negative control; constructed only when cfg_.tip_fault is armed.
    std::unique_ptr<parity::PerturbingTipObserver>   tip_fault_;
    std::unique_ptr<tmpl::ArmResolver>               arms_;
    std::unique_ptr<relay::LevinBlockRelay>          block_relay_;
    std::unique_ptr<parity::ParityOracle>            oracle_;
    std::unique_ptr<SyncDriver>                      driver_;

    std::atomic<bool>                     running_{false};
    // Set only once gate 4 has settled Confirmed (or the genesis boot needed no
    // gate). Until then no snapshot is read and, more importantly, none is
    // WRITTEN: a start that gate 4 refused must not overwrite a good image.
    std::atomic<bool>                     snap_armed_{false};
    std::atomic<std::uint64_t>            snap_next_ms_{0};
    // The last value published to C3's relay gate; see publish_tx_gate_().
    std::atomic<bool>                     tx_gate_{false};
    std::chrono::steady_clock::time_point epoch_ = std::chrono::steady_clock::now();

    mutable std::mutex        rec_mu_;
    std::vector<TipRecord>    tips_;
    std::vector<std::string>  log_;
    // M3 tip feed (see drain_mainchain_events). Same mutex as tips_/log_: these
    // are all written from the verify thread and read from the consumer's.
    std::vector<node::MainchainEvent> chain_events_;
    std::uint64_t                     chain_events_seen_ = 0;
    std::uint64_t                     snap_ok_ = 0, snap_failed_ = 0;   // COLD-BOOT-2: snapshot saves (rec_mu_)
    std::string                       snap_last_fail_;
};

} // namespace c2pool::xmr::native::rt
