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
// WHAT IS DELIBERATELY NOT DRIVEN HERE. C5's relay is CONSTRUCTED and its 2009
// responder is armed, but nothing in M0 calls relay(): a found block comes from
// the stratum/settlement path, which is M3. C4's arms are constructed and
// readable; rebinding the option-B settlement provider through them is M2.
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

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
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
#include "impl/xmr/native/chain/xmr_pow_gate.hpp"
#include "impl/xmr/native/node/xmr_chain_boot.hpp"
#include "impl/xmr/native/node/xmr_monerod_http.hpp"
#include "impl/xmr/native/node/xmr_sync_driver.hpp"
#include "impl/xmr/native/node/xmr_worker_loops.hpp"
#include "impl/xmr/native/p2p/chain_seeds.hpp"
#include "impl/xmr/native/p2p/xmr_peer_pool.hpp"
#include "impl/xmr/native/parity/xmr_parity_oracle.hpp"
#include "impl/xmr/native/parity/xmr_parity_report.hpp"
#include "impl/xmr/native/parity/xmr_txpool_parity.hpp"
#include "impl/xmr/native/relay/xmr_block_relay.hpp"
#include "impl/xmr/native/template/xmr_monerod_miner_data.hpp"
#include "impl/xmr/native/template/xmr_native_miner_data.hpp"
#include "impl/xmr/native/template/xmr_template_arm.hpp"
#include "impl/xmr/native/txpool/xmr_relayed_txpool.hpp"

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

    TemplateArm              serve_arm = TemplateArm::Native;
    ArmOrder                 relay_order = ArmOrder::DaemonFirst;   // see the owed ruling

    // READ-ONLY PROBE against somebody else's daemon: handshake, TIMED_SYNC,
    // one NOTIFY_REQUEST_CHAIN, and not one block requested. See
    // SyncDriverConfig::probe_only.
    bool                     probe_only = false;

    std::uint64_t            driver_tick_ms = 500;
    std::size_t              verify_queue   = 4096;
    std::size_t              txpool_queue   = 2048;

    // OR-C2-8: on a private chain with one pinned peer the cohort test cannot
    // distinguish "at the tip" from "alone", so the publication gate is set
    // rather than inferred -- and the status line says it was forced.
    bool                     force_synced = false;
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
    std::string                  template_arm;
    std::string                  io_threads;
    std::string                  verify_thread;
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
        if (cfg_.boot == BootMode::Anchor) {
            // The 60 timestamps are not in the bundle by its own contract; the
            // state treats a short window as "no median", which is why an empty
            // vector is a degraded-but-honest boot rather than a wrong one.
            if (!boot_.boot_from_anchor(cfg_.anchor_path, nets_.consensus, {}, why))
                return false;
        }

        index_.set_clock([] { return unix_seconds_(); });
        if (cfg_.force_synced) index_.force_synced(true);

        // Every tip the index adopts is recorded here and handed to the parity
        // oracle. This runs ON THE VERIFY THREAD (the index flushes its events
        // after releasing its own lock), which is what makes the native
        // observation the oracle takes later safe to read.
        index_.subscribe([this](const node::MainchainEvent& ev) { on_mainchain_(ev); });
        index_.subscribe_txs([this](const BlockTxEvent& ev) {
            // C2 -> C3: drop mined ids, evict key-image conflicts, re-admit on a
            // rollback. Posted to the pool thread for the same reason the relay
            // path is: it re-decodes bodies.
            pool_loop_.post([this, ev] {
                if (ev.kind == BlockTxEvent::Kind::Connected) txpool_.on_block_connected(ev);
                else                                          txpool_.on_block_disconnected(ev);
            });
        });

        verify_loop_.start();
        pool_loop_.start();

        // --- the daemon arm (parity / backup only) ---------------------------
        if (!cfg_.monerod_rpc_host.empty() && cfg_.monerod_rpc_port != 0) {
            rpc_    = std::make_unique<MonerodHttp>(cfg_.monerod_rpc_host, cfg_.monerod_rpc_port);
            mon_src_ = std::make_unique<tmpl::MonerodMinerDataSource>(*rpc_);
            mon_tip_ = std::make_unique<parity::MonerodTipObserver>(*rpc_);
            // M1's P-POOL arm. Constructed whenever a daemon endpoint is, so
            // that "the probe was never armed" is impossible to confuse with
            // "the probe found nothing": without an arm txpool_parity_sample()
            // returns an UNJUDGED report that says so.
            mon_pool_ = std::make_unique<parity::MonerodTxpoolObserver>(*rpc_);
        }

        tmpl::TemplateArmConfig arm_cfg;
        arm_cfg.serve = cfg_.serve_arm;
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
        if (cfg_.probe_only) {
            // A READ-ONLY probe dials exactly what it was told to dial. The
            // pool learns addresses from the handshake peerlist and the plan
            // refills toward its target, so a probe left on the default would
            // quietly open connections to strangers on the public network --
            // observed once against stagenet, where the probe dialed a peer it
            // had just learned from the daemon it was probing.
            pc.dial.target_outbound      = cfg_.connect.size();
            pc.dial.max_outbound         = cfg_.connect.size();
            pc.dial.max_concurrent_dials = cfg_.connect.size();
            pc.use_seeds                 = false;
        }
        pc.use_seeds              = cfg_.use_seeds;

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
            parity::ParityOracle::Deps od;
            od.native_tip  = native_tip_.get();
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
            [this] { return index_.refetch_wanted(); }, dcfg);

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
        arm_tick_();
        return true;
    }

    void stop() {
        if (!running_.exchange(false)) return;
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
        if (witness_) s.randomx = witness_->witness();
        s.randomx_mode = index_.pow_gate().mode();
        if (arms_)    s.template_arm = arms_->describe();
        // The driver's counters are only ever written on the verify thread, so
        // they are read there too rather than racing them.
        verify_loop_.call([this, &s] { if (driver_) s.driver = driver_->stats(); });
        s.io_threads   = thread_id_string_(io_thread_id_);
        s.verify_thread = thread_id_string_(verify_loop_.thread_id());
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

    parity::ParityOracle* oracle() noexcept { return oracle_.get(); }
    ChainIndex&           index()  noexcept { return index_; }
    RelayedTxPool&        txpool() noexcept { return txpool_; }
    tmpl::ArmResolver*    arms()   noexcept { return arms_.get(); }
    const NativeNodeConfig& config() const noexcept { return cfg_; }
    const NetPair&          nets()   const noexcept { return nets_; }

    // Force the publication gate after the fact (the regtest / single-peer case).
    void force_synced(bool v) { index_.force_synced(v); }

private:
    // --- construction helpers (called from the member initialiser list) -----
    ChainIndexOptions make_index_options_() const {
        ChainIndexOptions o;
        o.net = nets_.consensus;
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

    void arm_tick_() {
        if (!running_) return;
        tick_.expires_after(std::chrono::milliseconds(cfg_.driver_tick_ms));
        tick_.async_wait([this](const boost::system::error_code& ec) {
            if (ec || !running_) return;
            const std::uint64_t now = now_ms_();
            verify_loop_.post([this, now] {
                                  if (driver_) driver_->tick(now);
                                  publish_tx_gate_();
                              },
                              /*control=*/true);
            arm_tick_();
        });
    }

    std::uint64_t now_ms_() const {
        using namespace std::chrono;
        return static_cast<std::uint64_t>(
            duration_cast<milliseconds>(steady_clock::now() - epoch_).count());
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

    void note_(const std::string& line) {
        std::lock_guard<std::mutex> lk(rec_mu_);
        log_.push_back(line);
        if (log_.size() > 4096) log_.erase(log_.begin());
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
    ChainIndex     index_;
    ChainBoot      boot_;
    VerifyInbound  inbound_;
    RelayedTxPool  txpool_;
    TxSinkLoop     tx_sink_;
    tmpl::NativeMinerDataSource native_src_;

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
    std::unique_ptr<tmpl::ArmResolver>               arms_;
    std::unique_ptr<relay::LevinBlockRelay>          block_relay_;
    std::unique_ptr<parity::ParityOracle>            oracle_;
    std::unique_ptr<SyncDriver>                      driver_;

    std::atomic<bool>                     running_{false};
    // The last value published to C3's relay gate; see publish_tx_gate_().
    std::atomic<bool>                     tx_gate_{false};
    std::chrono::steady_clock::time_point epoch_ = std::chrono::steady_clock::now();

    mutable std::mutex        rec_mu_;
    std::vector<TipRecord>    tips_;
    std::vector<std::string>  log_;
};

} // namespace c2pool::xmr::native::rt
