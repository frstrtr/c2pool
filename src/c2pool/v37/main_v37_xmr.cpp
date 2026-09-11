// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/main_v37_xmr.cpp   (Track A2 / Milestone A — the live daemon)
//
// c2pool-v37-xmr — the single-node, stagenet/regtest-capable Monero/RandomX
// (Family-B) v37 daemon entrypoint. It stands up XmrNode (see xmr/xmr_node.hpp)
// against a live monerod and runs the mine-and-settle path.
//
// EXPERIMENTAL — PROTOTYPE / STAGENET / REGTEST ONLY. Do NOT run against
// mainnet value. The default network is stagenet; mainnet requires
// --i-understand-mainnet and is still fenced at the coinbase (FCMP/CARROT +
// mainnet acknowledgement).
//
// Modes:
//   --mock-smoke    network-free CI smoke against a monerod STUB
//                   (MockMonerodTransport); prints S1..S6 + FC1..FC16 and exits.
//   (default)       connect to monerod at --rpc-host/--rpc-port (+ --zmq-port),
//                   bring the node up, and run until SIGINT. With
//                   --payout-address the X9 O-2 SERVE SIDE is up as well:
//                   the stratum port is bound and miners are served.
//
// X9 O-2 — the SERVE side, assembled here in donor order (xmr/ headers):
//   wire 1  xmr_stratum_listener.hpp   POSIX poll() listener = the X5 server's
//                                      ITransport; login/job/submit/keepalived
//                                      in the xmrig dialect; NEW-TEMPLATE PUSH.
//   wire 2  xmr_o2_randomx_verify.hpp  IPowVerifier over the production light
//                                      RandomX verifier (librandomx, under
//                                      V37_XMR_O2_WITH_RANDOMX + --randomx);
//                                      every submit is RE-HASHED here, and the
//                                      EXACT 128-bit network rule gates submit.
//   wire 3  xmr_live_submit.hpp        block blob = monerod template + nonce ->
//                                      submit_block -> block_id resolved
//                                      (monerod > local keccak > header).
//   wire 4  xmr_o2_finalize_connect.hpp  FOUND -> XmrNode::on_network_block_won
//                                      -> F1 driver; FINALIZE at D_conf burial;
//                                      pending-FOUND sidecar across restarts.
//   xmr_o2_template.hpp                monerod get_block_template provider +
//                                      the ITemplateSource seam.
// HONEST SCOPE (option A): the block bytes are monerod's own template (single
// coinbase to --payout-address) with the winning nonce patched — a genuine,
// monerod-validated block end to end, NOT yet the v37 K_fair settlement
// coinbase (option B = XmrBlockTemplate + X6 over an implemented
// xmr_coin_primitives seam; slots in behind the same two seams).
//
// THREADING: the listener thread owns sockets, sessions, the X5 server, the
// RandomX verifier and the submit_block RPC; the main thread owns XmrNode /
// MonerodAdapter / MainchainIndex / XmrFinalizeDriver / OwedLedger, the
// template refresh and all stdout. The template snapshot (mutex) and the found
// queues (mutex) are the only state that crosses.
//
// NOTE (single-node): real multi-node p2p carrier relay (src/pool p2p) is a
// NOTED FOLLOW-ON. This cut runs single-node (its own carriers), enough for the
// X9 mine-and-settle demo. The light build (no XMR_BUILD_RANDOMX) still runs
// index + settlement + the F1 driver and can serve miners, but answers every
// submit "Couldn't check PoW" and never promotes a block (fail-closed).
// ===========================================================================

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

#include "xmr/xmr_node.hpp"
#include "xmr/xmr_node_config.hpp"
#include "xmr/xmr_node_smoke.hpp"
#include "xmr/xmr_live_transport.hpp"
#include "xmr/xmr_o2_template.hpp"           // O-2: monerod template provider + ITemplateSource (option A)
#include "xmr/xmr_o2_randomx_verify.hpp"     // O-2 wire 2: runtime RandomX IPowVerifier + exact gate
#include "xmr/xmr_live_submit.hpp"           // O-2 wire 3: block-blob assembly + submit_block
#include "xmr/xmr_stratum_listener.hpp"      // O-2 wire 1: POSIX stratum listener (ITransport)
#include "xmr/xmr_o2_finalize_connect.hpp"   // O-2 wire 4: FOUND -> on_network_block_won -> F1
#include "xmr/xmr_o2_settlement_fixture.hpp"  // O-2 option B: XmrSettlementConfig + XmrOwedFixture (proof ledger)
#include "xmr/xmr_o2_settlement_provider.hpp" // O-2 option B: v37 K_fair settlement template provider + source
#include "xmr/xmr_settlement_coinbase_shape.hpp"  // M2: the K_fair shape gate, read off the assembled block bytes
#include "xmr/xmr_native_template_backend.hpp"    // M2: the native-minimal Monero node as the miner-data source

using namespace c2pool::v37n::xmr;
namespace strat = ::v37::xmr::stratum;
namespace sub   = c2pool::v37n::xmr::submit;
namespace node  = ::c2pool::xmr::node;

#if __has_include(<c2pool_build_version.h>)
#include <c2pool_build_version.h>
#else
#define C2POOL_VERSION "unknown"
#endif

// ---------------------------------------------------------------------------
// The daemon's Monero network, as the native node's TWO answers to "which
// network". regtest (monerod --regtest) is the case that makes them separate
// facts rather than one: FAKECHAIN carries the MAINNET network id and genesis
// on the wire while running a hard-fork table that is neither. NativeNet is the
// enum that resolves both, and this is the only place the daemon's own
// MoneroNetwork is mapped onto it.
// ---------------------------------------------------------------------------
static inline ::c2pool::xmr::native::rt::NativeNet native_net_of(MoneroNetwork n) {
    using NN = ::c2pool::xmr::native::rt::NativeNet;
    switch (n) {
        case MoneroNetwork::Mainnet:  return NN::Mainnet;
        case MoneroNetwork::Testnet:  return NN::Testnet;
        case MoneroNetwork::Stagenet: return NN::Stagenet;
        case MoneroNetwork::Regtest:  return NN::Regtest;
    }
    return NN::Stagenet;
}

static std::atomic<bool> g_stop{false};
static void on_sigint(int) { g_stop.store(true); }

static MoneroNetwork parse_net(const std::string& s) {
    if (s == "mainnet")  return MoneroNetwork::Mainnet;
    if (s == "testnet")  return MoneroNetwork::Testnet;
    if (s == "regtest")  return MoneroNetwork::Regtest;
    return MoneroNetwork::Stagenet;
}

static int run_mock_smoke() {
    std::filesystem::path tmp =
        std::filesystem::temp_directory_path() /
        ("c2pool-v37-xmr-smoke-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);

    auto rep = smoke::run(tmp);
    // O-2 wire 4: the finalize-connect self-check (network-free, RandomX-free)
    // rides in the same report so `--mock-smoke` gates FOUND -> FINALIZE too.
    auto fc = o2::finalize_connect_selfcheck(tmp / "fc");
    for (const auto& c : fc.checks) rep.checks.push_back(c);

    std::printf("== c2pool-v37-xmr mock smoke ==\n");
    int fails = 0;
    for (const auto& c : rep.checks) {
        std::printf("  [%s] %s%s%s\n", c.pass ? "PASS" : "FAIL", c.name.c_str(),
                    c.detail.empty() ? "" : "  — ", c.detail.c_str());
        if (!c.pass) ++fails;
    }
    std::printf("== %s (%d/%zu passed) ==\n", fails ? "FAIL" : "OK",
                static_cast<int>(rep.checks.size()) - fails, rep.checks.size());
    std::filesystem::remove_all(tmp);
    return fails ? 1 : 0;
}

// ---------------------------------------------------------------------------
// The EXACT network gate in front of the live submitter (listener thread).
//
// XmrStratumServer's own "network block" decision (top-64-bit word <= target,
// xmr_stratum.cpp handle_submit) is a strict SUPERSET of Monero's rule — it can
// pass a boundary hash monerod would reject. So the bytes the server just
// hashed are re-checked here with O2RandomXVerifier::verify_network_block
// (hash * difficulty < 2^256, 128-bit, reusing the memoised hash) and ONLY an
// Accept reaches LiveSubmitShareSink -> submit_block. Fail-closed: with RandomX
// compiled out / disabled / not initialised nothing is ever submitted.
// ---------------------------------------------------------------------------
// Templated on the template PROVIDER + its SNAPSHOT type so BOTH the option-A
// monerod provider (MonerodTemplateProvider / MonerodTemplate) and the option-B
// v37 settlement provider (XmrSettlementTemplateProvider / SettlementSnapshot)
// drive the identical exact 128-bit gate. Snapshot needs only .difficulty and
// .difficulty_top64; Provider needs by_id(id, Snapshot&).
template <class Provider, class Snapshot>
class GatedShareSinkT final : public strat::IShareSink {
public:
    GatedShareSinkT(o2::O2RandomXVerifier& rx, const Provider& provider,
                    strat::ITemplateSource& source, sub::LiveSubmitShareSink& inner)
        : m_rx(rx), m_provider(provider), m_source(source), m_inner(inner) {}

    void on_accepted_share(const strat::AcceptedShare& s) override { m_inner.on_accepted_share(s); }

    void submit_network_block(std::uint32_t template_id, std::uint32_t nonce,
                              std::uint32_t extra_nonce) override {
        m_calls.fetch_add(1, std::memory_order_relaxed);
        strat::TemplateJob tj;
        Snapshot t;
        if (!m_source.rebuild_blob(template_id, extra_nonce, tj) ||
            !m_provider.by_id(template_id, t) ||
            tj.nonce_offset + strat::NONCE_SIZE > tj.blob.size()) {
            m_stale.fetch_add(1, std::memory_order_relaxed);
            set_last("template " + std::to_string(template_id) + " gone (stale)");
            return;
        }
        for (std::size_t i = 0; i < strat::NONCE_SIZE; ++i)   // == the bytes the server hashed
            tj.blob[tj.nonce_offset + i] = static_cast<std::uint8_t>(nonce >> (8 * i));
        if (!m_rx.network_blocks_allowed()) {
            m_refused.fetch_add(1, std::memory_order_relaxed);
            set_last(std::string("refused: randomx ") + o2::O2RandomXVerifier::to_string(m_rx.mode()) +
                     " (fail-closed, no submit)");
            return;
        }
        o2::Hash32 pow{};
        const o2::NetworkVerdict v = m_rx.verify_network_block(
            tj.blob.data(), tj.blob.size(), tj.seed_hash,
            o2::NetworkDifficulty{t.difficulty, t.difficulty_top64}, pow);
        if (v != o2::NetworkVerdict::Accept) {
            m_rejected.fetch_add(1, std::memory_order_relaxed);
            set_last(std::string("exact network gate: ") + o2::to_string(v) + " (no submit)");
            return;
        }
        m_accepted.fetch_add(1, std::memory_order_relaxed);
        set_last("exact network gate: Accept pow=" + sub::to_hex(pow.data(), pow.size()));
        m_inner.submit_network_block(template_id, nonce, extra_nonce);
    }

    std::uint64_t calls()    const { return m_calls.load(std::memory_order_relaxed); }
    std::uint64_t accepted() const { return m_accepted.load(std::memory_order_relaxed); }
    std::uint64_t rejected() const { return m_rejected.load(std::memory_order_relaxed); }
    std::uint64_t refused()  const { return m_refused.load(std::memory_order_relaxed); }
    std::uint64_t stale()    const { return m_stale.load(std::memory_order_relaxed); }
    std::string last() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_last;
    }

private:
    void set_last(std::string s) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_last = std::move(s);
    }
    o2::O2RandomXVerifier&              m_rx;
    const Provider&                     m_provider;
    strat::ITemplateSource&             m_source;
    sub::LiveSubmitShareSink&           m_inner;
    std::atomic<std::uint64_t> m_calls{0}, m_accepted{0}, m_rejected{0}, m_refused{0}, m_stale{0};
    mutable std::mutex m_mtx;
    std::string        m_last;
};

// The reward a snapshot's coinbase pays, and a one-line kind-specific tail for
// the template log. Overloaded so serve_and_run() stays provider-agnostic.
static inline std::uint64_t snap_reward(const o2::MonerodTemplate& t)    { return t.expected_reward; }
static inline std::uint64_t snap_reward(const o2::SettlementSnapshot& t) { return t.reward; }
static inline std::string   snap_extra(const o2::MonerodTemplate& t) {
    return "hashing=" + std::to_string(t.hashing_blob.size()) + "B full=" + std::to_string(t.full_blob.size()) + "B";
}
static inline std::string   snap_extra(const o2::SettlementSnapshot& t) {
    return "outputs=" + std::to_string(t.n_outputs) + " n_tx=" + std::to_string(t.n_tx) +
           " (v37 K_fair settlement coinbase)";
}

// ---------------------------------------------------------------------------
// Optional per-loop hooks. Option A installs none; option B uses them for the
// M2 evidence: the parity sample is drained off the serve path (the DASH
// shadow-compare rule -- a probe never sits in front of a miner) and the
// template-path RPC delta is reported next to the template counters.
// ---------------------------------------------------------------------------
struct ServeHooks {
    // Called after every provider.refresh(), with its verdict and whether the
    // template id moved. Never called when the pool is not serving.
    std::function<void(bool /*refreshed*/, bool /*new_template*/)> after_refresh;
    // Called from the status cadence, after the standard status line.
    std::function<void()> status_extra;
};

// ---------------------------------------------------------------------------
// serve_and_run — the serve side + main loop + teardown, generic over the
// template PROVIDER / SNAPSHOT / SOURCE so option A (monerod template) and
// option B (v37 settlement coinbase) share ONE body. Provider must expose
// refresh()/template_id()/current()->Snapshot/by_id(id,Snapshot&)/last_error()/
// offset_note()/refreshes()/failures()/changes(); Snapshot must expose
// template_id/height/difficulty/difficulty_top64/major_version/nonce_offset/
// prev_id (+ the reward/extra via snap_reward()/snap_extra()); Source is a
// strat::ITemplateSource. `candidate_lookup` maps (template_id, extra_nonce) to
// a submit::BlockCandidate for the live submitter (mode-specific).
// ---------------------------------------------------------------------------
template <class Provider, class Source>
static int serve_and_run(const XmrNodeConfig& cfg, LiveMonerodTransport& transport,
                         XmrNode& node, o2::FinalizeConnect& fc, o2::FoundBlockQueue& found_q,
                         const std::optional<::v37::bytes32>& payee_key, o2::O2RandomXVerifier& rx,
                         bool serving, const char* not_served_reason,
                         Provider& provider, Source& template_source,
                         sub::LiveSubmitShareSink::CandidateLookup candidate_lookup,
                         ServeHooks hooks = {}) {
    using Snapshot = std::decay_t<decltype(provider.current())>;

    sub::LiveBlockSubmitter submitter(transport);   // fresh socket per RPC: safe off-thread
    sub::FoundBlockQueue    submit_q;
    sub::LiveSubmitShareSink live_sink(submitter, submit_q, std::move(candidate_lookup));
    submitter.enable_network_submit(rx.network_blocks_allowed());   // fail-closed gate
    GatedShareSinkT<Provider, Snapshot> sink(rx, provider, template_source, live_sink);

    o2::StratumListenerOptions lo;
    lo.bind_host = cfg.stratum_bind_host;
    lo.bind_port = cfg.stratum_bind_port;
    o2::StratumListener listener(template_source, rx, sink, lo);
    // Seed prefetch on the LISTENER thread, before jobs are pushed (Argon2d
    // cache init never lands inside a miner's submit).
    listener.set_template_hook([&](const strat::TemplateJob& peek) { rx.on_template(peek); });

    std::uint32_t last_tid = 0;
    if (serving) {
        if (std::string e = listener.bind(); !e.empty()) {
            std::printf("%s\n", e.c_str());
            node.stop();
            return 1;
        }
        // First template BEFORE start(): the dirty flag is latched and consumed
        // on the loop's first pass, so the first logins are served immediately.
        if (provider.refresh()) {
            last_tid = provider.template_id();
            listener.notify_new_template();
            const Snapshot t = provider.current();
            std::printf("template: id=%u height=%llu difficulty=%llu%s reward=%llu piconero "
                        "major=%u nonce_offset=%zu %s%s%s\n",
                        t.template_id, static_cast<unsigned long long>(t.height),
                        static_cast<unsigned long long>(t.difficulty),
                        t.difficulty_top64 ? " (+top64)" : "",
                        static_cast<unsigned long long>(snap_reward(t)),
                        static_cast<unsigned>(t.major_version), t.nonce_offset,
                        snap_extra(t).c_str(),
                        provider.offset_note().empty() ? "" : " ",
                        provider.offset_note().c_str());
        } else {
            std::printf("template: first build FAILED: %s (miners are parked until it "
                        "succeeds; %s coinbase)\n",
                        provider.last_error().c_str(), to_string(cfg.coinbase));
        }
        listener.start();
        std::printf("stratum: listening on %s:%u (%s coinbase, share diff %s, network submit %s)\n",
                    cfg.stratum_bind_host.c_str(), listener.bound_port(), to_string(cfg.coinbase),
                    cfg.stratum_share_diff ? std::to_string(cfg.stratum_share_diff).c_str() : "network",
                    submitter.network_submit_enabled() ? "ENABLED" : "DISABLED (fail-closed)");
    } else {
        std::printf("stratum: NOT served (%s) — observe-side only\n", not_served_reason);
    }

    std::signal(SIGINT, on_sigint);
    std::signal(SIGTERM, on_sigint);
    const std::uint32_t poll_ms = cfg.poll_ms ? cfg.poll_ms : 5000;
    std::printf("node up. Ctrl-C to stop. (ZMQ push drives the tip; RPC poll fallback every %u ms)\n",
                poll_ms);

    auto bridge_found = [&]() {
        sub::FoundBlockEvent s;
        while (submit_q.pop(s)) {
            std::printf("  [submit] %s\n", sub::describe(s).c_str());
            o2::FoundBlockEvent e;
            e.height          = s.height;
            e.block_id_hex    = hex_of(s.block_id);
            e.prev_id_hex     = hex_of(s.prev_id);
            e.reward_piconero = s.reward;
            e.payee           = payee_key;
            e.template_id     = s.template_id;
            e.nonce           = s.nonce;
            e.extra_nonce     = s.extra_nonce;
            e.worker          = s.worker;
            e.address         = s.address;
            found_q.push(std::move(e));
        }
    };
    auto drain_stratum_log = [&]() {
        for (const auto& l : listener.drain_log()) std::printf("  [stratum] %s\n", l.c_str());
    };
    auto status = [&]() {
        const auto ls = listener.stats();
        const auto fs = fc.stats();
        const Snapshot t = provider.current();
        std::printf("status: hw=%llu cursor=%llu tip=%llu | template id=%u h=%llu diff=%llu "
                    "refresh=%llu fail=%llu changes=%llu | stratum conn=%llu active=%llu logins=%llu "
                    "submits=%llu shares=%llu net=%llu rejected=%llu pushes=%llu malformed=%llu | "
                    "gate calls=%llu accept=%llu reject=%llu refused=%llu stale=%llu | "
                    "submit calls=%zu ok=%zu rejected=%zu refused=%zu transport_err=%zu "
                    "id_mismatch=%zu unattributable=%zu | found registered=%llu settled=%llu "
                    "orphaned=%llu refused=%llu pending=%zu\n",
                    static_cast<unsigned long long>(node.hw().hw_height),
                    static_cast<unsigned long long>(node.finalize_driver().cursor_height()),
                    static_cast<unsigned long long>(node.adapter().index().best_height()),
                    t.template_id, static_cast<unsigned long long>(t.height),
                    static_cast<unsigned long long>(t.difficulty),
                    static_cast<unsigned long long>(provider.refreshes()),
                    static_cast<unsigned long long>(provider.failures()),
                    static_cast<unsigned long long>(provider.changes()),
                    static_cast<unsigned long long>(ls.connections),
                    static_cast<unsigned long long>(ls.active),
                    static_cast<unsigned long long>(ls.logins),
                    static_cast<unsigned long long>(ls.submits),
                    static_cast<unsigned long long>(ls.accepted_shares),
                    static_cast<unsigned long long>(ls.network_blocks),
                    static_cast<unsigned long long>(ls.rejected_submits),
                    static_cast<unsigned long long>(ls.job_pushes),
                    static_cast<unsigned long long>(ls.malformed),
                    static_cast<unsigned long long>(sink.calls()),
                    static_cast<unsigned long long>(sink.accepted()),
                    static_cast<unsigned long long>(sink.rejected()),
                    static_cast<unsigned long long>(sink.refused()),
                    static_cast<unsigned long long>(sink.stale()),
                    submitter.calls(), submitter.ok(), submitter.rejected(), submitter.refused(),
                    submitter.transport_errors(), submitter.id_mismatches(), submitter.unattributable(),
                    static_cast<unsigned long long>(fs.registered),
                    static_cast<unsigned long long>(fs.settled),
                    static_cast<unsigned long long>(fs.orphaned),
                    static_cast<unsigned long long>(fs.refused),
                    fc.pending().size());
        std::printf("  %s\n", rx.describe().c_str());
        const std::string g = sink.last();
        if (!g.empty()) std::printf("  gate: last=%s\n", g.c_str());
        const std::string se = submitter.last_error();
        if (!se.empty()) std::printf("  submit: last_error=%s\n", se.c_str());
        std::fflush(stdout);
    };

    auto last_status = std::chrono::steady_clock::now();
    std::string last_template_err;
    while (!g_stop.load()) {
        bridge_found();
        fc.tick();
        transport.pump_poll();
        node.adapter().ensure_seed_reach();
        if (serving) {
            const bool refreshed = provider.refresh();
            bool new_template = false;
            if (refreshed) {
                const std::uint32_t tid = provider.template_id();
                if (tid != last_tid) {
                    last_tid = tid;
                    new_template = true;
                    listener.notify_new_template();
                    const Snapshot t = provider.current();
                    std::printf("template: id=%u height=%llu difficulty=%llu prev=%s… reward=%llu -> "
                                "pushed to miners\n",
                                t.template_id, static_cast<unsigned long long>(t.height),
                                static_cast<unsigned long long>(t.difficulty),
                                hex_of(t.prev_id).substr(0, 12).c_str(),
                                static_cast<unsigned long long>(snap_reward(t)));
                }
            } else {
                const std::string e = provider.last_error();
                if (e != last_template_err) {
                    std::printf("template: refresh failed: %s\n", e.c_str());
                    last_template_err = e;
                }
            }
            if (hooks.after_refresh) hooks.after_refresh(refreshed, new_template);
        }
        drain_stratum_log();
        if (cfg.status_every_s &&
            std::chrono::steady_clock::now() - last_status >= std::chrono::seconds(cfg.status_every_s)) {
            status();
            if (hooks.status_extra) hooks.status_extra();
            last_status = std::chrono::steady_clock::now();
        }
        std::fflush(stdout);
        std::this_thread::sleep_for(std::chrono::milliseconds(poll_ms));
    }

    std::printf("\nstopping…\n");
    listener.stop();
    drain_stratum_log();
    bridge_found();
    fc.drain_before_stop();
    node.stop();
    status();
    if (hooks.status_extra) hooks.status_extra();
    std::printf("stopped. hw_height=%llu\n",
                static_cast<unsigned long long>(node.hw().hw_height));
    return 0;
}

static int run_live(const XmrNodeConfig& cfg) {
    std::printf("c2pool-v37-xmr: EXPERIMENTAL prototype — network=%s monerod=%s:%u (zmq %u)\n",
                to_string(cfg.network), cfg.monerod.rpc_host.c_str(),
                cfg.monerod.rpc_port, cfg.monerod.zmq_port);
    if (cfg.network == MoneroNetwork::Mainnet && !cfg.i_understand_mainnet) {
        std::printf("REFUSED: mainnet requires --i-understand-mainnet (prototype safety)\n");
        return 2;
    }

    LiveMonerodTransport transport(cfg.monerod);
    XmrNode node(cfg, transport);
    try {
        node.bring_up();
    } catch (const std::exception& e) {
        std::printf("bring_up FAILED: %s\n", e.what());
        return 1;
    }
    for (const auto& line : node.construction_log()) std::printf("  %s\n", line.c_str());

    // ── wire 4: finalize connect (main thread) — BEFORE the listener and BEFORE
    //    the first pump_poll, so a pending FOUND from the sidecar is re-driven
    //    into the fresh driver before any Extend can step past its height.
    o2::FoundBlockQueue found_q;
    o2::FinalizeConnectOptions fo;
    if (cfg.found_sidecar) fo.sidecar_path = cfg.resolved_settle_db_path() + "/pfound.tsv";
    o2::FinalizeConnect fc(node, cfg, found_q, fo);
    {
        const auto boot = fc.reseed_after_bring_up();
        std::printf("finalize-connect: sidecar=%s reseeded=%zu reregistered=%zu stale=%zu "
                    "UNRECOVERABLE=%zu malformed=%zu (D_conf=%llu)\n",
                    fo.sidecar_path.empty() ? "disabled" : (boot.sidecar_present ? "present" : "none"),
                    boot.reseeded, boot.reregistered, boot.stale_dropped, boot.unrecoverable,
                    boot.malformed, static_cast<unsigned long long>(cfg.d_conf));
    }

    // ── payee identity key (the address boundary's OUTPUT) ───────────────────
    std::optional<::v37::bytes32> payee_key;
    if (!cfg.payee_spend_key_hex.empty() || !cfg.payee_view_key_hex.empty()) {
        o2::PayeeKeys pk;
        if (!o2::hash_from_hex(cfg.payee_spend_key_hex, pk.spend) ||
            !o2::hash_from_hex(cfg.payee_view_key_hex, pk.view)) {
            std::printf("REFUSED: --payee-spend-hex and --payee-view-hex must both be 64 hex chars\n");
            node.stop();
            return 2;
        }
        pk.subaddress = cfg.payee_subaddress;
        payee_key = o2::payee_identity_key(pk);
        if (!payee_key) {
            std::printf("REFUSED: payee keys do not validate as an XMR payout descriptor "
                        "(ed25519 point check) — no ledger key\n");
            node.stop();
            return 2;
        }
        std::printf("payee: identity_key=%s… (amount-honest FOUND/FINALIZE records)\n",
                    hex_of(*payee_key).substr(0, 16).c_str());
    } else {
        std::printf("payee: no --payee-spend-hex/--payee-view-hex -> FOUND records are valueless "
                    "{}/{} (the ledger still registers the block)\n");
    }

    // ── wire 2: RandomX runtime verify (init on main, BEFORE the listener) ───
    o2::O2RandomXVerifier rx;
    rx.init(o2::RandomXPolicy::from_config(cfg));
    std::printf("  %s\n", rx.describe().c_str());
    if (cfg.randomx_enabled && !rx.ready()) {
        std::printf("REFUSED: --randomx requested but RandomX is %s "
                    "(build with -DXMR_BUILD_RANDOMX=ON / check memory)\n",
                    o2::O2RandomXVerifier::to_string(rx.mode()));
        node.stop();
        return 3;
    }
    if (!rx.ready())
        std::printf("WARNING: RandomX verify %s — every stratum submit is answered "
                    "\"Couldn't check PoW\"; network-block promotion is refused (fail-closed)\n",
                    o2::O2RandomXVerifier::to_string(rx.mode()));

    // ── the template + wire 3 (live submit) + wire 1 (listener) ─────────────
    // Branch on the coinbase mode. Option A (monerod template) is byte-identical
    // to PR #1534; option B (v37 settlement coinbase) drives the SAME listener /
    // RandomX gate / live submitter / finalize-connect through serve_and_run.
    if (cfg.coinbase == CoinbaseMode::V37Settlement) {
        // fail-closed: v37 mode serves only with a torsion-valid residual sink.
        const bool serving =
            !cfg.residual_sink_spend_hex.empty() && !cfg.residual_sink_view_hex.empty();

        o2::XmrSettlementConfig scfg;
        scfg.chain_id   = cfg.lane_chain;
        scfg.h_min      = cfg.settle_h_min;
        scfg.output_cap = cfg.settle_output_cap;
        std::array<std::uint8_t, 32> sink_B{}, sink_A{};
        if (serving) {
            if (!o2::hex32(cfg.residual_sink_spend_hex, sink_B) ||
                !o2::hex32(cfg.residual_sink_view_hex, sink_A) ||
                !scfg.set_residual_sink_hex(cfg.residual_sink_spend_hex, cfg.residual_sink_view_hex,
                                            cfg.residual_sink_subaddress)) {
                std::printf("REFUSED: --residual-sink-spend-hex/--residual-sink-view-hex must both be "
                            "64 hex chars (the XMR wallet the exact-sum residual is paid to)\n");
                node.stop();
                return 2;
            }
        }

        // The proof ledger (no live S-1 emission yet). Empty => the whole reward
        // flows to the residual sink (one v37 output). --owed-demo-amount seeds a
        // distinct K_fair OWED payee (the sink material with spend/view swapped —
        // still two valid ed25519 points, a different identity) so the assembled
        // coinbase carries an OWED output alongside the sink (multi-output proof).
        o2::XmrOwedFixture ledger(cfg.lane_chain);
        if (serving && cfg.owed_demo_amount) {
            ledger.seed_owed_std(sink_A, sink_B, cfg.owed_demo_amount);
            std::printf("owed-demo: seeded %llu piconero owed to a distinct K_fair payee "
                        "(coinbase will carry OWED + residual sink)\n",
                        static_cast<unsigned long long>(cfg.owed_demo_amount));
        }

        // ── M2: WHICH miner-data source the assembler is fed from ───────────
        // Nothing below this block knows the difference. The assembler, the X6
        // settlement source, the reward/payee fixpoint, the exact-sum residual
        // sink and the owed_digest in tx_extra 0x03 are the same code either
        // way; only the seam the numbers arrive through moves.
        std::unique_ptr<o2::NativeTemplateBackend> native;
        if (cfg.template_source == TemplateSourceMode::Native) {
            if (cfg.native_connect.empty()) {
                std::printf("REFUSED: --xmr-template-source native needs at least one "
                            "--native-connect <ip:port> levin peer (the embedded node dials "
                            "only what it is told to)\n");
                node.stop();
                return 2;
            }
            o2::NativeTemplateConfig ncfg;
            ncfg.net                  = native_net_of(cfg.network);
            ncfg.connect              = cfg.native_connect;
            ncfg.p2p_bind_ip          = cfg.native_p2p_bind_ip;
            ncfg.boot                 = cfg.native_anchor_path.empty()
                                            ? ::c2pool::xmr::native::rt::BootMode::Genesis
                                            : ::c2pool::xmr::native::rt::BootMode::Anchor;
            ncfg.anchor_path          = cfg.native_anchor_path;
            ncfg.monerod_rpc_host     = cfg.monerod.rpc_host;   // parity judge + submit arm ONLY
            ncfg.monerod_rpc_port     = cfg.monerod.rpc_port;
            ncfg.serve                = ::c2pool::xmr::native::TemplateArm::Native;
            ncfg.fallback             = cfg.native_template_fallback;
            ncfg.force_synced         = cfg.native_force_synced;
            ncfg.allow_unverified_pow = cfg.native_allow_unverified_pow;
            ncfg.parity               = true;
            ncfg.parity_ledger_path   = cfg.resolved_settle_db_path() + "/xmr_parity_ledger.json";
            ncfg.c2pool_commit        = C2POOL_VERSION;
            ncfg.ready_timeout_s      = cfg.native_ready_timeout_s;
            ncfg.backlog_refresh_s    = cfg.native_backlog_refresh_s;

            std::printf("template source: NATIVE — the embedded Monero node (levin, %zu pinned "
                        "peer(s)) feeds the option-B assembler; monerod stays the parity judge "
                        "and the submit arm, and is NOT on the template path\n",
                        cfg.native_connect.size());
            native = std::make_unique<o2::NativeTemplateBackend>(std::move(ncfg));
            std::string nwhy;
            if (!native->start_and_wait(nwhy, [](const std::string& w) {
                    std::printf("  native: not ready yet — %s\n", w.c_str());
                    std::fflush(stdout);
                })) {
                std::printf("REFUSED: %s\n", nwhy.c_str());
                node.stop();
                return 2;
            }
            std::printf("  native: template arm READY, fallback %s\n",
                        cfg.native_template_fallback
                            ? "ON (the daemon arm may serve if the native one loses a window)"
                            : "OFF (native-only: no template is served if the native arm is not ready)");
        } else {
            std::printf("template source: MONEROD — one get_miner_data per template refresh\n");
        }

        std::unique_ptr<o2::XmrSettlementTemplateProvider> provider_owner =
            native ? std::make_unique<o2::XmrSettlementTemplateProvider>(
                         native->source(), ledger, scfg, cfg.stratum_share_diff, native->pump())
                   : std::make_unique<o2::XmrSettlementTemplateProvider>(
                         transport, ledger, scfg, cfg.stratum_share_diff);
        o2::XmrSettlementTemplateProvider& provider = *provider_owner;

        // ── the K_fair shape gate, on BOTH arms ─────────────────────────────
        // Read back off the assembled block bytes, not off the builder's own
        // bookkeeping, and refused rather than warned: a template whose coinbase
        // is not the K_fair shape is never given a template_id and never reaches
        // a miner. Installed for the monerod arm too -- the rebind is what made
        // the check necessary, but the property it pins was always the one that
        // mattered.
        std::uint64_t shape_ok = 0, shape_refused = 0;
        std::string   last_shape;
        // n_tx of the block the gate judged -- the SELECTED count, which is not
        // the same number as the backlog the arm OFFERED. The assembler applies
        // monerod's own 5-second age gate (xmr_block_template.cpp), so a
        // transaction that arrived moments before the rebuild is held back for
        // the next one. Reporting only one of the two numbers would leave an
        // auditor comparing "backlog=4" against a coinbase paying three fees and
        // with no way to tell a filter from a bug, so both are printed.
        std::size_t   last_selected_tx = 0;
        provider.set_shape_gate(
            [&](const ::c2pool::xmr::assembly::AssembledTemplate& t, std::string* w) {
                const o2::KFairCoinbaseShape sh =
                    o2::inspect_kfair_coinbase(t, ledger.ledger().owed_digest());
                last_shape = sh.describe();
                last_selected_tx = t.n_tx();
                if (!sh.ok) {
                    ++shape_refused;
                    if (w) *w = sh.why;
                    return false;
                }
                ++shape_ok;
                return true;
            });

        o2::SettlementStratumTemplateSource template_source(provider);
        std::printf("coinbase: %s (lane_chain=%u, residual sink %s)\n",
                    to_string(cfg.coinbase), static_cast<unsigned>(cfg.lane_chain),
                    serving ? "SET (torsion-checked at build)" : "UNSET (observe-side only)");

        auto candidate = [&provider](std::uint32_t tid, std::uint32_t en, sub::BlockCandidate& out) {
            std::string w;
            return provider.candidate_by_id(tid, en, out, &w);
        };

        // ── the M2 evidence, off the serve path ─────────────────────────────
        ServeHooks hooks;
        hooks.after_refresh = [&](bool refreshed, bool new_template) {
            if (!native || !refreshed || !new_template) return;
            auto* orc = native->oracle();
            if (!orc) return;
            // P-TPL: the oracle judges the artefact that WENT OUT, so the miner
            // data is taken from the provider's record of the served template,
            // not re-read from the arm (which may already have moved on).
            node::MinerData served{};
            if (provider.last_miner_data(served))
                orc->on_serve(provider.current().epoch, served, provider.current().source_name);
        };
        hooks.status_extra = [&]() {
            if (!last_shape.empty())
                std::printf("  coinbase: n_tx=%zu %s (gate ok=%llu refused=%llu)\n",
                            last_selected_tx, last_shape.c_str(),
                            static_cast<unsigned long long>(shape_ok),
                            static_cast<unsigned long long>(shape_refused));
            if (!native) return;
            const auto ns = native->node()->status();
            // The backlog the native arm OFFERED for the template that actually
            // went out -- not the pool right now, because the number an auditor
            // is checking is the one the miners were handed. Read off the
            // provider's record of the served template, the same artefact the
            // P-TPL oracle judges. `selected` beside it is what the assembler
            // kept after monerod's 5-second age gate.
            std::size_t served_backlog_n = 0;
            {
                node::MinerData md_out{};
                if (provider.last_miner_data(md_out)) served_backlog_n = md_out.tx_backlog.size();
            }
            std::printf("  native: arm=%s resolves=%llu (native=%llu daemon=%llu) "
                        "template-path get_miner_data=%llu "
                        "| verified_frontier=%llu peers=%zu txpool_accepted=%llu "
                        "backlog offered=%zu selected=%zu\n",
                        native->arms()->describe().c_str(),
                        static_cast<unsigned long long>(native->source().resolves()),
                        static_cast<unsigned long long>(native->source().served_by_native()),
                        static_cast<unsigned long long>(native->source().served_by_daemon()),
                        static_cast<unsigned long long>(native->source().daemon_pumps()),
                        static_cast<unsigned long long>(ns.sync.verified_frontier),
                        ns.pool.peers_handshaked,
                        static_cast<unsigned long long>(ns.txpool.accepted),
                        served_backlog_n, last_selected_tx);

            // THE WIRE LINE. Two independent sockets reach the same daemon: the
            // embedded node's own transport (parity judge + submit arm) and the
            // pool's consumer transport, whose no-libzmq tip poll is the bulk of
            // the traffic. Printing only the first made the headline a tenth of
            // the truth, and an auditor with tcpdump would have read the gap as
            // a false claim rather than as a missing summand. TOTAL is what the
            // wire shows; the split says which of it is on the template path,
            // and that summand is the claim.
            const unsigned long long node_rpc  = ns.rpc_calls;
            const unsigned long long poll_rpc  = transport.tip_poll_calls();
            const unsigned long long other_rpc = transport.other_calls();
            std::printf("  wire RPC to monerod: TOTAL=%llu = template-path %llu "
                        "+ node(parity+submit) %llu + tip-poll %llu + pool-other %llu"
                        " [failures node=%llu pool=%llu]\n",
                        node_rpc + poll_rpc + other_rpc,
                        static_cast<unsigned long long>(native->source().daemon_pumps()),
                        node_rpc, poll_rpc, other_rpc,
                        static_cast<unsigned long long>(ns.rpc_failures),
                        static_cast<unsigned long long>(transport.rpc_failures()));
            if (auto* mon = native->node()->monerod_source())
                std::printf("  daemon arm: cache age=%llums (limit %llums)%s\n",
                            static_cast<unsigned long long>(mon->age_ms()),
                            static_cast<unsigned long long>(mon->config().max_age_ms),
                            mon->stale() ? " STALE -- not READY" : "");
            if (auto* orc2 = native->oracle())
                std::printf("  P-TPL backlog constraint: %s\n",
                            orc2->backlog_famine().c_str());
            // The parity probe is drained HERE, on the status cadence, so it is
            // never in front of a miner (the DASH shadow-compare rule).
            std::string pw;
            if (!native->poll_shadow(&pw) && !pw.empty())
                std::printf("  parity: shadow arm not refreshed: %s\n", pw.c_str());
            for (const auto& r : native->node()->parity_sample())
                std::printf("  parity: %s\n",
                            ::c2pool::xmr::native::parity::render_sample(r).c_str());
        };

        const int rc = serve_and_run(cfg, transport, node, fc, found_q, payee_key, rx, serving,
                                     "no --residual-sink-spend-hex/--residual-sink-view-hex",
                                     provider, template_source, candidate, std::move(hooks));
        if (native) native->stop();
        return rc;
    }

    // ── option A (default): monerod's own get_block_template ────────────────
    const bool serving = !cfg.payout_address.empty();
    o2::MonerodTemplateProvider provider(transport, cfg.payout_address, cfg.template_reserve_size);
    o2::MonerodStratumTemplateSource template_source(provider, cfg.stratum_share_diff);
    auto candidate = [&provider, &template_source](std::uint32_t tid, std::uint32_t en,
                                                   sub::BlockCandidate& out) {
        o2::MonerodTemplate t;
        if (!provider.by_id(tid, t)) return false;
        strat::TemplateJob tj;
        if (!template_source.rebuild_blob(tid, en, tj)) return false;
        out.template_id     = tid;
        out.height          = t.height;
        out.full_blob       = t.full_blob;
        out.hashing_blob    = tj.blob;          // the exact blob served for this job
        out.nonce_offset    = t.nonce_offset;
        out.major_version   = t.major_version;
        out.prev_id         = t.prev_id;
        out.expected_reward = t.expected_reward;
        out.reserved_offset = 0;                // single template, extra_nonce not baked
        out.reserved_size   = 0;
        return true;
    };
    return serve_and_run(cfg, transport, node, fc, found_q, payee_key, rx, serving,
                         "no --payout-address", provider, template_source, candidate);
}

int main(int argc, char** argv) {
    XmrNodeConfig cfg;
    bool mock_smoke = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* def) -> std::string {
            return (i + 1 < argc) ? argv[++i] : def;
        };
        if (a == "--mock-smoke" || a == "--selftest") mock_smoke = true;
        else if (a == "--network")  cfg.network = parse_net(next("stagenet"));
        else if (a == "--rpc-host") cfg.monerod.rpc_host = next("127.0.0.1");
        else if (a == "--rpc-port") cfg.monerod.rpc_port =
                     static_cast<std::uint16_t>(std::stoi(next("38081")));
        else if (a == "--zmq-port") cfg.monerod.zmq_port =
                     static_cast<std::uint16_t>(std::stoi(next("38083")));
        else if (a == "--stratum-port") cfg.stratum_bind_port =
                     static_cast<std::uint16_t>(std::stoi(next("3333")));
        else if (a == "--stratum-bind-host") cfg.stratum_bind_host = next("127.0.0.1");
        else if (a == "--payout-address") cfg.payout_address = next("");
        else if (a == "--share-diff") cfg.stratum_share_diff = std::stoull(next("0"));
        else if (a == "--template-reserve") cfg.template_reserve_size =
                     static_cast<std::uint32_t>(std::stoul(next("0")));
        else if (a == "--poll-ms") cfg.poll_ms = static_cast<std::uint32_t>(std::stoul(next("5000")));
        else if (a == "--status-every") cfg.status_every_s =
                     static_cast<std::uint32_t>(std::stoul(next("30")));
        else if (a == "--no-found-sidecar") cfg.found_sidecar = false;
        else if (a == "--payee-spend-hex") cfg.payee_spend_key_hex = next("");
        else if (a == "--payee-view-hex")  cfg.payee_view_key_hex = next("");
        else if (a == "--payee-subaddress") cfg.payee_subaddress = true;
        else if (a == "--coinbase") {
            const std::string m = next("monerod");
            cfg.coinbase = (m == "v37" || m == "settlement" || m == "v37-settlement")
                               ? CoinbaseMode::V37Settlement : CoinbaseMode::MonerodTemplate;
        }
        else if (a == "--residual-sink-spend-hex") cfg.residual_sink_spend_hex = next("");
        else if (a == "--residual-sink-view-hex")  cfg.residual_sink_view_hex = next("");
        else if (a == "--residual-sink-subaddress") cfg.residual_sink_subaddress = true;
        else if (a == "--settle-h-min") cfg.settle_h_min = std::stoull(next("0"));
        else if (a == "--settle-output-cap") cfg.settle_output_cap =
                     static_cast<std::uint32_t>(std::stoul(next("0")));
        else if (a == "--owed-demo-amount") cfg.owed_demo_amount = std::stoull(next("0"));
        else if (a == "--xmr-template-source") {
            const std::string m = next("monerod");
            cfg.template_source = (m == "native") ? TemplateSourceMode::Native
                                                  : TemplateSourceMode::Monerod;
        }
        else if (a == "--native-connect") cfg.native_connect.push_back(next(""));
        else if (a == "--native-p2p-bind") cfg.native_p2p_bind_ip = next("");
        else if (a == "--native-anchor") cfg.native_anchor_path = next("");
        else if (a == "--native-force-synced") cfg.native_force_synced = true;
        else if (a == "--native-allow-unverified-pow") cfg.native_allow_unverified_pow = true;
        else if (a == "--native-template-fallback") {
            const std::string m = next("on");
            cfg.native_template_fallback = !(m == "off" || m == "0" || m == "false");
        }
        else if (a == "--native-backlog-refresh") cfg.native_backlog_refresh_s =
                     static_cast<std::uint64_t>(std::stoull(next("0")));
        else if (a == "--native-ready-timeout") cfg.native_ready_timeout_s =
                     static_cast<std::uint32_t>(std::stoul(next("120")));
        else if (a == "--lane-chain") cfg.lane_chain =
                     static_cast<::v37::ChainId>(std::stoul(next("0")));
        else if (a == "--d-conf") cfg.d_conf = std::stoull(next("60"));
        else if (a == "--data-dir") cfg.settle_db_path = next("");
        else if (a == "--i-understand-mainnet") cfg.i_understand_mainnet = true;
        else if (a == "--randomx") cfg.randomx_enabled = true;
        else if (a == "--randomx-large-pages") cfg.randomx_large_pages = true;
        else if (a == "--help" || a == "-h") {
            std::printf(
                "c2pool-v37-xmr (EXPERIMENTAL prototype; stagenet default)\n"
                "  --mock-smoke                 network-free CI smoke (monerod stub), then exit\n"
                "  --network <stagenet|testnet|mainnet|regtest>   default stagenet\n"
                "  --rpc-host <h>  --rpc-port <p>  --zmq-port <p>\n"
                "  --lane-chain <id>  --d-conf <n>  --poll-ms <ms>  --status-every <s>\n"
                "  --data-dir <path>            override the settlement store dir\n"
                "  --no-found-sidecar           do not persist pending FOUNDs across restarts\n"
                "  --i-understand-mainnet       required to settle a mainnet block\n"
                "  --randomx                    enable heavy RandomX verify (needs XMR_BUILD_RANDOMX)\n"
                "  --randomx-large-pages        RandomX cache in huge pages\n"
                " serve side (X9 O-2; the stratum port is served only with a payout address):\n"
                "  --payout-address <addr>      get_block_template wallet address (network-prefixed)\n"
                "  --stratum-bind-host <ip>  --stratum-port <p>   default 127.0.0.1:3333\n"
                "  --share-diff <n>             share (lane) difficulty; 0 = network (solo)\n"
                "  --template-reserve <n>       get_block_template reserve_size (default 0)\n"
                "  --payee-spend-hex <64hex> --payee-view-hex <64hex> [--payee-subaddress]\n"
                "                               payout address keys -> amount-honest FOUND records\n"
                " option B (X9): the v37 K_fair SETTLEMENT coinbase (not monerod's template):\n"
                "  --coinbase <monerod|v37>     monerod (default, option A) | v37 (option B)\n"
                "  --residual-sink-spend-hex <64hex> --residual-sink-view-hex <64hex>\n"
                "                               REQUIRED for v37 mode: the XMR wallet the exact-sum\n"
                "                               residual is paid to (torsion-checked at build)\n"
                "  --residual-sink-subaddress   the sink keys are a subaddress (D_i, A_main)\n"
                "  --settle-h-min <pico>        owed-output floor (0 on XMR)\n"
                "  --settle-output-cap <n>      TOTAL outputs cap (0 = weight-aware default)\n"
                "  --owed-demo-amount <pico>    seed one K_fair OWED payee into the proof ledger\n"
                "                               (coinbase carries OWED + residual sink)\n"
                " M2 — where option B's miner data comes from (--coinbase v37 only):\n"
                "  --xmr-template-source <monerod|native>\n"
                "                               monerod (default): one get_miner_data per refresh.\n"
                "                               native: the embedded Monero node (levin P2P + chain\n"
                "                               index + relayed txpool) builds the template and the\n"
                "                               template path makes NO daemon call. monerod remains\n"
                "                               the parity judge and the block submit arm.\n"
                "  --native-connect <ip:port>   pinned levin peer for the embedded node (repeatable,\n"
                "                               REQUIRED for --xmr-template-source native)\n"
                "  --native-p2p-bind <ip>       source address for the node's outbound dials\n"
                "  --native-anchor <path>       trust-anchor bundle (cold start above genesis)\n"
                "  --native-force-synced        set the publication gate on a private chain (OR-C2-8)\n"
                "  --native-allow-unverified-pow  a build with no RandomX may connect blocks it did\n"
                "                               not verify (opt-in, loud, never a default)\n"
                "  --native-template-fallback <on|off>\n"
                "                               on (default): serve from monerod when the native arm\n"
                "                               is not ready. off: native-only, fail-closed.\n"
                "  --native-ready-timeout <s>   how long to wait for the native arm (default 120)\n"
                "  --native-backlog-refresh <s> rebuild the template when the POOL moves, at most\n"
                "                               once per <s> seconds (0 = tip-only, the default:\n"
                "                               a tip-only arm serves the empty template built at\n"
                "                               the start of each block interval)\n");
            return 0;
        }
    }

    // Default monerod ports follow the chosen network unless overridden. If the
    // user picked a network but left default ports, re-derive them.
    if (cfg.monerod.rpc_port == default_endpoint(MoneroNetwork::Stagenet).rpc_port &&
        cfg.network != MoneroNetwork::Stagenet) {
        auto e = default_endpoint(cfg.network);
        cfg.monerod.rpc_port = e.rpc_port;
        cfg.monerod.zmq_port = e.zmq_port;
    }

    if (mock_smoke) return run_mock_smoke();
    return run_live(cfg);
}
