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

using namespace c2pool::v37n::xmr;
namespace strat = ::v37::xmr::stratum;
namespace sub   = c2pool::v37n::xmr::submit;

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
                         sub::LiveSubmitShareSink::CandidateLookup candidate_lookup) {
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
            e.payee           = payee_key;   // informational since R-7 (never booked)
            // R-7 (2026-09-10): the FOUND record books what the COINBASE PAID —
            // the emitted Role::Owed set, captured at the SUBMIT seam from the
            // very snapshot whose bytes went to monerod (never re-looked-up here:
            // the provider ring can evict a template between submit and tick).
            // Empty under option A (monerod's template pays no v37 owed) and for
            // a sink-only option-B block. `credit` (E_b) stays empty until Track
            // A2 S-1 emission exists.
            e.coinbase_owed.insert(s.coinbase_owed.begin(), s.coinbase_owed.end());
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
        // R-7 acceptance probe, printed every status tick: the ledger-wide
        // minimum EffectiveOwed. It must be 0 (i.e. no negative row) for the
        // whole run, INCLUDING while blocks are pending. The pre-R-7 split-ledger
        // wiring drove this to -reward per pending FOUND.
        std::printf("  owed: min_effective_owed=%lld booked=%lld ledger_seq=%llu "
                    "split_brain_refused=%llu\n",
                    fc.min_effective_owed(), fc.stats().owed_booked,
                    static_cast<unsigned long long>(node.ledger().ledger_seq()),
                    static_cast<unsigned long long>(fc.stats().split_brain_refused));
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
            if (provider.refresh()) {
                const std::uint32_t tid = provider.template_id();
                if (tid != last_tid) {
                    last_tid = tid;
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
        }
        drain_stratum_log();
        if (cfg.status_every_s &&
            std::chrono::steady_clock::now() - last_status >= std::chrono::seconds(cfg.status_every_s)) {
            status();
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
        std::printf("payee: identity_key=%s… (INFORMATIONAL since R-7: this key is logged with "
                    "each FOUND but is NEVER booked into the ledger — the FOUND payout is the "
                    "coinbase's own emitted K_fair owed set)\n",
                    hex_of(*payee_key).substr(0, 16).c_str());
    } else {
        std::printf("payee: no --payee-spend-hex/--payee-view-hex (informational only since R-7)\n");
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
        scfg.allow_nonruled_local_only = cfg.lane_commitment_local_only;
        if (!o2::parse_lane_commitment_source(cfg.lane_commitment_source, scfg.lc_source)) {
            std::printf("REFUSED: --lane-commitment must be one of "
                        "state-root (RULED) | owed-digest | explicit; got \"%s\"\n",
                        cfg.lane_commitment_source.c_str());
            node.stop();
            return 2;
        }
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

        // ── R-7 (2026-09-10): ONE LEDGER ────────────────────────────────────
        // The coinbase MUST be built against the SAME OwedLedger the finalize
        // driver writes — the node's: store-backed, RecoveryDriver-replayed,
        // XmrFinalizeDriver-driven. Before this fix the daemon held TWO disjoint
        // OwedLedger objects (a settlement one the coinbase paid from, a node one
        // FINALIZE booked into). The settlement one was never decremented, so
        // propose_coinbase re-proposed the SAME owed row at its full
        // EffectiveOwed on EVERY block (a no-double-pay violation of whitepaper
        // section 9 / OI-W4-5) while the node one went negative by one full
        // reward per concurrent pending FOUND.
        // With one ledger, block N+1's proposal already sees block N's pending
        // payout deducted (effective_owed = finalW - SUM_pending payout), so a
        // row that is already in flight cannot be re-proposed.
        // `node` outlives `ledger`, the provider and every retained template.
        //
        // --owed-demo-amount seeds a distinct K_fair OWED payee (the sink
        // material with spend/view swapped — still two valid ed25519 points, a
        // different identity) so the assembled coinbase carries an OWED output
        // alongside the sink (multi-output proof). With no seed and an empty
        // ledger the whole reward flows to the residual sink (one v37 output).
        // NOTE (honest scope): the demo seed is written straight into the
        // in-memory ledger, NOT through the settle-store write-ahead log, so it
        // does not survive a restart and IS re-applied on every boot that passes
        // the flag. It is a proof knob, not lane state; real owed arrives with
        // Track A2 S-1 emission.
        o2::XmrOwedFixture ledger(node.ledger());
        if (serving && cfg.owed_demo_amount) {
            ledger.seed_owed_std(sink_A, sink_B, cfg.owed_demo_amount);
            std::printf("owed-demo: seeded %llu piconero owed to a distinct K_fair payee "
                        "(coinbase will carry OWED + residual sink)\n",
                        static_cast<unsigned long long>(cfg.owed_demo_amount));
        }

        o2::XmrSettlementTemplateProvider provider(transport, ledger, scfg, cfg.stratum_share_diff);
        o2::SettlementStratumTemplateSource template_source(provider);
        // Serve banner: name the two RULED consensus choices and print the
        // resolved 32-byte lane commitment, so a node's committed value is
        // auditable straight from the log (RULED 2026-09-10).
        {
            const ::v37::bytes32 lc = o2::resolve_lane_commitment(scfg, ledger.ledger());
            char lc_hex[65];
            for (int i = 0; i < 32; ++i) std::snprintf(lc_hex + 2 * i, 3, "%02x", lc[static_cast<std::size_t>(i)]);
            std::printf("coinbase: %s (lane_chain=%u, residual sink %s, k_fair=%s, "
                        "lane_commitment=%s%s %s)\n",
                        to_string(cfg.coinbase), static_cast<unsigned>(cfg.lane_chain),
                        serving ? "SET (torsion-checked at build)" : "UNSET (observe-side only)",
                        o2::to_string(scfg.kfair), o2::to_string(scfg.lc_source),
                        cfg.lane_commitment_local_only ? " LOCAL-ONLY-OVERRIDE" : "", lc_hex);
        }

        auto candidate = [&provider](std::uint32_t tid, std::uint32_t en, sub::BlockCandidate& out) {
            std::string w;
            return provider.candidate_by_id(tid, en, out, &w);
        };
        return serve_and_run(cfg, transport, node, fc, found_q, payee_key, rx, serving,
                             "no --residual-sink-spend-hex/--residual-sink-view-hex",
                             provider, template_source, candidate);
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
        else if (a == "--lane-commitment") cfg.lane_commitment_source = next("state-root");
        else if (a == "--lane-commitment-local-only") cfg.lane_commitment_local_only = true;
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
                "  --lane-commitment <state-root|owed-digest|explicit>\n"
                "                               what the tx_extra 0x03 MM root binds and what seeds\n"
                "                               the tx secret key r. RULED 2026-09-10: state-root =\n"
                "                               the whitepaper section 13 StateCommitment root\n"
                "                               (default; strictly subsumes owed-digest)\n"
                "  --lane-commitment-local-only accept a non-ruled --lane-commitment for a\n"
                "                               SINGLE-POOL experiment (never for a lane with peers)\n");
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
