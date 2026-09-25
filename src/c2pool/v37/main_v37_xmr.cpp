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

#include <algorithm>
#include <atomic>
#include <functional>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <random>
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
#include "xmr/xmr_coinbase_authority.hpp"  //  coinbase-authority booking
#include "xmr/xmr_credit_cut.hpp"           // recon(A+B credit): the on-chain credit cut
#include "xmr/xmr_fee_model.hpp"            // fee model: donation marker/sink, give-author u16, owner-fee roll
#include <c2pool/v37/w3_relay.hpp>           // recon(A+B credit): CutDescriptor + CarrierWire (the REAL v0x02 codec)
#include <c2pool/v37/w3_wire_freeze.hpp>     // recon(A+B credit): fixture_a (a well-formed carrier body to ride the descriptor)
#include "impl/xmr/node/minijson.hpp"
#include <deque>
#include <set>
#include <sstream>
#include "xmr/xmr_o2_settlement_fixture.hpp"  // O-2 option B: XmrSettlementConfig + XmrOwedFixture (proof ledger)
#include "xmr/xmr_o2_settlement_provider.hpp" // O-2 option B: v37 K_fair settlement template provider + source
#include "xmr/xmr_settlement_coinbase_shape.hpp"  // M2: the K_fair shape gate, read off the assembled block bytes
#include "xmr/xmr_native_template_backend.hpp"    // M2: the native-minimal Monero node as the miner-data source
#include "xmr/xmr_native_chain_source.hpp"        // M3: the native levin chain as the tip + canonical test
#include "xmr/xmr_cba_block_source.hpp"           // D6a: the booking's block blob from the native index
#include "xmr/xmr_p2p_block_publisher.hpp"        // M3: found block -> levin 2008 (no submit_block)
#include "xmr/xmr_recon_ring.hpp"                 // R-C rework-3 (D7): the RECON ring + root-age bound
#include "xmr/xmr_lane_suspend_state.hpp"         // R-C rework-3 (D5 + contested): the lane-suspend causes
// GAP-2: the real c2pool-to-c2pool receipt relay (docs/xmr-lane/gap2-sharechain-relay-design.md).
// OFF unless --relay-listen / --relay-peer is given; off = this daemon byte-identical to before.
#include "xmr/relay/xmr_relay_wire.hpp"        // FB_HELLO / FB_RECEIPTS / FB_BLOCK_WON, side_data_v2, lane_params_digest
#include "xmr/relay/xmr_receipt_mint.hpp"      // share -> PoW-carrying receipt; the structural check
#include "xmr/relay/xmr_relay_node.hpp"        // TCP relay: HELLO gate, verify worker (RandomX LAST), flood, backfill, repair
#include "xmr/relay/xmr_receipt_ingest.hpp"    // admitted receipts -> the lane (ordering policy + durable log)
#include "xmr/xmr_drops_wiring.hpp"            // ★ DROPS: the XMR shell's DropsWiring (flip-gated; DORMANT by default)
#include "xmr/relay/xmr_relay_native_ctx.hpp"   // RC-CTX: receipt contexts from the native node + the own-template journal
#include "xmr/relay/xmr_address.hpp"           // login address (base58) -> payee ref
#include "xmr/relay/xmr_rbind_registry.hpp"    // SEAM-1: per-job rbind (payee + give-author) the template writes
#include "xmr/relay/xmr_relay_chain_feed.hpp"  // D6b: the relay chain view fed from the native index (p2p-first)

// The in-process RandomX CPU miner (--mine). Header-only, and only compilable
// when librandomx is in the build -- so it is gated on exactly the macro that
// says so. Without it --mine is REFUSED with a reason, never silently ignored.
#if defined(V37_XMR_O2_WITH_RANDOMX)
#include "impl/xmr/pow/xmr_cpu_miner.hpp"     // --mine: in-process RandomX CPU miner (BSD-3 librandomx client)
#endif

// --mine-msr: the opt-in, root-gated MSR tuning. UNGATED by RandomX on purpose
// -- it links nothing and touches nothing unless asked, so the flag can be
// parsed, reported and refused identically in a build that has no librandomx.
#include "impl/xmr/pow/xmr_msr_boost.hpp"

using namespace c2pool::v37n::xmr;
namespace strat = ::v37::xmr::stratum;
namespace sub   = c2pool::v37n::xmr::submit;
namespace settle = ::c2pool::v37n::settle;   // recon(A+B credit): fold_eb at the on-chain cut
#if defined(V37_XMR_O2_WITH_RANDOMX)
namespace mine = ::c2pool::xmr::miner;
#endif
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
// It now lives in xmr/xmr_native_template_backend.hpp, beside
// native_template_config_of() -- the one function that turns an XmrNodeConfig
// into the embedded node's configuration -- so that the mapping and its only
// caller cannot drift apart. Named here because this is where a reader looks.

static std::atomic<bool> g_stop{false};
static std::atomic<bool> g_relay_partition_req{false};   // GAP-2 rig: SIGUSR1 -> relay partition
static void on_sigusr1(int) { g_relay_partition_req.store(true); }
static void on_sigint(int) { g_stop.store(true); }

// recon(A+B credit) knobs (regtest-only; parsed in main). See xmr/xmr_credit_cut.hpp.
static std::string   g_credit_feed;            // --credit-feed FILE: the shared receipt stream (carrier-relay stand-in)
static std::uint64_t g_credit_feed_lag_ms = 0; // --credit-feed-lag-ms N: this node ingests receipts N ms late (receiver-behind)
static std::string   g_wire_out, g_wire_in;    // --wire-out DIR / --wire-in DIR: S-1c v0x02 frames (the FAST PATH stand-in)
static long long     g_credit_mutate = 0;      // --credit-mutate N: +N piconero on one E_b row (the amount-sensitivity falsifier)
// R6 knobs (all networks). See xmr/xmr_o2_finalize_connect.hpp (R6) + docs/xmr-lane/finality-boundary.md.
static bool          g_no_book_deferral = false;         // --no-book-deferral: A/B escape hatch (reintroduces the lagging-receiver fork)
// D6a (xmr/xmr_cba_block_source.hpp): p2p-first books from the native index; monerod is opt-in only.
static bool          g_cba_monerod_compare = false;      // --cba-monerod-compare: compare-only oracle (counts, never decides)
static bool          g_cba_monerod_fallback = false;     // --cba-monerod-fallback: a native miss asks monerod instead of HOLDING
static bool          g_relay_feed_monerod_compare = false;   // --relay-feed-monerod-compare: D6b compare-only oracle (counts, never decides)
static std::uint64_t g_divergence_cap_heights = 0;       // --divergence-cap-heights N (0 = 2 * D_conf)
static std::uint64_t g_divergence_cap_ticks = 20;        // --divergence-cap-ticks N
static std::uint64_t g_divergence_cap_terminal = 2;      // --divergence-cap-terminal N (0 = off)
// fee model (xmr/xmr_fee_model.hpp), gated by LaneParams::fee (--fee-model v1;
// default OFF => master-identical coinbase and credit). The two knobs below are
// node-local JOB policy under the gate: they decide only what THIS node's jobs
// commit to (the payee + the give-author u16 in the PoW-bound receipt), never
// how any receipt is folded. The donation output itself has NO knob.
static double        g_give_author_pct = 0.0;            // --give-author-pct P: the u16 this node's receipts carry (default 0)
static double        g_owner_fee_pct = 0.0;              // --node-owner-fee-pct P: probability (%) a job commits to the owner
static std::string   g_owner_address;                    // --node-owner-address ADDR: the owner's standard address
// R-C rework-3 ruled defaults (docs/xmr-lane/r-c-rework-3.md).
static bool          g_contested_suspend = false;        // --contested-suspend on|off (default off): CONTESTED suspends lane production
static std::uint64_t g_recon_max_root_age = ~std::uint64_t{0};   // --recon-max-root-age N (default kReconMaxRootAgeDconf*D_conf; 0 = unbounded)
static bool g_lane_suspended_now = false;                  // R-C rework-2: main-thread view of the lane-suspend state (pump_miner reads it)
// GAP-2 relay knobs (design §6). All default OFF: with neither --relay-listen nor
// --relay-peer the daemon is byte-identical to the stand-in build.
static std::string   g_relay_listen;                    // --relay-listen HOST:PORT
static std::vector<std::string> g_relay_peers;          // --relay-peer HOST:PORT (repeatable)
static std::vector<std::string> g_drops_enrol;          // ★ DROPS: --drops-enrol <64-hex identity | XMR address> (repeatable)
static std::size_t   g_relay_max_peers = 8;             // --relay-max-peers N
static std::uint64_t g_relay_horizon = 64;              // --relay-index-horizon N (blocks)
static std::string   g_relay_rx_budget = "1,20,16,256"; // --relay-rx-budget P,C,G,GC
static std::uint32_t g_relay_solicited = 256;           // --relay-solicited-credits N
static std::uint64_t g_relay_backfill = 2048;           // --relay-backfill-positions N
static std::uint32_t g_relay_reoffer_s = 60;            // --relay-reoffer-seconds S
static std::string   g_relay_order = "canonical";       // --relay-order canonical|arrival (OQ-1)
static std::uint64_t g_relay_bin_lag = 1;               // --relay-bin-lag L
static std::uint32_t g_relay_grace_ms = 4000;           // --relay-bin-grace-ms MS
static std::size_t   g_relay_vault_entries = 0, g_relay_vault_bytes = 0;   // --relay-vault-entries/-bytes (0 = default)
static std::uint64_t g_relay_vault_horizon = 0;         // --relay-vault-horizon (0 = default 8640)
static bool          g_no_relay_serve = false;          // --no-relay-serve
static std::uint32_t g_relay_partition_s = 0;           // --relay-test-partition-seconds S (rig: SIGUSR1 drops the relay for S s)
static std::string   g_relay_bind = "none";             // --relay-bind none|rbind (rbind needs SEAM-1 in the template)
static bool relay_enabled() { return !g_relay_listen.empty() || !g_relay_peers.empty(); }
static bool split_hostport(const std::string& s, std::string& host, std::uint16_t& port) {
    const auto c = s.rfind(':');
    if (c == std::string::npos || c == 0 || c + 1 >= s.size()) return false;
    host = s.substr(0, c);
    try { const unsigned long v = std::stoul(s.substr(c + 1)); if (v == 0 || v > 65535) return false; port = static_cast<std::uint16_t>(v); }
    catch (...) { return false; }
    return true;
}

static MoneroNetwork parse_net(const std::string& s) {
    if (s == "mainnet")  return MoneroNetwork::Mainnet;
    if (s == "testnet")  return MoneroNetwork::Testnet;
    if (s == "regtest")  return MoneroNetwork::Regtest;
    return MoneroNetwork::Stagenet;
}
// DON-NET: the fee model's donation identity follows --network (xmr_fee_model.hpp
// donation_info); the value is also the relay HELLO network byte.
static c2pool::v37n::xmr::fee::DonationNet donation_net_of(MoneroNetwork n) {
    using DN = c2pool::v37n::xmr::fee::DonationNet;
    return n == MoneroNetwork::Mainnet ? DN::Mainnet : n == MoneroNetwork::Testnet ? DN::Testnet
         : n == MoneroNetwork::Stagenet ? DN::Stagenet : DN::Regtest;
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
    // `inner` is the PUBLISHER: sub::LiveSubmitShareSink (monerod submit_block)
    // under --arm-order daemon-first, o2::P2pBlockPublisher (a levin 2008)
    // under p2p-first. Taken as the INTERFACE rather than the concrete type so
    // that the exact 128-bit gate in front of it is the same code on both arm
    // orders -- the one property that must not fork when the publish path does.
    GatedShareSinkT(o2::O2RandomXVerifier& rx, const Provider& provider,
                    strat::ITemplateSource& source, strat::IShareSink& inner)
        : m_rx(rx), m_provider(provider), m_source(source), m_inner(inner) {}

    void on_accepted_share(const strat::AcceptedShare& s) override {
        m_inner.on_accepted_share(s);
        if (m_on_share) m_on_share(s);   // GAP-2: mint the share's receipt (unset = unchanged)
    }
    void set_on_share(std::function<void(const strat::AcceptedShare&)> f) { m_on_share = std::move(f); }

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
    strat::IShareSink&                  m_inner;
    std::function<void(const strat::AcceptedShare&)> m_on_share;   // GAP-2 (listener or main thread)
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

    // M3: THE TIP DRIVER, as one call per loop pass.
    //
    // Unset (daemon-first, the default) means the built-in one: pump the
    // transport's get_miner_data poll and top up the RandomX seed reach, both
    // of which are monerod round trips. Set (p2p-first) means the caller drives
    // the tip from the native node's own levin chain instead, and NOTHING in
    // this loop may touch the daemon -- which is the whole claim, so the built-
    // in pump is REPLACED here rather than merely skipped at its call site.
    std::function<void()> pump_tip;

    // M3: the found-block publish arm, when it is not the monerod submitter.
    // Non-null routes the RandomX-gated winner to C5's levin 2008 relay; null
    // keeps submit_block. serve_and_run builds the sink over this rather than
    // taking a built one, because the FOUND queue the sink pushes into is
    // loop-local -- one queue, one drain, whichever arm filled it.
    ::c2pool::xmr::native::relay::LevinBlockRelay* p2p_relay = nullptr;

    // OPERATOR TX-INJECTION scanner, one call per loop pass (throttled inside).
    // Set by main() when --native-inject --native-inject-dir is armed; it polls
    // the inject dir and routes each *.hex through submit_operator_inject. Unset
    // = no inject dir, and the served template is byte-identical to the plain
    // good-citizen path.
    std::function<void()> inject_pump;
    std::function<void()> cba_tick;   //  per-loop digest ring + log
    // GAP-2: every accepted share (stratum listener thread, or the main thread
    // for --mine hits), AFTER the publish sink saw it. Unset = no relay.
    std::function<void(const strat::AcceptedShare&)> on_share;
    // GAP-2: the node-chosen base of the stratum extra_nonce counter (and the
    // in-process miner's slot just below it). Unset = the counter starts at 0.
    std::optional<std::uint32_t> extra_nonce_base;
    // SEAM-1 (--relay-bind rbind): bind a job's extra_nonce (payee + give-author,
    // owner-fee roll at job issue) right before its blob is built. Called on the
    // listener thread for stratum jobs, and once on the main thread for the
    // in-process miner's fixed slot (address ""). Unset = no binding.
    std::function<void(std::uint32_t, const std::string&)> job_binder;
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
    sub::LiveSubmitShareSink live_sink(submitter, submit_q, candidate_lookup);

    // M3: WHICH arm publishes a found block. The daemon submitter is ARMED only
    // when it is that arm -- in p2p-first it is constructed (the object is
    // cheap and opens no socket) and left disabled, so even a mis-wired gate
    // cannot reach submit_block. Both arms push into the SAME loop-local FOUND
    // queue, so wire 4 downstream of here is identical on either order.
    const bool p2p_publish = (hooks.p2p_relay != nullptr);
    std::unique_ptr<o2::P2pBlockPublisher> publisher;
    if (p2p_publish) {
        publisher = std::make_unique<o2::P2pBlockPublisher>(*hooks.p2p_relay, submit_q,
                                                            candidate_lookup);
        publisher->enable_network_relay(rx.network_blocks_allowed());   // fail-closed gate
        // SOLO: a peerless node has no peer receipt to wait for, so the block
        // is booked on our own index's acceptance instead -- opt-in, counted
        // apart from relayed(), and refused everywhere else.
        publisher->enable_solo_own_index(cfg.native_solo);
        // A find that reached no peer is parked and re-announced on a bounded
        // backoff (tick() below); every step of that is logged, never silent.
        publisher->set_log([](bool err, const std::string& line) {
            std::printf("  [publish]%s %s\n", err ? " ERROR" : "", line.c_str());
            std::fflush(stdout);
        });
    }
    submitter.enable_network_submit(!p2p_publish && rx.network_blocks_allowed());
    strat::IShareSink& publish_sink =
        p2p_publish ? static_cast<strat::IShareSink&>(*publisher)
                    : static_cast<strat::IShareSink&>(live_sink);
    GatedShareSinkT<Provider, Snapshot> sink(rx, provider, template_source, publish_sink);
    if (hooks.on_share) sink.set_on_share(hooks.on_share);   // GAP-2

    o2::StratumListenerOptions lo;
    lo.bind_host = cfg.stratum_bind_host;
    lo.bind_port = cfg.stratum_bind_port;
    o2::StratumListener listener(template_source, rx, sink, lo);
    if (hooks.extra_nonce_base) listener.seed_extra_nonce(*hooks.extra_nonce_base);   // GAP-2
    if (hooks.job_binder) listener.set_job_binder(hooks.job_binder);                     // SEAM-1
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
        std::printf("stratum: listening on %s:%u (%s coinbase, share diff %s, publish arm %s, "
                    "network submit %s)\n",
                    cfg.stratum_bind_host.c_str(), listener.bound_port(), to_string(cfg.coinbase),
                    cfg.stratum_share_diff ? std::to_string(cfg.stratum_share_diff).c_str() : "network",
                    p2p_publish ? "LEVIN 2008 (p2p-first, no submit_block)"
                                : "monerod submit_block (daemon-first)",
                    (p2p_publish || submitter.network_submit_enabled())
                        ? "ENABLED" : "DISABLED (fail-closed)");
    } else {
        std::printf("stratum: NOT served (%s) — observe-side only\n", not_served_reason);
    }

    // ── --mine: the in-process RandomX CPU miner ────────────────────────────
    //
    // THE POINT: one process that builds its own template, hashes it, finds the
    // block and books the payout -- no external miner, no stratum hop. It is
    // wired here, inside serve_and_run, so BOTH template arms (option A's
    // monerod template and option B's v37 K_fair settlement coinbase) and BOTH
    // publish arms (submit_block / levin 2008) get it from one body.
    //
    // Everything that has consequences stays on the MAIN thread: the template
    // pull, the RandomX seed prefetch, and the hand-off of a hit into `sink`
    // (the exact 128-bit gate). Worker threads only hash. That is why no
    // locking discipline changes anywhere else in this file.
    // --mine-msr. Declared HERE, at serve_and_run scope, so its destructor --
    // which puts every register it changed back -- runs on every ordinary exit
    // from this function. It is constructed disabled-by-default and only ever
    // becomes live inside the branch below where the miner itself starts: MSR
    // tuning with no miner running would be a machine-wide change bought for
    // nothing.
    std::unique_ptr<c2pool::xmr::msr::MsrBoost> msr_boost;
#if defined(V37_XMR_O2_WITH_RANDOMX)
    std::unique_ptr<mine::CpuMiner> cpu_miner;
    std::uint32_t mine_extra_nonce = 0;
    std::uint32_t mine_job_tid = 0;
    std::uint64_t mine_pushed = 0, mine_blocks = 0, mine_shares = 0;
    std::string   mine_last_error;
    if (cfg.mine_enabled) {
        if (!serving) {
            std::printf("--mine: REFUSED — this node serves no template (%s), so there is "
                        "nothing to mine on\n", not_served_reason);
        } else if (!rx.network_blocks_allowed()) {
            // Fail-closed, and for the same reason the submit path is: a block
            // this build could not verify would be refused at the gate anyway,
            // so burning cores to produce one would be theatre.
            std::printf("--mine: REFUSED — RandomX is %s; a found block could not be verified "
                        "and would never be published (fail-closed)\n",
                        o2::O2RandomXVerifier::to_string(rx.mode()));
        } else {
            mine::MinerOptions mo;
            mo.threads     = cfg.mine_threads;
            mo.fast_mode   = cfg.mine_fast;
            mo.large_pages = cfg.mine_large_pages;
            mo.pin_threads = cfg.mine_pin;
            cpu_miner = std::make_unique<mine::CpuMiner>(mo);
            // The internal miner takes the TOP extra_nonce slot; the listener
            // hands stratum clients its own counter from 0 upwards, so the two
            // never collide on the same per-client blob.
            const std::uint32_t n = template_source.max_extra_nonces();
            mine_extra_nonce = n ? (n - 1) : 0;
            if (hooks.extra_nonce_base) mine_extra_nonce = *hooks.extra_nonce_base - 1;   // GAP-2: node-private slot
            if (hooks.job_binder) hooks.job_binder(mine_extra_nonce, std::string());        // SEAM-1: the miner's fixed slot
            std::printf("cpu-miner: ENABLED threads=%u mode=%s huge-pages=%s affinity=%s "
                        "extra_nonce=%u (in-process; no external miner)\n",
                        cpu_miner->threads_wanted(),
                        cfg.mine_fast ? "FAST (dataset, ~2080 MiB)" : "LIGHT (cache, ~256 MiB)",
                        cfg.mine_large_pages ? "requested" : "off",
                        cfg.mine_pin ? "on" : "off", mine_extra_nonce);

            // The miner is real, so the MSR tuning is now worth its cost. One
            // attempt, one line, and the destructor (serve_and_run scope) puts
            // the registers back. Every decline is a printed NO-OP: not root,
            // no msr module, unknown family -- the node mines on regardless.
            c2pool::xmr::msr::Options mopt;
            mopt.enabled = cfg.mine_msr;
            msr_boost = std::make_unique<c2pool::xmr::msr::MsrBoost>(mopt);
            if (cfg.mine_msr) {
                msr_boost->apply();
                std::printf("%s\n", msr_boost->describe().c_str());
            }
        }
    }
#else
    if (cfg.mine_enabled)
        std::printf("--mine: REFUSED — this build has no RandomX (configure with "
                    "-DXMR_BUILD_RANDOMX=ON)\n");
#endif
    // --mine-msr without a running miner is an operator mistake worth naming
    // rather than ignoring: it would change machine-wide CPU state to speed up
    // hashing that is not happening.
    if (cfg.mine_msr && !msr_boost)
        std::printf("--mine-msr: REFUSED — no in-process miner is running "
                    "(--mine / --mine-fast), so there is nothing to tune for; "
                    "no register was touched\n");

    // One call per loop pass: (1) keep the miner on the CURRENT template,
    // (2) drain what it found into the node's own share/block-found path.
    auto pump_miner = [&]() {
#if defined(V37_XMR_O2_WITH_RANDOMX)
        if (!cpu_miner) return;
        if (g_lane_suspended_now) {   // R-C rework-2: suspended -> no job, and no hit is ever submitted
            mine::MinerHit dropped;
            while (cpu_miner->pop_hit(dropped)) {}
            return;
        }
        strat::TemplateJob tj;
        if (template_source.get_job(mine_extra_nonce, tj) && tj.template_id != mine_job_tid) {
            // Seed residency BEFORE any hit can arrive: the Argon2d init is the
            // caller's job (verifier invariant I2), and doing it here keeps it
            // off both the submit path and the miner's hot loop.
            rx.on_template(tj);
            mine::MinerJob mj;
            mj.blob           = tj.blob;
            mj.nonce_offset   = tj.nonce_offset;
            mj.template_id    = tj.template_id;
            mj.extra_nonce    = mine_extra_nonce;
            mj.height         = tj.height;
            mj.network_target = tj.mainchain_target;
            mj.lane_target    = tj.lane_target;
            std::copy(tj.seed_hash.begin(), tj.seed_hash.end(), mj.seed_hash.begin());
            std::string why;
            if (cpu_miner->set_job(mj, &why)) {
                mine_job_tid = tj.template_id;
                ++mine_pushed;
            } else if (why != mine_last_error) {
                mine_last_error = why;
                std::printf("  [cpu-miner] job refused: %s\n", why.c_str());
            }
        }
        mine::MinerHit h;
        while (cpu_miner->pop_hit(h)) {
            // SAME ORDER as xmr_stratum.cpp handle_submit: the network block
            // first (so the FoundBlockEvent exists), then the accepted share
            // (which annotates it with worker/address).
            if (h.network) {
                ++mine_blocks;
                std::printf("  [cpu-miner] NETWORK BLOCK candidate tid=%u nonce=%u "
                            "extra_nonce=%u h=%llu pow=%s\n",
                            h.template_id, h.nonce, h.extra_nonce,
                            static_cast<unsigned long long>(h.height),
                            sub::to_hex(h.pow_hash.data(), h.pow_hash.size()).c_str());
                sink.submit_network_block(h.template_id, h.nonce, h.extra_nonce);
            }
            if (h.share || h.network) {
                ++mine_shares;
                strat::AcceptedShare acc;
                acc.template_id      = h.template_id;
                acc.extra_nonce      = h.extra_nonce;
                acc.nonce            = h.nonce;
                acc.pow_hash         = h.pow_hash;
                acc.achieved_target  = h.achieved_target;
                acc.height           = h.height;
                acc.is_network_block = h.network;
                acc.worker           = "cpu-miner";
                acc.address          = cfg.payout_address;
                sink.on_accepted_share(acc);
            }
        }
#endif
    };

    std::signal(SIGINT, on_sigint);
    std::signal(SIGTERM, on_sigint);
    const std::uint32_t poll_ms = cfg.poll_ms ? cfg.poll_ms : 5000;
    if (hooks.pump_tip)
        std::printf("node up. Ctrl-C to stop. (arm-order %s: the NATIVE levin chain drives the "
                    "tip; no monerod poll, every %u ms)\n",
                    to_string(cfg.arm_order), poll_ms);
    else
        std::printf("node up. Ctrl-C to stop. (arm-order %s: ZMQ push drives the tip; RPC poll "
                    "fallback every %u ms)\n",
                    to_string(cfg.arm_order), poll_ms);

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
    // R-C rework-3 (D5 + contested): the lane-suspend state machine (causes lag /
    // isolated / held / contested, each counted on its own rising edge).
    c2pool::v37n::xmr::LaneSuspendState lane_state(cfg.d_conf);
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
                    static_cast<unsigned long long>(node.best_height()),
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
        // c2pool#1551. r7=0 is the claim that matters: it counts settlements the
        // same-height gate did not authorise, which is the only shape an
        // orphan-credit or a double-credit can take.
        {
            const auto& rs = fc.race().stats();
            const auto contested = fc.race().contested_heights();
            std::printf("  same-height: tiebreak=%s D_conf=%llu | own=%llu other=%llu "
                        "contests=%llu (own-vs-other=%llu, open now=%zu) | credited=%llu "
                        "refused[orphaned=%llu other-only=%llu] deferred=%llu renotified=%llu "
                        "| R-7 violations=%llu double-credit blocked=%llu\n",
                        to_string(cfg.same_height_tiebreak),
                        static_cast<unsigned long long>(cfg.d_conf),
                        static_cast<unsigned long long>(rs.own_observed),
                        static_cast<unsigned long long>(rs.other_observed),
                        static_cast<unsigned long long>(rs.contests_opened),
                        static_cast<unsigned long long>(rs.own_vs_other_opened),
                        contested.size(),
                        static_cast<unsigned long long>(fs.race_credited),
                        static_cast<unsigned long long>(fs.race_refused_orphaned),
                        static_cast<unsigned long long>(fs.race_refused_other_only),
                        static_cast<unsigned long long>(fs.race_deferred),
                        static_cast<unsigned long long>(fs.race_renotified),
                        static_cast<unsigned long long>(fs.r7_violations),
                        static_cast<unsigned long long>(rs.double_credit_blocked));
            // R4/R5 booking-order alarms. late_unbooked (both sub-classes) and
            // stall_timeout MUST read 0 in a converged run; root_unknown retries
            // are normal (a receiver one ledger event behind the winner), terminal
            // must be 0.
            std::printf("  r4/r5: late_unbooked=%llu (post_finalize=%llu) stall_timeout=%llu (relay_repair_stall=%llu held=%llu resolved=%llu now=%llu) gate_stalls=%llu "
                        "| lane_root_unknown retries=%llu resolved=%llu terminal=%llu\n",
                        static_cast<unsigned long long>(fs.late_unbooked),
                        static_cast<unsigned long long>(fs.late_booked_post_finalize),
                        static_cast<unsigned long long>(fs.booking_stall_timeout),
                        static_cast<unsigned long long>(fs.relay_repair_stall_timeout),
                        static_cast<unsigned long long>(fs.relay_repair_held),
                        static_cast<unsigned long long>(fs.relay_repair_held_resolved),
                        static_cast<unsigned long long>(fs.relay_repair_held_now),
                        static_cast<unsigned long long>(node.finalize_driver().booking_stalls()),
                        static_cast<unsigned long long>(fs.lane_root_unknown_retries),
                        static_cast<unsigned long long>(fs.lane_root_unknown_resolved),
                        static_cast<unsigned long long>(fs.lane_root_unknown_terminal));
            // R6: two-sided chain-ordered booking + the divergence cap. deferred
            // is normal on a lagging node (it is the fix working); DIVERGED must
            // be 0 in a converged run and 1 -- loud, once -- past the finality
            // boundary (a reorg of depth >= D_conf; docs/xmr-lane/finality-boundary.md).
            {
                const std::uint64_t hw_now = node.hw().hw_height, cur = node.finalize_driver().cursor_height();
                const std::uint64_t fr = hw_now >= cfg.d_conf ? hw_now - cfg.d_conf : 0;
                const auto& fo_ = fc.options();
                std::printf("  r6: booking deferred=%llu attempted_after_deferral=%llu waiting_now=%zu | divergence: lag=%llu (max %llu) "
                            "cap=%llu heights/%llu ticks ticks_over=%llu ISOLATED=%llu alarms=%llu dropped=%llu\n",
                            static_cast<unsigned long long>(fs.booking_deferred),
                            static_cast<unsigned long long>(fs.booked_after_deferral),
                            fc.deferred_now(),
                            static_cast<unsigned long long>(fr > cur ? fr - cur : 0),
                            static_cast<unsigned long long>(fs.divergence_lag_max),
                            static_cast<unsigned long long>(fo_.divergence_cap_heights ? fo_.divergence_cap_heights : 2 * cfg.d_conf),
                            static_cast<unsigned long long>(fo_.divergence_cap_ticks),
                            static_cast<unsigned long long>(fs.divergence_ticks),
                            static_cast<unsigned long long>(fs.diverged),
                            static_cast<unsigned long long>(fs.divergence_alarms),
                            static_cast<unsigned long long>(fs.divergence_dropped));
                // R-C rework-2: the lineage vote (CONVERGED/CONTESTED/ISOLATED; never a
                // halt on refused blocks alone), debit-on-refuse + suspense (money
                // conservation of refused blocks), HELD (never dropped) + HELD-LAG,
                // the F2 gap re-drive, and the split lane-suspend counters.
                const auto ls2 = listener.stats();
                std::printf("  r-c: refused_not_credited=%llu vote=%s (window %llu/%llu refused, %llu unattributed; votes me=%llu counter=%llu; "
                            "contested_entered=%llu isolated_entered=%llu exited=%llu lineages=%llu; obs_restored=%llu)\n",
                            static_cast<unsigned long long>(fs.refused_not_credited),
                            o2::FinalizeConnect::vote_state_name(fc.vote_state()),
                            static_cast<unsigned long long>(fs.obs_refused), static_cast<unsigned long long>(fs.obs_n),
                            static_cast<unsigned long long>(fs.obs_unattributed),
                            static_cast<unsigned long long>(fs.votes_me), static_cast<unsigned long long>(fs.votes_counter),
                            static_cast<unsigned long long>(fs.contested_entered), static_cast<unsigned long long>(fs.isolated_entered),
                            static_cast<unsigned long long>(fs.isolated_exited), static_cast<unsigned long long>(fs.counter_lineages),
                            static_cast<unsigned long long>(fs.obs_restored));
                // R-C rework-3 (b): refused blocks' on-chain value is NODE-LOCAL LIABILITY;
                // ledger_mutations_on_refuse is the invariant (must read 0).
                std::printf("  liability: blocks=%llu pico=%llu (attributed=%llu to %llu payee(s), unattributed=%llu) | "
                            "ledger_mutations_on_refuse=%llu legacy_debit_records=%llu\n",
                            static_cast<unsigned long long>(fs.liability_blocks), static_cast<unsigned long long>(fs.liability_pico),
                            static_cast<unsigned long long>(fs.liability_attributed_pico), static_cast<unsigned long long>(fs.liability_payees),
                            static_cast<unsigned long long>(fs.liability_unattributed_pico),
                            static_cast<unsigned long long>(fs.ledger_mutations_on_refuse),
                            static_cast<unsigned long long>(fs.legacy_debit_records));
                const auto& gs = node.gap_stats();
                std::printf("  hold: held_now=%llu entered=%llu resolved=%llu | held_lag=%llu (entered %llu cleared %llu) | carry_unknown=%llu walk_holds=%llu "
                            "| gap-redrive scan=%llu heights=%llu calls=%llu fetch_failed=%llu truncated=%llu gate_holds=%llu\n",
                            static_cast<unsigned long long>(fs.held_now), static_cast<unsigned long long>(fs.held_entered),
                            static_cast<unsigned long long>(fs.held_resolved), static_cast<unsigned long long>(fs.held_lag),
                            static_cast<unsigned long long>(fs.held_lag_entered), static_cast<unsigned long long>(fs.held_lag_cleared),
                            static_cast<unsigned long long>(node.carry_unknown_answers()),
                            static_cast<unsigned long long>(node.finalize_driver().carry_unknown_holds()),
                            static_cast<unsigned long long>(node.scan_height()), static_cast<unsigned long long>(gs.redriven_heights),
                            static_cast<unsigned long long>(gs.redrive_calls), static_cast<unsigned long long>(gs.fetch_failed),
                            static_cast<unsigned long long>(gs.truncated), static_cast<unsigned long long>(gs.gate_holds));
                std::printf("  suspend: lane_suspended=%s (job %s) causes=%s | suspend lag=%llu isolated=%llu held=%llu contested=%llu "
                            "edges=%llu resume=%llu | stratum edges=%llu disconnects=%llu sink_refused=%llu push_refused=%llu\n",
                            listener.lane_suspended() ? "YES" : "no",
                            listener.lane_suspended() ? "WITHDRAWN, sessions dropped, logins parked" : "served",
                            c2pool::v37n::xmr::LaneSuspendState::names(lane_state.causes).c_str(),
                            static_cast<unsigned long long>(lane_state.n_lag), static_cast<unsigned long long>(lane_state.n_isolated),
                            static_cast<unsigned long long>(lane_state.n_held), static_cast<unsigned long long>(lane_state.n_contested),
                            static_cast<unsigned long long>(lane_state.n_suspend), static_cast<unsigned long long>(lane_state.n_resume),
                            static_cast<unsigned long long>(ls2.suspend_edges), static_cast<unsigned long long>(ls2.suspend_disconnects),
                            static_cast<unsigned long long>(ls2.suspended_sink_refused), static_cast<unsigned long long>(ls2.suspended_push_refused));
            }
            for (const std::uint64_t h : contested) {
                const auto* cs = fc.race().candidates_at(h);
                if (!cs) continue;
                std::string line;
                for (const auto& c : *cs)
                    line += " " + c.bid.substr(0, 12) + (c.own ? "(ours)" : "(theirs)");
                std::printf("    contested h=%llu:%s\n",
                            static_cast<unsigned long long>(h), line.c_str());
            }
        }
#if defined(V37_XMR_O2_WITH_RANDOMX)
        if (cpu_miner)
            std::printf("  %s | jobs_pushed=%llu blocks=%llu shares=%llu | %s\n",
                        cpu_miner->describe().c_str(),
                        static_cast<unsigned long long>(mine_pushed),
                        static_cast<unsigned long long>(mine_blocks),
                        static_cast<unsigned long long>(mine_shares),
                        cpu_miner->pinning_note().c_str());
#endif
        std::printf("  %s\n", rx.describe().c_str());
        const std::string g = sink.last();
        if (!g.empty()) std::printf("  gate: last=%s\n", g.c_str());
        if (p2p_publish) {
            std::printf("  p2p publish: calls=%llu relayed=%llu peers_written=%llu refused=%llu "
                        "reached_nobody=%llu stale=%llu | parked=%zu late_reached=%llu "
                        "abandoned=%llu orphaned_unreached=%llu dup_found=%llu "
                        "| solo_own_index=%s landed=%llu\n",
                        static_cast<unsigned long long>(publisher->calls()),
                        static_cast<unsigned long long>(publisher->relayed()),
                        static_cast<unsigned long long>(publisher->peers()),
                        static_cast<unsigned long long>(publisher->refused()),
                        static_cast<unsigned long long>(publisher->failed()),
                        static_cast<unsigned long long>(publisher->stale()),
                        publisher->parked(),
                        static_cast<unsigned long long>(publisher->late_reached()),
                        static_cast<unsigned long long>(publisher->abandoned()),
                        static_cast<unsigned long long>(publisher->orphaned_unreached()),
                        static_cast<unsigned long long>(publisher->duplicate_found()),
                        publisher->solo_own_index_enabled() ? "ON" : "off",
                        static_cast<unsigned long long>(publisher->solo_landed()));
            const std::string pe = publisher->last_error();
            if (!pe.empty()) std::printf("  p2p publish: last=%s\n", pe.c_str());
        } else {
            const std::string se = submitter.last_error();
            if (!se.empty()) std::printf("  submit: last_error=%s\n", se.c_str());
        }
        std::fflush(stdout);
    };

    auto last_status = std::chrono::steady_clock::now();
    std::string last_template_err;
    // R-C rework-2/3: THE LANE-SUSPEND STATE, one place, four causes, per-cause counters
    // (xmr/xmr_lane_suspend_state.hpp).
    //   lag      -- ONE lag definition everywhere (the R6 one, frontier-based):
    //               lag = (hw - D_conf) - cursor. Suspend at lag > 2*D_conf, RESUME
    //               at lag <= D_conf (hysteresis). The old gate used tip - cursor
    //               (a D_conf offset against R6), which never auto-resumed in
    //               the verify rig (RESUMED=0).
    //   isolated -- the lineage vote: a VERIFIED counter-lineage outvotes us
    //               (FinalizeConnect ISOLATED; non-terminal).
    //   held     -- HELD-LAG (an undecided lane block holds the cursor past the cap).
    //   contested -- R-C rework-3 operator opt-in (--contested-suspend on; default
    //               off): the lineage vote is CONTESTED; auto-resumes when CONVERGED.
    // The ISOLATED and CONTESTED edges are ALSO applied synchronously from inside
    // fc.tick() through their hooks; every cause is re-evaluated (and COUNTED on
    // its own rising edge -- D5) right after fc.tick() by LaneSuspendState.
    auto miner_suspend = [&]() {
#if defined(V37_XMR_O2_WITH_RANDOMX)
        if (cpu_miner) {
            cpu_miner->stop();                       // workers halted, job invalidated
            mine::MinerHit dropped; std::size_t n = 0;
            while (cpu_miner->pop_hit(dropped)) ++n;  // a hit on the withdrawn job is never submitted
            mine_job_tid = 0;                        // resume re-pushes the (fresh) template
            std::printf("  [cpu-miner] STOPPED on lane suspend (%zu queued hit(s) discarded)\n", n);
        }
#endif
    };
    auto apply_suspension = [&]() -> bool {
        if (!serving) return false;
        const std::uint64_t hw_now = node.hw().hw_height;
        const std::uint64_t cursor = node.finalize_driver().cursor_height();
        const std::uint64_t frontier = hw_now >= cfg.d_conf ? hw_now - cfg.d_conf : 0;
        const std::uint64_t lag = frontier > cursor ? frontier - cursor : 0;
        const bool contested = fc.options().contested_suspends && fc.contested();
        const auto e = lane_state.update(lag, fc.isolated(), fc.held_lag(), contested);
        const bool lane_suspend = lane_state.suspended();
        listener.set_lane_suspended(lane_suspend);   // edge-triggered inside (disconnect + park), gated (D4)
        g_lane_suspended_now = lane_suspend;
        using LS = c2pool::v37n::xmr::LaneSuspendState;
        auto cause_text = [](unsigned c) -> std::string {
            std::string t;
            if (c & LS::kIsolated)  t += " ISOLATED (a verified counter-lineage outvotes this node);";
            if (c & LS::kContested) t += " CONTESTED (>= 1/3 of the recent frontier lane blocks refused; operator opt-in --contested-suspend on);";
            if (c & LS::kHeld)      t += " HELD-LAG (an undecided lane block holds the cursor);";
            if (c & LS::kLag)       t += " LAG (finalize cursor behind the buried frontier);";
            return t;
        };
        if (e.suspend_edge) {
            miner_suspend();
            std::printf("cba-ALARM: lane template production SUSPENDED + stratum job WITHDRAWN (sessions dropped, logins parked) "
                        "+ in-process miner stopped -- cause=%s:%s (hw=%llu frontier=%llu cursor=%llu lag=%llu suspend>%llu resume<=%llu). "
                        "The node stays alive (chain follow, settlement, booking, peer relay); it will not emit a block committing a "
                        "stale/minority owed_digest root.%s\n",
                        LS::names(e.causes).c_str(), cause_text(e.causes).c_str(),
                        static_cast<unsigned long long>(hw_now), static_cast<unsigned long long>(frontier),
                        static_cast<unsigned long long>(cursor), static_cast<unsigned long long>(lag),
                        static_cast<unsigned long long>(lane_state.suspend_above()), static_cast<unsigned long long>(lane_state.resume_at()),
                        (e.causes & LS::kIsolated) ? " Exit: W6 verified adoption + restart, or the vote flips." : " Auto-resumes when every cause clears.");
            std::fflush(stdout);
        } else if (e.added) {
            // D5: a cause that rises while the lane is ALREADY suspended is counted and named.
            std::printf("cba-ALARM: lane suspension cause ADDED cause=%s:%s (active now: %s; lag=%llu)\n",
                        LS::names(e.added).c_str(), cause_text(e.added).c_str(), LS::names(e.causes).c_str(),
                        static_cast<unsigned long long>(lag));
            std::fflush(stdout);
        }
        if (e.resume_edge) {
            std::printf("cba: lane template production RESUMED -- all suspend causes cleared (lag=%llu <= %llu, not isolated, "
                        "no held-lag, vote not contested); parked logins will be served the fresh template\n",
                        static_cast<unsigned long long>(lag), static_cast<unsigned long long>(lane_state.resume_at()));
            std::fflush(stdout);
        } else if (e.cleared && lane_suspend) {
            std::printf("cba: lane suspension cause cleared cause=%s (still suspended: %s)\n",
                        LS::names(e.cleared).c_str(), LS::names(e.causes).c_str());
            std::fflush(stdout);
        }
        return lane_suspend;
    };
    fc.set_isolation_hook([&](bool on, const std::string&) {
        if (!on || !serving) return;
        listener.set_lane_suspended(true);   // synchronous: before fc.tick() returns
        g_lane_suspended_now = true;
        miner_suspend();
    });
    // R-C rework-3: CONTESTED suspends synchronously too (operator opt-in; default off); the
    // release is left to apply_suspension (another cause may still hold the lane).
    fc.set_contested_hook([&](bool on, const std::string&) {
        if (!on || !serving) return;
        listener.set_lane_suspended(true);
        g_lane_suspended_now = true;
        miner_suspend();
    });
    while (!g_stop.load()) {
        pump_miner();       // --mine: hits first, so a find is bridged the same pass
        if (hooks.inject_pump) hooks.inject_pump();  // --native-inject-dir scan
        if (publisher) publisher->tick();   // parked (reached-nobody) blocks: bounded re-announce
        bridge_found();
        fc.tick();
        const bool lane_suspend = apply_suspension();   // right after the tick that may have decided it
        if (hooks.cba_tick) hooks.cba_tick();   // 
        // M3: THE cut. daemon-first keeps the monerod poll + seed backfill;
        // p2p-first replaces both with the native chain's own event drain, and
        // this is the only place either of them is driven -- so "no daemon call
        // on the find path" is a property of one branch, not of good behaviour.
        if (hooks.pump_tip) hooks.pump_tip();
        else {
            transport.pump_poll();
            node.adapter().ensure_seed_reach();
        }
        if (serving) {

            const bool refreshed = lane_suspend ? false : provider.refresh();
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
            } else if (!lane_suspend) {
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

    fc.set_isolation_hook({});   // R-C rework-2: the hook captures loop-scope state; detach before teardown
    fc.set_contested_hook({});
    std::printf("\nstopping…\n");
#if defined(V37_XMR_O2_WITH_RANDOMX)
    if (cpu_miner) { cpu_miner->stop(); pump_miner(); }   // drain anything already found
#endif
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

// ---------------------------------------------------------------------------
// M3: build and start the embedded native node.
//
// Hoisted out of the option-B branch because the ORDER changed. Under
// --arm-order p2p-first this node is the tip driver, and XmrNode::bring_up()
// binds the finalize driver's canonical test at construction -- so the native
// chain has to exist BEFORE bring_up, not after it. Under daemon-first the
// order is immaterial and this is the same code M2h ran.
//
// Returns null on refusal, with the reason already printed.
// ---------------------------------------------------------------------------
static std::unique_ptr<o2::NativeTemplateBackend> start_native_backend(const XmrNodeConfig& cfg) {
    // An address source is required and either kind will do. Before --seeds was
    // forwarded, --native-connect was the ONLY one, which is why this refusal
    // named it alone; a mainnet operator who asked for seeds and nothing else
    // got this message and no way to act on it. --native-solo is the deliberate
    // exception: a private chain of our own, with no network to dial.
    if (cfg.native_connect.empty() && !cfg.native_solo && !cfg.native_use_seeds) {
        std::printf("REFUSED: the native Monero node needs an address source -- at least one "
                    "--native-connect <ip:port> levin peer, or --native-seeds to bootstrap "
                    "from the network's own seed set (it dials only what it is told to)\n");
        return nullptr;
    }
    const bool p2p_first = (cfg.arm_order == ArmOrderMode::P2PFirst);

    // THE FORWARD, in one call. Everything derivable from the configuration
    // value is derived in native_template_config_of(), so a knob cannot be
    // parsed here and dropped on the way to the node -- which is what happened
    // to the gate 4 window and to --seeds. The two fields below are the ones
    // that are NOT a function of the config value: a path through
    // config_path(), and a build macro.
    o2::NativeTemplateConfig ncfg = o2::native_template_config_of(cfg);
    ncfg.parity_ledger_path       = cfg.resolved_settle_db_path() + "/xmr_parity_ledger.json";
    ncfg.c2pool_commit            = C2POOL_VERSION;

    if (cfg.native_solo)
        std::printf("template source: NATIVE, SOLO — no peers, no daemon, no anchor: the chain "
                    "starts at the locally assembled genesis block (id-checked against the "
                    "pinned one) and every block after it is one this process mined itself\n");
    else
        std::printf("template source: NATIVE — the embedded Monero node (levin, %zu pinned peer(s)%s) "
                    "feeds the option-B assembler%s\n",
                    cfg.native_connect.size(),
                    cfg.native_use_seeds ? " + network seeds" : "",
                    p2p_first ? "; it is ALSO the tip, the canonical test and the block relay "
                                "(--arm-order p2p-first): monerod is not on the find path"
                              : "; monerod stays the parity judge and the submit arm, and is NOT "
                                "on the template path");
    // D6d: say which of the two p2p-first postures this is, so a run's wire count
    // can be read against the configuration that produced it.
    if (p2p_first && !cfg.native_solo)
        std::printf("  parity judge (monerod): %s\n",
                    ncfg.monerod_rpc_port == 0
                        ? "OFF -- tip, RandomX seed and difficulty/height come from the native "
                          "chain index; no monerod RPC is made (--native-parity-monerod opts the "
                          "compare-only judge back in)"
                        : "ON, compare-only (--native-parity-monerod): get_miner_data + get_info + "
                          "get_last_block_header on the status cadence, never on the find path");
    if (ncfg.boot == ::c2pool::xmr::native::rt::BootMode::Anchor) {
        // GATE 4 is not optional and has no off switch, so the operator is told
        // what window it will run in rather than left to infer it from a
        // refusal. Widening it is the only thing these three flags can do.
        std::printf("  gate 4 (anchor network confirm): up to %u peer(s), %llu ms each, "
                    "%llu ms in total — the anchor is fetched from live peers and re-hashed "
                    "before this node serves anything\n",
                    static_cast<unsigned>(ncfg.anchor_confirm.peers),
                    (unsigned long long)ncfg.anchor_confirm.per_peer_ms,
                    (unsigned long long)ncfg.anchor_confirm.timeout_ms);
    }
    if (!ncfg.snapshot_path.empty()) {
        std::printf("  chain snapshot: %s (save every %llus, and on a clean stop) — a restart "
                    "resumes there instead of re-walking from the anchor; an absent, corrupt "
                    "or foreign snapshot falls back to the anchor boot\n",
                    ncfg.snapshot_path.c_str(),
                    (unsigned long long)ncfg.snapshot_every_s);
    }

    auto native = std::make_unique<o2::NativeTemplateBackend>(std::move(ncfg));
    std::string why;
    if (!native->start_and_wait(why, [](const std::string& w) {
            std::printf("  native: not ready yet — %s\n", w.c_str());
            std::fflush(stdout);
        })) {
        std::printf("REFUSED: %s\n", why.c_str());
        // A refused start is where gate 4's verdict lives, so the node's own log
        // is drained here rather than lost with the node. Two sources because
        // there are two shapes of refusal: start() failing (the node is already
        // gone, and the backend kept its log) and the readiness wait expiring
        // (the node is still there).
        for (const std::string& l : native->start_log())
            std::fprintf(stderr, "  node: %s\n", l.c_str());
        if (auto* n = native->node()) for (const std::string& l : n->take_log())
            std::fprintf(stderr, "  node: %s\n", l.c_str());
        return nullptr;
    }
    std::printf("  native: template arm READY, fallback %s\n",
                native->config().fallback
                    ? "ON (the daemon arm may serve if the native one loses a window)"
                    : "OFF (native-only: no template is served if the native arm is not ready)");
    if (auto* n = native->node()) for (const std::string& l : n->take_log())
        std::printf("  node: %s\n", l.c_str());
    return native;
}

static int run_live(const XmrNodeConfig& cfg) {
    // REGTEST-ONLY rig knobs (the receipt-feed carrier stand-in, the v0x02
    // fast-path file relay, and the amount-sensitivity falsifier) are fenced OFF
    // on mainnet: they simulate the not-yet-landed S-1 carrier relay and must
    // never drive a real settlement. The on-chain credit cut itself (the 44-byte
    // 0x02 tail, R1) is operator-approved for all networks and stays armed.
    if (cfg.network == MoneroNetwork::Mainnet &&
        (!g_credit_feed.empty() || !g_wire_out.empty() || !g_wire_in.empty() ||
         g_credit_feed_lag_ms != 0 || g_credit_mutate != 0)) {
        std::printf("NOTICE: --credit-feed/--wire-out/--wire-in/--credit-feed-lag-ms/--credit-mutate "
                    "are REGTEST-ONLY carrier-relay stand-ins; IGNORED on mainnet (fenced OFF)\n");
        g_credit_feed.clear(); g_wire_out.clear(); g_wire_in.clear();
        g_credit_feed_lag_ms = 0; g_credit_mutate = 0;
    }
    // GAP-2: the real relay REPLACES the stand-ins; the two are never mixed.
    if (relay_enabled()) {
        if (!g_credit_feed.empty() || !g_wire_out.empty() || !g_wire_in.empty() || g_credit_feed_lag_ms) {
            std::printf("REFUSED: --relay-listen/--relay-peer (the real receipt relay) and --credit-feed/--wire-out/--wire-in "
                        "(its file stand-ins) are mutually exclusive\n");
            return 2;
        }
        if (g_relay_bind != "none" && g_relay_bind != "rbind") {
            std::printf("REFUSED: --relay-bind takes none|rbind\n");
            return 2;
        }
        // SEAM-1: the template now writes rbind into the coinbase 0x02 region, so
        // the relay may run on mainnet -- but ONLY with the payee/give-author PoW
        // binding active (--relay-bind rbind). bind=none stays regtest/stagenet/testnet.
        if (cfg.network == MoneroNetwork::Mainnet && g_relay_bind != "rbind") {
            std::printf("REFUSED: the receipt relay on mainnet requires --relay-bind rbind (the payee/give-author PoW "
                        "binding, SEAM-1, coinbase 0x02 [extra_nonce|rbind]); bind=none is regtest/stagenet/testnet only\n");
            return 2;
        }
        if (cfg.coinbase != CoinbaseMode::V37Settlement) {
            std::printf("REFUSED: the receipt relay needs --coinbase v37 (a lane coinbase to open)\n");
            return 2;
        }
        if (cfg.stratum_share_diff == 0) {
            std::printf("REFUSED: the receipt relay needs a fixed --share-diff (the R-1 target every node must share)\n");
            return 2;
        }
        if (g_relay_order != "canonical" && g_relay_order != "arrival") {
            std::printf("REFUSED: --relay-order takes canonical|arrival\n");
            return 2;
        }
    }
    // fee model (S4): LaneParams::fee. OFF (default) => master-identical; ON is a
    // lane-level consensus choice every peer must share (folded into the relay's
    // lane_params_digest, so a mixed fleet refuses at HELLO).
    if (c2pool::v37n::xmr::fee::fee_model_on(cfg.lane_params)) {
        if (cfg.coinbase != CoinbaseMode::V37Settlement) {
            std::printf("REFUSED: --fee-model v1 shapes the v37 settlement coinbase; it needs --coinbase v37\n");
            return 2;
        }
        if (relay_enabled() && g_relay_bind != "rbind") {
            std::printf("REFUSED: --fee-model v1 with the receipt relay needs --relay-bind rbind: the give-author u16 and "
                        "the owner-fee payee must be PoW-bound in the receipt (S3), not merely carried\n");
            return 2;
        }
        if (!g_credit_feed.empty()) {
            std::printf("REFUSED: --fee-model v1 reads give-author only from the PoW-committed relay receipt (S3), never "
                        "from a feed line; drop --credit-feed (use --relay-listen/--relay-peer with --relay-bind rbind)\n");
            return 2;
        }
    } else if (cfg.lane_params.fee.enabled) {
        std::printf("REFUSED: unknown fee-model version %u\n", cfg.lane_params.fee.version);
        return 2;
    } else if (g_give_author_pct != 0.0 || g_owner_fee_pct != 0.0 || !g_owner_address.empty()) {
        std::printf("REFUSED: --give-author-pct / --node-owner-fee-pct / --node-owner-address need --fee-model v1 "
                    "(the fee model is OFF: this node is master-identical)\n");
        return 2;
    }
    // The banner names the daemon it will talk to. Under --native-solo there is
    // none -- no endpoint is wired anywhere (start_native_backend() withholds
    // it) -- so printing the default 18081 there would advertise a connection
    // the process never makes, which is exactly the claim this mode is about.
    if (cfg.native_solo)
        std::printf("c2pool-v37-xmr: EXPERIMENTAL prototype — network=%s monerod=NONE (--native-solo: "
                    "no daemon endpoint is configured) arm-order=%s\n",
                    to_string(cfg.network), to_string(cfg.arm_order));
    else
        std::printf("c2pool-v37-xmr: EXPERIMENTAL prototype — network=%s monerod=%s:%u (zmq %u) "
                    "arm-order=%s\n",
                    to_string(cfg.network), cfg.monerod.rpc_host.c_str(),
                    cfg.monerod.rpc_port, cfg.monerod.zmq_port, to_string(cfg.arm_order));
    if (cfg.network == MoneroNetwork::Mainnet && !cfg.i_understand_mainnet) {
        std::printf("REFUSED: mainnet requires --i-understand-mainnet (prototype safety)\n");
        return 2;
    }

    // ── M3: p2p-first is fail-closed on its own preconditions ───────────────
    // The rules live in the config header as a pure function, so the thing the
    // daemon refuses on and the thing the KAT pins are the same code.
    const bool p2p_first = (cfg.arm_order == ArmOrderMode::P2PFirst);
    if (const std::string refusal = arm_order_refusal(cfg); !refusal.empty()) {
        std::printf("REFUSED: %s\n", refusal.c_str());
        return 2;
    }
    if (const std::string refusal = solo_refusal(cfg); !refusal.empty()) {
        std::printf("REFUSED: %s\n", refusal.c_str());
        return 2;
    }

    // The native node comes up FIRST in p2p-first: it is the chain XmrNode's
    // finalize driver will be bound to, and that binding happens in bring_up().
    std::unique_ptr<o2::NativeTemplateBackend> native;
    if (cfg.coinbase == CoinbaseMode::V37Settlement &&
        cfg.template_source == TemplateSourceMode::Native) {
        native = start_native_backend(cfg);
        if (!native) return 2;
    }

    LiveMonerodTransport transport(cfg.monerod);
    XmrNode node(cfg, transport);
    o2::NativeChainSource chain_src;
    if (p2p_first) {
        chain_src = o2::native_chain_source(*native);
        if (!chain_src) {
            std::printf("REFUSED: the native node exposed no chain source (internal wiring bug)\n");
            return 2;
        }
        node.set_native_chain_presence(chain_src.is_canonical);
        node.set_native_row_lookup(chain_src.bid_at);   // D2-0: reorg-in blocks below a Reorg tip reach the booking observer
    }
    // R-C rework-2 (F2): daemon-first re-drives every chain gap (downtime / a ZMQ
    // gap wider than the reconcile walk) through the booking path.
    if (!p2p_first) node.enable_gap_redrive(true);
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
    // R6: two-sided chain-ordered booking (ON) + the divergence cap.
    fo.book_deferral           = !g_no_book_deferral;
    fo.divergence_cap_heights  = g_divergence_cap_heights;
    fo.divergence_cap_ticks    = g_divergence_cap_ticks;
    fo.divergence_cap_terminal = g_divergence_cap_terminal;
    fo.contested_suspends      = g_contested_suspend;   // R-C rework-3 ruled default OFF (opt-in)
    std::printf("r-c rework-3: refuse-side money = NODE-LOCAL LIABILITY (never a ledger mutation) | contested-suspend=%s | "
                "vote window persisted=%s\n", fo.contested_suspends ? "ON" : "off", fo.persist_vote_obs ? "yes" : "no");
    std::printf("r6: book_deferral=%s divergence cap: heights=%llu (0 = 2*D_conf = %llu) ticks=%llu terminal=%llu\n",
                fo.book_deferral ? "ON" : "OFF (pre-R6 booking order; lagging receiver forks)",
                static_cast<unsigned long long>(fo.divergence_cap_heights),
                static_cast<unsigned long long>(2 * cfg.d_conf),
                static_cast<unsigned long long>(fo.divergence_cap_ticks),
                static_cast<unsigned long long>(fo.divergence_cap_terminal));
    // c2pool#1551: the per-height verdict journal. Default it next to the
    // settle store so that a multi-node run leaves one comparable file per node
    // without the operator having to ask for it.
    if (cfg.same_height_journal != "off")
        fo.race_journal_path = cfg.same_height_journal.empty()
                                   ? cfg.resolved_settle_db_path() + "/race.log"
                                   : cfg.same_height_journal;
    // Lever (2): the bounded prefer-own re-announce. Only the native levin
    // relay can do it -- under daemon-first the block went out through
    // monerod's submit_block and re-submitting a block monerod already has is
    // a no-op, so the lever is simply absent there and the gate says so.
    if (p2p_first && native && native->node() && native->node()->block_relay()) {
        auto* relay = native->node()->block_relay();
        fo.renotify = [relay](std::uint64_t height, const std::string& bid_hex) {
            (void)height;
            c2pool::xmr::node::Hash id{};
            if (!o2::hash_from_hex(bid_hex, id)) return false;
            std::size_t peers = 0;
            return relay->renotify(id, &peers);
        };
    }
    //  state (lifetimes: all outlive serve_and_run; the pointers are set in the option-B branch)
    o2::XmrOwedFixture*            cba_fx   = nullptr;
    const o2::XmrSettlementConfig* cba_scfg = nullptr;
    // R-C rework-3 (D7): this node's owed_digest history (newest at back) WITH the
    // coin height each state became current at -- the root-age bound needs it.
    c2pool::v37n::xmr::recon::ReconRing cba_ring(4096);
    const std::uint64_t cba_max_root_age = g_recon_max_root_age == ~std::uint64_t{0}
        ? c2pool::v37n::xmr::recon::default_max_root_age(cfg.d_conf) : g_recon_max_root_age;
    std::optional<::v37::bytes32>  cba_payee;
    unsigned long long             cba_lane_root_unknown = 0;   // counted alarm: 03-root matched no candidate (distinct bids)
    std::set<std::string>          cba_root_unknown_seen;       // R5: alarm once per bid; the retries are FinalizeConnect's
    // RECOMPUTE CROSS-CHECK (own wins): the bytes WE assembled and submitted
    // (candidate full_blob off the provider ring, captured at submit-OK) vs the
    // block the CHAIN carries (get_block, the authority). recompute = sanity,
    // on-chain coinbase = authority: on a mismatch we ALARM and still book the
    // on-chain coinbase. Peer blocks have no local recompute (no template).
    std::function<bool(std::uint32_t, std::uint32_t, sub::BlockCandidate&)> own_candidate_lookup;
    std::map<std::string, std::vector<std::uint8_t>> own_recompute;   // bid -> our submitted full_blob
    std::uint64_t recompute_captured = 0, recompute_unavailable = 0, recompute_ok = 0, recompute_mismatch = 0;
    std::optional<::v37::ScriptRef> cba_payee_ref;
    std::uint64_t cba_fetches = 0, cba_booked = 0, cba_not_lane = 0, cba_refused = 0;
    std::uint64_t cba_fetch_failed = 0;   // R-C rework-3 (D6): get_block transport/JSON failures -- transient, NOT refusals
    std::uint64_t cba_stale_root = 0;     // R-C rework-3 (D7): matched a historical root older than the age bound -> refused

    auto cba_ring_push = [&]() {
        const ::v37::bytes32 d = node.ledger().owed_digest();
        if (cba_ring.push(d, node.finalize_driver().digest_since())) {
            std::printf("cba-digest: cursor=%llu hw=%llu ledger_seq=%llu owed_digest=%s\n",
                        static_cast<unsigned long long>(node.finalize_driver().cursor_height()),
                        static_cast<unsigned long long>(node.hw().hw_height),
                        static_cast<unsigned long long>(node.ledger().ledger_seq()), hex_of(d).c_str());
            std::fflush(stdout);
        }
    };
    // R-B(i) follow-up: seed the ring from the boot replay so a RESUMED node holds its
    // FULL canonical history (post R-A every state is D(c)); without this a restart
    // left a 1-entry ring, and any peer root >= 1 cursor behind could never match while
    // the R4 gate (held by that very block) kept the ring from growing -> permanent hold.
    // decode_blob (below) already matches against the WHOLE ring, so a stale-but-canonical
    // root every converged peer also passed through matches here (defect 2: a K-window
    // turned an honest stale root into a network-wide halt).
    cba_ring.seed(node.boot_digest_history(), node.boot_digest_since());
    std::printf("cba-ring: seeded %zu canonical owed_digest state(s) from the boot replay (newest since h=%llu); "
                "RECON root-age bound = %llu heights%s\n", cba_ring.size(),
                static_cast<unsigned long long>(cba_ring.empty() ? 0 : cba_ring.back().since),
                static_cast<unsigned long long>(cba_max_root_age), cba_max_root_age ? "" : " (0 = UNBOUNDED, the rework-2 behaviour)");
    const bool cba_ring_seeded = node.recovered().recovered && node.boot_digest_history().size() > 1;
    // recon(A+B credit) state ──────────────────────────────────────────────────────────
    std::vector<::v37::ScriptRef> feed_refs;   // XMR_STD refs of the seeded owed keys (the receipt descriptors)
    std::uint64_t feed_off = 0, feed_pushed = 0, feed_rejected = 0;
    std::deque<std::pair<std::chrono::steady_clock::time_point, std::string>> feed_lagq;
    struct WireCache { c2pool::v37n::CutDescriptor d; bool prefolded = false; Amounts credit;
                       c2pool::v37n::settle::WorkPrice price{};   // ★ DROPS: the price at the prefolded cut (gate ON only)
                     };
    // ★ DROPS: the XMR shell's DropsWiring. nullptr in a default build (flip at 0)
    // and whenever the lane geometry does not carry the gate: then nothing below
    // is constructed, attached or priced, and every path is master's. Built and
    // attached further down, once the native tip is known and before the relay
    // listens or the stratum binds; declared HERE because the booking lambdas
    // below capture it. `drops_live` = built AND attached (it needs the receipt
    // relay: raindrops must be replicated, see xmr_drops_wiring.hpp (4)).
    std::unique_ptr<c2pool::v37n::xmr::drops::XmrDropsWiring> drops;
    bool drops_live = false;
    c2pool::v37n::settle::WorkPrice drops_fold_price{};   // the price of the LAST successful fold_at_cut (gate ON only)
    std::atomic<std::uint64_t> drops_mint_ok{0}, drops_mint_below_floor{0};
    std::map<std::string, WireCache> wire_cache;   // bid -> the v0x02 descriptor (+ its early fold)
    std::set<std::string> wire_seen;
    std::uint64_t wire_tx = 0, wire_rx = 0, wire_prefold = 0, wire_pending = 0, wire_hit = 0, wire_mismatch = 0, wire_diverged = 0;
    std::uint64_t cut_ok = 0, cut_pending = 0, cut_miss = 0, cut_mismatch = 0, cut_absent = 0, cut_fold_refused = 0;
    std::uint64_t cut_repaired = 0;   // R3: cut-misses reconstructed by W4 replay-to-prefix
    std::string   last_credit_line;
    // R3 state: the ordered, DERIVABLE receipt-push log for this lane (the same
    // records, in the same order, every node folds). It is what lets a receiver
    // whose 128-deep ring evicted prefix P reconstruct the view at P by replay:
    // this node ingested every push (feed is deterministic + shared), so a
    // cut-MISS here is a PUBLICATION miss, not a missing-record miss. Also
    // written durably to <data-dir>/lane<chain>.pushes and reloaded at boot.
    std::vector<std::pair<::v37::ScriptRef, std::uint64_t>> feed_log;
    std::map<std::string, std::shared_ptr<const c2pool::v37n::SettlementView>> replay_cache;   // "P:spinehex" -> verified view (whole booking window)
    // GAP-2 relay state. Constructed in the option-B branch when --relay-* is
    // given; null = the relay is off and every path below is the stand-in one.
    // Declaration order = teardown order in reverse: everything the relay's
    // threads touch (chain view, log queue, verifier) outlives relay_node.
    std::uint64_t relay_cut_repaired = 0, relay_repair_rejected = 0, relay_own_replay = 0;
    std::mutex    relay_log_mtx;
    std::vector<std::string> relay_log_q;
    std::atomic<std::uint64_t> mint_ok{0}, mint_fail{0}, mint_below{0}, mint_nopayee{0};
    std::atomic<std::uint64_t> bind_jobs{0}, bind_owner{0}, bind_nopayee{0};   // SEAM-1 job bindings (owner-fee hits)
    std::mt19937_64 bind_rng{std::random_device{}()};                          // SEAM-1 owner-fee roll (under mint_mtx)
    std::shared_ptr<relay::RbindRegistry> rbind_reg;                           // SEAM-1 (null unless --relay-bind rbind)
    std::mutex    mint_mtx;                                   // payee cache + last error (listener + main thread)
    std::string   mint_last_err;
    std::map<std::string, std::optional<::v37::ScriptRef>> mint_payee_cache;
    relay::ChainView                          relay_chain;
    relay::NativeCtxSource                    relay_native_ctx;   // RC-CTX: unset unless a native node runs
    relay::NativeCtxFeeder                    relay_ctx_feeder;
    relay::CtxJournal                         relay_ctx_journal;
    std::unique_ptr<o2::O2RandomXVerifier>    relay_rx;       // the verify worker's own light VM (+256 MiB)
    std::unique_ptr<relay::XmrRelayNode>      relay_node;
    std::unique_ptr<relay::XmrReceiptIngest>  relay_ingest;
    auto relay_hint = [&](const std::string& bid) -> std::uint64_t {
        if (!relay_node) return 0;
        const auto b = c2pool::v37n::cut_bid_bytes(bid);
        return b ? relay_node->peer_of_bid(*b) : 0;
    };
    auto amounts_str = [&](const Amounts& m) { std::string s; for (const auto& [k, a] : m) s += hex_of(k).substr(0, 8) + "=" + std::to_string(a) + " "; return s; };
    // decode one block blob's coinbase under coinbase authority against OUR candidate ring
    // (R5: the ring is fed per ledger event, so every owed_digest state this ledger passed
    // through is a candidate -- newest first, the live digest at index 0)
    // R-C rework-3 (D7): `superseded_out` (optional) receives, per candidate, the
    // coin height at which that state stopped being current (the root-age bound).
    auto decode_blob = [&](const std::vector<std::uint8_t>& blob, std::vector<std::uint64_t>* superseded_out = nullptr)
            -> c2pool::v37n::xmr::authority::CoinbaseBooking {
        std::vector<::v37::bytes32> cands; std::vector<std::uint64_t> sup;
        cba_ring.candidates(node.ledger().owed_digest(), cands, sup);
        if (superseded_out) *superseded_out = std::move(sup);
        std::vector<::v37::bytes32> keys;
        for (const auto& [k, vv] : node.ledger().effective_owed_all()) { (void)vv; keys.push_back(k); }
        for (const auto& k : cba_fx->keys()) keys.push_back(k);
        // fee model ON (S1/S4): the residual sink IS the donation address, and a lane coinbase
        // without the one mandatory donation output (owed + 1 + residual) is REFUSED here (every node,
        // own wins included). OFF: master's booking against the configured residual sink.
        if (c2pool::v37n::xmr::fee::fee_model_on(cfg.lane_params))
            return c2pool::v37n::xmr::authority::decode_lane_coinbase_fee(blob, cfg.lane_chain, cands, keys, cba_fx->pay_of(),
                                                                          donation_net_of(cfg.network));
        return c2pool::v37n::xmr::authority::decode_lane_coinbase(blob, cfg.lane_chain, cands, keys,
                            cba_scfg->residual_sink, cba_scfg->residual_sink_identity, cba_fx->pay_of());
    };
    // fetch + decode one block's coinbase under coinbase authority (shared by the chain path and the fast path)
    // D6a: WHERE the blob comes from. p2p-first + native templates: the native chain
    // index's retained bodies (a miss HOLDS; monerod only as the opt-in compare oracle or
    // the explicit fallback). Otherwise: monerod get_block, the pre-D6a path verbatim.
    o2::CbaBlockSource cba_src(
        (p2p_first && chain_src.block_blob) ? o2::CbaBlockSource::NativeFn(chain_src.block_blob) : o2::CbaBlockSource::NativeFn{},
        [&](const std::string& bid, std::vector<std::uint8_t>& blob, std::string& why) -> bool {
            std::string body, err;
            transport.rpc_post(c2pool::xmr::node::MoneroDaemonRpc::body_get_block(0, bid),
                               [&](const c2pool::xmr::node::RpcResponse& r) { if (!r.ok()) err = r.error; else body.assign(r.body.begin(), r.body.end()); });
            if (!err.empty()) { why = "get_block(" + bid.substr(0, 12) + "): " + err; return false; }
            c2pool::xmr::node::minijson::Value v;
            if (!c2pool::xmr::node::minijson::parse(body, v)) { why = "get_block: JSON parse failed"; return false; }
            const std::string blob_hex = v["result"]["blob"].as_string();
            if (blob_hex.empty() || !sub::from_hex(blob_hex, blob)) { why = "get_block: no/invalid result.blob"; return false; }
            return true;
        },
        o2::CbaBlockSourceOptions{g_cba_monerod_compare, g_cba_monerod_fallback},
        [](const std::string& line) { std::printf("%s\n", line.c_str()); std::fflush(stdout); });
    std::printf("cba: booking block source = %s (monerod compare oracle %s, monerod fallback %s)\n",
                cba_src.native_mode() ? "NATIVE chain index (no get_block)" : "monerod get_block",
                g_cba_monerod_compare ? "ON" : "off", g_cba_monerod_fallback ? "ON" : "off");
    auto fetch_decode = [&](const std::string& bid, c2pool::v37n::xmr::authority::CoinbaseBooking& bk, std::string& why,
                            std::vector<std::uint8_t>* blob_out = nullptr, std::vector<std::uint64_t>* superseded_out = nullptr) -> bool {
        std::vector<std::uint8_t> blob;
        if (!cba_src.fetch(bid, blob, why)) return false;
        if (blob_out) *blob_out = blob;
        bk = decode_blob(blob, superseded_out);
        if (!bk.ok) why = bk.why;
        return bk.ok;
    };
    // R3: MANDATORY W4 replay-to-prefix. Reconstruct the SettlementView at a
    // block-committed cut (P, spine) that our live 128-deep ring no longer holds
    // (P-age exceeded the ring, or the executor coalesced through the prefix).
    // This node ingested every receipt push (feed_log), so replay the first P of
    // them through a SCRATCH engine that publishes EVERY prefix (one submit +
    // wait per record), then read the view at exactly (P, spine). Digest-gated:
    // a reachable-but-different digest is a REAL fork (fail-closed cut_mismatch),
    // never a fold at a neighbouring prefix (O2.3). Cached for the booking
    // window. When the real S-1 carrier relay lands, swap the source to
    // FrameVaultChainReader + replay_to_cut (carrier_repair.hpp) — same gate,
    // same fold.
    auto replay_view = [&](std::uint64_t P, const ::v37::bytes32& spine, std::string& why)
            -> std::shared_ptr<const c2pool::v37n::SettlementView> {
        const std::string key = std::to_string(P) + ":" + hex_of(spine);
        if (auto it = replay_cache.find(key); it != replay_cache.end()) return it->second;
        if (feed_log.size() < P) {   // we have not ingested P records yet: retry (the feed catches up)
            ++cut_pending; why = "cut-pending: replay log has " + std::to_string(feed_log.size()) +
                                 " records < P=" + std::to_string(P) + " (receiver behind the winner's cut; retry)";
            return nullptr;
        }
        c2pool::v37n::V37Engine scratch;   // ring depth is irrelevant: P is the tip after exactly P replays
        scratch.start();
        scratch.submit_tracked(::v37::LaneRecord::add_lane(cfg.lane_chain, cfg.lane_params)).get();
        for (std::uint64_t i = 0; i < P; ++i) {
            ::v37::PayoutDescriptor d; d.pay = feed_log[i].first;
            scratch.submit_tracked(::v37::LaneRecord::push(cfg.lane_chain, d, feed_log[i].second, 0)).get();
        }
        bool mism2 = false;
        auto rv = scratch.settlement_view_by_cut(cfg.lane_chain, P, spine, &mism2);
        scratch.stop();
        if (!rv) {
            if (mism2) { ++cut_mismatch; why = "credit-cut MISMATCH after replay: prefix P=" + std::to_string(P) +
                                              " reconstructs a DIFFERENT lane digest (fail-closed: a real fork, not an eviction)"; }
            else       { ++cut_pending;  why = "cut-pending: replay reached P=" + std::to_string(P) +
                                              " but published no matching cut (retry)"; }
            return nullptr;
        }
        replay_cache[key] = rv; ++cut_repaired;
        std::printf("cut-repair: reconstructed view at P=%llu spine=%s… by replaying %llu receipt pushes (ring-evicted prefix)\n",
                    (unsigned long long)P, hex_of(spine).substr(0, 12).c_str(), (unsigned long long)P);
        std::fflush(stdout);
        return rv;
    };
    // GAP-2 SEAM-5: the relay's source for a view at a winner's cut (P, spine)
    // that our live ring does not hold. (1) our OWN order, when our recorded
    // digest at P IS the winner's spine (replay feed_log, exactly R3); else
    // (2) the relay REPAIR: the winner-side order over [0, P) from a peer whose
    // digest at P equals `spine` (SupplyService spine probe), every receipt in
    // it admitted here (RandomX-verified), replayed through a SCRATCH engine
    // and accepted ONLY if the digest at P equals `spine`. Same gate, same
    // fold_eb call downstream; a repair in flight answers cut-pending (the
    // FinalizeConnect retry bound), never a fold at a neighbouring prefix.
    auto relay_view = [&](std::uint64_t P, const ::v37::bytes32& spine, std::uint64_t hint, std::string& why)
            -> std::shared_ptr<const c2pool::v37n::SettlementView> {
        const std::string key = std::to_string(P) + ":" + hex_of(spine);
        if (auto it = replay_cache.find(key); it != replay_cache.end()) return it->second;
        if (const auto d = relay_node->digest_at(P); d && *d == spine && feed_log.size() >= P) {
            auto v = replay_view(P, spine, why);
            if (v) ++relay_own_replay;
            return v;
        }
        std::vector<::v37::bytes32> ids;
        const auto st = relay_node->repair_poll(P, spine, hint, &ids);
        if (st != relay::XmrRelayNode::RepairState::Ready) {
            ++cut_pending;
            // the stuck stage in words (FinalizeConnect prints it; past the retry
            // bound the block is HELD (RC-HOLD) -- an undecided repair never refuses)
            why = std::string("cut-pending: relay repair of P=") + std::to_string(P) + " spine=" + hex_of(spine).substr(0, 12) +
                  (st == relay::XmrRelayNode::RepairState::Exhausted ? " (no connected peer serves that order yet; retry)"
                                                                     : " in flight (fetching the winner-side order + missing receipts)") +
                  " [" + relay_node->repair_status(P, spine) + "]";
            return nullptr;
        }
        std::vector<std::pair<::v37::ScriptRef, std::uint64_t>> pushes;
        pushes.reserve(ids.size());
        const bool fee_on = c2pool::v37n::xmr::fee::fee_model_on(cfg.lane_params);
        for (const auto& id : ids) {
            ::v37::ScriptRef payee; std::uint16_t give_author = 0;
            if (!relay_node->cached(id, &payee, &give_author)) { ++cut_pending; why = "cut-pending: a repaired receipt left the verified cache (retry)"; return nullptr; }
            // fee model S3: the SAME split the live ingest applies, by the receipt's OWN PoW-committed u16.
            for (const auto& pr : c2pool::v37n::xmr::fee::receipt_lane_pushes(payee, give_author, fee_on, relay::kReceiptWeight,
                                                                                  donation_net_of(cfg.network)))
                pushes.push_back(pr);
        }
        c2pool::v37n::V37Engine scratch;
        scratch.start();
        scratch.submit_tracked(::v37::LaneRecord::add_lane(cfg.lane_chain, cfg.lane_params)).get();
        for (const auto& [ref, w] : pushes) {
            ::v37::PayoutDescriptor d; d.pay = ref;
            scratch.submit_tracked(::v37::LaneRecord::push(cfg.lane_chain, d, w, 0)).get();
        }
        bool mism = false;
        auto rv = scratch.settlement_view_by_cut(cfg.lane_chain, P, spine, &mism);
        scratch.stop();
        if (!rv) {
            relay_node->repair_reject(P, spine);
            ++relay_repair_rejected; ++cut_pending;
            why = "cut-pending: the repaired order did not reproduce the winner's spine at P=" + std::to_string(P) +
                  " (serving peer set aside; asking another)";
            return nullptr;
        }
        replay_cache[key] = rv; ++cut_repaired; ++relay_cut_repaired;
        std::printf("relay-repair: reconstructed view at P=%llu spine=%s… from the winner-side order (%zu receipts, every one admitted here: RandomX-verified, or our own)\n",
                    (unsigned long long)P, hex_of(spine).substr(0, 12).c_str(), ids.size());
        std::fflush(stdout);
        return rv;
    };
    // (B) THE AUTHORITY: fold E_b at the ON-CHAIN cut, read back from OUR OWN ring. Never at a neighbouring prefix.
    auto fold_at_cut = [&](std::uint64_t reward, const c2pool::v37n::xmr::credit::CreditCut& cc, Amounts& credit, std::string& why,
                           std::uint64_t relay_hint_pid = 0) -> bool {
        bool mism = false;
        auto view = node.engine().settlement_view_by_cut(cfg.lane_chain, cc.next_pos, cc.spine_digest, &mism);
        if (!view && relay_node) {   // GAP-2 SEAM-5: node-local order -> own replay or winner-order repair
            view = relay_view(cc.next_pos, cc.spine_digest, relay_hint_pid, why);
            if (!view) return false;
        }
        if (!view) {
            auto tip = node.engine().snapshot(cfg.lane_chain);
            const std::uint64_t tp = tip ? tip->next_pos : 0;
            if (mism) { ++cut_mismatch; why = "credit-cut MISMATCH: we published P=" + std::to_string(cc.next_pos) + " with a DIFFERENT lane digest (fail-closed: different records in the same prefix)"; return false; }
            if (tp < cc.next_pos) { ++cut_pending; why = "cut-pending: our lane tip " + std::to_string(tp) + " < P=" + std::to_string(cc.next_pos) + " (receiver behind the winner's cut; retry)"; return false; }
            // R3: the live ring evicted this prefix (P-age > ring, or coalesced
            // through it). Reconstruct it by replay-to-prefix instead of failing
            // terminally — this is the fix that stops the reorg fork.
            ++cut_miss;
            view = replay_view(cc.next_pos, cc.spine_digest, why);
            if (!view) return false;   // replay_view set why: cut-pending (retry) or cut-mismatch (fail-closed)
        }
        std::optional<settle::EbFold> f = settle::fold_eb(reward, *view, /*strict=*/true);
        if (!f) { ++cut_fold_refused; why = "fold_eb REFUSED at the on-chain cut (geometry not ratified)"; return false; }
        // ★ DROPS-R1: the (reward, SUM weight) pair at THIS cut, through the SAME
        // view and the SAME project() the fold just read. Gate OFF: not computed.
        if (drops) drops_fold_price = settle::work_price_at(reward, *view);
        credit.clear();
        for (const auto& [k, v] : f->credit) credit[k] = static_cast<long long>(v);
        if (g_credit_mutate && !credit.empty()) credit.begin()->second += g_credit_mutate;   // the falsifier: a 1-piconero lie must show in owed_digest
        return true;
    };
    // R-C rework-2/3: the RICH booking callback. Same authority as before for the
    // CREDIT side (fail-closed); on every refusal it reports the block's on-chain
    // PAYOUT map when it decodes from the ON-CHAIN BYTES + this node's own ring
    // alone, and the value it cannot attribute. rework-3 (b): that report feeds a
    // NODE-LOCAL liability only (FinalizeConnect::refuse_money), never the ledger.
    // rework-2's late attribution through the v0x02 WIRE descriptor (M3(b)) is
    // REMOVED: whether a peer's descriptor arrived before booking is node-local
    // timing, and it decided debit-vs-suspense -- three honest refusers, three
    // digests (verify D1). Nothing on this path depends on wire arrival any more.
    auto root_hex32 = [](const auto& r) {
        static const char* hx = "0123456789abcdef";
        std::string o; o.reserve(64);
        const unsigned char* rp = reinterpret_cast<const unsigned char*>(r.data());
        for (std::size_t i = 0; i < 32; ++i) { o.push_back(hx[rp[i] >> 4]); o.push_back(hx[rp[i] & 15]); }
        return o;
    };
    fo.book_from_chain_ex = [&](std::uint64_t h, const std::string& bid, o2::FinalizeConnectOptions::ChainBooking& out) -> bool {
        Amounts& credit = out.credit; Amounts& payout = out.payout; std::string& why = out.why;
        if (drops_live) drops->clear_cut_price();   // ★ DROPS: never a neighbour's price
        if (!cba_fx || !cba_scfg) {
            // option B not bound yet (boot window) -> TRANSIENT, never memoized not-lane;
            // option A never binds -> a stranger's block for this node.
            if (cfg.coinbase == CoinbaseMode::V37Settlement) { why = "cut-pending: settlement ledger not bound yet (boot)"; return false; }
            why = "not-lane: no v37 settlement ledger bound (option A)"; return false;
        }
        cba_ring_push();
        ++cba_fetches;
        c2pool::v37n::xmr::authority::CoinbaseBooking bk;
        std::vector<std::uint8_t> chain_blob;
        std::vector<std::uint64_t> cand_superseded;
        if (!fetch_decode(bid, bk, why, &chain_blob, &cand_superseded) && !bk.is_lane && bk.why.empty()) {
            ++cba_fetch_failed;   // R-C rework-3 (D6): a transport/JSON failure is a transient retry, NOT a refusal
            return false;
        }
        out.total_pico = bk.total;
        if (bk.has_onchain_root) out.onchain_root_hex = root_hex32(bk.onchain_root);
        // R-C rework-3 (D7): THE ROOT-AGE BOUND. The ring holds every state this
        // ledger lived through, so a forker committing a state honest nodes left
        // long ago (a fresh node on the genesis owed-demo seed) matched and was
        // CREDITED. An honest builder is lane-suspended beyond a 2*D_conf lag, so
        // the state it commits was superseded at most ~2*D_conf heights before the
        // block's builder cut; a match older than cba_max_root_age (4*D_conf) is
        // refused -- deterministic (chain height + the replayed ledger), never a
        // wall clock, never the wire.
        if (bk.is_lane && cba_max_root_age && bk.digest_index < cand_superseded.size()) {
            const std::uint64_t bcut = c2pool::v37n::xmr::recon::builder_cut(h, cfg.d_conf);
            const std::uint64_t sup  = cand_superseded[bk.digest_index];
            const std::uint64_t age  = c2pool::v37n::xmr::recon::root_age(sup, bcut);
            if (age > cba_max_root_age) {
                ++cba_stale_root; ++cba_refused;
                const std::string roothex = bk.has_onchain_root ? root_hex32(bk.onchain_root) : std::string(64, '0');
                why = "lane-root-refused:" + roothex + ":stale-root: the on-chain 03 root is a HISTORICAL state of this ledger "
                      "(candidate #" + std::to_string(bk.digest_index) + ", superseded at h=" + std::to_string(sup) +
                      ", builder cut " + std::to_string(bcut) + ", age " + std::to_string(age) + " > bound " +
                      std::to_string(cba_max_root_age) + ") -- never credited (D7)";
                if (bk.ok || bk.payout_partial) { payout = bk.payout; out.payout_decoded = true; out.unattributed_pico = bk.unmapped_total; }
                else out.unattributed_pico = bk.total;
                std::printf("cba-ALARM stale_root: h=%llu bid=%s… commits a historical owed_digest (candidate #%zu superseded at h=%llu; "
                            "age %llu > %llu heights from builder cut %llu) -- REFUSED, not credited; payout -> node-local liability\n",
                            static_cast<unsigned long long>(h), bid.substr(0, 12).c_str(), bk.digest_index,
                            static_cast<unsigned long long>(sup), static_cast<unsigned long long>(age),
                            static_cast<unsigned long long>(cba_max_root_age), static_cast<unsigned long long>(bcut));
                std::fflush(stdout);
                return false;
            }
        }
        if (!bk.ok) {
            why = bk.why;
            if (why.rfind("lane-root-unknown:", 0) == 0) {   // R5: NOT not-lane; FinalizeConnect keeps + retries it as the ring advances
                // R-C decidability. The R6 deferral gate guarantees our cursor >=
                // H_b-1-D_conf (the builder's cut) at book time. If we are SYNCED to
                // that cut and our FULL canonical history ring (seeded from the boot
                // replay -- which, with the F1 fix, contains every state this node
                // lived through) STILL holds no digest whose mm_root equals the
                // block's on-chain 0x03 root, this is NOT catch-up lag. Reclassify to
                // "lane-root-refused:<roothex>:" so FinalizeConnect REFUSES-not-credits
                // it (loud alarm, gate released), DEBITS its payout when attributable,
                // and records ONE lineage-vote observation (never a halt by itself).
                // During boot warm-up the ring is short and un-seeded: stay transient.
                static constexpr std::size_t kReconWarmupK = 4;   // R-C: warm-up depth below which an unseeded ring is not yet decidable
                const std::uint64_t bcut = (h >= 1 + cfg.d_conf) ? h - 1 - cfg.d_conf : 0;
                const std::uint64_t cur  = node.finalize_driver().cursor_height();
                const bool decidable = (cur >= bcut) && (cba_ring_seeded || cba_ring.size() > kReconWarmupK);
                if (decidable && bk.has_onchain_root) {
                    const std::string roothex = root_hex32(bk.onchain_root);
                    why = "lane-root-refused:" + roothex + ":" + why.substr(std::string("lane-root-unknown:").size());
                    // rework-3: no r without a matched root -> the whole reward (incl. the sink)
                    // is unattributable. NO wire-descriptor attribution (verify D1).
                    out.unattributed_pico = bk.total;
                    if (cba_root_unknown_seen.insert(bid).second) {
                        ++cba_lane_root_unknown;
                        std::printf("cba-ALARM lane_root_refused: h=%llu bid=%s SYNCED (cursor=%llu >= builder cut=%llu) but the on-chain 03 root %s matches NO digest in our %zu-state canonical history -- REFUSED (not credited), whole reward -> node-local LIABILITY (ledger untouched), one lineage-vote observation\n",
                                    static_cast<unsigned long long>(h), bid.substr(0, 12).c_str(),
                                    static_cast<unsigned long long>(cur), static_cast<unsigned long long>(bcut),
                                    roothex.substr(0, 12).c_str(), cba_ring.size());
                    }
                    return false;
                }
                if (cba_root_unknown_seen.insert(bid).second) {
                    ++cba_lane_root_unknown;
                    std::printf("cba-ALARM lane_root_unknown: h=%llu bid=%s carries a 03 21 00 tag whose root is UNKNOWN to this ledger yet (%s) -- kept, retried per ledger event (not yet synced/warmed: transient)\n",
                                static_cast<unsigned long long>(h), bid.substr(0, 12).c_str(), why.c_str());
                }
                return false;
            }
            if (bk.is_lane) {
                ++cba_refused;
                // matched root but fail-closed on an output (unmapped payee): the
                // mapped part is liability per payee, the unmapped sum unattributed.
                if (bk.payout_partial) { payout = bk.payout; out.payout_decoded = true; out.unattributed_pico = bk.unmapped_total; }
            } else ++cba_not_lane;
            return false;
        }
        // from here the payout side is fully decoded (proven coinbase authority, deterministic r)
        payout = bk.payout; out.payout_decoded = true;
        if (bk.height != h) { why = "coinbase txin_gen height " + std::to_string(bk.height) + " != chain height " + std::to_string(h); ++cba_refused; return false; }
        // RECOMPUTE CROSS-CHECK (own win): our submitted bytes vs the chain's. Sanity only --
        // the chain decode above stays the authority whatever this says.
        if (auto rit = own_recompute.find(bid); rit != own_recompute.end()) {
            namespace cons = ::c2pool::xmr::native;
            std::string mism;
            cons::ParsedBlock pa, pb;
            const auto sa = cons::parse_block(rit->second.data(), rit->second.size(), pa);
            const auto sb = cons::parse_block(chain_blob.data(), chain_blob.size(), pb);
            const bool pa_ok = (sa == cons::BlockParseStatus::Ok || sa == cons::BlockParseStatus::TxCountMismatch);
            const bool pb_ok = (sb == cons::BlockParseStatus::Ok || sb == cons::BlockParseStatus::TxCountMismatch);
            if (!pa_ok || !pb_ok) mism = "one side does not parse";
            else if (pa.miner_tx_size != pb.miner_tx_size ||
                     std::memcmp(rit->second.data() + pa.miner_tx_offset, chain_blob.data() + pb.miner_tx_offset, pa.miner_tx_size) != 0)
                mism = "miner_tx BYTES differ (ours " + std::to_string(pa.miner_tx_size) + "B vs chain " + std::to_string(pb.miner_tx_size) + "B)";
            else {
                const auto rk = decode_blob(rit->second);
                if (!rk.ok) mism = "our own bytes do not decode under coinbase authority: " + rk.why;
                else if (rk.payout != bk.payout || rk.total != bk.total || !(rk.lane_commitment == bk.lane_commitment) ||
                         rk.has_credit_cut != bk.has_credit_cut || !(rk.credit_cut == bk.credit_cut))
                    mism = "decoded maps differ (payout/total/lane_commitment/credit_cut)";
            }
            if (mism.empty()) { ++recompute_ok; std::printf("cba-recompute: own win h=%llu bid=%s… our submitted miner_tx == on-chain miner_tx (%zu B) and decodes identically; booking the on-chain coinbase\n",
                                                            static_cast<unsigned long long>(h), bid.substr(0, 12).c_str(), (std::size_t)pb.miner_tx_size); }
            else { ++recompute_mismatch; std::printf("cba-ALARM recompute_mismatch: own win h=%llu bid=%s… %s -- the ON-CHAIN coinbase is the authority, booking it as read from the block\n",
                                                     static_cast<unsigned long long>(h), bid.substr(0, 12).c_str(), mism.c_str()); }
            own_recompute.erase(rit);
        }
        // (the PAYOUT side was set above: proven coinbase authority, deterministic r)
        // recon(A+B credit): the CREDIT side. AUTHORITY = the on-chain credit cut (B); FAST PATH = the v0x02 descriptor (A),
        // used only when it AGREES with the chain; on mismatch the chain wins; unreconstructable => fail-closed.
        if (!bk.has_credit_cut) { ++cut_absent; why = "no on-chain credit cut (0x02 V37C tail) -- E_b unreproducible (fail-closed)"; ++cba_refused; return false; }
        const char* credit_src = "chain";
        c2pool::v37n::settle::WorkPrice booking_price{};   // ★ DROPS: the price at the cut E_b comes from
        if (auto wit = wire_cache.find(bid); wit != wire_cache.end()) {
            const auto& d = wit->second.d;
            const bool agree = d.cut_next_pos == bk.credit_cut.next_pos && d.cut_spine_digest == bk.credit_cut.spine_digest &&
                               d.reward == bk.total && d.h_b == h && d.owed_digest_at_win == bk.lane_commitment;
            if (!agree) { ++wire_mismatch; std::printf("ab-RECONCILE: wire descriptor for %s… DISAGREES with the on-chain commitment (wire P=%llu chain P=%llu) -> the CHAIN is the authority\n", bid.substr(0,12).c_str(), (unsigned long long)d.cut_next_pos, (unsigned long long)bk.credit_cut.next_pos); }
            else if (wit->second.prefolded) { credit = wit->second.credit; ++wire_hit; credit_src = "wire-prefold(agreed)"; booking_price = wit->second.price; }
        }
        if (credit_src[0] == 'c') {
            if (!fold_at_cut(bk.total, bk.credit_cut, credit, why, relay_hint(bid))) { if (why.rfind("cut-pending:", 0) != 0) ++cba_refused; return false; }
            booking_price = drops_fold_price;
        } else {
            // belt-and-braces: the fast path must equal the authority fold whenever the authority is available NOW
            Amounts chk; std::string w2;
            const bool chk_ok = fold_at_cut(bk.total, bk.credit_cut, chk, w2, relay_hint(bid));
            if (chk_ok) booking_price = drops_fold_price;
            if (chk_ok && chk != credit) { ++wire_mismatch; credit = chk; credit_src = "chain(wire-prefold-DISAGREED)"; }
        }
        // ★ DROPS: hand the node the price at THIS cut; XmrNode::on_network_block_won
        // (called by FinalizeConnect right after this returns) takes it, one-shot.
        if (drops_live) drops->set_cut_price(booking_price);
        ++cut_ok;
        ++cba_booked;
        last_credit_line = "h=" + std::to_string(h) + " P=" + std::to_string(bk.credit_cut.next_pos) + " src=" + credit_src + " credit{ " + amounts_str(credit) + "}";
        std::printf("cba-book: h=%llu bid=%s… lane_commitment=%s… (candidate #%zu) total=%llu outputs=%zu payout{ %s}\n",
                    static_cast<unsigned long long>(h), bid.substr(0, 12).c_str(), hex_of(bk.lane_commitment).substr(0, 12).c_str(),
                    bk.digest_index, static_cast<unsigned long long>(bk.total), bk.n_outputs, amounts_str(payout).c_str());
        std::printf("ab-credit: h=%llu bid=%s… P=%llu spine=%s… reward=%llu src=%s credit{ %s}\n",
                    static_cast<unsigned long long>(h), bid.substr(0, 12).c_str(), (unsigned long long)bk.credit_cut.next_pos,
                    hex_of(bk.credit_cut.spine_digest).substr(0, 12).c_str(), (unsigned long long)bk.total, credit_src, amounts_str(credit).c_str());
        std::fflush(stdout);
        return true;
    };
    // (A) THE FAST PATH, send side: our own win leaves as a REAL S-1c v0x02 frame (CarrierWire::encode, 122-byte trailer).
    fo.on_own_win_deferred = [&](std::uint64_t h, const std::string& bid, std::uint32_t tid, std::uint32_t en) {
        // recompute capture: the bytes we assembled for (tid, en), off the provider ring
        if (cba_fx && own_candidate_lookup) {
            sub::BlockCandidate c;
            if (own_candidate_lookup(tid, en, c) && !c.full_blob.empty()) { own_recompute[bid] = c.full_blob; ++recompute_captured; }
            else { ++recompute_unavailable; std::printf("cba-recompute: own win h=%llu bid=%s… template %u gone from the ring -> no local recompute (chain decode is the authority anyway)\n",
                                                        static_cast<unsigned long long>(h), bid.substr(0, 12).c_str(), tid); }
        }
        if (relay_node && cba_fx) {   // GAP-2: the fast path over the relay (FB_BLOCK_WON), not a directory drop
            c2pool::v37n::xmr::authority::CoinbaseBooking bk; std::string why;
            if (!fetch_decode(bid, bk, why) || !bk.has_credit_cut) { std::printf("ab-wire-tx: own win %s… not encodable (%s)\n", bid.substr(0,12).c_str(), why.c_str()); return; }
            relay::BlockWon bw;
            bw.chain_id = cfg.lane_chain; bw.bid = *c2pool::v37n::cut_bid_bytes(bid); bw.h_b = h;
            bw.cut_next_pos = bk.credit_cut.next_pos; bw.cut_spine_digest = bk.credit_cut.spine_digest;
            bw.reward = bk.total; bw.payout_emitted = true; bw.owed_digest_at_win = bk.lane_commitment;
            const std::size_t n = relay_node->broadcast_block_won(bw);
            ++wire_tx;
            std::printf("ab-wire-tx: own win h=%llu bid=%s… -> FB_BLOCK_WON to %zu relay peer(s) P=%llu\n",
                        (unsigned long long)h, bid.substr(0,12).c_str(), n, (unsigned long long)bw.cut_next_pos);
            return;
        }
        if (g_wire_out.empty() || !cba_fx) return;
        c2pool::v37n::xmr::authority::CoinbaseBooking bk; std::string why;
        if (!fetch_decode(bid, bk, why) || !bk.has_credit_cut) { std::printf("ab-wire-tx: own win %s… not encodable (%s)\n", bid.substr(0,12).c_str(), why.c_str()); return; }
        c2pool::v37n::Carrier c = c2pool::v37n::wire_freeze::fixture_a();
        c2pool::v37n::CutDescriptor d;
        d.bid = *c2pool::v37n::cut_bid_bytes(bid); d.h_b = h; d.cut_next_pos = bk.credit_cut.next_pos; d.cut_spine_digest = bk.credit_cut.spine_digest;
        d.reward = bk.total; d.payout_emitted = true; d.owed_digest_at_win = bk.lane_commitment;
        c.cut = d;
        const std::vector<std::uint8_t> frame = c2pool::v37n::CarrierWire::encode(c);
        std::error_code ec; std::filesystem::create_directories(g_wire_out, ec);
        std::ofstream o(g_wire_out + "/" + bid + ".v2.tmp"); for (std::uint8_t b : frame) o << "0123456789abcdef"[b >> 4] << "0123456789abcdef"[b & 15]; o.close();
        std::filesystem::rename(g_wire_out + "/" + bid + ".v2.tmp", g_wire_out + "/" + bid + ".v2", ec);
        ++wire_tx;
        std::printf("ab-wire-tx: own win h=%llu bid=%s… -> v0x02 frame %zu bytes (trailer 122) P=%llu\n", (unsigned long long)h, bid.substr(0,12).c_str(), frame.size(), (unsigned long long)d.cut_next_pos);
    };
    // (A) THE FAST PATH, receive side: decode the peer's v0x02 frame, VERIFY, and PRE-FOLD E_b at the carried cut NOW
    // (while P is fresh in our ring). Nothing enters the ledger from the wire: the chain path consumes the pre-fold
    // only if the on-chain commitment agrees with it.
    auto wire_pump = [&]() {
        if (g_wire_in.empty()) return;
        std::error_code ec;
        for (const auto& e : std::filesystem::directory_iterator(g_wire_in, ec)) {
            const std::string p = e.path().string();
            if (p.size() < 3 || p.compare(p.size() - 3, 3, ".v2") != 0 || wire_seen.count(p)) continue;
            wire_seen.insert(p);
            std::ifstream in(p); std::string hx((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            std::vector<std::uint8_t> frame; if (!sub::from_hex(hx, frame)) continue;
            const auto dr = c2pool::v37n::CarrierWire::decode(frame);
            if (!dr.ok() || !dr.carrier.cut) { std::printf("ab-wire-rx: %s does not decode as a v0x02 block-winner frame\n", p.c_str()); continue; }
            ++wire_rx;
            const auto& d = *dr.carrier.cut;
            const std::string bid = c2pool::v37n::cut_bid_hex(d.bid);
            WireCache wc; wc.d = d;
            const bool known = cba_ring.contains(d.owed_digest_at_win);
            if (!known) ++wire_diverged;
            c2pool::v37n::xmr::credit::CreditCut cc; cc.next_pos = d.cut_next_pos; cc.spine_digest = d.cut_spine_digest;
            std::string why;
            if (fold_at_cut(d.reward, cc, wc.credit, why)) { wc.prefolded = true; ++wire_prefold; if (drops) wc.price = drops_fold_price; } else ++wire_pending;
            wire_cache[bid] = wc;
            std::printf("ab-wire-rx: peer win h=%llu bid=%s… P=%llu reward=%llu owed_at_win %s | prefold=%s%s\n",
                        (unsigned long long)d.h_b, bid.substr(0,12).c_str(), (unsigned long long)d.cut_next_pos, (unsigned long long)d.reward,
                        known ? "KNOWN-to-our-ledger-history" : "UNKNOWN(diverged-or-not-yet)", wc.prefolded ? "yes" : "no", wc.prefolded ? "" : (" (" + why + ")").c_str());
        }
    };
    // GAP-2: the receive side of FB_BLOCK_WON -- wire_pump's body, fed by the relay instead of a directory.
    auto relay_on_cut = [&](const relay::BlockWon& bw, std::uint64_t from_pid) {
        c2pool::v37n::CutDescriptor d;
        d.bid = bw.bid; d.h_b = bw.h_b; d.cut_next_pos = bw.cut_next_pos; d.cut_spine_digest = bw.cut_spine_digest;
        d.reward = bw.reward; d.payout_emitted = bw.payout_emitted; d.owed_digest_at_win = bw.owed_digest_at_win;
        ++wire_rx;
        const std::string bid = c2pool::v37n::cut_bid_hex(d.bid);
        WireCache wc; wc.d = d;
        const bool known = cba_ring.contains(d.owed_digest_at_win);   // merge: rework-3 ReconRing (was a deque scan)
        if (!known) ++wire_diverged;
        c2pool::v37n::xmr::credit::CreditCut cc; cc.next_pos = d.cut_next_pos; cc.spine_digest = d.cut_spine_digest;
        std::string why;
        if (fold_at_cut(d.reward, cc, wc.credit, why, from_pid)) { wc.prefolded = true; ++wire_prefold; if (drops) wc.price = drops_fold_price; } else ++wire_pending;
        wire_cache[bid] = wc;
        std::printf("ab-wire-rx: peer win h=%llu bid=%s… P=%llu reward=%llu owed_at_win %s | prefold=%s%s (relay peer %llu)\n",
                    (unsigned long long)d.h_b, bid.substr(0,12).c_str(), (unsigned long long)d.cut_next_pos, (unsigned long long)d.reward,
                    known ? "KNOWN-to-our-ledger-history" : "UNKNOWN(diverged-or-not-yet)", wc.prefolded ? "yes" : "no",
                    wc.prefolded ? "" : (" (" + why + ")").c_str(), (unsigned long long)from_pid);
    };
    // THE RECEIPT FEED (the carrier-relay stand-in): a shared append-only file "idx weight" per line; every node
    // pushes the SAME records in the SAME order (submit_tracked+get: one record per burst => every prefix published).
    auto feed_push_line = [&](const std::string& ln) {
        unsigned idx = 0; unsigned long long w = 0;
        if (std::sscanf(ln.c_str(), "%u %llu", &idx, &w) != 2 || idx >= feed_refs.size() || w == 0) return;
        ::v37::PayoutDescriptor d; d.pay = feed_refs[idx];
        const auto res = node.engine().submit_tracked(::v37::LaneRecord::push(cfg.lane_chain, d, w, 0)).get();
        if (res.applied()) {
            ++feed_pushed;
            // R3: record the applied push, in order, for replay-to-prefix. This
            // node ingested every push, so feed_log[0..P-1] reconstructs any
            // ring-evicted prefix P. (Durable-log reload across a restart is a
            // stated follow-on; the fork the proof exercises is mid-run.)
            feed_log.emplace_back(feed_refs[idx], static_cast<std::uint64_t>(w));
        } else ++feed_rejected;
        if (feed_pushed <= 3 || feed_pushed % 100 == 0 || !res.applied()) {
            auto s = node.engine().snapshot(cfg.lane_chain);
            std::printf("credit-feed: pushed=%llu rejected=%llu lane next_pos=%llu digest=%s…\n", (unsigned long long)feed_pushed, (unsigned long long)feed_rejected,
                        s ? (unsigned long long)s->next_pos : 0ULL, s ? hex_of(s->digest).substr(0, 12).c_str() : "-");
        }
    };
    auto feed_pump = [&]() {
        if (g_credit_feed.empty() || feed_refs.empty()) return;
        std::ifstream in(g_credit_feed, std::ios::binary);
        if (in) {
            in.seekg(static_cast<std::streamoff>(feed_off));
            std::string chunk((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            std::size_t start = 0;
            for (;;) {
                const std::size_t nl = chunk.find('\n', start);
                if (nl == std::string::npos) break;
                const std::string line = chunk.substr(start, nl - start);
                start = nl + 1;
                if (g_credit_feed_lag_ms) feed_lagq.emplace_back(std::chrono::steady_clock::now(), line); else feed_push_line(line);
            }
            feed_off += start;
        }
        const auto now = std::chrono::steady_clock::now();
        while (!feed_lagq.empty() && std::chrono::duration_cast<std::chrono::milliseconds>(now - feed_lagq.front().first).count() >= static_cast<long long>(g_credit_feed_lag_ms)) {
            feed_push_line(feed_lagq.front().second); feed_lagq.pop_front();
        }
    };
    o2::FinalizeConnect fc(node, cfg, found_q, fo);
    // R5: the candidate ring is fed PER LEDGER EVENT (every FOUND/ORPHAN/FINALIZE the driver
    // applies), not per tick: a tick that applies several seqs at once (book h47 + finalize
    // h44) skipped the intermediate owed_digest, and a peer block committed to exactly that
    // state was memoized not-lane -> the h=48 SETTLED fork. Every state is now present.
    node.finalize_driver().set_ledger_event_observer([&]() { cba_ring_push(); });
    std::printf("same-height policy: tiebreak=%s D_conf=%llu renotify<=%u journal=%s "
                "| credit requires burial: YES  orphan-credit: NEVER  double-credit: BLOCKED\n",
                to_string(cfg.same_height_tiebreak),
                static_cast<unsigned long long>(cfg.d_conf),
                cfg.same_height_renotify,
                fo.race_journal_path.empty() ? "off" : fo.race_journal_path.c_str());
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
        cba_payee = payee_key;   // 
        cba_payee_ref = pk.subaddress ? ::v37::xmr::make_xmr_sub(pk.spend, pk.view) : ::v37::xmr::make_xmr_std(pk.spend, pk.view);
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
        // fee model (xmr/xmr_fee_model.hpp, LaneParams::fee). ON: the residual sink IS
        // the protocol donation address and the ONE donation output (owed + 1 + residual, S1 + merge) is a
        // mandated fixed output, both from compiled-in constants -- no node can omit or
        // redirect them. OFF (default): master's per-node residual sink, byte-identical.
        namespace fee = ::c2pool::v37n::xmr::fee;
        const bool fee_on = fee::fee_model_on(cfg.lane_params);
        const fee::DonationNet don_net = donation_net_of(cfg.network);   // DON-NET: the donation identity of --network
        o2::XmrSettlementConfig scfg;
        scfg.chain_id   = cfg.lane_chain;
        scfg.h_min      = cfg.settle_h_min;
        scfg.output_cap = cfg.settle_output_cap;
        bool serving = false;
        if (fee_on) {
            if (!cfg.residual_sink_spend_hex.empty() || !cfg.residual_sink_view_hex.empty() || cfg.residual_sink_subaddress) {
                std::printf("REFUSED: --fee-model v1: the exact-sum residual is the mandatory protocol donation output "
                            "(xmr_fee_model.hpp), not a per-node --residual-sink-* setting\n");
                node.stop();
                return 2;
            }
            scfg.residual_sink          = fee::donation_ref(don_net);
            scfg.residual_sink_identity = fee::donation_identity(don_net);
            scfg.fixed                  = {fee::donation_marker(don_net)};
            if (!::v37::xmr::xmr_ref_valid(scfg.residual_sink)) {
                std::printf("REFUSED: the compiled-in donation address does not torsion-check as an XMR "
                            "payout ref (ed25519 point-check backend missing?)\n");
                node.stop();
                return 2;
            }
            serving = true;
        } else {
            // fail-closed: v37 mode serves only with a torsion-valid residual sink.
            serving = !cfg.residual_sink_spend_hex.empty() && !cfg.residual_sink_view_hex.empty();
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
        }

        // fee model: node-local JOB policy (the payee + give-author a job's rbind commits to).
        std::optional<::v37::ScriptRef> owner_ref;
        const std::uint32_t owner_bp = fee_on ? fee::pct_to_bp(g_owner_fee_pct) : 0;
        const std::uint16_t my_give_author = fee_on ? fee::give_author_u16(g_give_author_pct) : 0;
        if (fee_on && !g_owner_address.empty()) {
            const fee::DecodedAddress da = fee::decode_xmr_address(g_owner_address);
            if (!da.ok || da.subaddress || !::v37::xmr::xmr_ref_valid(da.ref())) {
                std::printf("REFUSED: --node-owner-address is not a valid standard Monero address (%s)\n",
                            da.ok ? (da.subaddress ? "subaddress not supported as a payee" : "point check failed") : da.why.c_str());
                node.stop();
                return 2;
            }
            owner_ref = da.ref();
        }
        if (owner_bp && !owner_ref) {
            std::printf("REFUSED: --node-owner-fee-pct > 0 needs --node-owner-address\n");
            node.stop();
            return 2;
        }
        if (fee_on)
            std::printf("fee-model: v%u ON | donation[%s]=%s… (identity %s…) ONE mandatory output = max(%llu, residual) "
                        "(residual folds in, S1; dust from the LARGEST payee, S2) | give-author %.4f%% (u16=%u, PoW-bound "
                        "in this node's receipts, S3) | node-owner fee %.4f%% -> %s (rolled at job issue) | finder bonus: NONE\n",
                        cfg.lane_params.fee.version, fee::to_string(don_net),
                        std::string(fee::donation_address(don_net)).substr(0, 12).c_str(),
                        hex_of(fee::donation_identity(don_net)).substr(0, 12).c_str(),
                        static_cast<unsigned long long>(fee::kDonationDustPico), g_give_author_pct, (unsigned)my_give_author,
                        g_owner_fee_pct, g_owner_address.empty() ? "-" : g_owner_address.substr(0, 12).c_str());

        // The proof ledger (no live S-1 emission yet). Empty => the whole reward
        // flows to the residual sink (one v37 output). --owed-demo-amount seeds a
        // distinct K_fair OWED payee (the sink material with spend/view swapped —
        // still two valid ed25519 points, a different identity) so the assembled
        // coinbase carries an OWED output alongside the sink (multi-output proof).
        o2::XmrOwedFixture ledger(node.ledger());   //  ONE ledger — K_fair is built over the ledger FOUND/FINALIZE mutate
        cba_fx = &ledger; cba_scfg = &scfg;
        // R-C rework-2 (F1): every seed goes through the node's write-ahead event
        // log (FOUND + FINALIZE), so a restarted node's replayed boot digest history
        // (the RECON ring seed) contains the states it lived through; on a resumed
        // store the seed is already in the log and is NOT re-applied.
        ledger.set_seed_sink([&](const std::string& bid, const Amounts& credit, std::uint64_t bin) {
            return node.seed_settled_owed(bid, credit, bin);
        });
        // recon(A+B credit): the template commits THIS node's receipt-lane cut (P, spine) on-chain (0x02 tail)
        scfg.credit_cut_source = [&](std::uint64_t& P, ::v37::bytes32& dg) -> bool {
            auto s = node.engine().snapshot(cfg.lane_chain); if (!s) return false; P = s->next_pos; dg = s->digest; return true; };
        std::printf("ab: on-chain credit cut ARMED (0x02 tail V37C|P|spine); feed=%s lag=%llums wire-out=%s wire-in=%s mutate=%lld\n",
                    g_credit_feed.empty() ? "-" : g_credit_feed.c_str(), (unsigned long long)g_credit_feed_lag_ms,
                    g_wire_out.empty() ? "-" : g_wire_out.c_str(), g_wire_in.empty() ? "-" : g_wire_in.c_str(), g_credit_mutate);
        if (cba_payee_ref) ledger.learn_ref(*cba_payee_ref);
        if (fee_on) ledger.learn_ref(fee::donation_ref(don_net));   // fee model: give-author credit is paid as an ordinary owed output to the donation
        if (owner_ref) ledger.learn_ref(*owner_ref);          // fee model: owner-fee receipts pay the owner
        std::printf("cba: coinbase-authority booking ARMED (lane_chain=%u, payee %s, sink identity %s…)\n", cfg.lane_chain,
                    cba_payee ? "learned" : "none", hex_of(scfg.residual_sink_identity).substr(0, 12).c_str());
        if (serving && cfg.owed_demo_amount) {
            // P1 MULTI-PAYEE proof: seed >=3 DISTINCT owed keys, identical on both nodes.
            // Each (spend,view) is a valid ed25519 point s*G from a fixed domain hash, so
            // both nodes derive the same identities; derive_output needs only the pubkeys.
            const int nkeys = static_cast<int>([]{ const char* e = std::getenv("V37_OWED_KEYS"); return e ? std::atoi(e) : 3; }());
            for (int ki = 0; ki < nkeys; ++ki) {
                std::string ds = "v37-owed-spend#" + std::to_string(ki);
                std::string dv = "v37-owed-view#"  + std::to_string(ki);
                ::xmr::coin::EcScalar es{}, ev{};
                ::xmr::coin::hash_to_scalar(ds.data(), ds.size(), es);
                ::xmr::coin::hash_to_scalar(dv.data(), dv.size(), ev);
                ::xmr::coin::SecretKey ss{}, sv{};
                std::memcpy(ss.data(), es.data(), 32); std::memcpy(sv.data(), ev.data(), 32);
                ::xmr::coin::PublicKey PB{}, PA{};
                if (!::xmr::coin::secret_key_to_public_key(ss, PB) ||
                    !::xmr::coin::secret_key_to_public_key(sv, PA)) {
                    std::printf("owed-demo: key%d point-gen FAILED\n", ki); continue; }
                std::array<std::uint8_t,32> B{}, A{};
                std::memcpy(B.data(), PB.data(), 32); std::memcpy(A.data(), PA.data(), 32);
                const std::uint64_t amt = cfg.owed_demo_amount * static_cast<std::uint64_t>(ki + 1);
                ::v37::bytes32 kid = ledger.seed_owed_std(B, A, amt);
                feed_refs.push_back(::v37::xmr::make_xmr_std(B, A));   // recon(A+B credit): receipt identity == owed key
                std::printf("owed-demo: seeded key%d id=%s... amount=%llu piconero (distinct K_fair payee) [%s]\n",
                            ki, hex_of(kid).substr(0,12).c_str(), static_cast<unsigned long long>(amt),
                            ledger.last_seed_fresh() ? "written through the event log" : "already in the resumed store's log -- not re-applied");
            }
        }

        // ── M2: WHICH miner-data source the assembler is fed from ───────────
        // Nothing below this block knows the difference. The assembler, the X6
        // settlement source, the reward/payee fixpoint, the exact-sum residual
        // sink and the owed_digest in tx_extra 0x03 are the same code either
        // way; only the seam the numbers arrive through moves. `native` was
        // started above run_live's bring_up (M3: in p2p-first it IS the chain
        // the finalize driver is bound to, so it cannot be started down here).
        if (!native)
            std::printf("template source: MONEROD — one get_miner_data per template refresh\n");

        // GOOD-CITIZEN on the daemon arm: rebuild when the tx set monerod
        // OFFERS moves under an unchanged tip (rate-limited), not only when the
        // tip does. --no-good-citizen = legacy tip-only (CONTROL run).
        ::c2pool::xmr::native::tmpl::MonerodArmConfig daemon_arm_cfg;
        daemon_arm_cfg.backlog_refresh_s = cfg.no_good_citizen ? 0 : cfg.native_backlog_refresh_s;

        // ★ DROPS (flip-gated): build the bundle HERE, before the template
        // provider, because a live bundle changes ONE served number: the stratum
        // job target drops from share_diff to the raindrop FLOOR, so a miner
        // hands in its sub-threshold hashes (the raindrops) as well as its shares.
        // The exact share_diff rule still decides share vs raindrop at the mint
        // (relay_on_share), and every receipt still binds t_origin = share_diff.
        // Gate OFF: nullptr, and the provider serves share_diff exactly as master.
        {
            const std::uint64_t drops_rw = c2pool::v37n::xmr::fee::fee_model_on(cfg.lane_params)
                                               ? c2pool::v37n::xmr::fee::kFeeReceiptWeight : relay::kReceiptWeight;
            drops = c2pool::v37n::xmr::drops::XmrDropsWiring::make(cfg.lane_params, cfg.stratum_share_diff, drops_rw);
        }
        if (drops && !relay_enabled()) {
            // Raindrops are node-local observations; the XMR arm composes on EVERY
            // node from its OWN harvest, so without the relay replicating them a
            // composed delta would move this node's owed_digest alone. Refuse to
            // attach rather than fork.
            std::printf("DROPS: gate ON but NO receipt relay (--relay-listen/--relay-peer) -- raindrops cannot be "
                        "replicated, so DROPS is NOT attached (dormant: every composition credits zero)\n");
            drops.reset();
        }
        const std::uint64_t served_job_diff = drops ? drops->floor_diff() : cfg.stratum_share_diff;
        std::unique_ptr<o2::XmrSettlementTemplateProvider> provider_owner =
            native ? std::make_unique<o2::XmrSettlementTemplateProvider>(
                         native->source(), ledger, scfg, served_job_diff, native->pump())
                   : std::make_unique<o2::XmrSettlementTemplateProvider>(
                         transport, ledger, scfg, served_job_diff, daemon_arm_cfg);
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
        std::string   last_fee_tpl_key;   // fee model: one fee-tpl line per (height, parent, owed_digest, EffectiveOwed) state
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
                // fee model (gate ON only): the serve-side REFUSE-IF-ABSENT property. The
                // canonical coinbase (already byte-matched against the parsed block above) must
                // end in the ONE donation output (>= 1 piconero, the residual folded in, S1).
                if (fee_on) {
                const fee::MarkerLocation dm = fee::inspect_donation_marker(t.outputs(), don_net);
                if (!dm.ok) {
                    ++shape_refused;
                    last_shape += " | " + dm.why;
                    if (w) *w = dm.why;
                    return false;
                }
                // fee model evidence: a digest of the payout vector (amount + one-time key per vout,
                // canonical order) -- equal on two nodes at the same input state (key below) iff
                // they built byte-identical coinbase outputs, whatever their give-author %.
                {
                    std::vector<std::uint8_t> pv;
                    for (const auto& o : t.outputs()) {
                        for (int b = 0; b < 8; ++b) pv.push_back(static_cast<std::uint8_t>(o.amount >> (8 * b)));
                        pv.insert(pv.end(), o.one_time_key.data(), o.one_time_key.data() + 32);
                    }
                    const auto od = ::xmr::coin::keccak256(pv.data(), pv.size());
                    std::uint64_t don_total = 0, sum = 0;
                    for (const auto& o : t.outputs()) { sum += o.amount; if (o.identity == fee::donation_identity(don_net)) don_total += o.amount; }
                    // the full input state the outputs are a function of: height, parent, the
                    // owed_digest (finalized partition) AND the pending-netted EffectiveOwed map
                    // (a pending payout moves the owed set without moving owed_digest).
                    std::vector<std::uint8_t> eb;
                    for (const auto& [k, v] : ledger.ledger().effective_owed_all()) {
                        eb.insert(eb.end(), k.begin(), k.end());
                        for (int b = 0; b < 8; ++b) eb.push_back(static_cast<std::uint8_t>(static_cast<unsigned long long>(v) >> (8 * b)));
                    }
                    const auto eoh = ::xmr::coin::keccak256(eb.data(), eb.size());
                    const std::string prev12 = sub::to_hex(t.prev_id().data(), t.prev_id().size()).substr(0, 12);
                    std::string key = std::to_string(t.height()) + ":" + prev12 + ":" + hex_of(ledger.ledger().owed_digest()).substr(0, 12) +
                                      ":" + sub::to_hex(eoh.data(), eoh.size()).substr(0, 12);
                    if (key != last_fee_tpl_key) {
                        last_fee_tpl_key = key;
                        std::printf("fee-tpl: h=%llu prev=%s owed_digest=%s… eo=%s outs=%zu outputs_digest=%s donation_output=%llu@%zu donation_total=%llu sum=%llu reward=%llu exact_sum=%s\n",
                                    static_cast<unsigned long long>(t.height()), prev12.c_str(), hex_of(ledger.ledger().owed_digest()).substr(0, 12).c_str(),
                                    sub::to_hex(eoh.data(), eoh.size()).substr(0, 12).c_str(),
                                    t.outputs().size(), sub::to_hex(od.data(), od.size()).substr(0, 16).c_str(),
                                    static_cast<unsigned long long>(t.outputs()[dm.marker].amount), dm.marker,
                                    static_cast<unsigned long long>(don_total), static_cast<unsigned long long>(sum),
                                    static_cast<unsigned long long>(t.reward()), sum == t.reward() ? "YES" : "NO");
                        std::fflush(stdout);
                    }
                }
                }   // fee_on
                ++shape_ok;
                return true;
            });

        // ── GOOD-CITIZEN ────────────────────────────────────────────────────
        // The operator hard rule: a mined block ALWAYS carries the pool's valid
        // txs (empty coinbase-only ONLY when the pool is genuinely empty). ON by
        // default on both arms; --no-good-citizen is the CONTROL switch for the
        // live proof (reproduces the old coinbase-only-with-full-pool failure).
        //   native arm  take-mempool-as-given (provider gates on the answering
        //               arm's name()) + pool-change rebuild (backlog_refresh_s).
        //   daemon arm  offered-backlog-change rebuild (daemon_arm_cfg above);
        //               the p2pool 5-s age gate stays (time_received is 0 from
        //               get_miner_data, so it admits everything monerod offers).
        if (native && !cfg.no_good_citizen) {
            provider.set_take_mempool_as_given(true);
            std::printf("good-citizen: ON (native arm mines the selected mempool set verbatim; "
                        "backlog-refresh %llus)\n",
                        static_cast<unsigned long long>(cfg.native_backlog_refresh_s));
        } else if (native) {
            std::printf("good-citizen: OFF (--no-good-citizen: native arm uses the p2pool 5-s "
                        "age gate; CONTROL run)\n");
        } else if (!cfg.no_good_citizen) {
            std::printf("good-citizen: ON (daemon arm rebuilds the template when the offered "
                        "get_miner_data backlog moves, at most every %llus)\n",
                        static_cast<unsigned long long>(cfg.native_backlog_refresh_s));
        } else {
            std::printf("good-citizen: OFF (--no-good-citizen: daemon arm rebuilds on tip moves "
                        "only; CONTROL run)\n");
        }

        o2::SettlementStratumTemplateSource template_source(provider);
        std::printf("coinbase: %s (lane_chain=%u, residual sink %s)\n",
                    to_string(cfg.coinbase), static_cast<unsigned>(cfg.lane_chain),
                    serving ? "SET (torsion-checked at build)" : "UNSET (observe-side only)");

        auto candidate = [&provider](std::uint32_t tid, std::uint32_t en, sub::BlockCandidate& out) {
            std::string w;
            return provider.candidate_by_id(tid, en, out, &w);
        };
        own_candidate_lookup = candidate;   // recompute cross-check: our own submitted bytes

        // ── M3: the daemonless FIND path, assembled ─────────────────────────
        //
        // Three things move together or none of them counts: the TIP the
        // template is built on, the CANONICAL TEST settlement matures against
        // (installed above, before bring_up), and the ARM a found block leaves
        // on. All three are the native node's here, and the RPC counters below
        // are printed next to the claim so it stays falsifiable.
        // Tip-feed bookkeeping, main-thread-owned: what the native chain told
        // us, and what we did with it.
        std::uint64_t tip_extends = 0, tip_reorgs = 0, tip_orphans = 0, tip_best = 0;

        // ── GAP-2: the real sharechain relay (replaces --credit-feed / --wire-*) ──
        std::function<void(const strat::AcceptedShare&)> relay_on_share;
        std::function<void(std::uint32_t, const std::string&)> job_binder;   // SEAM-1
        std::function<void()> relay_tick;
        std::uint64_t relay_index_best = 0;
        std::map<std::uint64_t, node::Hash> relay_hdr_by_height;   // GAP-2: height -> block id (header cache)
        std::map<std::string, std::vector<std::uint8_t>> relay_ctx_blobs;   // receipt context: block id hex -> monerod blob (bounded)
        // D6b: under p2p-first the relay chain view (headers, tip, reorgs) is fed
        // from the native index -- no monerod RPC on this path. Context blobs are
        // RC-CTX's (relay_native_ctx.block_blob -> relay_ctx_feeder.serve).
        relay::NativeRelayChainFeed relay_native_feed;
        relay::NativeFeedSource     relay_native_src;
        relay::FeedCompare          relay_feed_cmp;           // compare-only oracle totals
        std::uint64_t               relay_feed_cmp_rpc = 0, relay_feed_cmp_rpc_failed = 0;
        if (p2p_first && chain_src.tip_block && chain_src.id_at && chain_src.seed_for) {
            relay_native_src.tip      = chain_src.tip_block;
            relay_native_src.id_at    = chain_src.id_at;
            relay_native_src.seed_for = chain_src.seed_for;
        }
        // ══ ★ DROPS — THE XMR LIVE WIRING (flip-gated; DORMANT by default) ══
        // The twin of main_v37_btc_dash.cpp's Step-2 block. XmrNode has carried
        // the four T3 seams since the XMR arm landed and nothing here called
        // them, so a flipped XMR node converged and credited nobody.
        //
        // ★★ THE CLOCK IS THE TIP. The TipBin is primed HERE from the tip this
        // node verified itself (p2p-first: the native levin chain, READY by now;
        // daemon-first: the adapter's ZMQ-fed index), and fed afterwards ONLY
        // from the height watch (pump_tip). The burial frontier reaches the
        // bundle only through pre_harvest -> declare_at_frontier and can never
        // reach an enrolment. Enrolment happens HERE, before the relay listens
        // and before the stratum binds, so the book is frozen for every reader.
        //
        // GATE OFF (the shipped default): make() (above, before the template
        // provider) returned nullptr and this block constructs nothing, attaches
        // nothing, and arms nothing.
        if (drops) {
            // THE FOUR NODE SEAMS. Enrolment and the share-count arm are NOT done
            // here: at this point the native index may still be walking up from
            // genesis (READY is not "at the tip" -- measured: tip 0 here, 120 a
            // moment later), and enrolling against that would be the stale-now
            // shape itself. drops_try_enrol() (below, from the height watch) does
            // both once the native tip has caught up with the template served.
            drops->attach(node);
            drops_live = true;
            std::printf("DROPS: ★ ACTIVE (V37_ACTIVATE_CONSENSUS_V1, K=%u, lz=%u, share_diff=%llu, raindrop floor diff=%llu, "
                        "receipt weight=%llu, to enrol=%zu at the native tip): every lane block composes the sub-threshold "
                        "REPLACE delta. CONSENSUS ACTIVATION -- a node without it will not agree on owed_digest.\n",
                        (unsigned)cfg.lane_params.subthreshold.K, c2pool::v37n::xmr::drops::kXmrDropsLz,
                        (unsigned long long)drops->share_diff(), (unsigned long long)drops->floor_diff(),
                        (unsigned long long)drops->receipt_weight(), g_drops_enrol.size());
            if (g_drops_enrol.empty())
                std::printf("DROPS: gate ON but NOBODY is enrolled (--drops-enrol) -- every composition credits zero (fail-closed, opt-in)\n");
        }
        // ★ DROPS: enrol + arm, ONCE, at the NATIVE TIP -- the first time the tip
        // clock (fed only from the height watch) has reached the bin of the
        // template this node serves (template height == native tip + 1). Before
        // that nothing is enrolled and the share-count book is unarmed, so every
        // earlier interval stays UNKNOWN and is withheld (fail-closed).
        bool drops_enrolled = false;
        std::uint64_t drops_peer_height = 0;
        // Under p2p-first "at the tip" is the native node's own claim checked
        // against its peers: the tip clock (tip + 1, a chain HEIGHT) must have
        // reached the best peer's advertised height. READY alone is not enough
        // (measured: a force-synced regtest node served a template at h=1 while
        // its index was still at 64 of 120).
        auto drops_tip_synced = [&]() -> bool {
            if (!p2p_first) return true;   // daemon-first: the ZMQ-fed index follows a synced monerod
            if (!native || !native->node()) return false;
            drops_peer_height = native->node()->status().driver.best_peer_height;
            const auto nb = drops->now_interval();
            return drops_peer_height > 0 && nb && *nb >= drops_peer_height;
        };
        auto drops_try_enrol = [&]() {
            if (!drops_live || drops_enrolled) return;
            const auto t = provider.current();
            const auto now_bin = drops->now_interval();
            if (!t.valid || !now_bin || *now_bin < t.height) return;
            if (!drops_tip_synced()) return;
            for (const auto& e : g_drops_enrol) {
                ::v37::bytes32 payee{};
                bool ok = false;
                if (e.size() == 64) {
                    std::vector<std::uint8_t> raw;
                    if (sub::from_hex(e, raw) && raw.size() == 32) { std::memcpy(payee.data(), raw.data(), 32); ok = true; }
                } else if (const auto da = relay::decode_address(e)) {
                    const ::v37::ScriptRef ref = da->ref();
                    if (::v37::xmr::xmr_ref_valid(ref)) { payee = ::v37::xmr::xmr_identity_key(ref); ok = true; }
                }
                if (!ok) { std::printf("DROPS: --drops-enrol %s is neither a 64-hex identity nor a valid XMR address -- NOT enrolled\n", e.c_str()); continue; }
                const auto oc = drops->enroll_at_tip(payee);
                std::printf("DROPS: enrol %s… %s at tip bin %llu (native tip %llu, best peer height %llu, served template h=%llu), effective from interval %llu\n",
                            hex_of(payee).substr(0, 16).c_str(),
                            oc == c2pool::v37n::EnrollOutcome::Enrolled ? "ENROLLED ex ante"
                            : oc == c2pool::v37n::EnrollOutcome::AlreadyEnrolled ? "already enrolled (the FIRST commitment stands)"
                            : "REFUSED (tip unknown)",
                            (unsigned long long)*now_bin, (unsigned long long)(*now_bin - 1), (unsigned long long)drops_peer_height, (unsigned long long)t.height,
                            (unsigned long long)(*now_bin + 1));
            }
            drops->arm_at_tip();
            drops_enrolled = true;
            std::printf("DROPS: share-count book armed at tip bin %llu; enrolled=%zu enrollment_digest=%s…\n",
                        (unsigned long long)*now_bin, drops->core().stats().enrolled,
                        hex_of(drops->core().enrollment().book_digest()).substr(0, 16).c_str());
            std::fflush(stdout);
        };
        if (relay_enabled()) {
            if (!serving) {
                std::printf("REFUSED: the receipt relay needs a served template (--residual-sink-spend-hex/--residual-sink-view-hex)\n");
                node.stop();
                return 2;
            }
            const relay::BindMode bind = (g_relay_bind == "rbind") ? relay::BindMode::Rbind : relay::BindMode::None;
            // The relay verify worker's OWN RandomX light VM: a receipt flood never
            // sits in front of a miner's submit on the listener's verifier.
            relay_rx = std::make_unique<o2::O2RandomXVerifier>();
            o2::RandomXPolicy rp = o2::RandomXPolicy::from_config(cfg);
            rp.lazy_prefetch_on_miss = true;   // the verify thread, never the submit path (I2 holds for the listener)
            relay_rx->init(rp);
            if (!relay_rx->ready()) {
                std::printf("REFUSED: the receipt relay must RandomX-verify every peer receipt, but its verifier is %s "
                            "(--randomx and a -DXMR_BUILD_RANDOMX=ON build are required; fail-closed)\n",
                            o2::O2RandomXVerifier::to_string(relay_rx->mode()));
                node.stop();
                return 3;
            }
            relay::RelayOptions ro;
            ro.network = cfg.network == MoneroNetwork::Mainnet ? 0 : cfg.network == MoneroNetwork::Testnet ? 1
                       : cfg.network == MoneroNetwork::Stagenet ? 2 : 3;
            ro.chain = cfg.lane_chain;
            ro.share_diff = cfg.stratum_share_diff;
            ro.bind = bind;
            ro.drops_floor_diff = drops_live ? drops->floor_diff() : 0;   // ★ DROPS: 0 = master's receiver
            ro.lane_params_digest = relay::lane_params_digest(cfg.lane_params, cfg.stratum_share_diff, bind,
                                                            ro.network);   // S4: + FeeModelGate (+ this network's donation identity) iff ON
            ro.max_pushes_per_receipt = fee_on ? 2 : 1;   // fee model S3: (payee, donation) split
            ro.listen = !g_relay_listen.empty();
            if (ro.listen && !split_hostport(g_relay_listen, ro.listen_host, ro.listen_port)) {
                std::printf("REFUSED: --relay-listen wants HOST:PORT, got \"%s\"\n", g_relay_listen.c_str());
                node.stop(); return 2;
            }
            for (const auto& pr : g_relay_peers) {
                std::string h; std::uint16_t pt = 0;
                if (!split_hostport(pr, h, pt)) { std::printf("REFUSED: --relay-peer wants HOST:PORT, got \"%s\"\n", pr.c_str()); node.stop(); return 2; }
                ro.peers.emplace_back(h, pt);
            }
            ro.max_peers = g_relay_max_peers;
            ro.index_horizon = g_relay_horizon;
            {
                double v[4] = {1, 20, 16, 256}; int k = 0; std::stringstream ss(g_relay_rx_budget); std::string tok;
                while (k < 4 && std::getline(ss, tok, ',')) { try { v[k++] = std::stod(tok); } catch (...) { k = -1; break; } }
                if (k != 4) { std::printf("REFUSED: --relay-rx-budget wants P,C,G,GC (refill/s, cap per peer; refill/s, cap global)\n"); node.stop(); return 2; }
                ro.dos.per_peer_refill = v[0]; ro.dos.per_peer_capacity = v[1]; ro.dos.global_refill = v[2]; ro.dos.global_capacity = v[3];
            }
            ro.solicited_credits = g_relay_solicited;
            ro.backfill_positions = g_relay_backfill;
            ro.reoffer_seconds = g_relay_reoffer_s;
            ro.serve = !g_no_relay_serve;
            if (g_relay_vault_entries) ro.vault.max_entries = g_relay_vault_entries;
            if (g_relay_vault_bytes)   ro.vault.max_bytes = g_relay_vault_bytes;
            if (g_relay_vault_horizon) ro.vault.horizon_positions = g_relay_vault_horizon;
            o2::O2RandomXVerifier* rxp = relay_rx.get();
            relay_node = std::make_unique<relay::XmrRelayNode>(
                ro, relay_chain,
                [rxp](const std::vector<std::uint8_t>& blob, const ::v37::bytes32& seed, ::v37::bytes32& pow) -> bool {
                    o2::Seed32 s{}; std::memcpy(s.data(), seed.data(), 32);
                    o2::Hash32 h{};
                    if (!rxp->randomx_hash(blob.data(), blob.size(), 0, s, h)) return false;
                    std::memcpy(pow.data(), h.data(), 32);
                    return true;
                },
                [&node, &cfg]() -> std::pair<std::uint64_t, ::v37::bytes32> {
                    auto s = node.engine().snapshot(cfg.lane_chain);
                    if (!s) return {0, ::v37::bytes32{}};
                    return {s->next_pos, s->digest};
                },
                [&relay_log_mtx, &relay_log_q](const std::string& l) {
                    std::lock_guard<std::mutex> lk(relay_log_mtx);
                    if (relay_log_q.size() < 4096) relay_log_q.push_back(l);
                });
            relay::XmrReceiptIngest::Options io;
            io.chain = cfg.lane_chain;
            io.order = (g_relay_order == "arrival") ? relay::XmrReceiptIngest::Order::Arrival
                                                    : relay::XmrReceiptIngest::Order::Canonical;
            io.bin_lag = g_relay_bin_lag;
            io.grace_ms = g_relay_grace_ms;
            {
                std::error_code ec; std::filesystem::create_directories(cfg.resolved_settle_db_path(), ec);
                io.durable_path = cfg.resolved_settle_db_path() + "/lane" + std::to_string(cfg.lane_chain) + ".receipts";
                // RC-CTX (3): the contexts of the templates this node issued survive a restart
                relay_ctx_journal = relay::CtxJournal(cfg.resolved_settle_db_path() + "/lane" + std::to_string(cfg.lane_chain) + ".ctx");
                const std::size_t nctx = relay_ctx_journal.load(relay_chain);
                std::printf("relay: receipt-context journal %s reloaded=%zu%s\n", relay_ctx_journal.path().c_str(), nctx,
                            relay_ctx_journal.bad_tail() ? " (a torn tail record was dropped)" : "");
            }
            // RC-CTX (1)+(2): the embedded native node's verified chain index is a
            // context source on every arm it runs on (rows -> ChainView; retained
            // bodies -> own wants + peers' FB_GETCTX). On p2p-first the rows come
            // from D6b's NativeRelayChainFeed instead of (1); (2) serves on every arm.
            if (native && native->node()) {
                auto* nn = native->node();
                relay_native_ctx.best_height = [nn]() -> std::optional<std::uint64_t> {
                    const auto t = nn->index().tip();
                    if (!t) return std::nullopt;
                    return t->height;
                };
                relay_native_ctx.id_at = [nn](std::uint64_t h) -> std::optional<::v37::bytes32> {
                    const auto b = nn->index().by_height(h);
                    if (!b) return std::nullopt;
                    ::v37::bytes32 id{}; std::memcpy(id.data(), b->id.data(), 32); return id;
                };
                relay_native_ctx.seed_for_bin = [nn](std::uint64_t bin) -> std::optional<::v37::bytes32> {
                    const auto sd = nn->index().seed_hash_for_height(bin);
                    if (!sd) return std::nullopt;
                    ::v37::bytes32 s{}; std::memcpy(s.data(), sd->data(), 32); return s;
                };
                relay_native_ctx.block_blob = [nn](const ::v37::bytes32& id, std::vector<std::uint8_t>& blob) {
                    node::Hash h{}; std::memcpy(h.data(), id.data(), 32);
                    return nn->index().block_blob_of(h, blob);
                };
                std::printf("relay: receipt contexts from the native node (best-chain rows + retained bodies; FB_GETCTX served natively)\n");
            }
            io.fee_model = fee_on;   // fee model S3: push split by the receipt's own PoW-committed give_author
            io.network = static_cast<std::uint8_t>(don_net);   // DON-NET: the donation payee of this network
            relay_ingest = std::make_unique<relay::XmrReceiptIngest>(
                io,
                [&](const ::v37::ScriptRef& payee, std::uint64_t w, std::uint64_t& next_after, ::v37::bytes32& dig) -> bool {
                    ::v37::PayoutDescriptor d; d.pay = payee;
                    const auto res = node.engine().submit_tracked(::v37::LaneRecord::push(cfg.lane_chain, d, w, 0)).get();
                    if (!res.applied()) { ++feed_rejected; return false; }
                    ++feed_pushed;
                    feed_log.emplace_back(payee, w);   // R3's replay log = this node's own lane order
                    auto s = node.engine().snapshot(cfg.lane_chain);
                    next_after = s ? s->next_pos : feed_log.size();
                    if (s) dig = s->digest;
                    return true;
                },
                [&](const relay::Admitted& a, std::uint64_t pos_first, std::uint32_t n_pushes, std::uint64_t next_after, const ::v37::bytes32& dig) {
                    relay_node->on_pushed(a.id, pos_first, n_pushes, a.raw, next_after, dig);
                    if (drops_live) drops->on_share_pushed(::v37::xmr::xmr_identity_key(a.r.payee), a.bin);   // ★ DROPS: S
                    ledger.learn_ref(a.r.payee);   // every node can resolve every credited payee's output
                });
            const std::size_t reloaded = relay_ingest->reload([&](const relay::Admitted& a) {
                relay_node->note_reloaded(a);
                ledger.learn_ref(a.r.payee);
            });
            std::string why;
            if (!relay_node->start(why)) { std::printf("REFUSED: %s\n", why.c_str()); node.stop(); return 2; }
            if (g_relay_partition_s) {   // test-only knob, never on mainnet (the relay is refused there)
                std::signal(SIGUSR1, on_sigusr1);
                std::printf("relay: TEST knob armed: SIGUSR1 partitions the relay for %u s\n", g_relay_partition_s);
            }
            {
                auto s = node.engine().snapshot(cfg.lane_chain);
                std::printf("relay: GAP-2 receipt relay UP listen=%s:%u peers=%zu bind=%s order=%s(L=%llu grace=%ums) share_diff=%llu "
                            "lane_params_digest=%s… horizon=%llu rx-budget=%s | durable %s reloaded=%zu lane next_pos=%llu digest=%s… | %s\n",
                            ro.listen ? ro.listen_host.c_str() : "-", (unsigned)relay_node->listen_port(), ro.peers.size(),
                            relay::to_string(bind), g_relay_order.c_str(), (unsigned long long)g_relay_bin_lag, g_relay_grace_ms,
                            (unsigned long long)cfg.stratum_share_diff, hex_of(ro.lane_params_digest).substr(0, 12).c_str(),
                            (unsigned long long)g_relay_horizon, g_relay_rx_budget.c_str(), io.durable_path.c_str(), reloaded,
                            s ? (unsigned long long)s->next_pos : 0ULL, s ? hex_of(s->digest).substr(0, 12).c_str() : "-",
                            rxp->describe().c_str());
                if (bind == relay::BindMode::None)
                    std::printf("relay: NOTE bind=none -- receipts are PoW-verified (opening -> tree_root -> RandomX >= share_diff) "
                                "but the payee/give-author are NOT PoW-bound (run --relay-bind rbind: SEAM-1 writes rbind into the coinbase 0x02 region)\n");
                std::fflush(stdout);
            }
            // SEAM-1 (--relay-bind rbind): the per-JOB binding. The stratum server calls the
            // binder with (extra_nonce, login address) right before the job's blob is built;
            // the payee is decided HERE -- the node-owner fee roll happens at job issue (v36
            // work.py) -- together with this node's give-author u16, and the template writes
            // rbind_v1(chain, side) into coinbase 0x02[4..36). The share the miner finds on
            // that job is RandomX-bound to (payee, give-author); the mint reads the SAME entry.
            if (bind == relay::BindMode::Rbind) {
                rbind_reg = std::make_shared<relay::RbindRegistry>();
                std::shared_ptr<relay::RbindRegistry> reg = rbind_reg;
                provider.set_extra_nonce_bind(relay::RbindRegistry::kBindBytes,
                    [reg](std::uint32_t en, std::uint8_t* out) { return reg->bind_bytes(en, out); });
                const std::uint64_t share_diff = cfg.stratum_share_diff;
                const std::uint32_t lane = cfg.lane_chain;
                job_binder = [&, reg, share_diff, lane, owner_bp, my_give_author](std::uint32_t en, const std::string& address) {
                    std::optional<::v37::ScriptRef> miner;
                    if (!address.empty()) {
                        std::lock_guard<std::mutex> lk(mint_mtx);
                        auto it = mint_payee_cache.find(address);
                        if (it == mint_payee_cache.end()) {
                            std::optional<::v37::ScriptRef> r;
                            if (const auto da = relay::decode_address(address)) {
                                const ::v37::ScriptRef ref = da->ref();
                                if (::v37::xmr::xmr_ref_valid(ref)) r = ref;
                            }
                            if (!r && cba_payee_ref) r = *cba_payee_ref;
                            it = mint_payee_cache.emplace(address, r).first;
                            if (mint_payee_cache.size() > 4096) mint_payee_cache.clear();
                        }
                        miner = it->second;
                    } else if (cba_payee_ref) {
                        miner = *cba_payee_ref;   // the in-process miner's slot: the node's own payee
                    }
                    if (!miner) { ++bind_nopayee; return; }   // unbound job: its shares cannot mint (fail-closed)
                    std::uint64_t roll = 0;
                    { std::lock_guard<std::mutex> lk(mint_mtx); roll = bind_rng(); }
                    bool owner_hit = false;
                    const ::v37::ScriptRef payee = address.empty() ? *miner
                        : fee::choose_payee(*miner, owner_ref, owner_bp, roll, &owner_hit);
                    if (reg->put(en, relay::make_job_binding(lane, share_diff, payee, my_give_author, owner_hit))) {
                        ++bind_jobs;
                        if (owner_hit) ++bind_owner;
                    }
                };
                std::printf("relay: SEAM-1 rbind ACTIVE -- coinbase 0x02 = [extra_nonce 4 | rbind 32 | pad | tail]; payee + "
                            "give-author (u16=%u) PoW-bound per job; node-owner fee %.4f%% rolled at job issue\n",
                            (unsigned)my_give_author, fee_on ? g_owner_fee_pct : 0.0);
            }
            // MINT (stratum listener thread, or the main thread for --mine hits).
            const std::uint64_t share_diff = cfg.stratum_share_diff;
            const std::uint32_t lane = cfg.lane_chain;
            relay_on_share = [&, bind, share_diff, lane](const strat::AcceptedShare& acc) {
                auto fail = [&](const std::string& w) {
                    ++mint_fail;
                    std::lock_guard<std::mutex> lk(mint_mtx);
                    mint_last_err = w;
                };
                ::v37::bytes32 pow{}; std::memcpy(pow.data(), acc.pow_hash.data(), 32);
                // ★ DROPS (gate ON only): below share_diff but at/above the floor is a
                // RAINDROP -- minted with the SAME binding and flooded, never pushed.
                bool is_drop = false;
                if (!relay::meets_share_diff(pow, share_diff)) {
                    if (!drops_live) { ++mint_below; return; }   // lax top-64 accept, exact rule refuses
                    if (!relay::meets_share_diff(pow, drops->floor_diff())) { ++mint_below; ++drops_mint_below_floor; return; }
                    is_drop = true;
                }
                std::optional<::v37::ScriptRef> payee;
                relay::SideDataV2 side;
                if (bind == relay::BindMode::Rbind) {
                    // SEAM-1: the job's binding IS the receipt's (payee, side) -- the coinbase
                    // the share hashed commits to exactly these bytes.
                    const auto jb = rbind_reg ? rbind_reg->get(acc.extra_nonce) : std::nullopt;
                    if (!jb) { ++mint_nopayee; return; }
                    payee = jb->payee;
                    side = jb->side;
                } else {
                    std::lock_guard<std::mutex> lk(mint_mtx);
                    auto it = mint_payee_cache.find(acc.address);
                    if (it == mint_payee_cache.end()) {
                        std::optional<::v37::ScriptRef> r;
                        if (const auto da = relay::decode_address(acc.address)) {
                            const ::v37::ScriptRef ref = da->ref();
                            if (::v37::xmr::xmr_ref_valid(ref)) r = ref;
                        }
                        if (!r && cba_payee_ref) r = *cba_payee_ref;
                        it = mint_payee_cache.emplace(acc.address, r).first;
                        if (mint_payee_cache.size() > 4096) mint_payee_cache.clear();
                    }
                    payee = it->second;
                    if (payee) {
                        side.t_lo = share_diff; side.identity = ::v37::xmr::xmr_identity_key(*payee); side.chain_id = lane;
                        side.give_author = 0;   // bind=none: never PoW-bound, so never a give-author (the fee model needs rbind)
                    }
                }
                if (!payee) { ++mint_nopayee; return; }
                sub::BlockCandidate c; std::string w;
                if (!provider.candidate_by_id(acc.template_id, acc.extra_nonce, c, &w)) { fail("candidate: " + w); return; }
                std::vector<std::uint8_t> hb = c.hashing_blob;
                if (!sub::patch_u32_le(hb, c.nonce_offset, acc.nonce)) { fail("nonce patch"); return; }
                relay::FbReceipt fb;
                if (!relay::mint_receipt(c.full_blob, hb, side, *payee, fb, &w)) { fail(w); return; }
                relay::CheckCtx cc; cc.lane_chain = lane; cc.share_diff = share_diff; cc.bind = bind; cc.check_payee_point = false;
                const relay::CheckResult cr = relay::check_structural(fb, cc);
                if (!cr.ok()) { fail(std::string("self-check ") + relay::to_string(cr.stage) + ": " + cr.why); return; }
                relay::Admitted a;
                a.id = cr.id; a.raw = relay::encode_fb_receipt(fb);
                if (a.raw.empty()) { fail("encode: receipt over the relay budget"); return; }
                a.r = std::move(fb); a.bin = acc.height; a.own = true;
                if (is_drop) { a.pow = pow; relay_node->submit_own_drop(std::move(a)); ++drops_mint_ok; return; }
                relay_node->submit_own(std::move(a));
                ++mint_ok;
            };
            // Per-loop (main thread): chain view, admitted -> lane, bin closing, block-won.
            relay_tick = [&]() {
                {
                    const auto t = provider.current();
                    if (t.valid) {
                        ::v37::bytes32 prev{}, seed{};
                        std::memcpy(prev.data(), t.prev_id.data(), 32); std::memcpy(seed.data(), t.seed_hash.data(), 32);
                        relay_chain.note(prev, t.height, seed);
                        relay_chain.note_seed(::xmr::coin::rx_seedheight(t.height), seed);
                        relay_chain.set_tip(t.height);
                        relay_ctx_journal.note(prev, t.height, seed);   // RC-CTX (3)
                    }
                }
                if (p2p_first && relay_native_src) {
                    // D6b: under p2p-first the relay chain view is fed from the chain
                    // this node verified itself -- the daemon arm's body (same 128
                    // window, same seed rule, same notes) once per new tip (a tip-ID
                    // change, so a same-height reorg re-notes too). It is the ONE row
                    // feed on this arm; RC-CTX (1) (else-branch) feeds the arms it does
                    // not run on (daemon-first with a native node), unchanged.
                    // monerod is only ever the opt-in compare oracle: it counts, it
                    // never decides. Receipt CONTEXT is not served here: own wants and
                    // peers' FB_GETCTX go through RC-CTX's feeder (2) below.
                    relay::FeedSink sink;
                    sink.note = [&](const relay::FeedId& p, std::uint64_t h, const relay::FeedId& sd) {
                        ::v37::bytes32 prev{}, seed{};
                        std::memcpy(prev.data(), p.data(), 32); std::memcpy(seed.data(), sd.data(), 32);
                        relay_chain.note(prev, h, seed);
                    };
                    sink.note_seed = [&](std::uint64_t sh, const relay::FeedId& sd) {
                        ::v37::bytes32 seed{}; std::memcpy(seed.data(), sd.data(), 32);
                        relay_chain.note_seed(sh, seed);
                    };
                    if (relay_native_feed.tick(relay_native_src, sink) && g_relay_feed_monerod_compare && !cfg.no_daemon_rpc) {
                        const std::uint64_t best = relay_native_feed.best();
                        const std::uint64_t lo = best > relay::NativeRelayChainFeed::kWindow ? best - relay::NativeRelayChainFeed::kWindow : 0;
                        std::map<std::uint64_t, relay::FeedId> nat, mon;
                        for (std::uint64_t h = lo; h <= best; ++h)
                            if (const auto id = relay_native_src.id_at(h)) nat[h] = *id;
                        bool ok = false;
                        ++relay_feed_cmp_rpc;
                        transport.rpc_post(node::MoneroDaemonRpc::body_get_block_headers_range(lo, best), [&](const node::RpcResponse& r) {
                            if (!r.ok()) return;
                            if (auto v = node::MoneroDaemonRpc::parse_block_headers_range(r.body)) {
                                ok = true;
                                for (const auto& b : *v) mon[b.height] = b.id;
                            }
                        });
                        if (!ok) ++relay_feed_cmp_rpc_failed;
                        else {
                            const relay::FeedCompare c = relay::compare_windows(nat, mon);
                            relay_feed_cmp.equal += c.equal; relay_feed_cmp.mismatch += c.mismatch;
                            relay_feed_cmp.native_only += c.native_only; relay_feed_cmp.monerod_only += c.monerod_only;
                        }
                    }
                } else if (relay_native_ctx) {
                    relay_ctx_feeder.feed(relay_chain, relay_native_ctx);   // RC-CTX (1)
                }
                if (!p2p_first && !cfg.no_daemon_rpc) {
                    // The daemon arm: once per new tip, ONE get_block_headers_range over the
                    // last 128 blocks (+ the RandomX seed block, cached) so a peer receipt built
                    // on any recent block -- including the blocks this node missed while it was
                    // down -- resolves to (bin, seed) on the verify thread without an RPC there.
                    const std::uint64_t best = node.adapter().index().best_height();
                    if (drops_live && best) { drops->observe_native_tip(best); drops_try_enrol(); }   // ★ DROPS: daemon-first tip (ZMQ-fed index, no RPC)
                    if (best && best != relay_index_best) {
                        relay_index_best = best;
                        auto rpc_headers = [&](const std::string& body, bool range) {
                            std::vector<node::ChainMainBlock> out;
                            transport.rpc_post(body, [&](const node::RpcResponse& r) {
                                if (!r.ok()) return;
                                if (range) { if (auto v = node::MoneroDaemonRpc::parse_block_headers_range(r.body)) out = *v; }
                                else if (auto b = node::MoneroDaemonRpc::parse_block_header(r.body)) out.push_back(*b);
                            });
                            return out;
                        };
                        const std::uint64_t lo = best > 128 ? best - 128 : 0;
                        const auto hdrs = rpc_headers(node::MoneroDaemonRpc::body_get_block_headers_range(lo, best), true);
                        for (const auto& b : hdrs) relay_hdr_by_height[b.height] = b.id;
                        for (const auto& b : hdrs) {
                            const std::uint64_t sh = node::rx_seed_height(b.height + 1);
                            auto sit = relay_hdr_by_height.find(sh);
                            if (sit == relay_hdr_by_height.end()) {
                                for (const auto& s : rpc_headers(node::MoneroDaemonRpc::body_get_block_header_by_height(sh), false))
                                    relay_hdr_by_height[s.height] = s.id;
                                sit = relay_hdr_by_height.find(sh);
                                if (sit == relay_hdr_by_height.end()) continue;
                            }
                            ::v37::bytes32 prev{}, seed{};
                            std::memcpy(prev.data(), b.id.data(), 32); std::memcpy(seed.data(), sit->second.data(), 32);
                            relay_chain.note(prev, b.height + 1, seed);
                            relay_chain.note_seed(sh, seed);
                        }
                        while (relay_hdr_by_height.size() > 4096) relay_hdr_by_height.erase(relay_hdr_by_height.begin());
                    }
                    // Receipt CONTEXT (the relay-repair fix): a block a receipt was
                    // mined on that this node never saw (an orphaned sibling). ONE
                    // monerod get_block by hash serves both sides: (1) OUR wants --
                    // our monerod may hold it as an alternative block; (2) a PEER's
                    // FB_GETCTX -- the minter's monerod had it as its tip. The blob
                    // is verified by the relay (id recomputed, height from the
                    // coinbase, parent-linked), never trusted. Bounded per tick.
                    auto get_block_blob = [&](const ::v37::bytes32& id) -> std::vector<std::uint8_t> {
                        const std::string hx = hex_of(id);
                        if (auto it = relay_ctx_blobs.find(hx); it != relay_ctx_blobs.end()) return it->second;
                        {   // RC-CTX (2): the native node's retained body first -- no RPC
                            std::vector<std::uint8_t> nb;
                            if (relay_native_ctx.block_blob && relay_native_ctx.block_blob(id, nb) && !nb.empty() && nb.size() <= relay::kCtxMaxBlob)
                                return nb;
                        }
                        std::string body, err;
                        transport.rpc_post(node::MoneroDaemonRpc::body_get_block(0, hx),
                                           [&](const node::RpcResponse& r) { if (!r.ok()) err = r.error; else body.assign(r.body.begin(), r.body.end()); });
                        std::vector<std::uint8_t> blob;
                        if (!err.empty()) return blob;
                        node::minijson::Value v;
                        if (!node::minijson::parse(body, v)) return blob;
                        const std::string bh = v["result"]["blob"].as_string();
                        if (bh.empty() || !sub::from_hex(bh, blob) || blob.size() > relay::kCtxMaxBlob) { blob.clear(); return blob; }
                        relay_ctx_blobs[hx] = blob;
                        while (relay_ctx_blobs.size() > 128) relay_ctx_blobs.erase(relay_ctx_blobs.begin());
                        return blob;
                    };
                    std::size_t budget = 16;
                    for (const auto& id : relay_node->ctx_wants_local()) {
                        if (!budget--) break;
                        const auto blob = get_block_blob(id);
                        if (!blob.empty()) relay_node->offer_ctx(id, blob, 0);
                    }
                    for (const auto& [pid, ids] : relay_node->drain_ctx_requests())
                        for (const auto& id : ids) {
                            if (!budget) { relay_node->send_ctx(pid, id, {}); continue; }   // over budget: "unknown" -> the asker fails over at once
                            --budget;
                            relay_node->send_ctx(pid, id, get_block_blob(id));
                        }
                } else if (relay_native_ctx) {
                    // RC-CTX (2), P2P-first arm: own wants + peers' FB_GETCTX from the native node's bodies
                    relay_ctx_feeder.serve(*relay_node, relay_native_ctx);
                } else {
                    for (const auto& [pid, ids] : relay_node->drain_ctx_requests())   // no monerod RPC and no native node to serve from
                        for (const auto& id : ids) relay_node->send_ctx(pid, id, {});
                }
                {
                    std::vector<std::string> ls;
                    { std::lock_guard<std::mutex> lk(relay_log_mtx); ls.swap(relay_log_q); }
                    for (const auto& l : ls) std::printf("  [relay] %s\n", l.c_str());
                }
                if (g_relay_partition_req.exchange(false) && g_relay_partition_s)
                    relay_node->partition_for(std::chrono::seconds(g_relay_partition_s));
                for (auto& a : relay_node->drain_admitted()) relay_ingest->on_admitted(std::move(a));
                if (drops_live)   // ★ DROPS: every replicated raindrop (own + peers') -> the harvester
                    for (auto& a : relay_node->drain_drops())
                        drops->on_raindrop(::v37::xmr::xmr_identity_key(a.r.payee), a.bin, a.pow);
                relay_ingest->tick(provider.current().height);
                for (const auto& [bw, pid] : relay_node->drain_block_won()) relay_on_cut(bw, pid);
            };
        }

        ServeHooks hooks;
        hooks.cba_tick = [&]() { cba_ring_push(); feed_pump(); wire_pump(); if (relay_tick) relay_tick(); };   // recon(A+B credit): + receipt feed + v0x02 fast path (+ GAP-2 relay)
        hooks.on_share = relay_on_share;
        hooks.job_binder = job_binder;   // SEAM-1 (unset unless --relay-bind rbind)
        if (relay_node) {
            // GAP-2: disjoint per-node miner search spaces (see XmrStratumServer::seed_extra_nonce).
            std::random_device rd;
            hooks.extra_nonce_base = (1u << 24) + (static_cast<std::uint32_t>(rd()) % ((1u << 31) - (1u << 24)));
            std::printf("relay: stratum extra_nonce base = %u (node-private miner search space)\n", *hooks.extra_nonce_base);
        }
        if (p2p_first) {
            if (!native->node()->block_relay()) {
                std::printf("REFUSED: the native node built no block relay (internal wiring bug)\n");
                node.stop();
                return 2;
            }
            hooks.p2p_relay = native->node()->block_relay();

            // THE TIP, from the chain we verified ourselves. Drained here, on
            // the main thread, at exactly the point in the loop where
            // pump_poll() used to issue get_miner_data -- one substitution, in
            // one place, so the RPC that is gone is gone by construction.
            hooks.pump_tip = [&]() {
                for (const auto& ev : chain_src.drain()) {
                    using K = node::MainchainEventKind;
                    if (ev.kind == K::Orphan) ++tip_orphans;
                    else {
                        if (ev.kind == K::Reorg) ++tip_reorgs; else ++tip_extends;
                        if (ev.block.height > tip_best) tip_best = ev.block.height;
                    }
                    node.pump_mainchain_event(ev);
                }
                // ★ DROPS: THE EX-ANTE CLOCK, from the SAME native tip, in the same
                // place -- never the burial frontier, never a monerod poll.
                if (drops_live && tip_best) { drops->observe_native_tip(tip_best); drops_try_enrol(); }
                // c2pool#1551: the candidates we HOLD but did not adopt. In the
                // branch where our own block stays best the rival never becomes
                // a mainchain event at all, so without this sweep the race book
                // would report the height uncontested and credit as if we had
                // run unopposed.
                if (chain_src.alt_candidates) {
                    std::vector<o2::FinalizeConnect::AltObservation> alts;
                    for (const auto& a : chain_src.alt_candidates())
                        alts.push_back(o2::FinalizeConnect::AltObservation{a.height, a.bid_hex, a.own_mined});
                    fc.observe_alt_tips(alts);
                }
            };
        }
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
            if (drops_live) {   // ★ DROPS (gate ON only)
                const auto ds = drops->core().stats();
                const auto& rs = relay_node->stats();
                std::printf("  drops: tip_bin=%llu enrolled=%zu digest=%s… raindrops=%llu late=%llu withheld=%llu discarded=%llu open=%zu "
                            "shares_seen=%llu declared=%llu priced=%llu unpriced=%llu last_rows=%zu | mint drops=%llu below_floor=%llu | "
                            "relay drops own=%llu foreign=%llu dup=%llu\n",
                            (unsigned long long)(drops->now_interval() ? *drops->now_interval() : 0), ds.enrolled,
                            hex_of(drops->core().enrollment().book_digest()).substr(0, 12).c_str(),
                            (unsigned long long)ds.harvested, (unsigned long long)ds.late, (unsigned long long)ds.withheld,
                            (unsigned long long)ds.discarded, ds.open, (unsigned long long)ds.shares_seen, (unsigned long long)ds.declared,
                            (unsigned long long)drops->priced(), (unsigned long long)drops->unpriced(), node.last_harvest_rows(),
                            (unsigned long long)drops_mint_ok.load(), (unsigned long long)drops_mint_below_floor.load(),
                            (unsigned long long)rs.drops_own.load(), (unsigned long long)rs.drops_foreign.load(), (unsigned long long)rs.drops_dup.load());
            }
            if (relay_node) {   // GAP-2
                std::printf("  %s\n", relay_node->describe().c_str());
                if (relay_native_ctx || relay_ctx_journal.written())
                    std::printf("  %s | ctx-journal size=%zu written=%llu\n", relay_ctx_feeder.describe().c_str(),
                                relay_ctx_journal.size(), (unsigned long long)relay_ctx_journal.written());
                const auto& is = relay_ingest->stats();
                std::string le;
                { std::lock_guard<std::mutex> lk(mint_mtx); le = mint_last_err; }
                const std::string lr = relay_node->last_reject();
                std::printf("  relay-ingest: order=%s pushed=%llu late=%llu bins_closed=%llu pending=%zu(bins=%zu) reloaded=%llu durable=%llu | "
                            "mint ok=%llu fail=%llu below=%llu nopayee=%llu | rbind jobs=%llu owner-fee=%llu unbound=%llu | cut via relay: own-replay=%llu repaired=%llu repair-rejected=%llu | chain_view=%zu tip=%llu%s%s%s%s\n",
                            relay_ingest->options().order == relay::XmrReceiptIngest::Order::Canonical ? "canonical" : "arrival",
                            (unsigned long long)is.pushed, (unsigned long long)is.late, (unsigned long long)is.bins_closed,
                            relay_ingest->pending_receipts(), relay_ingest->pending_bins(),
                            (unsigned long long)is.reloaded, (unsigned long long)is.durable_writes,
                            (unsigned long long)mint_ok.load(), (unsigned long long)mint_fail.load(),
                            (unsigned long long)mint_below.load(), (unsigned long long)mint_nopayee.load(),
                            (unsigned long long)bind_jobs.load(), (unsigned long long)bind_owner.load(), (unsigned long long)bind_nopayee.load(),
                            (unsigned long long)relay_own_replay, (unsigned long long)relay_cut_repaired, (unsigned long long)relay_repair_rejected,
                            relay_chain.size(), (unsigned long long)relay_chain.tip(),
                            le.empty() ? "" : " | mint last_err=", le.c_str(), lr.empty() ? "" : " | last reject=", lr.c_str());
                if (relay_native_src) {   // D6b
                    const auto& fs = relay_native_feed.stats();
                    std::printf("  relay-feed: src=native tips=%llu reorg_tips=%llu headers=%llu seed_miss=%llu row_miss=%llu | "
                                "monerod compare %s rpc=%llu failed=%llu equal=%llu MISMATCH=%llu native_only=%llu monerod_only=%llu\n",
                                (unsigned long long)fs.tips, (unsigned long long)fs.reorg_tips, (unsigned long long)fs.headers,
                                (unsigned long long)fs.seed_miss, (unsigned long long)fs.row_miss,
                                g_relay_feed_monerod_compare ? "ON" : "off",
                                (unsigned long long)relay_feed_cmp_rpc, (unsigned long long)relay_feed_cmp_rpc_failed,
                                (unsigned long long)relay_feed_cmp.equal, (unsigned long long)relay_feed_cmp.mismatch,
                                (unsigned long long)relay_feed_cmp.native_only, (unsigned long long)relay_feed_cmp.monerod_only);
                }
            }
            {   // recon(A+B credit)
                auto s = node.engine().snapshot(cfg.lane_chain);
                std::printf("  ab-credit: feed pushed=%llu rejected=%llu lagq=%zu lane next_pos=%llu digest=%s… | cut ok=%llu pending=%llu miss=%llu repaired=%llu mismatch=%llu absent=%llu fold-refused=%llu | wire tx=%llu rx=%llu prefold=%llu pending=%llu hit=%llu mismatch=%llu owed-unknown=%llu | last %s\n",
                            (unsigned long long)feed_pushed, (unsigned long long)feed_rejected, feed_lagq.size(),
                            s ? (unsigned long long)s->next_pos : 0ULL, s ? hex_of(s->digest).substr(0, 12).c_str() : "-",
                            (unsigned long long)cut_ok, (unsigned long long)cut_pending, (unsigned long long)cut_miss, (unsigned long long)cut_repaired, (unsigned long long)cut_mismatch, (unsigned long long)cut_absent, (unsigned long long)cut_fold_refused,
                            (unsigned long long)wire_tx, (unsigned long long)wire_rx, (unsigned long long)wire_prefold, (unsigned long long)wire_pending, (unsigned long long)wire_hit, (unsigned long long)wire_mismatch, (unsigned long long)wire_diverged,
                            last_credit_line.c_str());
                std::printf("  cba: fetches=%llu booked=%llu not_lane=%llu refused=%llu fetch_failed=%llu stale_root=%llu root_unknown_bids=%llu ring=%zu max_root_age=%llu | recompute captured=%llu unavailable=%llu ok=%llu MISMATCH=%llu\n",
                            (unsigned long long)cba_fetches, (unsigned long long)cba_booked, (unsigned long long)cba_not_lane, (unsigned long long)cba_refused,
                            (unsigned long long)cba_fetch_failed, (unsigned long long)cba_stale_root,
                            cba_lane_root_unknown, cba_ring.size(), (unsigned long long)cba_max_root_age,
                            (unsigned long long)recompute_captured, (unsigned long long)recompute_unavailable, (unsigned long long)recompute_ok, (unsigned long long)recompute_mismatch);
                const auto& cs = cba_src.stats();
                std::printf("  cba-src: %s native_hits=%llu native_hold=%llu holding=%zu get_block_rpc=%llu rpc_failed=%llu | compare equal=%llu MISMATCH=%llu unavailable=%llu | fallback_used=%llu\n",
                            cba_src.native_mode() ? "native" : "monerod",
                            (unsigned long long)cs.native_hits, (unsigned long long)cs.native_hold, cba_src.holding_now(),
                            (unsigned long long)cs.rpc_calls, (unsigned long long)cs.rpc_failed,
                            (unsigned long long)cs.compare_equal, (unsigned long long)cs.compare_mismatch, (unsigned long long)cs.compare_unavailable,
                            (unsigned long long)cs.fallback_used);
            }
            if (!last_shape.empty())
                std::printf("  coinbase: n_tx=%zu %s (gate ok=%llu refused=%llu)\n",
                            last_selected_tx, last_shape.c_str(),
                            static_cast<unsigned long long>(shape_ok),
                            static_cast<unsigned long long>(shape_refused));
            if (!native) {
                // GOOD-CITIZEN headline for the daemon arm: what monerod offered
                // on the last poll, what the served template selected, and how
                // many times the offered set moved the epoch under an unchanged
                // tip (each one is a rebuild that would have been a coinbase-only
                // block under the legacy tip-only rule).
                if (const auto* d = provider.owned_daemon_arm())
                    std::printf("  good-citizen: %s offered=%zu selected=%zu backlog-admits=%llu\n",
                                cfg.no_good_citizen ? "off" : "on",
                                d->last_backlog_n(), last_selected_tx,
                                static_cast<unsigned long long>(d->backlog_admits()));
                return;
            }
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
                        "| verified_frontier=%llu peers=%zu silent=%zu bcast_fallbacks=%llu "
                        "request_kicks=%llu txpool_accepted=%llu "
                        "backlog offered=%zu selected=%zu\n",
                        native->arms()->describe().c_str(),
                        static_cast<unsigned long long>(native->source().resolves()),
                        static_cast<unsigned long long>(native->source().served_by_native()),
                        static_cast<unsigned long long>(native->source().served_by_daemon()),
                        static_cast<unsigned long long>(native->source().daemon_pumps()),
                        static_cast<unsigned long long>(ns.sync.verified_frontier),
                        ns.pool.peers_handshaked,
                        ns.pool.relay_silent_peers,
                        static_cast<unsigned long long>(ns.pool.broadcast_fallbacks),
                        static_cast<unsigned long long>(ns.pool.request_kicks),
                        static_cast<unsigned long long>(ns.txpool.accepted),
                        served_backlog_n, last_selected_tx);

            // GOOD-CITIZEN headline: the pool the selector was offered, what it
            // chose, and the invariant tripwire. violations MUST stay 0 (a
            // non-empty pool that produced an empty selection). "gc=on/off"
            // records whether the take-mempool-as-given path is active.
            std::printf("  good-citizen: %s pool=%zu chosen=%zu violations=%llu\n",
                        (native && !cfg.no_good_citizen) ? "on" : "off",
                        ns.citizen_pool_n, ns.citizen_chosen_n,
                        static_cast<unsigned long long>(ns.good_citizen_violations));
            // Template dup-tx hygiene: mined txs kept out of templates (the
            // connect/refresh race, caught), own blocks refused as invalid,
            // own forks abandoned by the liveness guard, relays refused as
            // already mined. The last three stay 0 on a healthy node.
            std::printf("  chain-hygiene: tmpl_dropped_mined=%llu own_invalid=%llu "
                        "own_fork_abandoned=%llu pool_already_mined=%llu\n",
                        static_cast<unsigned long long>(ns.tmpl_dropped_mined),
                        static_cast<unsigned long long>(ns.own_invalid_refused),
                        static_cast<unsigned long long>(ns.own_forks_abandoned),
                        static_cast<unsigned long long>(ns.pool_already_mined));

            // #1680 observability: the block-DoS bucket accounting for the
            // solicited fluffy missing-tx (2009) reply. dropped = frames the DoS
            // buckets dropped; fluffy_req = 2009s we sent (each mints a credit);
            // credited = 2008 replies that spent a credit instead of a block
            // token; body_refetch = whole-block GET_OBJECTS fallbacks the driver
            // fired for a stranded bodiless fluffy park. A healthy fixed node
            // keeps dropped at 0 and credited climbing with fluffy_req.
            // refunded = block pushes whose token came back because the index
            // found the block is one it HAS (connected, or a valid alt candidate;
            // D3a) -- under honest relay it climbs with every copy of every block.
            std::printf("  dos: dropped=%llu fluffy_req=%llu credited=%llu body_refetch=%llu refunded=%llu\n",
                        static_cast<unsigned long long>(ns.pool.frames_dropped_dos),
                        static_cast<unsigned long long>(ns.pool.fluffy_requests_out),
                        static_cast<unsigned long long>(ns.pool.frames_credited_fluffy),
                        static_cast<unsigned long long>(ns.driver.bodies_refetch_requests),
                        static_cast<unsigned long long>(ns.pool.block_tokens_refunded));

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

            // ── M3: THE HEADLINE, AND ITS DEFINITION ────────────────────────
            //
            // rpc_on_find_path is every monerod round trip made by anything
            // that decides WHAT WE MINE or WHERE IT GOES: the template's own
            // daemon resolves, and everything the pool's consumer transport put
            // on the socket (which is the tip poll, the seed backfill and
            // submit_block -- all three of them find-path by construction).
            //
            // What is deliberately OUTSIDE it: the C6 parity judge, which is
            // driven from this status cadence and never from a template
            // refresh or a submit. Printing them together would let a
            // parity-enabled run look like a failed claim; printing only the
            // headline would let an auditor's packet capture look like a lie.
            // So both are printed, and they sum to the wire.
            const unsigned long long find_rpc =
                static_cast<unsigned long long>(native->source().daemon_pumps()) +
                static_cast<unsigned long long>(transport.rpc_calls());
            std::printf("  arm-order=%s rpc_on_find_path=%llu "
                        "(template %llu + pool-transport %llu) | off-path parity=%llu\n",
                        to_string(cfg.arm_order), find_rpc,
                        static_cast<unsigned long long>(native->source().daemon_pumps()),
                        static_cast<unsigned long long>(transport.rpc_calls()), node_rpc);
            if (p2p_first)
                std::printf("  native tip feed: events=%llu (extend=%llu reorg=%llu orphan=%llu) "
                            "best=%llu | node.best_height=%llu\n",
                            static_cast<unsigned long long>(
                                chain_src.events_seen ? chain_src.events_seen() : 0),
                            static_cast<unsigned long long>(tip_extends),
                            static_cast<unsigned long long>(tip_reorgs),
                            static_cast<unsigned long long>(tip_orphans),
                            static_cast<unsigned long long>(tip_best),
                            static_cast<unsigned long long>(node.best_height()));
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

        // ── OPERATOR TX-INJECTION: the CLI path that exercises the gate ──────
        // --native-inject-hex loads once at startup; --native-inject-dir polls
        // the dir each loop pass and routes every *.hex through the SAME gate.
        // Both call NativeNode::submit_operator_inject with default flags
        // (PriorityRequest) and default expiry (tip + ttl), so the served
        // template offers the tx FIRST, mined even at 0 fee, up to the cap.
        if (cfg.native_inject && native && native->node()) {
            auto* inode = native->node();
            auto hex_to_bytes = [](const std::string& hs, std::vector<std::uint8_t>& out) -> bool {
                std::string s; s.reserve(hs.size());
                for (char c : hs) { if (c==' '||c=='\n'||c=='\r'||c=='\t') continue; s.push_back(c); }
                if (s.size() % 2 != 0) return false;
                auto nib = [](char c)->int {
                    if (c>='0'&&c<='9') return c-'0';
                    if (c>='a'&&c<='f') return c-'a'+10;
                    if (c>='A'&&c<='F') return c-'A'+10;
                    return -1; };
                out.clear(); out.reserve(s.size()/2);
                for (std::size_t i=0;i<s.size();i+=2){ int hi=nib(s[i]),lo=nib(s[i+1]);
                    if(hi<0||lo<0) return false; out.push_back(static_cast<std::uint8_t>((hi<<4)|lo)); }
                return true;
            };
            auto submit_one = [inode](std::vector<std::uint8_t> blob, const std::string& src) {
                auto r = inode->submit_operator_inject(std::move(blob));
                std::printf("[native-inject] %s: cause=%s ok=%d pool=%zu\n",
                            src.c_str(), r.cause.c_str(), r.ok ? 1 : 0, inode->inject_pool_size());
                std::fflush(stdout);
            };
            if (!cfg.native_inject_hex.empty()) {
                std::ifstream f(cfg.native_inject_hex);
                if (!f) {
                    std::printf("[native-inject] --native-inject-hex: cannot open %s\n",
                                cfg.native_inject_hex.c_str());
                } else {
                    std::vector<std::vector<std::uint8_t>> blobs; std::string line; bool ok = true;
                    while (std::getline(f, line)) {
                        if (line.find_first_not_of(" \t\r\n") == std::string::npos) continue;
                        std::vector<std::uint8_t> b;
                        if (!hex_to_bytes(line, b)) { ok = false; break; }
                        blobs.push_back(std::move(b));
                    }
                    if (!ok) std::printf("[native-inject] --native-inject-hex: a line is not hex; "
                                         "loaded nothing (all-or-nothing)\n");
                    else for (auto& b : blobs) submit_one(std::move(b), "hex-file");
                }
            }
            if (!cfg.native_inject_dir.empty()) {
                const std::string dir = cfg.native_inject_dir;
                auto last = std::make_shared<std::chrono::steady_clock::time_point>(
                    std::chrono::steady_clock::now() - std::chrono::seconds(1));
                hooks.inject_pump = [dir, hex_to_bytes, submit_one, last]() {
                    const auto now = std::chrono::steady_clock::now();
                    if (now - *last < std::chrono::milliseconds(250)) return;
                    *last = now;
                    std::error_code ec;
                    if (!std::filesystem::exists(dir, ec)) return;
                    std::vector<std::filesystem::path> hits;
                    for (auto& de : std::filesystem::directory_iterator(dir, ec)) {
                        if (ec) break;
                        if (de.path().extension() == ".hex") hits.push_back(de.path());
                    }
                    std::sort(hits.begin(), hits.end());
                    for (auto& p : hits) {
                        std::ifstream in(p, std::ios::binary);
                        std::string hs((std::istreambuf_iterator<char>(in)),
                                       std::istreambuf_iterator<char>());
                        in.close();
                        // Rename FIRST: a blob that crashes the decoder must not
                        // be re-fed every tick forever (harness rule).
                        std::filesystem::path done = p; done += ".done";
                        std::filesystem::rename(p, done, ec);
                        std::vector<std::uint8_t> blob;
                        if (!hex_to_bytes(hs, blob)) {
                            std::printf("[native-inject] %s: not hex\n",
                                        p.filename().string().c_str());
                            continue;
                        }
                        submit_one(std::move(blob), p.filename().string());
                    }
                };
            }
        }

        const int rc = serve_and_run(cfg, transport, node, fc, found_q, payee_key, rx, serving,
                                     "no --residual-sink-spend-hex/--residual-sink-view-hex",
                                     provider, template_source, candidate, std::move(hooks));
        if (relay_node) relay_node->stop();   // GAP-2: quiesce the relay threads before the option-B locals go
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
        // The embedded node's flags first, from the ONE function that owns
        // them (xmr_node_config.hpp). Keeping them here as a dozen more `else
        // if` arms is how --seeds and the gate 4 window came to be parsed
        // nowhere and forwarded nowhere; a single owner is what a KAT can call.
        {
            std::string ferr;
            const int used = apply_native_node_flag(cfg, argc, argv, i, ferr);
            if (used < 0) { std::printf("REFUSED: %s\n", ferr.c_str()); return 2; }
            if (used > 0) { i += used - 1; continue; }
        }
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
        // fee model (LaneParams::fee, S4): off (default, master-identical) | v1
        else if (a == "--fee-model") {
            const std::string m = next("off");
            if (m == "off" || m == "0") cfg.lane_params.fee = ::v37::FeeModelGate{};
            else if (m == "v1" || m == "1") cfg.lane_params.fee = ::v37::FeeModelGate::for_version(1);
            else { std::printf("REFUSED: --fee-model takes off|v1, got \"%s\"\n", m.c_str()); return 2; }
        }
        // fee model: node-local JOB policy under the gate (see xmr/xmr_fee_model.hpp)
        else if (a == "--give-author-pct")    g_give_author_pct = std::stod(next("0"));
        else if (a == "--node-owner-fee-pct") g_owner_fee_pct = std::stod(next("0"));
        else if (a == "--node-owner-address") g_owner_address = next("");
        else if (a == "--settle-h-min") cfg.settle_h_min = std::stoull(next("0"));
        else if (a == "--settle-output-cap") cfg.settle_output_cap =
                     static_cast<std::uint32_t>(std::stoul(next("0")));
        else if (a == "--owed-demo-amount") cfg.owed_demo_amount = std::stoull(next("0"));
        // recon(A+B credit) knobs
        else if (a == "--credit-feed")        g_credit_feed = next("");
        else if (a == "--credit-feed-lag-ms") g_credit_feed_lag_ms = std::stoull(next("0"));
        else if (a == "--wire-out")           g_wire_out = next("");
        else if (a == "--wire-in")            g_wire_in = next("");
        else if (a == "--credit-mutate")      g_credit_mutate = std::stoll(next("0"));
        else if (a == "--no-book-deferral")        g_no_book_deferral = true;
        else if (a == "--cba-monerod-compare")     g_cba_monerod_compare = true;
        else if (a == "--cba-monerod-fallback")    g_cba_monerod_fallback = true;
        else if (a == "--relay-feed-monerod-compare") g_relay_feed_monerod_compare = true;
        // GAP-2 relay knobs
        else if (a == "--relay-listen")             g_relay_listen = next("");
        else if (a == "--relay-peer")               g_relay_peers.push_back(next(""));
        else if (a == "--drops-enrol")              g_drops_enrol.push_back(next(""));
        else if (a == "--relay-max-peers")          g_relay_max_peers = static_cast<std::size_t>(std::stoull(next("8")));
        else if (a == "--relay-index-horizon")      g_relay_horizon = std::stoull(next("64"));
        else if (a == "--relay-rx-budget")          g_relay_rx_budget = next("1,20,16,256");
        else if (a == "--relay-solicited-credits")  g_relay_solicited = static_cast<std::uint32_t>(std::stoul(next("256")));
        else if (a == "--relay-backfill-positions") g_relay_backfill = std::stoull(next("2048"));
        else if (a == "--relay-reoffer-seconds")    g_relay_reoffer_s = static_cast<std::uint32_t>(std::stoul(next("60")));
        else if (a == "--relay-order")              g_relay_order = next("canonical");
        else if (a == "--relay-bin-lag")            g_relay_bin_lag = std::stoull(next("1"));
        else if (a == "--relay-bin-grace-ms")       g_relay_grace_ms = static_cast<std::uint32_t>(std::stoul(next("4000")));
        else if (a == "--relay-vault-entries")      g_relay_vault_entries = static_cast<std::size_t>(std::stoull(next("0")));
        else if (a == "--relay-vault-bytes")        g_relay_vault_bytes = static_cast<std::size_t>(std::stoull(next("0")));
        else if (a == "--relay-vault-horizon")      g_relay_vault_horizon = std::stoull(next("0"));
        else if (a == "--no-relay-serve")           g_no_relay_serve = true;
        else if (a == "--relay-test-partition-seconds") g_relay_partition_s = static_cast<std::uint32_t>(std::stoul(next("0")));
        else if (a == "--relay-bind")               g_relay_bind = next("none");
        else if (a == "--divergence-cap-heights")  g_divergence_cap_heights = std::stoull(next("0"));
        else if (a == "--divergence-cap-ticks")    g_divergence_cap_ticks = std::stoull(next("20"));
        else if (a == "--divergence-cap-terminal") g_divergence_cap_terminal = std::stoull(next("2"));
        else if (a == "--contested-suspend") { const std::string v = next("on"); g_contested_suspend = !(v == "off" || v == "0" || v == "false"); }
        else if (a == "--recon-max-root-age")      g_recon_max_root_age = std::stoull(next("0"));
        else if (a == "--xmr-template-source") {
            const std::string m = next("monerod");
            cfg.template_source = (m == "native") ? TemplateSourceMode::Native
                                                  : TemplateSourceMode::Monerod;
        }
        // Native-node flags that apply_native_node_flag() (above) does NOT own
        // are parsed here: the config-value knobs it predates. Everything it
        // DOES own -- --native-connect/-anchor/-seeds, the gate 4 window, the
        // snapshot path, etc. -- was handled at the top of the loop and never
        // reaches these arms.
        else if (a == "--native-output-set") cfg.native_output_set_path = next("");
        // The fully self-contained (peerless, daemonless) run. See
        // solo_refusal() in xmr_node_config.hpp for what it refuses and why.
        else if (a == "--native-solo") cfg.native_solo = true;
        else if (a == "--native-dos-solicited-credits") cfg.native_dos_solicited_credits =
                     static_cast<std::uint32_t>(std::stoull(next("8")));  // #1680 lever
        else if (a == "--no-good-citizen") cfg.no_good_citizen = true;
        // OPERATOR TX-INJECTION (2026-09-19 ruling).
        else if (a == "--native-inject") cfg.native_inject = true;
        else if (a == "--native-inject-dir")  cfg.native_inject_dir = next("");
        else if (a == "--native-inject-hex")  cfg.native_inject_hex = next("");
        else if (a == "--native-inject-ttl-blocks") cfg.native_inject_ttl_blocks =
                     static_cast<std::uint64_t>(std::stoull(next("720")));
        // M3 (R-ARMORDER, switchable): daemon-first stays the default.
        else if (a == "--arm-order") {
            const std::string m = next("daemon-first");
            cfg.arm_order = (m == "p2p-first" || m == "p2p" || m == "daemonless")
                                ? ArmOrderMode::P2PFirst : ArmOrderMode::DaemonFirst;
        }
        else if (a == "--no-daemon-rpc") cfg.no_daemon_rpc = true;
        else if (a == "--lane-chain") cfg.lane_chain =
                     static_cast<::v37::ChainId>(std::stoul(next("0")));
        else if (a == "--d-conf") cfg.d_conf = std::stoull(next("60"));
        // c2pool#1551: the same-height double-block tiebreak. One flag drives
        // BOTH levers -- the fork choice's D-14 build-on rule and the
        // accounting's nomination -- because two flags could disagree.
        else if (a == "--same-height-tiebreak") {
            const std::string m = next("prefer-own");
            if (!parse_tie_break(m, cfg.same_height_tiebreak)) {
                std::printf("REFUSED: --same-height-tiebreak takes prefer-own or first-seen, "
                            "not \"%s\" (refusing rather than picking a side for you)\n", m.c_str());
                return 2;
            }
        }
        else if (a == "--own-fork-bound-s") cfg.own_fork_bound_s =
                     static_cast<std::uint32_t>(std::stoul(next("240")));
        else if (a == "--same-height-renotify") cfg.same_height_renotify =
                     static_cast<std::uint32_t>(std::stoul(next("3")));
        else if (a == "--same-height-journal") cfg.same_height_journal = next("");
        else if (a == "--data-dir") cfg.settle_db_path = next("");
        else if (a == "--i-understand-mainnet") cfg.i_understand_mainnet = true;
        else if (a == "--randomx") cfg.randomx_enabled = true;
        else if (a == "--randomx-large-pages") cfg.randomx_large_pages = true;
        else if (a == "--mine") {
            cfg.mine_enabled = true;
            // The thread count is OPTIONAL and must not swallow the next flag.
            if (i + 1 < argc && argv[i + 1][0] >= '0' && argv[i + 1][0] <= '9')
                cfg.mine_threads = static_cast<unsigned>(std::stoul(next("0")));
        }
        else if (a == "--mine-threads") {
            cfg.mine_enabled = true;
            cfg.mine_threads = static_cast<unsigned>(std::stoul(next("0")));
        }
        else if (a == "--mine-fast") { cfg.mine_enabled = true; cfg.mine_fast = true; }
        else if (a == "--mine-msr") cfg.mine_msr = true;
        else if (a == "--mine-no-huge-pages") cfg.mine_large_pages = false;
        else if (a == "--mine-no-affinity") cfg.mine_pin = false;
        else if (a == "--help" || a == "-h") {
            std::printf(
                "c2pool-v37-xmr (EXPERIMENTAL prototype; stagenet default)\n"
                "  --mock-smoke                 network-free CI smoke (monerod stub), then exit\n"
                "  --network <stagenet|testnet|mainnet|regtest>   default stagenet\n"
                "  --rpc-host <h>  --rpc-port <p>  --zmq-port <p>\n"
                "  --lane-chain <id>  --d-conf <n>  --poll-ms <ms>  --status-every <s>\n"
                "  --divergence-cap-heights <n> R6 divergence cap: finalize cursor may trail the buried\n"
                "                               frontier by at most n heights while a lane block is\n"
                "                               lane-root-unknown (default 0 = 2*D_conf) ...\n"
                "  --divergence-cap-ticks <n>   ... for at most n consecutive ticks (default 20) before\n"
                "                               the lane is declared DIVERGED (loud, terminal, halted)\n"
                "  --divergence-cap-terminal <n> also DIVERGED after n exhausted root-unknown retry\n"
                "                               bounds (default 2; 0 = off)\n"
                "  --contested-suspend <on|off> default off: a CONTESTED lineage vote is a loud alarm +\n"
                "                               counters and the node keeps building; on = suspend lane\n"
                "                               template production until CONVERGED (operator opt-in)\n"
                "  --recon-max-root-age <n>     R-C rework-3 (D7): never credit a matched historical root\n"
                "                               older than n heights from the block's builder cut\n"
                "                               (default 4*D_conf; 0 = unbounded, the rework-2 behaviour)\n"
                "  --no-book-deferral           A/B escape hatch: book chain blocks as they arrive\n"
                "                               (pre-R6; a lagging receiver then FORKS owed_digest)\n"
                "  --cba-monerod-compare        p2p-first: ALSO fetch each booked block from monerod and\n"
                "                               count equal/mismatch (compare-only oracle; never decides)\n"
                "  --cba-monerod-fallback       p2p-first: a block the native index no longer holds is read\n"
                "                               from monerod instead of HELD (explicit opt-in; default HOLD)\n"
                "  --relay-feed-monerod-compare p2p-first: ALSO fetch the relay chain-view window from monerod\n"
                "                               per new tip and count equal/mismatch (compare-only oracle)\n"
                "  --same-height-tiebreak <prefer-own|first-seen>   same-height race policy\n"
                "  --own-fork-bound-s <n>   abandon an own-mined tip no peer adopts after n s (0=off, 240)\n"
                "                               (default prefer-own; drives BOTH the D-14 fork\n"
                "                               choice and the settlement nomination)\n"
                "  --same-height-renotify <n>   bounded re-announce of our own block on a\n"
                "                               contested height (default 3; 0 = off)\n"
                "  --same-height-journal <path|off>   per-height verdict journal\n"
                "                               (default: race.log next to the settle store)\n"
                "  --data-dir <path>            override the settlement store dir\n"
                " GAP-2 receipt relay (c2pool<->c2pool over TCP; OFF by default; --coinbase v37; mainnet only with rbind):\n"
                "  --relay-listen HOST:PORT     bind the receipt relay\n"
                "  --relay-peer HOST:PORT       dial a relay peer (repeatable; redial 1..60 s backoff)\n"
                "  --drops-enrol ID|ADDR        DROPS (only in a V37_ACTIVATE_CONSENSUS_V1 build): enrol this payee (64-hex identity\n"
                "                               key or XMR address) ex ante at the native TIP (repeatable); ignored when dormant\n"
                "  --relay-max-peers N  --relay-index-horizon N  --relay-rx-budget P,C,G,GC\n"
                "  --relay-solicited-credits N  --relay-backfill-positions N  --relay-reoffer-seconds S\n"
                "  --relay-order canonical|arrival  --relay-bin-lag L  --relay-bin-grace-ms MS\n"
                "  --relay-vault-entries N --relay-vault-bytes N --relay-vault-horizon N  --no-relay-serve\n"
                "  --relay-bind none|rbind      rbind = write + require the SEAM-1 payee/give-author\n"
                "                               binding (coinbase 0x02 [extra_nonce|rbind]); mainnet\n"
                "                               and --fee-model v1 relays need it\n"
                "                               (mutually exclusive with --credit-feed / --wire-in / --wire-out)\n"
                "  --no-found-sidecar           do not persist pending FOUNDs across restarts\n"
                "  --i-understand-mainnet       required to settle a mainnet block\n"
                "  --randomx                    enable heavy RandomX verify (needs XMR_BUILD_RANDOMX)\n"
                "  --randomx-large-pages        RandomX cache in huge pages\n"
                " in-process CPU miner (OPTIONAL, OFF by default; CPU only, no GPU):\n"
                "  --mine [threads]             mine the node's OWN template in-process with the\n"
                "                               vendored RandomX library. 0/absent = auto (half of\n"
                "                               hardware_concurrency). Needs --randomx and a served\n"
                "                               template; refused, loudly, without either.\n"
                "  --mine-threads <n>           same, with an explicit thread count\n"
                "  --mine-fast                  FAST mode: RANDOMX_FLAG_FULL_MEM + a ~2080 MiB\n"
                "                               dataset (default is LIGHT, a 256 MiB cache)\n"
                "  --mine-msr                   opt-in MSR tuning (\"randomx_boost\"): disable the\n"
                "                               hardware prefetcher / set the documented per-family\n"
                "                               registers, worth ~5-15%% on the parts it covers.\n"
                "                               OFF by default. Needs ROOT and the msr kernel module;\n"
                "                               without either, or on an unknown CPU family, it prints\n"
                "                               one NO-OP line and changes nothing. The registers are\n"
                "                               MACHINE-WIDE and are restored on a clean exit.\n"
                "  --mine-no-huge-pages         do not ask for RANDOMX_FLAG_LARGE_PAGES (huge pages\n"
                "                               are requested by default and fall back silently)\n"
                "  --mine-no-affinity           do not pin miner threads to CPUs\n"
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
                "                               REQUIRED for v37 mode with the fee model OFF: the XMR\n"
                "                               wallet the exact-sum residual is paid to\n"
                "  --residual-sink-subaddress   the sink keys are a subaddress (D_i, A_main)\n"
                "  --fee-model <off|v1>         the v36 fee model (LaneParams::fee; default off =\n"
                "                               master-identical). v1: ONE mandatory donation output\n"
                "                               = max(1 pico, residual) (compiled-in address, the\n"
                "                               residual sink; --residual-sink-* refused), the dust\n"
                "                               from the LARGEST payee, receipts pushed at 65535 split\n"
                "                               by their PoW-bound give-author u16. Every peer must\n"
                "                               agree (folded into the relay HELLO digest)\n"
                "  --give-author-pct <p>        (v1) give-author %% carried as a u16 in the receipts\n"
                "                               THIS node's jobs bind (default 0; folded everywhere)\n"
                "  --node-owner-fee-pct <p>     (v1) probability %% that a job commits to the node\n"
                "                               owner instead of the miner (default 0; job issue)\n"
                "  --node-owner-address <addr>  (v1) the node owner's standard address\n"
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
                "  --native-connect <ip:port>   pinned levin peer for the embedded node (repeatable;\n"
                "                               one of this or --native-seeds is REQUIRED for\n"
                "                               --xmr-template-source native)\n"
                "  --native-seeds               bootstrap from the network's own seed set instead of\n"
                "                               (or as well as) pinned peers. MAINNET: four DNS seed\n"
                "                               hosts + six compiled-in IP seeds. testnet/stagenet\n"
                "                               have no DNS seeds (monerod lists them for mainnet\n"
                "                               only) and use their five IP seeds. Also spelled\n"
                "                               --seeds, matching the xmr_native_node tool.\n"
                "  --native-p2p-bind <ip>       source address for the node's outbound dials\n"
                "  --native-anchor <path>       trust-anchor bundle (cold start above genesis)\n"
                "  --native-output-set <path>   format-2 output-set snapshot: seed the historical\n"
                "                               set so pre-anchor (below-base) rings resolve\n"
                "  --anchor-confirm-peers <n>   GATE 4: distinct peers to ask before the anchor is\n"
                "                               refused by exhaustion (default 4, minimum 1)\n"
                "  --anchor-confirm-peer-ms <ms>  GATE 4: one peer's turn (default 12000)\n"
                "  --anchor-confirm-timeout-ms <ms>\n"
                "                               GATE 4: the whole gate's wall deadline (default\n"
                "                               60000). These three WIDEN the window on a slow link.\n"
                "                               There is no flag that turns the gate off: the block\n"
                "                               the anchor pins is always fetched from live peers and\n"
                "                               re-hashed before this node serves anything.\n"
                "  --native-snapshot-path <file>\n"
                "                               persist the chain index here so a restart resumes\n"
                "                               instead of re-walking from the anchor. Read only\n"
                "                               AFTER gate 4 confirms, and bound to that anchor's\n"
                "                               identity: an absent, corrupt, foreign-network or\n"
                "                               differently-anchored file falls back to the anchor\n"
                "                               boot. Default: no persistence.\n"
                "  --native-snapshot-every <s>  periodic save cadence (default 300; 0 = only on a\n"
                "                               clean stop)\n"
                "  --native-force-synced        set the publication gate on a private chain (OR-C2-8)\n"
                "  --native-solo                FULLY SELF-CONTAINED (regtest only): no peers, no\n"
                "                               daemon, no anchor. The chain starts at the locally\n"
                "                               assembled genesis block (id-checked against the\n"
                "                               pinned one), the template is ours, and with --mine\n"
                "                               the hashing is ours too -- one process, nothing on\n"
                "                               the wire. Requires --arm-order p2p-first; implies\n"
                "                               --no-daemon-rpc and the private-chain sync gate. A\n"
                "                               found block is booked on OUR OWN index accepting it\n"
                "                               (a weaker claim than a peer receipt; counted apart).\n"
                "  --native-allow-unverified-pow  a build with no RandomX may connect blocks it did\n"
                "                               not verify (opt-in, loud, never a default)\n"
                "  --native-template-fallback <on|off>\n"
                "                               on (default): serve from monerod when the native arm\n"
                "                               is not ready. off: native-only, fail-closed.\n"
                "  --native-ready-timeout <s>   how long to wait for the native arm (default 120)\n"
                "  --native-backlog-refresh <s> rebuild the template when the POOL moves, at most\n"
                "  --backlog-refresh <s>        once per <s> seconds (default 3; 0 = legacy tip-only,\n"
                "                               which serves the empty template built at the start\n"
                "                               of each block interval and collects almost no fees).\n"
                "                               BOTH arms: native keys on its pool version, the\n"
                "                               daemon arm on the offered get_miner_data backlog.\n"
                "  --no-good-citizen            disable the good-citizen path (CONTROL / debug):\n"
                "                               native arm uses the p2pool 5-s age gate instead of\n"
                "                               mining the selected mempool set verbatim; daemon\n"
                "                               arm rebuilds on tip moves only (coinbase-only\n"
                "                               blocks while the pool fills -- the 09-21 breach)\n"
                " OPERATOR TX-INJECTION (2026-09-19 ruling; native arm only):\n"
                "  --native-inject              ARM operator tx-injection (default OFF). Injected\n"
                "                               txs are placed FIRST at highest priority in the\n"
                "                               served template (mined even at 0 fee), with first\n"
                "                               claim on the block-weight cap; the good-citizen\n"
                "                               take-all tail fills the rest, never overfilling\n"
                "                               SUPPORTED ARM for a 0-FEE inject is p2p-first: it\n"
                "                               is always mined there. Under --arm-order daemon-\n"
                "                               first a 0-fee inject is REFUSED BY NAME at submit\n"
                "                               (monerod would reject the block); see --arm-order\n"
                "  --native-inject-dir <dir>    poll <dir>/*.hex (one signed raw tx hex each) and\n"
                "                               route each through the inject gate; renames to .done\n"
                "  --native-inject-hex <file>   load one signed raw tx hex per line at startup\n"
                "                               (all-or-nothing), then inject each\n"
                "  --native-inject-ttl-blocks <n> TTL for an inject with no explicit expiry (720)\n"
                " M3 — WHICH ARM DRIVES THE FIND PATH (R-ARMORDER, switchable):\n"
                "  --arm-order <daemon-first|p2p-first>\n"
                "                               daemon-first (DEFAULT): monerod drives the tip\n"
                "                               (get_miner_data poll / ZMQ), answers the finalize\n"
                "                               driver's canonical test, and publishes a found block\n"
                "                               with submit_block. The bring-up posture.\n"
                "                               p2p-first: the embedded native node drives all three.\n"
                "                               Its levin, RandomX-verified chain IS the tip and the\n"
                "                               canonical test, and a found block goes out as a levin\n"
                "                               2008 NOTIFY_NEW_FLUFFY_BLOCK. NO monerod call is made\n"
                "                               on the find path. Requires --coinbase v37 and\n"
                "                               --xmr-template-source native, and pins the template\n"
                "                               fallback OFF (a daemonless find cannot have a daemon\n"
                "                               fallback on it and still be one).\n"
                "  --no-daemon-rpc              give the embedded node NO monerod RPC endpoint at\n"
                "                               all. With p2p-first this makes the claim a packet\n"
                "                               capture can settle in one line, at the cost of the\n"
                "                               C6 parity judge (its samples become VOID).\n"
                "                               Under p2p-first this is now the DEFAULT posture\n"
                "                               (D6d): the endpoint is withheld unless\n"
                "  --native-parity-monerod      p2p-first: ALSO hand the embedded node the monerod\n"
                "                               endpoint as the C6 parity judge (compare-only oracle:\n"
                "                               get_miner_data + get_info + get_last_block_header per\n"
                "                               status tick; never on the find path, never decides).\n");
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
