// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/main_v37_xmr.cpp
//
// c2pool-v37-xmr: the Monero/RandomX v37 daemon (Path B).
//
// Modes:
//   (default)       the pool node, run_pathb -> serve_pathb: the native Monero
//                   follower (its chain index, tx pool and the Path B follower
//                   rows), PathbNode over its store, the Path B relay node, the
//                   stratum listener, --mine, the publish arms, the status
//                   line and the web view.
//   --follow-only   the native Monero follower alone, run_follow_only ->
//                   serve_follow_only: the template record of the Monero tip
//                   for an empty window, logged; no pool identity, no store,
//                   no job, no relay, no daemon endpoint.
//
// Start: the flags (every flag recorded in given_flags; a removed flag is
// refused), apply_follow_only, the mode refusals (mode_refusal), then the
// pool's start-up checks (startup_checks), the store (pathb_load) and the node.
//
// Threading: every PathbNode call runs under the relay node's node lock
// (PathbRelayNode::with_node): the relay threads, the stratum listener thread
// (jobs, the node's own shares), the serve loop (main thread: templates,
// timers, the prune step, status) and the CPU miner pump (main thread). The
// serve loop never calls the listener while it holds the node lock. The
// follower rows are recorded on the native node's verify thread under the
// chain index mutex.
// ===========================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <ifaddrs.h>
#include <netdb.h>

#include <core/filesystem.hpp>   // core::filesystem::config_path

#include "xmr/xmr_node_config.hpp"
#include "xmr/xmr_live_transport.hpp"
#include "xmr/xmr_o2_randomx_verify.hpp"
#include "xmr/xmr_live_submit.hpp"
#include "xmr/xmr_stratum_listener.hpp"
#include "xmr/xmr_web_dashboard.hpp"
#include "xmr/xmr_native_template_backend.hpp"
#include "xmr/xmr_native_chain_source.hpp"
#include "xmr/xmr_p2p_block_publisher.hpp"
#include "xmr/xmr_lane_suspend_state.hpp"
#include "xmr/xmr_lane_resume_fresh.hpp"
#include "xmr/relay/xmr_relay_peerstore.hpp"
#include "xmr/relay/xmr_relay_bootstrap.hpp"

#include "xmr/pathb/pathb_relay_links.hpp"
#include "xmr/pathb/pathb_startup.hpp"
#include "xmr/pathb/pathb_mainnet_refusal.hpp"
#include "xmr/pathb/pathb_follow_template.hpp"
#include "xmr/pathb/pathb_stratum_hooks.hpp"
#include "xmr/pathb/pathb_policy.hpp"
#include "xmr/pathb/pathb_follower_rows.hpp"
#include "xmr/pathb/pathb_job_source.hpp"
#include "xmr/pathb/pathb_own_share.hpp"
#include "xmr/pathb/xmr_pathb_store.hpp"

#include "impl/xmr/pathb/pathb_pool_identity.hpp"
#include "impl/xmr/pathb/pathb_store.hpp"
#include "impl/xmr/pathb/pathb_branch_follower.hpp"
#include "impl/xmr/pathb/pathb_lane_rules.hpp"
#include "impl/xmr/pathb/pathb_caps.hpp"
#include "impl/xmr/pathb/pathb_bucket_wire.hpp"
#include "impl/xmr/coin/xmr_check_hash.hpp"

#if defined(V37_XMR_O2_WITH_RANDOMX)
#include "impl/xmr/pow/xmr_cpu_miner.hpp"     // --mine
#endif
#include "impl/xmr/pow/xmr_msr_boost.hpp"     // --mine-msr
#include "impl/xmr/native/anchor/xmr_anchor_pinned.hpp"   // --version

using namespace c2pool::v37n::xmr;
namespace strat  = ::v37::xmr::stratum;
namespace sub    = ::c2pool::v37n::xmr::submit;
namespace pb     = ::c2pool::xmr::pathb;
namespace pbs    = ::c2pool::xmr::pathb::stratum;
namespace pmode  = ::c2pool::v37n::xmr::pathb_mode;
namespace native = ::c2pool::xmr::native;
namespace rly    = ::c2pool::v37n::xmr::relay;
namespace node   = ::c2pool::xmr::node;
namespace xweb   = ::c2pool::v37n::xmr::web;
#if defined(V37_XMR_O2_WITH_RANDOMX)
namespace mine = ::c2pool::xmr::miner;
#endif

#if __has_include(<c2pool_build_version.h>)
#include <c2pool_build_version.h>
#endif
#ifndef C2POOL_VERSION
#define C2POOL_VERSION "v37-dev"
#endif

static std::atomic<bool> g_stop{false};
static std::atomic<bool> g_relay_partition_req{false};   // SIGUSR1 -> relay partition (--relay-test-partition-seconds)
static void on_sigusr1(int) { g_relay_partition_req.store(true); }
static void on_sigint(int) { g_stop.store(true); }

// The fees of this node's jobs: the give-author share (default 0.1 %) and the
// node-owner fee with its address.
static double g_give_author_pct = 0.1;                                   // --give-author-pct P
static pb::policy::ExactPct g_give_author_exact{1, 10, true};            // 0.1
static double g_owner_fee_pct = 0.0;                                     // --node-owner-fee-pct P
static pb::policy::ExactPct g_owner_fee_exact{0, 1, true};
static std::string g_owner_address;                                      // --node-owner-address ADDR

// Stratum listener policy (unset = the StratumListenerOptions default).
static std::optional<double>             g_stratum_share_rate;        // --stratum-share-rate R
static std::optional<std::uint32_t>      g_stratum_vardiff_shares;    // --stratum-vardiff-shares N
static std::optional<std::uint32_t>      g_stratum_submit_burst;      // --stratum-submit-burst N
static std::optional<std::uint32_t>      g_stratum_ban_seconds;       // --stratum-ban-seconds S
static std::optional<std::array<int, 4>> g_stratum_share_score;       // --stratum-share-score BAD,GOOD,BAN,CAP
static std::optional<std::uint32_t>      g_stratum_login_timeout_ms;  // --stratum-login-timeout-ms MS
static std::uint32_t g_stratum_min_diff_shift = pbs::kStratumMinDiffShiftDefault;   // --stratum-min-diff-shift S

// The Path B relay node's transport knobs.
static std::size_t   g_relay_max_inbound = 101;          // --relay-max-inbound N (--relay-max-peers)
static bool          g_relay_discovery = true;           // --relay-discovery on|off
static std::size_t   g_relay_max_outbound = 12;          // --relay-max-outbound N
static std::string   g_relay_rx_budget;                  // --relay-rx-budget P,C,G,GC
static std::optional<std::uint32_t> g_relay_rx_global;   // --relay-rx-global G
static std::optional<std::uint32_t> g_relay_ban_seconds; // --relay-ban-seconds S
static std::uint32_t g_relay_verify_threads = 0;         // --relay-verify-threads N (0 = auto)
static std::optional<std::uint32_t> g_relay_solicited;   // --relay-solicited-credits N
static std::size_t   g_relay_parked_max = 0;             // --relay-parked-max N (0 = the relay node's default)
static std::optional<std::uint32_t> g_relay_keepalive_ms;   // --relay-keepalive-ms MS
static std::optional<std::uint32_t> g_relay_silence_ms;     // --relay-silence-timeout-ms MS
static std::optional<double> g_relay_peer_valid_rate;    // --relay-peer-valid-rate R (P-15; raise only)
static std::optional<std::uint64_t> g_relay_pending_cap; // --relay-pending-cap N (P-09; raise only)
static std::optional<std::uint64_t> g_relay_send_queue;  // --relay-send-queue-bytes N (P-67; floor two FC_HEADERS frames)
static std::optional<std::uint64_t> g_relay_ctx_block_cap;  // --relay-ctx-block-cap N (P-13; raise only)
static bool          g_no_relay_bootstrap = false;       // --no-relay-bootstrap
static std::uint32_t g_relay_partition_s = 0;            // --relay-test-partition-seconds S

// The web dashboard (off unless --web-port).
static std::uint16_t g_web_port = 0;                     // --web-port P
static std::string   g_web_host = "127.0.0.1";           // --web-host IP
static std::string   g_web_dir  = "web-static";          // --dashboard-dir DIR
static xweb::XmrWebDashboard* g_web = nullptr;

// The Path B flags (S4w).
struct PathbFlags {
    std::optional<std::string> genesis_from;          // --pool-genesis-from <H>:<hash64>:"<headline>"
    std::optional<std::string> pool_genesis;          // --pool-genesis <hex64>:<H>
    std::optional<std::string> pool_genesis_height;   // --pool-genesis-height <H>
    bool vote_no = false;                             // --vote no
    std::string deployments_file;                     // --pathb-deployments FILE
    std::optional<std::uint64_t> key_cache_mb;        // --pathb-key-cache-mb N
    bool penalty_fill = false;                        // --pathb-penalty-fill
    std::optional<std::uint64_t> journal_depth;       // --journal-depth N
    bool launch = false;                              // --pathb-launch
    std::optional<std::uint64_t> body_keep;           // --pathb-body-keep N
    std::optional<std::uint64_t> header_keep;         // --pathb-header-keep N
    std::optional<std::uint64_t> side_keep;           // --pathb-side-keep N
    std::optional<std::uint64_t> abandon_timeout_s;   // --pathb-abandon-timeout S
    std::optional<std::uint64_t> waiting_cap;         // --pathb-waiting-cap N
    std::optional<std::uint64_t> bucket_serve_cap;    // --pathb-bucket-serve-cap BYTES
    std::optional<std::uint64_t> claim_alarm_rate_milli;  // --pathb-claim-alarm-rate R (P-50; raise only), milli/s
    std::optional<std::uint64_t> bucket_frame;        // --pathb-bucket-frame BYTES
    std::optional<std::uint64_t> join_min_peers;      // --join-min-peers N
    std::optional<std::uint64_t> bucket_inflight;     // --pathb-bucket-inflight N
    std::optional<std::uint64_t> bucket_rate;         // --pathb-bucket-rate BYTES
    std::optional<pb::RatchetParams> regtest_k30;     // --pathb-regtest-k30 L,GRACE,TIMEOUT (regtest rig input)
};

static MoneroNetwork parse_net(const std::string& s) {
    if (s == "mainnet")  return MoneroNetwork::Mainnet;
    if (s == "testnet")  return MoneroNetwork::Testnet;
    if (s == "regtest")  return MoneroNetwork::Regtest;
    return MoneroNetwork::Stagenet;
}

static pb::LaneNet lane_net_of(MoneroNetwork n) {
    switch (n) {
        case MoneroNetwork::Mainnet:  return pb::LaneNet::Mainnet;
        case MoneroNetwork::Testnet:  return pb::LaneNet::Testnet;
        case MoneroNetwork::Stagenet: return pb::LaneNet::Stagenet;
        case MoneroNetwork::Regtest:  return pb::LaneNet::Regtest;
    }
    return pb::LaneNet::Stagenet;
}

static bool split_hostport(const std::string& s, std::string& host, std::uint16_t& port) {
    const auto c = s.rfind(':');
    if (c == std::string::npos || c == 0 || c + 1 >= s.size()) return false;
    unsigned long v = 0;
    for (std::size_t i = c + 1; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        v = v * 10 + static_cast<unsigned long>(s[i] - '0');
        if (v > 65535) return false;
    }
    if (v == 0) return false;
    host = s.substr(0, c);
    port = static_cast<std::uint16_t>(v);
    return true;
}

static std::string hex_of(const std::uint8_t* p, std::size_t n) {
    static const char* k = "0123456789abcdef";
    std::string s;
    s.reserve(2 * n);
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(k[p[i] >> 4]);
        s.push_back(k[p[i] & 0x0f]);
    }
    return s;
}
template <std::size_t N>
static std::string hex_of(const std::array<std::uint8_t, N>& a) { return hex_of(a.data(), N); }

static std::string u128_dec(std::uint64_t lo, std::uint64_t hi) {
    unsigned __int128 v = (static_cast<unsigned __int128>(hi) << 64) | lo;
    if (v == 0) return "0";
    std::string s;
    while (v != 0) {
        s.push_back(static_cast<char>('0' + static_cast<int>(v % 10)));
        v /= 10;
    }
    std::reverse(s.begin(), s.end());
    return s;
}

// <data>: --data-dir, else the config path.
static std::filesystem::path data_root(const XmrNodeConfig& cfg) {
    if (!cfg.data_dir.empty()) return std::filesystem::path(cfg.data_dir);
    return core::filesystem::config_path();
}

// ---------------------------------------------------------------------------
// The exact network gate in front of the publish arm (listener thread, or the
// CPU miner pump). The stratum server's network-block test (top 64-bit word
// <= target) is a superset of Monero's rule; the bytes it hashed are checked
// again with O2RandomXVerifier::verify_network_block (hash x difficulty <
// 2^256, 128-bit, the memoised hash) and only an Accept reaches the publish
// arm. Fail-closed: with RandomX compiled out, disabled or not ready nothing
// is published. An accepted share goes to the node's own-share hook.
// ---------------------------------------------------------------------------
class GatedShareSink final : public strat::IShareSink {
public:
    // `inner`: the publish arm (sub::LiveSubmitShareSink, monerod submit_block,
    // under daemon-first; o2::P2pBlockPublisher, levin, under p2p-first).
    GatedShareSink(o2::O2RandomXVerifier& rx, const pb::PathbJobSource& jobs, strat::IShareSink& inner)
        : m_rx(rx), m_jobs(jobs), m_inner(inner) {}

    void on_accepted_share(const strat::AcceptedShare& s) override {
        m_inner.on_accepted_share(s);
        if (m_on_share) m_on_share(s);
    }
    void set_on_share(std::function<void(const strat::AcceptedShare&)> f) { m_on_share = std::move(f); }

    void submit_network_block(std::uint32_t template_id, std::uint32_t nonce,
                              std::uint32_t extra_nonce) override {
        m_calls.fetch_add(1, std::memory_order_relaxed);
        const std::optional<pb::IssuedJob> j = m_jobs.network_job(template_id, extra_nonce);
        if (!j || !j->net.known || j->nonce_offset + strat::NONCE_SIZE > j->hashing_blob.size()) {
            m_stale.fetch_add(1, std::memory_order_relaxed);
            set_last("template " + std::to_string(template_id) + " gone (stale)");
            return;
        }
        std::vector<std::uint8_t> blob = j->hashing_blob;
        for (std::size_t i = 0; i < strat::NONCE_SIZE; ++i)   // == the bytes the server hashed
            blob[j->nonce_offset + i] = static_cast<std::uint8_t>(nonce >> (8 * i));
        if (!m_rx.network_blocks_allowed()) {
            m_refused.fetch_add(1, std::memory_order_relaxed);
            set_last(std::string("refused: randomx ") + o2::O2RandomXVerifier::to_string(m_rx.mode()) +
                     " (fail-closed, no submit)");
            return;
        }
        o2::Hash32 pow{};
        const o2::NetworkVerdict v = m_rx.verify_network_block(
            blob.data(), blob.size(), j->net.seed, o2::NetworkDifficulty{j->net.difficulty_lo, j->net.difficulty_hi}, pow);
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
    o2::O2RandomXVerifier&     m_rx;
    const pb::PathbJobSource&  m_jobs;
    strat::IShareSink&         m_inner;
    std::function<void(const strat::AcceptedShare&)> m_on_share;
    std::atomic<std::uint64_t> m_calls{0}, m_accepted{0}, m_rejected{0}, m_refused{0}, m_stale{0};
    mutable std::mutex m_mtx;
    std::string        m_last;
};

// ---------------------------------------------------------------------------
// The follower's alt store caps in force (--alt-max-blocks, else the index's default, k_alt; the index's byte cap), set
// on the rows (the kept rows' and kept blobs' bounds) before they load; one line when the count is below k_alt.
// ---------------------------------------------------------------------------
static std::uint64_t unix_now_s();  // the wall clock in unix seconds (defined below)

// The verified class's byte cap of the alt store at the node's view (alt_max_blocks x blob_cap_ctx of a child of the
// index tip; --alt-max-bytes only lowers it), set on the index and the rows (the kept blobs' bound) when it moves.
struct AltBytes {
    std::uint64_t cap = 0;
    bool noted = false;
};
static void apply_alt_bytes(const XmrNodeConfig& cfg, pb::PathbFollowerRows& rows, native::ChainIndex& idx, AltBytes& s,
                            const char* who) {
    const auto t = idx.tip();
    const std::optional<pb::RowWeights> w = t ? rows.weights(t->id) : std::nullopt;
    const std::uint64_t derived = pb::alt_verified_bytes_cap(idx.alt_max_blocks(), w);
    const std::uint64_t cap = pb::alt_verified_bytes_cap(idx.alt_max_blocks(), w, cfg.alt_max_bytes);
    if (cap == s.cap) return;
    s.cap = cap;
    idx.set_alt_verified_max_bytes(cap);
    rows.set_alt_max_bytes(cap);
    if (cap < derived && !s.noted) {
        s.noted = true;
        std::printf("%s: --alt-max-bytes %llu lowers the verified alternative blocks' cap (derived %llu)\n", who,
                    static_cast<unsigned long long>(cfg.alt_max_bytes), static_cast<unsigned long long>(derived));
    }
}

static void apply_alt_max_blocks(const XmrNodeConfig& cfg, pb::PathbFollowerRows& rows, const char* who) {
    const std::size_t n = cfg.alt_max_blocks ? cfg.alt_max_blocks : native::ChainIndexOptions{}.alt_max_blocks;
    rows.set_alt_max_blocks(n);
    rows.set_alt_max_bytes(pb::alt_verified_bytes_cap_max(n, cfg.alt_max_bytes));  // the kept blobs at load
    if (n < pb::kAltDepth)
        std::printf("%s: --alt-max-blocks %zu below k_alt %llu: a context climb deeper than %zu alternative blocks is not "
                    "servable\n", who, n, static_cast<unsigned long long>(pb::kAltDepth), n);
}

// ---------------------------------------------------------------------------
// The embedded native Monero node. Returns null on refusal, the reason printed.
// ---------------------------------------------------------------------------
static std::unique_ptr<o2::NativeTemplateBackend> start_native_backend(const XmrNodeConfig& cfg,
                                                                        native::ChainIndex::RowSink row_sink,
                                                                        bool serve_monerod) {
    if (cfg.native_connect.empty() && !cfg.native_solo && !cfg.native_use_seeds) {
        std::printf("REFUSED: the native Monero node needs an address source -- at least one "
                    "--native-connect <ip:port> levin peer, or --native-seeds to bootstrap "
                    "from the network's own seed set (it dials only what it is told to)\n");
        return nullptr;
    }
    const bool p2p_first = (cfg.arm_order == ArmOrderMode::P2PFirst);
    o2::NativeTemplateConfig ncfg = o2::native_template_config_of(cfg);
    ncfg.parity_ledger_path = (data_root(cfg) / net_dir(cfg.network) / "xmr_parity_ledger.json").string();
    ncfg.c2pool_commit      = C2POOL_VERSION;
    ncfg.row_sink           = std::move(row_sink);
    if (serve_monerod) ncfg.serve = native::TemplateArm::Monerod;

    if (cfg.native_solo)
        std::printf("monero: NATIVE, SOLO -- no peers, no daemon, no anchor: the chain starts at the locally "
                    "assembled genesis block (id-checked against the pinned one)\n");
    else
        std::printf("monero: NATIVE -- the embedded Monero node (levin, %zu pinned peer(s)%s); %s\n",
                    cfg.native_connect.size(), cfg.native_use_seeds ? " + network seeds" : "",
                    p2p_first ? "the tip, the template source and the block relay (--arm-order p2p-first)"
                              : "the tip; monerod is the parity judge and the submit arm");
    if (p2p_first && !cfg.native_solo)
        std::printf("  parity judge (monerod): %s\n",
                    ncfg.monerod_rpc_port == 0 ? "OFF" : "ON, compare-only (--native-parity-monerod)");
    if (ncfg.boot == native::rt::BootMode::Anchor)
        std::printf("  gate 4 (anchor network confirm): up to %u peer(s), %llu ms each, %llu ms in total\n",
                    static_cast<unsigned>(ncfg.anchor_confirm.peers),
                    static_cast<unsigned long long>(ncfg.anchor_confirm.per_peer_ms),
                    static_cast<unsigned long long>(ncfg.anchor_confirm.timeout_ms));
    if (!ncfg.snapshot_path.empty())
        std::printf("  chain snapshot: %s (save every %llus, and on a clean stop)\n", ncfg.snapshot_path.c_str(),
                    static_cast<unsigned long long>(ncfg.snapshot_every_s));

    auto backend = std::make_unique<o2::NativeTemplateBackend>(std::move(ncfg));
    std::string why;
    if (!backend->start_and_wait(why, [](const std::string& w) {
            std::printf("  native: not ready yet -- %s\n", w.c_str());
            std::fflush(stdout);
        })) {
        std::printf("REFUSED: %s\n", why.c_str());
        for (const std::string& l : backend->start_log()) std::fprintf(stderr, "  node: %s\n", l.c_str());
        if (auto* n = backend->node())
            for (const std::string& l : n->take_log()) std::fprintf(stderr, "  node: %s\n", l.c_str());
        return nullptr;
    }
    if (!why.empty())
        std::printf("  native: %s -- proceeding\n", why.c_str());
    else
        std::printf("  native: template arm READY, fallback %s\n", backend->config().fallback ? "ON" : "OFF");
    if (auto* n = backend->node())
        for (const std::string& l : n->take_log()) std::printf("  node: %s\n", l.c_str());
    return backend;
}

// ---------------------------------------------------------------------------
// The master status lines kept (good-citizen, txpool, wire RPC, the find path)
// from the native node and the pool's monerod transport (absent: 0).
// ---------------------------------------------------------------------------
static pb::KeptStatusValues kept_status_values(const XmrNodeConfig& cfg, o2::NativeTemplateBackend& backend,
                                               const LiveMonerodTransport* transport) {
    pb::KeptStatusValues v;
    native::rt::NodeStatus ns{};
    if (auto* n = backend.node()) ns = n->status();
    v.good_citizen_on = !cfg.no_good_citizen;
    v.citizen_pool_n = ns.citizen_pool_n;
    v.citizen_chosen_n = ns.citizen_chosen_n;
    v.good_citizen_violations = ns.good_citizen_violations;
    v.txpool_gate_open = ns.txpool_gate_open;
    v.txpool_tip_known = ns.txpool_tip_known;
    v.txpool_warm = ns.txpool_warm;
    v.txpool_warm_why = ns.txpool_warm_why;
    v.txpool_warm_after_ms = ns.txpool_warm_after_ms;
    v.complement_requests_out = ns.pool.complement_requests_out;
    v.complement_answers_in = ns.pool.complement_answers_in;
    v.complement_rounds = ns.complement_rounds;
    v.complement_txs = ns.complement_txs;
    v.pool_count = ns.txpool.count;
    v.pool_accepted = ns.txpool.accepted;
    v.pool_duplicates = ns.txpool.duplicates;
    v.pool_rejected = ns.txpool.rejected;
    v.pool_rejected_not_synced = ns.txpool.rejected_not_synced;
    v.pool_rejected_member_locked = ns.txpool.rejected_member_locked;
    v.pool_unresolved_ring = ns.txpool.unresolved_ring;
    v.pool_rejected_key_image_spent = ns.txpool.rejected_key_image_spent;
    v.pool_rejected_already_mined = ns.txpool.rejected_already_mined;
    v.pool_tip_seated = ns.txpool.tip_seated;
    v.node_rpc = ns.rpc_calls;
    v.template_daemon_pumps = backend.source().daemon_pumps();
    v.node_rpc_failures = ns.rpc_failures;
    if (transport != nullptr) {
        v.pool_tip_poll_rpc = transport->tip_poll_calls();
        v.pool_other_rpc = transport->other_calls();
        v.pool_transport_rpc = transport->rpc_calls();
        v.pool_rpc_failures = transport->rpc_failures();
    }
    v.arm_order = to_string(cfg.arm_order);
    return v;
}

// The template's candidates from the source's ready snapshot (priority order).
static std::vector<pb::TemplateTx> candidates_of(const node::MinerData& md) {
    std::vector<pb::TemplateTx> out;
    out.reserve(md.tx_backlog.size());
    for (const node::TxBacklogEntry& e : md.tx_backlog) out.push_back(pb::TemplateTx{e.id, e.weight, e.fee});
    return out;
}

// ---------------------------------------------------------------------------
// The follow-only mode (run_plan_of: the native node, the follower rows, the
// template record routine, serve_follow_only; nothing else).
// ---------------------------------------------------------------------------
static int run_follow_only(XmrNodeConfig& cfg, const PathbFlags& pf) {
    const pmode::RunPlan plan = pmode::run_plan_of(cfg);
    const pb::LaneNet lnet = lane_net_of(cfg.network);
    const pb::Hash32 g = pb::genesis_rules_digest(lnet);
    const std::string dir = pmode::follow_only_dir(data_root(cfg).string(), cfg.network, g);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    pb::PathbFollowerRows rows(pmode::follow_only_row_weights_path(dir));
    apply_alt_max_blocks(cfg, rows, "follow-only");
    std::string why;
    if (!rows.load(why, unix_now_s())) std::printf("follow-only: %s -- starting with an empty table\n", why.c_str());
    else if (!why.empty()) std::printf("follow-only: %s\n", why.c_str());
    if (!plan.native_node) return 2;

    std::printf("%s\n", pb::follow_only_start_line(to_string(cfg.network),
                                                   cfg.native_snapshot_path.empty() ? std::string("none")
                                                                                    : cfg.native_snapshot_path)
                            .c_str());
    std::fflush(stdout);
    auto backend = start_native_backend(
            cfg,
            [&rows](const native::ConsensusState& st, const native::ChainRow& row, bool seeded) { rows.on_row(st, row, seeded); },
            false);
    if (!backend) return 2;
    native::rt::NativeNode* nn = backend->node();
    rows.bind(&nn->index());
    const pb::FollowerBranchView view(rows);
    const o2::NativeChainSource chain = o2::native_chain_source(*backend);

    // The connected blocks' transactions (the compare line), from the index's tx events.
    std::mutex txm;
    std::map<native::Hash, std::vector<native::Hash>> block_txs;
    nn->index().subscribe_txs([&](const native::BlockTxEvent& e) {
        if (e.kind != native::BlockTxEvent::Kind::Connected) return;
        std::lock_guard<std::mutex> lk(txm);
        block_txs[e.block_id] = e.tx_hashes;
        while (block_txs.size() > 64) block_txs.erase(block_txs.begin());
    });

    const auto t_start = std::chrono::steady_clock::now();
    auto now_s = [&]() {
        return static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - t_start).count());
    };
    std::uint64_t last_save_s = 0;

    pb::FollowOnlyIo io;
    io.pump = [&]() {
        std::vector<pb::FollowEvent> out;
        if (!chain.drain) return out;
        if (chain.set_booking_frontier)
            if (const auto f = rows.frontier()) chain.set_booking_frontier(*f);
        const auto tip = nn->index().tip();
        for (const node::MainchainEvent& e : chain.drain()) {
            pb::FollowEvent fe;
            fe.kind = e.kind == node::MainchainEventKind::Reorg    ? pb::FollowEventKind::Reorg
                      : e.kind == node::MainchainEventKind::Orphan ? pb::FollowEventKind::Orphan
                                                                    : pb::FollowEventKind::Extend;
            fe.height = e.block.height;
            fe.id = e.block.id;
            fe.prev = e.block.prev_id;
            fe.depth = e.kind == node::MainchainEventKind::Reorg ? e.depth : 0;
            fe.tip = tip ? tip->height : e.block.height;
            {
                std::lock_guard<std::mutex> lk(txm);
                const auto it = block_txs.find(e.block.id);
                if (it != block_txs.end()) fe.tx_ids = it->second;
            }
            out.push_back(std::move(fe));
        }
        // a reorg: a follow line per block of the new branch (its blocks from the index, their transactions)
        return pb::expand_reorgs(out, [&](const pb::Hash32& id) -> std::optional<pb::FollowEvent> {
            const auto b = nn->index().by_id(id);
            if (!b) return std::nullopt;
            pb::FollowEvent fe;
            fe.height = b->height;
            fe.id = b->id;
            fe.prev = b->prev_id;
            std::lock_guard<std::mutex> lk(txm);
            const auto it = block_txs.find(b->id);
            if (it != block_txs.end()) fe.tx_ids = it->second;
            return fe;
        });
    };
    io.backlog_version = [&]() { return backend->source().epoch().backlog_seq; };
    io.tmpl.readiness = [&]() {
        pb::FollowReadiness r;
        backend->source().resolve(nullptr);
        const native::MinerDataReadiness rd = backend->source().readiness();
        r.ok = rd.ok();
        r.pool_cold = !rd.pool_warm;
        r.why = rd.why;
        return r;
    };
    io.tmpl.main_tip = [&]() -> std::optional<pb::FollowTip> {
        const auto t = nn->index().tip();
        if (!t) return std::nullopt;
        return pb::FollowTip{t->height, t->id, t->prev_id};
    };
    io.tmpl.hf_for_child = [&](const pb::Hash32& p_r) -> std::optional<std::uint8_t> {
        const auto w = rows.weights(p_r);
        if (!w) return std::nullopt;
        return w->hf_child;
    };
    io.tmpl.weights_at = [&](const pb::Hash32& p_r) { return view.weights_at(p_r); };
    io.tmpl.candidates = [&]() {
        const auto md = backend->source().snapshot(nullptr);
        return md ? candidates_of(*md) : std::vector<pb::TemplateTx>{};
    };
    io.log_values = [&]() {
        pb::FollowLogValues v;
        const auto ns = nn->status();
        v.pool = ns.txpool.count;
        v.warm = ns.txpool_warm_why;
        v.uptime_s = now_s();
        return v;
    };
    io.status_values = [&]() { return kept_status_values(cfg, *backend, nullptr); };
    io.out = [](const std::string& line) {
        std::printf("%s\n", line.c_str());
        std::fflush(stdout);
    };
    io.web = [&](const std::vector<std::string>&) {
        if (!g_web) return;
        xweb::XmrWebState w;
        w.version = C2POOL_VERSION;
        w.network = to_string(cfg.network);
        if (const auto t = nn->index().tip()) w.chain_height = t->height;
        g_web->publish(std::move(w));
    };
    io.now_s = now_s;
    AltBytes alt_bytes;
    io.idle = [&]() {
        for (const std::string& l : nn->take_log()) std::printf("  node: %s\n", l.c_str());
        apply_alt_bytes(cfg, rows, nn->index(), alt_bytes, "follow-only");
        if (now_s() >= last_save_s + 60) {
            last_save_s = now_s();
            std::string w;
            if (!rows.save(w)) std::printf("follow-only: row weights save FAILED: %s\n", w.c_str());
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(std::min<std::uint32_t>(cfg.poll_ms, 1000)));
    };
    io.stop = []() { return g_stop.load(); };
    pb::FollowOnlyOptions fo;
    fo.penalty_fill = pf.penalty_fill;
    fo.status_every_s = cfg.status_every_s;

    std::signal(SIGINT, on_sigint);
    std::signal(SIGTERM, on_sigint);
    const pb::FollowOnlyState st = pb::serve_follow_only(io, fo);
    std::string w;
    if (!rows.save(w)) std::printf("follow-only: row weights save FAILED: %s\n", w.c_str());
    std::printf("follow-only: stopped (passes=%llu records=%llu none=%llu compares=%llu)\n",
                static_cast<unsigned long long>(st.passes), static_cast<unsigned long long>(st.records),
                static_cast<unsigned long long>(st.nones), static_cast<unsigned long long>(st.compares));
    backend->stop();
    return 0;
}

// ---------------------------------------------------------------------------
// The pool start's helpers
// ---------------------------------------------------------------------------
// The Path B relay node's options from the kept relay flags (defaults: the relay node's).
static bool relay_options_of(const XmrNodeConfig& cfg, pb::PathbRelayOptions& ro, std::string& why) {
    ro.listen = !cfg.relay_listen.empty();
    if (ro.listen && !split_hostport(cfg.relay_listen, ro.listen_host, ro.listen_port)) {
        why = "--relay-listen wants HOST:PORT, got \"" + cfg.relay_listen + "\"";
        return false;
    }
    for (const std::string& pr : cfg.relay_peers) {
        std::string h;
        std::uint16_t pt = 0;
        if (!split_hostport(pr, h, pt)) {
            why = "--relay-peer wants HOST:PORT, got \"" + pr + "\"";
            return false;
        }
        ro.peers.emplace_back(h, pt);
    }
    ro.max_inbound = g_relay_max_inbound;
    ro.max_outbound = g_relay_max_outbound;
    ro.discovery = g_relay_discovery;
    if (g_relay_solicited) ro.solicited_credits = *g_relay_solicited;
    if (g_relay_parked_max) ro.parked_max = g_relay_parked_max;
    if (g_relay_keepalive_ms) ro.keepalive_ms = *g_relay_keepalive_ms;
    if (g_relay_silence_ms) ro.silence_timeout_ms = *g_relay_silence_ms;
    if (g_relay_peer_valid_rate) ro.peer_valid_rate = *g_relay_peer_valid_rate;  // P-15 (its capacity follows P-09)
    if (g_relay_send_queue) ro.send_queue_bytes = static_cast<std::size_t>(*g_relay_send_queue);  // P-67 (start refuses below)
    // verify workers: N, or (0) clamp(cores / 2, 2, 8) of the cores the in-process miner leaves
    {
        const unsigned hc = std::max(1u, std::thread::hardware_concurrency());
        std::size_t want = g_relay_verify_threads;
        if (want == 0) {
            unsigned mined = 0;
            if (cfg.mine_enabled) mined = cfg.mine_threads ? cfg.mine_threads : std::max(1u, hc / 2);
            const unsigned left = hc > mined ? hc - mined : 1;
            want = std::clamp<std::size_t>(left / 2, left >= 2 ? 2 : 1, 8);
        }
        ro.verify_threads = std::clamp<std::size_t>(want, 1, pb::PathbRelayNode::kMaxVerifyThreads);
    }
    // the invalid-object budget: --relay-rx-budget P,C,G,GC, else --relay-rx-global G over the links and workers
    if (!g_relay_rx_budget.empty()) {
        std::array<double, 4> v{};
        std::size_t k = 0, at = 0;
        while (k < 4) {
            const std::size_t c = g_relay_rx_budget.find(',', at);
            const std::string tok = g_relay_rx_budget.substr(at, c == std::string::npos ? std::string::npos : c - at);
            double x = 0;
            const auto r = std::from_chars(tok.data(), tok.data() + tok.size(), x);
            if (tok.empty() || r.ec != std::errc{} || r.ptr != tok.data() + tok.size() || !std::isfinite(x) || x < 0) break;
            v[k++] = x;
            if (c == std::string::npos) break;
            at = c + 1;
        }
        if (k != 4) {
            why = "--relay-rx-budget wants P,C,G,GC (refill/s, cap per address; refill/s, cap global)";
            return false;
        }
        ::c2pool::xmr::DosPolicy d;
        d.per_peer_refill = v[0];
        d.per_peer_capacity = v[1];
        d.global_refill = v[2];
        d.global_capacity = v[3];
        ro.dos = d;
        if (v[2] > 0) ro.ban_seconds = static_cast<std::uint32_t>(std::ceil(v[3] / v[2]));
    } else if (g_relay_rx_global) {
        const std::uint64_t n = std::max<std::size_t>(ro.max_inbound + ro.max_outbound, 1);
        const std::uint64_t c = std::max<std::size_t>(ro.verify_threads, 1);
        const double g = static_cast<double>(*g_relay_rx_global);
        ::c2pool::xmr::DosPolicy d;
        d.per_peer_capacity = static_cast<double>(c);
        d.per_peer_refill = g / static_cast<double>(n);
        d.global_capacity = static_cast<double>(n * c);
        d.global_refill = g;
        ro.dos = d;
        ro.ban_seconds = static_cast<std::uint32_t>((n * c + *g_relay_rx_global - 1) / *g_relay_rx_global);
    }
    if (g_relay_ban_seconds) ro.ban_seconds = *g_relay_ban_seconds;
    // this machine's addresses (never dialed or handed out) and the network's bootstrap list
    std::vector<std::string> local_ips;
    ifaddrs* ifs = nullptr;
    if (::getifaddrs(&ifs) == 0) {
        for (ifaddrs* i = ifs; i != nullptr; i = i->ifa_next) {
            if (i->ifa_addr == nullptr) continue;
            const int fam = i->ifa_addr->sa_family;
            if (fam != AF_INET && fam != AF_INET6) continue;
            char buf[NI_MAXHOST];
            const socklen_t len = fam == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
            if (::getnameinfo(i->ifa_addr, len, buf, sizeof buf, nullptr, 0, NI_NUMERICHOST) == 0) local_ips.emplace_back(buf);
        }
        ::freeifaddrs(ifs);
    }
    ro.self_hosts = local_ips;
    const std::uint8_t netb = static_cast<std::uint8_t>(lane_net_of(cfg.network));
    const rly::BootstrapPick bp = rly::resolve_bootstrap(netb, g_no_relay_bootstrap, cfg.relay_peers, cfg.relay_listen, local_ips);
    rly::route_bootstrap(bp.use, ro.discovery, ro.seeds, ro.peers);
    return true;
}

// The stratum listener's options from the stratum flags.
static o2::StratumListenerOptions listener_options_of(const XmrNodeConfig& cfg) {
    o2::StratumListenerOptions lo;
    lo.bind_host = cfg.stratum_bind_host;
    lo.bind_port = cfg.stratum_bind_port;
    lo.min_diff_shift = g_stratum_min_diff_shift;
    if (g_stratum_share_rate) {
        lo.submit_rate = *g_stratum_share_rate;
    } else {
        lo.submit_rate = static_cast<double>(pbs::kStratumRefillFactor << g_stratum_min_diff_shift) /
                         static_cast<double>(kXmrTargetIntervalS);
    }
    if (g_stratum_vardiff_shares) {
        lo.submit_vardiff = !g_stratum_share_rate;
        lo.vardiff_shares_per_window = *g_stratum_vardiff_shares;
    }
    if (g_stratum_submit_burst) {
        lo.submit_burst = *g_stratum_submit_burst;
        lo.max_pending_submits = *g_stratum_submit_burst;
    }
    lo.ban_seconds = g_stratum_ban_seconds
                             ? static_cast<int>(*g_stratum_ban_seconds)
                             : static_cast<int>(std::ceil(lo.submit_burst / lo.submit_rate));
    if (g_stratum_share_score) {
        lo.bad_share_points = (*g_stratum_share_score)[0];
        lo.good_share_points = (*g_stratum_share_score)[1];
        lo.ban_score = (*g_stratum_share_score)[2];
        lo.max_score = (*g_stratum_share_score)[3];
    }
    if (g_stratum_login_timeout_ms) lo.login_timeout_ms = static_cast<int>(*g_stratum_login_timeout_ms);
    return lo;
}

// The configured deployment file: 59-byte descriptor records (C-DEP field order).
static bool read_deployments(const std::string& path, std::vector<pb::Deployment>& out, std::string& why) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        why = "--pathb-deployments: cannot open " + path;
        return false;
    }
    const std::vector<std::uint8_t> b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (b.empty() || b.size() % pb::kDescriptorBytes != 0) {
        why = "--pathb-deployments: " + path + " is not a whole number of " + std::to_string(pb::kDescriptorBytes) +
              "-byte descriptor records";
        return false;
    }
    for (std::size_t o = 0; o < b.size(); o += pb::kDescriptorBytes) {
        const std::optional<pb::Deployment> d =
                pb::decode_descriptor(std::span<const std::uint8_t>(b.data() + o, pb::kDescriptorBytes));
        if (!d) {
            why = "--pathb-deployments: record " + std::to_string(o / pb::kDescriptorBytes) + " does not decode";
            return false;
        }
        out.push_back(*d);
    }
    return true;
}

// The start line's store directories: every old-path store found (not read) and
// every other Path B store (not read, never deleted).
static void name_other_stores(const XmrNodeConfig& cfg, const std::filesystem::path& netdir, const std::string& ours) {
    std::error_code ec;
    std::vector<std::filesystem::path> old;
    old.push_back(netdir / "v37_settle_db");
    if (!cfg.data_dir.empty()) old.push_back(std::filesystem::path(cfg.data_dir));
    for (const std::filesystem::path& p : old)
        if (std::filesystem::exists(p / "settle.img", ec))
            std::printf("store: old-path store at %s: not read, flag day S4w\n", p.string().c_str());
    const std::filesystem::path db = netdir / "pathb_db";
    if (!std::filesystem::is_directory(db, ec)) return;
    for (const auto& de : std::filesystem::directory_iterator(db, ec)) {
        if (ec) break;
        if (!de.is_directory(ec) || de.path().filename().string() == ours) continue;
        std::printf("store: Path B store at %s: not read, never deleted\n", de.path().string().c_str());
    }
}

// The listener's view of the job a session receives (the login reply's ballot).
static pb::BallotChoice ballot_now(pb::PathbNode& n, const std::optional<std::uint32_t>& vote) {
    const pb::CarrierNode& b = n.tree().best();
    const pb::PathbNodeConfig& c = n.config();
    return pb::ballot_to_write(c.rp, b.rs, b.pos + 1, c.T, vote, c.vote_no);
}

static const char* template_status_name(pb::TemplateStatus s) {
    switch (s) {
        case pb::TemplateStatus::Ok: return "ok";
        case pb::TemplateStatus::NoPathbPeer: return "no Path B peer (--pathb-launch for the pool's first node)";
        case pb::TemplateStatus::Poisoned: return "store poisoned";
        case pb::TemplateStatus::RestsOnClaims: return "rests on claims (joiner path)";
        case pb::TemplateStatus::Hold: return "hold";
        case pb::TemplateStatus::ForkFuse: return "fork-fuse";
        case pb::TemplateStatus::Defer: return "defer (a Monero input, a weight input or a bucket is missing)";
        case pb::TemplateStatus::NoTemplate: return "no template fits";
    }
    return "?";
}

static std::uint64_t unix_now_s() {
    return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

// ---------------------------------------------------------------------------
// run_pathb: the pool node
// ---------------------------------------------------------------------------
static int run_pathb(XmrNodeConfig& cfg, const PathbFlags& pf) {
    const bool p2p_first = cfg.arm_order == ArmOrderMode::P2PFirst;
    const pmode::RunPlan plan = pmode::run_plan_of(cfg);
    const pb::LaneNet lnet = lane_net_of(cfg.network);
    // epoch 0: the network's lane rules and G; on regtest the rig's K30 set gives its own list and G (E-43)
    pb::PathbLaneRules rules0 = pb::epoch0_lane_rules(lnet);
    if (pf.regtest_k30) {
        const std::optional<pb::PathbLaneRules> r = pb::regtest_k30_rules(lnet, *pf.regtest_k30);
        if (!r) {
            std::printf("REFUSED: %s is regtest only\n", std::string(pb::kRegtestK30Flag).c_str());
            return 2;
        }
        rules0 = *r;
    }
    const std::optional<pb::Hash32> G0 = pb::genesis_digest_for(lnet, rules0);
    if (!G0) {
        std::printf("REFUSED: the epoch-0 lane rules are not the network's list\n");
        return 2;
    }
    const pb::Hash32 G = *G0;
    const pb::LaneParams P = pb::kRuledLaneParams;
    const pb::RatchetParams RP = pb::ratchet_params_of(rules0);

    // ---- the fees and the payees given at start (the configured sum first: start-up step 1) ----
    const std::uint32_t give_bp = pb::policy::pct_to_bp(g_give_author_exact);
    const std::uint32_t owner_bp = pb::policy::pct_to_bp(g_owner_fee_exact);
    if (const std::optional<std::string> r = pb::fee_sum_refusal(owner_bp, give_bp)) {
        std::printf("REFUSED: %s\n", r->c_str());
        return 2;
    }
    std::optional<pb::XmrKeyRef> owner_ref;
    if (owner_bp > 0) {
        if (g_owner_address.empty()) {
            std::printf("REFUSED: --node-owner-fee-pct above 0 needs --node-owner-address\n");
            return 2;
        }
        const pbs::LoginPayee op = pbs::login_payee(g_owner_address, lnet);
        if (!op.refusal.empty()) {
            std::printf("REFUSED: --node-owner-address: %s\n", op.refusal.c_str());
            return 2;
        }
        owner_ref = op.ref;
    }
    std::optional<pb::XmrKeyRef> mine_payee;
    if (cfg.mine_enabled) {
        if (cfg.payout_address.empty()) {
            std::printf("REFUSED: --mine needs --payout-address (the payee of the miner's jobs)\n");
            return 2;
        }
        const pbs::LoginPayee mp = pbs::login_payee(cfg.payout_address, lnet);
        if (!mp.refusal.empty()) {
            std::printf("REFUSED: --payout-address: %s\n", mp.refusal.c_str());
            return 2;
        }
        mine_payee = mp.ref;
    }
    std::vector<pb::Deployment> deployments;
    if (!pf.deployments_file.empty()) {
        std::string why;
        if (!read_deployments(pf.deployments_file, deployments, why)) {
            std::printf("REFUSED: %s\n", why.c_str());
            return 2;
        }
    }

    std::printf("c2pool-v37-xmr %s: Path B pool node, network=%s arm-order=%s\n", C2POOL_VERSION,
                to_string(cfg.network), to_string(cfg.arm_order));
    std::printf("stratum: login reply {\"give_author_pct\":%s,\"node_owner_fee_pct\":%s,\"vote\":...}\n",
                pbs::pct4_of_bp(give_bp).c_str(), pbs::pct4_of_bp(owner_bp).c_str());

    // ---- RandomX: the stratum's verifier and the node's (receipts, carriers, headers) ----
    o2::O2RandomXVerifier rx;
    rx.init(o2::RandomXPolicy::from_config(cfg));
    if (!rx.ready()) {
        std::printf("REFUSED: the pool node needs RandomX (a -DXMR_BUILD_RANDOMX=ON build and --randomx): "
                    "randomx is %s\n", o2::O2RandomXVerifier::to_string(rx.mode()));
        return 3;
    }
    o2::O2RandomXVerifier node_rx;
    {
        o2::RandomXPolicy np = o2::RandomXPolicy::from_config(cfg);
        np.lazy_prefetch_on_miss = true;
        node_rx.init(np);
    }
    std::printf("randomx: stratum %s; node %s\n", rx.describe().c_str(), node_rx.describe().c_str());

    // ---- the follower rows and the native Monero node ----
    const std::filesystem::path netdir = data_root(cfg) / net_dir(cfg.network);
    const std::filesystem::path follower_dir = netdir / "pathb_follower" / hex_of(G);
    std::error_code ec;
    std::filesystem::create_directories(follower_dir, ec);
    pb::PathbFollowerRows rows((follower_dir / "row_weights").string());
    apply_alt_max_blocks(cfg, rows, "follower");
    {
        std::string why;
        if (!rows.load(why, unix_now_s())) std::printf("follower: %s -- starting with an empty table\n", why.c_str());
        else std::printf("follower: row weights %s (%zu loaded, %zu kept blobs)%s%s\n", rows.path().c_str(), rows.loaded(),
                         rows.kept_blobs_loaded(), why.empty() ? "" : "; ", why.c_str());
    }
    std::unique_ptr<LiveMonerodTransport> transport;
    if (plan.monerod_transport) transport = std::make_unique<LiveMonerodTransport>(cfg.monerod);
    auto backend = start_native_backend(
            cfg,
            [&rows](const native::ConsensusState& st, const native::ChainRow& row, bool seeded) { rows.on_row(st, row, seeded); },
            !p2p_first && cfg.template_source == TemplateSourceMode::Monerod);
    if (!backend) return 2;
    native::rt::NativeNode* nn = backend->node();
    rows.bind(&nn->index());
    const pb::FollowerBranchView view(rows);
    const o2::NativeChainSource chain = o2::native_chain_source(*backend);

    // the follower's weights at its tip (hf and Z_lt of the relay buffers)
    std::optional<pb::RowWeights> tipw;
    std::optional<node::ChainMainBlock> tip;
    for (std::uint32_t waited = 0; waited <= cfg.native_ready_timeout_s * 2; ++waited) {
        tip = nn->index().tip();
        if (tip) tipw = rows.weights(tip->id);
        if (tipw || g_stop.load()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    if (!tip || !tipw) {
        std::printf("REFUSED: the follower holds no RowWeights at its tip\n");
        backend->stop();
        return 2;
    }
    const std::uint8_t hf = tipw->hf_child;
    const std::uint64_t z_lt = tipw->ltem_child;

    // ---- the start-up checks (E1) ----
    pb::StartupInputs in;
    in.net = lnet;
    in.chain_id = static_cast<std::uint32_t>(cfg.lane_chain);
    in.owner_fee_bp = owner_bp;
    in.give_author_bp = give_bp;
    in.journal_depth = pf.journal_depth ? *pf.journal_depth : pb::journal_j0(P, pb::kSealDepth);
    in.p = P;
    in.rp = RP;
    in.T.compiled.push_back(pb::CompiledEpoch{0, G, rules0});
    in.deployments = deployments;
    in.hf = hf;
    in.z_lt_view = z_lt;
    const std::optional<pb::RelayBuffers> buffers = pb::relay_buffers_default(hf, z_lt, P.r_max);
    if (!buffers) {
        std::printf("REFUSED: no relay buffers for hf %u and Z_lt %llu\n", static_cast<unsigned>(hf),
                    static_cast<unsigned long long>(z_lt));
        backend->stop();
        return 2;
    }
    in.buffers = *buffers;
    in.genesis_from = pf.genesis_from;
    in.raw = pb::RawStartInputs{pf.pool_genesis, pf.pool_genesis_height};
    in.hash_at = [nn](std::uint64_t h) -> std::optional<pb::Hash32> {
        const auto b = nn->index().by_height(h);
        if (!b) return std::nullopt;
        return b->id;
    };
    in.monero_tip = tip->height;
    const pb::StartupResult sr = pb::startup_checks(in);
    if (!sr.ok()) {
        std::printf("REFUSED: %s\n", sr.why.c_str());
        backend->stop();
        return 2;
    }
    if (sr.raw_warning) std::printf("%s\n", std::string(pb::kRawGenesisWarning).c_str());
    std::printf("%s\n", pb::identity_line(sr.identity).c_str());
    const auto p0 = nn->index().by_height(sr.identity.height);
    if (!p0) {
        std::printf("REFUSED: the Monero block at H=%llu is not on this node's chain (tip %llu)\n",
                    static_cast<unsigned long long>(sr.identity.height), static_cast<unsigned long long>(tip->height));
        backend->stop();
        return 2;
    }

    pb::PathbNodeConfig nc;
    nc.identity = sr.identity;
    nc.genesis_prev = p0->id;
    nc.rules_g = G;
    nc.T = sr.T;
    nc.p = P;
    nc.rp = RP;
    nc.journal_depth = in.journal_depth;
    nc.buffers = *buffers;
    nc.headers_frame_bytes = pb::transport_ceiling(hf, z_lt).value_or(nc.buffers.frame);
    if (const auto bw = pb::bucket_wire_policy_default(hf, z_lt)) nc.bucket_policy = *bw;
    if (pf.bucket_frame) nc.bucket_policy.frame_bytes = *pf.bucket_frame;
    if (pf.bucket_inflight) nc.bucket_policy.inflight = *pf.bucket_inflight;
    if (pf.bucket_rate) nc.bucket_policy.bytes_per_minute = *pf.bucket_rate;
    if (pf.bucket_serve_cap) nc.bucket_serve_cap = *pf.bucket_serve_cap;
    if (pf.abandon_timeout_s) nc.abandon_timeout_s = *pf.abandon_timeout_s;
    if (pf.waiting_cap) nc.waiting_cap = *pf.waiting_cap;
    nc.body_keep = pf.body_keep;
    nc.header_keep = pf.header_keep;
    nc.side_keep = pf.side_keep;
    nc.author = pb::author_ref(lnet);
    nc.give_author_bp = static_cast<std::uint16_t>(give_bp);
    nc.owner_fee_bp = static_cast<std::uint16_t>(owner_bp);
    nc.owner = owner_ref;
    nc.launch = pf.launch;
    nc.penalty_fill = pf.penalty_fill;
    nc.vote_no = pf.vote_no;
    if (pf.key_cache_mb) nc.key_cache_bytes = static_cast<std::size_t>(*pf.key_cache_mb) << 20;
    if (g_relay_pending_cap) nc.pending_cap = *g_relay_pending_cap;  // P-09 (P-15's capacity follows it)

    // ---- the store (W-E14) ----
    const std::string store_name = pb::store_dir_name(sr.identity.pool_id, G);
    const std::filesystem::path store_dir = netdir / "pathb_db" / store_name;
    name_other_stores(cfg, netdir, store_name);
    std::filesystem::create_directories(store_dir, ec);
    std::unique_ptr<pb::PathbKv> kv = pb::open_pathb_store(store_dir.string());
    if (!kv) {
        std::printf("REFUSED: the Path B store %s does not open\n", store_dir.string().c_str());
        backend->stop();
        return 2;
    }
    pb::LoadInputs li;
    li.p = P;
    li.rp = RP;
    li.T = nc.T;
    li.journal_depth = nc.journal_depth;
    li.chain = nc.record_chain;
    pb::LoadResult lr = pb::pathb_load(*kv, sr.identity.pool_id, G, li);
    if (lr.fault != pb::StoreFault::None && lr.fault != pb::StoreFault::NoHead && !pb::store_readable(*kv)) {
        // a store LevelDB cannot read: an adoption could not write into it; moved aside, an empty store in its place
        // (the load failure stands: the joiner path)
        std::string moved, mwhy;
        kv = pb::move_store_aside(std::move(kv), store_dir.string(), unix_now_s(), moved, mwhy);
        if (!kv) {
            std::printf("REFUSED: the Path B store %s is unreadable and was not moved aside: %s\n",
                        store_dir.string().c_str(), mwhy.c_str());
            backend->stop();
            return 2;
        }
        std::printf("store: %s unreadable (a LevelDB scan failed): moved aside to %s; an empty store in its place\n",
                    store_dir.string().c_str(), moved.c_str());
    }

    // ---- the node's I/O ----
    std::vector<pb::TemplateTx> cur_cands;   // the serve loop's ready snapshot (read by make_template, main thread)
    pb::PathbNodeIo io;
    io.monero = &view;
    io.resolve_pr = [&view, &rows](const pb::Hash32& p_r) {
        pb::PrInfo out;
        const std::optional<pb::BranchBlock> b = view.block(p_r);
        const std::optional<pb::RowWeights> w = rows.weights(p_r);
        if (!b || !w) return out;
        out.status = pb::PrInfo::Status::Held;
        out.height = b->height;
        std::optional<std::uint64_t> m;
        const pb::BranchStatus st = pb::timestamp_median_for_child(view, p_r, m);
        out.in = pb::HeaderInputs{w->hf_child, st.selected() ? m : std::nullopt, w->z_child, w->ltem_child};
        return out;
    };
    io.seed_of = [&view, nn](const pb::Hash32& p_r) -> std::optional<pb::Hash32> {
        const std::optional<pb::BranchBlock> b = view.block(p_r);
        if (!b) return std::nullopt;
        return nn->index().seed_hash_for_height(b->height + 1);
    };
    io.verify = [&node_rx](const pb::HashingBlob& b, std::uint64_t d, const pb::Hash32& seed) {
        std::vector<std::uint8_t> bytes;
        pb::encode_hashing_blob(b, bytes);
        o2::Hash32 out{};
        if (!node_rx.randomx_hash(bytes.data(), bytes.size(), 0, seed, out)) return false;
        unsigned char h[32];
        std::copy(out.begin(), out.end(), h);
        return ::xmr::coin::check_hash(h, d);
    };
    io.monero_tip = [nn]() -> std::optional<std::uint64_t> {
        const auto t = nn->index().tip();
        if (!t) return std::nullopt;
        return t->height;
    };
    io.monero_block_at = [nn](std::uint64_t h) -> std::optional<pb::Hash32> {
        const auto b = nn->index().by_height(h);
        if (!b) return std::nullopt;
        return b->id;
    };
    io.tx_source = [&cur_cands]() { return cur_cands; };

    // ---- the Path B relay node (one node lock for every PathbNode call) ----
    pb::PathbRelayOptions ro;
    if (g_relay_ctx_block_cap) {   // P-13 raised: the floor is blob_cap_ctx at the node's view
        const std::uint64_t floor = pb::blob_cap_ctx(hf, tipw->z_child).value_or(0);
        if (*g_relay_ctx_block_cap < floor) {
            std::printf("REFUSED: --relay-ctx-block-cap %llu is below blob_cap_ctx(%u, %llu) = %llu (raise only)\n",
                        static_cast<unsigned long long>(*g_relay_ctx_block_cap), static_cast<unsigned>(hf),
                        static_cast<unsigned long long>(tipw->z_child), static_cast<unsigned long long>(floor));
            backend->stop();
            return 2;
        }
        ro.ctx_block_cap = *g_relay_ctx_block_cap;
    }
    {
        std::string why;
        if (!relay_options_of(cfg, ro, why)) {
            std::printf("REFUSED: %s\n", why.c_str());
            backend->stop();
            return 2;
        }
    }
    if (pf.claim_alarm_rate_milli) ro.claim_alarm_rate_milli = *pf.claim_alarm_rate_milli;     // P-50
    if (pf.join_min_peers) ro.join_min_peers = static_cast<std::size_t>(*pf.join_min_peers);  // P-40
    std::string book_path;
    if (ro.discovery) {
        book_path = (netdir / rly::peerstore_file_name(static_cast<std::uint8_t>(lnet), hex_of(sr.identity.pool_id))).string();
        std::string why_load;
        if (!rly::peerstore_load(book_path, ro.book_load, &why_load))
            std::printf("relay: peer book %s unreadable (%s) -- starting empty\n", book_path.c_str(), why_load.c_str());
        ro.book_save = [book_path](const std::vector<rly::PeerRecord>& v) {
            std::string w;
            if (!rly::peerstore_save(book_path, v, &w))
                std::printf("relay: peer book save FAILED %s (%s)\n", book_path.c_str(), w.c_str());
        };
    }
    std::mutex relay_log_mtx;
    std::deque<std::string> relay_log;
    pb::CarrierLinks links;
    auto relay = std::make_unique<pb::PathbRelayNode>(ro, links, pb::RelayClock::system(), [&](const std::string& l) {
        std::lock_guard<std::mutex> lk(relay_log_mtx);
        if (relay_log.size() >= 4096) relay_log.pop_front();
        relay_log.push_back(l);
    });
    io = relay->bind_io(std::move(io));

    std::unique_ptr<pb::PathbNode> node;
    if (lr.fault == pb::StoreFault::NoHead) {
        node = std::make_unique<pb::PathbNode>(nc, io, kv.get());
        std::printf("store: %s empty: position 0 = (pool_id, H + 1 = %llu)\n", store_dir.string().c_str(),
                    static_cast<unsigned long long>(sr.identity.height + 1));
    } else if (lr.fault == pb::StoreFault::None && lr.state) {
        node = std::make_unique<pb::PathbNode>(nc, io, std::move(*lr.state), kv.get());
        std::printf("store: %s loaded: best position %llu\n", store_dir.string().c_str(),
                    static_cast<unsigned long long>(node->tree().best().pos));
    } else {
        node = std::make_unique<pb::PathbNode>(nc, io, kv.get(), pb::PathbNode::LoadFailed{});
        std::printf("store: %s load failed (fault %u at %llu, check %u): the joiner path\n", store_dir.string().c_str(),
                    static_cast<unsigned>(lr.fault), static_cast<unsigned long long>(lr.at), static_cast<unsigned>(lr.check));
    }
    relay->attach(*node);
    {
        pb::PathbCtxSource cs;
        cs.block_blob = pb::served_ctx_blob(
                [nn](const pb::Hash32& id, std::vector<std::uint8_t>& blob) { return nn->index().block_blob_of(id, blob); }, &rows);
        cs.chain.verified = [nn](const ::v37::bytes32& id) {
            node::Hash h{};
            std::memcpy(h.data(), id.data(), 32);
            return nn->index().holds_verified(h);
        };
        cs.chain.target = [nn, &rows](const ::v37::bytes32& anchor, const std::vector<rly::CtxStep>& above, std::uint64_t major,
                               rly::CtxTarget& out, std::string& why) {
            node::Hash a{};
            std::memcpy(a.data(), anchor.data(), 32);
            std::vector<std::pair<std::uint64_t, node::Difficulty128>> rws;
            rws.reserve(above.size());
            for (const auto& st : above) {
                node::Difficulty128 d{};
                d.lo = st.diff_lo;
                d.hi = st.diff_hi;
                rws.emplace_back(st.timestamp, d);
            }
            node::Difficulty128 d{};
            node::Hash seed{};
            std::uint64_t h = 0;
            const std::uint8_t mv = static_cast<std::uint8_t>(major > 255 ? 255 : major);
            if (!nn->index().context_target(a, rws, mv, d, seed, h, why)) return false;
            if (const std::optional<pb::RowWeights> w = rows.weights(anchor))   // P-13 at the newest known ancestor
                out.blob_cap = pb::blob_cap_ctx(w->hf_child, w->z_child).value_or(0);
            out.diff_lo = d.lo;
            out.diff_hi = d.hi;
            out.height = h;
            std::memcpy(out.seed.data(), seed.data(), 32);
            return true;
        };
        cs.rx = [&node_rx](const std::vector<std::uint8_t>& blob, const ::v37::bytes32& seed, ::v37::bytes32& pow) {
            o2::Hash32 s{}, out{};
            std::memcpy(s.data(), seed.data(), 32);
            if (!node_rx.randomx_hash(blob.data(), blob.size(), 0, s, out)) return false;
            std::memcpy(pow.data(), out.data(), 32);
            return true;
        };
        cs.accept = [nn](const rly::BlockCtx&, const std::vector<std::uint8_t>& blob) {
            native::BlockEntry e;
            e.block_blob = blob;
            (void)nn->index().offer_block(nullptr, std::move(e), false);
        };
        cs.view_cap = [nn, &rows]() -> std::uint64_t {   // P-13 at the node's view (a child of its index tip)
            const auto t = nn->index().tip();
            const std::optional<pb::RowWeights> w = t ? rows.weights(t->id) : std::nullopt;
            return w ? pb::blob_cap_ctx(w->hf_child, w->z_child).value_or(0) : 0;
        };
        relay->set_ctx_source(std::move(cs));
    }
    {
        std::string why;
        if (!relay->start(why)) {
            std::printf("REFUSED: %s\n", why.c_str());
            backend->stop();
            return 2;
        }
    }
    std::printf("relay: Path B relay node: listen=%s peers=%zu seeds=%zu discovery=%s verify threads=%zu\n",
                ro.listen ? cfg.relay_listen.c_str() : "off", ro.peers.size(), ro.seeds.size(),
                ro.discovery ? "on" : "off", ro.verify_threads);
    if (g_relay_partition_s) std::signal(SIGUSR1, on_sigusr1);

    // ---- stratum: the job source, the publish arm, the exact gate, the listener ----
    pb::PathbJobSource jobs([&relay](const pb::PathbTemplate& t, const pb::PathbSession& s) {
        return relay->with_node([&](pb::PathbNode& n) { return n.make_job(t, s); });
    });
    struct FoundLine {
        std::string line;
        xweb::XmrWebFound web;
    };
    std::mutex found_mtx;
    std::deque<FoundLine> found_new;
    std::deque<xweb::XmrWebFound> found_web;
    const sub::FoundHook found_hook = [&](const sub::FoundBlockEvent& e) {
        FoundLine f;
        f.web.height = e.height;
        f.web.id_hex = e.block_id_hex();
        f.web.time = unix_now_s();
        f.web.landed = sub::to_string(e.landed);
        f.web.reward_pico = e.reward;
        if (const std::optional<pb::IssuedJob> j = jobs.network_job(e.template_id, e.extra_nonce)) {
            f.web.tip_hex = hex_of(j->tip);
            f.web.window_root_hex = hex_of(j->window_root);
            f.web.n_outputs = j->n_outputs;
            f.web.reward_pico = j->reward;
        }
        f.line = "found h=" + std::to_string(f.web.height) + " id=" + f.web.id_hex + " tip=" + f.web.tip_hex +
                 " window_root=" + f.web.window_root_hex + " n_outputs=" + std::to_string(f.web.n_outputs) +
                 " R=" + std::to_string(f.web.reward_pico) + " landed=" + f.web.landed;
        std::lock_guard<std::mutex> lk(found_mtx);
        found_new.push_back(std::move(f));
    };
    const auto lookup = [&jobs](std::uint32_t tid, std::uint32_t en, sub::BlockCandidate& c) { return jobs.candidate(tid, en, c); };
    std::unique_ptr<sub::LiveBlockSubmitter> submitter;
    std::unique_ptr<sub::LiveSubmitShareSink> live_sink;
    std::unique_ptr<o2::P2pBlockPublisher> publisher;
    strat::IShareSink* arm = nullptr;
    if (p2p_first) {
        auto* br = nn->block_relay();
        if (br == nullptr) {
            std::printf("REFUSED: the native node has no levin block relay\n");
            relay->stop();
            backend->stop();
            return 2;
        }
        publisher = std::make_unique<o2::P2pBlockPublisher>(*br, lookup);
        publisher->enable_network_relay(rx.network_blocks_allowed());
        publisher->enable_solo_own_index(cfg.native_solo);
        publisher->set_found_hook(found_hook);
        publisher->set_log([&](bool err, const std::string& l) {
            std::lock_guard<std::mutex> lk(relay_log_mtx);
            relay_log.push_back(std::string(err ? "publish ERROR: " : "publish: ") + l);
        });
        arm = publisher.get();
    } else {
        submitter = std::make_unique<sub::LiveBlockSubmitter>(*transport);
        submitter->enable_network_submit(rx.network_blocks_allowed());
        live_sink = std::make_unique<sub::LiveSubmitShareSink>(*submitter, lookup);
        live_sink->set_found_hook(found_hook);
        arm = live_sink.get();
    }
    GatedShareSink sink(rx, jobs, *arm);
    std::atomic<std::uint64_t> own_shares{0}, own_placed{0}, own_pending{0}, own_other{0}, own_below_d{0}, own_stale{0};
    // the own share path: on_own_share under the node lock; a RandomX failure keeps the share (job, nonce, pow hash)
    // and the serve loop runs it again until it is placed or its job is no longer issued
    pb::OwnShareRunner own_runner(
            [&relay](const pb::OwnShare& o) {
                return relay->with_node([&](pb::PathbNode& n) { return n.on_own_share(o.job, o.nonce, o.pow_hash); });
            },
            [&jobs](const pb::OwnShare& o) { return jobs.issued(o.template_id, o.extra_nonce).has_value(); },
            [&](const std::string& l) {
                std::lock_guard<std::mutex> lk(relay_log_mtx);
                relay_log.push_back("ALARM: " + l);
            });
    const auto count_own = [&](const pb::NodeEventResult& r) {
        if (r.action == pb::NodeAction::Placed || r.action == pb::NodeAction::Switched) own_placed.fetch_add(1);
        else if (r.action == pb::NodeAction::Pending) own_pending.fetch_add(1);
        else own_other.fetch_add(1);
    };
    sink.set_on_share([&](const strat::AcceptedShare& s) {
        const std::optional<pb::IssuedJob> j = jobs.issued(s.template_id, s.extra_nonce);
        if (g_web) g_web->on_share(static_cast<double>(j ? j->d : 0), s.address, s.worker);
        if (!j) {
            own_stale.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        unsigned char h[32];
        std::copy(s.pow_hash.begin(), s.pow_hash.end(), h);
        if (!::xmr::coin::check_hash(h, j->d)) {
            own_below_d.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        own_shares.fetch_add(1, std::memory_order_relaxed);
        if (const std::optional<pb::NodeEventResult> r =
                    own_runner.submit(pb::OwnShare{s.template_id, s.extra_nonce, j->job, s.nonce, s.pow_hash}))
            count_own(*r);
    });

    o2::StratumListener listener(jobs, rx, sink, listener_options_of(cfg));
    std::uint32_t en_base = 0;
    {
        std::random_device rd;
        en_base = static_cast<std::uint32_t>(rd()) | 0x01000000u;
    }
    listener.seed_extra_nonce(en_base);
    listener.set_template_hook([&rx](const strat::TemplateJob& peek) { rx.on_template(peek); });
    listener.set_login_hook([lnet](const std::string& login, const std::string& pass) {
        const strat::LoginString ls = strat::StratumDialect::parse_login_string(login);
        const pbs::LoginHook h = pbs::login_hook(ls.address, pass, lnet);
        return o2::StratumListener::LoginDecision{h.refusal, h.stated_vote};
    });
    listener.set_login_reply_hook([&](const std::optional<std::uint32_t>& vote) {
        const pb::BallotChoice b = relay->with_node([&](pb::PathbNode& n) { return ballot_now(n, vote); });
        return pbs::login_reply_c2pool(give_bp, owner_bp, b);
    });
    listener.set_session_binder([&jobs, lnet](std::uint32_t en, const std::string& address,
                                              const std::optional<std::uint32_t>& vote) {
        const pbs::LoginPayee p = pbs::login_payee(address, lnet);
        if (!p.refusal.empty()) return;
        pb::PathbSession s;
        s.payee = p.ref;
        s.stated_vote = vote;
        jobs.bind(en, s);
    });
    if (const std::string e = listener.bind(); !e.empty()) {
        std::printf("REFUSED: %s\n", e.c_str());
        relay->stop();
        backend->stop();
        return 2;
    }
    listener.start();
    std::printf("stratum: listening on %s:%u (min-diff shift %u)\n", cfg.stratum_bind_host.c_str(),
                static_cast<unsigned>(listener.bound_port()), static_cast<unsigned>(g_stratum_min_diff_shift));

    // ---- --mine: the in-process CPU miner on its own job slot ----
    std::unique_ptr<::c2pool::xmr::msr::MsrBoost> msr_boost;
#if defined(V37_XMR_O2_WITH_RANDOMX)
    std::unique_ptr<mine::CpuMiner> cpu_miner;
    const std::uint32_t mine_en = en_base - 1;
    std::uint32_t mine_job_tid = 0;
    std::uint64_t mine_pushed = 0, mine_blocks = 0, mine_hits = 0;
    std::string mine_last_error;
    if (cfg.mine_enabled && mine_payee) {
        mine::MinerOptions mo;
        mo.threads = cfg.mine_threads;
        mo.fast_mode = cfg.mine_fast;
        mo.large_pages = cfg.mine_large_pages;
        mo.pin_threads = cfg.mine_pin;
        cpu_miner = std::make_unique<mine::CpuMiner>(mo);
        pb::PathbSession ms;
        ms.payee = *mine_payee;
        jobs.bind(mine_en, ms);
        std::printf("cpu-miner: ENABLED threads=%u mode=%s payee=%s extra_nonce=%u\n", cpu_miner->threads_wanted(),
                    cfg.mine_fast ? "FAST" : "LIGHT", cfg.payout_address.c_str(), mine_en);
        ::c2pool::xmr::msr::Options mopt;
        mopt.enabled = cfg.mine_msr;
        msr_boost = std::make_unique<::c2pool::xmr::msr::MsrBoost>(mopt);
        if (cfg.mine_msr) {
            msr_boost->apply();
            std::printf("%s\n", msr_boost->describe().c_str());
        }
    }
#else
    if (cfg.mine_enabled) std::printf("--mine: REFUSED -- this build has no RandomX (configure with -DXMR_BUILD_RANDOMX=ON)\n");
#endif
    if (cfg.mine_msr && !msr_boost)
        std::printf("--mine-msr: REFUSED -- no in-process miner is running, no register was touched\n");

    // ---- --native-inject ----
    std::function<void()> inject_pump;
    if (cfg.native_inject) {
        auto hex_to_bytes = [](const std::string& hs, std::vector<std::uint8_t>& out) -> bool {
            std::string s;
            for (char c : hs)
                if (c != ' ' && c != '\n' && c != '\r' && c != '\t') s.push_back(c);
            return sub::from_hex(s, out);
        };
        auto submit_one = [nn](std::vector<std::uint8_t> blob, const std::string& src) {
            auto r = nn->submit_operator_inject(std::move(blob));
            std::printf("[native-inject] %s: cause=%s ok=%d pool=%zu\n", src.c_str(), r.cause.c_str(), r.ok ? 1 : 0,
                        nn->inject_pool_size());
        };
        if (!cfg.native_inject_hex.empty()) {
            std::ifstream f(cfg.native_inject_hex);
            if (!f) {
                std::printf("[native-inject] --native-inject-hex: cannot open %s\n", cfg.native_inject_hex.c_str());
            } else {
                std::vector<std::vector<std::uint8_t>> blobs;
                std::string line;
                bool ok = true;
                while (std::getline(f, line)) {
                    if (line.find_first_not_of(" \t\r\n") == std::string::npos) continue;
                    std::vector<std::uint8_t> b;
                    if (!hex_to_bytes(line, b)) {
                        ok = false;
                        break;
                    }
                    blobs.push_back(std::move(b));
                }
                if (!ok) std::printf("[native-inject] --native-inject-hex: a line is not hex; loaded nothing\n");
                else for (auto& b : blobs) submit_one(std::move(b), "hex-file");
            }
        }
        if (!cfg.native_inject_dir.empty()) {
            const std::string dir = cfg.native_inject_dir;
            inject_pump = [dir, hex_to_bytes, submit_one]() {
                std::error_code e2;
                if (!std::filesystem::exists(dir, e2)) return;
                std::vector<std::filesystem::path> hits;
                for (auto& de : std::filesystem::directory_iterator(dir, e2)) {
                    if (e2) break;
                    if (de.path().extension() == ".hex") hits.push_back(de.path());
                }
                std::sort(hits.begin(), hits.end());
                for (auto& p : hits) {
                    std::ifstream fin(p, std::ios::binary);
                    std::string hs((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
                    fin.close();
                    std::filesystem::path done = p;
                    done += ".done";
                    std::filesystem::rename(p, done, e2);
                    std::vector<std::uint8_t> blob;
                    if (!hex_to_bytes(hs, blob)) {
                        std::printf("[native-inject] %s: not hex\n", p.filename().string().c_str());
                        continue;
                    }
                    submit_one(std::move(blob), p.filename().string());
                }
            };
        }
    }

    std::signal(SIGINT, on_sigint);
    std::signal(SIGTERM, on_sigint);

    // ---- serve_pathb: follower pump -> best tip and hold() -> the template -> job withdrawal -> status / web ----
    const std::uint32_t poll_ms = std::max<std::uint32_t>(cfg.poll_ms, 50);
    const std::uint64_t refresh_every_s = std::max<std::uint64_t>(cfg.native_backlog_refresh_s, 1);
    const std::uint64_t prune_every_s = 60;
    const std::uint64_t save_every_s = 60;
    LaneSuspendState lane_state;
    bool have_state = false;
    pb::Hash32 last_best{};
    std::uint64_t last_pending_digest = 0;
    native::MinerDataEpoch last_epoch{};
    std::uint64_t last_refresh_s = 0, last_prune_s = 0, last_save_s = 0, last_status_s = 0, last_web_s = 0;
    pb::TemplateStatus tstatus = pb::TemplateStatus::NoTemplate, last_tstatus = pb::TemplateStatus::Ok;
    std::string tstatus_why, last_tstatus_why;
    bool template_kept = false, fork_fuse = false;
    std::uint64_t templates = 0, tip_extends = 0, tip_reorgs = 0, tip_orphans = 0, prunes = 0;
    pb::PathbNode::PruneReport last_prune{};
    std::uint64_t last_rows_recorded = rows.recorded();
    const auto mono_s = []() { return pb::RelayClock::system().mono_ms() / 1000; };
    const std::uint64_t t0 = mono_s();

    struct NodeView {
        pb::Hash32 best{};
        std::uint64_t pos = 0;
        std::string cum_work;
        pb::PathbNode::HoldState hold{};
        bool poisoned = false;
        bool rests_on_claims = false;
        std::size_t pending = 0;
        std::size_t deferred = 0;
        std::uint64_t pending_digest = 0;
        std::vector<std::string> pending_ids;  // the first 64, 12 hex digits each (the relay log's form)
        std::uint64_t leaf_count = 0;
        std::uint64_t coinbase_internal = 0;
        pb::PathbNode::SwitchCounts sw{};
        std::uint64_t own_carriers = 0, own_orphaned = 0;
        pb::PathbNode::OpenState open{};
    };
    const auto node_view = [&]() {
        return relay->with_node([&](pb::PathbNode& n) {
            NodeView v;
            const pb::CarrierNode& b = n.tree().best();
            v.best = b.id;
            v.pos = b.pos;
            v.cum_work = u128_dec(b.cum_work.lo, b.cum_work.hi);
            v.hold = n.hold_state();
            v.poisoned = n.poisoned();
            v.rests_on_claims = n.rests_on_claims();
            v.pending = n.pending().size();
            v.deferred = n.deferred().size();
            for (const pb::PendingReceipt* r : n.pending().all()) {
                std::uint64_t x = 0;
                for (std::size_t i = 0; i < 8; ++i) x |= std::uint64_t{r->id[i]} << (8 * i);
                v.pending_digest ^= x;
                if (v.pending_ids.size() < 64) v.pending_ids.push_back(hex_of(r->id).substr(0, 12));
            }
            const pb::LaneView lv = n.store().view_at(b.id);
            v.leaf_count = lv.ok() ? lv.leaf_count() : 0;
            v.coinbase_internal = n.alarms().count_of(pb::RowId::R12, pb::Missing::NodeInternal);
            v.sw = n.switch_counts();
            v.own_carriers = n.own_carriers();
            v.own_orphaned = n.own_orphaned();
            v.open = n.open_state();
            return v;
        });
    };

    AltBytes alt_bytes;
    while (!g_stop.load()) {
        const std::uint64_t now = mono_s();
        apply_alt_bytes(cfg, rows, nn->index(), alt_bytes, "follower");

        // 1. the follower pump (the consumer frontier: the last row whose RowWeights record is written)
        if (chain.set_booking_frontier)
            if (const auto f = rows.frontier()) chain.set_booking_frontier(*f);
        bool tip_moved = false;
        if (chain.drain) {
            for (const node::MainchainEvent& e : chain.drain()) {
                tip_moved = true;
                if (e.kind == node::MainchainEventKind::Reorg) ++tip_reorgs;
                else if (e.kind == node::MainchainEventKind::Orphan) ++tip_orphans;
                else ++tip_extends;
            }
        }
        // a Monero tip change or a new RowWeights record: the frames parked on a Monero input run again (the relay
        // node's on_monero_tip, called here outside the node lock)
        if (tip_moved || rows.recorded() != last_rows_recorded) {
            last_rows_recorded = rows.recorded();
            relay->on_monero_tip();
        }
        for (const pb::NodeEventResult& r : own_runner.run_kept()) count_own(r);  // the kept own shares
        if (inject_pump) inject_pump();
        if (publisher) publisher->tick();
        if (g_relay_partition_req.exchange(false) && g_relay_partition_s) {
            relay->partition_for(std::chrono::seconds(g_relay_partition_s));
            std::printf("relay: PARTITION for %u s (SIGUSR1)\n", g_relay_partition_s);
        }
        if (now >= last_prune_s + prune_every_s) {
            last_prune_s = now;
            last_prune = relay->with_node([&](pb::PathbNode& n) { return n.prune(now); });
            if (last_prune.written) ++prunes;
        }

        // 2. the best tip and hold()
        const NodeView nv = node_view();
        const bool best_moved = !have_state || nv.best != last_best;

        // 3. the template (E2), at a new best tip, a Monero tip, the source's epoch or the pending set
        std::string why;
        const bool resolved = backend->source().resolve(&why);
        const native::MinerDataEpoch ep = backend->source().epoch();
        const bool epoch_moved = !(ep == last_epoch);
        const bool pending_moved = nv.pending_digest != last_pending_digest;
        const bool due = best_moved || tip_moved || (epoch_moved && ep.prev_id != last_epoch.prev_id) ||
                         ((epoch_moved || pending_moved || !jobs.has_template()) && now >= last_refresh_s + refresh_every_s) ||
                         !have_state;
        if (due) {
            last_refresh_s = now;
            last_epoch = ep;
            last_pending_digest = nv.pending_digest;
            std::optional<node::MinerData> md;
            if (resolved) md = backend->source().snapshot(&why);
            if (!md) {
                const native::MinerDataReadiness rd = backend->source().readiness();
                tstatus = pb::TemplateStatus::Defer;
                tstatus_why = rd.pool_warm ? ("source not ready: " + (why.empty() ? rd.why : why)) : "pool cold";
                jobs.clear();
            } else {
                cur_cands = candidates_of(*md);
                const pb::PathbTemplate t = relay->with_node([&](pb::PathbNode& n) { return n.make_template(unix_now_s()); });
                tstatus = t.status;
                tstatus_why.clear();
                fork_fuse = t.status == pb::TemplateStatus::ForkFuse;
                if (t.status == pb::TemplateStatus::Ok) {
                    pb::JobNetwork net;
                    if (md->prev_id == t.p_r && md->height == t.h) {
                        net.known = true;
                        net.difficulty_lo = md->difficulty.lo;
                        net.difficulty_hi = md->difficulty.hi;
                        net.seed = md->seed_hash;
                        net.next_seed = md->next_seed_hash;
                    } else if (const auto sd = nn->index().seed_hash_for_height(t.h)) {
                        net.seed = *sd;
                    }
                    const std::uint32_t tid = jobs.set_template(t, net);
                    template_kept = false;
                    ++templates;
                    if (const auto b = pbs::stratum_budget_of(t.d, g_stratum_min_diff_shift))
                        listener.set_stratum_budget(b->min_diff, b->refill_per_t);
                    listener.notify_new_template();
                    std::printf("template %u: tip=%s x=%llu h=%llu hf=%u d=%llu R=%llu n_tx=%zu cb=%llu P_r=%s%s\n", tid,
                                hex_of(t.tip).substr(0, 16).c_str(), static_cast<unsigned long long>(t.x),
                                static_cast<unsigned long long>(t.h), static_cast<unsigned>(t.hf),
                                static_cast<unsigned long long>(t.d), static_cast<unsigned long long>(t.reward),
                                t.txs.size(), static_cast<unsigned long long>(t.coinbase), hex_of(t.p_r).substr(0, 16).c_str(),
                                net.known ? "" : " (no network block: P_r is not the source's parent)");
                } else if (t.status == pb::TemplateStatus::NoTemplate) {
                    template_kept = jobs.has_template();   // the previous template stays (E2 step 8)
                } else {
                    jobs.clear();
                }
            }
        }

        if (tstatus != last_tstatus || tstatus_why != last_tstatus_why) {
            if (tstatus != pb::TemplateStatus::Ok)
                std::printf("template: none -- %s%s%s\n", template_status_name(tstatus), tstatus_why.empty() ? "" : ": ",
                            tstatus_why.c_str());
            last_tstatus = tstatus;
            last_tstatus_why = tstatus_why;
        }

        // 4. job withdrawal: HOLD and FORK-FUSE close the stratum gate (logins park)
        const LaneSuspendState::Edge edge = lane_state.update(nv.hold.hold, fork_fuse);
        if (edge.suspend_edge || edge.resume_edge)
            std::printf("lane %s: causes=%s (epoch %u, H_hold %llu)\n", edge.suspend_edge ? "SUSPEND" : "RESUME",
                        LaneSuspendState::names(edge.causes).c_str(), static_cast<unsigned>(nv.hold.epoch_cur),
                        static_cast<unsigned long long>(nv.hold.h_hold));
        if (nv.hold.hold && edge.suspend_edge)
            std::printf("HOLD: epoch %u, x=%llu, H_act %llu: rules-behind -> upgrade\n", static_cast<unsigned>(nv.hold.epoch_cur),
                        static_cast<unsigned long long>(nv.hold.x), static_cast<unsigned long long>(nv.hold.h_hold));
        const bool gate_closed = apply_lane_gate(listener, lane_state.suspended(), [&]() {
            const std::optional<pb::PathbTemplate> cur = jobs.current();
            return cur && cur->tip == nv.best;
        });
        last_best = nv.best;
        have_state = true;

        // 5. --mine (W-E5b): the miner's job is PathbNode::make_job for its own session
#if defined(V37_XMR_O2_WITH_RANDOMX)
        if (cpu_miner) {
            if (gate_closed) {
                mine::MinerHit dropped;
                while (cpu_miner->pop_hit(dropped)) {}
            } else {
                strat::TemplateJob tj;
                if (jobs.get_job(mine_en, tj) && !tj.blob.empty() && tj.template_id != mine_job_tid) {
                    rx.on_template(tj);
                    mine::MinerJob mj;
                    mj.blob = tj.blob;
                    mj.nonce_offset = tj.nonce_offset;
                    mj.template_id = tj.template_id;
                    mj.extra_nonce = mine_en;
                    mj.height = tj.height;
                    mj.network_target = tj.mainchain_target;
                    mj.lane_target = tj.lane_target;
                    std::copy(tj.seed_hash.begin(), tj.seed_hash.end(), mj.seed_hash.begin());
                    std::string mwhy;
                    if (cpu_miner->set_job(mj, &mwhy)) {
                        mine_job_tid = tj.template_id;
                        ++mine_pushed;
                    } else if (mwhy != mine_last_error) {
                        mine_last_error = mwhy;
                        std::printf("  [cpu-miner] job refused: %s\n", mwhy.c_str());
                    }
                }
                mine::MinerHit h;
                while (cpu_miner->pop_hit(h)) {
                    if (h.network) {
                        ++mine_blocks;
                        sink.submit_network_block(h.template_id, h.nonce, h.extra_nonce);
                    }
                    if (h.share || h.network) {
                        ++mine_hits;
                        strat::AcceptedShare acc;
                        acc.template_id = h.template_id;
                        acc.extra_nonce = h.extra_nonce;
                        acc.nonce = h.nonce;
                        acc.pow_hash = h.pow_hash;
                        acc.achieved_target = h.achieved_target;
                        acc.height = h.height;
                        acc.is_network_block = h.network;
                        acc.worker = "cpu-miner";
                        acc.address = cfg.payout_address;
                        sink.on_accepted_share(acc);
                    }
                }
            }
        }
#endif

        // 6. the logs, the found lines, the status line and the web view
        for (const std::string& l : listener.drain_log()) std::printf("  [stratum] %s\n", l.c_str());
        for (const std::string& l : nn->take_log()) std::printf("  node: %s\n", l.c_str());
        {
            std::deque<std::string> lines;
            {
                std::lock_guard<std::mutex> lk(relay_log_mtx);
                lines.swap(relay_log);
            }
            for (const std::string& l : lines) std::printf("  %s\n", l.c_str());
        }
        {
            std::deque<FoundLine> fl;
            {
                std::lock_guard<std::mutex> lk(found_mtx);
                fl.swap(found_new);
            }
            for (FoundLine& f : fl) {
                std::printf("%s\n", f.line.c_str());
                found_web.push_front(std::move(f.web));
                while (found_web.size() > 64) found_web.pop_back();
            }
        }
        if (now >= last_save_s + save_every_s) {
            last_save_s = now;
            std::string w;
            if (!rows.save(w)) std::printf("follower: row weights save FAILED: %s\n", w.c_str());
        }
        const std::optional<pb::PathbTemplate> cur = jobs.current();
        if (cfg.status_every_s != 0 && now >= last_status_s + cfg.status_every_s) {
            last_status_s = now;
            const auto tipm = nn->index().tip();
            std::printf("status: up=%llus monero=%llu best pos=%llu id=%s cum_work=%s epoch=%u H_hold=%llu "
                        "window_root=%s mmr_root=%s leaves=%llu pending=%zu deferred=%zu re-pended(last switch)=%llu "
                        "lost(last switch)=%llu switches=%llu re-pended=%llu carried=%llu sealed-pending=%llu lost=%llu "
                        "joiner-switches=%llu joiner-lost=%llu own-carriers=%llu own-orphaned=%llu template=%s%s%s "
                        "templates=%llu\n",
                        static_cast<unsigned long long>(now - t0),
                        static_cast<unsigned long long>(tipm ? tipm->height : 0), static_cast<unsigned long long>(nv.pos),
                        hex_of(nv.best).substr(0, 16).c_str(), nv.cum_work.c_str(), static_cast<unsigned>(nv.hold.epoch_cur),
                        static_cast<unsigned long long>(nv.hold.h_hold),
                        cur ? hex_of(cur->window.window_root).substr(0, 16).c_str() : "-",
                        cur ? hex_of(cur->window.mmr_root).substr(0, 16).c_str() : "-",
                        static_cast<unsigned long long>(nv.leaf_count), nv.pending, nv.deferred,
                        static_cast<unsigned long long>(nv.sw.last_repended), static_cast<unsigned long long>(nv.sw.last_lost),
                        static_cast<unsigned long long>(nv.sw.switches), static_cast<unsigned long long>(nv.sw.repended),
                        static_cast<unsigned long long>(nv.sw.carried), static_cast<unsigned long long>(nv.sw.sealed_pending),
                        static_cast<unsigned long long>(nv.sw.lost), static_cast<unsigned long long>(nv.sw.joiner_switches),
                        static_cast<unsigned long long>(nv.sw.joiner_lost), static_cast<unsigned long long>(nv.own_carriers),
                        static_cast<unsigned long long>(nv.own_orphaned), template_status_name(tstatus),
                        tstatus_why.empty() ? "" : " ", tstatus_why.c_str(), static_cast<unsigned long long>(templates));
            if (nv.poisoned || fork_fuse || template_kept || nv.coinbase_internal != 0 || nv.hold.hold)
                std::printf("  ALARM:%s%s%s%s%s\n", nv.poisoned ? " store-poisoned(no template; the joiner path at the next start)" : "",
                            fork_fuse ? " fork-fuse" : "", template_kept ? " template-kept" : "",
                            nv.coinbase_internal ? (" coinbase-internal=" + std::to_string(nv.coinbase_internal)).c_str() : "",
                            nv.hold.hold ? " hold" : "");
            std::printf("  open-state: placements=%llu bytes=%llu\n", static_cast<unsigned long long>(nv.open.placements),
                        static_cast<unsigned long long>(nv.open.bytes));
            if (cur && cur->window.window) {
                const std::vector<pb::SplitOutput> so = pb::split(cur->reward, *cur->window.window);
                std::printf("  window: payees=%zu R=%llu\n", so.size(), static_cast<unsigned long long>(cur->reward));
            }
            const o2::StratumListenerStats ls = listener.stats();
            std::printf("  stratum: conns=%llu active=%llu logins=%llu parked=%llu shares=%llu rejected=%llu "
                        "own receipts=%llu (carrier %llu, pending %llu, other %llu, below d %llu, stale %llu) jobs=%llu "
                        "min-diff=%llu gate=%s\n",
                        static_cast<unsigned long long>(ls.connections), static_cast<unsigned long long>(ls.active),
                        static_cast<unsigned long long>(ls.logins), static_cast<unsigned long long>(ls.parked_logins),
                        static_cast<unsigned long long>(ls.accepted_shares), static_cast<unsigned long long>(ls.rejected_submits),
                        static_cast<unsigned long long>(own_shares.load()), static_cast<unsigned long long>(own_placed.load()),
                        static_cast<unsigned long long>(own_pending.load()), static_cast<unsigned long long>(own_other.load()),
                        static_cast<unsigned long long>(own_below_d.load()), static_cast<unsigned long long>(own_stale.load()),
                        static_cast<unsigned long long>(jobs.issued_count()),
                        static_cast<unsigned long long>(listener.min_difficulty_effective()), gate_closed ? "closed" : "open");
#if defined(V37_XMR_O2_WITH_RANDOMX)
            if (cpu_miner)
                std::printf("  %s jobs=%llu hits=%llu blocks=%llu\n", cpu_miner->describe().c_str(),
                            static_cast<unsigned long long>(mine_pushed), static_cast<unsigned long long>(mine_hits),
                            static_cast<unsigned long long>(mine_blocks));
#endif
            std::printf("  %s\n", rx.describe().c_str());
            std::printf("  gate: calls=%llu accept=%llu reject=%llu refused=%llu stale=%llu last=%s\n",
                        static_cast<unsigned long long>(sink.calls()), static_cast<unsigned long long>(sink.accepted()),
                        static_cast<unsigned long long>(sink.rejected()), static_cast<unsigned long long>(sink.refused()),
                        static_cast<unsigned long long>(sink.stale()), sink.last().c_str());
            if (publisher)
                std::printf("  publish: relayed=%llu solo_landed=%llu failed=%llu refused=%llu parked=%zu (%s)\n",
                            static_cast<unsigned long long>(publisher->relayed()),
                            static_cast<unsigned long long>(publisher->solo_landed()),
                            static_cast<unsigned long long>(publisher->failed()),
                            static_cast<unsigned long long>(publisher->refused()), publisher->parked(),
                            publisher->solo_own_index_enabled() ? "SOLO own-index on" : "own-index off");
            if (live_sink)
                std::printf("  submit: found=%llu unnamed=%llu ok=%llu rejected=%llu refused=%llu last_error=%s\n",
                            static_cast<unsigned long long>(live_sink->found()),
                            static_cast<unsigned long long>(live_sink->unnamed()),
                            static_cast<unsigned long long>(submitter->ok()),
                            static_cast<unsigned long long>(submitter->rejected()),
                            static_cast<unsigned long long>(submitter->refused()), live_sink->last_error().c_str());
            std::printf("  %s\n", relay->describe().c_str());
            {
                const pb::PathbRelayStats& rs = relay->stats();
                const pb::OwnShareRunner::Stats os = own_runner.stats();
                const auto alt_now = nn->index().alt_class_bytes();
                const auto alt_peak = nn->index().alt_class_bytes_peak();
                std::printf("  soak: p15_drops=%llu reoffer_paused=%llu queued_bytes_hwm=%zu queue_full_drops=%llu "
                            "reoffer_queue_full_drops=%llu live_queue_full_drops=%llu "
                            "rx_failures=%llu own_rx_failures=%llu own_kept=%zu own_stale=%llu stale_events=%llu owner_waits=%llu "
                            "owner_queue_hwm=%llu reoffer_done=%llu reoffer_last_ms=%llu reoffer_max_ms=%llu "
                            "claim_alarms=%llu claim_alarm_drops=%llu join_waits=%llu ctx_wants=%zu ctx_want_bytes=%zu ctx_want_bytes_peak=%zu "
                            "ctx_wanted=%llu "
                            "ctx_resolved=%llu ctx_gave_up=%llu parked_reruns=%llu repend_offers=%llu repend_offered=%llu "
                            "reoffer_cap_drops=%llu parked_receipts=%zu parked_receipts_sealed=%llu alt_blocks_max=%zu "
                            "alt_verified_bytes=%llu alt_verified_bytes_peak=%llu alt_verified_bytes_max=%llu "
                            "alt_unproven_bytes=%llu alt_unproven_bytes_peak=%llu alt_unsolicited_drops=%llu "
                            "alt_source_drops=%llu join_side_attempts=%llu join_side_completed=%llu "
                            "join_side_not_served=%llu\n",
                            static_cast<unsigned long long>(rs.p15_drops.load()),
                            static_cast<unsigned long long>(rs.reoffer_paused.load()), links.net().queued_bytes_hwm(),
                            static_cast<unsigned long long>(links.net().peers_dropped_queue_full()),
                            static_cast<unsigned long long>(rs.reoffer_queue_full.load()),
                            static_cast<unsigned long long>(rs.live_queue_full.load()),
                            static_cast<unsigned long long>(rs.rx_failures.load()),
                            static_cast<unsigned long long>(os.rx_failures), own_runner.kept(),
                            static_cast<unsigned long long>(os.stale),
                            static_cast<unsigned long long>(rs.stale_events.load()),
                            static_cast<unsigned long long>(rs.owner_waits.load()),
                            static_cast<unsigned long long>(rs.owner_queue_hwm.load()),
                            static_cast<unsigned long long>(rs.reoffer_done.load()),
                            static_cast<unsigned long long>(rs.reoffer_last_ms.load()),
                            static_cast<unsigned long long>(rs.reoffer_max_ms.load()),
                            static_cast<unsigned long long>(rs.claim_alarms.load()),
                            static_cast<unsigned long long>(rs.claim_alarm_drops.load()),
                            static_cast<unsigned long long>(rs.join_waits.load()), relay->ctx_wants(),
                            relay->ctx_want_bytes(), relay->ctx_want_bytes_peak(),
                            static_cast<unsigned long long>(rs.ctx_wanted.load()),
                            static_cast<unsigned long long>(rs.ctx_resolved.load()),
                            static_cast<unsigned long long>(rs.ctx_gave_up.load()),
                            static_cast<unsigned long long>(rs.parked_reruns.load()),
                            static_cast<unsigned long long>(rs.repend_offers.load()),
                            static_cast<unsigned long long>(rs.repend_offered.load()),
                            static_cast<unsigned long long>(rs.reoffer_cap_drops.load()), relay->parked_receipts(),
                            static_cast<unsigned long long>(rs.parked_receipts_sealed.load()), nn->index().alt_max_blocks(),
                            static_cast<unsigned long long>(alt_now.first), static_cast<unsigned long long>(alt_peak.first),
                            static_cast<unsigned long long>(nn->index().alt_verified_max_bytes()),
                            static_cast<unsigned long long>(alt_now.second), static_cast<unsigned long long>(alt_peak.second),
                            static_cast<unsigned long long>(nn->index().unsolicited_dropped()),
                            static_cast<unsigned long long>(nn->index().source_dropped()),
                            static_cast<unsigned long long>(rs.join_side_attempts.load()),
                            static_cast<unsigned long long>(rs.join_side_completed.load()),
                            static_cast<unsigned long long>(rs.join_side_not_served.load()));
            }
            {
                const std::map<std::uint64_t, std::uint64_t> om = relay->omission_counts();
                std::string per;
                for (const auto& [link, n] : om) per += " " + std::to_string(link) + ":" + std::to_string(n);
                std::printf("  omissions: total=%llu peers=%zu%s\n", static_cast<unsigned long long>(relay->omitted_total()),
                            om.size(), per.c_str());
                static const char* const kVerdictName[] = {"strike", "refuse", "defer", "duplicate", "ban", "carrier",
                                                           "pending", "drop"};
                static_assert(std::size(kVerdictName) == pb::PathbRelayNode::kVerdictKinds, "a name per verdict");
                const pb::PathbRelayNode::VerdictCounts vc = relay->verdict_counts();
                std::string vs;
                for (std::size_t row = 0; row < vc.size(); ++row)
                    for (std::size_t v = 0; v < vc[row].size(); ++v)
                        if (vc[row][v] != 0)
                            vs += " " + (row == 0 ? std::string("-") : "R" + std::to_string(row)) + "/" + kVerdictName[v] +
                                  "=" + std::to_string(vc[row][v]);
                std::printf("  verdicts:%s\n", vs.empty() ? " none" : vs.c_str());
            }
            std::printf("  follower: rows=%zu recorded=%llu events extend=%llu reorg=%llu orphan=%llu catching_up=%d prunes=%llu\n",
                        rows.size(), static_cast<unsigned long long>(rows.recorded()),
                        static_cast<unsigned long long>(tip_extends), static_cast<unsigned long long>(tip_reorgs),
                        static_cast<unsigned long long>(tip_orphans), chain.catchup_held && chain.catchup_held() ? 1 : 0,
                        static_cast<unsigned long long>(prunes));
            for (const std::string& l : pb::kept_status_lines(kept_status_values(cfg, *backend, transport.get())))
                std::printf("%s\n", l.c_str());
            std::fflush(stdout);
        }
        if (g_web && now >= last_web_s + 2) {
            last_web_s = now;
            xweb::XmrWebState w;
            w.version = C2POOL_VERSION;
            w.network = to_string(cfg.network);
            w.stratum_host = cfg.stratum_bind_host;
            w.stratum_port = listener.bound_port();
            if (const auto tipm = nn->index().tip()) w.chain_height = tipm->height;
            if (cur) {
                w.template_height = cur->h;
                w.share_difficulty = cur->d;
            }
            w.relay_enabled = ro.listen || !ro.peers.empty();
            w.give_author_pct = g_give_author_pct;
            w.owner_fee_pct = g_owner_fee_pct;
            w.owner_address = g_owner_address;
            w.payout_address = cfg.payout_address;
            const o2::StratumListenerStats ls = listener.stats();
            w.stratum_connections = ls.connections;
            w.stratum_active = ls.active;
            w.stratum_shares = ls.accepted_shares;
            w.stratum_rejected = ls.rejected_submits;
            w.lane_suspended = gate_closed;
            w.pathb.tip_pos = nv.pos;
            w.pathb.tip_id_hex = hex_of(nv.best);
            w.pathb.cum_work = nv.cum_work;
            w.pathb.epoch_cur = nv.hold.epoch_cur;
            w.pathb.h_hold = nv.hold.h_hold;
            if (cur) {
                w.pathb.window_root_hex = hex_of(cur->window.window_root);
                w.pathb.mmr_root_hex = hex_of(cur->window.mmr_root);
            }
            w.pathb.leaf_count = nv.leaf_count;
            w.pathb.pending = nv.pending;
            w.pathb.deferred = nv.deferred;
            w.pathb.pending_ids = nv.pending_ids;
            w.pathb.repended_last_switch = nv.sw.last_repended;
            w.pathb.switches = nv.sw.switches;
            w.pathb.template_status = template_status_name(tstatus);
            w.pathb.hold = nv.hold.hold;
            w.pathb.fork_fuse = fork_fuse;
            w.pathb.template_kept = template_kept;
            w.pathb.store_poisoned = nv.poisoned;
            w.pathb.coinbase_internal = nv.coinbase_internal;
            if (cur && cur->window.window && cur->reward != 0) {
                for (const pb::SplitOutput& o : pb::split(cur->reward, *cur->window.window)) {
                    xweb::XmrWebPayeeShare e;
                    e.payee = "key:" + hex_of(o.payee);
                    e.amount_pico = o.amount;
                    e.share = static_cast<double>(o.amount) / static_cast<double>(cur->reward);
                    w.window.push_back(std::move(e));
                }
            }
            w.found.assign(found_web.begin(), found_web.end());
            g_web->publish(std::move(w));
        }

        // 7. the cadence: fast while the follower catches up
        const bool catching_up = chain.catchup_held && chain.catchup_held();
        std::this_thread::sleep_for(std::chrono::milliseconds(catching_up ? std::min<std::uint32_t>(poll_ms, 200) : poll_ms));
    }

    // ---- teardown ----
#if defined(V37_XMR_O2_WITH_RANDOMX)
    if (cpu_miner) {
        mine::MinerHit dropped;
        while (cpu_miner->pop_hit(dropped)) {}
        cpu_miner.reset();
    }
#endif
    listener.stop();
    relay->stop();
    {
        std::string w;
        if (!rows.save(w)) std::printf("follower: row weights save FAILED: %s\n", w.c_str());
    }
    for (const std::string& l : listener.drain_log()) std::printf("  [stratum] %s\n", l.c_str());
    backend->stop();
    std::printf("c2pool-v37-xmr: stopped\n");
    return 0;
}

// ---------------------------------------------------------------------------
// CLI-STRICT: every token is a known flag; a value flag is followed by its value
// (a token starting with "--" is the next flag, not a value); numbers and
// enumerated values parse whole. A violation is a usage error: one line on
// stderr naming the flag, exit 2. A flag removed at the S4w flag day is
// refused with its fixed text, exit 2. Nothing is constructed before the parse
// ends.
// ---------------------------------------------------------------------------
namespace cli_strict {

constexpr int kUsageExit = 2;

struct UsageError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

inline std::uint64_t to_u64(const std::string& flag, const std::string& v,
                            std::uint64_t max = std::numeric_limits<std::uint64_t>::max()) {
    std::uint64_t out = 0;
    const char* b = v.data();
    const char* e = b + v.size();
    const auto r = std::from_chars(b, e, out);
    if (v.empty() || r.ec != std::errc{} || r.ptr != e || out > max)
        throw UsageError(flag + " wants an integer in [0, " + std::to_string(max) + "], got '" + v + "'");
    return out;
}

inline std::int64_t to_i64(const std::string& flag, const std::string& v) {
    std::int64_t out = 0;
    const char* b = v.data();
    const char* e = b + v.size();
    const auto r = std::from_chars(b, e, out);
    if (v.empty() || r.ec != std::errc{} || r.ptr != e) throw UsageError(flag + " wants an integer, got '" + v + "'");
    return out;
}

inline double to_double(const std::string& flag, const std::string& v) {
    double out = 0;
    const char* b = v.data();
    const char* e = b + v.size();
    const auto r = std::from_chars(b, e, out);
    if (v.empty() || r.ec != std::errc{} || r.ptr != e || !std::isfinite(out))
        throw UsageError(flag + " wants a number, got '" + v + "'");
    return out;
}

// A decimal of at most three fraction digits as an integer in thousandths ("1.7" -> 1700); nothing else.
inline std::uint64_t to_milli(const std::string& flag, const std::string& v) {
    const auto bad = [&]() { return UsageError(flag + " wants a decimal of at most 3 fraction digits, got '" + v + "'"); };
    const std::size_t dot = v.find('.');
    const std::string ip = v.substr(0, dot), fp = dot == std::string::npos ? std::string() : v.substr(dot + 1);
    if (ip.empty() || fp.size() > 3 || (dot != std::string::npos && fp.empty())) throw bad();
    for (char c : ip + fp)
        if (c < '0' || c > '9') throw bad();
    std::uint64_t whole = 0;
    const auto r = std::from_chars(ip.data(), ip.data() + ip.size(), whole);
    if (r.ec != std::errc{} || whole > (UINT64_MAX - 999) / 1000) throw bad();
    std::uint64_t frac = 0;
    for (std::size_t i = 0; i < 3; ++i) frac = frac * 10 + (i < fp.size() ? static_cast<std::uint64_t>(fp[i] - '0') : 0);
    return whole * 1000 + frac;
}
inline std::string milli_str(std::uint64_t m) {
    std::string f = std::to_string(m % 1000);
    while (f.size() < 3) f = "0" + f;
    while (!f.empty() && f.back() == '0') f.pop_back();
    return std::to_string(m / 1000) + (f.empty() ? "" : "." + f);
}

// A rate as the refusal names it (one decimal).
inline std::string rate_str(double r) {
    char b[32];
    std::snprintf(b, sizeof b, "%.1f", r);
    return b;
}

inline const std::string& one_of(const std::string& flag, const std::string& v, std::initializer_list<const char*> ok) {
    std::string list;
    for (const char* o : ok) {
        if (v == o) return v;
        list += (list.empty() ? "" : "|") + std::string(o);
    }
    throw UsageError(flag + " takes " + list + ", got '" + v + "'");
}

// --version / -V: who this binary is, what it defaults to, and which bootstrap
// it pins. Nothing is opened or started.
inline void print_version() {
    namespace nat = ::c2pool::xmr::native;
    const XmrNodeConfig defaults;
    std::printf("c2pool-v37-xmr %s\n", C2POOL_VERSION);
    std::printf("network default: %s\n", to_string(defaults.network));
    std::printf("pinned snapshot: mainnet height %llu (block %s); stagenet height %llu (block %s); "
                "testnet, regtest: none\n",
                static_cast<unsigned long long>(nat::PINNED_SNAPSHOT_MAINNET.height), nat::PINNED_SNAPSHOT_MAINNET.block_id,
                static_cast<unsigned long long>(nat::PINNED_SNAPSHOT_STAGENET.height), nat::PINNED_SNAPSHOT_STAGENET.block_id);
}

// The flags removed at the S4w flag day: refused with "<flag>: removed at the S4w flag day".
// The ones that took a value on master consume it.
struct RemovedFlag {
    const char* name;
    bool takes_value;
};
inline constexpr RemovedFlag kRemovedFlags[] = {
        {"--coinbase", true},
        {"--template-reserve", true},
        {"--share-diff", true},
        {"--fee-model", true},
        {"--residual-sink-spend-hex", true},
        {"--residual-sink-view-hex", true},
        {"--residual-sink-subaddress", false},
        {"--settle-h-min", true},
        {"--settle-output-cap", true},
        {"--owed-demo-amount", true},
        {"--no-found-sidecar", false},
        {"--payee-spend-hex", true},
        {"--payee-view-hex", true},
        {"--payee-subaddress", false},
        {"--d-conf", true},
        {"--same-height-journal", true},
        {"--same-height-renotify", true},
        {"--minority-converge", true},
        {"--minority-window", true},
        {"--minority-min-blocks", true},
        {"--converge-retry-bound", true},
        {"--converge-hold-ticks", true},
        {"--recon-max-root-age", true},
        {"--contested-suspend", true},
        {"--divergence-cap-heights", true},
        {"--divergence-cap-ticks", true},
        {"--divergence-cap-terminal", true},
        {"--relay-order", true},
        {"--relay-bin-lag", true},
        {"--relay-bin-grace-ms", true},
        {"--relay-vault-entries", true},
        {"--relay-vault-bytes", true},
        {"--relay-vault-horizon", true},
        {"--relay-deep-order", true},
        {"--relay-deep-probe-step", true},
        {"--relay-shadow-persist", true},
        {"--relay-shadow-persist-bytes", true},
        {"--relay-bind", true},
        {"--relay-backfill-positions", true},
        {"--relay-reoffer-seconds", true},
        {"--relay-index-horizon", true},
        {"--no-relay-serve", false},
        {"--drops-enrol", true},
        {"--drops-enrol-min-tip", true},
        {"--drops-retain-bins", true},
        {"--drops-store-persist", true},
        {"--credit-feed", true},
        {"--credit-feed-lag-ms", true},
        {"--wire-out", true},
        {"--wire-in", true},
        {"--credit-mutate", true},
        {"--no-book-deferral", false},
        {"--cba-monerod-compare", false},
        {"--cba-monerod-fallback", false},
        {"--cba-refetch-bound", true},
        {"--relay-feed-monerod-compare", false},
        {"--test-crash-after-publish", true},
        {"--test-suspend-lane-seconds", true},
        {"--mock-smoke", false},
        {"--selftest", false},
};

inline const RemovedFlag* removed_flag(const std::string& a) {
    for (const RemovedFlag& r : kRemovedFlags)
        if (a == r.name) return &r;
    return nullptr;
}

}  // namespace cli_strict

static void print_help() {
    std::printf(
            "c2pool-v37-xmr (Path B; stagenet default)\n"
            "  --version, -V                print the version, the network default and the pinned snapshot heights\n"
            "  --network <stagenet|testnet|mainnet|regtest>   default stagenet\n"
            "  --follow-only                follow Monero and log the template record of the Monero tip for an\n"
            "                               empty window: no pool, no store, no job, no relay, no daemon endpoint\n"
            "                               (sets --arm-order p2p-first, the native template source, --no-daemon-rpc)\n"
            "  --i-understand-mainnet       required on mainnet (mainnet: --follow-only only)\n"
            " the pool identity (one form):\n"
            "  --pool-genesis-from <H>:<hash64>:\"<headline>\"   the derived identity (every network; mainnet's only form)\n"
            "  --pool-genesis <hex64>:<H>   a raw genesis with its height (regtest, testnet, stagenet)\n"
            "  --pool-genesis-height <H>    the height of the network's default raw genesis (regtest, testnet, stagenet)\n"
            "  --lane-chain <id>            the chain id of the pool identity (default 0)\n"
            " the pool:\n"
            "  --pathb-launch               the pool's first node: build templates with no Path B peer\n"
            "  --vote no                    ballot no for the open deployment (default yes)\n"
            "  --journal-depth <n>          positions rewound by the journal (default and floor 1152; raise only)\n"
            "  --pathb-deployments <file>   kind-2 deployment descriptors, 59-byte records (test networks)\n"
            "  --pathb-key-cache-mb <n>     the coinbase key cache (default 64)\n"
            "  --pathb-penalty-fill         fill the template into the penalty zone (default off)\n"
            "  --pathb-body-keep <n>        carrier bodies and tree nodes kept below the best tip (positions)\n"
            "  --pathb-header-keep <n>      carrier headers kept below the best tip (positions)\n"
            "  --pathb-side-keep <n>        side headers and side views kept below the best tip (positions)\n"
            "  --pathb-abandon-timeout <s>  a join request's next-frame timeout (default 11)\n"
            "  --pathb-waiting-cap <n>      deferred carriers (default 1152)\n"
            "  --pathb-bucket-serve-cap <bytes>  FC_BUCKETS bytes served per request (default: the asker's rate left)\n"
            "  --pathb-claim-alarm-rate <r> claim-leaf alarms per peer per second (default and floor 1.7; raise only)\n"
            "  --pathb-bucket-frame <bytes> FC_BUCKETS frame buffer\n"
            "  --join-min-peers <n>         peers whose HELLO tails name the candidates before a join (default 2)\n"
            "  --pathb-bucket-inflight <n>  FC_GETBUCKETS in flight per peer (default 1)\n"
            "  --pathb-bucket-rate <bytes>  FC_BUCKETS bytes per peer per minute\n"
            "  --pathb-regtest-k30 <L,GRACE,TIMEOUT>  the regtest rig's K30 set (regtest only; G from it)\n"
            "  --give-author-pct <p>        the author's weight share in this node's jobs (defaults to 0.1; 0 opts out)\n"
            "  --node-owner-fee-pct <p>     the node owner's weight share in this node's jobs (default 0)\n"
            "  --node-owner-address <addr>  the node owner's standard address\n"
            "  --data-dir <path>            the data directory (default: the config path)\n"
            "  --poll-ms <ms>  --status-every <s>\n"
            "  --randomx                    RandomX verify (needs XMR_BUILD_RANDOMX; the pool node needs it)\n"
            "  --randomx-large-pages        RandomX cache in huge pages\n"
            " the Path B relay:\n"
            "  --relay-listen HOST:PORT     listen\n"
            "  --relay-peer HOST:PORT       dial a peer (repeatable)\n"
            "  --no-relay-bootstrap         do not dial the network's bootstrap peers\n"
            "  --relay-max-inbound <n>      accepted links (default 101; --relay-max-peers is an alias)\n"
            "  --relay-max-outbound <n>     dialed links (default 12)\n"
            "  --relay-discovery <on|off>   FB_GETADDR / FB_ADDR and the peer book (default on)\n"
            "  --relay-rx-global <G>        invalid-object tokens per second, global\n"
            "  --relay-rx-budget P,C,G,GC   the invalid-object budget (refill/s, cap per address; global)\n"
            "  --relay-ban-seconds <s>      address ban\n"
            "  --relay-verify-threads <n>   RandomX verify workers (0 = auto)\n"
            "  --relay-solicited-credits <n>  --relay-parked-max <n>\n"
            "  --relay-keepalive-ms <ms>    PING interval (default 5000; 0 = off)\n"
            "  --relay-silence-timeout-ms <ms>  drop a silent link (default 25000; 0 = never)\n"
            "  --relay-peer-valid-rate <r>  valid objects per peer per second (default and floor 1.7; raise only)\n"
            "  --relay-pending-cap <n>      pending receipts (default and floor 18432; raise only)\n"
            "  --relay-send-queue-bytes <n> per-link send queue (default 16777216; floor two FC_HEADERS frames)\n"
            "  --relay-ctx-block-cap <n>    context block cap (default and floor blob_cap_ctx(hf, Z); raise only)\n"
            "  --relay-test-partition-seconds <s>  SIGUSR1 drops the relay for s seconds (test rigs)\n"
            " stratum and mining:\n"
            "  --stratum-bind-host <ip>  --stratum-port <p>   default 127.0.0.1:3333\n"
            "  --stratum-min-diff-shift <s> min-diff = max(1, d >> s), submit refill 2 << s per T (default 0)\n"
            "  --stratum-share-rate <r>     fixed submit refill per connection, submits/s\n"
            "  --stratum-vardiff-shares <n> vardiff on: n shares per lane window per connection\n"
            "  --stratum-submit-burst <n>   submit burst and queue bound per connection (default 24)\n"
            "  --stratum-ban-seconds <s>    address ban (default ceil(burst / refill))\n"
            "  --stratum-share-score B,G,K,M  share score: bad B, good G, ban at K, cap M (default -3,1,-9,0)\n"
            "  --stratum-login-timeout-ms <ms>  no login by then: banned (default 5000; 0 = off)\n"
            "  --payout-address <addr>      the payee of the in-process miner's jobs\n"
            "  --mine [threads]             the in-process RandomX CPU miner on this node's jobs\n"
            "  --mine-threads <n>  --mine-fast  --mine-msr  --mine-no-huge-pages  --mine-no-affinity\n"
            "  --web-port <p>  --web-host <ip>  --dashboard-dir <dir>   the web dashboard (default off)\n"
            " the Monero node:\n"
            "  --arm-order <daemon-first|p2p-first>   daemon-first (default): monerod submit_block publishes;\n"
            "                               p2p-first: a found block goes out over levin\n"
            "  --xmr-template-source <monerod|native>  the template's transactions (daemon-first: either)\n"
            "  --rpc-host <h>  --rpc-port <p>  --zmq-port <p>   monerod\n"
            "  --no-daemon-rpc              no monerod endpoint for the native node\n"
            "  --native-parity-monerod      p2p-first: monerod as the compare-only parity judge\n"
            "  --native-connect <ip:port>   pinned levin peer (repeatable)\n"
            "  --native-seeds, --seeds      the network's seed set\n"
            "  --native-p2p-bind <ip>  --native-anchor <path>  --native-output-set <path>\n"
            "  --anchor-confirm-peers <n>  --anchor-confirm-peer-ms <ms>  --anchor-confirm-timeout-ms <ms>\n"
            "  --native-snapshot-path <file>  --native-snapshot-every <s>  --native-catchup-window <n>\n"
            "  --native-force-synced  --native-allow-unverified-pow  --native-template-fallback <on|off>\n"
            "  --native-ready-timeout <s>  --native-backlog-refresh <s>, --backlog-refresh <s>\n"
            "  --native-dos-solicited-credits <n>  --no-good-citizen\n"
            "  --native-txpool-warm-timeout-ms <ms>  after a restart, no template until the tx pool is warm or\n"
            "                               this many ms passed (default 30000; 0 = no warm gate)\n"
            "  --native-solo                regtest only: no peers, no daemon, no anchor; the chain starts at the\n"
            "                               locally assembled genesis block. A found block that reached no peer\n"
            "                               counts as landed when OUR OWN index accepts it.\n"
            "  --native-inject  --native-inject-dir <dir>  --native-inject-hex <file>  --native-inject-ttl-blocks <n>\n"
            "  --same-height-tiebreak <prefer-own|first-seen>  --own-fork-bound-s <n>  --test-unknown-fork-stall-s <n>\n"
            "  --alt-max-blocks <n>         alternative Monero blocks the follower keeps and serves (default 720 = k_alt,\n"
            "                               one full context climb; at least 1)\n"
            "  --alt-max-bytes <n>          lowers the bytes of verified alternative blocks kept (derived: the blocks x\n"
            "                               the context block cap at the node's view)\n");
}

int main(int argc, char** argv) {
    XmrNodeConfig cfg;
    PathbFlags pf;
    namespace cs = cli_strict;
    std::optional<std::string> removed;   // the first removed flag given

    std::string a;
    try {
        for (int i = 1; i < argc; ++i) {
            a = argv[i];
            std::string flag_value;   // recorded in given_flags
            auto value = [&]() -> std::string {
                if (i + 1 >= argc || std::string(argv[i + 1]).rfind("--", 0) == 0) throw cs::UsageError(a + " wants a value");
                flag_value = argv[++i];
                return flag_value;
            };
            auto u64 = [&](std::uint64_t max = std::numeric_limits<std::uint64_t>::max()) {
                const std::string v = value();
                return cs::to_u64(a, v, max);
            };
            auto u32 = [&]() { return static_cast<std::uint32_t>(u64(std::numeric_limits<std::uint32_t>::max())); };
            auto u16 = [&]() { return static_cast<std::uint16_t>(u64(std::numeric_limits<std::uint16_t>::max())); };
            auto record = [&]() { cfg.given_flags.push_back(GivenFlag{a, flag_value}); };
            {
                std::string ferr;
                const int used = apply_native_node_flag(cfg, argc, argv, i, ferr);
                if (used < 0) throw cs::UsageError(ferr);
                if (used > 0) {
                    cfg.given_flags.push_back(GivenFlag{a, used > 1 ? std::string(argv[i + 1]) : std::string()});
                    i += used - 1;
                    continue;
                }
            }
            if (const cs::RemovedFlag* rf = cs::removed_flag(a)) {
                if (rf->takes_value && i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) flag_value = argv[++i];
                record();
                if (!removed) removed = a;
                continue;
            }
            if (a == "--version" || a == "-V") {
                cs::print_version();
                return 0;
            } else if (a == "--help" || a == "-h") {
                print_help();
                return 0;
            } else if (a == "--network") {
                const std::string m = value();
                cs::one_of(a, m, {"stagenet", "testnet", "mainnet", "regtest"});
                cfg.network = parse_net(m);
            } else if (a == "--rpc-host") cfg.monerod.rpc_host = value();
            else if (a == "--rpc-port") cfg.monerod.rpc_port = u16();
            else if (a == "--zmq-port") cfg.monerod.zmq_port = u16();
            else if (a == "--stratum-port") cfg.stratum_bind_port = u16();
            else if (a == "--stratum-bind-host") cfg.stratum_bind_host = value();
            else if (a == "--stratum-share-rate") {
                const double r = cs::to_double(a, value());
                if (!(r > 0)) throw cs::UsageError(a + " wants a number > 0");
                g_stratum_share_rate = r;
            } else if (a == "--stratum-vardiff-shares") {
                const auto nsh = static_cast<std::uint32_t>(u64(std::numeric_limits<int>::max()));
                if (nsh == 0) throw cs::UsageError(a + " wants an integer >= 1");
                g_stratum_vardiff_shares = nsh;
            } else if (a == "--stratum-submit-burst") {
                const auto b = static_cast<std::uint32_t>(u64(std::numeric_limits<int>::max()));
                if (b == 0) throw cs::UsageError(a + " wants an integer >= 1");
                g_stratum_submit_burst = b;
            } else if (a == "--stratum-ban-seconds") g_stratum_ban_seconds = static_cast<std::uint32_t>(u64(std::numeric_limits<int>::max()));
            else if (a == "--stratum-login-timeout-ms") g_stratum_login_timeout_ms = static_cast<std::uint32_t>(u64(std::numeric_limits<int>::max()));
            else if (a == "--stratum-share-score") {
                const std::string v = value();
                std::vector<std::string> toks;
                for (std::size_t at = 0;;) {
                    const std::size_t c = v.find(',', at);
                    toks.push_back(v.substr(at, c == std::string::npos ? std::string::npos : c - at));
                    if (c == std::string::npos) break;
                    at = c + 1;
                }
                if (toks.size() != 4) throw cs::UsageError(a + " wants BAD,GOOD,BAN,CAP integers, got '" + v + "'");
                std::array<int, 4> s{};
                for (std::size_t k = 0; k < 4; ++k) {
                    const std::int64_t n = cs::to_i64(a, toks[k]);
                    if (n < std::numeric_limits<int>::min() || n > std::numeric_limits<int>::max())
                        throw cs::UsageError(a + " wants BAD,GOOD,BAN,CAP integers, got '" + v + "'");
                    s[k] = static_cast<int>(n);
                }
                g_stratum_share_score = s;
            } else if (a == "--stratum-min-diff-shift") {
                g_stratum_min_diff_shift = static_cast<std::uint32_t>(u64(pbs::kStratumMinDiffShiftMax));
            } else if (a == "--payout-address") cfg.payout_address = value();
            else if (a == "--poll-ms") cfg.poll_ms = u32();
            else if (a == "--status-every") cfg.status_every_s = u32();
            else if (a == "--give-author-pct" || a == "--node-owner-fee-pct") {
                const std::string v = value();
                const pb::policy::ExactPct ex = pb::policy::parse_pct_exact(v);
                if (!ex.ok) throw cs::UsageError(a + " wants a decimal percentage (digits, up to 9 decimals), got '" + v + "'");
                if (a == "--give-author-pct") {
                    g_give_author_pct = cs::to_double(a, v);
                    g_give_author_exact = ex;
                } else {
                    g_owner_fee_pct = cs::to_double(a, v);
                    g_owner_fee_exact = ex;
                }
            } else if (a == "--node-owner-address") g_owner_address = value();
            // one identity form: --pool-genesis-from, or a raw form (--pool-genesis, or --pool-genesis-height with
            // the network's default raw genesis); startup_checks refuses a derived and a raw form given together
            else if (a == "--pool-genesis-from") pf.genesis_from = value();
            else if (a == "--pool-genesis") pf.pool_genesis = value();
            else if (a == "--pool-genesis-height") pf.pool_genesis_height = value();
            else if (a == "--vote") {
                cs::one_of(a, value(), {"no"});
                pf.vote_no = true;
            } else if (a == "--pathb-deployments") pf.deployments_file = value();
            else if (a == "--pathb-key-cache-mb") pf.key_cache_mb = u64(std::numeric_limits<std::uint32_t>::max());
            else if (a == "--pathb-penalty-fill") pf.penalty_fill = true;
            else if (a == "--journal-depth") pf.journal_depth = u64();
            else if (a == "--pathb-launch") pf.launch = true;
            else if (a == "--pathb-body-keep") pf.body_keep = u64();
            else if (a == "--pathb-header-keep") pf.header_keep = u64();
            else if (a == "--pathb-side-keep") pf.side_keep = u64();
            else if (a == "--pathb-abandon-timeout") pf.abandon_timeout_s = u64();
            else if (a == "--pathb-waiting-cap") pf.waiting_cap = u64();
            else if (a == "--pathb-bucket-serve-cap") pf.bucket_serve_cap = u64();
            else if (a == "--pathb-claim-alarm-rate") {
                const std::uint64_t r = cs::to_milli(a, value());
                const std::uint64_t fl = pb::claim_alarm_rate_floor_milli(pb::kRuledLaneParams);
                const std::uint64_t mx = pb::claim_alarm_rate_max_milli(pb::kRuledLaneParams);
                if (r < fl) throw cs::UsageError(a + " wants a rate >= " + cs::milli_str(fl) + " (raise only)");
                if (r > mx) throw cs::UsageError(a + " wants a rate <= " + cs::milli_str(mx));
                pf.claim_alarm_rate_milli = r;
            }
            else if (a == "--pathb-bucket-frame") pf.bucket_frame = u64();
            else if (a == "--join-min-peers") pf.join_min_peers = u64();
            else if (a == "--pathb-bucket-inflight") pf.bucket_inflight = u64();
            else if (a == "--pathb-bucket-rate") pf.bucket_rate = u64();
            else if (a == "--pathb-regtest-k30") {
                const std::string v = value();
                std::array<std::uint64_t, 3> k{};
                std::size_t n = 0, at = 0;
                for (; n < 3; ++n) {
                    const std::size_t c = v.find(',', at);
                    k[n] = cs::to_u64(a, v.substr(at, c == std::string::npos ? std::string::npos : c - at));
                    if (c == std::string::npos) break;
                    at = c + 1;
                }
                if (n != 2) throw cs::UsageError(a + " wants L,GRACE,TIMEOUT, got '" + v + "'");
                pf.regtest_k30 = pb::RatchetParams{k[0], k[1], k[2]};
            }
            else if (a == "--follow-only") cfg.follow_only = true;
            else if (a == "--native-txpool-warm-timeout-ms") cfg.native_txpool_warm_timeout_ms = u64();
            else if (a == "--relay-listen") cfg.relay_listen = value();
            else if (a == "--relay-peer") cfg.relay_peers.push_back(value());
            else if (a == "--no-relay-bootstrap") g_no_relay_bootstrap = true;
            else if (a == "--relay-max-inbound" || a == "--relay-max-peers") g_relay_max_inbound = static_cast<std::size_t>(u64());
            else if (a == "--relay-discovery") g_relay_discovery = cs::one_of(a, value(), {"on", "off"}) == "on";
            else if (a == "--relay-max-outbound") g_relay_max_outbound = static_cast<std::size_t>(u64());
            else if (a == "--relay-rx-budget") g_relay_rx_budget = value();
            else if (a == "--relay-rx-global") {
                g_relay_rx_global = u32();
                if (*g_relay_rx_global == 0) throw cs::UsageError(a + " wants an integer >= 1");
            } else if (a == "--relay-ban-seconds") g_relay_ban_seconds = u32();
            else if (a == "--relay-verify-threads") g_relay_verify_threads = u32();
            else if (a == "--relay-solicited-credits") g_relay_solicited = u32();
            else if (a == "--relay-parked-max") g_relay_parked_max = static_cast<std::size_t>(u64());
            else if (a == "--relay-keepalive-ms") g_relay_keepalive_ms = u32();
            else if (a == "--relay-silence-timeout-ms") g_relay_silence_ms = u32();
            else if (a == "--relay-peer-valid-rate") {
                const double r = cs::to_double(a, value());
                const double fl = static_cast<double>(1 + pb::kRuledLaneParams.r_max) /
                                  static_cast<double>(pb::kRuledLaneParams.carrier_interval_s);
                if (r < fl) throw cs::UsageError(a + " wants a rate >= " + cs::rate_str(fl) + " (raise only)");
                g_relay_peer_valid_rate = r;
            } else if (a == "--relay-pending-cap") {
                const std::uint64_t n = u64();
                const std::uint64_t fl = pb::relay_horizons(pb::kRuledLaneParams).pending_cap;
                if (n < fl) throw cs::UsageError(a + " wants an integer >= " + std::to_string(fl) + " (raise only)");
                g_relay_pending_cap = n;
            } else if (a == "--relay-send-queue-bytes") g_relay_send_queue = u64();
            else if (a == "--relay-ctx-block-cap") g_relay_ctx_block_cap = u64();
            else if (a == "--relay-test-partition-seconds") g_relay_partition_s = u32();
            else if (a == "--web-port") g_web_port = u16();
            else if (a == "--web-host") g_web_host = value();
            else if (a == "--dashboard-dir") g_web_dir = value();
            else if (a == "--xmr-template-source") {
                const std::string m = cs::one_of(a, value(), {"monerod", "native"});
                cfg.template_source = (m == "native") ? TemplateSourceMode::Native : TemplateSourceMode::Monerod;
            } else if (a == "--native-output-set") cfg.native_output_set_path = value();
            else if (a == "--native-solo") cfg.native_solo = true;
            else if (a == "--native-dos-solicited-credits") cfg.native_dos_solicited_credits = u32();
            else if (a == "--no-good-citizen") cfg.no_good_citizen = true;
            else if (a == "--native-inject") cfg.native_inject = true;
            else if (a == "--native-inject-dir") cfg.native_inject_dir = value();
            else if (a == "--native-inject-hex") cfg.native_inject_hex = value();
            else if (a == "--native-inject-ttl-blocks") cfg.native_inject_ttl_blocks = u64();
            else if (a == "--arm-order") {
                const std::string m = cs::one_of(a, value(), {"daemon-first", "p2p-first", "p2p", "daemonless"});
                cfg.arm_order = (m == "p2p-first" || m == "p2p" || m == "daemonless") ? ArmOrderMode::P2PFirst
                                                                                      : ArmOrderMode::DaemonFirst;
            } else if (a == "--no-daemon-rpc") cfg.no_daemon_rpc = true;
            else if (a == "--lane-chain") cfg.lane_chain = static_cast<::v37::ChainId>(u32());
            else if (a == "--same-height-tiebreak") {
                const std::string m = value();
                if (!parse_tie_break(m, cfg.same_height_tiebreak))
                    throw cs::UsageError("--same-height-tiebreak takes prefer-own or first-seen, not '" + m + "'");
            } else if (a == "--own-fork-bound-s") cfg.own_fork_bound_s = u32();
            else if (a == "--test-unknown-fork-stall-s") cfg.test_unknown_fork_stall_s = u32();
            else if (a == "--alt-max-bytes") {
                cfg.alt_max_bytes = u64();
                if (cfg.alt_max_bytes == 0) throw cs::UsageError("--alt-max-bytes takes at least 1");
            } else if (a == "--alt-max-blocks") {
                cfg.alt_max_blocks = static_cast<std::size_t>(u64(std::numeric_limits<std::uint32_t>::max()));
                if (cfg.alt_max_blocks == 0) throw cs::UsageError("--alt-max-blocks takes at least 1");
            }
            else if (a == "--data-dir") cfg.data_dir = value();
            else if (a == "--i-understand-mainnet") cfg.i_understand_mainnet = true;
            else if (a == "--randomx") cfg.randomx_enabled = true;
            else if (a == "--randomx-large-pages") cfg.randomx_large_pages = true;
            else if (a == "--mine") {
                cfg.mine_enabled = true;
                if (i + 1 < argc && argv[i + 1][0] >= '0' && argv[i + 1][0] <= '9') cfg.mine_threads = u32();
            } else if (a == "--mine-threads") {
                cfg.mine_enabled = true;
                cfg.mine_threads = u32();
            } else if (a == "--mine-fast") {
                cfg.mine_enabled = true;
                cfg.mine_fast = true;
            } else if (a == "--mine-msr") cfg.mine_msr = true;
            else if (a == "--mine-no-huge-pages") cfg.mine_large_pages = false;
            else if (a == "--mine-no-affinity") cfg.mine_pin = false;
            else if (a.rfind("-", 0) == 0) throw cs::UsageError("unknown option '" + a + "'");
            else throw cs::UsageError("unexpected argument '" + a + "'");
            record();
        }
    } catch (const cs::UsageError& e) {
        std::fprintf(stderr, "c2pool-v37-xmr: %s (see c2pool-v37-xmr --help)\n", e.what());
        return cs::kUsageExit;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "c2pool-v37-xmr: %s: bad value (%s) (see c2pool-v37-xmr --help)\n", a.c_str(), e.what());
        return cs::kUsageExit;
    }

    if (removed) {
        std::fprintf(stderr, "c2pool-v37-xmr: REFUSED: %s\n", pmode::removed_flag_refusal(*removed).c_str());
        return cs::kUsageExit;
    }

    // Default monerod ports follow the chosen network unless overridden.
    if (cfg.monerod.rpc_port == default_endpoint(MoneroNetwork::Stagenet).rpc_port && cfg.network != MoneroNetwork::Stagenet) {
        const auto e = default_endpoint(cfg.network);
        cfg.monerod.rpc_port = e.rpc_port;
        cfg.monerod.zmq_port = e.zmq_port;
    }

    // The mode: --follow-only's effects, then the mode refusals (fence, mainnet,
    // follow-only, solo, arm order), before anything is constructed.
    pmode::apply_follow_only(cfg);
    if (const std::string r = pmode::mode_refusal(cfg); !r.empty()) {
        std::printf("REFUSED: %s\n", r.c_str());
        return 2;
    }

    std::unique_ptr<xweb::XmrWebDashboard> web;
    if (g_web_port) {
        web = std::make_unique<xweb::XmrWebDashboard>(g_web_host, g_web_port, g_web_dir, cfg.network != MoneroNetwork::Mainnet);
        xweb::XmrWebState w0;
        w0.version = C2POOL_VERSION;
        w0.network = to_string(cfg.network);
        w0.stratum_host = cfg.stratum_bind_host;
        w0.stratum_port = cfg.stratum_bind_port;
        w0.payout_address = cfg.payout_address;
        web->publish(std::move(w0));
        if (web->start()) {
            g_web = web.get();
            std::printf("web: dashboard LIVE on http://%s:%u (dashboard-dir=%s, payout scheme %s)\n", g_web_host.c_str(),
                        static_cast<unsigned>(web->bound_port()), g_web_dir.c_str(), xweb::kPayoutScheme);
        } else {
            std::printf("web: dashboard FAILED to bind %s:%u -- dashboard disabled\n", g_web_host.c_str(),
                        static_cast<unsigned>(g_web_port));
            web.reset();
        }
    }
    const int rc = cfg.follow_only ? run_follow_only(cfg, pf) : run_pathb(cfg, pf);
    g_web = nullptr;
    web.reset();
    return rc;
}
