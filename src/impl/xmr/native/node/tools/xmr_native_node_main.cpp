// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/node/tools/xmr_native_node_main.cpp
//
// `xmr_native_node` -- the M0 entrypoint: run the assembled native Monero node
// and print what it did.
//
// It is a HARNESS, not the pool. The pool proper reaches this node through
// C4's IMinerDataSource seam (M2) and C5's relay (M3); this binary exists so
// that the node can be started, pointed at a daemon, and judged on its own --
// which is the only way "the chain index follows the tip over levin" is a fact
// rather than a design.
//
// THREE MODES, one binary:
//
//   * FOLLOW (default). Boot, dial, sync, then follow. `--follow-to H` exits
//     as soon as the native tip reaches H, which is what makes it scriptable:
//     mine a block, wait for the node to reach that height, compare against the
//     daemon, repeat.
//   * PROBE (`--probe-only`). Handshake, TIMED_SYNC, exactly one
//     NOTIFY_REQUEST_CHAIN, print what came back, exit. Nothing is fetched and
//     no block is verified: this is what is allowed against somebody else's
//     daemon that is busy syncing.
//   * PARITY (`--monerod-rpc host:port`, on by default when set). C6's P-TIP
//     seam runs at every height the node adopts, and every sample is printed.
//     The daemon is the judge, never the source: `rpc_calls` is printed beside
//     `blocks_in` so the two can be read against each other.
//
// THE ONE CLAIM THIS BINARY IS BUILT TO SUPPORT is printed in the summary and
// is deliberately a pair of numbers rather than an assertion:
//
//     randomx: hashes=N threads=[verify] foreign=0
//
// `foreign` counts RandomX evaluations that happened on a thread the node
// declared forbidden -- the io threads. A wiring regression that put the
// verifier back on the io thread would make it non-zero without anybody having
// to notice a call graph changed.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/.
// ---------------------------------------------------------------------------
#include <dirent.h>

#include <algorithm>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <ctime>
#include <iostream>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "impl/xmr/native/node/xmr_native_node.hpp"
#include "impl/xmr/native/parity/xmr_graduation_ledger.hpp"
#include "impl/xmr/native/parity/xmr_parity_report.hpp"
#include "impl/xmr/native/parity/xmr_soak_driver.hpp"

namespace rt     = ::c2pool::xmr::native::rt;
namespace native = ::c2pool::xmr::native;
namespace parity = ::c2pool::xmr::native::parity;

namespace {

volatile std::sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

std::string hex(const native::Hash& h) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (std::uint8_t b : h) { s.push_back(d[b >> 4]); s.push_back(d[b & 0xf]); }
    return s;
}

std::string u128(const native::U128& v) {
    // Small enough for every number this harness prints (regtest cumulative
    // difficulty, a stagenet block difficulty); the high word is reported
    // separately rather than silently dropped.
    if (v.hi == 0) return std::to_string(v.lo);
    return std::to_string(v.hi) + ":" + std::to_string(v.lo);
}

bool from_hex(const std::string& hex, std::vector<std::uint8_t>& out) {
    out.clear();
    if (hex.size() % 2 != 0 || hex.empty()) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return true;
}

bool split_host_port(const std::string& s, std::string& host, std::uint16_t& port) {
    const std::size_t c = s.rfind(':');
    if (c == std::string::npos || c == 0 || c + 1 >= s.size()) return false;
    host = s.substr(0, c);
    const long v = std::strtol(s.c_str() + c + 1, nullptr, 10);
    if (v <= 0 || v > 65535) return false;
    port = static_cast<std::uint16_t>(v);
    return true;
}

void usage() {
    std::cout <<
        "xmr_native_node -- the M0 native Monero node harness\n"
        "\n"
        "  --net <mainnet|stagenet|testnet|regtest>   which network (default stagenet)\n"
        "  --connect <ip:port>                        a pinned levin peer (repeatable)\n"
        "  --seeds                                    also use the network's seed nodes\n"
        "  --boot <genesis|anchor>                    where the index's history starts\n"
        "  --anchor-path <file>                       anchor boot from a .inc (default: embedded)\n"
        "  --monerod-rpc <host:port>                  the parity/backup arm (read-only)\n"
        "  --no-parity                                construct no parity oracle\n"
        "  --parity-ledger <file>                     persist the graduation ledger\n"
        "  --commit <sha>                             the c2pool commit, a graduation key\n"
        "  --serve-arm <native|monerod>               which template arm serves\n"
        "  --relay-order <daemon-first|parallel|p2p-only>\n"
        "  --follow-to <height>                       exit once the native tip reaches it\n"
        "  --run-seconds <n>                          hard stop (default 120)\n"
        "  --status-every <ms>                        status line cadence (default 2000)\n"
        "  --force-synced                             set the publication gate (regtest)\n"
        "  --probe-only                               handshake + one chain request, then exit\n"
        "  --allow-unverified-pow                     start even though this build cannot\n"
        "                                             check proof of work (no librandomx)\n"
        "\n"
        "  M1 (the transaction pool):\n"
        "  --txpool-parity                            run the P-POOL seam against the daemon\n"
        "  --txpool-parity-every <ms>                 its cadence (default 1500)\n"
        "  --m1-min-txs <n>                           distinct transactions the verdict needs\n"
        "  --m1-require-mined-eviction                the verdict also needs a transaction to\n"
        "                                             have left the pool by being mined\n"
        "  --m1-require-conflict-eviction             ... and one to have left it because a block\n"
        "                                             spent its key image in another transaction\n"
        "  --m1-allow-uncompared <n>                  daemon pool ids allowed to stay uncompared\n"
        "                                             (default 0; raise it ONLY for a scenario\n"
        "                                             that holds a divergence on purpose)\n"
        "  --inject-dir <dir>                         feed <dir>/*.hex to C3 verbatim, and\n"
        "                                             <dir>/*.twin as its key-image twin\n"
        "\n"
        "  M4 (the parity soak; the posture is whatever --serve-arm says):\n"
        "  --m4-soak                                  run the two-posture soak driver\n"
        "  --m4-ledger <file>                         the M4 graduation ledger (persisted,\n"
        "                                             and the SAME file across both postures)\n"
        "  --m4-thresholds <stagenet|regtest>         72h/720-block, or the scaled mini-soak\n"
        "  --m4-min-clean <n>                         override: consecutive CLEAN samples\n"
        "  --m4-min-blocks <n>                        override: blocks inside the streak\n"
        "  --m4-min-seconds <n>                       override: wall clock of the streak\n"
        "  --m4-min-tip <n>                           override: clean P-TIP samples of it\n"
        "  --m4-min-tpl <n>                           override: clean P-TPL samples of it\n"
        "  --m4-max-void-run <n>                      consecutive VOIDs before the streak\n"
        "                                             is declared stalled and reset\n"
        "  --m4-serve-every <ms>                      P-TPL cadence (default 2000)\n"
        "  --m4-require graduated|refusal             exit non-zero unless the ledger\n"
        "                                             GRADUATED / unless it REFUSED\n"
        "  --m4-inject-field <name>                   NEGATIVE CONTROL: perturb this native\n"
        "                                             tip field by one unit\n"
        "  --m4-inject-after <n>                      ... only after n honest observations\n"
        "  --m4-inject-for <n>                        ... and only for n of them (0 = all)\n"
        "  --m4-inject-absent                         withhold the field instead\n";
}

void print_status(const rt::NodeStatus& s) {
    std::printf(
        "[status] h=%llu/%llu verified=%llu anchor=%llu synced=%d rows=%llu | "
        "alt=%llu orphans=%llu reorgs=%llu | "
        "peers=%zu/%zu silent=%zu | in: blocks=%llu chains=%llu objs=%llu txs=%llu | "
        "drv: chain=%llu boot=%llu refetch=%llu timeouts=%llu target=%s | "
        "q: verify=%zu/%llu pool=%zu/%llu refused=%llu | "
        "rx: mode=%d hashes=%llu rekeys=%llu foreign=%llu | rpc=%llu | tmpl=%s | "
        "txpool: gate=%d n=%llu acc=%llu rej=%llu\n",
        (unsigned long long)s.sync.header_frontier, (unsigned long long)s.sync.cohort_height,
        (unsigned long long)s.sync.verified_frontier, (unsigned long long)s.sync.anchor_height,
        s.sync.synced ? 1 : 0, (unsigned long long)s.sync.rows,
        (unsigned long long)s.sync.alt_rows, (unsigned long long)s.sync.orphans,
        (unsigned long long)s.sync.reorgs,
        s.pool.peers_handshaked, s.pool.peers_total, s.pool.relay_silent_peers,
        (unsigned long long)s.pool.blocks_in, (unsigned long long)s.pool.chain_entries_in,
        (unsigned long long)s.pool.objects_in, (unsigned long long)s.pool.txs_in,
        (unsigned long long)s.driver.chain_requests, (unsigned long long)s.driver.boot_requests,
        (unsigned long long)s.driver.refetch_requests,
        (unsigned long long)s.driver.chain_timeouts, s.driver.target.c_str(),
        s.verify_queue.depth, (unsigned long long)s.verify_queue.executed,
        s.pool_queue.depth, (unsigned long long)s.pool_queue.executed,
        (unsigned long long)(s.verify_queue.refused + s.inbound.refused),
        (int)s.randomx_mode, (unsigned long long)s.randomx.hashes,
        (unsigned long long)s.sync.seed_rekeys, (unsigned long long)s.randomx.foreign_calls,
        (unsigned long long)s.rpc_calls, s.template_arm.c_str(),
        s.txpool_gate_open ? 1 : 0, (unsigned long long)s.txpool.count,
        (unsigned long long)s.txpool.accepted, (unsigned long long)s.txpool.rejected);
    std::fflush(stdout);
}

void print_tip(const rt::TipRecord& r) {
    const std::string reorg =
        r.reorg ? (" REORG depth=" + std::to_string(r.reorg_depth)) : std::string();
    std::printf("[tip] height=%llu id=%s prev=%s difficulty=%s cumdiff=%s "
                "timestamp=%llu reward=%llu weight=%llu%s\n",
                (unsigned long long)r.height, hex(r.id).c_str(), hex(r.prev_id).c_str(),
                u128(r.difficulty).c_str(), u128(r.cumulative_difficulty).c_str(),
                (unsigned long long)r.timestamp, (unsigned long long)r.reward,
                (unsigned long long)r.weight, reorg.c_str());
    std::fflush(stdout);
}

} // namespace

int main(int argc, char** argv) {
    rt::NativeNodeConfig cfg;
    cfg.net          = rt::NativeNet::Stagenet;
    cfg.boot         = rt::BootMode::Genesis;
    std::uint64_t follow_to    = 0;
    std::uint64_t run_seconds  = 120;
    std::uint64_t status_every = 2000;

    bool          txpool_parity       = false;
    std::uint64_t txpool_parity_every = 1500;
    std::size_t   m1_min_txs          = 10;
    bool          m1_need_mined_evict    = false;
    bool          m1_need_conflict_evict = false;
    std::size_t   m1_allow_uncompared    = 0;
    std::string   inject_dir;

    // --- M4 ---------------------------------------------------------------
    bool          m4_soak        = false;
    std::string   m4_ledger_path;
    std::string   m4_threshold_set;          // "" = pick from --net
    std::uint64_t m4_serve_every = 2000;
    std::string   m4_require;                // "graduated" | "refusal" | ""
    parity::SoakThresholds m4_thr{};
    bool          m4_thr_chosen  = false;
    bool          m4_ov_clean = false, m4_ov_blocks = false, m4_ov_seconds = false;
    bool          m4_ov_tip = false, m4_ov_tpl = false, m4_ov_void = false;
    std::uint64_t m4_v_clean = 0, m4_v_blocks = 0, m4_v_seconds = 0;
    std::uint64_t m4_v_tip = 0, m4_v_tpl = 0, m4_v_void = 0;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "missing value for " << what << "\n";
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--help" || a == "-h") { usage(); return 0; }
        else if (a == "--net") {
            if (!rt::parse_native_net(next("--net"), cfg.net)) {
                std::cerr << "unknown network\n";
                return 2;
            }
        }
        else if (a == "--connect")       cfg.connect.push_back(next("--connect"));
        else if (a == "--p2p-bind-ip")   cfg.p2p_bind_ip = next("--p2p-bind-ip");
        else if (a == "--seeds")         cfg.use_seeds = true;
        else if (a == "--boot") {
            const std::string v = next("--boot");
            if (v == "genesis")     cfg.boot = rt::BootMode::Genesis;
            else if (v == "anchor") cfg.boot = rt::BootMode::Anchor;
            else { std::cerr << "unknown boot mode\n"; return 2; }
        }
        else if (a == "--anchor-path")   cfg.anchor_path = next("--anchor-path");
        else if (a == "--monerod-rpc") {
            if (!split_host_port(next("--monerod-rpc"), cfg.monerod_rpc_host,
                                 cfg.monerod_rpc_port)) {
                std::cerr << "--monerod-rpc wants host:port\n";
                return 2;
            }
        }
        else if (a == "--no-parity")     cfg.parity = false;
        else if (a == "--parity-ledger") cfg.parity_ledger_path = next("--parity-ledger");
        else if (a == "--commit")        cfg.c2pool_commit = next("--commit");
        else if (a == "--serve-arm") {
            const std::string v = next("--serve-arm");
            if (v == "native")       cfg.serve_arm = native::TemplateArm::Native;
            else if (v == "monerod") cfg.serve_arm = native::TemplateArm::Monerod;
            else { std::cerr << "unknown serve arm\n"; return 2; }
        }
        else if (a == "--relay-order") {
            const std::string v = next("--relay-order");
            if (v == "daemon-first")  cfg.relay_order = native::ArmOrder::DaemonFirst;
            else if (v == "parallel") cfg.relay_order = native::ArmOrder::Parallel;
            else if (v == "p2p-only") cfg.relay_order = native::ArmOrder::P2pOnly;
            else { std::cerr << "unknown relay order\n"; return 2; }
        }
        else if (a == "--follow-to")     follow_to    = std::strtoull(next("--follow-to").c_str(), nullptr, 10);
        else if (a == "--run-seconds")   run_seconds  = std::strtoull(next("--run-seconds").c_str(), nullptr, 10);
        else if (a == "--status-every")  status_every = std::strtoull(next("--status-every").c_str(), nullptr, 10);
        else if (a == "--txpool-parity") txpool_parity = true;
        else if (a == "--txpool-parity-every")
            txpool_parity_every = std::strtoull(next("--txpool-parity-every").c_str(), nullptr, 10);
        else if (a == "--m1-min-txs")
            m1_min_txs = static_cast<std::size_t>(
                std::strtoull(next("--m1-min-txs").c_str(), nullptr, 10));
        else if (a == "--m1-require-mined-eviction")    m1_need_mined_evict = true;
        else if (a == "--m1-require-conflict-eviction") m1_need_conflict_evict = true;
        else if (a == "--m1-allow-uncompared")
            m1_allow_uncompared = static_cast<std::size_t>(
                std::strtoull(next("--m1-allow-uncompared").c_str(), nullptr, 10));
        else if (a == "--inject-dir")    inject_dir = next("--inject-dir");
        else if (a == "--m4-soak")       m4_soak = true;
        else if (a == "--m4-ledger")     m4_ledger_path = next("--m4-ledger");
        else if (a == "--m4-thresholds") { m4_threshold_set = next("--m4-thresholds"); m4_thr_chosen = true; }
        else if (a == "--m4-min-clean")  { m4_ov_clean = true;  m4_v_clean   = std::strtoull(next("--m4-min-clean").c_str(), nullptr, 10); }
        else if (a == "--m4-min-blocks") { m4_ov_blocks = true; m4_v_blocks  = std::strtoull(next("--m4-min-blocks").c_str(), nullptr, 10); }
        else if (a == "--m4-min-seconds"){ m4_ov_seconds = true; m4_v_seconds = std::strtoull(next("--m4-min-seconds").c_str(), nullptr, 10); }
        else if (a == "--m4-min-tip")    { m4_ov_tip = true;    m4_v_tip     = std::strtoull(next("--m4-min-tip").c_str(), nullptr, 10); }
        else if (a == "--m4-min-tpl")    { m4_ov_tpl = true;    m4_v_tpl     = std::strtoull(next("--m4-min-tpl").c_str(), nullptr, 10); }
        else if (a == "--m4-max-void-run"){ m4_ov_void = true;  m4_v_void    = std::strtoull(next("--m4-max-void-run").c_str(), nullptr, 10); }
        else if (a == "--m4-serve-every") m4_serve_every = std::strtoull(next("--m4-serve-every").c_str(), nullptr, 10);
        else if (a == "--m4-require")    m4_require = next("--m4-require");
        else if (a == "--m4-inject-field")  cfg.tip_fault.field = next("--m4-inject-field");
        else if (a == "--m4-inject-after")
            cfg.tip_fault.after_samples = std::strtoull(next("--m4-inject-after").c_str(), nullptr, 10);
        else if (a == "--m4-inject-for")
            cfg.tip_fault.for_samples = std::strtoull(next("--m4-inject-for").c_str(), nullptr, 10);
        else if (a == "--m4-inject-absent") cfg.tip_fault.absent = true;
        else if (a == "--force-synced")  cfg.force_synced = true;
        else if (a == "--probe-only")    cfg.probe_only = true;
        else if (a == "--allow-unverified-pow") cfg.allow_unverified_pow = true;
        else { std::cerr << "unknown argument: " << a << "\n"; usage(); return 2; }
    }

    if (cfg.connect.empty() && !cfg.use_seeds) {
        std::cerr << "nothing to dial: pass --connect <ip:port> or --seeds\n";
        return 2;
    }
    if (txpool_parity && cfg.monerod_rpc_host.empty()) {
        std::cerr << "--txpool-parity needs a judge: pass --monerod-rpc host:port\n";
        return 2;
    }
    if (m4_soak) {
        if (cfg.monerod_rpc_host.empty()) {
            std::cerr << "--m4-soak needs the arm it is judged against: pass --monerod-rpc host:port\n";
            return 2;
        }
        if (!cfg.parity) {
            std::cerr << "--m4-soak and --no-parity are contradictory: the soak IS the oracle\n";
            return 2;
        }
        if (m4_ledger_path.empty()) {
            std::cerr << "--m4-soak needs --m4-ledger <file>: a graduation that is not "
                         "written down is a recollection\n";
            return 2;
        }
        if (!m4_require.empty() && m4_require != "graduated" && m4_require != "refusal") {
            std::cerr << "--m4-require wants 'graduated' or 'refusal'\n";
            return 2;
        }
        // The default threshold set follows the network, because getting this
        // wrong in the quiet direction is the only mistake that matters: a
        // stagenet run must never silently inherit the mini-soak's numbers.
        const std::string set = m4_thr_chosen ? m4_threshold_set
                              : (cfg.net == rt::NativeNet::Regtest ? "regtest" : "stagenet");
        if (set == "regtest")       m4_thr = parity::SoakThresholds::regtest_mini();
        else if (set == "stagenet") m4_thr = parity::SoakThresholds::stagenet_m4();
        else { std::cerr << "--m4-thresholds wants 'stagenet' or 'regtest'\n"; return 2; }
        if (m4_ov_clean)   m4_thr.min_clean_samples  = m4_v_clean;
        if (m4_ov_blocks)  m4_thr.min_blocks         = m4_v_blocks;
        if (m4_ov_seconds) m4_thr.min_seconds        = m4_v_seconds;
        if (m4_ov_tip)     m4_thr.min_tip_clean      = m4_v_tip;
        if (m4_ov_tpl)     m4_thr.min_template_clean = m4_v_tpl;
        if (m4_ov_void)    m4_thr.max_void_run       = m4_v_void;
    }
    if (cfg.tip_fault.armed() && !m4_soak) {
        std::cerr << "--m4-inject-field is the soak's negative control and only means "
                     "something with --m4-soak\n";
        return 2;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    rt::NativeNode node(cfg);
    std::string    why;
    std::printf("[node] net=%s wire-net=%d consensus-net=%s boot=%s peers=%zu "
                "parity=%d probe=%d\n",
                rt::to_string(cfg.net), (int)node.nets().wire,
                native::to_string(node.nets().consensus), rt::to_string(cfg.boot),
                cfg.connect.size(), cfg.parity ? 1 : 0, cfg.probe_only ? 1 : 0);
    if (!node.start(why)) {
        std::cerr << "[node] start refused: " << why << "\n";
        return 1;
    }

    const auto    t0 = std::chrono::steady_clock::now();
    std::uint64_t last_status = 0;
    std::size_t   tips_seen   = 0;
    std::uint64_t clean = 0, failed = 0, mismatch = 0, voided = 0;
    int exit_code = 0;

    // -----------------------------------------------------------------------
    // M4 state. Off by default; costs one branch when it is.
    //
    // The ledger is constructed here rather than inside the node because it
    // OUTLIVES a process: the two postures are two runs of this binary against
    // the same --m4-ledger file, which is exactly the shape a 72 h + 72 h
    // stagenet soak has. Persisting is therefore not an optimisation, it is the
    // mechanism by which a leg survives its own posture flip.
    // -----------------------------------------------------------------------
    auto unix_now = [] { return static_cast<std::uint64_t>(std::time(nullptr)); };
    native::GraduationKey m4_key;
    m4_key.c2pool_commit   = cfg.c2pool_commit;
    m4_key.monerod_version = "";               // bound on the daemon's first answer
    m4_key.net             = rt::to_string(cfg.net);
    parity::M4GraduationLedger m4_ledger(m4_key, m4_thr);
    parity::SoakDriver::Config m4_cfg;
    m4_cfg.posture = (cfg.serve_arm == native::TemplateArm::Native)
                       ? parity::SoakPosture::ServeNativeShadowMonerod
                       : parity::SoakPosture::ServeMonerodShadowNative;
    m4_cfg.ledger_path = m4_ledger_path;
    parity::SoakDriver m4(m4_ledger, m4_cfg);
    if (m4_soak) {
        std::string lwhy;
        const bool loaded = m4_ledger.load(m4_ledger_path, &lwhy);
        std::printf("[M4-SOAK] posture=%s thresholds: clean>=%llu blocks>=%llu seconds>=%llu "
                    "tip>=%llu tpl>=%llu void_run<=%llu | ledger=%s (%s)\n",
                    parity::posture_tag(m4_cfg.posture),
                    (unsigned long long)m4_thr.min_clean_samples,
                    (unsigned long long)m4_thr.min_blocks,
                    (unsigned long long)m4_thr.min_seconds,
                    (unsigned long long)m4_thr.min_tip_clean,
                    (unsigned long long)m4_thr.min_template_clean,
                    (unsigned long long)m4_thr.max_void_run,
                    m4_ledger_path.c_str(),
                    loaded ? "resumed" : (lwhy.empty() ? "new" : lwhy.c_str()));
    }
    std::uint64_t m4_last_serve = 0;
    std::uint64_t m4_serve_ok = 0, m4_serve_refused = 0;
    std::string   m4_last_serve_why;

    // ONE place where a drained batch is turned into numbers, because there are
    // now two callers (a tip moved; the M4 cadence fired) and two sets of
    // counters that must not diverge.
    auto absorb = [&](const std::vector<parity::SeamResult>& batch) {
        for (const parity::SeamResult& r : batch) {
            switch (r.sample.verdict) {
                case native::ParityVerdict::Clean:          ++clean;    break;
                case native::ParityVerdict::Fail:           ++failed;   break;
                case native::ParityVerdict::ServedMismatch: ++mismatch; break;
                case native::ParityVerdict::Void:           ++voided;   break;
            }
        }
        if (!m4_soak) return;
        for (const std::string& line : m4.ingest(batch, unix_now()))
            std::printf("%s\n", line.c_str());
    };

    // Draining is a function rather than a loop body because it has to happen
    // ONE MORE TIME after the exit condition fires: the tip that satisfied
    // --follow-to is normally recorded a few milliseconds after the read that
    // would have printed it, and a run that proved a height and then did not
    // say so is a run nobody can check.
    auto drain = [&] {
        const std::vector<rt::TipRecord> tips = node.tips();
        if (tips.size() > tips_seen) {
            for (std::size_t i = tips_seen; i < tips.size(); ++i) print_tip(tips[i]);
            tips_seen = tips.size();
            // The oracle renders every sample through its own log sink, which
            // is drained just below -- printing it here as well would double
            // every line.
            absorb(node.parity_sample());
        }
        for (const std::string& line : node.take_log()) std::printf("%s\n", line.c_str());
        std::fflush(stdout);
    };

    // The M4 tick: serve a template from the POSTURE'S arm (which is what makes
    // P-TPL fire at all -- nothing else in this binary calls on_serve), then
    // drain. It runs on its own cadence rather than on tip events because a
    // chain that has gone quiet must still produce samples, or "no samples"
    // would be indistinguishable from "agreement".
    auto m4_tick = [&] {
        const rt::NativeNode::ServeProbe p = node.m4_serve_probe();
        if (p.served) {
            ++m4_serve_ok;
        } else {
            ++m4_serve_refused;
            if (p.why != m4_last_serve_why) {
                m4_last_serve_why = p.why;
                std::printf("[M4-SOAK] serving arm '%s' produced no template: %s\n",
                            p.arm.empty() ? "?" : p.arm.c_str(), p.why.c_str());
            }
        }
        if (parity::MonerodTipObserver* mt = node.monerod_tip())
            m4_ledger.bind_monerod_version(mt->daemon_version(), unix_now());
        absorb(node.parity_sample());
        std::fflush(stdout);
    };

    // -----------------------------------------------------------------------
    // M1 state. Everything below is off by default and costs nothing when it is.
    // -----------------------------------------------------------------------
    std::uint64_t last_pool_probe = 0;
    std::uint64_t last_inject_scan = 0;
    std::uint64_t pool_samples_printed = 0;
    // The pool as it stood at the previous probe, and the tip it stood at:
    // what an eviction is measured against.
    std::set<native::Hash> prev_pool_ids;
    std::uint64_t          prev_pool_height = 0;
    bool                   have_prev_pool   = false;
    std::uint64_t prev_evicted_mined = 0, prev_evicted_conflict = 0;
    std::uint64_t mined_evictions = 0, conflict_evictions = 0;
    std::uint64_t conflict_rejections = 0, injected = 0, injected_accepted = 0;
    std::uint64_t incoherent_samples = 0;

    auto probe_txpool = [&] {
        const parity::TxpoolParityReport rep = node.txpool_parity_sample();
        if (!rep.judged) {
            ++incoherent_samples;
            if (pool_samples_printed < 6)
                std::printf("[XMR-PARITY] seam=POOL h=%llu verdict=UNJUDGED note=\"%s\"\n",
                            (unsigned long long)rep.height, rep.why.c_str());
            ++pool_samples_printed;
            std::fflush(stdout);
            return;
        }

        // What left OUR pool since the previous probe, and why the pool says it
        // did. The set difference is the observation; the counters are the
        // pool's own account of the same event, and a proof needs both -- a
        // counter with no id behind it names nothing, and an id that vanished
        // with no counter behind it could have been evicted for size or age.
        const native::TxpoolStats st = node.status().txpool;
        const std::uint64_t d_mined    = st.evicted_mined - prev_evicted_mined;
        const std::uint64_t d_conflict = st.evicted_conflict - prev_evicted_conflict;
        prev_evicted_mined    = st.evicted_mined;
        prev_evicted_conflict = st.evicted_conflict;
        mined_evictions    += d_mined;
        conflict_evictions += d_conflict;

        std::set<native::Hash> now_ids(rep.native_ids.begin(), rep.native_ids.end());

        if ((d_mined != 0 || d_conflict != 0) && have_prev_pool) {
            std::string gone;
            std::size_t n_gone = 0;
            for (const native::Hash& h : prev_pool_ids) {
                if (now_ids.count(h)) continue;
                ++n_gone;
                if (n_gone <= 4) gone += (gone.empty() ? "" : ",") + hex(h).substr(0, 16);
            }
            std::printf("[M1-EVICT] h=%llu->%llu left_pool=%zu mined=%llu conflict=%llu ids=%s\n",
                        (unsigned long long)prev_pool_height, (unsigned long long)rep.height,
                        n_gone, (unsigned long long)d_mined, (unsigned long long)d_conflict,
                        gone.empty() ? "-" : gone.c_str());
        }
        prev_pool_ids    = std::move(now_ids);
        prev_pool_height = rep.height;
        have_prev_pool   = true;

        const bool notable = !rep.all_equal() || rep.voided != 0;
        if (notable || pool_samples_printed < 6 || !rep.samples.empty()) {
            std::printf("[XMR-PARITY] seam=POOL h=%llu verdict=%s ours=%zu theirs=%zu "
                        "compared=%zu clean=%zu fail=%zu fields=%zu/%zu "
                        "ours_only=%zu theirs_only=%zu\n",
                        (unsigned long long)rep.height,
                        rep.samples.empty() ? "NO-SAMPLES"
                                            : (rep.all_equal() ? "CLEAN" : "FAIL"),
                        rep.native_count, rep.monerod_count, rep.samples.size(),
                        rep.clean, rep.fail, rep.fields_equal, rep.fields_compared,
                        rep.ours_only.size(), rep.theirs_only.size());
            for (const parity::SeamResult& r : rep.samples) {
                if (r.sample.verdict == native::ParityVerdict::Clean) continue;
                std::printf("             tx verdict=%s note=\"%s\"\n",
                            parity::to_string(r.sample.verdict), r.sample.note.c_str());
                for (const native::FieldDiff& d : r.sample.fields)
                    std::printf("               %-12s served=%s shadow=%s\n",
                                d.field.c_str(), d.served.c_str(), d.shadow.c_str());
            }
        }
        ++pool_samples_printed;
        std::fflush(stdout);
    };

    // The injection seam: a directory of hex blobs, each fed to C3 exactly once.
    //
    // `.twin` is the key-image twin construction, done HERE rather than in a
    // script because it needs the real decoder: tx_extra is the tail of the
    // transaction prefix and only a parse knows where that tail begins. One
    // byte of it is flipped, which leaves every key image, every commitment and
    // the range proof untouched while changing the id -- the adversarial object
    // C3's first-seen-wins rule exists to refuse, built from a transaction a
    // real wallet really signed.
    auto make_twin = [](const std::vector<std::uint8_t>& blob,
                        std::vector<std::uint8_t>& out, std::string& why) -> bool {
        native::DecodedTx d;
        const native::TxDecodeStatus st = native::decode_relayed_tx(blob, d);
        if (st != native::TxDecodeStatus::Ok) {
            why = std::string("decode: ") + native::to_string(st);
            return false;
        }
        if (d.w.extra_size == 0 || d.prefix_size < d.w.extra_size) {
            why = "the transaction has no tx_extra to mutate";
            return false;
        }
        out = blob;
        out[d.prefix_size - d.w.extra_size] ^= 0x01;
        return true;
    };

    auto scan_inject_dir = [&] {
        DIR* d = ::opendir(inject_dir.c_str());
        if (d == nullptr) return;
        std::vector<std::string> names;
        for (dirent* e = ::readdir(d); e != nullptr; e = ::readdir(d)) {
            const std::string n = e->d_name;
            const bool is_hex  = n.size() > 4 && n.compare(n.size() - 4, 4, ".hex") == 0;
            const bool is_twin = n.size() > 5 && n.compare(n.size() - 5, 5, ".twin") == 0;
            if (is_hex || is_twin) names.push_back(n);
        }
        ::closedir(d);
        std::sort(names.begin(), names.end());
        for (const std::string& n : names) {
            const std::string path = inject_dir + "/" + n;
            std::FILE* f = std::fopen(path.c_str(), "rb");
            if (f == nullptr) continue;
            std::string hexs;
            char buf[65536];
            std::size_t got = 0;
            while ((got = std::fread(buf, 1, sizeof(buf), f)) > 0) hexs.append(buf, got);
            std::fclose(f);
            while (!hexs.empty() && (hexs.back() == '\n' || hexs.back() == '\r' ||
                                     hexs.back() == ' '  || hexs.back() == '\t'))
                hexs.pop_back();
            // Rename FIRST. A blob that crashed the decoder must not be fed to
            // it again on the next tick, forever.
            std::rename(path.c_str(), (path + ".done").c_str());
            std::vector<std::uint8_t> blob;
            if (!from_hex(hexs, blob)) {
                std::printf("[M1-INJECT] %s: not hex (%zu chars)\n", n.c_str(), hexs.size());
                continue;
            }
            const bool want_twin = n.size() > 5 && n.compare(n.size() - 5, 5, ".twin") == 0;
            if (want_twin) {
                std::vector<std::uint8_t> twin;
                std::string twin_why;
                if (!make_twin(blob, twin, twin_why)) {
                    std::printf("[M1-INJECT] %s: no twin -- %s\n", n.c_str(), twin_why.c_str());
                    continue;
                }
                std::printf("[M1-INJECT] %s: injecting the KEY-IMAGE TWIN of the blob "
                            "(one tx_extra byte flipped; same key images, new id)\n", n.c_str());
                blob.swap(twin);
            }
            const native::TxRelayVerdict v = node.inject_relayed(blob, /*peer_id=*/0xC2000001ull);
            ++injected;
            if (v.reason == native::TxRelayVerdict::Reason::Accepted) ++injected_accepted;
            if (v.reason == native::TxRelayVerdict::Reason::KeyImageConflict)
                ++conflict_rejections;
            std::printf("[M1-INJECT] %s bytes=%zu verdict=%s drop_offense=%d id=%s\n",
                        n.c_str(), blob.size(), native::to_string(v.reason),
                        v.drop_offense ? 1 : 0, hex(v.id).c_str());
            std::fflush(stdout);
        }
    };

    for (;;) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto now = std::chrono::steady_clock::now();
        const std::uint64_t elapsed_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count());

        drain();

        if (elapsed_ms - last_status >= status_every) {
            last_status = elapsed_ms;
            print_status(node.status());
        }

        if (!inject_dir.empty() && elapsed_ms - last_inject_scan >= 250) {
            last_inject_scan = elapsed_ms;
            scan_inject_dir();
        }
        if (txpool_parity && elapsed_ms - last_pool_probe >= txpool_parity_every) {
            last_pool_probe = elapsed_ms;
            probe_txpool();
        }
        if (m4_soak && elapsed_ms - m4_last_serve >= m4_serve_every) {
            m4_last_serve = elapsed_ms;
            m4_tick();
        }

        // --- exit conditions ---------------------------------------------------
        if (g_stop) break;
        if (cfg.probe_only) {
            const rt::NodeStatus s = node.status();
            if (s.boot.last_entry.have) break;
            if (elapsed_ms > 30'000) { exit_code = 1; break; }
        }
        if (follow_to != 0) {
            const rt::NodeStatus s = node.status();
            if (s.sync.header_frontier >= follow_to) break;
        }
        if (elapsed_ms >= run_seconds * 1000) {
            if (follow_to != 0) exit_code = 1;
            break;
        }
    }

    drain();
    const rt::NodeStatus s = node.status();
    print_status(s);

    std::printf("\n=== summary ===\n");
    std::printf("tip            : height=%llu verified_frontier=%llu rows=%llu synced=%d "
                "alt=%llu orphans=%llu reorgs=%llu\n",
                (unsigned long long)s.sync.header_frontier,
                (unsigned long long)s.sync.verified_frontier,
                (unsigned long long)s.sync.rows, s.sync.synced ? 1 : 0,
                (unsigned long long)s.sync.alt_rows, (unsigned long long)s.sync.orphans,
                (unsigned long long)s.sync.reorgs);
    std::printf("boot           : %s booted=%d inspected=%llu refusals=%llu dropped=%llu (%s)\n",
                rt::to_string(cfg.boot), s.boot.booted ? 1 : 0,
                (unsigned long long)s.boot.blobs_inspected,
                (unsigned long long)s.boot.refusals,
                (unsigned long long)s.boot.dropped_preboot, s.boot.why.c_str());
    if (s.boot.last_entry.have) {
        std::printf("chain-entry    : start=%llu total=%llu ids=%zu first=%s last=%s "
                    "first_block=%d/%zu bytes\n",
                    (unsigned long long)s.boot.last_entry.start_height,
                    (unsigned long long)s.boot.last_entry.total_height,
                    s.boot.last_entry.ids, hex(s.boot.last_entry.first_id).c_str(),
                    hex(s.boot.last_entry.last_id).c_str(),
                    s.boot.last_entry.first_block_present ? 1 : 0,
                    s.boot.last_entry.first_block_size);
    }
    std::printf("peers          : handshaked=%zu total=%zu netgroups=%zu silent=%zu "
                "handshakes=%llu dials=%llu/%llu last_close=%s (%s)\n",
                s.pool.peers_handshaked, s.pool.peers_total, s.pool.netgroups,
                s.pool.relay_silent_peers, (unsigned long long)s.pool.handshakes,
                (unsigned long long)s.pool.dials_started,
                (unsigned long long)s.pool.dials_failed,
                s.pool.last_close_peer.c_str(), s.pool.last_close_why.c_str());
    std::printf("levin in       : blocks=%llu chain_entries=%llu objects=%llu txs=%llu "
                "frames=%llu dos_drops=%llu\n",
                (unsigned long long)s.pool.blocks_in,
                (unsigned long long)s.pool.chain_entries_in,
                (unsigned long long)s.pool.objects_in, (unsigned long long)s.pool.txs_in,
                (unsigned long long)s.pool.frames_in,
                (unsigned long long)s.pool.frames_dropped_dos);
    std::printf("levin served   : chain=%llu objects=%llu fluffy=%llu declined=%llu\n",
                (unsigned long long)s.pool.served_chain,
                (unsigned long long)s.pool.served_objects,
                (unsigned long long)s.pool.served_fluffy,
                (unsigned long long)s.pool.served_declined);
    if (s.randomx_mode == native::RandomXMode::Disabled)
        std::printf("randomx        : NOT COMPILED IN -- every block above connected "
                    "WITHOUT a proof-of-work check\n");
    std::printf("randomx        : mode=%d hashes=%llu prefetches=%llu rekeys=%llu "
                "verified=%llu failed=%llu foreign=%llu threads=",
                (int)s.randomx_mode, (unsigned long long)s.randomx.hashes,
                (unsigned long long)s.randomx.prefetches,
                (unsigned long long)s.sync.seed_rekeys,
                (unsigned long long)s.sync.pow_verified,
                (unsigned long long)s.sync.pow_failed,
                (unsigned long long)s.randomx.foreign_calls);
    for (const std::string& t : s.randomx.threads) std::printf("%s ", t.c_str());
    std::printf("\n");
    std::printf("threads        : io=%s verify=%s\n", s.io_threads.c_str(),
                s.verify_thread.c_str());
    std::printf("monerod rpc    : calls=%llu (parity/bootstrap only; never on the "
                "tip-follow path)\n", (unsigned long long)s.rpc_calls);
    std::printf("parity         : clean=%llu fail=%llu served_mismatch=%llu void=%llu\n",
                (unsigned long long)clean, (unsigned long long)failed,
                (unsigned long long)mismatch, (unsigned long long)voided);
    if (node.oracle())
        std::printf("%s\n", node.oracle()->verdict_report().c_str());

    // --- M1 ----------------------------------------------------------------
    bool m1_ok = true;
    if (txpool_parity) {
        // One last probe: the tail of a run is where the pool is emptiest and a
        // sample taken after the last block is what makes the two pools agree
        // on a SET rather than merely on their intersection.
        probe_txpool();
        const parity::TxpoolParityTally& t = node.txpool_tally();
        std::printf("\n=== M1: txpool parity (P-POOL) ===\n");
        std::printf("samples        : judged=%llu unjudged=%llu aligned=%llu no-samples=%llu "
                    "(polls=%llu)\n",
                    (unsigned long long)t.samples(), (unsigned long long)t.unjudged(),
                    (unsigned long long)t.aligned_samples(),
                    (unsigned long long)t.empty_samples(), (unsigned long long)t.polls());
        std::printf("transactions   : distinct_compared=%zu daemon_ids_seen=%zu "
                    "never_compared=%zu | pool_max ours=%zu theirs=%zu\n",
                    t.distinct_txs_compared(), t.distinct_daemon_ids(),
                    t.never_compared().size(), t.native_pool_max(), t.monerod_pool_max());
        std::printf("per-tx verdicts: clean=%llu fail=%llu served_mismatch=%llu void=%llu\n",
                    (unsigned long long)t.clean(), (unsigned long long)t.failed(),
                    (unsigned long long)t.served_mismatch(), (unsigned long long)t.voided());
        std::printf("fields         : compared=%llu equal=%llu differed=%llu absent=%llu "
                    "(weight, fee, blob_size per transaction; tx_id is the alignment key)\n",
                    (unsigned long long)t.fields_compared(),
                    (unsigned long long)t.fields_equal(),
                    (unsigned long long)t.fields_differed(),
                    (unsigned long long)t.fields_absent());
        std::printf("evictions      : mined=%llu key_image_conflict=%llu\n",
                    (unsigned long long)mined_evictions,
                    (unsigned long long)conflict_evictions);
        std::printf("conflicts      : rejected_key_image=%llu (of which injected=%llu) | "
                    "injected=%llu accepted=%llu\n",
                    (unsigned long long)s.txpool.rejected_key_image_conflict,
                    (unsigned long long)conflict_rejections,
                    (unsigned long long)injected, (unsigned long long)injected_accepted);
        std::printf("txpool         : count=%llu bytes=%llu accepted=%llu duplicates=%llu "
                    "rejected=%llu evicted(age=%llu cap=%llu)\n",
                    (unsigned long long)s.txpool.count, (unsigned long long)s.txpool.bytes,
                    (unsigned long long)s.txpool.accepted,
                    (unsigned long long)s.txpool.duplicates,
                    (unsigned long long)s.txpool.rejected,
                    (unsigned long long)s.txpool.evicted_age,
                    (unsigned long long)s.txpool.evicted_cap);
        std::printf("dos            : frames_in=%llu dropped=%llu (the buckets are charged on "
                    "every inbound frame; a drop here is the guard, not a loss)\n",
                    (unsigned long long)s.pool.frames_in,
                    (unsigned long long)s.pool.frames_dropped_dos);

        // TWO KINDS OF RUN, and the verdict must not confuse them.
        //
        // A PARITY run (--m1-min-txs > 0) claims coverage: so many distinct
        // transactions compared, every daemon id eventually compared, at least
        // one aligned sample, no disagreement. The full gate applies.
        //
        // A SCENARIO run (--m1-min-txs 0) claims one specific mechanism -- the
        // key-image-conflict proof deliberately makes the two pools hold
        // different members of one double spend, so it compares almost nothing
        // and must not pretend otherwise. It asserts only that nothing judged
        // disagreed, plus whatever eviction it explicitly required. A scenario
        // run that required no eviction asserts nothing at all, and that is a
        // FAIL rather than a free pass.
        std::string m1_why;
        if (m1_min_txs > 0) {
            m1_ok = t.passes(m1_min_txs, m1_allow_uncompared, m1_why);
        } else {
            std::printf("scope          : SCENARIO run -- parity coverage is NOT claimed "
                        "(--m1-min-txs 0); the verdict rests on the required eviction(s)\n");
            m1_ok = t.no_disagreement(m1_why);
            if (m1_ok && !m1_need_mined_evict && !m1_need_conflict_evict) {
                m1_ok  = false;
                m1_why = "a scenario run must require an eviction, or it asserts nothing";
            }
        }
        if (m1_ok && m1_need_mined_evict && mined_evictions == 0) {
            m1_ok  = false;
            m1_why = "no mined eviction was observed";
        }
        if (m1_ok && m1_need_conflict_evict && conflict_evictions == 0) {
            m1_ok  = false;
            m1_why = "no key-image-conflict eviction was observed";
        }
        const std::vector<native::Hash> missed = t.never_compared();
        for (std::size_t i = 0; i < missed.size() && i < 8; ++i)
            std::printf("never-compared : %s\n", hex(missed[i]).c_str());
        std::printf("M1-VERDICT: %s txs_compared=%zu all_equal=%d fields=%llu/%llu "
                    "mined_evictions=%llu conflict_evictions=%llu never_compared=%zu%s%s\n",
                    m1_ok ? "PASS" : "FAIL", t.distinct_txs_compared(),
                    (t.fields_differed() == 0 && t.fields_absent() == 0) ? 1 : 0,
                    (unsigned long long)t.fields_equal(),
                    (unsigned long long)t.fields_compared(),
                    (unsigned long long)mined_evictions,
                    (unsigned long long)conflict_evictions, missed.size(),
                    m1_why.empty() ? "" : " why=", m1_why.c_str());
    }

    // --- M4 ----------------------------------------------------------------
    //
    // TWO KINDS OF RUN, and as with M1 the verdict must not confuse them.
    //
    // An HONEST run (--m4-require graduated) claims the posture soaked clean and
    // is judged on the ledger reaching GRADUATED.
    //
    // A REFUSAL run (--m4-require refusal) is the negative control: it injects a
    // divergence on purpose and its claim is the OPPOSITE one -- the ledger must
    // NOT graduate, and it must have reset a streak on a real FAIL rather than
    // merely failed to accumulate one. A refusal run that graduated is a broken
    // gate; a refusal run whose injection never fired asserts nothing, and both
    // are FAIL here.
    bool m4_ok = true;
    if (m4_soak) {
        // One last tick, for the same reason M1 takes one last pool sample: the
        // tail of a run is where the last template lives.
        m4_tick();
        std::string swhy;
        if (!m4.save(&swhy) && !swhy.empty()) std::printf("[M4-SOAK] %s\n", swhy.c_str());

        std::printf("\n=== M4: two-posture parity soak ===\n");
        std::printf("drains         : %llu (of which produced no sample: %llu)\n",
                    (unsigned long long)m4.drains(),
                    (unsigned long long)m4_ledger.no_sample_drains(m4_cfg.posture));
        std::printf("template probe : served=%llu refused=%llu%s%s\n",
                    (unsigned long long)m4_serve_ok,
                    (unsigned long long)m4_serve_refused,
                    m4_last_serve_why.empty() ? "" : " last_refusal=",
                    m4_last_serve_why.c_str());
        if (parity::PerturbingTipObserver* inj = node.tip_fault())
            std::printf("injection      : ARMED field='%s' observations=%llu perturbed=%llu "
                        "(this run is a REFUSAL EXPERIMENT)\n",
                        cfg.tip_fault.field.c_str(),
                        (unsigned long long)inj->observations(),
                        (unsigned long long)inj->injected());
        std::printf("%s", m4_ledger.report().c_str());
        for (const parity::SoakEntry& e : m4.failures())
            std::printf("failure        : %s\n", e.render().c_str());
        std::printf("%s\n", m4.verdict_line().c_str());

        const parity::PostureLeg& L = m4_ledger.leg(m4_cfg.posture);
        std::string m4_why;
        if (m4_require == "graduated") {
            m4_ok = m4_ledger.graduated();
            if (!m4_ok) {
                const std::vector<std::string> sf = m4_ledger.shortfalls();
                m4_why = sf.empty() ? "not graduated" : sf.front();
            }
        } else if (m4_require == "refusal") {
            if (m4_ledger.graduated()) {
                m4_ok = false;
                m4_why = "the ledger GRADUATED under an injected divergence";
            } else if (L.fail == 0 && L.served_mismatch == 0) {
                m4_ok = false;
                m4_why = "no sample ever FAILED: the injection did not reach the comparator, "
                         "so this run refuses nothing";
            } else if (L.resets == 0) {
                m4_ok = false;
                m4_why = "a sample failed but no streak was reset";
            }
        }
        std::printf("M4-RUN: %s require=%s graduated=%d fail=%llu resets=%llu%s%s\n",
                    m4_ok ? "PASS" : "FAIL",
                    m4_require.empty() ? "-" : m4_require.c_str(),
                    m4_ledger.graduated() ? 1 : 0,
                    (unsigned long long)L.fail, (unsigned long long)L.resets,
                    m4_why.empty() ? "" : " why=", m4_why.c_str());
    }

    // The M0 verdict, in one line a script can grep.
    //
    // A REFUSAL run breaks the M0 line's premise on purpose -- it is engineered
    // to produce parity failures -- so the M0 gate reads the injection out of
    // the totals rather than reporting a lost claim it never made.
    const bool refusal_run = m4_soak && m4_require == "refusal";
    const bool ok = (exit_code == 0) && (refusal_run || (failed == 0 && mismatch == 0)) &&
                    s.randomx.foreign_calls == 0 && m1_ok && m4_ok;
    std::printf("M0-VERDICT: %s heights=%zu parity_clean=%llu parity_fail=%llu "
                "randomx_foreign=%llu%s\n",
                ok ? "PASS" : "FAIL", tips_seen, (unsigned long long)clean,
                (unsigned long long)(failed + mismatch),
                (unsigned long long)s.randomx.foreign_calls,
                refusal_run ? " (REFUSAL RUN: parity failures are the point)" : "");

    node.stop();
    return ok ? 0 : 1;
}
