// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/test/v37_xmr_follow_only_kat.cpp
// --follow-only (c2pool/v37/xmr/pathb/pathb_follow_only.hpp,
// pathb_follow_template.hpp), with the shared selection, the status lines and
// the stratum hooks:
//   refusals  (a) follow_only_refusal: one case per refused input, its fixed
//             text; the allowed configurations (mainnet with
//             --i-understand-mainnet); mainnet without the fence refused inside
//             the function with master's text; without --follow-only none
//   solo      solo_refusal: --relay-listen, --relay-peer refused
//   plan      (b) run_plan_of: the native node, the follower adapter, the
//             template routine, serve_follow_only, the status lines; no
//             PathbNode, store, relay, stratum, miner, publisher, monerod
//             transport
//   native    (c) after apply_follow_only: no monerod host or port, relay order
//             P2pOnly, fallback off, template source native, arm order
//             p2p-first (none given); the warm timeout forwarded
//   equiv     (d) the record equals PathbNode::make_template at x = 1 with
//             --pathb-launch on a raw regtest genesis (gap <= Fresh, the
//             empty window): h, P_r, hf, B, Z, the transactions, T, F, R, c,
//             txset; c is the size of the node's miner tx; plain, varint-
//             crossing and penalty-zone vectors, with and without
//             --pathb-penalty-fill
//   restart   (e) a cold pool: none reason=pool-cold, no record; the first
//             record after the complement answer holds its k > 0
//             transactions (warm=complement); without an answer the record
//             after the timeout says warm=timeout
//   forkfuse  (f) hf 17: none reason=fork-fuse hf=17
//   weights   (g) no weights_at(P_r): none reason=missing-weights
//   lines     the start, follow, template, compare and status lines; the
//             follow-only directory
//   hooks     the login hook, the login reply's c2pool object, the stratum
//             budget from d_at
//   reorglines  a reorg: one follow line per block of the new branch
// ---------------------------------------------------------------------------
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/pathb/pathb_follow_only.hpp"
#include "c2pool/v37/xmr/pathb/pathb_follow_template.hpp"
#include "c2pool/v37/xmr/pathb/pathb_startup.hpp"
#include "c2pool/v37/xmr/pathb/pathb_status.hpp"
#include "c2pool/v37/xmr/pathb/pathb_stratum_hooks.hpp"
#include "c2pool/v37/xmr/xmr_native_template_backend.hpp"
#include "pathb_kat_node.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

namespace xn = ::c2pool::v37n::xmr;
namespace pm = ::c2pool::v37n::xmr::pathb_mode;
namespace o2 = ::c2pool::v37n::xmr::o2;
namespace st = ::c2pool::xmr::pathb::stratum;
namespace nrt = ::c2pool::xmr::native::rt;

void give(xn::XmrNodeConfig& c, const std::string& name, const std::string& value = {}) {
    c.given_flags.push_back(xn::GivenFlag{name, value});
}

// --follow-only with a levin peer, the entry effects applied.
xn::XmrNodeConfig fo_base(xn::MoneroNetwork net = xn::MoneroNetwork::Regtest) {
    xn::XmrNodeConfig c;
    c.network = net;
    give(c, "--network", xn::to_string(net));
    if (net == xn::MoneroNetwork::Mainnet) {
        c.i_understand_mainnet = true;
        give(c, "--i-understand-mainnet");
    }
    c.follow_only = true;
    give(c, "--follow-only");
    c.native_connect.push_back("127.0.0.1:18080");
    give(c, "--native-connect", "127.0.0.1:18080");
    pm::apply_follow_only(c);
    return c;
}

std::string fo(const std::string& input) { return "--follow-only refuses " + input; }

const std::vector<std::string> kStratumFlags = {
        "--stratum-port",       "--stratum-bind-host",   "--stratum-ban-seconds",  "--stratum-login-timeout-ms",
        "--stratum-share-rate", "--stratum-share-score", "--stratum-submit-burst", "--stratum-vardiff-shares",
        "--stratum-min-diff-shift",
};

const std::vector<std::string> kPoolFlags = {
        "--pathb-launch",          "--vote",                  "--journal-depth",         "--pathb-body-keep",
        "--pathb-header-keep",     "--pathb-side-keep",       "--pathb-key-cache-mb",    "--pathb-abandon-timeout",
        "--pathb-waiting-cap",     "--pathb-bucket-serve-cap", "--pathb-claim-alarm-rate", "--pathb-bucket-frame",
        "--join-min-peers",        "--pathb-bucket-inflight", "--pathb-bucket-rate",     "--pathb-deployments",
};

const std::vector<std::string> kMineFlags = {
        "--mine", "--mine-threads", "--mine-fast", "--mine-msr", "--mine-no-affinity", "--mine-no-huge-pages",
};

const std::vector<std::string> kRelayFlags = {
        "--relay-listen",          "--relay-peer",            "--relay-backfill-positions", "--relay-ban-seconds",
        "--relay-bin-grace-ms",    "--relay-bin-lag",         "--relay-bind",               "--relay-deep-order",
        "--relay-deep-probe-step", "--relay-discovery",       "--relay-feed-monerod-compare", "--relay-index-horizon",
        "--relay-keepalive-ms",    "--relay-max-inbound",     "--relay-max-outbound",       "--relay-max-peers",
        "--relay-order",           "--relay-parked-max",      "--relay-reoffer-seconds",    "--relay-rx-budget",
        "--relay-rx-global",       "--relay-shadow-persist",  "--relay-shadow-persist-bytes", "--relay-silence-timeout-ms",
        "--relay-solicited-credits", "--relay-test-partition-seconds", "--relay-vault-bytes", "--relay-vault-entries",
        "--relay-vault-horizon",   "--relay-verify-threads",  "--no-relay-bootstrap",       "--no-relay-serve",
};

struct Input {
    std::string name;
    std::function<void(xn::XmrNodeConfig&)> set;
    std::string text;
};

std::vector<Input> refused_inputs() {
    std::vector<Input> v;
    const auto flag = [&v](const std::string& f, const std::string& value = "1") {
        v.push_back({f, [f, value](xn::XmrNodeConfig& c) { give(c, f, value); }, fo(f)});
    };
    // the pool identity
    flag("--pool-genesis-from", "3000:00:\"x\"");
    flag("--pool-genesis", "00:3000");
    flag("--pool-genesis-height", "3000");
    // the pool start and the pool policy
    for (const std::string& f : kPoolFlags) flag(f, f == "--pathb-launch" ? "" : "1");
    // mining and serving
    for (const std::string& f : kMineFlags) flag(f, f == "--mine" ? "" : "1");
    v.push_back({"mine_enabled", [](xn::XmrNodeConfig& c) { c.mine_enabled = true; }, fo("--mine")});
    for (const std::string& f : kStratumFlags) flag(f);
    flag("--payout-address", "x");
    v.push_back({"payout_address", [](xn::XmrNodeConfig& c) { c.payout_address = "x"; }, fo("--payout-address")});
    flag("--give-author-pct", "0.1");
    flag("--node-owner-fee-pct", "1");
    flag("--node-owner-address", "x");
    // the Path B relay
    for (const std::string& f : kRelayFlags) flag(f);
    v.push_back({"relay_listen", [](xn::XmrNodeConfig& c) { c.relay_listen = "0.0.0.0:37889"; }, fo("--relay-listen")});
    v.push_back({"relay_peers", [](xn::XmrNodeConfig& c) { c.relay_peers.push_back("192.0.2.1:37889"); }, fo("--relay-peer")});
    // monerod
    flag("--native-parity-monerod", "");
    v.push_back({"native_parity_monerod", [](xn::XmrNodeConfig& c) { c.native_parity_monerod = true; },
                 fo("--native-parity-monerod")});
    v.push_back({"--xmr-template-source monerod", [](xn::XmrNodeConfig& c) { give(c, "--xmr-template-source", "monerod"); },
                 fo("--xmr-template-source monerod")});
    v.push_back({"--arm-order daemon-first", [](xn::XmrNodeConfig& c) { give(c, "--arm-order", "daemon-first"); },
                 fo("--arm-order daemon-first")});
    flag("--native-template-fallback", "on");
    v.push_back({"--native-template-fallback off", [](xn::XmrNodeConfig& c) { give(c, "--native-template-fallback", "off"); },
                 fo("--native-template-fallback")});
    flag("--rpc-host", "127.0.0.1");
    flag("--rpc-port", "18081");
    flag("--zmq-port", "18083");
    for (const std::string value : {"monerod", "v37", "x", ""})
        v.push_back({"--coinbase " + value, [value](xn::XmrNodeConfig& c) { give(c, "--coinbase", value); },
                     "--coinbase: removed at the S4w flag day"});
    // the evidence inputs
    flag("--native-solo", "");
    v.push_back({"native_solo", [](xn::XmrNodeConfig& c) { c.native_solo = true; }, fo("--native-solo")});
    flag("--native-force-synced", "");
    v.push_back({"native_force_synced", [](xn::XmrNodeConfig& c) { c.native_force_synced = true; },
                 fo("--native-force-synced")});
    flag("--native-allow-unverified-pow", "");
    v.push_back({"native_allow_unverified_pow", [](xn::XmrNodeConfig& c) { c.native_allow_unverified_pow = true; },
                 fo("--native-allow-unverified-pow")});
    flag("--no-good-citizen", "");
    v.push_back({"no_good_citizen", [](xn::XmrNodeConfig& c) { c.no_good_citizen = true; }, fo("--no-good-citizen")});
    flag("--native-inject", "");
    flag("--native-inject-dir", "/tmp/x");
    flag("--native-inject-hex", "/tmp/x");
    flag("--native-inject-ttl-blocks", "10");
    v.push_back({"native_inject", [](xn::XmrNodeConfig& c) { c.native_inject = true; }, fo("--native-inject")});
    v.push_back({"--native-txpool-warm-timeout-ms 0",
                 [](xn::XmrNodeConfig& c) {
                     give(c, "--native-txpool-warm-timeout-ms", "0");
                     c.native_txpool_warm_timeout_ms = 0;
                 },
                 fo("--native-txpool-warm-timeout-ms 0")});
    return v;
}

// ---------------------------------------------------------------------------
void refusals() {
    // the S4w-a flag names are in the lists; --pathb-penalty-fill is not
    const auto listed = [](std::string_view f) {
        return std::find(pm::kFollowOnlyPoolFlags.begin(), pm::kFollowOnlyPoolFlags.end(), f) != pm::kFollowOnlyPoolFlags.end();
    };
    check(listed(pb::kPathbLaunchFlag) && listed(pb::kVoteFlag) && listed(pb::kJournalDepthFlag) && listed(pb::kBodyKeepFlag)
                  && listed(pb::kHeaderKeepFlag) && listed(pb::kSideKeepFlag) && listed(pb::kKeyCacheFlag)
                  && listed(pb::kAbandonTimeoutFlag) && listed(pb::kWaitingCapFlag) && listed(pb::kBucketServeCapFlag)
                  && listed(pb::kClaimAlarmRateFlag) && listed(pb::kBucketFrameFlag) && listed(pb::kBucketInflightFlag)
                  && listed(pb::kBucketRateFlag) && listed(pb::kDeploymentsFlag) && listed(pb::kRegtestK30Flag)
                  && !listed(pb::kPenaltyFillFlag),
          "refusals: the policy flags of S4w-a and the regtest K30 rig input are listed; --pathb-penalty-fill is not");
    check(pm::kPoolIdentityFlags[0] == pb::kPoolGenesisFromFlag && pm::kPoolIdentityFlags[1] == pb::kPoolGenesisFlag
                  && pm::kPoolIdentityFlags[2] == pb::kPoolGenesisHeightFlag,
          "refusals: the pool identity flags of S4w-a");
    // the allowed configurations
    for (const xn::MoneroNetwork n : {xn::MoneroNetwork::Regtest, xn::MoneroNetwork::Stagenet, xn::MoneroNetwork::Testnet,
                                      xn::MoneroNetwork::Mainnet})
        check(pm::follow_only_refusal(fo_base(n)).empty(), std::string("refusals: allowed on ") + xn::to_string(n));
    {
        xn::XmrNodeConfig c = fo_base(xn::MoneroNetwork::Mainnet);
        for (const auto& [f, value] : std::vector<std::pair<std::string, std::string>>{
                     {"--pathb-penalty-fill", ""}, {"--native-txpool-warm-timeout-ms", "1"}, {"--arm-order", "p2p-first"},
                     {"--xmr-template-source", "native"}, {"--no-daemon-rpc", ""}, {"--native-seeds", ""},
                     {"--native-snapshot-path", "/tmp/s"}, {"--native-snapshot-every", "60"},
                     {"--native-catchup-window", "256"}, {"--native-backlog-refresh", "3"}, {"--native-p2p-bind", "127.0.0.1"},
                     {"--native-anchor", "/tmp/a"}, {"--native-output-set", "/tmp/o"}, {"--native-ready-timeout", "120"},
                     {"--anchor-confirm-peers", "4"}, {"--anchor-confirm-timeout-ms", "60000"},
                     {"--anchor-confirm-peer-ms", "12000"}, {"--native-dos-solicited-credits", "8"}, {"--data-dir", "/tmp/d"},
                     {"--status-every", "30"}, {"--web-port", "8080"}, {"--web-host", "127.0.0.1"},
                     {"--same-height-tiebreak", "prefer-own"}, {"--own-fork-bound-s", "240"}, {"--randomx", ""}})
            give(c, f, value);
        c.native_txpool_warm_timeout_ms = 1;
        check(pm::follow_only_refusal(c).empty(), "refusals: mainnet --follow-only --i-understand-mainnet with the native "
                                                  "node's flags, --pathb-penalty-fill and a warm timeout above 0: "
                                                          + pm::follow_only_refusal(c));
    }
    // the fence inside the function, master's text
    {
        xn::XmrNodeConfig c = fo_base(xn::MoneroNetwork::Mainnet);
        c.i_understand_mainnet = false;
        check(pm::follow_only_refusal(c) == "mainnet requires --i-understand-mainnet (prototype safety)",
              "refusals: mainnet without --i-understand-mainnet: master's fence text");
    }
    // one case per refused input
    std::size_t n = 0, ok = 0;
    for (const Input& in : refused_inputs()) {
        ++n;
        xn::XmrNodeConfig c = fo_base();
        in.set(c);
        const std::string r = pm::follow_only_refusal(c);
        ok += r == in.text ? 1 : 0;
        check(r == in.text, "refusals: " + in.name + ": got '" + r + "'");
        xn::XmrNodeConfig m = fo_base(xn::MoneroNetwork::Mainnet);
        in.set(m);
        check(!pm::follow_only_refusal(m).empty(), "refusals: " + in.name + " refused on mainnet");
        xn::XmrNodeConfig off;
        in.set(off);
        check(pm::follow_only_refusal(off).empty(), "refusals: " + in.name + " without --follow-only: none");
    }
    check(ok == n, "refusals: " + std::to_string(ok) + "/" + std::to_string(n) + " inputs with their fixed text");
}

// ---------------------------------------------------------------------------
void solo() {
    xn::XmrNodeConfig c;
    c.network = xn::MoneroNetwork::Regtest;
    c.native_solo = true;
    c.arm_order = xn::ArmOrderMode::P2PFirst;
    check(xn::solo_refusal(c).empty(), "solo: a regtest solo node");
    xn::XmrNodeConfig l = c;
    l.relay_listen = "127.0.0.1:37889";
    check(xn::solo_refusal(l) == "--native-solo takes no --relay-listen", "solo: --relay-listen refused");
    xn::XmrNodeConfig p = c;
    p.relay_peers.push_back("127.0.0.1:37889");
    check(xn::solo_refusal(p) == "--native-solo takes no --relay-peer", "solo: --relay-peer refused");
}

// ---------------------------------------------------------------------------
void plan() {
    const pm::RunPlan p = pm::run_plan_of(fo_base());
    check(p.native_node && p.follower_adapter && p.follow_template && p.serve_follow_only && p.status_function,
          "plan: native node, follower adapter, template routine, serve_follow_only, status lines");
    check(!p.serve_pathb && !p.pathb_node && !p.carrier_tree && !p.bin_store && !p.activation_record && !p.store
                  && !p.joiner && !p.relay_node,
          "plan: no PathbNode, CarrierTree, BinStore, AR, store, joiner, relay");
    check(!p.stratum_listener && !p.job_binder && !p.miner && !p.publisher && !p.monerod_transport,
          "plan: no stratum listener, job binder, miner, publisher, monerod transport");
    xn::XmrNodeConfig m = fo_base();
    m.mine_enabled = true;
    check(!pm::run_plan_of(m).miner, "plan: no miner under --follow-only whatever the field says");
    xn::XmrNodeConfig q;
    q.mine_enabled = true;
    const pm::RunPlan pp = pm::run_plan_of(q);
    check(pp.serve_pathb && pp.pathb_node && pp.store && pp.relay_node && pp.stratum_listener && pp.miner
                  && !pp.serve_follow_only && !pp.follow_template,
          "plan: the pool mode runs serve_pathb");
}

// ---------------------------------------------------------------------------
void native() {
    const xn::XmrNodeConfig d;
    check(d.arm_order == xn::ArmOrderMode::DaemonFirst && d.template_source == xn::TemplateSourceMode::Monerod && !d.no_daemon_rpc,
          "native: the defaults are daemon-first and monerod");
    const xn::XmrNodeConfig c = fo_base();
    check(c.arm_order == xn::ArmOrderMode::P2PFirst && c.template_source == xn::TemplateSourceMode::Native && c.no_daemon_rpc,
          "native: --follow-only sets p2p-first, the native source and no daemon RPC");
    const o2::NativeTemplateConfig n = o2::native_template_config_of(c);
    check(n.monerod_rpc_host.empty() && n.monerod_rpc_port == 0, "native: no monerod host or port");
    check(n.relay_order == ::c2pool::xmr::native::ArmOrder::P2pOnly, "native: relay order P2pOnly");
    check(!n.fallback, "native: fallback off");
    check(xn::arm_order_refusal(c).empty(), "native: arm_order_refusal passes: " + xn::arm_order_refusal(c));
    xn::XmrNodeConfig p = fo_base();
    p.native_parity_monerod = true;
    const o2::NativeTemplateConfig np = o2::native_template_config_of(p);
    check(np.monerod_rpc_host.empty() && np.monerod_rpc_port == 0, "native: no endpoint with the parity field set");
    xn::XmrNodeConfig s;
    s.follow_only = true;
    pm::apply_follow_only(s);
    check(!xn::arm_order_refusal(s).empty(), "native: no levin address source refused");
    xn::XmrNodeConfig w = fo_base();
    w.native_txpool_warm_timeout_ms = 12345;
    check(o2::native_template_config_of(w).txpool_warm_timeout_ms == 12345, "native: the warm timeout forwarded");
    check(d.native_txpool_warm_timeout_ms == 30000 && nrt::NativeNodeConfig{}.txpool_warm_timeout_ms == 30000
                  && o2::NativeTemplateConfig{}.txpool_warm_timeout_ms == 30000
                  && o2::native_template_config_of(d).txpool_warm_timeout_ms == 30000,
          "native: the warm timeout default 30,000 ms");
}

// ---------------------------------------------------------------------------
// A chain whose B and Z change with the height.
void vary(KatNet& net) {
    for (auto& [id, w] : net.rows.w) {
        const std::optional<pb::BranchBlock> blk = net.rows.block(id);
        if (!blk) continue;
        const std::uint64_t z = 300000 + (blk->height % 5) * 20000;
        w = rw(1000000000000000000ull + blk->height * 1000000000000000ull, z, z + 10000);
    }
}

pb::FollowTemplateIo record_io(Harness& h, const pb::FollowerBranchView& view, std::uint64_t m) {
    pb::FollowTemplateIo io;
    io.readiness = [] { return pb::FollowReadiness{true, false, ""}; };
    io.main_tip = [m]() -> std::optional<pb::FollowTip> { return pb::FollowTip{m, mon_block(m), mon_block(m - 1)}; };
    io.hf_for_child = [&h, &view](const pb::Hash32& p) -> std::optional<std::uint8_t> {
        const pb::PrInfo pr = h.resolve(view, p);
        if (pr.status != pb::PrInfo::Status::Held) return std::nullopt;
        return pr.in.hf;
    };
    io.weights_at = [&view](const pb::Hash32& p) { return view.weights_at(p); };
    io.candidates = [&h] { return h.txs; };
    return io;
}

std::vector<pb::Hash32> ids_of(const std::vector<pb::TemplateTx>& v) {
    std::vector<pb::Hash32> out;
    for (const pb::TemplateTx& t : v) out.push_back(t.hash);
    return out;
}

void equiv() {
    KatNet net;
    vary(net);
    const pb::EpochTable T = kat_table(net);
    struct Vec {
        std::string name;
        std::function<std::vector<pb::TemplateTx>(std::uint64_t base)> make;
    };
    const std::vector<Vec> vecs = {
            {"plain",
             [](std::uint64_t) {
                 return std::vector<pb::TemplateTx>{{seq32(0xE1), 2000, 3000000}, {seq32(0xE2), 1500, 2000000}};
             }},
            {"varint",
             [](std::uint64_t b) {
                 std::uint64_t next = 1;
                 while (next <= b) next <<= 7;
                 return std::vector<pb::TemplateTx>{{seq32(0xA1), 2500, next - b + 12345},
                                                    {seq32(0xA2), 1800, 4000000},
                                                    {seq32(0xA3), 700000, next << 7}};
             }},
            {"penalty",
             [](std::uint64_t) {
                 std::vector<pb::TemplateTx> v;
                 for (std::uint8_t i = 0; i < 4; ++i) v.push_back({seq32(static_cast<std::uint8_t>(0xF0 + i)), 120000, 900000000ull});
                 v.push_back({seq32(0xF8), 3000, 5000000});
                 return v;
             }},
    };
    std::size_t runs = 0, same = 0, penalised = 0, crossed = 0;
    for (const bool fill : {false, true}) {
        for (const Vec& vec : vecs) {
            for (const std::uint64_t m : {kPoolH, kPoolH + 1, kPoolH + 2}) {
                Harness h(net);
                pb::PathbNodeConfig pc = h.config(T, true);
                pc.penalty_fill = fill;
                h.nodes.push_back(std::make_unique<pb::PathbNode>(pc, h.io(0), nullptr));
                h.mon_tip = m;
                const pb::FollowerBranchView& view = *h.views[0];
                const std::uint64_t b = view.weights_at(mon_block(m))->base_reward;
                h.txs = vec.make(b);
                const pb::PathbTemplate t = h[0].make_template(h.now);
                const pb::FollowTemplateIo io = record_io(h, view, m);
                const pb::FollowRecord r = pb::follow_template_record(io, fill);
                const std::string tag = "equiv " + vec.name + (fill ? " fill" : "") + " m=H+" + std::to_string(m - kPoolH) + ": ";
                ++runs;
                check(t.status == pb::TemplateStatus::Ok && t.x == 1 && t.window.window && t.window.window->empty_finder_only,
                      tag + "make_template at x = 1, the empty window");
                check(r.ok(), tag + "a record");
                const bool eq = r.h == t.h && r.p_r == t.p_r && r.hf == t.hf && r.base == t.base && r.zone == t.median
                                && ids_of(r.txs) == ids_of(t.txs) && r.sel.T == t.tx_weight && r.sel.F == t.fees
                                && r.sel.reward == t.reward && r.sel.coinbase == t.coinbase
                                && pb::follow_txset(r.txs) == pb::follow_txset(t.txs);
                same += eq ? 1 : 0;
                check(eq, tag + "h, P_r, hf, B, Z, the transactions, T, F, R, c, txset equal make_template's");
                check(r.h == m + 1 && r.p_r == mon_block(m), tag + "P_r = the Monero tip, h = M + 1");
                const std::optional<pb::PathbJob> j = h[0].make_job(t, h.session(1));
                check(j && j->miner_tx.outs.size() == 1 && j->miner_tx.prefix.size() + 1 == r.sel.coinbase
                              && vout_sum(j->miner_tx) == r.sel.reward,
                      tag + "c = the size of the node's one-output miner tx, Sum(vout) = R");
                const std::uint64_t w = r.sel.T + r.sel.coinbase;
                if (w > r.zone) {
                    ++penalised;
                    const std::optional<std::uint64_t> rr = pb::reward_for_child(r.zone, w, r.base, r.hf);
                    check(fill && rr && r.sel.reward == *rr + r.sel.F, tag + "penalised: R = reward_for_child(Z, T + c, B) + F");
                } else {
                    check(r.sel.reward == r.base + r.sel.F, tag + "R = B + F");
                }
                if (vec.name == "varint") {
                    std::uint64_t next = 1;
                    while (next <= r.base) next <<= 7;
                    crossed += r.sel.reward >= next ? 1 : 0;
                }
            }
        }
    }
    check(same == runs && runs == 18, "equiv: " + std::to_string(same) + "/" + std::to_string(runs) + " records equal");
    check(penalised >= 3, "equiv: penalty-zone records with --pathb-penalty-fill: " + std::to_string(penalised));
    check(crossed == 6, "equiv: R crosses a varint length in every varint run: " + std::to_string(crossed));
}

// ---------------------------------------------------------------------------
// A native node restarted: the relay gate, the complement answer, the warm
// latch (warm once the gate is open and the answer was admitted or the
// timeout passed since the gate opened; latched).
struct NodeStub {
    std::uint64_t timeout_ms = 0;
    std::uint64_t now_ms = 0;
    bool gate_open = false;
    std::uint64_t gate_open_ms = 0;
    bool answered = false;
    bool warm = false;
    std::string why;
    std::vector<pb::TemplateTx> pool;
    std::uint64_t backlog = 0;

    void latch() {
        if (warm || !gate_open) return;
        const std::uint64_t waited = now_ms > gate_open_ms ? now_ms - gate_open_ms : 0;
        if (!answered && waited < timeout_ms) return;
        warm = true;
        why = answered ? "complement" : "timeout";
    }
};

struct Rig {
    const KatNet& net;
    pb::FollowerBranchView view;
    NodeStub node;
    std::uint64_t tip = kPoolH + 1;
    std::uint8_t hf = 16;
    bool hide_pr_weights = false;
    std::vector<pb::FollowEvent> events;
    std::vector<std::string> lines;
    pb::FollowOnlyIo io;
    pb::FollowOnlyState state;

    explicit Rig(const KatNet& n) : net(n), view(n.rows) {
        io.pump = [this] { return std::exchange(events, {}); };
        io.backlog_version = [this] { return node.backlog; };
        io.tmpl.readiness = [this] {
            node.latch();
            if (!node.warm) return pb::FollowReadiness{false, true, "PoolCold"};
            return pb::FollowReadiness{true, false, ""};
        };
        io.tmpl.main_tip = [this]() -> std::optional<pb::FollowTip> { return pb::FollowTip{tip, mon_block(tip), mon_block(tip - 1)}; };
        io.tmpl.hf_for_child = [this](const pb::Hash32&) -> std::optional<std::uint8_t> { return hf; };
        io.tmpl.weights_at = [this](const pb::Hash32& p) -> std::optional<pb::WeightInputs> {
            if (hide_pr_weights && p == mon_block(tip)) return std::nullopt;
            return view.weights_at(p);
        };
        io.tmpl.candidates = [this] { return node.pool; };
        io.log_values = [this] { return pb::FollowLogValues{node.pool.size(), node.why, node.now_ms / 1000}; };
        io.out = [this](const std::string& l) { lines.push_back(l); };
        io.now_s = [this] { return node.now_ms / 1000; };
        io.status_values = [this] {
            pb::KeptStatusValues v;
            v.txpool_gate_open = node.gate_open;
            v.txpool_warm = node.warm;
            v.txpool_warm_why = node.why;
            v.pool_count = node.pool.size();
            v.arm_order = "p2p-first";
            return v;
        };
    }
    void pass() { pb::follow_only_pass(io, pb::FollowOnlyOptions{false, 30}, state); }
    void advance(std::uint64_t ms) { node.now_ms += ms; }
    void new_tip() {
        ++tip;
        pb::FollowEvent e;
        e.height = tip;
        e.id = mon_block(tip);
        e.prev = mon_block(tip - 1);
        e.tip = tip;
        events.push_back(e);
    }
    std::vector<std::string> template_lines() const {
        std::vector<std::string> out;
        for (const std::string& l : lines)
            if (l.rfind("[follow-only] template", 0) == 0) out.push_back(l);
        return out;
    }
};

bool has(const std::string& s, const std::string& part) { return s.find(part) != std::string::npos; }

std::vector<pb::TemplateTx> pool_of(std::uint8_t first, std::size_t k) {
    std::vector<pb::TemplateTx> v;
    for (std::size_t i = 0; i < k; ++i) v.push_back({seq32(static_cast<std::uint8_t>(first + 8 * i)), 1500 + 10 * i, 2000000 + i});
    return v;
}

void restart() {
    const KatNet net;
    const std::uint64_t timeout = o2::native_template_config_of(fo_base()).txpool_warm_timeout_ms;
    check(timeout == 30000, "restart: the stub's timeout is the forwarded default");
    // the complement answer
    {
        Rig r(net);
        r.node.timeout_ms = timeout;
        r.pass();  // the restart: the gate shut, the pool empty
        r.advance(1000);
        r.node.gate_open = true;
        r.node.gate_open_ms = r.node.now_ms;
        r.new_tip();
        r.advance(1000);
        r.pass();
        const std::vector<std::string> cold = r.template_lines();
        bool all_cold = !cold.empty();
        for (const std::string& l : cold) all_cold = all_cold && has(l, " none reason=pool-cold") && !has(l, "log-only");
        check(all_cold && cold.size() == 2 && r.state.records == 0, "restart: none reason=pool-cold and no record while cold");
        r.node.pool = pool_of(0x30, 3);
        r.node.answered = true;
        ++r.node.backlog;
        r.advance(500);
        r.pass();
        const std::vector<std::string> after = r.template_lines();
        check(after.size() == 3 && has(after[2], " n_tx=3 ") && has(after[2], " warm=complement ") && has(after[2], " log-only"),
              "restart: the first record after the complement answer holds k = 3: " + (after.empty() ? "" : after.back()));
        // the compare line when the network's block at h connects
        r.tip = kPoolH + 2;
        pb::FollowEvent e;
        e.height = kPoolH + 3;
        e.id = seq32(0x77);
        e.prev = mon_block(kPoolH + 2);
        e.tip = kPoolH + 3;
        e.tx_ids = {r.node.pool[0].hash, r.node.pool[2].hash, seq32(0x99)};
        e.tx_weight = 9999;
        r.events.push_back(e);
        r.tip = kPoolH + 3;
        r.pass();
        bool cmp = false;
        for (const std::string& l : r.lines)
            cmp = cmp || l == "[follow-only] compare h=" + std::to_string(kPoolH + 3) + " net_id=" + pb::follow_hex(seq32(0x77))
                                       + " net_n_tx=3 net_tx_weight=9999 our_n_tx=3 our_tx_weight=4530 common=2";
        check(cmp, "restart: the compare line for the record's height");
    }
    // no answer: the timeout
    {
        Rig r(net);
        r.node.timeout_ms = timeout;
        r.node.gate_open = true;
        r.node.gate_open_ms = 0;
        r.node.pool = pool_of(0x50, 2);  // relayed, no complement answer
        r.pass();
        r.advance(timeout - 1);
        r.new_tip();
        r.pass();
        const std::vector<std::string> cold = r.template_lines();
        check(cold.size() == 2 && has(cold[0], "none reason=pool-cold") && has(cold[1], "none reason=pool-cold"),
              "restart: no answer, before the timeout: pool-cold");
        r.advance(1);
        r.new_tip();
        r.pass();
        const std::vector<std::string> after = r.template_lines();
        check(after.size() == 3 && has(after[2], " warm=timeout ") && has(after[2], " n_tx=2 "),
              "restart: the record after the timeout says warm=timeout: " + (after.empty() ? "" : after.back()));
    }
}

// ---------------------------------------------------------------------------
void forkfuse() {
    const KatNet net;
    Rig r(net);
    r.node.warm = true;
    r.node.why = "complement";
    r.node.pool = pool_of(0x60, 2);
    r.hf = 17;
    r.pass();
    const std::vector<std::string> l = r.template_lines();
    check(l.size() == 1 && l[0] == "[follow-only] template h=" + std::to_string(kPoolH + 2) + " none reason=fork-fuse hf=17"
                  && r.state.records == 0,
          "forkfuse: hf 17: none reason=fork-fuse hf=17, no record");
    r.hf = 16;
    r.new_tip();
    r.pass();
    check(r.state.records == 1, "forkfuse: hf 16: a record");
}

// ---------------------------------------------------------------------------
void weights() {
    const KatNet net;
    Rig r(net);
    r.node.warm = true;
    r.node.why = "complement";
    r.hide_pr_weights = true;
    r.pass();
    const std::vector<std::string> l = r.template_lines();
    check(l.size() == 1 && l[0] == "[follow-only] template h=" + std::to_string(kPoolH + 2) + " none reason=missing-weights"
                  && r.state.records == 0,
          "weights: no weights_at(P_r): none reason=missing-weights");
}

// ---------------------------------------------------------------------------
void lines() {
    pb::Hash32 g{};
    for (std::size_t i = 0; i < g.size(); ++i) g[i] = static_cast<std::uint8_t>(i);
    const std::string dir = pm::follow_only_dir("/d", xn::MoneroNetwork::Mainnet, g);
    check(dir == "/d/mainnet/follow_only/000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
          "lines: the follow-only directory keyed by network and G: " + dir);
    check(pm::follow_only_row_weights_path(dir) == dir + "/row_weights", "lines: the RowWeights table in it");
    check(pb::follow_only_start_line("mainnet", dir)
                  == "c2pool-v37-xmr: FOLLOW-ONLY network=mainnet pool=none stratum=off relay=off mine=off monerod=none snapshot="
                             + dir,
          "lines: the start line");
    pb::FollowEvent e;
    e.kind = pb::FollowEventKind::Reorg;
    e.height = 12;
    e.id = seq32(0x10);
    e.prev = seq32(0x20);
    e.depth = 2;
    e.tip = 12;
    check(pb::follow_line(e) == "[follow-only] follow h=12 id=" + hex(seq32(0x10).data(), 32) + " prev="
                                        + hex(seq32(0x20).data(), 32) + " event=reorg depth=2 tip=12",
          "lines: the follow line");
    // a record line
    const KatNet net;
    Rig r(net);
    r.node.warm = true;
    r.node.why = "complement";
    r.node.now_ms = 77000;
    r.node.pool = pool_of(0x40, 2);
    r.pass();
    const std::vector<std::string> l = r.template_lines();
    const pb::WeightInputs wi = *r.view.weights_at(mon_block(kPoolH + 1));
    const std::uint64_t F = 2000000 + 2000001, T = 1500 + 1510;
    const std::uint64_t R = wi.base_reward + F;
    std::vector<std::uint64_t> amounts{R};
    const std::uint64_t c = pb::coinbase_weight_hf16(kPoolH + 2, amounts);
    const std::string want = "[follow-only] template h=" + std::to_string(kPoolH + 2) + " prev=" + pb::follow_hex(mon_block(kPoolH + 1))
                             + " hf=16 n_tx=2 tx_weight=" + std::to_string(T) + " fees=" + std::to_string(F)
                             + " reward=" + std::to_string(R) + " cb_size=" + std::to_string(c)
                             + " block_weight=" + std::to_string(T + c) + " zone=" + std::to_string(wi.zone)
                             + " base=" + std::to_string(wi.base_reward) + " pool=2 warm=complement uptime_s=77 txset="
                             + pb::follow_hex(pb::follow_txset(r.node.pool)) + " log-only";
    check(l.size() == 1 && l[0] == want, "lines: the template line: " + (l.empty() ? std::string() : l[0]));
    // the status lines: master's formats
    pb::KeptStatusValues v;
    v.good_citizen_on = true;
    v.citizen_pool_n = 5;
    v.citizen_chosen_n = 4;
    v.good_citizen_violations = 0;
    v.txpool_gate_open = true;
    v.txpool_tip_known = true;
    v.txpool_warm = true;
    v.txpool_warm_why = "complement";
    v.txpool_warm_after_ms = 812;
    v.complement_requests_out = 3;
    v.complement_answers_in = 2;
    v.complement_rounds = 1;
    v.complement_txs = 7;
    v.pool_count = 9;
    v.pool_accepted = 11;
    v.pool_duplicates = 12;
    v.pool_rejected = 13;
    v.pool_rejected_not_synced = 14;
    v.pool_rejected_member_locked = 15;
    v.pool_unresolved_ring = 16;
    v.pool_rejected_key_image_spent = 17;
    v.pool_rejected_already_mined = 18;
    v.pool_tip_seated = 19;
    v.node_rpc = 4;
    v.template_daemon_pumps = 5;
    v.pool_tip_poll_rpc = 6;
    v.pool_other_rpc = 7;
    v.pool_transport_rpc = 8;
    v.node_rpc_failures = 9;
    v.pool_rpc_failures = 10;
    v.arm_order = "p2p-first";
    char b[2048];
    std::vector<std::string> want_s;
    std::snprintf(b, sizeof b, "  good-citizen: %s pool=%zu chosen=%zu violations=%llu", "on", std::size_t{5}, std::size_t{4}, 0ull);
    want_s.emplace_back(b);
    std::snprintf(b, sizeof b,
                  "  txpool: gate=%d tip_known=%d warm=%d(%s %llums) complement req=%llu ans=%llu "
                  "admitted_rounds=%llu txs=%llu | count=%llu accepted=%llu dup=%llu rejected=%llu "
                  "not_synced=%llu member_locked=%llu unresolved=%llu ki_spent=%llu already_mined=%llu "
                  "tip_seated=%llu",
                  1, 1, 1, "complement", 812ull, 3ull, 2ull, 1ull, 7ull, 9ull, 11ull, 12ull, 13ull, 14ull, 15ull, 16ull, 17ull,
                  18ull, 19ull);
    want_s.emplace_back(b);
    std::snprintf(b, sizeof b,
                  "  wire RPC to monerod: TOTAL=%llu = template-path %llu "
                  "+ node(parity+submit) %llu + tip-poll %llu + pool-other %llu"
                  " [failures node=%llu pool=%llu]",
                  17ull, 5ull, 4ull, 6ull, 7ull, 9ull, 10ull);
    want_s.emplace_back(b);
    std::snprintf(b, sizeof b,
                  "  arm-order=%s rpc_on_find_path=%llu "
                  "(template %llu + pool-transport %llu) | off-path parity=%llu",
                  "p2p-first", 13ull, 5ull, 8ull, 4ull);
    want_s.emplace_back(b);
    check(pb::kept_status_lines(v) == want_s, "lines: good-citizen, txpool, wire RPC, rpc_on_find_path in master's formats");
    // the follow-only witness: no pool transport, no daemon endpoint
    const std::vector<std::string> w0 = pb::kept_status_lines(pb::KeptStatusValues{});
    check(w0.size() == 4 && w0[2].rfind("  wire RPC to monerod: TOTAL=0 = template-path 0 ", 0) == 0
                  && w0[3].find(" rpc_on_find_path=0 (template 0 + pool-transport 0) | off-path parity=0") != std::string::npos,
          "lines: wire RPC to monerod: TOTAL=0, rpc_on_find_path=0");
    bool web = false;
    r.io.web = [&web](const std::vector<std::string>& s) { web = s.size() == 4; };
    r.state.next_status_s = 0;
    r.pass();
    check(web, "lines: the status lines reach the web status");
}

// ---------------------------------------------------------------------------
void hooks() {
    const std::string addr = "42QtUEQ6E4v2wtkG2h72osTqZgLo7vtjg4SngeG47AnaaQLUUQrGvPXSuvCmHcRVuPa5xxUU5Mfo6jSEqYYUk34Z1PM1oPF";
    const st::LoginHook a = st::login_hook(addr, "vote=3", pb::LaneNet::Mainnet);
    check(a.refusal.empty() && a.stated_vote == std::optional<std::uint32_t>(3), "hooks: an XMR_STD payee, vote=3");
    const st::LoginHook b = st::login_hook(addr, "x", pb::LaneNet::Regtest);
    check(b.refusal.empty() && !b.stated_vote, "hooks: a password without vote= states no vote");
    check(!st::login_hook(addr, "vote=1", pb::LaneNet::Testnet).refusal.empty(), "hooks: an address of another network refused");
    std::string bad = addr;
    bad.back() = 'G';
    check(!st::login_hook(bad, "vote=1", pb::LaneNet::Mainnet).refusal.empty(), "hooks: a bad checksum refused");
    const pb::BallotChoice def{0x0001, pb::BallotSource::Default};
    check(st::login_reply_c2pool(10, 0, def)
                  == "\"c2pool\":{\"give_author_pct\":0.1000,\"node_owner_fee_pct\":0.0000,"
                     "\"vote\": {\"ballot\": \"0x0001\", \"source\": \"default\"}}",
          "hooks: the c2pool object: give_author_pct, node_owner_fee_pct, vote");
    check(st::login_reply_c2pool(0, 1250, pb::BallotChoice{0x8000, pb::BallotSource::Own})
                  == "\"c2pool\":{\"give_author_pct\":0.0000,\"node_owner_fee_pct\":12.5000,"
                     "\"vote\": {\"ballot\": \"0x8000\", \"source\": \"own\"}}",
          "hooks: the c2pool object at give-author 0");
    const std::optional<st::StratumBudget> d0 = st::stratum_budget_of(18180);
    check(d0 && d0->min_diff == 18180 && d0->refill_per_t == 2 && d0->t_s == 10, "hooks: the default: min-diff = d_at, 2 submits per T");
    const std::optional<st::StratumBudget> d6 = st::stratum_budget_of(18180, 6);
    check(d6 && d6->min_diff == 284 && d6->refill_per_t == 128, "hooks: shift 6: d_at / 64, 128 submits per T");
    check(!st::stratum_budget_of(18180, 63) && st::stratum_budget_of(18180, 62), "hooks: shift at most 62");
}

}  // namespace

// ---------------------------------------------------------------------------
// reorglines: a reorg of depth 2 to a branch of 3 blocks (orphans 5, 6; new branch 5', 6', 7'): one follow line per
// block of the new branch, oldest first, event=reorg depth=2, each with its own id; extends unchanged.
void reorglines() {
    std::map<pb::Hash32, pb::FollowEvent> held;
    const auto blk = [&](std::uint64_t h, std::uint8_t tag, std::uint8_t prev_tag) {
        pb::FollowEvent e;
        e.height = h;
        e.id = seq32(tag);
        e.prev = seq32(prev_tag);
        e.tx_ids = {seq32(static_cast<std::uint8_t>(tag + 0x40))};
        held[e.id] = e;
        return e;
    };
    (void)blk(4, 0x04, 0x03);
    (void)blk(5, 0x25, 0x04);
    (void)blk(6, 0x26, 0x25);
    pb::FollowEvent tip = blk(7, 0x27, 0x26);
    std::vector<pb::FollowEvent> in;
    pb::FollowEvent o5, o6;
    o5.kind = o6.kind = pb::FollowEventKind::Orphan;
    o5.height = 5;
    o5.id = seq32(0x15);
    o6.height = 6;
    o6.id = seq32(0x16);
    in.push_back(o6);
    in.push_back(o5);
    tip.kind = pb::FollowEventKind::Reorg;
    tip.depth = 2;
    tip.tip = 7;
    in.push_back(tip);
    pb::FollowEvent ext = blk(8, 0x28, 0x27);
    ext.kind = pb::FollowEventKind::Extend;
    ext.tip = 8;
    in.push_back(ext);
    const std::vector<pb::FollowEvent> out = pb::expand_reorgs(in, [&](const pb::Hash32& id) -> std::optional<pb::FollowEvent> {
        const auto it = held.find(id);
        if (it == held.end()) return std::nullopt;
        return it->second;
    });
    std::vector<std::uint64_t> reorg_h;
    bool ids_ok = true, depth_ok = true;
    for (const pb::FollowEvent& e : out)
        if (e.kind == pb::FollowEventKind::Reorg) {
            reorg_h.push_back(e.height);
            ids_ok = ids_ok && e.id == held[e.id].id && !e.tx_ids.empty();
            depth_ok = depth_ok && e.depth == 2 && e.tip == 7;
        }
    check(out.size() == 6 && reorg_h == std::vector<std::uint64_t>{5, 6, 7} && ids_ok && depth_ok
                  && out.back().kind == pb::FollowEventKind::Extend && out.back().height == 8,
          "reorglines: a reorg to 5', 6', 7' gives one follow line per block of the new branch (" +
                  std::to_string(reorg_h.size()) + " reorg lines)");
    check(pb::follow_line(out[2]).find(" event=reorg depth=2 tip=7") != std::string::npos,
          "reorglines: the line names event=reorg and the depth");
}

int main(int argc, char** argv) {
    std::printf("v37_xmr_follow_only_kat\n");
    const std::string only = argc > 1 ? argv[1] : "";
    const auto run = [&](const char* name, void (*fn)()) {
        if (only.empty() || only == name) run_part(name, fn);
    };
    run("refusals", refusals);
    run("solo", solo);
    run("plan", plan);
    run("native", native);
    run("equiv", equiv);
    run("restart", restart);
    run("forkfuse", forkfuse);
    run("weights", weights);
    run("lines", lines);
    run("hooks", hooks);
    run("reorglines", reorglines);
    return finish("v37_xmr_follow_only_kat");
}
