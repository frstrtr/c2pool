// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/test/v37_xmr_mainnet_refusal_kat.cpp
// The mainnet refusal (c2pool/v37/xmr/pathb/pathb_mainnet_refusal.hpp):
//   allowed   mainnet with --follow-only --i-understand-mainnet (and a levin
//             address source): mainnet_refusal and mode_refusal pass
//   refused   one case per input, the text pinned: no --follow-only; every
//             --stratum-* input; --mine and every --mine-* input (and the
//             field); --pathb-launch; every --relay-* / --no-relay-* input and
//             the relay fields; off mainnet none of them is refused here
//   order     mode_refusal: the fence (without --follow-only), then
//             mainnet_refusal, then follow_only_refusal (its fence clause)
//   knob      the test-only --test-unknown-fork-stall-s above 0 is refused on
//             mainnet in either mode, before every other mode refusal; 0 and
//             off mainnet pass
//   bypass    each refused case stays refused with any other flag of the
//             binary added (the full flag table and further names), and with
//             every Path B switch field set except follow_only
// ---------------------------------------------------------------------------
#include <algorithm>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include "c2pool/v37/xmr/pathb/pathb_mainnet_refusal.hpp"

namespace {

namespace xn = ::c2pool::v37n::xmr;
namespace pm = ::c2pool::v37n::xmr::pathb_mode;

int g_pass = 0, g_fail = 0;

const char* const kFence = "mainnet requires --i-understand-mainnet (prototype safety)";

void check(bool ok, const std::string& what, const std::string& detail = {}) {
    if (ok) {
        ++g_pass;
        return;
    }
    ++g_fail;
    std::printf("  FAIL: %s%s%s\n", what.c_str(), detail.empty() ? "" : " -- ", detail.c_str());
}

void give(xn::XmrNodeConfig& c, const std::string& name, const std::string& value = {}) {
    c.given_flags.push_back(xn::GivenFlag{name, value});
}

// mainnet, --i-understand-mainnet, --follow-only, --native-seeds.
xn::XmrNodeConfig allowed_mainnet() {
    xn::XmrNodeConfig c;
    c.network = xn::MoneroNetwork::Mainnet;
    give(c, "--network", "mainnet");
    c.i_understand_mainnet = true;
    give(c, "--i-understand-mainnet");
    c.follow_only = true;
    give(c, "--follow-only");
    c.native_use_seeds = true;
    give(c, "--native-seeds");
    pm::apply_follow_only(c);
    return c;
}

const std::vector<std::string> kStratumFlags = {
        "--stratum-port",          "--stratum-bind-host",    "--stratum-ban-seconds",     "--stratum-login-timeout-ms",
        "--stratum-share-rate",    "--stratum-share-score",  "--stratum-submit-burst",    "--stratum-vardiff-shares",
        "--stratum-min-diff-shift",
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

// The master flag table (125) and the Path B flags.
const std::vector<std::string> kAllFlags = {
        "--arm-order", "--cba-monerod-compare", "--cba-monerod-fallback", "--cba-refetch-bound", "--coinbase",
        "--contested-suspend", "--converge-hold-ticks", "--converge-retry-bound", "--credit-feed", "--credit-feed-lag-ms",
        "--credit-mutate", "--d-conf", "--dashboard-dir", "--data-dir", "--divergence-cap-heights",
        "--divergence-cap-terminal", "--divergence-cap-ticks", "--drops-enrol", "--drops-enrol-min-tip",
        "--drops-retain-bins", "--drops-store-persist", "--fee-model", "--give-author-pct", "--help",
        "--i-understand-mainnet", "--lane-chain", "--mine", "--mine-fast", "--mine-msr", "--mine-no-affinity",
        "--mine-no-huge-pages", "--mine-threads", "--minority-converge", "--minority-min-blocks", "--minority-window",
        "--mock-smoke", "--native-dos-solicited-credits", "--native-inject", "--native-inject-dir", "--native-inject-hex",
        "--native-inject-ttl-blocks", "--native-output-set", "--native-solo", "--network", "--no-book-deferral",
        "--no-daemon-rpc", "--no-found-sidecar", "--no-good-citizen", "--no-relay-bootstrap", "--no-relay-serve",
        "--node-owner-address", "--node-owner-fee-pct", "--owed-demo-amount", "--own-fork-bound-s", "--payee-spend-hex",
        "--payee-subaddress", "--payee-view-hex", "--payout-address", "--poll-ms", "--pool-genesis", "--randomx",
        "--randomx-large-pages", "--recon-max-root-age", "--relay-backfill-positions", "--relay-ban-seconds",
        "--relay-bin-grace-ms", "--relay-bin-lag", "--relay-bind", "--relay-deep-order", "--relay-deep-probe-step",
        "--relay-discovery", "--relay-feed-monerod-compare", "--relay-index-horizon", "--relay-keepalive-ms",
        "--relay-listen", "--relay-max-inbound", "--relay-max-outbound", "--relay-max-peers", "--relay-order",
        "--relay-parked-max", "--relay-peer", "--relay-reoffer-seconds", "--relay-rx-budget", "--relay-rx-global",
        "--relay-shadow-persist", "--relay-shadow-persist-bytes", "--relay-silence-timeout-ms",
        "--relay-solicited-credits", "--relay-test-partition-seconds", "--relay-vault-bytes", "--relay-vault-entries",
        "--relay-vault-horizon", "--relay-verify-threads", "--residual-sink-spend-hex", "--residual-sink-subaddress",
        "--residual-sink-view-hex", "--rpc-host", "--rpc-port", "--same-height-journal", "--same-height-renotify",
        "--same-height-tiebreak", "--selftest", "--settle-h-min", "--settle-output-cap", "--share-diff",
        "--status-every", "--stratum-ban-seconds", "--stratum-bind-host", "--stratum-login-timeout-ms",
        "--stratum-port", "--stratum-share-rate", "--stratum-share-score", "--stratum-submit-burst",
        "--stratum-vardiff-shares", "--template-reserve", "--test-crash-after-publish", "--test-suspend-lane-seconds",
        "--test-unknown-fork-stall-s", "--version", "--web-host", "--web-port", "--wire-in", "--wire-out",
        "--xmr-template-source", "--zmq-port",
        // the native node's flags
        "--native-connect", "--native-p2p-bind", "--native-anchor", "--native-force-synced",
        "--native-allow-unverified-pow", "--native-seeds", "--seeds", "--native-parity-monerod", "--native-snapshot-path",
        "--native-snapshot-every", "--native-catchup-window", "--native-backlog-refresh", "--backlog-refresh",
        "--anchor-confirm-peers", "--anchor-confirm-timeout-ms", "--anchor-confirm-peer-ms", "--native-ready-timeout",
        "--native-template-fallback", "--alt-max-blocks",
        // Path B
        "--pool-genesis-from", "--pool-genesis-height", "--vote", "--journal-depth", "--pathb-launch",
        "--pathb-deployments", "--pathb-key-cache-mb", "--pathb-penalty-fill", "--pathb-body-keep",
        "--pathb-header-keep", "--pathb-side-keep", "--pathb-abandon-timeout", "--pathb-waiting-cap",
        "--pathb-bucket-serve-cap", "--pathb-claim-alarm-rate", "--pathb-bucket-frame", "--join-min-peers",
        "--pathb-bucket-inflight", "--pathb-bucket-rate", "--pathb-window-cache-mb", "--pathb-entry-retention",
        "--pathb-bucket-retention", "--join-fork-walk", "--native-txpool-warm-timeout-ms", "--stratum-min-diff-shift",
        // further names
        "--i-really-understand-mainnet", "--mainnet-pool", "--allow-mainnet-pool", "--no-mainnet-refusal",
        "--mainnet-bypass", "--force", "--unsafe", "--yes", "--release", "--pathb-mainnet",
};

struct Case {
    std::string name;
    xn::XmrNodeConfig cfg;
    std::string text;  // the mainnet_refusal text
};

std::vector<Case> refused_cases() {
    std::vector<Case> out;
    {
        xn::XmrNodeConfig c = allowed_mainnet();
        c.follow_only = false;
        c.given_flags.erase(std::remove_if(c.given_flags.begin(), c.given_flags.end(),
                                           [](const xn::GivenFlag& f) { return f.name == "--follow-only"; }),
                            c.given_flags.end());
        out.push_back({"no --follow-only", c, "mainnet requires --follow-only"});
    }
    for (const std::string& f : kStratumFlags) {
        xn::XmrNodeConfig c = allowed_mainnet();
        give(c, f, "1");
        out.push_back({f, c, "mainnet refuses " + f});
    }
    for (const std::string& f : kMineFlags) {
        xn::XmrNodeConfig c = allowed_mainnet();
        give(c, f, f == "--mine" ? "" : "1");
        out.push_back({f, c, "mainnet refuses " + f});
    }
    {
        xn::XmrNodeConfig c = allowed_mainnet();
        c.mine_enabled = true;
        out.push_back({"mine_enabled", c, "mainnet refuses --mine"});
    }
    {
        xn::XmrNodeConfig c = allowed_mainnet();
        give(c, "--pathb-launch");
        out.push_back({"--pathb-launch", c, "mainnet refuses --pathb-launch"});
    }
    for (const std::string& f : kRelayFlags) {
        xn::XmrNodeConfig c = allowed_mainnet();
        give(c, f, "1");
        out.push_back({f, c, "mainnet refuses " + f});
    }
    {
        xn::XmrNodeConfig c = allowed_mainnet();
        c.relay_listen = "0.0.0.0:37889";
        out.push_back({"relay_listen", c, "mainnet refuses --relay-listen"});
    }
    {
        xn::XmrNodeConfig c = allowed_mainnet();
        c.relay_peers.push_back("192.0.2.1:37889");
        out.push_back({"relay_peers", c, "mainnet refuses --relay-peer"});
    }
    return out;
}

void allowed() {
    const xn::XmrNodeConfig c = allowed_mainnet();
    check(pm::mainnet_refusal(c).empty(), "allowed: mainnet --follow-only --i-understand-mainnet", pm::mainnet_refusal(c));
    check(pm::mode_refusal(c).empty(), "allowed: mode_refusal passes", pm::mode_refusal(c));
    xn::XmrNodeConfig p = c;
    give(p, "--pathb-penalty-fill");
    give(p, "--native-txpool-warm-timeout-ms", "45000");
    p.native_txpool_warm_timeout_ms = 45000;
    check(pm::mode_refusal(p).empty(), "allowed: --pathb-penalty-fill and a warm timeout above 0", pm::mode_refusal(p));
}

void refused() {
    for (const Case& k : refused_cases()) {
        const std::string r = pm::mainnet_refusal(k.cfg);
        check(r == k.text, "refused: " + k.name, "got '" + r + "'");
        const std::string m = pm::mode_refusal(k.cfg);
        check(m == k.text, "mode_refusal: " + k.name, "got '" + m + "'");
        for (xn::MoneroNetwork n : {xn::MoneroNetwork::Stagenet, xn::MoneroNetwork::Testnet, xn::MoneroNetwork::Regtest}) {
            xn::XmrNodeConfig o = k.cfg;
            o.network = n;
            check(pm::mainnet_refusal(o).empty(), "off mainnet: " + k.name + " on " + xn::to_string(n));
        }
    }
}

void order() {
    // no --follow-only, no --i-understand-mainnet: the fence first
    xn::XmrNodeConfig a;
    a.network = xn::MoneroNetwork::Mainnet;
    check(pm::mode_refusal(a) == std::string(kFence), "order: the fence before the mainnet refusal",
          pm::mode_refusal(a));
    // --i-understand-mainnet without --follow-only
    a.i_understand_mainnet = true;
    check(pm::mode_refusal(a) == "mainnet requires --follow-only", "order: then no --follow-only", pm::mode_refusal(a));
    // --follow-only without --i-understand-mainnet: follow_only_refusal's fence clause
    xn::XmrNodeConfig b = allowed_mainnet();
    b.i_understand_mainnet = false;
    check(pm::mode_refusal(b) == std::string(kFence), "order: --follow-only, the fence inside follow_only_refusal",
          pm::mode_refusal(b));
    check(pm::mainnet_refusal(b).empty(), "order: mainnet_refusal passes --follow-only without the fence");
    // a doubly refused input: the mainnet refusal's text
    give(b, "--stratum-port", "3333");
    check(pm::mode_refusal(b) == "mainnet refuses --stratum-port", "order: mainnet_refusal before follow_only_refusal",
          pm::mode_refusal(b));
    xn::XmrNodeConfig s = allowed_mainnet();
    give(s, "--payout-address", "x");
    check(pm::mode_refusal(s) == "--follow-only refuses --payout-address", "order: an input only follow_only_refusal refuses",
          pm::mode_refusal(s));
}

void bypass() {
    std::size_t still = 0, total = 0;
    for (const Case& k : refused_cases()) {
        for (const std::string& f : kAllFlags) {
            if (f == "--follow-only") continue;
            xn::XmrNodeConfig c = k.cfg;
            give(c, f, "1");
            ++total;
            still += pm::mainnet_refusal(c).empty() ? 0 : 1;
            if (pm::mainnet_refusal(c).empty()) {
                check(false, "bypass: " + k.name + " with " + f);
                break;
            }
        }
        // every switch field set, follow_only as the case has it
        xn::XmrNodeConfig c = k.cfg;
        c.i_understand_mainnet = true;
        c.no_daemon_rpc = true;
        c.native_parity_monerod = true;
        c.native_solo = true;
        c.native_force_synced = true;
        c.native_allow_unverified_pow = true;
        c.native_use_seeds = true;
        c.native_inject = true;
        c.no_good_citizen = true;
        c.randomx_enabled = true;
        ++total;
        still += pm::mainnet_refusal(c).empty() ? 0 : 1;
        check(!pm::mainnet_refusal(c).empty(), "bypass: " + k.name + " with every switch field set");
    }
    check(still == total, "bypass: every refused case stays refused (" + std::to_string(still) + "/" + std::to_string(total) + ")");
}


void knob() {
    const std::string want = "--test-unknown-fork-stall-s is test-only and refused on mainnet";
    xn::XmrNodeConfig f = allowed_mainnet();
    f.test_unknown_fork_stall_s = 120;
    give(f, "--test-unknown-fork-stall-s", "120");
    check(pm::mode_refusal(f) == want, "knob: --follow-only on mainnet with the stall knob", pm::mode_refusal(f));
    xn::XmrNodeConfig p;
    p.network = xn::MoneroNetwork::Mainnet;
    p.i_understand_mainnet = true;
    p.test_unknown_fork_stall_s = 120;
    check(pm::mode_refusal(p) == want, "knob: the pool mode on mainnet: the knob's line first", pm::mode_refusal(p));
    xn::XmrNodeConfig z = allowed_mainnet();
    z.test_unknown_fork_stall_s = 0;
    check(pm::mode_refusal(z).empty(), "knob: 0 on mainnet passes", pm::mode_refusal(z));
    xn::XmrNodeConfig r;
    r.network = xn::MoneroNetwork::Regtest;
    r.test_unknown_fork_stall_s = 120;
    check(pm::test_knob_mainnet_refusal(r).empty(), "knob: off mainnet the knob passes");
}

}  // namespace

int main() {
    std::printf("== v37_xmr_mainnet_refusal_kat ==\n");
    allowed();
    refused();
    order();
    bypass();
    knob();
    std::printf("v37_xmr_mainnet_refusal_kat: %d passed, %d failed\n", g_pass, g_fail);
    std::printf("RESULT: %s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
