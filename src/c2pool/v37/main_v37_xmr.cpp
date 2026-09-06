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
// c2pool-v37-xmr — the single-node, stagenet-capable Monero/RandomX (Family-B)
// v37 daemon entrypoint. It stands up XmrNode (see xmr/xmr_node.hpp) against a
// live monerod and runs the mine-and-settle path.
//
// EXPERIMENTAL — PROTOTYPE / STAGENET ONLY. Do NOT run against mainnet value.
// The default network is stagenet; mainnet requires --i-understand-mainnet and
// is still fenced at the coinbase (FCMP/CARROT + mainnet acknowledgement).
//
// Modes:
//   --mock-smoke    network-free CI smoke against a monerod STUB
//                   (MockMonerodTransport); prints S1..S6 and exits.
//   (default)       connect to monerod at --rpc-host/--rpc-port (+ --zmq-port),
//                   bring the node up, and run until SIGINT.
//
// NOTE (single-node): real multi-node p2p carrier relay (src/pool p2p) is a
// NOTED FOLLOW-ON. This cut runs single-node (its own carriers), enough for the
// X9 stagenet mine-and-settle demo. RandomX verify + the X6 coinbase crypto are
// linked only in the CI/stagenet build (V37_XMR_HAVE_MONERO_CRYPTO / RandomX);
// the light build runs index + settlement + the F1 driver.
// ===========================================================================

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>

#include "xmr/xmr_node.hpp"
#include "xmr/xmr_node_config.hpp"
#include "xmr/xmr_node_smoke.hpp"
#include "xmr/xmr_live_transport.hpp"

using namespace c2pool::v37n::xmr;

static std::atomic<bool> g_stop{false};
static void on_sigint(int) { g_stop.store(true); }

static MoneroNetwork parse_net(const std::string& s) {
    if (s == "mainnet")  return MoneroNetwork::Mainnet;
    if (s == "testnet")  return MoneroNetwork::Testnet;
    return MoneroNetwork::Stagenet;
}

static int run_mock_smoke() {
    std::filesystem::path tmp =
        std::filesystem::temp_directory_path() /
        ("c2pool-v37-xmr-smoke-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);

    auto rep = smoke::run(tmp);
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

    std::signal(SIGINT, on_sigint);
    std::signal(SIGTERM, on_sigint);
    std::printf("node up. Ctrl-C to stop. (ZMQ push drives the tip; RPC poll fallback every 5s)\n");

    // Main loop: pump the RPC poll fallback (no-op under real ZMQ) so the
    // MainchainIndex keeps tracking the tip + seed reach, and re-issue the
    // adapter's ensure_seed_reach on each tick.
    while (!g_stop.load()) {
        transport.pump_poll();
        node.adapter().ensure_seed_reach();
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    std::printf("\nstopping…\n");
    node.stop();
    std::printf("stopped. hw_height=%llu\n",
                static_cast<unsigned long long>(node.hw().hw_height));
    return 0;
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
        else if (a == "--lane-chain") cfg.lane_chain =
                     static_cast<::v37::ChainId>(std::stoul(next("0")));
        else if (a == "--d-conf") cfg.d_conf = std::stoull(next("60"));
        else if (a == "--data-dir") cfg.settle_db_path = next("");
        else if (a == "--i-understand-mainnet") cfg.i_understand_mainnet = true;
        else if (a == "--randomx") cfg.randomx_enabled = true;
        else if (a == "--help" || a == "-h") {
            std::printf(
                "c2pool-v37-xmr (EXPERIMENTAL prototype; stagenet default)\n"
                "  --mock-smoke                 network-free CI smoke (monerod stub), then exit\n"
                "  --network <stagenet|testnet|mainnet>   default stagenet\n"
                "  --rpc-host <h>  --rpc-port <p>  --zmq-port <p>\n"
                "  --stratum-port <p>  --lane-chain <id>  --d-conf <n>\n"
                "  --data-dir <path>            override the settlement store dir\n"
                "  --i-understand-mainnet       required to settle a mainnet block\n"
                "  --randomx                    enable heavy RandomX verify (CI/stagenet)\n");
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
