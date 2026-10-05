// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// v37_xmr_relay_eclipse_kat -- inbound and outbound relay links counted apart.
//
// A victim relay V (discovery on, three honest seed relays H1..H3, inbound cap
// 8, outbound target 3) whose dialing is held while eight inbound relays fill
// every inbound slot:
//   E1  the defaults: 22 inbound, 10 outbound, 1 accepted link per address
//   E2  eight inbound links are accepted; a ninth is refused at accept (never
//       HELLO-ok) and V's inbound count stays 8
//   E3  dialing released: V dials the seeds and reaches its outbound target,
//       3 HELLO-ok outbound links, with all 8 inbound links still up (11
//       links) -- inbound links took no outbound slot and did not stop the
//       dialing (a dial gate on the total link count, 8 before, stops here)
//   E4  the target is met, not exceeded: V holds exactly 3 outbound links
// Loopback only; no RandomX is called; no monerod.
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <thread>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>

using namespace gap2test;
using namespace std::chrono_literals;

static constexpr u32 kChain = 7;
static constexpr u64 kShareDiff = 1000;

static RelayOptions base_opts() {
    RelayOptions o;
    o.network = 3; o.chain = kChain; o.share_diff = kShareDiff; o.bind = BindMode::None;
    o.lane_params_digest = lane_params_digest(::v37::LaneParams{}, kShareDiff, BindMode::None);
    o.listen_host = "127.0.0.1"; o.listen_port = 0;
    o.hello_timeout_ms = 3000;
    return o;
}

struct Node {
    ChainView chain;
    std::unique_ptr<XmrRelayNode> relay;
    explicit Node(RelayOptions o, bool dialing = true) {
        relay = std::make_unique<XmrRelayNode>(
            std::move(o), chain,
            [](const std::vector<u8>&, const bytes32&, bytes32& pow) { pow.fill(0); return true; },
            [] { return std::pair<u64, bytes32>{0, bytes32{}}; },
            [](const std::string&) {});
        if (!dialing) relay->set_dialing(false);
    }
    ~Node() { relay->stop(); }
    std::pair<std::size_t, std::size_t> links() const {   // (outbound, inbound) HELLO-ok links
        std::size_t out = 0, in = 0;
        for (const auto& [k, o] : relay->ready_links()) { (void)k; (o ? out : in)++; }
        return {out, in};
    }
};

template <class F>
static bool wait_until(F cond, std::chrono::milliseconds limit = 15000ms) {
    const auto dl = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < dl) {
        if (cond()) return true;
        std::this_thread::sleep_for(20ms);
    }
    return cond();
}

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_eclipse_kat ==\n");
    std::string why;

    {
        const RelayOptions d;
        C(d.max_inbound == 22 && d.max_outbound == 10 && d.max_inbound_per_addr == 1,
          "E1 defaults: 22 inbound, 10 outbound, 1 accepted link per address");
    }

    // three honest seed relays (listen only)
    std::vector<std::unique_ptr<Node>> H;
    std::vector<std::pair<std::string, u16>> seeds;
    for (int i = 0; i < 3; ++i) {
        RelayOptions o = base_opts(); o.listen = true;
        H.push_back(std::make_unique<Node>(o));
        C(H.back()->relay->start(why), "seed H" + std::to_string(i + 1) + " starts " + why);
        seeds.emplace_back("127.0.0.1", H.back()->relay->listen_port());
    }

    // the victim: discovery on, seeds H1..H3, inbound cap 8, outbound target 3, dialing held
    RelayOptions vo = base_opts();
    vo.listen = true; vo.discovery = true; vo.seeds = seeds;
    vo.max_inbound = 8; vo.max_outbound = 3;
    Node V(vo, /*dialing=*/false);
    C(V.relay->start(why), "victim V starts (dialing held) " + why);
    const u16 vport = V.relay->listen_port();

    // eight inbound relays fill V's inbound slots
    std::vector<std::unique_ptr<Node>> A;
    for (int i = 0; i < 8; ++i) {
        RelayOptions o = base_opts(); o.peers.emplace_back("127.0.0.1", vport);
        A.push_back(std::make_unique<Node>(o));
        A.back()->relay->start(why);
    }
    C(wait_until([&] { return V.links().second == 8; }) && V.links().first == 0,
      "E2 eight inbound links HELLO-ok at V (no outbound yet: dialing held)");

    // a ninth is refused at accept
    const u64 ref0 = V.relay->transport().refused_inbound_cap();
    RelayOptions o7 = base_opts(); o7.peers.emplace_back("127.0.0.1", vport);
    auto A7 = std::make_unique<Node>(o7);
    A7->relay->start(why);
    C(wait_until([&] { return V.relay->transport().refused_inbound_cap() > ref0; }, 5000ms),
      "E2 a ninth inbound relay is refused at accept (inbound cap 8)");
    std::this_thread::sleep_for(300ms);
    C(V.links().second == 8 && A7->relay->ready_peers().empty(), "E2 V's inbound count stays 8; the ninth never passes HELLO");

    // release dialing: V must reach its outbound target with every inbound slot full
    V.relay->set_dialing(true);
    C(wait_until([&] { return V.links().first == 3; }),
      "E3 V dials the seeds and reaches its outbound target (3 HELLO-ok outbound links)");
    const auto [out, in] = V.links();
    C(in == 8 && V.relay->n_connections() >= 11,
      "E3 ... with all 8 inbound links still up (" + std::to_string(out) + " out + " + std::to_string(in) + " in)");
    std::this_thread::sleep_for(2500ms);   // two more discovery ticks
    C(V.links().first == 3, "E4 the outbound target is met, not exceeded (3 outbound links)");

    A7.reset();
    A.clear();
    H.clear();
    return C.done("v37_xmr_relay_eclipse_kat");
}
