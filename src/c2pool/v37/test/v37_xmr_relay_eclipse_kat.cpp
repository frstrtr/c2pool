// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// v37_xmr_relay_eclipse_kat -- inbound and outbound relay links counted apart
// (the Path B relay node).
//
// A victim relay V (discovery on, three honest seed relays H1..H3, inbound cap
// 8, outbound target 3) whose dialing is held while eight inbound relays fill
// every inbound slot:
//   E1  the defaults: 101 inbound, 12 outbound, 1 accepted link per address
//   E2  eight inbound links are accepted; a ninth is refused at accept (never
//       HELLO-ok) and V's inbound count stays 8
//   E3  dialing released: V dials the seeds and reaches its outbound target,
//       3 HELLO-ok outbound links, with all 8 inbound links still up (11
//       links) -- inbound links took no outbound slot and did not stop the
//       dialing
//   E4  the target is met, not exceeded: V holds exactly 3 outbound links
// Loopback only; every node with its own PathbNode; no monerod.
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <thread>

#include "xmr_pathb_relay_test_util.hpp"

using namespace pathb_relay_test;
using namespace std::chrono_literals;

// (outbound, inbound) HELLO-ok links
static std::pair<std::size_t, std::size_t> links_of(RNode& n) {
    std::size_t out = 0, in = 0;
    for (const auto& [k, o] : n.r().ready_links()) { (void)k; (o ? out : in)++; }
    return {out, in};
}

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_eclipse_kat ==\n");
    std::string why;

    {
        const pb::PathbRelayOptions d;
        C(d.max_inbound == 101 && d.max_outbound == 12 && d.max_inbound_per_addr == 1,
          "E1 defaults: 101 inbound, 12 outbound, 1 accepted link per address");
    }

    Rig rig;
    // three honest seed relays (listen only)
    std::vector<std::unique_ptr<RNode>> H;
    std::vector<std::pair<std::string, u16>> seeds;
    for (int i = 0; i < 3; ++i) {
        H.push_back(rig.make("H" + std::to_string(i + 1), Rig::opts(true)));
        C(H.back()->start(why), "seed H" + std::to_string(i + 1) + " starts " + why);
        seeds.emplace_back("127.0.0.1", H.back()->port());
    }

    // the victim: discovery on, seeds H1..H3, inbound cap 8, outbound target 3, dialing held
    pb::PathbRelayOptions vo = Rig::opts(true);
    vo.discovery = true; vo.seeds = seeds;
    vo.max_inbound = 8; vo.max_outbound = 3;
    auto V = rig.make("V", vo);
    V->r().set_dialing(false);
    C(V->start(why), "victim V starts (dialing held) " + why);
    const u16 vport = V->port();

    // eight inbound relays fill V's inbound slots
    std::vector<std::unique_ptr<RNode>> A;
    for (int i = 0; i < 8; ++i) {
        A.push_back(rig.make("A" + std::to_string(i), Rig::opts(false, {vport})));
        A.back()->start(why);
    }
    C(wait_until([&] { return links_of(*V).second == 8; }, 15000ms) && links_of(*V).first == 0,
      "E2 eight inbound links HELLO-ok at V (no outbound yet: dialing held)");

    // a ninth is refused at accept
    const u64 ref0 = V->links.net().refused_inbound_cap();
    auto A7 = rig.make("A8", Rig::opts(false, {vport}));
    A7->start(why);
    C(wait_until([&] { return V->links.net().refused_inbound_cap() > ref0; }, 5000ms),
      "E2 a ninth inbound relay is refused at accept (inbound cap 8)");
    std::this_thread::sleep_for(300ms);
    C(links_of(*V).second == 8 && A7->r().ready_peers().empty(), "E2 V's inbound count stays 8; the ninth never passes HELLO");

    // release dialing: V must reach its outbound target with every inbound slot full
    V->r().set_dialing(true);
    C(wait_until([&] { return links_of(*V).first == 3; }, 15000ms),
      "E3 V dials the seeds and reaches its outbound target (3 HELLO-ok outbound links)");
    const auto [out, in] = links_of(*V);
    C(in == 8 && V->links.n_peers() >= 11,
      "E3 ... with all 8 inbound links still up (" + std::to_string(out) + " out + " + std::to_string(in) + " in)");
    std::this_thread::sleep_for(2500ms);   // two more discovery ticks
    C(links_of(*V).first == 3, "E4 the outbound target is met, not exceeded (3 outbound links)");

    A7.reset();
    A.clear();
    V.reset();
    H.clear();
    return C.done("v37_xmr_relay_eclipse_kat");
}
