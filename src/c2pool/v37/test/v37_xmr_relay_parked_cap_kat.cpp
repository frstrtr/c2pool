// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_parked_cap_kat -- O-P5 (ruling 23, POLICY): the relay verify
// parked-list cap (RelayOptions::parked_max, park()).
//
//   P1  the default cap is open_bins x (1 + r_max) from the ruled lane params
//       (the:K04, the:K08) = 1632 objects, not a literal.
//   P2  a parked set of exactly the cap is retained: none evicted,
//       RelayStats::queue_dropped stays 0.
//   P3  the cap+1-th parked item evicts the oldest (FIFO): the size holds at
//       the cap, queue_dropped == 1, the first id is gone, the rest are kept.
//   P4  a configured cap (--relay-parked-max path) is honoured: a smaller cap
//       holds that many and evicts the overflow.
#include <chrono>
#include <cstdio>
#include <utility>
#include <vector>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include "impl/xmr/pathb/pathb_params.hpp"

using namespace gap2test;
namespace pathb = c2pool::xmr::pathb;

// A distinct id per index (index in the low 8 bytes; fits any cap used here).
static bytes32 id_of(std::size_t i) {
    bytes32 b{};
    for (int k = 0; k < 8; ++k) b[k] = static_cast<u8>((i >> (8 * k)) & 0xffu);
    return b;
}

static XmrRelayNode make_node(RelayOptions ro, ChainView& chain) {
    return XmrRelayNode(
        std::move(ro), chain,
        [](const std::vector<u8>&, const bytes32&, bytes32&) { return true; },
        []() -> std::pair<u64, bytes32> { return {0, bytes32{}}; },
        [](const std::string&) {});
}

int main() {
    Checker check;

    // P1: the derived default.
    const std::size_t cap = pathb::kRuledLaneParams.open_bins * (1 + pathb::kRuledLaneParams.r_max);
    RelayOptions ro; ro.chain = 7;
    check(ro.parked_max == cap, "default parked cap == open_bins x (1 + r_max)");
    check(cap == 96u * 17u, "ruled lane params give 96 x 17");
    check(ro.parked_max == 1632u, "default parked cap == 1632 objects");

    ChainView chain;
    XmrRelayNode node = make_node(ro, chain);

    // P2: fill exactly the cap with distinct honest ids; none evicted.
    std::size_t sz = 0;
    for (std::size_t i = 0; i < cap; ++i) sz = node.test_park(id_of(i));
    check(sz == cap, "a parked set of exactly the cap is retained");
    check(node.verify_parked_size() == cap, "parked size == cap after filling the cap");
    check(node.stats().queue_dropped.load() == 0u, "no eviction at or below the cap");
    check(node.test_parked_has(id_of(0)), "oldest (id 0) still parked at exactly the cap");

    // P3: one more (the cap+1-th) evicts the oldest; size holds at the cap.
    sz = node.test_park(id_of(cap));
    check(sz == cap, "parked size stays at the cap after the cap+1-th item");
    check(node.stats().queue_dropped.load() == 1u, "exactly one eviction on overflow");
    check(!node.test_parked_has(id_of(0)), "the oldest (id 0) was evicted");
    check(node.test_parked_has(id_of(1)), "the second-oldest (id 1) is retained");
    check(node.test_parked_has(id_of(cap)), "the newest (id cap) is retained");

    // P4: a configured (smaller) cap is honoured and tracks the overflow.
    RelayOptions ro2; ro2.chain = 7; ro2.parked_max = 4;
    ChainView chain2;
    XmrRelayNode node2 = make_node(ro2, chain2);
    for (std::size_t i = 0; i < 6; ++i) node2.test_park(id_of(i));
    check(node2.verify_parked_size() == 4u, "a configured cap of 4 holds 4");
    check(node2.stats().queue_dropped.load() == 2u, "2 evicted past a cap of 4");

    return check.done("v37_xmr_relay_parked_cap_kat");
}
