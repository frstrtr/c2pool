// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_parked_cap_kat -- the relay verify parked-list cap of the Path B
// relay node (PathbRelayOptions::parked_max, --relay-parked-max).
//
//   P1  the default cap is open_bins x (1 + r_max) from the ruled lane params
//       = 1632 objects, not a literal.
//   P2  a parked set of exactly the cap is retained: none evicted,
//       PathbRelayStats::queue_dropped stays 0.
//   P3  the cap+1-th parked item evicts the oldest (FIFO): the size holds at
//       the cap, queue_dropped == 1, the first frame is gone, the rest are kept.
//   P4  a configured cap (--relay-parked-max path) is honoured: a smaller cap
//       holds that many and evicts the overflow.
#include <cstdio>
#include <utility>
#include <vector>

#include "xmr_pathb_relay_test_util.hpp"
#include "impl/xmr/pathb/pathb_params.hpp"

using namespace pathb_relay_test;
namespace pathb = c2pool::xmr::pathb;

// A distinct FC_CARRIER-headed frame per index (index in the 8 bytes after the frame header).
static std::vector<u8> frame_of(std::size_t i) {
    std::vector<u8> f{pathb::kOpFcCarrier, pathb::kFrameVersion1, 0x00, 0x00, 0x00, 0x00};
    for (int k = 0; k < 8; ++k) f.push_back(static_cast<u8>((i >> (8 * k)) & 0xffu));
    return f;
}

int main() {
    Checker check;

    // P1: the derived default.
    const std::size_t cap = pathb::kRuledLaneParams.open_bins * (1 + pathb::kRuledLaneParams.r_max);
    pathb::PathbRelayOptions ro;
    check(ro.parked_max == cap, "default parked cap == open_bins x (1 + r_max)");
    check(cap == 96u * 17u, "ruled lane params give 96 x 17");
    check(ro.parked_max == 1632u, "default parked cap == 1632 objects");

    pathb::CarrierLinks links;
    pathb::PathbRelayNode node(ro, links);

    // P2: fill exactly the cap with distinct frames; none evicted.
    std::size_t sz = 0;
    for (std::size_t i = 0; i < cap; ++i) sz = node.test_park(1, frame_of(i));
    check(sz == cap, "a parked set of exactly the cap is retained");
    check(node.parked_size() == cap, "parked size == cap after filling the cap");
    check(node.stats().queue_dropped.load() == 0u, "no eviction at or below the cap");
    check(node.parked_has(frame_of(0)), "oldest (frame 0) still parked at exactly the cap");

    // P3: one more (the cap+1-th) evicts the oldest; size holds at the cap.
    sz = node.test_park(1, frame_of(cap));
    check(sz == cap, "parked size stays at the cap after the cap+1-th item");
    check(node.stats().queue_dropped.load() == 1u, "exactly one eviction on overflow");
    check(!node.parked_has(frame_of(0)), "the oldest (frame 0) was evicted");
    check(node.parked_has(frame_of(1)), "the second-oldest (frame 1) is retained");
    check(node.parked_has(frame_of(cap)), "the newest (frame cap) is retained");

    // P4: a configured (smaller) cap is honoured and tracks the overflow.
    pathb::PathbRelayOptions ro2;
    ro2.parked_max = 4;
    pathb::CarrierLinks links2;
    pathb::PathbRelayNode node2(ro2, links2);
    for (std::size_t i = 0; i < 6; ++i) node2.test_park(1, frame_of(i));
    check(node2.parked_size() == 4u, "a configured cap of 4 holds 4");
    check(node2.stats().queue_dropped.load() == 2u, "2 evicted past a cap of 4");

    return check.done("v37_xmr_relay_parked_cap_kat");
}
