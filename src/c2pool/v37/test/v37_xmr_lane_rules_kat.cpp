// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_lane_rules_kat -- the Path B lane rules (impl/xmr/pathb/pathb_lane_rules.hpp):
//   the field set (22 TLV ids = the K numbers, the codec byte K22, epoch_cur in the trailer); the epoch-0
//   TLV (263 B) and G per network against the independent goldens; rules_digest changes when any K value
//   changes; a node whose compiled G differs refuses to start; LANE_RULES_MISMATCH names the first differing
//   id with both values; unknown / missing / out-of-order ids and codec byte 1 refused; peers at another
//   epoch_cur accepted; the 29 retired fields, the pool identity and the policy values are not fields.
#include <cstdio>

#include "impl/xmr/pathb/test/pathb_lane_rules_cases.hpp"

int main() {
    std::printf("== v37_xmr_lane_rules_kat ==\n");
    return pathb_lane_rules_cases::run() != 0 ? 1 : 0;
}
