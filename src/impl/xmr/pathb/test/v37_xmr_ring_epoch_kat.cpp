// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_ring_epoch_kat (test builds only: V37_XMR_RING_TEST_EPOCHS), in
// memory:
//   at_bin = H(h_act - 1) + 1 + Fresh, on the best chain and on a side tip
//   forking below h_act - 1 with another H(h_act - 1) (each reads its own);
//   depth_of_bin at at_bin - 1 and at at_bin; depth_of_rules; the depth of
//   epoch 0 with and without its list, of an epoch >= 1 without its list
//   (unknown); the ring rules' refusals with their exact texts, depth_max 7
//   accepted and 8 refused; sigma's vectors (one merge crossed; a merge and an
//   older split; 2 -> 4 -> 2; the plain first split; the reach boundary; a
//   common depth not divided out; the reach ended at the second K-step
//   boundary) and merge_delta at a merge and a split; merge_delta and sigma
//   with a step at the top bin.
// ---------------------------------------------------------------------------
#ifndef V37_XMR_RING_TEST_EPOCHS
#error "v37_xmr_ring_epoch_kat is built only with V37_XMR_RING_TEST_EPOCHS"
#endif

#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_kstep.hpp"
#include "pathb_kat_admit.hpp"
#include "pathb_kat_store.hpp"
#include "pathb_ratchet_sim.hpp"

namespace {

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

const std::uint64_t kFresh = pb::kRuledLaneParams.fresh_max;

// ---------------------------------------------------------------------------
void at_bin_values() {
    check(pb::at_bin_of(3000105, 2) == 3000108, "at_bin_of(3,000,105, Fresh 2) = 3,000,108 (H + 1 + Fresh)");
    check(pb::at_bin_of(0, 0) == 1, "at_bin_of(0, 0) = 1");
    const pb::KStepList one{pb::KStep{3000108, 0, 1}};
    check(pb::depth_of_bin(one, 3000107, 0) == 0 && pb::depth_of_bin(one, 3000108, 0) == 1 &&
                  pb::depth_of_bin(one, 3000109, 0) == 1,
          "depth_of_bin: at_bin - 1 keeps the depth before; at_bin has the depth after");
    const pb::KStepList two{pb::KStep{100, 0, 1}, pb::KStep{110, 1, 0}};
    check(pb::depth_of_bin(two, 99, 0) == 0 && pb::depth_of_bin(two, 100, 0) == 1 && pb::depth_of_bin(two, 109, 0) == 1 &&
                  pb::depth_of_bin(two, 110, 0) == 0,
          "depth_of_bin over a split then a merge");
}

// ---------------------------------------------------------------------------
void depths() {
    const pb::PathbLaneRules r0 = pb::epoch0_lane_rules(pb::LaneNet::Regtest);
    check(pb::depth_of_rules(pb::ring_test_rules(r0, 1)) == 0 && pb::depth_of_rules(pb::ring_test_rules(r0, 2)) == 1 &&
                  pb::depth_of_rules(pb::ring_test_rules(r0, 4)) == 2 && pb::depth_of_rules(pb::ring_test_rules(r0, 128)) == 7,
          "depth_of_rules: log2 of a power-of-two K17 (1, 2, 4, 128 -> 0, 1, 2, 7)");
    check(!pb::depth_of_rules(pb::ring_test_rules(r0, 0)) && !pb::depth_of_rules(pb::ring_test_rules(r0, 3)) &&
                  !pb::depth_of_rules(pb::ring_test_rules(r0, 255)),
          "depth_of_rules: K17 0, 3 and 255 have no depth");
    const pb::Hash32 g = pb::genesis_rules_digest(pb::LaneNet::Regtest);
    pb::EpochTable absent, held;
    absent.compiled.push_back(pb::CompiledEpoch{0, g, std::nullopt});
    held.compiled.push_back(pb::CompiledEpoch{0, g, r0});
    check(pb::depth_of_epoch(absent, 0, std::nullopt) == 0 && pb::depth_of_epoch(absent, 0, seq32(0x11)) == 0 &&
                  pb::depth_of_epoch(held, 0, std::nullopt) == 0 && pb::depth_of_epoch(held, 0, g) == 0,
          "rule E0: epoch 0's depth is 0 with its list absent or held, whatever digest is given");
    const pb::PathbLaneRules r2 = pb::ring_test_rules(r0, 2);
    pb::EpochTable t = held;
    t.compiled.push_back(pb::CompiledEpoch{1, seq32(0x21), std::nullopt});
    t.compiled.push_back(pb::CompiledEpoch{2, pb::rules_digest(r2), r2});
    check(!pb::depth_of_epoch(t, 1, std::nullopt) && !pb::depth_of_epoch(t, 1, seq32(0x21)),
          "an epoch >= 1 without its list: depth unknown, never 0");
    check(pb::depth_of_epoch(t, 2, pb::rules_digest(r2)) == 1 && pb::depth_of_epoch(t, 2, std::nullopt) == 1 &&
                  !pb::depth_of_epoch(t, 2, seq32(0x22)) && !pb::depth_of_epoch(t, 3, std::nullopt),
          "an epoch >= 1 with its list: its depth, by digest when one is given; another digest or no entry: unknown");
    check(pb::table_has_k_step(t) && !pb::table_has_k_step(held), "the gate: a K17 = 2 epoch or an unknown depth arms it");
}

// ---------------------------------------------------------------------------
// at_bin on a chain: the best tip and a side tip forking below h_act - 1 with another H(h_act - 1)
void at_bin_on_chains() {
    const KatNet net;
    const pb::PathbLaneRules r2 = pb::ring_test_rules(pb::epoch0_lane_rules(pb::LaneNet::Regtest), 2);
    const pb::Hash32 d2 = pb::rules_digest(r2);
    const std::uint64_t h_act = 12;  // H(h_act) != H(h_act - 1) at one Monero height per 12 positions
    pb::EpochTable T = kat_table(net);
    T.attempts.push_back(ratchet_sim::fixed2(1, d2, 1, h_act));
    T.compiled.push_back(pb::CompiledEpoch{1, d2, r2});
    KatNode n(net, 1152, pb::kRuledRatchetParams, T);
    const std::vector<pb::Hash32> best = scaffold_chain(n, n.tree.genesis().id, 20, 0x51, h_pos);
    const std::uint64_t fork = h_act - 3;
    const auto higher = [](std::uint64_t x) { return h_pos(x) + 1; };
    const std::vector<pb::Hash32> side = scaffold_chain(n, best[fork - 1], h_act + 1 - fork, 0x52, higher, 3);
    check(best.size() == 20 && side.size() == h_act + 1 - fork && n.ar.rows().size() == 1 && n.ar.rows()[0].h_act == h_act,
          "a chain of 20 with the activation at 12, a side branch of 4 forking at 9");
    const auto list_of = [&](const pb::Hash32& tip) {
        const pb::CarrierNode& t = n.node(tip);
        const std::optional<pb::TipActs> a = pb::tip_acts(n.RP, n.T, n.tree, n.store, n.ar, t, true);
        const pb::LaneView v = n.store.view_at(tip);
        return std::make_pair(a, pb::ksteps_at(*a, n.T, n.store, v, pb::KStepBook{}, kFresh));
    };
    const pb::LaneView bv = n.store.view_at(best.back());
    const pb::LaneView sv = n.store.view_at(side.back());
    const std::uint64_t hb = bv.record(h_act - 1), hs = sv.record(h_act - 1);
    check(hb != hs && hb != bv.record(h_act), "the vector: H(h_act - 1) differs between the branches, and from H(h_act)");
    const auto [ab, kb] = list_of(best.back());
    check(ab && ab->consistent && !kb.gap && kb.list == pb::KStepList{pb::KStep{pb::at_bin_of(hb, kFresh), 0, 1}},
          "the best tip: one step at at_bin_of(H(h_act - 1)), depth 0 -> 1");
    const auto [as, ks] = list_of(side.back());
    check(as && as->consistent && as->rows.size() == 1 && !ks.gap &&
                  ks.list == pb::KStepList{pb::KStep{pb::at_bin_of(hs, kFresh), 0, 1}},
          "the side tip forking below h_act - 1: its own at_bin, from its own H(h_act - 1)");
}

// ---------------------------------------------------------------------------
// the ring rules (start-up step 5 with the option)
pb::EpochTable ring_table(std::vector<std::uint8_t> k17, std::vector<std::uint16_t> epochs = {}) {
    const pb::PathbLaneRules r0 = pb::epoch0_lane_rules(pb::LaneNet::Regtest);
    pb::EpochTable T;
    T.compiled.push_back(pb::CompiledEpoch{0, pb::genesis_rules_digest(pb::LaneNet::Regtest), r0});
    for (std::size_t i = 0; i < k17.size(); ++i) {
        pb::PathbLaneRules r = pb::ring_test_rules(r0, k17[i]);
        r.coverage = static_cast<std::uint8_t>(r0.coverage + i + 1);  // a list (and digest) of its own per epoch
        const std::uint16_t e = epochs.empty() ? static_cast<std::uint16_t>(i + 1) : epochs[i];
        T.compiled.push_back(pb::CompiledEpoch{e, pb::rules_digest(r), r});
    }
    return T;
}

void refuses(const pb::EpochTable& T, const std::string& want, const std::string& what) {
    const pb::StartupCheck c = pb::ring_rules_valid(pb::LaneNet::Regtest, T);
    check(!c.ok && c.why == want, what + ": \"" + c.why + "\"");
}

void ring_rules() {
    {
        pb::EpochTable T = ring_table({2});
        T.ring_rules[1] = pb::RingRule{1, 1};
        check(pb::ring_rules_valid(pb::LaneNet::Regtest, T).ok, "K17 = 2 with depth_max 1, step_max 1: ok");
    }
    refuses(ring_table({3}), "compiled epoch 1: payment_groups 3 is not a power of two", "R-1");
    refuses(ring_table({2}), "compiled epoch 1: no ring rule", "R-2");
    {
        pb::EpochTable T = ring_table({2});
        T.ring_rules[1] = pb::RingRule{std::nullopt, 1};
        refuses(T, "compiled epoch 1: ring rule field depth_max unset", "R-3 depth_max");
        T.ring_rules[1] = pb::RingRule{1, std::nullopt};
        refuses(T, "compiled epoch 1: ring rule field step_max unset", "R-3 step_max");
        T.ring_rules[1] = pb::RingRule{};
        refuses(T, "compiled epoch 1: ring rule field depth_max unset", "R-3 a value-initialised rule");
    }
    {
        pb::EpochTable T = ring_table({2});
        T.ring_rules[1] = pb::RingRule{7, 1};
        check(pb::ring_rules_valid(pb::LaneNet::Regtest, T).ok, "R-4: depth_max = 7 accepted (K17 = 2, step_max 1)");
        T.ring_rules[1] = pb::RingRule{8, 1};
        refuses(T, "compiled epoch 1: ring rule field depth_max = 8: not built (K17 is one byte)", "R-4: depth_max = 8");
    }
    {
        pb::EpochTable T = ring_table({2});
        T.ring_rules[1] = pb::RingRule{1, 0};
        refuses(T, "compiled epoch 1: ring rule field step_max = 0: below 1", "R-5 below 1");
        T.ring_rules[1] = pb::RingRule{1, 2};
        refuses(T, "compiled epoch 1: ring rule field step_max = 2 above depth_max 1", "R-5 above depth_max");
    }
    {
        pb::EpochTable T = ring_table({4});
        T.ring_rules[1] = pb::RingRule{1, 1};
        refuses(T, "compiled epoch 1: depth 2 above depth_max 1", "R-6");
    }
    {
        pb::EpochTable T = ring_table({2}, {2});
        T.ring_rules[2] = pb::RingRule{1, 1};
        refuses(T, "compiled epoch 2: the epoch before it is not compiled", "R-7");
    }
    {
        pb::EpochTable T = ring_table({4});
        T.ring_rules[1] = pb::RingRule{2, 1};
        refuses(T, "compiled epoch 1: depth step 2 above step_max 1", "R-8 a split of two levels");
    }
    {
        pb::EpochTable T = ring_table({2, 4, 1});
        T.ring_rules[1] = pb::RingRule{1, 1};
        T.ring_rules[2] = pb::RingRule{2, 1};
        refuses(T, "compiled epoch 3: depth step 2 above step_max 1", "R-8 a merge to K17 = 1 against the earlier epoch's rule");
        T.ring_rules[2] = pb::RingRule{2, 2};
        check(pb::ring_rules_valid(pb::LaneNet::Regtest, T).ok, "R-8: the same merge within the earlier epoch's step_max: ok");
    }
    {
        pb::EpochTable T = ring_table({2});
        T.ring_rules[1] = pb::RingRule{1, 1};
        T.ring_rules[5] = pb::RingRule{1, 1};
        refuses(T, "ring rule for epoch 5: no compiled epoch", "R-9");
    }
}

// ---------------------------------------------------------------------------
// sigma and merge_delta, as values (top 120, reach from 90 unless stated; top = the window's start bin + 1)
void sigma_values() {
    const pb::KStepList merge{pb::KStep{100, 1, 0}};
    check(pb::sigma(merge, 120, 90, 0) == 0, "(i) one merge behind, crossed: sigma 0");
    check(pb::sigma(merge, 120, 105, 0) == 0, "(ii) the same lane, the reach (and any window) before the merge: sigma 0");
    const pb::KStepList one_two_one{pb::KStep{100, 0, 1}, pb::KStep{110, 1, 0}};
    check(pb::sigma(one_two_one, 120, 90, 0) == 1, "(iii) a merge and an older split within reach (K 1 -> 2 -> 1): sigma 1");
    const pb::KStepList two_four_two{pb::KStep{100, 1, 2}, pb::KStep{110, 2, 1}};
    check(pb::sigma(two_four_two, 120, 90, 1) == 0, "(iii) the same two steps with K 2 -> 4 -> 2: sigma 0");
    check(pb::sigma(one_two_one, 120, 100, 0) == 0, "(iv) the split's older bin the first bin out of reach: sigma 0");
    check(pb::sigma(pb::KStepList{}, 120, 90, 1) == 0, "(v) a common depth (K = 2 throughout) is not divided out: sigma 0");
    // K 2 -> 1 -> 2 -> 1: an older merge at 95, the split at 100, the merge at 110
    const pb::KStepList three{pb::KStep{95, 1, 0}, pb::KStep{100, 0, 1}, pb::KStep{110, 1, 0}};
    check(pb::sigma(three, 120, 100, 0) == 0 && pb::sigma(three, 120, 90, 0) == 1,
          "(vi) the reach ended at the second K-step boundary (100): sigma 0; a reach past it, to the older merge: 1");
    const pb::KStepList split{pb::KStep{100, 0, 1}};
    check(pb::sigma(split, 120, 90, 1) == 0, "(vii) the plain first split (K 1 -> 2): sigma 0");
    check(pb::merge_delta(one_two_one, 120, 105) == 1 && pb::merge_delta(one_two_one, 120, 95) == 1 &&
                  pb::merge_delta(one_two_one, 120, 112) == 0 && pb::merge_delta(one_two_one, 105, 95) == 0,
          "merge_delta: the merge counts within (b, top], the split adds nothing");
    check(pb::merge_delta(pb::KStepList{pb::KStep{110, 2, 0}}, 120, 100) == 2, "merge_delta of a two-level merge: 2");
    check(pb::merge_delta(split, 120, 90) == 0, "merge_delta of a split: 0");
    // a step at the top bin
    const pb::KStepList top_merge{pb::KStep{121, 1, 0}};
    check(pb::merge_delta(top_merge, 121, 120) == 1, "merge_delta: a merge at the top bin, from the bin below it: 1");
    check(pb::merge_delta(top_merge, 121, 100) == 1, "merge_delta: a merge at the top bin, from an older bin: 1");
    check(pb::sigma(pb::KStepList{pb::KStep{100, 0, 1}, pb::KStep{121, 1, 0}}, 121, 90, 0) == 1,
          "sigma: a merge at the top bin and an older split within reach: 1");
    check(pb::sigma(top_merge, 121, 90, 0) == 0, "sigma: a lone merge at the top bin: 0");
}

}  // namespace

int main() {
    at_bin_values();
    depths();
    at_bin_on_chains();
    ring_rules();
    sigma_values();
    return finish("v37_xmr_ring_epoch_kat");
}
