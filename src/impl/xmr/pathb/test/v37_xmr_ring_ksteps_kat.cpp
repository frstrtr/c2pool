// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_ring_ksteps_kat (test builds only: V37_XMR_RING_TEST_EPOCHS): the
// K-step list of every tip and the K-step book, on persisted in-process nodes
// (the node KATs' Harness over MemoryKv), with a regtest table whose K17 goes
// 1 -> 1 -> 2 -> 1 by kind-2 descriptors (e1 = the epoch-0 list with coverage
// + 1, e2 = e1 with K17 = 2, e3 = e1 with coverage + 2: four digests).
// The oracle: a node fed the same frames from the lane's start. After every
// step: at each common held tip the list equals the oracle's (with a gap: the
// listed steps are the oracle's steps from known_from_bin on, depth0 the
// oracle's depth there); every visible step is readable on the tip's view or
// held by the book; the book holds exactly the best chain's known steps above
// the seed; the store's K_KSTEP rows equal the book.
// Cases: extensions across the steps, a prune past them, restarts before and
// after it (#1, #4, #12); a switch to a branch holding the step with another
// H(h_act - 1), then a prune (#2, #3b); a heavier, shorter branch whose tip
// lies below h_act (#3a), a held side tip and a template tip off the best
// chain (#8, #8b), away and back (#9); a carried receipt's projection row
// (#13); the self-check's anchor (#8c); step 4b's refusals (#11); joiners on
// a depth-0 chain and seeded above a step, then pruned (#10, #5); an adoption
// replacing a store with K_KSTEP rows, a restart, a prune (#6, #7); a below-seed held tip on a side branch forking
// in the claimed prefix, on a depth-0 chain and across a step (#10b, #10c); kbook_sync above a step (#3c); a tip
// not held below an activation of the best chain (#8d); step 4b (4) at the first record (#11); a joiner whose
// K step activates at p0 (#5b).
// ---------------------------------------------------------------------------
#ifndef V37_XMR_RING_TEST_EPOCHS
#error "v37_xmr_ring_ksteps_kat is built only with V37_XMR_RING_TEST_EPOCHS"
#endif

#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_kstep.hpp"
#include "pathb_kat_join.hpp"
#include "pathb_kat_node.hpp"
#include "pathb_ratchet_sim.hpp"

namespace c2pool::xmr::pathb {
struct PathbNodeTestAccess {
    static const KStepBook& kbook(const PathbNode& n) { return *n.kbook_; }
};
}  // namespace c2pool::xmr::pathb

namespace {

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;
using Access = pb::PathbNodeTestAccess;

const std::uint64_t kFresh = pb::kRuledLaneParams.fresh_max;

// The lane's table: K17 1 -> 1 -> 2 -> 1 at y1 < y2 < y3.
struct Lane {
    pb::EpochTable T;
    std::uint64_t y1 = 0, y2 = 0, y3 = 0;
};

Lane lane(const KatNet& net, std::uint64_t y1, std::uint64_t y2, std::uint64_t y3, std::uint8_t k2 = 2) {
    pb::PathbLaneRules r1 = pb::epoch0_lane_rules(pb::LaneNet::Regtest);
    r1.coverage = static_cast<std::uint8_t>(r1.coverage + 1);
    pb::PathbLaneRules r2 = pb::ring_test_rules(r1, k2);
    if (k2 == pb::kPaymentGroups) r2.coverage = static_cast<std::uint8_t>(r1.coverage + 3);  // still a list of its own
    pb::PathbLaneRules r3 = r1;
    r3.coverage = static_cast<std::uint8_t>(r1.coverage + 2);
    Lane l;
    l.y1 = y1;
    l.y2 = y2;
    l.y3 = y3;
    l.T = kat_table(net);
    l.T.attempts.push_back(ratchet_sim::fixed2(1, pb::rules_digest(r1), 1, y1));
    l.T.attempts.push_back(ratchet_sim::fixed2(2, pb::rules_digest(r2), y1 + 1, y2));
    l.T.attempts.push_back(ratchet_sim::fixed2(3, pb::rules_digest(r3), y2 + 1, y3));
    l.T.compiled.push_back(pb::CompiledEpoch{1, pb::rules_digest(r1), r1});
    l.T.compiled.push_back(pb::CompiledEpoch{2, pb::rules_digest(r2), r2});
    l.T.compiled.push_back(pb::CompiledEpoch{3, pb::rules_digest(r3), r3});
    l.T.ring_rules[2] = pb::RingRule{1, 1};
    return l;
}

// The K-step list of t at node n, with its own book; nullopt: not held, no Ok view, or not of kind Epoch.
struct TipList {
    pb::TipActs acts;
    pb::KSteps ks;
};
std::optional<TipList> list_at(const pb::PathbNode& n, const pb::EpochTable& T, const pb::Hash32& tip, bool held = true) {
    const pb::CarrierNode* t = n.tree().find(tip);
    if (t == nullptr) return std::nullopt;
    const pb::LaneView v = n.store().view_at(tip);
    if (!v.ok()) return std::nullopt;
    const std::optional<pb::TipActs> a = pb::tip_acts(pb::kRuledRatchetParams, T, n.tree(), n.store(), n.ar(), *t, held);
    if (!a || a->kind != pb::EpochAtKind::Epoch) return std::nullopt;
    return TipList{*a, pb::ksteps_at(*a, T, n.store(), v, Access::kbook(n), kFresh)};
}

// SH-2: equal lists without a gap; with a gap, the oracle's steps from known_from_bin on and its depth there.
bool same_as_oracle(const pb::KSteps& k, const pb::KSteps& o) {
    if (o.gap) return false;
    if (!k.gap) return k.list == o.list && k.depth0 == o.depth0;
    if (k.known_from_bin == pb::kNoKnownBin) return false;
    pb::KStepList tail;
    for (const pb::KStep& s : o.list)
        if (s.at_bin >= k.known_from_bin) tail.push_back(s);
    std::uint8_t d = o.depth0;
    for (const pb::KStep& s : o.list)
        if (s.at_bin <= k.known_from_bin) d = s.depth_after;
    return k.list == tail && k.depth0 == d;
}

// A gap whose first listed step lies at known_from_bin (a K step at p0): the listed steps equal the oracle's from
// known_from_bin on, depth0 equals the oracle's depth just below known_from_bin, and the depth at known_from_bin agrees.
bool same_from_step(const pb::KSteps& k, const pb::KSteps& o) {
    if (o.gap || !k.gap || k.known_from_bin == pb::kNoKnownBin || k.known_from_bin == 0) return false;
    pb::KStepList tail;
    for (const pb::KStep& s : o.list)
        if (s.at_bin >= k.known_from_bin) tail.push_back(s);
    return k.list == tail && pb::depth_of_bin(o.list, k.known_from_bin - 1, o.depth0) == k.depth0 &&
           pb::depth_of_bin(o.list, k.known_from_bin, o.depth0) == pb::depth_of_bin(k.list, k.known_from_bin, k.depth0);
}

// The book a node must hold: every non-seed AR row whose pair is a known step, at_bin from the oracle's record.
pb::KStepBook expected_book(const pb::PathbNode& n, const pb::PathbNode& o, const pb::EpochTable& T) {
    pb::KStepBook out;
    const std::vector<pb::ActivationRow>& rows = n.ar().rows();
    const std::size_t first = n.ar().joiner_p0() ? 1 : 0;
    const pb::LaneView ov = o.store().view_at(o.store().best_tip());
    for (std::size_t i = first; i < rows.size(); ++i) {
        const std::optional<std::uint8_t> before =
                i == 0 ? std::optional<std::uint8_t>(pb::kEpoch0Depth) : pb::depth_of_epoch(T, rows[i - 1].epoch, rows[i - 1].rules_digest);
        const std::optional<std::uint8_t> after = pb::depth_of_epoch(T, rows[i].epoch, rows[i].rules_digest);
        if (!before || !after || *before == *after) continue;
        out[rows[i].h_act] = pb::KStepRecord{rows[i].epoch, rows[i].h_act, pb::at_bin_of(ov.record(rows[i].h_act - 1), kFresh)};
    }
    return out;
}

pb::KStepBook kv_book(const MemoryKv& kv) {
    pb::KStepBook out;
    const std::string p = pb::store_keys::kstep_prefix(0);
    for (auto it = kv.data.lower_bound(p); it != kv.data.end() && it->first.compare(0, p.size(), p) == 0; ++it)
        if (const std::optional<pb::KStepRecord> r = pb::decode_kstep_row(it->second)) out[r->h_act] = *r;
    return out;
}

// After every step: the oracle comparison at each common held tip of n's best chain (and `extra` tips), KS-1's
// disjunction, the book against the best chain, the store's rows against the book.
void audit(const std::string& what, const pb::PathbNode& n, const pb::PathbNode& o, const pb::EpochTable& T,
           const MemoryKv* kv, const std::vector<pb::Hash32>& extra = {}) {
    std::vector<pb::Hash32> tips = extra;
    for (std::uint64_t x = std::max(n.store().first_record_pos(), n.tree().genesis().pos); x <= n.store().tip_pos(); ++x)
        if (const std::optional<pb::Hash32> id = n.store().best_at(x)) tips.push_back(*id);
    std::size_t compared = 0, bad = 0, ks1 = 0;
    std::string first_bad;
    for (const pb::Hash32& tip : tips) {
        const std::optional<TipList> a = list_at(n, T, tip), b = list_at(o, T, tip);
        if (!a || !b) continue;
        ++compared;
        if (!same_as_oracle(a->ks, b->ks)) {
            if (bad++ == 0) first_bad = "pos " + std::to_string(n.tree().find(tip)->pos);
        }
        // KS-1: every visible known step readable on the tip's view, or held by the book
        const pb::LaneView v = n.store().view_at(tip);
        for (std::size_t i = a->acts.seed_p0 ? 1 : 0; i < a->acts.rows.size(); ++i) {
            const pb::ActivationRow& r = a->acts.rows[i];
            const std::optional<std::uint8_t> before =
                    i == 0 ? std::optional<std::uint8_t>(pb::kEpoch0Depth)
                           : pb::depth_of_epoch(T, a->acts.rows[i - 1].epoch, a->acts.rows[i - 1].rules_digest);
            const std::optional<std::uint8_t> after = pb::depth_of_epoch(T, r.epoch, r.rules_digest);
            if (!before || !after || *before == *after) continue;
            const bool on_view = r.h_act - 1 <= v.pos() && (r.h_act - 1 > v.fork_pos() || r.h_act - 1 >= n.store().first_record_pos());
            const auto it = Access::kbook(n).find(r.h_act);
            const bool in_book = it != Access::kbook(n).end() && it->second.epoch == r.epoch;
            if (!on_view && !in_book) ++ks1;
        }
    }
    check(compared > 0 && bad == 0, what + ": the list at " + std::to_string(compared) + " common tips equals the oracle's" +
                                            (bad ? " (" + std::to_string(bad) + " differ, first at " + first_bad + ")" : ""));
    check(ks1 == 0, what + ": every visible step readable on its tip's view or held by the book (" + std::to_string(ks1) + " not)");
    check(Access::kbook(n) == expected_book(n, o, T), what + ": the book holds exactly the best chain's known steps (" +
                                                              std::to_string(Access::kbook(n).size()) + ")");
    if (kv != nullptr) check(kv_book(*kv) == Access::kbook(n), what + ": the store's K_KSTEP rows equal the book");
}

constexpr std::uint64_t kJ = 64;  // the subject's journal depth when it prunes (the node KATs' restart depth)

std::size_t add_node(Harness& h, const pb::PathbNodeConfig& c, MemoryKv** kv) {
    const std::size_t self = h.nodes.size();
    MemoryKv* k = nullptr;
    if (kv != nullptr) {
        h.kvs.push_back(std::make_unique<MemoryKv>());
        k = h.kvs.back().get();
        *kv = k;
    }
    h.nodes.push_back(std::make_unique<pb::PathbNode>(c, h.io(self), k));
    return self;
}

// A pruning subject: the fewest bodies and headers the flags keep (its own horizon and the view horizon bind).
pb::PathbNodeConfig pruner(Harness& h, const pb::EpochTable& T) {
    pb::PathbNodeConfig c = h.config(T, true, kJ);
    c.body_keep = 1;
    c.header_keep = 1;
    return c;
}

struct Miner {
    Harness& h;
    std::uint64_t tick_every = 12;  // one Monero height per 12 positions (0: none)
    std::uint32_t nonce = 100;
    std::uint64_t mined = 0;
    std::uint64_t top = kMonTop;    // the highest follower tip (a JoinNet holds rows above kMonTop)
    void operator()(std::size_t i) {
        if (tick_every != 0 && mined % tick_every == 0) h.mon_tip = std::min(h.mon_tip + 1, top);
        ++mined;
        h.mine(i, static_cast<std::size_t>(mined % 4), nonce++);
    }
};

void deliver(Harness& h, std::size_t from, std::size_t to, std::uint64_t lo, std::uint64_t hi) {
    for (std::uint64_t x = lo; x <= hi; ++x) {
        const std::optional<pb::Hash32> id = h[from].store().best_at(x);
        if (!id) break;
        (void)h[to].on_carrier(from, *pb::encode_fc_carrier(0, *h[from].bodies().get(*id), pb::kRuledLaneParams.r_max));
        h.pump();
    }
}

bool restart(Harness& h, std::size_t i, MemoryKv& kv, const pb::PathbNodeConfig& c, pb::StoreFault* fault = nullptr) {
    pb::LoadInputs in;
    in.T = c.T;
    in.journal_depth = c.journal_depth;
    pb::LoadResult lr = pb::pathb_load(kv, h.net.pool_id, h.net.rules_g, in);
    if (fault != nullptr) *fault = lr.fault;
    if (lr.fault != pb::StoreFault::None || !lr.state) return false;
    h.nodes[i] = std::make_unique<pb::PathbNode>(c, h.io(i), std::move(*lr.state), &kv);
    return true;
}

// The length at which the subject's prune (journal kJ) moves its first record past `pos`.
std::uint64_t prune_length(std::uint64_t pos) {
    return kJ + pb::admit_j0(pb::kRuledLaneParams) + pb::kRuledLaneParams.retarget_span + pos + 2 * 12 * 12;
}

// ---------------------------------------------------------------------------
// #1, #4, #12: extensions across the steps, restarts before and after a prune past them
void extensions() {
    const KatNet net;
    const Lane ln = lane(net, 8, 16, 24);
    Harness h(net);
    MemoryKv* kva = nullptr;
    const pb::PathbNodeConfig ca = pruner(h, ln.T);
    const std::size_t a = add_node(h, ca, &kva);
    const std::size_t o = h.add(ln.T, false);
    Miner mine{h};
    while (h[a].tree().best().pos < ln.y3 + 6) {
        mine(a);
        const std::uint64_t p = h[a].tree().best().pos;
        if (p == ln.y1 || p == ln.y2 || p == ln.y3) audit("#1 extension to " + std::to_string(p), h[a], h[o], ln.T, kva);
    }
    check(h[a].ar().rows().size() == 3 && Access::kbook(h[a]).size() == 2, "#1 three activations, two K steps in the book");
    // #12: a held tip at y2 - 1 with the best chain past y2: exactly one row at y2
    {
        const pb::CarrierNode* t = h[a].tree().find(*h[a].store().best_at(ln.y2 - 1));
        const std::optional<pb::TipActs> acts = pb::tip_acts(pb::kRuledRatchetParams, ln.T, h[a].tree(), h[a].store(), h[a].ar(), *t, true);
        std::size_t at_x = 0;
        for (const pb::ActivationRow& r : acts ? acts->rows : std::vector<pb::ActivationRow>{}) at_x += r.h_act == ln.y2 ? 1 : 0;
        check(acts && acts->consistent && at_x == 1, "#12 pos(best) >= x with an activation at x: exactly one row at x (" + std::to_string(at_x) + ")");
    }
    // #3c: kbook_sync above y2 puts the rows above y2 only (the y3 row again) and deletes none
    {
        pb::KStepBook copy = Access::kbook(h[a]);
        const std::optional<pb::KStepOps> ops = pb::kbook_sync(copy, h[a].ar(), ln.T, h[a].store(), kFresh, ln.y2);
        check(ops && ops->put.size() == 1 && ops->put[0].h_act == ln.y3 && ops->del.empty() && copy == Access::kbook(h[a]),
              "#3c kbook_sync above y2: one put, the y3 row; no delete; the book unchanged (" +
                      std::to_string(ops ? ops->put.size() : 0) + " puts)");
    }
    // #8d: a tip not held at x = y2 - 1, the best chain past y2 and y3: AR rows to x
    {
        const pb::Hash32 t = *h[a].store().best_at(ln.y2 - 2);
        const std::optional<TipList> nh = list_at(h[a], ln.T, t, false), oh = list_at(h[o], ln.T, t);
        check(nh && oh && nh->acts.consistent && same_as_oracle(nh->ks, oh->ks),
              "#8d a tip not held at x = y2 - 1, the best chain past y2: consistent, the oracle's list");
    }
    check(restart(h, a, *kva, ca), "#4 a restart before the prune loads");
    audit("#4 restart, the records held", h[a], h[o], ln.T, kva);
    const std::uint64_t L = prune_length(ln.y3);
    while (h[a].tree().best().pos < L) mine(a);
    const pb::PathbNode::PruneReport pr = h[a].prune(h.now);
    check(pr.written && h[a].store().first_record_pos() > ln.y3 - 1,
          "#1 the prune moves the first record past y3 - 1 (first " + std::to_string(h[a].store().first_record_pos()) + ")");
    audit("#1 after the prune: the steps from the book", h[a], h[o], ln.T, kva);
    {  // #11 (5) with h_act - 1 below the first record: a known step without its row
        MemoryKv k;
        k.data = kva->data;
        k.data.erase(pb::store_keys::kstep(0, ln.y2));
        pb::LoadInputs in;
        in.T = ln.T;
        in.journal_depth = kJ;
        check(pb::pathb_load(k, net.pool_id, net.rules_g, in).fault == pb::StoreFault::KStep,
              "#11 (5) pruned: a known step's row missing (h_act - 1 below the first record): KStep");
    }
    pb::StoreFault f = pb::StoreFault::None;
    check(restart(h, a, *kva, ca, &f), "#4 a restart after the prune loads (fault " + std::to_string(static_cast<int>(f)) + ")");
    audit("#4 restart after the prune: the book from the store", h[a], h[o], ln.T, kva);
    mine(a);
    audit("#4 an extension after the restart", h[a], h[o], ln.T, kva);
}

// ---------------------------------------------------------------------------
// #2, #3b: a switch to a branch holding the step with another H(y2 - 1); then a prune
void switches() {
    const KatNet net;
    const Lane ln = lane(net, 8, 16, 24);
    Harness h(net);
    MemoryKv* kva = nullptr;
    const pb::PathbNodeConfig ca = pruner(h, ln.T);
    const std::size_t a = add_node(h, ca, &kva);
    const std::size_t b = h.add(ln.T, true);
    const std::size_t o = h.add(ln.T, false);
    Miner mine{h};
    const std::uint64_t fork = ln.y2 - 3;
    while (h[a].tree().best().pos < fork) mine(a);
    h.cut = {{a, b}, {b, a}, {a, o}, {b, o}};
    while (h[a].tree().best().pos < ln.y2 + 2) mine(a);
    h.tick_monero();
    while (h[b].tree().best().pos < ln.y2 + 3) mine(b);
    const std::uint64_t ha = h[a].store().view_at(h[a].store().best_tip()).record(ln.y2 - 1);
    const std::uint64_t hb = h[b].store().view_at(h[b].store().best_tip()).record(ln.y2 - 1);
    check(ha != hb && Access::kbook(h[a]).size() == 1, "#2 the two branches' H(y2 - 1) differ (" + std::to_string(ha) + ", " + std::to_string(hb) + ")");
    h.cut.clear();
    deliver(h, a, b, fork + 1, h[a].tree().best().pos);
    deliver(h, b, o, fork + 1, h[b].tree().best().pos);
    deliver(h, b, a, fork + 1, h[b].tree().best().pos);
    check(h[a].tree().best().id == h[b].tree().best().id && h[o].tree().best().id == h[b].tree().best().id,
          "#2 A switches to B's branch, which holds the step");
    audit("#2 after the switch: B's at_bin", h[a], h[o], ln.T, kva);
    const std::uint64_t L = prune_length(ln.y3);
    while (h[a].tree().best().pos < L) mine(a);
    const pb::PathbNode::PruneReport pr = h[a].prune(h.now);
    check(pr.written && h[a].store().first_record_pos() > ln.y2 - 1, "#3b the prune passes y2 - 1");
    audit("#3b the rewound step's new at_bin, pruned", h[a], h[o], ln.T, kva);
}

// ---------------------------------------------------------------------------
// #3a, #8, #8b, #9: a heavier, SHORTER branch (flat Monero heights raise its difficulty) against a longer one that
// crosses y2. f = 110 (the difficulty still at d_min), S = 300 flat positions, L = 400 rising ones, y2 between.
void heavier_shorter() {
    const KatNet net;
    const std::uint64_t f = 110, s_len = 300, l_len = 400;
    const Lane ln = lane(net, 8, f + 350, f + 1000);
    Harness h(net);
    MemoryKv* kva = nullptr;
    const std::size_t a = add_node(h, h.config(ln.T, true), &kva);  // the subject (launch: builds templates, never mines)
    const std::size_t b = h.add(ln.T, true);                         // mines L
    const std::size_t c = h.add(ln.T, true);                         // mines S
    Miner flat{h, 0};
    while (h[c].tree().best().pos < f) flat(c);
    h.cut = {{a, b}, {b, a}, {a, c}, {c, a}, {b, c}, {c, b}};
    while (h[c].tree().best().pos < f + s_len) flat(c);
    Miner rising{h, 1, 50000};
    while (h[b].tree().best().pos < f + l_len) rising(b);
    const pb::CarrierNode sb = h[c].tree().best();  // copies: relayed frames grow the trees
    const pb::CarrierNode lb = h[b].tree().best();
    check(::c2pool::xmr::native::u128_greater(sb.cum_work, lb.cum_work) && sb.pos < ln.y2 && lb.pos >= ln.y2,
          "the vector: S (to " + std::to_string(sb.pos) + ") heavier than L (to " + std::to_string(lb.pos) + "), y2 = " +
                  std::to_string(ln.y2) + " between");
    h.cut.clear();
    deliver(h, b, a, f + 1, f + l_len);
    check(h[a].tree().best().id == lb.id && Access::kbook(h[a]).size() == 1, "#3a A on L, the step at y2 in its book");
    audit("#3a A on L", h[a], h[b], ln.T, kva);
    const pb::Hash32 l_tip = lb.id;
    const std::optional<TipList> before = list_at(h[a], ln.T, l_tip);
    const pb::PathbTemplate tmpl = h[a].make_template(h.now);  // #8b: a template on L's tip
    deliver(h, c, a, f + 1, f + s_len);
    check(h[a].tree().best().id == sb.id && h[a].ar().rows().size() == 1,
          "#3a A switches to the heavier, shorter S: its tip below y2, the activation rewound");
    check(Access::kbook(h[a]).empty() && kv_book(*kva).empty(), "#3a the book and the store hold no K step: erased, deleted, not put again");
    audit("#3a A on S", h[a], h[c], ln.T, kva);
    // #8: L's tip, held at A with pos(best) < y2 < x, against B (L best there)
    const std::optional<TipList> at_a = list_at(h[a], ln.T, l_tip), at_b = list_at(h[b], ln.T, l_tip);
    check(at_a && at_b && same_as_oracle(at_a->ks, at_b->ks) && at_a->ks.list.size() == 1,
          "#8 a held side tip with pos(best) < y < x: its own step, as on the node where its branch is best");
    // #8b: the template's tip, off the store's best chain after the switch
    const std::optional<TipList> at_t = list_at(h[a], ln.T, tmpl.tip);
    check(tmpl.status == pb::TemplateStatus::Ok && tmpl.tip == l_tip && at_t && at_b && same_as_oracle(at_t->ks, at_b->ks),
          "#8b the template's tip after the switch: f derived, its own step");
    // #9: away and back with a rewind: the same list
    Miner more{h, 1, 90000};
    const std::uint64_t need = h[b].tree().best().pos + 2 * s_len * 6;  // L outweighs S again
    h.cut = {{b, a}, {b, c}};
    while (::c2pool::xmr::native::u128_greater(h[c].tree().best().cum_work, h[b].tree().best().cum_work) && h[b].tree().best().pos < need) more(b);
    h.cut.clear();
    deliver(h, b, a, f + 1, h[b].tree().best().pos);
    const std::optional<TipList> again = list_at(h[a], ln.T, l_tip);
    check(h[a].tree().best().id == h[b].tree().best().id && before && again && again->ks == before->ks,
          "#9 a switch away and back (rewinds both ways): the same KSteps at L's old tip");
    audit("#9 A back on L", h[a], h[b], ln.T, kva);
}

// ---------------------------------------------------------------------------
// #13: a carried receipt's tip (fork-local) whose branch activates in (pos(best), x]: at_bin on t's own view
void projection() {
    const KatNet net;
    const Lane ln = lane(net, 8, 16, 24);
    Harness h(net);
    const std::size_t a = h.add(ln.T, true), b = h.add(ln.T, true);
    Miner mine{h};
    const std::uint64_t p = ln.y3 - 1;
    while (h[a].tree().best().pos < p - 1) mine(a);
    h.cut = {{a, b}, {b, a}};
    mine(a);
    const pb::Hash32 sib_a = h[a].tree().best().id;
    h.tick_monero();
    mine(b);
    const pb::Hash32 sib_b = h[b].tree().best().id;
    h.cut.clear();
    (void)h[b].on_carrier(a, *pb::encode_fc_carrier(0, *h[a].bodies().get(sib_a), pb::kRuledLaneParams.r_max));
    (void)h[a].on_carrier(b, *pb::encode_fc_carrier(0, *h[b].bodies().get(sib_b), pb::kRuledLaneParams.r_max));
    h.pump();
    const pb::Hash32 best = h[a].tree().best().id;
    const pb::Hash32 t = best == sib_a ? sib_b : sib_a;
    const pb::LaneView vt = h[a].store().view_at(t), vb = h[a].store().view_at(best);
    check(t != best && vt.ok() && vb.ok() && vt.record(p) != vb.record(p),
          "#13 siblings at y3 - 1 with different H (t " + std::to_string(h[a].tree().find(t) ? h[a].tree().find(t)->H : 0) + " h " +
                  std::to_string(h[a].tree().find(t) ? h[a].tree().find(t)->h : 0) + ", best " + std::to_string(h[a].tree().best().H) +
                  " pos " + std::to_string(h[a].tree().best().pos) + ", same " + std::to_string(t == best) + ")");
    // the fork-local list at A (a carried receipt's tip) against t's own held list (S_{pos(t)} on its branch)
    const std::optional<TipList> fl = list_at(h[a], ln.T, t, false), own = list_at(h[a], ln.T, t, true);
    const bool proj = fl && !fl->acts.rows.empty() && fl->acts.rows.back().h_act == ln.y3;
    check(proj && own && fl->ks.list == own->ks.list && !fl->ks.list.empty() &&
                  fl->ks.list.back().at_bin == pb::at_bin_of(vt.record(p), kFresh),
          "#13 the projection row at y3: its at_bin read on t's view");
}

// ---------------------------------------------------------------------------
// #8c: S-1's anchor: a full chain whose walk has no AR row at or below f; the first activation's field hidden
void anchor() {
    const KatNet net;
    const Lane ln = lane(net, 8, 16, 24);
    Harness h(net);
    const std::size_t a = h.add(ln.T, true), b = h.add(ln.T, true);
    Miner mine{h};
    const std::uint64_t f = ln.y1 - 3;
    while (h[a].tree().best().pos < f) mine(a);
    h.cut = {{a, b}, {b, a}};
    while (h[a].tree().best().pos < ln.y2 + 2) mine(a);
    const pb::Hash32 t = h[a].tree().best().id;
    const std::optional<TipList> own = list_at(h[a], ln.T, t);  // t's list while its branch is best
    h.tick_monero();
    while (h[b].tree().best().pos < ln.y2 + 3) mine(b);
    h.cut.clear();
    deliver(h, b, a, f + 1, h[b].tree().best().pos);
    check(h[a].tree().best().id != t && h[a].tree().find(t) != nullptr, "#8c t now a held side tip forking at f < y1");
    const std::optional<TipList> side = list_at(h[a], ln.T, t);
    check(own && side && side->acts.consistent && side->ks == own->ks, "#8c without the hook: t's own list");
    const pb::Hash32 y1_on_t = [&] {
        const pb::CarrierNode* n = h[a].tree().find(t);
        while (n != nullptr && n->pos > ln.y1) n = h[a].tree().find(n->parent);
        return n ? n->id : pb::Hash32{};
    }();
    pb::detail_kstep::g_test_hide_activation = [&](const pb::CarrierNode& n) { return n.id == y1_on_t; };
    const std::optional<TipList> hidden = list_at(h[a], ln.T, t);
    pb::detail_kstep::g_test_hide_activation = nullptr;
    check(hidden && !hidden->acts.consistent && hidden->ks.gap && hidden->ks.known_from_bin == pb::kNoKnownBin &&
                  hidden->acts.rows.size() == 1 && hidden->acts.rows[0].epoch == 2,
          "#8c the first activation's field hidden: rows [2] fail the anchor; a gap knowing no bin");
}

// ---------------------------------------------------------------------------
// #11: step 4b's refusals, one planted row each, under known and unknown depths
void refusals() {
    const KatNet net;
    const Lane ln = lane(net, 8, 16, 24);
    Harness h(net);
    MemoryKv* kva = nullptr;
    const std::size_t a = add_node(h, h.config(ln.T, true), &kva);
    Miner mine{h};
    while (h[a].tree().best().pos < ln.y3 + 6) mine(a);
    const auto r2it = Access::kbook(h[a]).find(ln.y2);
    check(r2it != Access::kbook(h[a]).end(), "#11 the book holds the y2 step before any row is planted (book size " +
                                                     std::to_string(Access::kbook(h[a]).size()) + ")");
    if (r2it == Access::kbook(h[a]).end()) return;
    const pb::KStepRecord r2 = r2it->second;
    const std::uint64_t hy1 = h[a].store().view_at(h[a].store().best_tip()).record(ln.y1 - 1);
    const auto load = [&](const pb::EpochTable& T, const std::function<void(pb::LaneKv&)>& plant) {
        MemoryKv k;
        k.data = kva->data;
        plant(k.data);
        pb::LoadInputs in;
        in.T = T;
        in.journal_depth = 1152;
        return pb::pathb_load(k, net.pool_id, net.rules_g, in);
    };
    const auto refused = [&](const std::function<void(pb::LaneKv&)>& plant, const std::string& what) {
        check(load(ln.T, plant).fault == pb::StoreFault::KStep, "#11 " + what + ": KStep");
    };
    check(load(ln.T, [](pb::LaneKv&) {}).fault == pb::StoreFault::None, "#11 the store as written loads");
    refused([&](pb::LaneKv& d) { d[pb::store_keys::kstep(0, ln.y2)] = "torn"; }, "(1) a row that does not decode");
    refused([&](pb::LaneKv& d) { d[pb::store_keys::kstep(0, ln.y2 + 1)] = pb::encode_kstep_row(r2); }, "(1) a row under another key");
    refused([&](pb::LaneKv& d) {
        const pb::KStepRecord x{2, ln.y2 + 5, r2.at_bin};
        d[pb::store_keys::kstep(0, x.h_act)] = pb::encode_kstep_row(x);
    }, "(2) a row naming no AR row");
    refused([&](pb::LaneKv& d) {
        const pb::KStepRecord x{3, ln.y2, r2.at_bin};
        d[pb::store_keys::kstep(0, ln.y2)] = pb::encode_kstep_row(x);
    }, "(2) a row naming another epoch at the AR row's h_act");
    const pb::KStepRecord e1{1, ln.y1, pb::at_bin_of(hy1, kFresh)};
    refused([&](pb::LaneKv& d) { d[pb::store_keys::kstep(0, ln.y1)] = pb::encode_kstep_row(e1); }, "(3) a row for a pair of two known equal depths");
    {  // (3) with e1's list absent (its depth unknown): the row is kept, never read
        pb::EpochTable tu = ln.T;
        tu.compiled[1].rules.reset();
        const pb::LoadResult r = load(tu, [&](pb::LaneKv& d) { d[pb::store_keys::kstep(0, ln.y1)] = pb::encode_kstep_row(e1); });
        check(r.fault == pb::StoreFault::None && r.state && r.state->kbook.count(ln.y1) == 1,
              "#11 (3) the same row with e1's depth unknown: kept (the load passes)");
    }
    refused([&](pb::LaneKv& d) {
        pb::KStepRecord x = r2;
        ++x.at_bin;
        d[pb::store_keys::kstep(0, ln.y2)] = pb::encode_kstep_row(x);
    }, "(4) a row with another at_bin");
    refused([&](pb::LaneKv& d) { d.erase(pb::store_keys::kstep(0, ln.y2)); },
            "(5) a known step's row missing, h_act - 1 at or above the first record");
}

// ---------------------------------------------------------------------------
// #11 (4) at the first record: a launched store (first record at position 0) whose epoch 1 is a K step at h_act 1
void first_record_step() {
    const KatNet net;
    pb::PathbLaneRules r1 = pb::epoch0_lane_rules(pb::LaneNet::Regtest);
    r1.coverage = static_cast<std::uint8_t>(r1.coverage + 1);
    const pb::PathbLaneRules rk = pb::ring_test_rules(r1, 2);
    pb::EpochTable T = kat_table(net);
    T.attempts.push_back(ratchet_sim::fixed2(1, pb::rules_digest(rk), 1, 1));
    T.compiled.push_back(pb::CompiledEpoch{1, pb::rules_digest(rk), rk});
    T.ring_rules[1] = pb::RingRule{1, 1};
    Harness h(net);
    MemoryKv* kva = nullptr;
    const pb::PathbNodeConfig c = h.config(T, true);
    const std::size_t a = add_node(h, c, &kva);
    Miner mine{h};
    while (h[a].tree().best().pos < 6) mine(a);
    const auto it = Access::kbook(h[a]).find(1);
    check(h[a].store().first_record_pos() == 0 && it != Access::kbook(h[a]).end(),
          "#11 (4) at the first record: the K step at h_act 1 in the book, the first record at 0 (first " +
                  std::to_string(h[a].store().first_record_pos()) + ", book " + std::to_string(Access::kbook(h[a]).size()) + ")");
    if (it == Access::kbook(h[a]).end()) return;
    pb::LoadInputs in;
    in.T = T;
    in.journal_depth = c.journal_depth;
    MemoryKv k;
    k.data = kva->data;
    check(pb::pathb_load(k, net.pool_id, net.rules_g, in).fault == pb::StoreFault::None,
          "#11 (4) at the first record: the store as written loads");
    pb::KStepRecord x = it->second;
    ++x.at_bin;
    k.data[pb::store_keys::kstep(0, 1)] = pb::encode_kstep_row(x);
    check(pb::pathb_load(k, net.pool_id, net.rules_g, in).fault == pb::StoreFault::KStep,
          "#11 (4) at the first record: a row with another at_bin, h_act - 1 = the first record: KStep");
}

// ---------------------------------------------------------------------------
// #10, #5: joiners (one Monero height per position; a non-young span)
struct Joined {
    std::size_t j = 0;
    MemoryKv* kv = nullptr;
    std::unique_ptr<KatTransport> tr;
    pb::JoinStep st;
};
Joined join_from(Harness& h, std::size_t server, const pb::PathbNodeConfig& c) {
    Joined o;
    h.kvs.push_back(std::make_unique<MemoryKv>());
    o.kv = h.kvs.back().get();
    o.j = h.nodes.size();
    h.nodes.push_back(std::make_unique<pb::PathbNode>(c, h.io(o.j), o.kv, pb::PathbNode::LoadFailed{}));
    o.tr = std::make_unique<KatTransport>(h, o.j);
    h[o.j].set_join_transport(o.tr.get());
    h.hello(o.j, server);
    o.st = h[o.j].run_join();
    return o;
}

constexpr std::uint64_t kJoinL = 3500;  // above N_rt + 1,176: a non-young span

void joiners() {
    {  // #10: a chain that never left depth 0
        const JoinNet net(kJoinL + 300);
        pb::PathbLaneRules r1 = pb::epoch0_lane_rules(pb::LaneNet::Regtest);
        r1.coverage = static_cast<std::uint8_t>(r1.coverage + 1);
        pb::EpochTable T = kat_table(net);
        T.attempts.push_back(ratchet_sim::fixed2(1, pb::rules_digest(r1), 1, 8));
        T.compiled.push_back(pb::CompiledEpoch{1, pb::rules_digest(r1), r1});
        Harness h(net);
        const std::size_t s = h.add(T, true);
        Miner mine{h, 1, 100, 0, kAnchorH + kJoinL + 300};
        while (h[s].tree().best().pos < kJoinL) mine(s);
        Joined jn = join_from(h, s, h.config(T, false));
        const pb::JoinedState* js = h[jn.j].joined();
        check(jn.st.switched && js != nullptr && !js->young && h[jn.j].ar().joiner_p0(), "#10 a non-young join (seeded)");
        const std::optional<TipList> at_j = list_at(h[jn.j], T, h[jn.j].tree().best().id), at_s = list_at(h[s], T, h[s].tree().best().id);
        check(at_j && at_s && !at_j->ks.gap && at_j->ks == at_s->ks, "#10 a joiner on a chain that never left depth 0: no gap");
        audit("#10 the joined node", h[jn.j], h[s], T, jn.kv);
    }
    {  // #5: a joiner seeded above the step: a gap from at_bin_of(H(p0 - 1)); after a prune past p0 - 1, from adopt_bound
        const std::uint64_t top = 2 * kJoinL + 1200;
        const JoinNet net(top + 200);
        const Lane ln = lane(net, 8, 16, kJoinL + 600);
        Harness h(net);
        const std::size_t s = h.add(ln.T, true);
        Miner mine{h, 1, 100, 0, kAnchorH + top + 200};
        while (h[s].tree().best().pos < kJoinL) mine(s);
        pb::PathbNodeConfig cj = h.config(ln.T, false, kJ);
        cj.body_keep = 1;
        cj.header_keep = 1;
        Joined jn = join_from(h, s, cj);
        const std::optional<std::uint64_t> p0 = h[jn.j].ar().joiner_p0();
        check(jn.st.switched && p0 && *p0 - 1 > ln.y2 && h[jn.j].ar().rows()[0].epoch == 2,
              "#5 seeded above y2 (p0 " + std::to_string(p0.value_or(0)) + ", seed epoch 2)");
        const std::uint64_t hp = h[s].store().view_at(h[s].store().best_tip()).record(*p0 - 1);
        const std::optional<TipList> k1 = list_at(h[jn.j], ln.T, h[jn.j].tree().best().id);
        check(k1 && k1->ks.gap && k1->ks.known_from_bin == pb::at_bin_of(hp, kFresh) && k1->ks.depth0 == 1,
              "#5 a gap with known_from_bin = at_bin_of(H(p0 - 1)) on the joined view, depth0 = m(e_s) = 1");
        audit("#5 joined", h[jn.j], h[s], ln.T, jn.kv);
        while (h[s].tree().best().pos < top) mine(s);
        const pb::PathbNode::PruneReport pr = h[jn.j].prune(h.now);
        check(pr.written && h[jn.j].store().first_record_pos() > *p0 - 1 && h[jn.j].tree().best().id == h[s].tree().best().id,
              "#5 the joined node follows past y3 and prunes past p0 - 1 (first " + std::to_string(h[jn.j].store().first_record_pos()) + ")");
        const std::optional<TipList> k2 = list_at(h[jn.j], ln.T, h[jn.j].tree().best().id);
        check(k2 && k2->ks.gap && k2->ks.known_from_bin == pb::at_bin_of(hp, kFresh),
              "#5 after the prune: the same known_from_bin, from the adopt bound");
        audit("#5 joined, pruned, past y3", h[jn.j], h[s], ln.T, jn.kv);
    }
}

// ---------------------------------------------------------------------------
// #5b: a joiner whose K step (y3: K17 2 -> 1) activates at p0. p0 comes from a probe join on the same chain shape
// with y3 above the span. The adopted book holds the row at p0; the list at the root (x = p0) and above it.
void step_at_p0() {
    const JoinNet net(kJoinL + 300);
    std::uint64_t probe = 0;
    {
        const Lane lp = lane(net, 8, 16, kJoinL + 200);
        Harness hp(net);
        const std::size_t s = hp.add(lp.T, true);
        Miner mine{hp, 1, 100, 0, kAnchorH + kJoinL + 300};
        while (hp[s].tree().best().pos < kJoinL) mine(s);
        Joined jp = join_from(hp, s, hp.config(lp.T, false));
        probe = hp[jp.j].ar().joiner_p0().value_or(0);
    }
    check(probe > 17, "#5b the probe join's p0 lies above y2 (" + std::to_string(probe) + ")");
    if (probe <= 17) return;
    const Lane ln = lane(net, 8, 16, probe);
    Harness h(net);
    const std::size_t s = h.add(ln.T, true);
    Miner mine{h, 1, 100, 0, kAnchorH + kJoinL + 300};
    while (h[s].tree().best().pos < kJoinL) mine(s);
    Joined jn = join_from(h, s, h.config(ln.T, false));
    const std::optional<std::uint64_t> p0 = h[jn.j].ar().joiner_p0();
    const std::vector<pb::ActivationRow>& rows = h[jn.j].ar().rows();
    check(jn.st.switched && p0 && *p0 == probe && rows.size() >= 2 && rows[0].epoch == 2 && rows[1].h_act == *p0 &&
                  rows[1].epoch == 3,
          "#5b the join: p0 = y3, the seed at epoch 2, the AR row (3, p0)");
    if (!p0) return;
    const auto bk = Access::kbook(h[jn.j]).find(*p0);
    const pb::KStepBook eb = expected_book(h[jn.j], h[s], ln.T);
    const auto ek = eb.find(*p0);
    check(bk != Access::kbook(h[jn.j]).end() && ek != eb.end() && bk->second == ek->second,
          "#5b the adopted book holds the step at p0");
    check(Access::kbook(h[jn.j]) == eb && kv_book(*jn.kv) == eb,
          "#5b the book and the store's K_KSTEP rows: the best chain's known steps");
    const pb::Hash32 tip = h[jn.j].tree().best().id;
    const std::optional<TipList> kt = list_at(h[jn.j], ln.T, tip), ot = list_at(h[s], ln.T, tip);
    const std::uint64_t kfb = pb::at_bin_of(h[s].store().view_at(tip).record(*p0 - 1), kFresh);
    check(kt && ot && kt->acts.consistent && kt->ks.gap && kt->ks.known_from_bin == kfb && kt->ks.depth0 == 1 &&
                  kt->ks.list == pb::KStepList{pb::KStep{kfb, 1, 0}} && same_from_step(kt->ks, ot->ks),
          "#5b at the joined tip: a gap from at_bin_of(H(p0 - 1)), depth0 1, the step 1 -> 0 at that bin; the oracle's "
          "steps from that bin, its depth below it 1");
}

// ---------------------------------------------------------------------------
// #6, #7: an adoption replacing a (failed) store that holds K_KSTEP rows: the y2 row (below the new seed) and a y3 row
// whose at_bin differs from the adopted chain's; then a restart and a prune
void adoptions() {
    const std::uint64_t top = 2 * kJoinL + 1200;
    const JoinNet net(top + 200);
    const Lane ln = lane(net, 8, 16, kJoinL - 50);
    Harness h(net);
    MemoryKv* ks = nullptr;
    const std::size_t s = add_node(h, h.config(ln.T, true), &ks);
    Miner mine{h, 1, 100, 0, kAnchorH + top + 200};
    while (h[s].tree().best().pos < kJoinL) mine(s);
    const pb::KStepBook sb = kv_book(*ks);
    check(sb.size() == 2 && sb.count(ln.y2) == 1 && sb.count(ln.y3) == 1, "#6 the source store holds the y2 and y3 rows");
    if (sb.count(ln.y3) == 0) return;
    h.kvs.push_back(std::make_unique<MemoryKv>());
    MemoryKv* kj = h.kvs.back().get();
    kj->data = ks->data;
    pb::KStepRecord old3 = sb.at(ln.y3);
    old3.at_bin += kFresh;  // the replaced store's at_bin differs at the same (epoch, h_act)
    kj->data[pb::store_keys::kstep(0, ln.y3)] = pb::encode_kstep_row(old3);
    kj->data[pb::store_keys::poison(0)] = std::string(1, '\x01');  // a load failure: the joiner path
    pb::PathbNodeConfig cj = h.config(ln.T, false, kJ);
    cj.body_keep = 1;
    cj.header_keep = 1;
    const std::size_t j = h.nodes.size();
    h.nodes.push_back(std::make_unique<pb::PathbNode>(cj, h.io(j), kj, pb::PathbNode::LoadFailed{}));
    KatTransport tr(h, j);
    h[j].set_join_transport(&tr);
    h.hello(j, s);
    const pb::JoinStep st = h[j].run_join();
    const std::optional<std::uint64_t> p0 = h[j].ar().joiner_p0();
    check(st.switched && st.batch_written && p0 && *p0 - 1 > ln.y2 && *p0 - 1 < ln.y3,
          "#6 / #7 the adoption: seeded above y2 and below y3 (p0 " + std::to_string(p0.value_or(0)) + ")");
    const pb::KStepBook kb = kv_book(*kj);
    check(kb.count(ln.y2) == 0, "#7 no old key remains: the y2 row deleted with the replaced store");
    check(kb.count(ln.y3) == 1 && kb.at(ln.y3) == sb.at(ln.y3), "#6 the y3 row holds the adopted chain's at_bin, not the replaced store's");
    audit("#6 adopted", h[j], h[s], ln.T, kj);
    check(restart(h, j, *kj, cj), "#7 the adopted store restarts and loads");
    audit("#7 restarted", h[j], h[s], ln.T, kj);
    while (h[s].tree().best().pos < prune_length(ln.y3)) mine(s);
    const pb::PathbNode::PruneReport pr = h[j].prune(h.now);
    check(pr.written && h[j].store().first_record_pos() > ln.y3 - 1 && h[j].tree().best().id == h[s].tree().best().id,
          "#6 the adopted node prunes past y3 - 1");
    audit("#6 adopted, restarted, pruned: the y3 step from the book", h[j], h[s], ln.T, kj);
}

// ---------------------------------------------------------------------------
// #10b, #10c: a below-seed held tip. The joined state holds a side branch forking at a claimed prefix node
// f < p0 - 1: a span carrier carries a receipt whose tip is that branch's tip, and the join takes the branch's state
// from the server (the report's side_needs). The chain shape is the joiner KAT's (one Monero height per 12 positions,
// L = 4600, x0 = 1265); f = x0 - 5 leaves no height boundary in (f, x0 - 1]; the side branch climbs one height at
// f + 1 and two from f + 2 = y; its tip is at x0 = p0.
constexpr std::uint64_t kAbandonS = 11;  // the KAT's abandon timeout (a parameter, as in the joiner KAT)

void below_seed(bool step) {
    const std::string tag = step ? "#10c" : "#10b";
    const JoinNet net(900);
    const std::uint64_t L = 4600, x0 = 1265, f = x0 - 5, y = f + 2;
    const Lane ln = lane(net, 8, y, 6000, step ? 2 : pb::kPaymentGroups);
    KatNode a(net, 6000, pb::kRuledRatchetParams, ln.T);  // the server and the oracle: it keeps the side views
    // every body built for position x states the epoch in force at x (the activations at y1, y, y3)
    const auto epoch_of = [&](std::uint64_t x) {
        return static_cast<std::uint16_t>((x >= ln.y1 ? 1 : 0) + (x >= ln.y2 ? 1 : 0) + (x >= ln.y3 ? 1 : 0));
    };
    ChainShape sh;
    sh.tweak = [&](pb::ReceiptBodyV3& b, std::uint64_t x) { b.side.rules_epoch = epoch_of(x); };
    const auto at = [&](std::uint64_t x) { return Tweak([&, x](pb::ReceiptBodyV3& b) { b.side.rules_epoch = epoch_of(x); }); };
    grow(a, x0, sh);
    const pb::Hash32 fork = at_pos(a, f);
    const std::uint64_t hf = a.node(fork).H;
    pb::Hash32 parent = fork, side_y{};
    bool placed = true;
    for (std::uint64_t pos = f + 1; pos <= x0; ++pos) {
        const pb::CarrierBodyV3 s = carrier_on(a, parent, pos == f + 1 ? hf + 1 : hf + 2, {}, 5, 3500000 + pos, at(pos));
        placed = placed && admit_place(a, s).placed;
        parent = pb::receipt_id(s.own);
        if (pos == y) side_y = parent;
    }
    const pb::Hash32 t = parent;
    const pb::ReceiptBodyV3 r = body_on(a, t, a.node(t).h, 7, 3500001, at(x0 + 1));
    const pb::CarrierBodyV3 c = carrier_on(a, at_pos(a, x0), h_pos(x0 + 1), {r}, (x0 + 1) % 4, 3500002, at(x0 + 1));
    placed = placed && admit_place(a, c).placed;
    grow(a, 4810 - (x0 + 1), sh);
    const pb::LaneView tv = a.store.view_at(t), bv = a.store.view_at(a.store.best_tip());
    check(placed && a.store.best_at(x0) != t && a.node(t).pos == x0 && a.store.best_at(x0 + 1) == pb::receipt_id(c.own) &&
                  tv.ok() && tv.fork_pos() == f && side_y != at_pos(a, y) && a.node(side_y).activation &&
                  a.node(t).rs.epoch_cur == 2,
          tag + " the vector: a side branch forking at f = x0 - 5, its tip at x0, the activation at y on it, carried at "
                  "x0 + 1 (H(f) " + std::to_string(hf) + ", H(t) " + std::to_string(a.node(t).H) + ")");
    KatServer srv(a, 120);
    srv.top = L;
    JoinerEnv je(net, 6000);  // a journal depth that keeps the side branch's view (fork f) in the joined state
    je.in.T = ln.T;
    pb::Joiner j(je.in, kAbandonS);
    j.offer(srv.best_id(), srv);
    const std::optional<pb::AttemptReport> rep = j.run_next();
    const pb::JoinedState* js = j.adopted();
    const std::optional<std::uint64_t> p0 = js ? js->ar.joiner_p0() : std::nullopt;
    const pb::CarrierNode* jt = js ? js->tree->find(t) : nullptr;
    check(rep && rep->end == pb::AttemptEnd::Completed && rep->side_needs >= 1 && js && p0 && *p0 == x0 && f < *p0 - 1 &&
                  jt && js->store->view_at(t).ok() && js->store->view_at(t).fork_pos() == f,
          tag + " the join completes (p0 = x0), takes the side branch's state from the server, and holds the side tip "
                "(an Ok view forking at f < p0 - 1)" +
                  (rep ? ": " + rep_desc(*rep) : std::string()));
    if (!js || !jt || !p0) return;
    const std::optional<pb::TipActs> ja = pb::tip_acts(pb::kRuledRatchetParams, ln.T, *js->tree, *js->store, js->ar, *jt, true);
    const std::optional<pb::TipActs> oa = pb::tip_acts(a.RP, ln.T, a.tree, a.store, a.ar, a.node(t), true);
    check(ja && ja->kind == pb::EpochAtKind::Epoch && ja->consistent && oa && oa->consistent,
          tag + " the below-seed tip: kind Epoch and consistent at the joined state and at the oracle");
    if (!ja || !oa) return;
    const pb::KSteps kj = pb::ksteps_at(*ja, ln.T, *js->store, js->store->view_at(t), js->kbook, kFresh);
    const pb::KSteps ko = pb::ksteps_at(*oa, ln.T, a.store, tv, pb::KStepBook{}, kFresh);
    std::printf("  %s: f %llu, p0 %llu, y %llu, H_t(y - 1) %llu, H_t(p0 - 1) %llu, H_best(p0 - 1) %llu; joined: gap %d from %llu "
                "depth0 %u steps %zu; oracle: depth0 %u steps %zu\n",
                tag.c_str(), static_cast<unsigned long long>(f), static_cast<unsigned long long>(*p0),
                static_cast<unsigned long long>(y), static_cast<unsigned long long>(tv.record(y - 1)),
                static_cast<unsigned long long>(tv.record(*p0 - 1)), static_cast<unsigned long long>(bv.record(*p0 - 1)),
                static_cast<int>(kj.gap), static_cast<unsigned long long>(kj.known_from_bin), static_cast<unsigned>(kj.depth0),
                kj.list.size(), static_cast<unsigned>(ko.depth0), ko.list.size());
    if (!step) {
        check(!kj.gap && kj == ko && kj.list.empty(), tag + " a below-seed held tip on a depth-0 chain: no gap, the oracle's list");
        return;
    }
    const std::uint64_t ht_y = tv.record(y - 1), ht_p = tv.record(*p0 - 1), hb_p = bv.record(*p0 - 1);
    const pb::KStep st{pb::at_bin_of(ht_y, kFresh), 0, 1};
    check(ht_y > hb_p && !ko.gap && ko.depth0 == 0 && ko.list == pb::KStepList{st},
          tag + " the vector: H_t(y - 1) = " + std::to_string(ht_y) + " above H_best(p0 - 1) = " + std::to_string(hb_p) +
                  "; the oracle's list for t is one step 0 -> 1 at at_bin_of(H_t(y - 1)) = " + std::to_string(st.at_bin));
    check(kj.gap && kj.known_from_bin == pb::at_bin_of(ht_p, kFresh),
          tag + " a gap with known_from_bin = at_bin_of(H_t(p0 - 1)) = " + std::to_string(pb::at_bin_of(ht_p, kFresh)) +
                  ", read on t's view (got " + (kj.gap ? std::to_string(kj.known_from_bin) : std::string("no gap")) + ")");
    check(same_as_oracle(kj, ko), tag + " the list equals the oracle's under SH-2 (from bin " + std::to_string(kj.known_from_bin) +
                                          ", depth0 " + std::to_string(kj.depth0) + ")");
}

}  // namespace

int main() {
    extensions();
    switches();
    heavier_shorter();
    projection();
    anchor();
    refusals();
    first_record_step();
    joiners();
    step_at_p0();
    adoptions();
    below_seed(false);
    below_seed(true);
    return finish("v37_xmr_ring_ksteps_kat");
}
