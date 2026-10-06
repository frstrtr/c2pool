// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/xmr_carrier_sharechain_kat.cpp
// Carrier fork choice (pathb_fork_choice.hpp) with the retarget of
// pathb_retarget.hpp, the journal of pathb_journal.hpp (J = 1,152), the
// ratchet state and receipts_root fold of pathb_ratchet_state.hpp and the
// headers-first decision of pathb_headers_first.hpp:
//   (a) cum_work 3 x 2^63 against 2 x 2^63 + 2^62: the heavier wins; equal
//       cum_work: the lower id, bytes compared from the first; on a tree:
//       two equal branches -> the lower tip id, one more carrier -> heavier;
//       work after the branch point decides as cum_work does;
//   (b) a carrier whose parent is not held waits and is placed, with the
//       carriers waiting behind it, when the parent arrives; a repeat is a
//       duplicate; a waiting carrier below its parent's record is discarded
//       with the carriers waiting on it;
//   (c) a heavier branch with a carrier lacking bodies, or not verified, is
//       not taken; it is taken once that carrier is complete;
//   (d) a heavier side branch forking 500 positions below the applied tip:
//       Rewound; rewind + replay gives the chain of a node that saw only
//       the winning branch (same ids, d, cum_work);
//   (e) fork at depth J: Rewound; fork at depth J + 1: RebuildRequired;
//       rebuild from a snapshot + replay gives the same chain;
//   (f) headers-first, heavier side headers: a failed PoW, a broken parent
//       link and a height below the parent's record are each refused at
//       that header, no bodies; checked headers weigh the d each carrier
//       gets when placed;
//   (g) headers-first, equal work: a lower last id fetches bodies and the
//       branch becomes best once placed; a higher last id keeps headers
//       within J and prunes deeper; the same id does not fetch;
//   (h) a heavier side branch forking 2,000 positions below the best tip
//       (deeper than J): fetched, taken, RebuildRequired, same chain as a
//       node that saw only that branch;
//   (i) h(c) < H(parent) is not a carrier; two carriers of one tip at one
//       height are both placed; each carrier's d equals the retarget over
//       its own chain;
//   (j) receipts_root fold (carried_root 0, ballots 0): genesis S = epoch 0,
//       rules_cur = the genesis digest; after three carriers of d 18,180
//       only `all` moves (54,540); the fourth carrier commits rs_root
//       33c0bf81... and receipts_root 9c6c4c42... (the vector of
//       v37_xmr_side_data_v3_kat); a wrong fold (a flipped bit, the state
//       of another position, a non-zero carried_root) is FoldMismatch
//       (strike) and not placed; a waiting carrier with a wrong fold is
//       discarded with the carriers waiting on it when its parent arrives;
//       a side header with a wrong fold is refused at that header; at
//       x = (k + 1) L - 1 (L 5) the sums reset and level 0 is appended; a
//       ballot epoch 1 carrier moves y1 and its child commits that S; S
//       after a switch equals S of a node that saw only the winning branch.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <array>
#include <functional>
#include <span>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_caps.hpp"
#include "impl/xmr/pathb/pathb_fork_choice.hpp"
#include "impl/xmr/pathb/pathb_ratchet_state.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;
namespace nat = ::c2pool::xmr::native;

namespace {

const pb::LaneParams P = pb::kRuledLaneParams;
const pb::Hash32 kGenesis = seq32(0x01);
constexpr std::uint64_t kGenesisHeight = 1000;

pb::Hash32 cid(std::uint8_t branch, std::uint64_t n) {
    pb::Hash32 h{};
    h[0] = 0x80;
    h[1] = branch;
    for (int i = 0; i < 8; ++i) h[2 + i] = static_cast<std::uint8_t>(n >> (56 - 8 * i));
    return h;
}

pb::Hash32 with_first_byte(pb::Hash32 h, std::uint8_t b) {
    h[0] = b;
    return h;
}

// Twelve carriers per Monero height.
std::uint64_t steady_h(std::uint64_t pos) { return kGenesisHeight + pos / 12; }

// Announcements of `count` carriers after `parent` (held by t, at position
// parent_pos), each with the receipts_root it commits on that chain: the fold
// of carried_root 0 with rs_root of S at its parent.
std::vector<pb::CarrierAnnounce> announce(const pb::CarrierTree& t, const pb::Hash32& parent, std::uint64_t parent_pos,
                                          std::uint8_t branch, std::uint64_t count,
                                          const std::function<std::uint64_t(std::uint64_t)>& h_of = steady_h,
                                          std::uint16_t ballot = 0) {
    std::vector<pb::CarrierAnnounce> out;
    const pb::CarrierNode* pn = t.find(parent);
    if (pn == nullptr || pn->pos != parent_pos) {
        check(false, "announce: parent not held at the given position");
        return out;
    }
    pb::RetargetWindow w = *t.window_after(parent);
    pb::RatchetState rs = pn->rs;
    std::uint64_t record = pn->H;
    pb::Hash32 prev = parent;
    for (std::uint64_t i = 1; i <= count; ++i) {
        const std::uint64_t pos = parent_pos + i;
        const pb::CarrierAnnounce c{cid(branch, pos), prev, h_of(pos),
                                    pb::carrier_receipts_root(pb::kNoCarriedRoot, rs), ballot};
        const std::uint64_t d = w.next_difficulty();
        record = pb::record_height(record, c.h);
        w.push(pb::RetargetEntry{d, record});
        const pb::RatchetPlacement own{d, ballot};
        rs = pb::rs_step(t.ratchet_params(), rs, pos, std::span<const pb::RatchetPlacement>(&own, 1));
        out.push_back(c);
        prev = c.id;
    }
    return out;
}

// One carrier on a held tip, with the receipts_root it commits there.
pb::CarrierAnnounce on_tip(const pb::CarrierTree& t, const pb::Hash32& id, const pb::Hash32& tip, std::uint64_t h,
                           std::uint16_t ballot = 0) {
    return pb::CarrierAnnounce{id, tip, h, t.next_receipts_root(tip).value_or(pb::Hash32{}), ballot};
}

// Places and (when `complete`) verifies and marks bodies. Returns true if all placed.
bool admit(pb::CarrierTree& t, const std::vector<pb::CarrierAnnounce>& cs, bool complete = true) {
    bool ok = true;
    for (const pb::CarrierAnnounce& c : cs) {
        ok = ok && t.place(c).verdict == pb::PlaceVerdict::Placed;
        if (complete) ok = ok && t.mark_verified(c.id) && t.mark_bodies(c.id);
    }
    return ok;
}

// The applied chain of a node: journal of depth J + ids by position.
struct Applied {
    pb::RewindJournal<pb::Hash32> j;
    std::vector<pb::Hash32> chain;  // chain[pos - 1]
    explicit Applied(std::uint64_t depth) : j(depth) {}
    void apply(const pb::Hash32& id) {
        chain.push_back(id);
        j.append(id);
    }
    pb::Hash32 tip() const { return chain.empty() ? kGenesis : chain.back(); }
};

bool execute(Applied& a, const pb::CarrierTree& t, const pb::SwitchPlan& plan, std::uint64_t snapshot_pos) {
    if (plan.verdict == pb::RewindVerdict::Rewound) {
        std::vector<pb::Hash32> undone;
        if (a.j.rewind_to(plan.fork_position, undone) != pb::RewindVerdict::Rewound || undone.size() != plan.undo_depth)
            return false;
        a.chain.resize(plan.fork_position);
    } else if (plan.verdict == pb::RewindVerdict::RebuildRequired) {
        if (snapshot_pos > plan.fork_position) return false;
        const pb::Hash32 snap = snapshot_pos == 0 ? kGenesis : a.chain[snapshot_pos - 1];
        a.chain.resize(snapshot_pos);
        a.j.rebuild_from(snapshot_pos);
        const auto trunk = t.path(snap, plan.fork);
        if (!trunk) return false;
        for (const pb::Hash32& id : *trunk) a.apply(id);
    } else {
        return false;
    }
    for (const pb::Hash32& id : plan.apply) a.apply(id);
    return true;
}

// A node that saw only the best chain of `t`: same ids, d and cum_work.
bool fresh_node_agrees(const pb::CarrierTree& t, const Applied& a) {
    const auto chain = t.path(kGenesis, t.best().id);
    if (!chain || *chain != a.chain) return false;
    pb::CarrierTree fresh(P, kGenesis, kGenesisHeight, {}, t.ratchet_params(), t.genesis().rs.rules_cur);
    for (const pb::Hash32& id : *chain) {
        const pb::CarrierNode* n = t.find(id);
        if (fresh.place(pb::CarrierAnnounce{id, n->parent, n->h, n->receipts_root, n->ballot}).verdict
            != pb::PlaceVerdict::Placed)
            return false;
        fresh.mark_verified(id);
        fresh.mark_bodies(id);
        const pb::CarrierNode* f = fresh.find(id);
        if (f->d != n->d || !(f->cum_work == n->cum_work) || f->pos != n->pos || f->H != n->H || !(f->rs == n->rs))
            return false;
    }
    return fresh.best().id == t.best().id;
}

// Each carrier's d equals the retarget over the carriers before it on its chain.
bool d_matches_chain(const pb::CarrierTree& t, const pb::Hash32& tip) {
    const auto chain = t.path(kGenesis, tip);
    if (!chain) return false;
    std::vector<pb::RetargetEntry> entries;
    for (const pb::Hash32& id : *chain) {
        const pb::CarrierNode* n = t.find(id);
        if (n->d != pb::retarget(P, entries)) return false;
        entries.push_back(pb::RetargetEntry{n->d, n->H});
    }
    return true;
}

auto pow_all = [](const pb::CarrierAnnounce&, std::uint64_t) { return true; };

// The S1 fold vector (gen_pathb_golden.py; v37_xmr_side_data_v3_kat): S after
// three carriers of d 18,180 on a genesis with rules digest seq32(0x11).
const char* kFoldRsRootHex = "33c0bf81942281b70e7a5aff7a18e509ab663453f85ebc3e2e73d5d7c5c83a96";
const char* kFoldReceiptsRootHex = "9c6c4c423ea279867e47120c92c2d67d2bac5c3ff052e3dfaf5e8a7c7294bf55";

}  // namespace

int main() {
    std::printf("xmr_carrier_sharechain_kat\n");
    const std::uint64_t J = pb::journal_depth(P);
    check(J == 1152, "J = 1,152");

    // (a) order
    {
        const nat::U128 three{std::uint64_t{1} << 63, 1};      // 3 x 2^63
        const nat::U128 two_q{std::uint64_t{1} << 62, 1};      // 2 x 2^63 + 2^62
        const pb::Hash32 lo = seq32(0x10), hi = seq32(0x20);
        check(pb::fork_choice_prefers({three, hi}, {two_q, lo}) && !pb::fork_choice_prefers({two_q, lo}, {three, hi}),
              "3 x 2^63 over 2 x 2^63 + 2^62, whatever the ids");
        check(pb::fork_choice_prefers({three, lo}, {three, hi}) && !pb::fork_choice_prefers({three, hi}, {three, lo}),
              "equal cum_work: the lower id");
        check(!pb::fork_choice_prefers({three, lo}, {three, lo}), "the same tip: no preference");
        pb::Hash32 x = seq32(0x30), y = seq32(0x30);
        x[0] = 0x2f;
        x[31] = 0xff;
        y[31] = 0x00;
        check(pb::fork_choice_prefers({three, x}, {three, y}), "ids compared from the first byte");
    }
    {
        pb::CarrierTree t(P, kGenesis, kGenesisHeight);
        check(t.best().id == kGenesis && t.genesis().chain_valid, "empty tree: best = genesis");
        const auto trunk = announce(t, kGenesis, 0, 1, 30);
        check(admit(t, trunk), "trunk placed");
        const pb::Hash32 fork = trunk.back().id;
        auto bx = announce(t, fork, 30, 2, 5);
        auto by = announce(t, fork, 30, 3, 5);
        bx.back().id = with_first_byte(bx.back().id, 0xf0);
        by.back().id = with_first_byte(by.back().id, 0x10);
        check(admit(t, bx) && t.best().id == bx.back().id, "branch X best");
        check(admit(t, by), "branch Y placed");
        check(t.find(bx.back().id)->cum_work == t.find(by.back().id)->cum_work, "X and Y: equal cum_work");
        check(t.best().id == by.back().id, "equal cum_work: the lower tip id (Y)");
        check(*t.work_after(fork, bx.back().id) == *t.work_after(fork, by.back().id), "equal work after the branch point");
        const pb::CarrierAnnounce x6 = on_tip(t, cid(2, 36), bx.back().id, steady_h(36));
        check(admit(t, {x6}) && t.best().id == x6.id, "one more carrier on X: heavier, X best");
        check(nat::u128_greater(*t.work_after(fork, x6.id), *t.work_after(fork, by.back().id)),
              "greater work after the branch point");
        check(d_matches_chain(t, x6.id) && d_matches_chain(t, by.back().id), "(i) d over each branch's own chain");

        // (b)
        const auto bz = announce(t, x6.id, 36, 4, 3);
        check(t.place(bz[2]).verdict == pb::PlaceVerdict::Deferred && t.place(bz[1]).verdict == pb::PlaceVerdict::Deferred
                      && t.waiting() == 2,
              "unknown parent: deferred, not refused");
        check(t.place(bz[1]).verdict == pb::PlaceVerdict::Duplicate, "a waiting carrier repeated: duplicate");
        const pb::PlaceOutcome o = t.place(bz[0]);
        check(o.verdict == pb::PlaceVerdict::Placed && o.placed.size() == 3 && o.placed[0] == bz[0].id
                      && o.placed[1] == bz[1].id && o.placed[2] == bz[2].id && t.waiting() == 0,
              "parent arrives: the waiting carriers are placed behind it");
        check(t.place(bz[0]).verdict == pb::PlaceVerdict::Duplicate, "placed carrier repeated: duplicate");
        {
            const auto bq = announce(t, bz[2].id, 39, 10, 3);
            pb::CarrierAnnounce below = bq[1];
            below.h = 0;
            check(t.place(bq[2]).verdict == pb::PlaceVerdict::Deferred && t.place(below).verdict == pb::PlaceVerdict::Deferred,
                  "two carriers waiting");
            const pb::PlaceOutcome q = t.place(bq[0]);
            check(q.verdict == pb::PlaceVerdict::Placed && q.placed.size() == 1 && q.not_carrier.size() == 1
                          && q.not_carrier[0] == below.id && t.waiting() == 0 && t.find(bq[2].id) == nullptr,
                  "a waiting carrier below its parent's record is discarded with the carriers waiting on it");
        }
        check(t.best().id == x6.id, "placed but not verified: not best");
        for (const auto& c : bz) t.mark_verified(c.id);
        check(t.best().id == x6.id, "verified without bodies: not best");
        for (const auto& c : bz) t.mark_bodies(c.id);
        check(t.best().id == bz[2].id && t.find(bz[2].id)->chain_valid, "complete: best");

        // (c)
        const auto bw = announce(t, bz[2].id, 39, 5, 6);
        check(admit(t, bw, false), "branch W placed");
        for (std::size_t i = 0; i < bw.size(); ++i) {
            if (i != 2) t.mark_bodies(bw[i].id);
            t.mark_verified(bw[i].id);
        }
        check(t.best().id == bw[1].id, "a carrier without bodies: the chain is not extended past it");
        t.mark_bodies(bw[2].id);
        check(t.best().id == bw.back().id, "bodies arrive: extended");
        const auto bv = announce(t, bw.back().id, 45, 6, 4);
        for (const auto& c : bv) {
            t.place(c);
            t.mark_bodies(c.id);
            if (c.id != bv[1].id) t.mark_verified(c.id);
        }
        check(t.best().id == bv[0].id, "a carrier not verified: the chain is not extended past it");
        t.mark_verified(bv[1].id);
        check(t.best().id == bv.back().id, "verified: extended");

        // drop of an unverified branch
        const auto bu = announce(t, bv.back().id, 49, 7, 3);
        check(admit(t, bu, false) && t.size() == 1 + 30 + 5 + 5 + 1 + 3 + 1 + 6 + 4 + 3, "unverified branch placed");
        check(t.drop(bu[0].id) && t.find(bu[0].id) == nullptr && t.find(bu[2].id) == nullptr
                      && t.size() == 1 + 30 + 5 + 5 + 1 + 3 + 1 + 6 + 4 && t.best().id == bv.back().id,
              "drop removes the unverified carrier and its descendants");
        check(!t.drop(bv.back().id) && !t.drop(kGenesis), "a chain-valid carrier is not dropped");

        // (i)
        const pb::CarrierNode* tipn = t.find(bv.back().id);
        check(t.place(on_tip(t, cid(8, 1), tipn->id, tipn->H - 1)).verdict == pb::PlaceVerdict::NotCarrier,
              "h(c) < H(parent): not a carrier");
        check(t.place(on_tip(t, cid(8, 2), tipn->id, tipn->H)).verdict == pb::PlaceVerdict::Placed
                      && t.place(on_tip(t, cid(8, 3), tipn->id, tipn->H)).verdict == pb::PlaceVerdict::Placed
                      && t.find(cid(8, 2))->d == t.find(cid(8, 3))->d,
              "two carriers of one tip at one height: both placed, one d");
        check(d_matches_chain(t, bv.back().id), "(i) d over the extended chain");
    }

    // (d) within J
    {
        pb::CarrierTree t(P, kGenesis, kGenesisHeight);
        Applied node(J);
        const auto trunk = announce(t, kGenesis, 0, 1, 200);
        check(admit(t, trunk), "trunk placed");
        const auto a = announce(t, trunk.back().id, 200, 2, 500);
        const auto b = announce(t, trunk.back().id, 200, 3, 501);
        check(admit(t, a), "A placed");
        for (const auto& c : trunk) node.apply(c.id);
        for (const auto& c : a) node.apply(c.id);
        check(t.best().id == a.back().id && node.tip() == a.back().id, "A best and applied");
        check(admit(t, b) && t.best().id == b.back().id, "B (one carrier longer, same heights) best");
        const auto plan = t.plan_switch(node.tip(), node.j);
        check(plan && plan->fork == trunk.back().id && plan->fork_position == 200 && plan->undo_depth == 500
                      && plan->verdict == pb::RewindVerdict::Rewound && plan->apply.size() == 501,
              "fork 500 below the applied tip: rewind");
        check(plan && execute(node, t, *plan, 0) && fresh_node_agrees(t, node),
              "rewind + replay: the chain of a node that saw only B");
        check(t.find(a.back().id) != nullptr && d_matches_chain(t, a.back().id) && d_matches_chain(t, b.back().id),
              "both branches kept, d over each");
    }

    // (e) depth J and J + 1
    for (const std::uint64_t depth : {J, J + 1}) {
        pb::CarrierTree t(P, kGenesis, kGenesisHeight);
        Applied node(J);
        const auto trunk = announce(t, kGenesis, 0, 1, 200);
        admit(t, trunk);
        const auto a = announce(t, trunk.back().id, 200, 2, depth);
        const auto b = announce(t, trunk.back().id, 200, 3, depth + 1);
        admit(t, a);
        for (const auto& c : trunk) node.apply(c.id);
        for (const auto& c : a) node.apply(c.id);
        admit(t, b);
        const auto plan = t.plan_switch(node.tip(), node.j);
        const pb::RewindVerdict want = depth == J ? pb::RewindVerdict::Rewound : pb::RewindVerdict::RebuildRequired;
        check(plan && plan->undo_depth == depth && plan->verdict == want && t.best().id == b.back().id,
              "fork at depth " + std::to_string(depth) + (depth == J ? ": rewind" : ": rebuild"));
        check(plan && execute(node, t, *plan, 100) && fresh_node_agrees(t, node),
              "depth " + std::to_string(depth) + ": the chain of a node that saw only B");
    }

    // (f) (g) headers-first
    {
        pb::CarrierTree t(P, kGenesis, kGenesisHeight);
        const auto trunk = announce(t, kGenesis, 0, 1, 300);
        admit(t, trunk);
        const auto a = announce(t, trunk.back().id, 300, 2, 40);
        admit(t, a);
        const pb::Hash32 fork = trunk.back().id;
        const pb::Hash32 best = a.back().id;
        const nat::U128 fork_work = t.find(fork)->cum_work;

        const auto heavier = announce(t, fork, 300, 3, 41);
        auto d = t.decide_headers(fork, heavier, pow_all, J);
        check(d && d->action == pb::SideBranchAction::FetchBodies, "heavier side headers: fetch bodies");
        check(d && nat::u128_greater(d->claimed_work, t.best().cum_work), "claimed work above the best tip's");

        const pb::Hash32 bad_pow = heavier[7].id;
        d = t.decide_headers(fork, heavier, [&](const pb::CarrierAnnounce& h, std::uint64_t) { return h.id != bad_pow; }, J);
        const auto side = t.check_side_headers(fork, heavier, pow_all);
        nat::U128 first7 = fork_work;
        for (std::size_t i = 0; i < 7; ++i) first7 = nat::u128_add(first7, nat::U128{(*side)[i].work, 0});
        check(d && d->action == pb::SideBranchAction::RefuseHeader && d->refused_index == 7 && d->claimed_work == first7,
              "failed PoW at header 7: refused there, no bodies");
        auto broken = heavier;
        broken[3].parent = cid(9, 9);
        d = t.decide_headers(fork, broken, pow_all, J);
        check(d && d->action == pb::SideBranchAction::RefuseHeader && d->refused_index == 3, "broken parent link: refused");
        auto low = heavier;
        low[5].h = low[4].h - 1;
        d = t.decide_headers(fork, low, pow_all, J);
        check(d && d->action == pb::SideBranchAction::RefuseHeader && d->refused_index == 5,
              "height below the parent's record: refused");
        std::uint64_t seen_d = 0;
        d = t.decide_headers(fork, std::span(heavier).first(1),
                             [&](const pb::CarrierAnnounce&, std::uint64_t dd) {
                                 seen_d = dd;
                                 return true;
                             },
                             J);
        check(seen_d == *t.next_difficulty(fork), "PoW checked at the retarget d after the fork");
        check(!t.decide_headers(cid(9, 9), heavier, pow_all, J), "fork point not held: no decision");

        // (g) equal work
        auto tie = announce(t, fork, 300, 4, 40);
        tie.back().id = with_first_byte(tie.back().id, 0x10);
        check(tie.back().id < best, "side tip id below the best tip id");
        d = t.decide_headers(fork, tie, pow_all, J);
        check(d && d->action == pb::SideBranchAction::FetchBodies && d->claimed_work == t.best().cum_work,
              "equal work, lower last id: fetch bodies");
        auto tie_hi = announce(t, fork, 300, 5, 40);
        tie_hi.back().id = with_first_byte(tie_hi.back().id, 0xf0);
        d = t.decide_headers(fork, tie_hi, pow_all, J);
        check(d && d->action == pb::SideBranchAction::KeepHeaders, "equal work, higher last id, within J: keep headers");
        auto tie_same = announce(t, fork, 300, 6, 40);
        tie_same.back().id = best;
        d = t.decide_headers(fork, tie_same, pow_all, J);
        check(d && d->action == pb::SideBranchAction::KeepHeaders, "equal work, the same last id: no fetch");
        const auto lighter = announce(t, fork, 300, 7, 39);
        d = t.decide_headers(fork, lighter, pow_all, J);
        check(d && d->action == pb::SideBranchAction::KeepHeaders, "lighter within J: keep headers");

        // fetched: headers weigh what the carriers get when placed; the tie branch becomes best
        const auto tie_side = t.check_side_headers(fork, tie, pow_all);
        check(admit(t, tie), "tie branch placed");
        bool weights = true;
        for (std::size_t i = 0; i < tie.size(); ++i) weights = weights && (*tie_side)[i].work == t.find(tie[i].id)->d;
        check(weights, "header work = placed carrier d");
        check(t.best().id == tie.back().id, "equal work, lower tip id: best after placement");
        const auto heavier_side = t.check_side_headers(fork, heavier, pow_all);
        admit(t, heavier);
        bool w2 = true;
        for (std::size_t i = 0; i < heavier.size(); ++i) w2 = w2 && (*heavier_side)[i].work == t.find(heavier[i].id)->d;
        check(w2 && t.best().id == heavier.back().id, "heavier branch placed: best, header work = d");
    }

    // (g) higher id deeper than J: prune; (h) deep reorg accepted
    {
        pb::CarrierTree t(P, kGenesis, kGenesisHeight);
        Applied node(J);
        const auto trunk = announce(t, kGenesis, 0, 1, 100);
        admit(t, trunk);
        const auto a = announce(t, trunk.back().id, 100, 2, 2000);
        admit(t, a);
        for (const auto& c : trunk) node.apply(c.id);
        for (const auto& c : a) node.apply(c.id);
        const pb::Hash32 fork = trunk.back().id;

        auto tie_hi = announce(t, fork, 100, 5, 2000);
        tie_hi.back().id = with_first_byte(tie_hi.back().id, 0xf0);
        auto d = t.decide_headers(fork, tie_hi, pow_all, J);
        check(d && d->action == pb::SideBranchAction::Prune, "equal work, higher last id, fork deeper than J: prune");
        const auto lighter = announce(t, fork, 100, 6, 1999);
        d = t.decide_headers(fork, lighter, pow_all, J);
        check(d && d->action == pb::SideBranchAction::Prune, "lighter, fork deeper than J: prune");

        const auto b = announce(t, fork, 100, 3, 2001);
        d = t.decide_headers(fork, b, pow_all, J);
        check(d && d->action == pb::SideBranchAction::FetchBodies, "heavier, fork 2,000 below the best tip: fetch bodies");
        check(admit(t, b) && t.best().id == b.back().id, "deep branch taken: no depth limit");
        const auto plan = t.plan_switch(node.tip(), node.j);
        check(plan && plan->undo_depth == 2000 && plan->verdict == pb::RewindVerdict::RebuildRequired
                      && plan->apply.size() == 2001,
              "fork 2,000 below the applied tip: rebuild");
        check(plan && execute(node, t, *plan, 50) && fresh_node_agrees(t, node),
              "rebuild + replay: the chain of a node that saw only the deep branch");
        check(*t.work_after(fork, b.back().id) == nat::u128_add(*t.work_after(fork, a.back().id),
                                                                 nat::U128{t.find(b.back().id)->d, 0}),
              "work after the branch point: A plus one carrier");
    }

    // (j) receipts_root fold
    {
        const pb::Hash32 rules = seq32(0x11);
        pb::CarrierTree t(P, kGenesis, kGenesisHeight, {}, pb::kRuledRatchetParams, rules);
        check(t.genesis().rs == pb::genesis_ratchet_state(rules),
              "genesis S: epoch 0, rules_cur = the genesis digest, sums and levels 0");
        const auto c = announce(t, kGenesis, 0, 11, 3);
        check(admit(t, c), "three carriers placed");
        const pb::CarrierNode* n3 = t.find(c[2].id);
        check(t.find(c[0].id)->d == P.d_min && t.find(c[1].id)->d == P.d_min && n3->d == P.d_min,
              "chain start: d_min at positions 1..3");
        check(n3->rs.all == pb::RsWork(3 * P.d_min) && n3->rs.y1.is_zero() && n3->rs.y2.is_zero()
                      && n3->rs.epoch_cur == 0 && n3->rs.rules_cur == rules
                      && n3->rs.levels == std::array<std::uint8_t, 4>{},
              "ballots 0: only `all` moves (54,540)");
        const pb::Hash32 rs3 = pb::rs_root(n3->rs);
        const pb::Hash32 rr4 = *t.next_receipts_root(c[2].id);
        check(hex(rs3.data(), rs3.size()) == kFoldRsRootHex && hex(rr4.data(), rr4.size()) == kFoldReceiptsRootHex,
              "fold vector: position 4 commits rs_root 33c0bf81..., receipts_root 9c6c4c42...");
        bool committed = true;
        pb::Hash32 parent = kGenesis;
        for (const auto& x : c) {
            committed = committed && x.receipts_root == pb::carrier_receipts_root(pb::kNoCarriedRoot, t.find(parent)->rs)
                        && t.find(x.id)->receipts_root == x.receipts_root;
            parent = x.id;
        }
        check(committed, "each placed carrier commits the fold over S at its parent");

        // a wrong fold: strike, not placed
        const pb::CarrierAnnounce good = on_tip(t, cid(11, 4), c[2].id, steady_h(4));
        pb::CarrierAnnounce bad = good;
        bad.receipts_root[0] ^= 1;
        check(t.place(bad).verdict == pb::PlaceVerdict::FoldMismatch && t.find(bad.id) == nullptr && t.waiting() == 0,
              "a flipped bit: FoldMismatch (strike), not placed");
        bad.receipts_root = *t.next_receipts_root(c[1].id);
        check(t.place(bad).verdict == pb::PlaceVerdict::FoldMismatch, "the fold over another position's S: FoldMismatch");
        bad.receipts_root = pb::carrier_receipts_root(seq32(0x30), n3->rs);
        check(t.place(bad).verdict == pb::PlaceVerdict::FoldMismatch,
              "a non-zero carried_root on a carrier that carries nothing: FoldMismatch");
        check(t.place(good).verdict == pb::PlaceVerdict::Placed, "the honest fold: placed");

        // a waiting carrier with a wrong fold
        auto wq = announce(t, good.id, 4, 12, 3);
        wq[1].receipts_root[5] ^= 0x80;
        check(t.place(wq[2]).verdict == pb::PlaceVerdict::Deferred && t.place(wq[1]).verdict == pb::PlaceVerdict::Deferred,
              "two carriers waiting");
        const pb::PlaceOutcome o = t.place(wq[0]);
        check(o.verdict == pb::PlaceVerdict::Placed && o.placed.size() == 1 && o.fold_mismatch.size() == 1
                      && o.fold_mismatch[0] == wq[1].id && o.not_carrier.empty() && t.waiting() == 0
                      && t.find(wq[1].id) == nullptr && t.find(wq[2].id) == nullptr,
              "parent arrives: the waiting carrier with a wrong fold is discarded with the carrier waiting on it");

        // headers-first
        auto side = announce(t, c[2].id, 3, 13, 5);
        const auto honest = t.check_side_headers(c[2].id, side, pow_all);
        bool passed = honest.has_value();
        for (const auto& h : *honest) passed = passed && h.check == pb::HeaderCheck::Passed;
        check(passed, "side headers with the honest fold over the side chain's S: passed");
        side[2].receipts_root[0] ^= 1;
        const auto d = t.decide_headers(c[2].id, side, pow_all, J);
        check(d && d->action == pb::SideBranchAction::RefuseHeader && d->refused_index == 2,
              "a side header with a wrong fold: refused at that header");
        int pow_calls = 0;
        t.check_side_headers(c[2].id, side, [&](const pb::CarrierAnnounce&, std::uint64_t) {
            ++pow_calls;
            return true;
        });
        check(pow_calls == 2, "the fold is checked before PoW: no PoW call for the refused header");

        // a ballot enters S
        const pb::CarrierAnnounce v1 = on_tip(t, cid(11, 6), wq[0].id, steady_h(6), pb::make_ballot(1, false));
        check(t.place(v1).verdict == pb::PlaceVerdict::Placed, "a carrier with ballot epoch 1 placed");
        const pb::CarrierNode* nv = t.find(v1.id);
        check(nv->rs.y1 == pb::RsWork(nv->d) && nv->rs.y2.is_zero(), "ballot epoch 1: y1 = its d");
        check(t.place(on_tip(t, cid(11, 7), v1.id, steady_h(7))).verdict == pb::PlaceVerdict::Placed,
              "its child commits S with y1: placed");
        const pb::RatchetPlacement unvoted{nv->d, 0};
        const pb::RatchetState no_vote = pb::rs_step(t.ratchet_params(), t.find(wq[0].id)->rs, nv->pos,
                                                     std::span<const pb::RatchetPlacement>(&unvoted, 1));
        const pb::CarrierAnnounce ignores{cid(11, 8), v1.id, steady_h(7),
                                          pb::carrier_receipts_root(pb::kNoCarriedRoot, no_vote), 0};
        check(t.place(ignores).verdict == pb::PlaceVerdict::FoldMismatch, "a child that drops the ballot from S: FoldMismatch");

        // the grid window end (L 5, GRACE 20)
        pb::CarrierTree ts(P, kGenesis, kGenesisHeight, {}, pb::RatchetParams{5, 20}, rules);
        const auto cs = announce(ts, kGenesis, 0, 14, 6);
        check(admit(ts, cs), "L 5: six carriers placed");
        check(ts.find(cs[2].id)->rs.all == pb::RsWork(3 * P.d_min), "L 5: position 3, all = 3 d");
        check(ts.find(cs[3].id)->rs.all.is_zero() && ts.find(cs[3].id)->rs.levels == std::array<std::uint8_t, 4>{},
              "L 5: position 4 ends window 0: sums reset, level 0");
        check(ts.find(cs[5].id)->rs.all == pb::RsWork(2 * P.d_min), "L 5: positions 5 and 6 in window 1");
        check(ts.find(cs[3].id)->rs == ts.genesis().rs && cs[4].receipts_root == cs[0].receipts_root,
              "L 5: after the window end S equals the genesis S, so position 5 commits the fold of position 1");
    }

    return finish("xmr_carrier_sharechain_kat");
}
