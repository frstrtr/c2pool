// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/xmr_carrier_sharechain_kat.cpp
// Carrier fork choice (pathb_fork_choice.hpp) with the retarget of
// pathb_retarget.hpp, the journal of pathb_journal.hpp (J = 1,152), the
// ratchet state and receipts_root fold of pathb_ratchet_state.hpp, the
// carried_root fold of pathb_receipt_admission.hpp, rs_step_at of
// pathb_ratchet_activation.hpp and the headers-first decision of
// pathb_headers_first.hpp:
//   (a) cum_work 3 x 2^63 against 2 x 2^63 + 2^62: the heavier wins; equal
//       cum_work: the lower id, bytes compared from the first; on a tree:
//       two equal branches -> the lower tip id, one more carrier -> heavier;
//       work after the branch point decides as cum_work does;
//   (b) a carrier whose parent is not held waits; when the parent is placed
//       it is released (not placed), admitted again and placed, and the
//       carrier waiting on it is released in turn; a repeat is a duplicate;
//       a released carrier below its parent's record is not a carrier and
//       the two-level chain waiting on it is discarded;
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
//   (j) receipts_root fold with nothing carried (carried_root 0, ballots 0,
//       no deployment): genesis S = epoch 0, rules_cur = the genesis
//       digest; after three carriers of d 18,180 only `all` moves (54,540);
//       the fourth carrier commits rs_root 33c0bf81... and receipts_root
//       9c6c4c42... (the vector of v37_xmr_side_data_v3_kat); a wrong fold
//       (a flipped bit, the state of another position, a non-zero
//       carried_root) is FoldMismatch (strike) and not placed; a released
//       carrier with a wrong fold is FoldMismatch and the two-level chain waiting on
//       it is discarded; a header with a wrong receipts_root passes the
//       header checks (no fold on the header path) and is FoldMismatch when
//       placed; at x = (k + 1) L - 1 (L 5) the sums reset and level 0 is
//       appended; a ballot epoch 1 carrier moves y1 and its child commits
//       that S;
//   (k) carried lists: next_receipts_root over carried ids seq32(1..3)
//       (carried_root 75e683fc...) on the position-3 state is a9ddf8c4...;
//       carriers carrying 1, 2 and 16 receipts are placed (the fold over
//       their ids) and the same carriers committing carried_root 0 are
//       FoldMismatch; the tree's fold verdict equals check_carried_fold for
//       0..16 ids; the fold follows the list order, not the byte order of
//       the ids; the ratchet tally covers every placement: a live carried
//       receipt adds its work to `all` and by its ballot to y1 / y2, a dead
//       one adds 0, then the carrier adds d; a child committing the
//       carrier-only S is FoldMismatch; cum_work counts carriers only;
//   (l) activation inside the tree (L 5, GRACE 20, kind 2 fixed at 20):
//       S_20 has epoch 1 and rules_cur = the deployment digest, equal to
//       rs_step with step (1); the activation row (1, 20, digest) is kept
//       on the carrier at 20 and on no other; the carrier at 21 commits
//       S_20; the same carriers in a tree without the table: the carrier at
//       21 is FoldMismatch;
//   (m) an honest heavier side branch whose carriers carry 1-3 receipts
//       (some dead): headers first fetches it (every header passes), every
//       carrier is placed (none struck), it becomes best, the rewind gives
//       the chain and S of a node that saw only that branch; a released
//       carrier carrying receipts is placed with its carried list;
//   (n) a waiting entry is (id, claimed parent): a copy of X naming an
//       unknown parent arrives first, then X with a held parent is placed,
//       the copy's entry is dropped and X's child released; a carrier waiting
//       under two claimed parents keeps its own waiting children when one of
//       them is refused; a refused copy of a carrier that still waits under
//       another claimed parent discards nothing;
//   (o) N-7: a two-level chain under a refused carrier is discarded as the
//       pairs ((child, refused), (grandchild, child)); unwait(id, p) removes
//       the one pair (id, p): id's claim under another parent and the
//       entries waiting on id stay, waiting() counts the pairs left.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <array>
#include <functional>
#include <map>
#include <span>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_caps.hpp"
#include "impl/xmr/pathb/pathb_fork_choice.hpp"
#include "impl/xmr/pathb/pathb_ratchet_activation.hpp"
#include "impl/xmr/pathb/pathb_ratchet_state.hpp"
#include "impl/xmr/pathb/pathb_receipt_admission.hpp"
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

// A carried receipt id (distinct from every carrier id).
pb::Hash32 rid(std::uint8_t branch, std::uint64_t pos, std::uint8_t k) {
    pb::Hash32 h = cid(branch, pos);
    h[0] = 0x52;
    h[10] = k;
    return h;
}

// Twelve carriers per Monero height.
std::uint64_t steady_h(std::uint64_t pos) { return kGenesisHeight + pos / 12; }

// The carried list each announced carrier was built with (by carrier id).
std::map<pb::Hash32, std::vector<pb::CarriedPlacement>> g_carried;

const std::vector<pb::CarriedPlacement>& carried_of(const pb::Hash32& id) {
    static const std::vector<pb::CarriedPlacement> kNone;
    const auto it = g_carried.find(id);
    return it == g_carried.end() ? kNone : it->second;
}

std::vector<pb::Hash32> ids_of(const std::vector<pb::CarriedPlacement>& cs) {
    std::vector<pb::Hash32> out;
    for (const pb::CarriedPlacement& r : cs) out.push_back(r.id);
    return out;
}

// rs_step step (2) inputs of a carrier of work d and ballot b carrying cs:
// each carried receipt at its work (0 when dead), then the carrier.
std::vector<pb::RatchetPlacement> step_inputs(std::uint64_t d, std::uint16_t b, const std::vector<pb::CarriedPlacement>& cs) {
    std::vector<pb::RatchetPlacement> out;
    for (const pb::CarriedPlacement& r : cs) out.push_back(pb::RatchetPlacement{r.live ? r.work : 0, r.ballot});
    out.push_back(pb::RatchetPlacement{d, b});
    return out;
}

using CarriedGen = std::function<std::vector<pb::CarriedPlacement>(std::uint64_t)>;

// Announcements of `count` carriers after `parent` (held by t, at position
// parent_pos), each with the receipts_root it commits on that chain: the fold
// of carried_root over its carried ids (carry(pos); none without carry) with
// rs_root of S at its parent; S follows rs_step_at with t's table over the
// carried placements and the carrier.
std::vector<pb::CarrierAnnounce> announce(const pb::CarrierTree& t, const pb::Hash32& parent, std::uint64_t parent_pos,
                                          std::uint8_t branch, std::uint64_t count,
                                          const std::function<std::uint64_t(std::uint64_t)>& h_of = steady_h,
                                          std::uint16_t ballot = 0, const CarriedGen& carry = {}) {
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
        const std::vector<pb::CarriedPlacement> cs = carry ? carry(pos) : std::vector<pb::CarriedPlacement>{};
        const pb::CarrierAnnounce c{cid(branch, pos), prev, h_of(pos), pb::carrier_receipts_root_over(ids_of(cs), rs),
                                    ballot};
        const std::uint64_t d = w.next_difficulty();
        record = pb::record_height(record, c.h);
        w.push(pb::RetargetEntry{d, record});
        rs = pb::rs_step_at(t.ratchet_params(), rs, pos, step_inputs(d, ballot, cs), t.epoch_table()).s;
        g_carried[c.id] = cs;
        out.push_back(c);
        prev = c.id;
    }
    return out;
}

// One carrier on a held tip carrying cs, with the receipts_root it commits there.
pb::CarrierAnnounce on_tip(const pb::CarrierTree& t, const pb::Hash32& id, const pb::Hash32& tip, std::uint64_t h,
                           std::uint16_t ballot = 0, const std::vector<pb::CarriedPlacement>& cs = {}) {
    g_carried[id] = cs;
    return pb::CarrierAnnounce{id, tip, h, t.next_receipts_root(tip, ids_of(cs)).value_or(pb::Hash32{}), ballot};
}

// The node of a held carrier; a missing carrier fails a check and reads as an empty node.
const pb::CarrierNode& node_of(const pb::CarrierTree& t, const pb::Hash32& id) {
    static const pb::CarrierNode kMissing{};
    const pb::CarrierNode* n = t.find(id);
    if (n == nullptr) {
        check(false, "carrier not held: " + hex(id.data(), 10));
        return kMissing;
    }
    return *n;
}

// Places c with the carried list it was announced with.
pb::PlaceOutcome put(pb::CarrierTree& t, const pb::CarrierAnnounce& c) { return t.place(c, carried_of(c.id)); }

// Places and (when `complete`) verifies and marks bodies. Returns true if all placed.
bool admit(pb::CarrierTree& t, const std::vector<pb::CarrierAnnounce>& cs, bool complete = true) {
    bool ok = true;
    for (const pb::CarrierAnnounce& c : cs) {
        ok = ok && put(t, c).verdict == pb::PlaceVerdict::Placed;
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

// A node that saw only the best chain of `t`: same ids, d, cum_work, S and
// activation rows.
bool fresh_node_agrees(const pb::CarrierTree& t, const Applied& a) {
    const auto chain = t.path(kGenesis, t.best().id);
    if (!chain || *chain != a.chain) return false;
    pb::CarrierTree fresh(P, kGenesis, kGenesisHeight, t.epoch_table(), {}, t.ratchet_params(),
                          t.genesis().rs.rules_cur);
    for (const pb::Hash32& id : *chain) {
        const pb::CarrierNode* n = t.find(id);
        if (fresh.place(pb::CarrierAnnounce{id, n->parent, n->h, n->receipts_root, n->ballot}, carried_of(id)).verdict
            != pb::PlaceVerdict::Placed)
            return false;
        fresh.mark_verified(id);
        fresh.mark_bodies(id);
        const pb::CarrierNode* f = fresh.find(id);
        if (f->d != n->d || !(f->cum_work == n->cum_work) || f->pos != n->pos || f->H != n->H || !(f->rs == n->rs)
            || f->activation != n->activation)
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
// carried_root over seq32(0x01), seq32(0x02), seq32(0x03) (E-10 n = 3), and
// its fold with the rs_root above.
const char* kCarried3Hex = "75e683fcba0f631eea34521cf0c7cceb72cca7c99fb168e7ff8ba2888436dfdd";
const char* kFoldCarried3Hex = "a9ddf8c4c22124167b5ee4c411a9639055c2e00b864c97b637261cdd10329ba9";

std::string hx(const pb::Hash32& h) { return hex(h.data(), h.size()); }

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
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
        pb::CarrierTree t(P, kGenesis, kGenesisHeight, pb::EpochTable{});
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
        check(put(t, bz[2]).verdict == pb::PlaceVerdict::Deferred && put(t, bz[1]).verdict == pb::PlaceVerdict::Deferred
                      && t.waiting() == 2,
              "unknown parent: deferred, not refused");
        check(put(t, bz[1]).verdict == pb::PlaceVerdict::Duplicate, "a waiting carrier repeated: duplicate");
        const pb::PlaceOutcome o = put(t, bz[0]);
        check(o.verdict == pb::PlaceVerdict::Placed && o.released == std::vector<pb::Hash32>{bz[1].id}
                      && o.discarded.empty() && t.waiting() == 1 && t.find(bz[1].id) == nullptr,
              "parent arrives: the carrier waiting on it is released, not placed");
        const pb::PlaceOutcome o1 = put(t, bz[1]);
        check(o1.verdict == pb::PlaceVerdict::Placed && o1.released == std::vector<pb::Hash32>{bz[2].id}
                      && t.waiting() == 0,
              "the released carrier admitted again: placed; the carrier waiting on it released");
        const pb::PlaceOutcome o2 = put(t, bz[2]);
        check(o2.verdict == pb::PlaceVerdict::Placed && o2.released.empty() && t.find(bz[2].id)->pos == 39,
              "the last released carrier placed at its position");
        check(put(t, bz[0]).verdict == pb::PlaceVerdict::Duplicate, "placed carrier repeated: duplicate");
        {
            const auto bq = announce(t, bz[2].id, 39, 10, 4);
            pb::CarrierAnnounce below = bq[1];
            below.h = 0;
            check(put(t, bq[3]).verdict == pb::PlaceVerdict::Deferred && put(t, bq[2]).verdict == pb::PlaceVerdict::Deferred
                          && put(t, below).verdict == pb::PlaceVerdict::Deferred && t.waiting() == 3,
                  "three carriers waiting, a chain of two under the third");
            const pb::PlaceOutcome q = put(t, bq[0]);
            check(q.verdict == pb::PlaceVerdict::Placed && q.released == std::vector<pb::Hash32>{below.id}
                          && t.waiting() == 2,
                  "parent arrives: the waiting carrier released");
            const pb::PlaceOutcome qb = put(t, below);
            check(qb.verdict == pb::PlaceVerdict::NotCarrier
                          && qb.discarded == std::vector<pb::WaitKey>{{bq[2].id, below.id}, {bq[3].id, bq[2].id}}
                          && t.waiting() == 0
                          && t.find(below.id) == nullptr && t.find(bq[2].id) == nullptr && t.find(bq[3].id) == nullptr,
                  "a released carrier below its parent's record: not a carrier, the two-level chain waiting on it "
                  "discarded");
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
            put(t, c);
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
        check(put(t, on_tip(t, cid(8, 1), tipn->id, tipn->H - 1)).verdict == pb::PlaceVerdict::NotCarrier,
              "h(c) < H(parent): not a carrier");
        check(put(t, on_tip(t, cid(8, 2), tipn->id, tipn->H)).verdict == pb::PlaceVerdict::Placed
                      && put(t, on_tip(t, cid(8, 3), tipn->id, tipn->H)).verdict == pb::PlaceVerdict::Placed
                      && t.find(cid(8, 2))->d == t.find(cid(8, 3))->d,
              "two carriers of one tip at one height: both placed, one d");
        check(d_matches_chain(t, bv.back().id), "(i) d over the extended chain");
    }

    // (d) within J
    {
        pb::CarrierTree t(P, kGenesis, kGenesisHeight, pb::EpochTable{});
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
        pb::CarrierTree t(P, kGenesis, kGenesisHeight, pb::EpochTable{});
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
        pb::CarrierTree t(P, kGenesis, kGenesisHeight, pb::EpochTable{});
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
        pb::CarrierTree t(P, kGenesis, kGenesisHeight, pb::EpochTable{});
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
        pb::CarrierTree t(P, kGenesis, kGenesisHeight, pb::EpochTable{}, {}, pb::kRuledRatchetParams, rules);
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
        const pb::Hash32 rr4 = *t.next_receipts_root(c[2].id, {});
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
        check(put(t, bad).verdict == pb::PlaceVerdict::FoldMismatch && t.find(bad.id) == nullptr && t.waiting() == 0,
              "a flipped bit: FoldMismatch (strike), not placed");
        bad.receipts_root = *t.next_receipts_root(c[1].id, {});
        check(put(t, bad).verdict == pb::PlaceVerdict::FoldMismatch, "the fold over another position's S: FoldMismatch");
        bad.receipts_root = pb::carrier_receipts_root(seq32(0x30), n3->rs);
        check(put(t, bad).verdict == pb::PlaceVerdict::FoldMismatch,
              "a non-zero carried_root on a carrier that carries nothing: FoldMismatch");
        check(put(t, good).verdict == pb::PlaceVerdict::Placed, "the honest fold: placed");

        // a released carrier with a wrong fold
        auto wq = announce(t, good.id, 4, 12, 4);
        wq[1].receipts_root[5] ^= 0x80;
        check(put(t, wq[3]).verdict == pb::PlaceVerdict::Deferred && put(t, wq[2]).verdict == pb::PlaceVerdict::Deferred
                      && put(t, wq[1]).verdict == pb::PlaceVerdict::Deferred,
              "three carriers waiting");
        const pb::PlaceOutcome o = put(t, wq[0]);
        check(o.verdict == pb::PlaceVerdict::Placed && o.released == std::vector<pb::Hash32>{wq[1].id}
                      && o.discarded.empty() && t.waiting() == 2,
              "parent arrives: the waiting carrier released");
        const pb::PlaceOutcome ow = put(t, wq[1]);
        check(ow.verdict == pb::PlaceVerdict::FoldMismatch
                      && ow.discarded == std::vector<pb::WaitKey>{{wq[2].id, wq[1].id}, {wq[3].id, wq[2].id}}
                      && ow.released.empty()
                      && t.waiting() == 0 && t.find(wq[1].id) == nullptr && t.find(wq[2].id) == nullptr
                      && t.find(wq[3].id) == nullptr,
              "the released carrier with a wrong fold: FoldMismatch, the two-level chain waiting on it discarded");

        // headers-first: a header carries no carried bodies, so no fold on that path
        auto side = announce(t, c[2].id, 3, 13, 5);
        const auto honest = t.check_side_headers(c[2].id, side, pow_all);
        bool passed = honest.has_value();
        for (const auto& h : *honest) passed = passed && h.check == pb::HeaderCheck::Passed;
        check(passed, "honest side headers: passed");
        side[2].receipts_root[0] ^= 1;
        int pow_calls = 0;
        const auto flipped = t.check_side_headers(c[2].id, side, [&](const pb::CarrierAnnounce&, std::uint64_t) {
            ++pow_calls;
            return true;
        });
        bool all_passed = flipped.has_value();
        for (const auto& h : *flipped) all_passed = all_passed && h.check == pb::HeaderCheck::Passed;
        check(all_passed && pow_calls == 5, "a header with a wrong receipts_root: the header checks pass, PoW on every header");
        check(put(t, side[0]).verdict == pb::PlaceVerdict::Placed && put(t, side[1]).verdict == pb::PlaceVerdict::Placed
                      && put(t, side[2]).verdict == pb::PlaceVerdict::FoldMismatch,
              "placed with its carried list: that carrier is FoldMismatch");

        // a ballot enters S
        const pb::CarrierAnnounce v1 = on_tip(t, cid(11, 6), wq[0].id, steady_h(6), pb::make_ballot(1, false));
        check(put(t, v1).verdict == pb::PlaceVerdict::Placed, "a carrier with ballot epoch 1 placed");
        const pb::CarrierNode nv = *t.find(v1.id);
        check(nv.rs.y1 == pb::RsWork(nv.d) && nv.rs.y2.is_zero(), "ballot epoch 1: y1 = its d");
        check(put(t, on_tip(t, cid(11, 7), v1.id, steady_h(7))).verdict == pb::PlaceVerdict::Placed,
              "its child commits S with y1: placed");
        const pb::RatchetPlacement unvoted{nv.d, 0};
        const pb::RatchetState no_vote = pb::rs_step(t.ratchet_params(), t.find(wq[0].id)->rs, nv.pos,
                                                     std::span<const pb::RatchetPlacement>(&unvoted, 1));
        const pb::CarrierAnnounce ignores{cid(11, 8), v1.id, steady_h(7),
                                          pb::carrier_receipts_root(pb::kNoCarriedRoot, no_vote), 0};
        check(put(t, ignores).verdict == pb::PlaceVerdict::FoldMismatch, "a child that drops the ballot from S: FoldMismatch");

        // the grid window end (L 5, GRACE 20)
        pb::CarrierTree ts(P, kGenesis, kGenesisHeight, pb::EpochTable{}, {}, pb::RatchetParams{5, 20}, rules);
        const auto cs = announce(ts, kGenesis, 0, 14, 6);
        check(admit(ts, cs), "L 5: six carriers placed");
        check(ts.find(cs[2].id)->rs.all == pb::RsWork(3 * P.d_min), "L 5: position 3, all = 3 d");
        check(ts.find(cs[3].id)->rs.all.is_zero() && ts.find(cs[3].id)->rs.levels == std::array<std::uint8_t, 4>{},
              "L 5: position 4 ends window 0: sums reset, level 0");
        check(ts.find(cs[5].id)->rs.all == pb::RsWork(2 * P.d_min), "L 5: positions 5 and 6 in window 1");
        check(ts.find(cs[3].id)->rs == ts.genesis().rs && cs[4].receipts_root == cs[0].receipts_root,
              "L 5: after the window end S equals the genesis S, so position 5 commits the fold of position 1");
    }

    // (k) carried lists: the fold over the carried ids, the tally over every placement
    {
        const pb::Hash32 rules = seq32(0x11);
        pb::CarrierTree t(P, kGenesis, kGenesisHeight, pb::EpochTable{}, {}, pb::kRuledRatchetParams, rules);
        const auto c = announce(t, kGenesis, 0, 0x21, 3);
        check(admit(t, c), "(k) three carriers placed");
        const pb::Hash32 tip = c[2].id;
        const pb::CarrierNode nt = node_of(t, tip);
        const std::vector<pb::Hash32> ids3{seq32(0x01), seq32(0x02), seq32(0x03)};
        check(hx(pb::carried_root(ids3)) == kCarried3Hex && hx(pb::rs_root(nt.rs)) == kFoldRsRootHex
                      && hx(*t.next_receipts_root(tip, ids3)) == kFoldCarried3Hex,
              "(k) next_receipts_root over three carried ids: carried_root 75e683fc..., receipts_root a9ddf8c4...");
        check(hx(*t.next_receipts_root(tip, {})) == kFoldReceiptsRootHex,
              "(k) next_receipts_root over no carried id: receipts_root 9c6c4c42...");

        // 1, 2 and 16 carried receipts
        for (const std::uint8_t n : {std::uint8_t{1}, std::uint8_t{2}, std::uint8_t{16}}) {
            const std::string tag = "(k) " + std::to_string(n) + " carried: ";
            std::vector<pb::CarriedPlacement> cs;
            std::uint64_t sum = 0;
            for (std::uint8_t k = 0; k < n; ++k) {
                cs.push_back(pb::CarriedPlacement{rid(0x22, n, k), P.d_min + k, 0, true});
                sum += P.d_min + k;
            }
            const pb::CarrierAnnounce honest = on_tip(t, cid(0x22, n), tip, steady_h(4), 0, cs);
            pb::CarrierAnnounce zero_root = honest;
            zero_root.id = cid(0x23, n);
            zero_root.receipts_root = pb::carrier_receipts_root(pb::kNoCarriedRoot, nt.rs);
            g_carried[zero_root.id] = cs;
            check(put(t, zero_root).verdict == pb::PlaceVerdict::FoldMismatch, tag + "a receipts_root over carried_root 0: FoldMismatch");
            pb::CarrierAnnounce no_list = honest;
            no_list.id = cid(0x24, n);
            check(t.place(no_list, {}).verdict == pb::PlaceVerdict::FoldMismatch,
                  tag + "the honest receipts_root placed without its carried list: FoldMismatch");
            check(put(t, honest).verdict == pb::PlaceVerdict::Placed, tag + "the fold over their ids: placed");
            const pb::CarrierNode nn = node_of(t, honest.id);
            pb::RsWork all = nt.rs.all;
            all += pb::RsWork(sum);
            all += pb::RsWork(nn.d);
            check(nn.rs.all == all && nn.rs.y1.is_zero() && nn.rs.y2.is_zero(), tag + "all += the carried work, then d");
        }

        // one #10: the tree's verdict is check_carried_fold's
        bool agree = true;
        for (std::uint8_t n = 0; n <= 16; ++n) {
            std::vector<pb::CarriedPlacement> cs;
            std::vector<pb::Hash32> ids;
            for (std::uint8_t k = 0; k < n; ++k) {
                cs.push_back(pb::CarriedPlacement{rid(0x25, n, k), P.d_min, 0, true});
                ids.push_back(cs.back().id);
            }
            for (std::uint8_t flip = 0; flip < 2; ++flip) {
                pb::CarrierAnnounce x = on_tip(t, cid(static_cast<std::uint8_t>(0x25 + flip), n), tip, steady_h(4), 0, cs);
                if (flip) x.receipts_root[31] ^= 1;
                const bool adm = pb::check_carried_fold(x.receipts_root, ids, nt.rs) == pb::FoldVerdict::Match;
                const bool tree = put(t, x).verdict == pb::PlaceVerdict::Placed;
                agree = agree && adm == tree && adm == (flip == 0);
            }
        }
        check(agree, "(k) the tree's #10 verdict equals check_carried_fold for 0..16 carried ids, honest and flipped");

        // the fold is over the list order, not the byte order of the ids
        std::vector<pb::CarriedPlacement> desc;
        for (std::uint8_t k = 3; k-- > 0;) desc.push_back(pb::CarriedPlacement{rid(0x29, 4, k), P.d_min, 0, true});
        std::vector<pb::Hash32> bytewise = ids_of(desc);
        std::sort(bytewise.begin(), bytewise.end());
        check(bytewise != ids_of(desc), "(k) a carried list whose order is not the byte order of its ids");
        const pb::CarrierAnnounce in_list = on_tip(t, cid(0x29, 4), tip, steady_h(4), 0, desc);
        pb::CarrierAnnounce in_bytes = in_list;
        in_bytes.id = cid(0x29, 5);
        in_bytes.receipts_root = pb::carrier_receipts_root_over(bytewise, nt.rs);
        g_carried[in_bytes.id] = desc;
        check(put(t, in_bytes).verdict == pb::PlaceVerdict::FoldMismatch,
              "(k) a receipts_root over the ids in byte order: FoldMismatch");
        check(put(t, in_list).verdict == pb::PlaceVerdict::Placed, "(k) the fold over the ids in list order: placed");

        // the tally: every placement at x, a dead one at 0
        const std::vector<pb::CarriedPlacement> mix{
                {rid(0x27, 4, 0), 30000, pb::make_ballot(1, false), true},
                {rid(0x27, 4, 1), 40000, pb::make_ballot(1, false), false},
                {rid(0x27, 4, 2), 25000, pb::make_ballot(2, true), true}};
        const pb::CarrierAnnounce cm = on_tip(t, cid(0x27, 4), tip, steady_h(4), 0, mix);
        check(put(t, cm).verdict == pb::PlaceVerdict::Placed, "(k) a carrier with two live and one dead carried receipt placed");
        const pb::CarrierNode nm = node_of(t, cm.id);
        pb::RsWork all = nt.rs.all;
        all += pb::RsWork(30000);
        all += pb::RsWork(25000);
        all += pb::RsWork(nm.d);
        check(nm.rs.all == all, "(k) all += the live carried work and d; the dead receipt adds 0");
        check(nm.rs.y1 == pb::RsWork(55000) && nm.rs.y2 == pb::RsWork(25000),
              "(k) y1 / y2 by the carried ballots; the dead receipt adds 0");
        check(nm.cum_work == nat::u128_add(nt.cum_work, nat::U128{nm.d, 0}), "(k) cum_work counts the carrier only");
        check(put(t, on_tip(t, cid(0x27, 5), cm.id, steady_h(5))).verdict == pb::PlaceVerdict::Placed,
              "(k) its child commits the S of every placement: placed");
        const pb::RatchetPlacement own_only{nm.d, 0};
        const pb::RatchetState carrier_only =
                pb::rs_step(t.ratchet_params(), nt.rs, nm.pos, std::span<const pb::RatchetPlacement>(&own_only, 1));
        const pb::CarrierAnnounce co{cid(0x27, 6), cm.id, steady_h(5),
                                     pb::carrier_receipts_root(pb::kNoCarriedRoot, carrier_only), 0};
        check(put(t, co).verdict == pb::PlaceVerdict::FoldMismatch, "(k) a child committing the carrier-only S: FoldMismatch");
        const std::vector<pb::RatchetPlacement> dead_counted{
                {30000, pb::make_ballot(1, false)}, {40000, pb::make_ballot(1, false)}, {25000, pb::make_ballot(2, true)}, {nm.d, 0}};
        const pb::CarrierAnnounce cd{cid(0x27, 7), cm.id, steady_h(5),
                                     pb::carrier_receipts_root(pb::kNoCarriedRoot,
                                                               pb::rs_step(t.ratchet_params(), nt.rs, nm.pos, dead_counted)),
                                     0};
        check(put(t, cd).verdict == pb::PlaceVerdict::FoldMismatch,
              "(k) a child committing S with the dead receipt counted: FoldMismatch");
    }

    // (l) activation inside the tree: L 5, GRACE 20, kind 2 fixed at 20
    {
        const pb::RatchetParams R{5, 20, 130};
        const pb::Hash32 G = seq32(0x47), D1 = seq32(0xa1);
        pb::EpochTable T;
        T.compiled.push_back(pb::CompiledEpoch{0, G, std::nullopt});
        T.compiled.push_back(pb::CompiledEpoch{1, D1, std::nullopt});
        T.attempts.push_back(pb::Deployment{1, D1, pb::kKindFixed, 0, 0, 20});
        pb::CarrierTree t(P, kGenesis, kGenesisHeight, T, {}, R, G);
        const CarriedGen one = [](std::uint64_t pos) {
            return std::vector<pb::CarriedPlacement>{{rid(0x28, pos, 0), 1000, pb::make_ballot(1, false), true}};
        };
        const auto cs = announce(t, kGenesis, 0, 0x28, 24, steady_h, 0, one);
        check(admit(t, cs), "(l) 24 carriers carrying one receipt each placed through the activation at 20");
        const pb::CarrierNode n19 = node_of(t, cs[18].id), n20 = node_of(t, cs[19].id), n21 = node_of(t, cs[20].id);
        check(n19.pos == 19 && n19.rs.epoch_cur == 0 && n19.rs.rules_cur == G, "(l) S_19: epoch 0, rules_cur G");
        check(n20.pos == 20 && n20.rs.epoch_cur == 1 && n20.rs.rules_cur == D1,
              "(l) S_20: epoch 1, rules_cur = the deployment digest");
        check(n20.rs == pb::rs_step(R, n19.rs, 20, step_inputs(n20.d, 0, carried_of(n20.id)), true, D1),
              "(l) S_20 = rs_step with step (1) over every placement at 20");
        bool one_row = true;
        for (const auto& x : cs) {
            const pb::CarrierNode& n = node_of(t, x.id);
            one_row = one_row
                      && (n.pos == 20 ? n.activation == pb::ActivationRow{1, 20, D1} : !n.activation.has_value());
        }
        check(one_row, "(l) the activation row (1, 20, digest) on the carrier at 20 only");
        check(n21.receipts_root == pb::carrier_receipts_root_over(ids_of(carried_of(n21.id)), n20.rs),
              "(l) the carrier at 21 commits S_20");
        pb::CarrierTree u(P, kGenesis, kGenesisHeight, pb::EpochTable{}, {}, R, G);
        bool through = true;
        for (std::size_t i = 0; i < 20; ++i) through = through && put(u, cs[i]).verdict == pb::PlaceVerdict::Placed;
        check(through && node_of(u, cs[19].id).rs.epoch_cur == 0 && !node_of(u, cs[19].id).activation.has_value(),
              "(l) the same carriers in a tree without the table: no activation at 20");
        check(put(u, cs[20]).verdict == pb::PlaceVerdict::FoldMismatch, "(l) there the carrier at 21 is FoldMismatch");
    }

    // (m) an honest heavier side branch whose carriers carry 1-3 receipts
    {
        pb::CarrierTree t(P, kGenesis, kGenesisHeight, pb::EpochTable{});
        Applied node(J);
        const auto trunk = announce(t, kGenesis, 0, 0x31, 100);
        check(admit(t, trunk), "(m) trunk placed");
        const pb::Hash32 fork = trunk.back().id;
        const auto a = announce(t, fork, 100, 0x32, 50);
        check(admit(t, a), "(m) A, carrying nothing, placed");
        for (const auto& c : trunk) node.apply(c.id);
        for (const auto& c : a) node.apply(c.id);
        check(t.best().id == a.back().id, "(m) A best and applied");
        const CarriedGen some = [](std::uint64_t pos) {
            std::vector<pb::CarriedPlacement> cs;
            const std::uint8_t n = static_cast<std::uint8_t>(1 + pos % 3);
            for (std::uint8_t k = 0; k < n; ++k)
                cs.push_back(pb::CarriedPlacement{rid(0x33, pos, k), P.d_min + 7 * k,
                                                  pb::make_ballot(static_cast<std::uint16_t>(k % 2), false),
                                                  (pos + k) % 5 != 0});
            return cs;
        };
        const auto b = announce(t, fork, 100, 0x33, 51, steady_h, 0, some);
        const auto dh = t.decide_headers(fork, b, pow_all, J);
        check(dh && dh->action == pb::SideBranchAction::FetchBodies,
              "(m) headers first: the heavier branch whose carriers carry receipts is fetched");
        const auto side = t.check_side_headers(fork, b, pow_all);
        bool hp = side.has_value();
        for (const auto& h : *side) hp = hp && h.check == pb::HeaderCheck::Passed;
        check(hp, "(m) every header of that branch passes");
        bool none_struck = true;
        std::size_t n_carried = 0, n_dead = 0;
        for (const auto& c : b) {
            none_struck = none_struck && put(t, c).verdict == pb::PlaceVerdict::Placed;
            t.mark_verified(c.id);
            t.mark_bodies(c.id);
            for (const pb::CarriedPlacement& r : carried_of(c.id)) {
                ++n_carried;
                n_dead += r.live ? 0 : 1;
            }
        }
        check(none_struck && n_carried >= 51 && n_dead > 0,
              "(m) every carrier placed with its 1-3 carried receipts, some dead: none struck");
        check(t.best().id == b.back().id, "(m) the heavier branch wins fork choice");
        check(t.work_after(fork, b.back().id) == nat::u128_add(t.work_after(fork, a.back().id).value_or(nat::U128{}),
                                                               nat::U128{node_of(t, b.back().id).d, 0}),
              "(m) work after the branch point: A plus one carrier (receipts never count)");
        pb::RatchetState s = node_of(t, fork).rs;
        for (const auto& c : b) {
            const pb::CarrierNode& n = node_of(t, c.id);
            s = pb::rs_step_at(t.ratchet_params(), s, n.pos, step_inputs(n.d, c.ballot, carried_of(c.id)),
                               t.epoch_table())
                        .s;
        }
        check(s == node_of(t, b.back().id).rs, "(m) S at the tip: every placement of the branch, dead at 0");
        const auto plan = t.plan_switch(node.tip(), node.j);
        check(plan && plan->verdict == pb::RewindVerdict::Rewound && plan->undo_depth == 50 && plan->apply.size() == 51,
              "(m) fork 50 below the applied tip: rewind");
        check(plan && execute(node, t, *plan, 0) && fresh_node_agrees(t, node),
              "(m) rewind + replay: the chain and S of a node that saw only that branch");

        // a released carrier carrying receipts
        const auto e = announce(t, b.back().id, 151, 0x34, 2, steady_h, 0, some);
        check(e.size() == 2, "(m) two carriers announced on the branch tip");
        if (e.size() == 2) {
            check(put(t, e[1]).verdict == pb::PlaceVerdict::Deferred, "(m) a carrier carrying receipts waits on its parent");
            const pb::PlaceOutcome oe = put(t, e[0]);
            check(oe.verdict == pb::PlaceVerdict::Placed && oe.released == std::vector<pb::Hash32>{e[1].id},
                  "(m) its parent placed: released");
            const pb::PlaceOutcome oe1 = put(t, e[1]);
            const pb::CarrierNode ne0 = node_of(t, e[0].id);
            const pb::CarrierNode* ne1 = t.find(e[1].id);
            check(oe1.verdict == pb::PlaceVerdict::Placed && ne1 != nullptr
                          && ne1->rs
                                     == pb::rs_step_at(t.ratchet_params(), ne0.rs, ne1->pos,
                                                       step_inputs(ne1->d, 0, carried_of(e[1].id)), t.epoch_table())
                                                .s,
                  "(m) admitted again with its carried list: placed, S over every placement");
        }
    }

    // (n) a waiting entry is (id, claimed parent): a forged parent claim does not block the honest carrier
    {
        pb::CarrierTree t(P, kGenesis, kGenesisHeight, pb::EpochTable{});
        const auto trunk = announce(t, kGenesis, 0, 0x41, 3);
        check(admit(t, trunk), "(n) trunk placed");
        const pb::Hash32 tip = trunk.back().id;
        const pb::Hash32 forged_parent = cid(0x43, 4);
        const auto hc = announce(t, tip, 3, 0x42, 5);  // X at 4 on the tip, its child at 5, then 6, 7, 8
        check(hc.size() == 5, "(n) five carriers announced on the tip");
        if (hc.size() == 5) {
            pb::CarrierAnnounce forged = hc[0];
            forged.parent = forged_parent;
            check(put(t, forged).verdict == pb::PlaceVerdict::Deferred && t.waiting() == 1,
                  "(n) X's id naming an unknown parent arrives first: Deferred");
            check(put(t, forged).verdict == pb::PlaceVerdict::Duplicate, "(n) the same (id, claimed parent) again: Duplicate");
            check(put(t, hc[1]).verdict == pb::PlaceVerdict::Deferred && t.waiting() == 2, "(n) X's child waits on X");
            const pb::PlaceOutcome ox = put(t, hc[0]);
            check(ox.verdict == pb::PlaceVerdict::Placed && ox.released == std::vector<pb::Hash32>{hc[1].id}
                          && t.waiting() == 0 && node_of(t, hc[0].id).parent == tip,
                  "(n) the honest X with a held parent: placed (not Duplicate), the forged claim dropped, its child "
                  "released");
            check(put(t, hc[1]).verdict == pb::PlaceVerdict::Placed, "(n) X's child placed");
            const pb::CarrierAnnounce z = on_tip(t, forged_parent, tip, steady_h(4));
            const pb::PlaceOutcome oz = put(t, z);
            check(oz.verdict == pb::PlaceVerdict::Placed && oz.released.empty(),
                  "(n) the forged claim's parent placed later: nothing released");

            // Y waits under its unknown honest parent and under a forged one; the forged parent is refused
            const pb::CarrierAnnounce& ph = hc[2];  // Y's honest parent, not yet held
            const pb::CarrierAnnounce& y = hc[3];
            const pb::CarrierAnnounce& yc = hc[4];  // Y's child
            const pb::Hash32 bad_parent = cid(0x44, 6);
            pb::CarrierAnnounce y_forged = y;
            y_forged.parent = bad_parent;
            check(put(t, yc).verdict == pb::PlaceVerdict::Deferred && put(t, y).verdict == pb::PlaceVerdict::Deferred
                          && put(t, y_forged).verdict == pb::PlaceVerdict::Deferred && t.waiting() == 3,
                  "(n) Y waits under two claimed parents, Y's child waits on Y");
            const pb::CarrierAnnounce refused =
                    on_tip(t, bad_parent, hc[1].id, node_of(t, hc[1].id).H - 1);  // below its parent's record
            const pb::PlaceOutcome orf = put(t, refused);
            check(orf.verdict == pb::PlaceVerdict::NotCarrier
                          && orf.discarded == std::vector<pb::WaitKey>{{y.id, bad_parent}}
                          && t.waiting() == 2,
                  "(n) the forged parent refused: only Y's claim under it dropped; Y's child kept (Y still waits)");
            const pb::PlaceOutcome op = put(t, ph);
            check(op.verdict == pb::PlaceVerdict::Placed && op.released == std::vector<pb::Hash32>{y.id},
                  "(n) Y's honest parent placed: Y released");
            const pb::PlaceOutcome oy = put(t, y);
            check(oy.verdict == pb::PlaceVerdict::Placed && oy.released == std::vector<pb::Hash32>{yc.id}
                          && put(t, yc).verdict == pb::PlaceVerdict::Placed && t.waiting() == 0,
                  "(n) Y and its child placed");

            // R waits under its unknown honest parent; a copy of R naming a held parent is refused; R's child stays
            const auto rc = announce(t, yc.id, 8, 0x46, 3);  // R1 at 9 on Y's child, R at 10, R's child at 11
            check(rc.size() == 3, "(n) three carriers announced on Y's child");
            if (rc.size() == 3) {
                check(put(t, rc[2]).verdict == pb::PlaceVerdict::Deferred
                              && put(t, rc[1]).verdict == pb::PlaceVerdict::Deferred && t.waiting() == 2,
                      "(n) R waits on its unknown parent, R's child waits on R");
                pb::CarrierAnnounce r_held = rc[1];
                r_held.parent = yc.id;
                r_held.h = node_of(t, yc.id).H - 1;  // below its parent's record
                const pb::PlaceOutcome orh = put(t, r_held);
                check(orh.verdict == pb::PlaceVerdict::NotCarrier && orh.discarded.empty() && t.waiting() == 2,
                      "(n) a copy of R naming a held parent refused: R still waits, so R's child is kept");
                const pb::PlaceOutcome or1 = put(t, rc[0]);
                check(or1.verdict == pb::PlaceVerdict::Placed && or1.released == std::vector<pb::Hash32>{rc[1].id},
                      "(n) R's honest parent placed: R released");
                const pb::PlaceOutcome orr = put(t, rc[1]);
                check(orr.verdict == pb::PlaceVerdict::Placed && orr.released == std::vector<pb::Hash32>{rc[2].id}
                              && put(t, rc[2]).verdict == pb::PlaceVerdict::Placed && t.waiting() == 0,
                      "(n) R and its child placed");
            }
        }
    }

    // (o) N-7 pairs; unwait removes one pair and does not cascade
    {
        pb::CarrierTree t(P, kGenesis, kGenesisHeight, pb::EpochTable{});
        const auto trunk = announce(t, kGenesis, 0, 0x51, 3);
        check(admit(t, trunk), "(o) trunk placed");
        const pb::Hash32 tip = trunk.back().id;
        const auto lv = announce(t, tip, 3, 0x52, 3);  // refused at 4, child at 5, grandchild at 6
        check(lv.size() == 3, "(o) three carriers announced");
        if (lv.size() == 3) {
            check(put(t, lv[2]).verdict == pb::PlaceVerdict::Deferred && put(t, lv[1]).verdict == pb::PlaceVerdict::Deferred
                          && t.waiting() == 2,
                  "(o) the child waits on the refused carrier, the grandchild on the child");
            pb::CarrierAnnounce refused = lv[0];
            refused.h = node_of(t, tip).H - 1;  // below its parent's record
            const pb::PlaceOutcome o = put(t, refused);
            check(o.verdict == pb::PlaceVerdict::NotCarrier
                          && o.discarded == std::vector<pb::WaitKey>{{lv[1].id, refused.id}, {lv[2].id, lv[1].id}}
                          && t.waiting() == 0,
                  "(o) N-7: the discarded entries are ((child, refused), (grandchild, child))");
        }
        // unwait: X waits under parents A and B, Z waits on X
        const pb::Hash32 pa = cid(0x53, 4), pb_ = cid(0x54, 4);
        const pb::CarrierAnnounce x{cid(0x55, 5), pa, steady_h(5), pb::Hash32{}, 0};
        pb::CarrierAnnounce x_b = x;
        x_b.parent = pb_;
        const pb::CarrierAnnounce z{cid(0x56, 6), x.id, steady_h(6), pb::Hash32{}, 0};
        check(put(t, x).verdict == pb::PlaceVerdict::Deferred && put(t, x_b).verdict == pb::PlaceVerdict::Deferred
                      && put(t, z).verdict == pb::PlaceVerdict::Deferred && t.waiting() == 3,
              "(o) X waits under A and under B, Z waits on X");
        check(t.unwait(x.id, pa) && t.waiting() == 2, "(o) unwait(X, A): one pair removed");
        check(!t.unwait(x.id, pa), "(o) unwait of a removed pair: false");
        check(t.place(x_b, {}).verdict == pb::PlaceVerdict::Duplicate && t.place(z, {}).verdict == pb::PlaceVerdict::Duplicate,
              "(o) X's claim under B and Z's entry on X stay (no cascade)");
        check(t.place(x, {}).verdict == pb::PlaceVerdict::Deferred && t.waiting() == 3,
              "(o) the removed pair can wait again");
        check(t.unwait(x.id, pa) && t.unwait(x.id, pb_) && t.waiting() == 1, "(o) both of X's pairs removed; Z stays");
        check(t.unwait(z.id, x.id) && t.waiting() == 0, "(o) Z's pair removed: nothing waits");
    }

    return finish("xmr_carrier_sharechain_kat");
}
