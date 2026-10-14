// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_epoch_kat (C23; pathb_ratchet_activation.hpp): the activation machine
// at L 34,881, GRACE 120,960, TIMEOUT 941,760.
//   1  genesis epoch 0; rules_epoch != epoch_at refused; a carried receipt from
//      before H_act admitted after it; HELLO trailer only (no table); equal
//      epoch_cur + other lane rules -> LANE_RULES_MISMATCH; other epoch_cur accepted
//   2  HOLD from the node's own chain at exactly (k+1)L - 1 + GRACE - 1; one
//      unit below 3/4: no HOLD; no strike; the chain stays a prefix
//   3  no HOLD on a frame: rules_epoch 65535, a known epoch before H_act, an
//      epoch not locked in: STRIKE, no HOLD, jobs keep advancing
//   4  deferral cap: H_hold .. H_hold + 3,335 stored, the next dropped, no strike
//   5  lock-in at the end of the range (F1) and in an early window
//   6  act exactly at H_act; rs_step_at == rs_step(act); AR row at H_act only
//   7  epoch_at: AR == S-derived on a two-activation chain; journal depths
//      64 / 1,152 / 4,608 give one verdict (orphaned branch, header-only,
//      activation 2,100 back); (i) == (ii) at the best tip; a longer side
//      branch with a window end inside (pos(best), y); x > f + GRACE DEFERs;
//      rewind across H_act; joiner claimed below p0
//   8  fold only for carriers
//   9  HELLO diagnostics; the 59-byte descriptor preimage golden
//   10 kind 2 on regtest
//   11 ratchet-state commitment (i)-(iii); HOLD paid and converged
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_hello.hpp"
#include "impl/xmr/pathb/pathb_lane_rules.hpp"
#include "impl/xmr/pathb/pathb_ratchet_activation.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_ratchet_sim.hpp"

using namespace pathb_kat;
using namespace ratchet_sim;

namespace {

const pb::RatchetParams P = pb::kRuledRatchetParams;
const std::uint64_t L = P.window;
const std::uint64_t GRACE = P.grace;
const std::uint64_t NW = pb::ratchet_vote_windows(P);
// 3/4 of one window of unit carriers rounded up: 26,161 locks in, 26,160 does not.
const std::uint64_t kYesLock = (3 * L + 3) / 4;

std::string hx(const Hash32& h) { return hex(h.data(), h.size()); }

// yes on the first `n` positions of grid window k only.
std::function<bool(std::uint64_t)> yes_in(std::uint64_t k, std::uint64_t n) {
    return [k, n](std::uint64_t x) { return x / L == k && x % L < n; };
}

void genesis_and_frames() {
    const pb::EpochTable T = release({});
    const pb::RatchetState s0 = pb::genesis_ratchet_state(kG);
    check(s0.epoch_cur == 0 && s0.rules_cur == kG, "1 genesis: epoch_cur 0, rules_cur G");
    check(pb::base(s0, T) && !pb::open(P, s0, 0, T) && pb::e_impl(P, s0, 0, T).value == 0, "1 genesis: base, nothing open");
    check(pb::frame_epoch_verdict(5, 0, pb::kNoHold, 0) == pb::FrameVerdict::Judge, "1 rules_epoch == epoch_at: JUDGE");
    check(pb::frame_epoch_verdict(5, 1, pb::kNoHold, 0) == pb::FrameVerdict::Strike, "1 rules_epoch != epoch_at: STRIKE");
    // a carried receipt whose tip is before H_act keeps its epoch (0) and is judged after H_act
    const std::uint64_t h_act = 1000;
    check(pb::frame_epoch_verdict(h_act - 5, 0, pb::kNoHold, 0) == pb::FrameVerdict::Judge,
          "1 carried receipt with a tip before H_act: rules_epoch 0 JUDGE after H_act");
    check(pb::frame_epoch_verdict(h_act + 1, 0, pb::kNoHold, 1) == pb::FrameVerdict::Strike,
          "1 a tip after H_act claiming epoch 0: STRIKE");
    // HELLO: only the 68-byte trailer (epoch_cur + diagnostics), no table
    check(pb::kHelloTrailerBytes == 68, "1 HELLO trailer 68 B, no deployment table");
    const pb::PathbLaneRules a = pb::epoch0_lane_rules(pb::LaneNet::Mainnet);
    pb::PathbLaneRules b = a;
    b.r_max = 17;
    const auto ba = pb::rules_block(a), bb = pb::rules_block(b);
    const pb::LaneRulesCompare c = pb::hello_rules_compare(0, ba, 0, bb);
    check(c.verdict == pb::LaneRulesVerdict::Mismatch && c.id == 0x08
              && c.text.rfind("LANE_RULES_MISMATCH field=r_max", 0) == 0,
          "1 equal epoch_cur, other r_max: " + c.text);
    check(pb::hello_rules_compare(0, ba, 1, bb).verdict == pb::LaneRulesVerdict::Equal,
          "1 a peer at another epoch_cur is accepted, rules not compared");
}

// 2 + 5 + 6: one upgraded release (start 0) and one release without the epoch.
struct HoldRun {
    std::uint64_t h_act = 0;
    std::uint64_t n_first_hold = 0;
    std::uint64_t n_strikes = 0, u_strikes = 0;
    std::uint16_t u_epoch_after = 0;
    std::uint64_t jobs_before = 0;
    bool u_built_at_hact = false;
    bool prefix = false;
    bool ar_row_ok = false;
};

HoldRun hold_run(std::uint64_t lock_window, std::uint64_t yes_count, std::uint64_t until) {
    Sim sim(P);
    Node U("U", release({vote(P, 1, kR1, 0)}));
    Node N("N", release({}));
    sim.nodes = {&U, &N};
    HoldRun r;
    r.h_act = pb::window_h_act(P, lock_window);
    sim.run(U, std::min(until, r.h_act), yes_in(lock_window, yes_count));
    r.prefix = N.h == U.h && N.S == U.S;
    r.jobs_before = N.jobs;
    if (until > r.h_act) {
        r.u_built_at_hact = !U.held(P) && U.h == r.h_act;
        sim.run(U, until, yes_in(lock_window, yes_count));
    }
    r.n_first_hold = N.first_hold.value_or(0);
    r.n_strikes = N.strikes;
    r.u_strikes = U.strikes;
    r.u_epoch_after = U.S.epoch_cur;
    r.ar_row_ok = U.ar.rows().size() == 1 && U.ar.rows()[0] == pb::ActivationRow{1, r.h_act, kR1};
    return r;
}

void hold_from_own_chain() {
    // window 0 locks in: h_L = L - 1, H_act = L - 1 + GRACE = 155,840
    const HoldRun r = hold_run(0, kYesLock, pb::window_h_act(P, 0) + 3);
    check(r.h_act == 155840, "2 H_act = (k+1)L - 1 + GRACE = 155,840");
    check(r.prefix, "2 one position earlier the node without the epoch still builds (S equal at H_act - 1)");
    check(r.n_first_hold == r.h_act, "2 the node without the epoch and without a descriptor HOLDs at tip H_act - 1 (x = H_act)");
    check(r.n_strikes == 0 && r.u_strikes == 0, "2 no strike on either node");
    check(r.u_built_at_hact && r.u_epoch_after == 1 && r.ar_row_ok, "5 early window: activation at H_act, AR row (1, H_act, digest)");
    const HoldRun below = hold_run(0, kYesLock - 1, pb::window_h_act(P, 0) + 3);
    check(below.n_first_hold == 0 && below.u_epoch_after == 0 && below.n_strikes == 0,
          "2 one credited unit below 3/4: no lock-in, no HOLD, no activation");
}

void end_of_range() {
    // lock-in in window 22, one of the last 4 of 26: H_act after timeout_D
    const std::uint64_t k = NW - 4;
    const std::uint64_t h_act = pb::window_h_act(P, k);
    check(h_act > NW * L, "5 F1: H_act " + std::to_string(h_act) + " after timeout " + std::to_string(NW * L));
    const HoldRun r = hold_run(k, kYesLock, h_act + 2);
    check(r.u_built_at_hact, "5 F1: the upgraded node is LOCKED_IN at x = H_act and builds there");
    check(r.u_epoch_after == 1 && r.ar_row_ok, "5 F1: activation at H_act");
    check(r.n_first_hold == h_act && r.n_strikes == 0, "5 F1: the node without e holds at H_act - 1, no strike");
}

void act_predicate() {
    Sim sim(P);
    Node U("U", release({vote(P, 1, kR1, 0)}));
    sim.nodes = {&U};
    const std::uint64_t h_act = pb::window_h_act(P, 0);
    sim.run(U, h_act - 1, yes_in(0, kYesLock));
    const pb::RatchetState s_m2 = U.S;  // S_{H_act - 2}
    check(!pb::act(P, s_m2, h_act - 1, U.T).has_value(), "6 act false at H_act - 1");
    sim.run(U, h_act, yes_in(0, kYesLock));
    const pb::RatchetState s_m1 = U.S;  // S_{H_act - 1}
    check(pb::act(P, s_m1, h_act, U.T) == std::optional<Hash32>(kR1), "6 act true exactly at H_act");
    check(!pb::act(P, s_m1, h_act + 1, U.T).has_value() && !pb::act(P, s_m1, h_act - 1, U.T).has_value(),
          "6 act false off H_act on the same S");
    // level-1 window outside [S_D, timeout_D): a table whose attempt starts at 2L
    const pb::EpochTable late = release({vote(P, 1, kR1, 2 * L)});
    check(!pb::act(P, s_m1, h_act, late).has_value() && !pb::locked(P, s_m1, h_act, late),
          "6 act false for a level-1 window outside the attempt's range");
    pb::RatchetState nb = s_m1;
    nb.rules_cur = dg(0x99);
    check(!pb::act(P, nb, h_act, U.T).has_value(), "6 act false when ~base");
    // rs_step_at == rs_step(.., act(..), ..) and the AR row only at H_act
    const pb::RatchetPlacement pl{1, 1};
    bool eq = true, rows = true;
    for (std::uint64_t x : {h_act - 2, h_act - 1, h_act, h_act + 1}) {
        const pb::RatchetState& s = x <= h_act - 1 ? s_m2 : s_m1;
        const std::optional<Hash32> a = pb::act(P, s, x, U.T);
        const pb::StepAt st = pb::rs_step_at(P, s, x, std::span<const pb::RatchetPlacement>(&pl, 1), U.T);
        eq = eq && st.s == pb::rs_step(P, s, x, std::span<const pb::RatchetPlacement>(&pl, 1), a.has_value(), a.value_or(Hash32{}));
        rows = rows && st.row.has_value() == (x == h_act && &s == &s_m1);
    }
    check(eq, "6 rs_step_at equals rs_step(act(...)) on every vector");
    check(rows, "6 rs_step_at emits the AR row at H_act only");
    // h_act - 1 mutation probe: at x = H_act - 1 with S_{H_act - 2} the attempt is locked but act is false
    check(pb::locked(P, s_m2, h_act - 1, U.T), "6 LOCKED_IN before H_act");
}

void no_hold_on_frame() {
    Sim sim(P);
    Node U("U", release({vote(P, 1, kR1, 0)}));
    Node N("N", release({}));
    sim.nodes = {&U, &N};
    sim.run(U, 2 * L, yes_in(0, kYesLock));  // window 0 locked in, H_act = 155,840 not reached
    const std::uint64_t x = sim.pos;
    const std::uint64_t jobs0 = N.jobs + U.jobs;
    for (std::uint32_t forged : {65535u, 1u, 7u}) {
        for (Node* n : {&U, &N}) {
            const std::uint64_t hh = pb::h_hold(P, n->S, x, n->T);
            const pb::FrameVerdict v = pb::frame_epoch_verdict(x, forged, hh, pb::epoch_at_held(P, n->S, x, n->T));
            check(v == pb::FrameVerdict::Strike,
                  "3 " + n->name + ": forged rules_epoch " + std::to_string(forged) + " (with or without PoW) STRIKE");
            check(!n->held(P), "3 " + n->name + ": no HOLD after the forged frame");
        }
    }
    sim.run(U, 2 * L + 100, [](std::uint64_t) { return true; });
    check(N.jobs + U.jobs > jobs0 && N.strikes == 0 && U.strikes == 0, "3 template production / jobs keep advancing on every node");
}

void deferral_cap() {
    const std::uint64_t hh = 155840;
    const std::uint64_t span = pb::deferred_frame_span_default();
    check(span == 3336, "4 P-34 default = one joiner span at its minimum, N_rt + 1,176 = 3,336 positions");
    check(pb::defer_frame(hh, hh, true, span) == pb::DeferVerdict::Stored
              && pb::defer_frame(hh + 1176, hh, true, span) == pb::DeferVerdict::Stored
              && pb::defer_frame(hh + 3335, hh, true, span) == pb::DeferVerdict::Stored,
          "4 frames of H_hold .. H_hold + 3,335 stored without a verdict (H_hold + 1,176 among them)");
    check(pb::defer_frame(hh + 3336, hh, true, span) == pb::DeferVerdict::Drop, "4 the next frame beyond P-34 DROPPED");
    check(pb::defer_frame(hh + 3, hh, false, span) == pb::DeferVerdict::Drop, "4 a deferred frame failing the old header checks DROPPED");
    const std::uint64_t cap = pb::deferred_receipt_cap_default();
    check(cap == 18432 && pb::defer_receipt(cap - 1, cap, true) == pb::DeferVerdict::Stored
              && pb::defer_receipt(cap, cap, true) == pb::DeferVerdict::Drop,
          "4 deferred receipts beyond P-09 (18,432) DROPPED");
    // no strike / ban path exists for a deferred frame: the verdict under a HOLD is DEFER for every r in [epoch_at, 2^15 - 1]
    bool all_defer = true;
    for (std::uint32_t r = 0; r <= pb::kEpochMax; r += 97) all_defer = all_defer && pb::frame_epoch_verdict(hh, r, hh, 0) == pb::FrameVerdict::Defer;
    check(all_defer && pb::frame_epoch_verdict(hh, pb::kEpochMax, hh, 0) == pb::FrameVerdict::Defer
              && pb::frame_epoch_verdict(hh, pb::kEpochMax + 1, hh, 0) == pb::FrameVerdict::Strike,
          "4 DEFER guard epoch_at <= r <= 2^15 - 1; 32768 STRIKE");
    check(pb::frame_epoch_verdict(hh, 0, hh, 1) == pb::FrameVerdict::Strike, "4 DEFER guard: r below epoch_at STRIKE");
}

// 7: epoch_at
void epoch_at_chain() {
    // two activations: epoch 1 from start 0 (window 0), epoch 2 from 30 L (window 30)
    const std::uint64_t s2 = 30 * L;
    Sim sim(P);
    Node U("U", release({vote(P, 1, kR1, 0), vote(P, 2, kQ2, s2)}));
    sim.nodes = {&U};
    const std::uint64_t h1 = pb::window_h_act(P, 0), h2 = pb::window_h_act(P, 30);
    bool same = true;
    std::uint64_t checked = 0;
    while (sim.pos < h2 + 10) {
        const std::uint64_t x = sim.pos;
        const bool yes = (x / L == 0 || x / L == 30) && x % L < kYesLock;
        const std::uint16_t want = pb::epoch_at_held(P, U.S, x, U.T);
        sim.extend(U, yes ? std::nullopt : std::optional<std::uint16_t>(pb::make_ballot(U.S.epoch_cur, false)));
        same = same && U.ar.epoch_at(x) == want && want == U.S.epoch_cur;
        ++checked;
    }
    check(same && checked == h2 + 10, "7 AR epoch_at == S-derived epoch at every position of a two-activation chain");
    check(U.ar.rows().size() == 2 && U.ar.rows()[0].h_act == h1 && U.ar.rows()[1].h_act == h2 && U.S.epoch_cur == 2,
          "7 two activations recorded");
    // rewind across H_act(2) drops the row, a replay restores it
    U.J = 4608;
    Sim sim2(P);
    Node V("V", U.T, 4608);
    sim2.nodes = {&V};
    sim2.run_ballots(V, h2 + 20, [&](std::uint64_t x) -> std::optional<std::uint16_t> {
        const bool yes = (x / L == 0 || x / L == 30) && x % L < kYesLock;
        return yes ? std::nullopt : std::optional<std::uint16_t>(pb::make_ballot(V.S.epoch_cur, false));
    });
    check(sim2.rewind(h2 - 5) && V.ar.rows().size() == 1 && V.S.epoch_cur == 1, "7 a rewind across H_act drops the AR row");
    sim2.run_ballots(V, h2 + 20, [&](std::uint64_t) -> std::optional<std::uint16_t> { return std::nullopt; });
    check(V.ar.rows().size() == 2 && V.ar.rows()[1].h_act == h2 && V.S.epoch_cur == 2, "7 a replay restores the AR row");
}

void epoch_at_journal_depths() {
    // A (P-01 1,152), B (4 x 1,152), C (64): one release; activation of 1 at H_act
    const pb::EpochTable T = release({vote(P, 1, kR1, 0)});
    Sim sim(P);
    Node A("A", T, 1152), B("B", T, 4608), C("C", T, 64);
    sim.nodes = {&A, &B, &C};
    const std::uint64_t h1 = pb::window_h_act(P, 0);
    const std::uint64_t best = h1 + 2100;
    check(sim.run(A, best + 1, yes_in(0, kYesLock)), "7 chain to H_act + 2,100");
    // a carried receipt whose tip is on the best chain at H_act + 100, carried at the best tip
    const std::uint64_t t = h1 + 100, x = t + 1;
    std::vector<pb::FrameVerdict> v;
    std::vector<std::uint16_t> e;
    for (Node* n : {&A, &B, &C}) {
        const pb::EpochAt ea = pb::epoch_at(P, n->T, n->journal_state(t), n->ar, n->h - 1, n->S, t, x);
        e.push_back(ea.epoch);
        v.push_back(pb::frame_verdict(x, 1, pb::h_hold(P, n->S, n->h, n->T), ea));
    }
    check(B.journal_state(t).has_value() && !A.journal_state(t).has_value() && !C.journal_state(t).has_value(),
          "7 B holds S of the tip in its journal, A and C do not");
    check(e[0] == 1 && e[1] == 1 && e[2] == 1, "7 activation 2,100 back, tip at H_act + 100: epoch_at = 1 on A, B and C");
    check(v[0] == pb::FrameVerdict::Judge && v[1] == v[0] && v[2] == v[0], "7 one #4 verdict on A, B and C");

    // orphaned branch: X and Y fork at f; an activation inside (f, f + GRACE] on both;
    // the receipt's tip is on X 11 positions below the carrier on Y
    const std::uint64_t f = h1 - 500;
    Sim sx(P), sy(P);
    Node Ax("A", T, 1152), Bx("B", T, 4608), Cx("C", T, 64);
    sx.nodes = {&Ax, &Bx, &Cx};
    sx.run(Ax, f + 1, yes_in(0, kYesLock));
    Node Bside = Bx;  // B also follows branch X (held side branch)
    // branch X: f + 1 .. f + 1999 with other carrier works
    Sim bx(P);
    bx.pos = f + 1;
    bx.nodes = {&Bside};
    while (bx.pos < f + 2000) bx.extend(Bside, std::nullopt, 3);
    // branch Y wins: f + 1 .. f + 2010
    sy.pos = f + 1;
    sy.nodes = {&Ax, &Bx, &Cx};
    while (sy.pos < f + 2011) sy.extend(Ax);
    const std::uint64_t tX = f + 1999, xX = tX + 1;
    const pb::EpochAt ea_a = pb::epoch_at(P, T, std::nullopt, Ax.ar, Ax.h - 1, Ax.S, f, xX);
    const pb::EpochAt ea_b = pb::epoch_at(P, T, Bside.journal_state(tX), Bx.ar, Bx.h - 1, Bx.S, f, xX);
    const pb::EpochAt ea_c = pb::epoch_at(P, T, std::nullopt, Cx.ar, Cx.h - 1, Cx.S, f, xX);
    const pb::EpochAt ea_hdr = pb::epoch_at_fork_local(P, T, Bx.ar, Bx.h - 1, Bx.S, f, xX);
    check(Bside.journal_state(tX).has_value() && Bside.S.epoch_cur == 1, "7 B holds the orphaned branch with S (activation on it)");
    check(ea_a.epoch == 1 && ea_b.epoch == 1 && ea_c.epoch == 1 && ea_hdr.epoch == 1,
          "7 reorg of 2,000: a tip on the orphaned branch gets epoch 1 on A, B, C and header-only");
    // (i) == (ii) on every position of branch X that B holds
    bool agree = true;
    for (const auto& [px, s] : Bside.journal) {
        if (px < f || px + 1 > f + GRACE) continue;
        const std::uint64_t xx = px + 1;
        // (i) needs S_{px}: the journal entry at px is S_px
        const std::uint16_t i_val = pb::epoch_at_held(P, s, xx, T);
        const pb::EpochAt ii = pb::epoch_at_fork_local(P, T, Bx.ar, Bx.h - 1, Bx.S, f, xx);
        agree = agree && ii.kind == pb::EpochAtKind::Epoch && ii.epoch == i_val;
    }
    check(agree, "7 (i) == (ii) on every held position of the orphaned branch");
}

void epoch_at_branches() {
    const pb::EpochTable T = release({vote(P, 1, kR1, 0)});
    const std::uint64_t h1 = pb::window_h_act(P, 0);
    // (a) the best tip at H_act - 1: act fires at pos(best) + 1
    Sim sim(P);
    Node U("U", T, 4608);
    sim.nodes = {&U};
    sim.run(U, h1, yes_in(0, kYesLock));  // positions 0 .. H_act - 1
    const std::uint64_t pos_best = U.h - 1;
    const std::uint16_t i_val = pb::epoch_at_held(P, U.S, pos_best + 1, T);
    const pb::EpochAt ii = pb::epoch_at_fork_local(P, T, U.ar, pos_best, U.S, pos_best, pos_best + 1);
    check(pos_best + 1 == h1 && i_val == 1 && ii.epoch == 1, "7 (i) == (ii) = 1 at the best tip when act fires at pos(best) + 1");
    // (b) a longer side branch with a grid window end inside (pos(best), y)
    Sim s2(P);
    Node W("W", T, 4608);
    s2.nodes = {&W};
    const std::uint64_t pb_tip = 4 * L - 10;  // window 3; window 3 ends at 4L - 1 < y = H_act
    s2.run(W, pb_tip + 1, yes_in(0, kYesLock));
    const pb::RatchetState s_best = W.S;
    const pb::ActivationRecord ar_best = W.ar;
    const std::uint64_t f = pb_tip - 5;
    Node side = W;
    s2.nodes = {&side};
    s2.run(side, h1 + 1, [](std::uint64_t) { return true; });  // the side branch runs past y = H_act
    const std::uint64_t t = h1, x = t + 1;
    const std::uint16_t i2 = side.S.epoch_cur;  // S_t on the side branch, t = H_act
    const pb::EpochAt ii2 = pb::epoch_at_fork_local(P, T, ar_best, pb_tip, s_best, f, x);
    check(4 * L - 1 > pb_tip && 4 * L - 1 < h1, "7 a grid window end lies inside (pos(best), y)");
    check(i2 == 1 && ii2.epoch == 1, "7 a longer side branch: (ii) reads the lock-in at pos(best) + 1 and agrees with (i)");
    // (iii) x > f + GRACE: DEFER
    check(pb::epoch_at_fork_local(P, T, ar_best, pb_tip, s_best, f, f + GRACE + 1).kind == pb::EpochAtKind::Defer
              && pb::epoch_at_fork_local(P, T, ar_best, pb_tip, s_best, f, f + GRACE).kind == pb::EpochAtKind::Epoch,
          "7 x > f + GRACE DEFERs on every node (ruling 33 EP-4); x = f + GRACE judged");
    // a joiner: tips below p0 claimed; at or above p0 as a follower
    pb::ActivationRecord jar;
    jar.seed_joiner(s_best, pb_tip + 1);
    check(pb::epoch_at_fork_local(P, T, jar, pb_tip, s_best, pb_tip - 10, pb_tip - 9).kind == pb::EpochAtKind::Claimed,
          "7 joiner: a tip below p0 is claimed");
    check(pb::epoch_at_fork_local(P, T, jar, pb_tip + 1, s_best, pb_tip + 1, pb_tip + 2).kind == pb::EpochAtKind::Epoch,
          "7 joiner: a tip at p0 is judged like a follower");
    // (iii) before (i): a node that holds S on t's branch DEFERs too when x > f + GRACE
    const pb::EpochAt held_far = pb::epoch_at(P, T, side.S, ar_best, pb_tip, s_best, f, f + GRACE + 1);
    check(held_far.kind == pb::EpochAtKind::Defer
              && pb::frame_verdict(f + GRACE + 1, 7, pb::kNoHold, held_far) == pb::FrameVerdict::Defer
              && pb::frame_verdict(f + GRACE + 1, 7, 0, held_far) == pb::FrameVerdict::Defer,
          "7 x > f + GRACE: DEFER even where the node holds t's branch, whatever H_hold");
    // a joiner (adopted epoch 1) whose first reorg replaces p0 keeps its first row
    {
        Sim sj(P);
        Node V("V", T, 4608);
        sj.nodes = {&V};
        sj.run(V, h1 + 400, yes_in(0, kYesLock));
        const std::uint64_t p0 = h1 + 200;
        pb::ActivationRecord j;
        j.seed_joiner(*V.journal_state(p0 - 1), p0);
        const pb::ArRewind rw = j.rewind(p0 - 1);  // the first reorg replaces positions from p0 on
        const pb::ArRewind below = j.rewind(p0 - 2);
        check(rw == pb::ArRewind::Rewound && below == pb::ArRewind::BelowJoinerSeed && j.rows().size() == 1
                  && j.rows()[0] == pb::ActivationRow{1, p0 - 1, V.journal_state(p0 - 1)->rules_cur}
                  && j.joiner_p0() == std::optional<std::uint64_t>(p0),
              "7 a rewind below a joiner's p0 - 1 is refused and leaves its activation record unchanged");
        const pb::EpochAt ej = pb::epoch_at(P, T, std::nullopt, j, h1 + 399, V.S, p0 + 5, p0 + 6);
        check(j.rows().size() == 1 && j.joiner_p0() == std::optional<std::uint64_t>(p0) && ej.kind == pb::EpochAtKind::Epoch && ej.epoch == 1,
              "7 a joiner whose first reorg replaces p0 keeps its first row and judges a tip above p0 like a follower");
        check(pb::frame_verdict(p0 + 6, 3, pb::kNoHold, pb::EpochAt{pb::EpochAtKind::Claimed, 0}) == pb::FrameVerdict::Judge
                  && pb::frame_verdict(p0 + 6, 65535, pb::kNoHold, pb::EpochAt{pb::EpochAtKind::Claimed, 0}) == pb::FrameVerdict::Strike,
              "7 claimed: the receipt's rules_epoch is taken as claimed; 65535 still STRIKE");
    }
}

void fold_only_for_carriers() {
    // a carried receipt with a tip 2,000 behind its carrier: #4 from epoch_at, the fold is not compared
    const pb::EpochTable T = release({});
    Sim sim(P);
    Node U("U", T, 1152);
    sim.nodes = {&U};
    sim.run(U, 3000, [](std::uint64_t) { return false; });
    const pb::EpochAt e = pb::epoch_at(P, T, U.journal_state(999), U.ar, U.h - 1, U.S, 999, 1000);
    check(e.kind == pb::EpochAtKind::Epoch && e.epoch == 0
              && pb::frame_epoch_verdict(3000, 0, pb::kNoHold, e.epoch) == pb::FrameVerdict::Judge,
          "8 a carried receipt 2,000 behind its carrier (beyond the journal) admitted at #4");
    pb::RatchetState wrong = U.S;
    wrong.all += pb::RsWork(1);
    const Hash32 rr = pb::carrier_receipts_root(pb::kNoCarriedRoot, wrong);
    check(pb::check_carrier_fold(rr, pb::kNoCarriedRoot, U.S) == pb::FoldVerdict::Strike
              && pb::check_carrier_fold(pb::carrier_receipts_root(pb::kNoCarriedRoot, U.S), pb::kNoCarriedRoot, U.S)
                         == pb::FoldVerdict::Match,
          "8 a carrier with a wrong fold is STRIKE");
}

void hello_diagnostics() {
    const pb::Deployment d{1, pb::genesis_rules_digest(pb::LaneNet::Mainnet), pb::kKindVote, 30 * L, 56 * L, 0};
    const pb::DescriptorBytes b = pb::encode_descriptor(d);
    check(b.size() == 59, "9 descriptor preimage 59 B");
    check(hx(pb::descriptor_digest(d)) == "6a8afa719755c4dd46419a4ca5a511ed079a956b133a1c83e33f5a771d20b34a",
          "9 descriptor digest golden: " + hx(pb::descriptor_digest(d)));
    check(pb::decode_descriptor(b) == std::optional<pb::Deployment>(d), "9 descriptor record round trip");
    pb::HelloTrailer a{0, 1, dg(1), dg(2)}, c = a;
    check(!pb::trailer_alarm(a, c), "9 equal trailers: no alarm");
    c.deploy_digest = dg(3);
    check(pb::trailer_alarm(a, c), "9 equal epoch_cur / deploy_top, other deploy_digest: local alarm");
    c = a;
    c.next_digest = dg(4);
    check(pb::trailer_alarm(a, c), "9 two different nonzero next_digest: local alarm");
    c.next_digest = Hash32{};
    check(!pb::trailer_alarm(a, c), "9 a zero next_digest: no alarm");
    c = a;
    c.deploy_top = 0;
    c.deploy_digest = Hash32{};
    check(!pb::trailer_alarm(a, c), "9 other deploy_top: no alarm");
    // the alarm is not a verdict: lane rules at equal epoch_cur still compare Equal
    const auto blk = pb::rules_block(pb::epoch0_lane_rules(pb::LaneNet::Mainnet));
    check(pb::hello_rules_compare(0, blk, 0, blk).verdict == pb::LaneRulesVerdict::Equal, "9 links kept, no STRIKE");
    // trailer values from a node: E_impl below -> deploy_top = epoch_cur, digest zero
    pb::RatchetState s = pb::genesis_ratchet_state(dg(0x55));
    const pb::HelloTrailer t = pb::hello_trailer(P, s, 10, release({vote(P, 1, kR1, 0)}));
    check(t.deploy_top == 0 && t.deploy_digest == Hash32{}, "9 below: deploy_top = epoch_cur, deploy_digest zero");
    const pb::HelloTrailer t2 = pb::hello_trailer(P, pb::genesis_ratchet_state(kG), 10, release({vote(P, 1, kR1, 0)}));
    check(t2.deploy_top == 1 && t2.deploy_digest == pb::descriptor_digest(vote(P, 1, kR1, 0))
              && t2.next_digest == t2.deploy_digest,
          "9 open attempt: deploy_top = E_impl, deploy_digest = next_digest = its descriptor digest");
}

void kind2() {
    const pb::RatchetParams R = P;  // regtest default set
    const pb::Deployment k2 = fixed2(1, kR1, 0, GRACE);
    pb::EpochTable up = release({});
    up.compiled.push_back(pb::CompiledEpoch{1, kR1, std::nullopt});
    pb::EpochTable lacks = release({});
    const std::vector<pb::Deployment> file{k2};
    check(pb::merge_configured_deployments(pb::LaneNet::Regtest, up, file).ok
              && pb::merge_configured_deployments(pb::LaneNet::Regtest, lacks, file).ok,
          "10 the configured file merges into T on regtest");
    pb::EpochTable main_t = release({});
    check(!pb::merge_configured_deployments(pb::LaneNet::Mainnet, main_t, file).ok, "10 the configured file is refused on mainnet");
    check(!pb::deployment_table_valid(R, pb::LaneNet::Mainnet, up).ok && pb::deployment_table_valid(R, pb::LaneNet::Regtest, up).ok,
          "10 a table with a kind-2 descriptor: refused at start-up on mainnet, accepted on regtest");
    check(pb::implements2(up, k2) && !pb::implements2(lacks, k2), "10 implements2: compiled digest == descriptor digest");
    Sim sim(R);
    Node U("U", up), N("N", lacks);
    sim.nodes = {&U, &N};
    // labels before start / within
    check(pb::step(R, U.S, 0, U.T, *pb::own_attempt(U.T, 1)) == pb::DeploymentState::LockedIn, "10 LOCKED_IN from start");
    check(sim.run(U, GRACE + 50, [](std::uint64_t) { return false; }), "10 the upgraded node builds through fixed");
    check(U.S.epoch_cur == 1 && U.ar.rows().size() == 1 && U.ar.rows()[0].h_act == GRACE, "10 the upgraded node activates at fixed");
    check(N.first_hold == std::optional<std::uint64_t>(GRACE) && N.h == GRACE, "10 the node whose build lacks rules_of(e) holds at fixed - 1");
    check(N.strikes == 0 && N.defers == 50, "10 the held node strikes no upgraded frame at x >= fixed (all DEFERRED)");
    check(N.S.epoch_cur == 0, "10 it never activates");
    {
        const pb::RatchetState g1 = pb::genesis_ratchet_state(kG);
        check(!pb::locked(R, g1, 10, N.T) && !pb::act(R, g1, GRACE, N.T).has_value()
                  && pb::step(R, g1, 10, N.T, *pb::own_attempt(N.T, 1)) == pb::DeploymentState::Failed
                  && pb::step(R, g1, 10, U.T, *pb::own_attempt(U.T, 1)) == pb::DeploymentState::LockedIn,
              "10 implements2 gates locked / act: the lacking build is never LOCKED_IN (reads FAILED), the upgraded one is");
    }
    // a joiner of the lacking build starting after fixed adopts epoch 1 / kR1: never base, HOLDs at once, strikes nothing
    Node Nj("Nj", N.T);
    Nj.S = U.S;
    Nj.h = U.h;
    check(!pb::base(Nj.S, Nj.T) && pb::e_impl(R, Nj.S, Nj.h, Nj.T).below && Nj.held(R),
          "10 a joiner of a build lacking rules_of(e) starting after fixed HOLDs at once");
    // after fixed without the activation the kind-2 hold is gone (a node at x > fixed does not hold for it)
    pb::RatchetState g0 = pb::genesis_ratchet_state(kG);
    check(pb::h_hold(R, g0, GRACE, N.T) == GRACE && pb::h_hold(R, g0, GRACE + 1, N.T) == pb::kNoHold,
          "10 the kind-2 H_hold = fixed only while x <= fixed");
    check(pb::step(R, U.S, GRACE + 50, U.T, *pb::own_attempt(U.T, 1)) == pb::DeploymentState::Active, "10 ACTIVE");
    check(pb::step(R, N.S, GRACE + 1, N.T, *pb::own_attempt(N.T, 1)) == pb::DeploymentState::Failed,
          "10 FAILED: x > fixed without the activation");
    pb::EpochTable later = release({});
    later.compiled.push_back(pb::CompiledEpoch{1, kR1, std::nullopt});
    std::vector<pb::Deployment> f2{fixed2(1, kR1, 100, 100 + GRACE)};
    pb::merge_configured_deployments(pb::LaneNet::Regtest, later, f2);
    check(pb::step(R, pb::genesis_ratchet_state(kG), 50, later, later.attempts[0]) == pb::DeploymentState::Defined, "10 DEFINED before start");
    pb::RatchetState nb = pb::genesis_ratchet_state(dg(0x77));
    check(pb::step(R, nb, 150, later, later.attempts[0]) == pb::DeploymentState::Waiting, "10 WAITING: ~base inside start..fixed");
    // spacing: kind 2 of e then kind 1 of e + 1 starting at or before fixed(e): refused
    pb::EpochTable sp = release({fixed2(1, kR1, 0, GRACE), vote(R, 2, kQ2, 0)});
    check(!pb::deployment_table_valid(R, pb::LaneNet::Regtest, sp).ok, "10 kind 1 of e+1 starting before fixed(e) + 1 refused");
    const std::uint64_t ok_start = ((GRACE + 1 + L - 1) / L) * L;
    pb::EpochTable sp2 = release({fixed2(1, kR1, 0, GRACE), vote(R, 2, kQ2, ok_start)});
    check(pb::deployment_table_valid(R, pb::LaneNet::Regtest, sp2).ok, "10 kind 1 of e+1 at the first multiple of L after fixed(e) accepted");
    // decode a configured descriptor record
    const pb::DescriptorBytes rec = pb::encode_descriptor(k2);
    check(pb::decode_descriptor(rec) == std::optional<pb::Deployment>(k2), "10 configured record in the C-DEP field order");
}

void commitment_and_paid() {
    const pb::EpochTable Tu = release({vote(P, 1, kR1, 0)});
    const pb::EpochTable Tn = release({});
    const std::uint64_t h1 = pb::window_h_act(P, 0);
    Sim sim(P);
    sim.keep_chain = true;
    Node U("U", Tu, 4608), N("N", Tn, 4608);
    sim.nodes = {&U, &N};
    sim.run(U, L + 100, yes_in(0, kYesLock));  // past h_L = L - 1
    // (i) joiners during GRACE adopt S from the first span carrier (p0 between h_L and H_act)
    Node Ju("Ju", Tu, 4608), Jn("Jn", Tn, 4608);
    Ju.S = U.S;
    Ju.h = U.h;
    Ju.ar.seed_joiner(U.S, U.h);
    Jn.S = U.S;
    Jn.h = U.h;
    Jn.ar.seed_joiner(U.S, U.h);
    sim.nodes = {&U, &N, &Ju, &Jn};
    sim.run(U, h1 + 5, [](std::uint64_t) { return true; });
    check(Ju.S == U.S && Ju.S.epoch_cur == 1, "11(i) an upgraded joiner during GRACE activates at the follower's H_act");
    check(Jn.first_hold == std::optional<std::uint64_t>(h1) && N.first_hold == std::optional<std::uint64_t>(h1),
          "11(i) a lagging joiner holds at the same H_act as the follower");
    // a lagging joiner after H_act: adopted epoch_cur 1 above its E_impl -> HOLD at once
    Node Jlate("Jlate", Tn);
    Jlate.S = U.S;
    Jlate.h = U.h;
    check(pb::e_impl(P, Jlate.S, Jlate.h, Jlate.T).below && Jlate.held(P), "11(i) a lagging joiner whose adopted epoch_cur exceeds E_impl HOLDs at once");
    // (ii) a carrier whose receipts_root folds a different rs_root; a served S failing the fold
    pb::RatchetState other = U.S;
    other.all += pb::RsWork(1);
    check(pb::check_carrier_fold(pb::carrier_receipts_root(pb::kNoCarriedRoot, other), pb::kNoCarriedRoot, U.S) == pb::FoldVerdict::Strike,
          "11(ii) a carrier folding another rs_root is STRIKE");
    check(pb::check_carrier_fold(pb::carrier_receipts_root(pb::kNoCarriedRoot, U.S), pb::kNoCarriedRoot, other) == pb::FoldVerdict::Strike,
          "11(ii) a served S that fails the first span carrier's fold is refused");
    // (iii) two honest branches diverging across a grid window end, reorged within the journal
    sim.nodes = {&U};
    const std::uint64_t wend = 5 * L - 1;
    sim.run(U, wend - 3, [](std::uint64_t) { return false; });
    const std::uint64_t f = sim.pos - 1;
    const pb::RatchetState s_f = U.S;
    while (sim.pos < wend + 10) sim.extend(U, pb::make_ballot(2, false), 3);  // branch 1: other ballots and works across the window end
    const pb::RatchetState s_branch1 = U.S;
    check(sim.rewind(f) && U.S == s_f, "11(iii) reorg within the journal");
    sim.run(U, wend + 20, [](std::uint64_t) { return false; });  // branch 2 wins
    const std::vector<pb::RatchetState> re = sim.replay(Tu);
    bool every = re.size() == sim.pos && !(s_branch1 == U.S);
    for (const auto& [x, sx] : U.journal) every = every && re[x] == sx && pb::rs_root(re[x]) == pb::rs_root(sx);
    check(every && re.back() == U.S, "11(iii) rs_root of every carrier on the winning branch equals the value recomputed from genesis");
    // HOLD converged: the held node upgrades, restarts, judges the stored frames from its H_hold and reaches the majority's S
    N.T = Tu;
    const std::uint64_t from = N.h;
    bool judged = true;
    for (std::uint64_t x = from; x < sim.pos; ++x)
        judged = judged && sim.judge(N, x, re[x].epoch_cur, re[x - 1], sim.chain[x]) == pb::FrameVerdict::Judge;
    check(from == h1 && judged && N.S == U.S && N.strikes == 0,
          "11 HOLD paid and converged: after upgrade + restart the held node judges every deferred frame and equals the majority");
}

}  // namespace

int main() {
    genesis_and_frames();
    hold_from_own_chain();
    end_of_range();
    act_predicate();
    no_hold_on_frame();
    deferral_cap();
    epoch_at_chain();
    epoch_at_journal_depths();
    epoch_at_branches();
    fold_only_for_carriers();
    hello_diagnostics();
    kind2();
    commitment_and_paid();
    return finish("v37_xmr_epoch_kat");
}
