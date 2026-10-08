// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// xmr_epoch_tally_kat (C23; pathb_ratchet_state.hpp step 1,
// pathb_ratchet_activation.hpp): the tally and rs_step at L 34,881,
// GRACE 120,960, TIMEOUT 941,760.
//   1  fixed windows on the global grid; 4 yes == 3 all locks in; one unit
//      below fails; an empty window never locks in; no ballot = no; carried
//      receipts count at placement; a dead receipt adds 0
//   2  GRACE from h_L; STARTED windows 0..25, FAILED at S + 906,906, never
//      again; tail 70 % / 76 %: no yes after timeout, no HOLD
//   3  rs_step step 1; act = false byte-identical; a second activation
//   4  rewind across h_L
//   5  junk ballots; supermajority for an unpublished epoch
//   6  start-up checks; re-proposal spacing (F3)
//   7  predecessor digest; predecessor not in force
//   8  failure + re-proposal (R5-B1); failed release with a later epoch
//      (R6-M1); joiner of a failed release (R6-M2); same-digest re-proposal
//      (R6-m1); the layout-MT scenario
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <functional>
#include <tuple>
#include <optional>
#include <string>
#include <vector>

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
const std::uint64_t kYesLock = (3 * L + 3) / 4;  // 26,161 of 34,881

std::uint8_t level_after_window(const std::vector<pb::RatchetPlacement>& per_pos, std::uint64_t k,
                                const std::function<std::vector<pb::RatchetPlacement>(std::uint64_t)>& at) {
    pb::RatchetState s = pb::genesis_ratchet_state(kG);
    for (std::uint64_t x = k * L; x < (k + 1) * L; ++x) {
        const std::vector<pb::RatchetPlacement> v = at ? at(x) : per_pos;
        s = pb::rs_step(P, s, x, v);
    }
    return s.levels.back();
}

void tally() {
    // fixed windows, evaluated once at the last position
    pb::RatchetState s = pb::genesis_ratchet_state(kG);
    const pb::RatchetPlacement yes{1, 1};
    for (std::uint64_t x = 0; x < L - 1; ++x) s = pb::rs_step(P, s, x, std::span<const pb::RatchetPlacement>(&yes, 1));
    check(s.levels == std::array<std::uint8_t, 4>{0, 0, 0, 0} && s.all == pb::RsWork(L - 1), "1 no level before (k+1)L - 1");
    s = pb::rs_step(P, s, L - 1, std::span<const pb::RatchetPlacement>(&yes, 1));
    check(s.levels.back() == 1 && s.all.is_zero(), "1 the level is appended at (k+1)L - 1 and the sums reset");
    // 4 yes == 3 all: carriers work 1 with no ballot + one carried work 3 yes ballot per position
    auto eq = [](std::uint64_t x) {
        std::vector<pb::RatchetPlacement> v{{1, 0}, {3, 1}};
        (void)x;
        return v;
    };
    check(level_after_window({}, 0, eq) == 1, "1 4 x yes == 3 x all locks in (carried receipts count at placement)");
    auto below = [](std::uint64_t x) {
        std::vector<pb::RatchetPlacement> v{{1, 0}, {x == 7 ? 2u : 3u, 1}};
        return v;
    };
    check(level_after_window({}, 0, below) == 0, "1 one credited unit below fails");
    auto empty = [](std::uint64_t) { return std::vector<pb::RatchetPlacement>{{0, 1}}; };
    check(level_after_window({}, 0, empty) == 0, "1 an empty window (all work 0) never locks in");
    auto noballot = [](std::uint64_t x) {
        std::vector<pb::RatchetPlacement> v{{1, x % 4 == 0 ? std::uint16_t{1} : std::uint16_t{0}}};
        return v;
    };
    check(level_after_window({}, 0, noballot) == 0, "1 work without a yes ballot counts as no");
    auto dead = [](std::uint64_t x) {
        std::vector<pb::RatchetPlacement> v{{1, x < kYesLock - 1 ? std::uint16_t{1} : std::uint16_t{0}}, {0, 1}};
        return v;
    };
    check(level_after_window({}, 0, dead) == 0, "1 a LEGALLY DEAD receipt adds 0 (26,160 yes + dead yes: no lock-in)");
    // the grid is global: a window is [kL, (k+1)L) from lane genesis whatever the attempt
    check(pb::window_in_range(P, vote(P, 1, kR1, 3 * L), 3) && !pb::window_in_range(P, vote(P, 1, kR1, 3 * L), 2)
              && !pb::window_in_range(P, vote(P, 1, kR1, 3 * L), 3 + NW),
          "1 attempt windows are grid windows [S, S + N_W L)");
}

void grace_and_failure() {
    // window 0 at 70 % (fails), window 1 at 75 %: H_act from window 1, the failed window does not move it
    Sim sim(P);
    Node U("U", release({vote(P, 1, kR1, 0)})), N("N", release({}));
    sim.nodes = {&U, &N};
    const std::uint64_t seventy = (7 * L) / 10;
    const std::uint64_t h_act = pb::window_h_act(P, 1);
    sim.run(U, h_act + 1, [&](std::uint64_t x) { return (x / L == 0 && x % L < seventy) || (x / L == 1 && x % L < kYesLock); });
    check(U.ar.rows().size() == 1 && U.ar.rows()[0].h_act == h_act && N.first_hold == std::optional<std::uint64_t>(h_act),
          "2 GRACE counted from h_L of the locking window; the failed window before it does not move H_act");

    // windows 0..25 STARTED, FAILED at S + 906,906, the tail: 70 % in 0..25, 76 % of upgraded work in window 26
    Sim t(P);
    Node A("A", release({vote(P, 1, kR1, 0)})), Z("Z", release({}));
    t.nodes = {&A, &Z};
    const pb::Deployment& d = *pb::own_attempt(A.T, 1);
    check(d.timeout == 906906, "2 timeout = S + 26 L = 906,906");
    bool started = true;
    t.run_ballots(A, d.timeout, [&](std::uint64_t x) -> std::optional<std::uint16_t> {
        started = started && pb::step(P, A.S, x, A.T, d) == pb::DeploymentState::Started;
        return x % L < seventy ? std::nullopt : std::optional<std::uint16_t>(pb::make_ballot(0, false));
    });
    check(started, "2 windows 0..25 STARTED");
    check(pb::step(P, A.S, d.timeout, A.T, d) == pb::DeploymentState::Failed, "2 FAILED at timeout");
    std::uint64_t yes_after = 0;
    const std::uint64_t seventy6 = (76 * L) / 100;
    t.run_ballots(A, d.timeout + L + 10, [&](std::uint64_t x) -> std::optional<std::uint16_t> {
        // 76 % of the work comes from upgraded nodes: their ballot is the writer's default
        const pb::BallotChoice c = pb::ballot_to_write(P, A.S, x, A.T, std::optional<std::uint32_t>(1), false);
        if (pb::ballot_epoch(c.ballot) >= 1) ++yes_after;
        return (x % L) < seventy6 ? std::optional<std::uint16_t>(c.ballot) : std::optional<std::uint16_t>(pb::make_ballot(0, false));
    });
    check(yes_after == 0, "2 tail: no yes ballot after timeout, a stated vote=1 is written as the default");
    check(A.S.levels.back() == 0 && Z.first_hold == std::nullopt && Z.strikes == 0 && A.strikes == 0,
          "2 tail: window 26 level 0, the node without e keeps building (no HOLD)");
    check(pb::step(P, A.S, t.pos, A.T, d) == pb::DeploymentState::Failed && !pb::open(P, A.S, t.pos, A.T)
              && !pb::locked(P, A.S, t.pos, A.T),
          "2 after timeout the attempt never opens or locks again");
}

void step1_vectors() {
    pb::RatchetState s = pb::genesis_ratchet_state(kG);
    s.epoch_cur = 0;
    s.all = pb::RsWork(100);
    s.y1 = pb::RsWork(80);
    s.y2 = pb::RsWork(30);
    s.levels = {0, 1, 2, 1};
    const pb::RatchetPlacement pl[2] = {{5, 1}, {7, 3}};
    const pb::RatchetState a = pb::rs_step(P, s, 10, pl, true, kR1);
    // step 1: epoch 1, rules_cur kR1, y1 <- y2 (30), y2 <- 0, J -> {0,0,1,0}; then the loop at above = 2:
    // all += 12; ballot 1 < 2: no; ballot 3 >= 2: y1 += 7; ballot 3 >= 3: y2 += 7
    check(a.epoch_cur == 1 && a.rules_cur == kR1, "3 step 1: epoch_cur += 1, rules_cur <- act_digest");
    check(a.y1 == pb::RsWork(37) && a.y2 == pb::RsWork(7) && a.all == pb::RsWork(112),
          "3 step 1 before the placement loop: y1 <- y2, y2 <- 0, then the loop with the raised epoch_cur");
    check((a.levels == std::array<std::uint8_t, 4>{0, 0, 1, 0}), "3 step 1: J[i] <- max(J[i] - 1, 0)");
    // act = false is the S1 rs_step byte for byte
    Rng rng(41);
    bool same = true;
    for (int i = 0; i < 2000; ++i) {
        pb::RatchetState r = s;
        r.all = pb::RsWork(rng.next() >> 8);
        r.y1 = pb::RsWork(rng.next() >> 10);
        r.levels = {std::uint8_t(rng.next() % 3), std::uint8_t(rng.next() % 3), std::uint8_t(rng.next() % 3), std::uint8_t(rng.next() % 3)};
        const std::uint64_t x = rng.next() % (40 * L);
        const pb::RatchetPlacement q{rng.next() % 1000, std::uint16_t(rng.next())};
        same = same && pb::encode_ratchet_state(pb::rs_step(P, r, x, std::span<const pb::RatchetPlacement>(&q, 1), false, kR2))
                               == pb::encode_ratchet_state(pb::rs_step(P, r, x, std::span<const pb::RatchetPlacement>(&q, 1)));
    }
    check(same, "3 act = false reproduces the S1 rs_step byte for byte (2,000 vectors)");
    // a second activation re-bases again
    const pb::RatchetState b = pb::rs_step(P, a, 11, {}, true, kQ2);
    check(b.epoch_cur == 2 && b.rules_cur == kQ2 && b.y1 == pb::RsWork(7) && b.y2.is_zero() && (b.levels == std::array<std::uint8_t, 4>{0, 0, 0, 0}),
          "3 a second activation re-bases again");
}

void rewind_across_hl() {
    Sim sim(P);
    sim.keep_chain = true;
    Node U("U", release({vote(P, 1, kR1, 0)}), 4608), N("N", release({}), 4608);
    sim.nodes = {&U, &N};
    const std::uint64_t h_l = L - 1;
    sim.run(U, h_l + 3, [](std::uint64_t x) { return x % L < kYesLock; });
    const std::uint64_t hh_before = N.hold_at(P);
    check(hh_before == pb::window_h_act(P, 0), "4 lock-in seen at h_L");
    // remove the last position of the lock-in window, then restore it
    check(sim.rewind(h_l - 1), "4 rewind across h_L");
    check(N.hold_at(P) == pb::kNoHold && N.S.levels.back() == 0, "4 the rewind removes the lock-in");
    sim.run(U, h_l + 3, [](std::uint64_t x) { return x % L < kYesLock; });
    const std::vector<pb::RatchetState> re = sim.replay(U.T);
    check(N.hold_at(P) == hh_before && U.S == re.back() && N.S == re.back()
              && pb::step(P, U.S, U.h, U.T, *pb::own_attempt(U.T, 1)) == pb::DeploymentState::LockedIn,
          "4 H_act, every label and rs_root equal the values recomputed from genesis");
}

void junk_and_supermajority() {
    // 10^5 junk receipts in window 0 covering every u16 ballot value, far below 3/4 of the window's work
    const std::uint64_t kJunk = 100000;
    const std::uint64_t carrier_work = 100;
    auto run_case = [&](bool junk) {
        Sim sim(P);
        Node U("U", release({vote(P, 1, kR1, 0)})), N("N", release({}));
        sim.nodes = {&U, &N};
        std::uint64_t placed = 0;
        bool size_ok = true;
        while (sim.pos < pb::window_h_act(P, 0) + 2) {
            const std::uint64_t x = sim.pos;
            std::vector<Placed> extra;
            if (junk && x < L)
                while (placed < kJunk && placed * L < (x + 1) * kJunk) {
                    extra.push_back(Placed{1, static_cast<std::uint16_t>(placed)});
                    ++placed;
                }
            const bool yes = x / L == 0 && x % L < kYesLock;
            sim.extend(U, yes ? std::nullopt : std::optional<std::uint16_t>(pb::make_ballot(U.S.epoch_cur, false)), carrier_work, extra);
            size_ok = size_ok && pb::encode_ratchet_state(N.S).size() == 134;
        }
        return std::make_tuple(N.first_hold.value_or(0), placed, size_ok, N.strikes + U.strikes);
    };
    const auto [h0, p0, ok0, st0] = run_case(false);
    const auto [h1, p1, ok1, st1] = run_case(true);
    check(p1 == kJunk && ok1 && ok0 && pb::rs_layout::kSize == 134, "5 10^5 junk receipts (every u16 ballot value): S stays 134 B");
    check(h0 == pb::window_h_act(P, 0) && h1 == h0 && st0 == 0 && st1 == 0, "5 the honest HOLD happens at the same position with the junk added");
    // junk alone (no honest yes): no HOLD
    {
        Sim sim(P);
        Node N("N", release({}));
        sim.nodes = {&N};
        std::uint64_t placed = 0;
        while (sim.pos < 2 * L) {
            const std::uint64_t x = sim.pos;
            std::vector<Placed> extra;
            if (x < L)
                while (placed < kJunk && placed * L < (x + 1) * kJunk) extra.push_back(Placed{1, static_cast<std::uint16_t>(placed++)});
            sim.extend(N, pb::make_ballot(0, false), carrier_work, extra);
        }
        check(N.first_hold == std::nullopt && N.hold_at(P) == pb::kNoHold, "5 junk ballots alone: no HOLD");
    }
    // supermajority for an epoch no release implements: every node HOLDs at the same position
    Sim sim(P);
    Node A("A", release({})), B("B", release({}));
    sim.nodes = {&A, &B};
    const bool ran = sim.run_ballots(A, pb::window_h_act(P, 0) + 1, [](std::uint64_t x) -> std::optional<std::uint16_t> {
        return pb::make_ballot(x / L == 0 && x % L < kYesLock ? 1 : 0, false);
    });
    check(!ran && A.held(P) && B.held(P) && A.h == pb::window_h_act(P, 0) && B.h == A.h && A.S.epoch_cur == 0 && A.strikes + B.strikes == 0,
          "5 supermajority for an unpublished epoch: every node HOLDs at H_act - 1 (the intended stop)");
}

void startup_checks() {
    using pb::LaneNet;
    auto ok = [](const pb::EpochTable& T, LaneNet n = LaneNet::Mainnet, pb::RatchetParams p = P) {
        return pb::deployment_table_valid(p, n, T).ok;
    };
    check(ok(release({})) && ok(release({vote(P, 1, kR1, 0)})) && ok(release({vote(P, 1, kR1, 0), vote(P, 2, kQ2, 30 * L)})),
          "6 valid tables accepted");
    check(!ok(release({vote(P, 1, kR1, 0), vote(P, 1, kR2, 10 * L)})), "6 two overlapping kind-1 ranges refused");
    check(!ok(release({vote(P, 1, kR1, 7)})), "6 a start not a multiple of L refused");
    pb::Deployment badto = vote(P, 1, kR1, 0);
    badto.timeout += 1;
    check(!ok(release({badto})), "6 a timeout other than start + N_W L refused");
    check(!ok(release({vote(P, 1, kR1, 0), vote(P, 2, kQ2, 29 * L)})), "6 start(e + 1) < timeout(e) + GRACE refused");
    check(ok(release({vote(P, 1, kR1, 0), vote(P, 2, kQ2, 30 * L)})), "6 start(e + 1) at the first multiple of L >= timeout(e) + GRACE accepted");
    check(!ok(release({}), LaneNet::Regtest, pb::RatchetParams{5, 21, 50}) && ok(release({}), LaneNet::Regtest, pb::RatchetParams{5, 20, 50}),
          "6 regtest W_R = floor((GRACE - 1) / L) + 1 > 4 refused");
    check(!ok(release({vote(P, 2, kQ2, 0)})), "6 epoch numbers start at 1");
    // regtest W_R = 2 (L 5, GRACE 6): only the newest W_R slots of S are kept windows
    {
        const pb::RatchetParams rp{5, 6, 50};
        pb::RatchetState s = pb::genesis_ratchet_state(kG);
        s.levels = {1, 0, 0, 1};  // at x = 40 the slots are windows 4..7; windows 6 and 7 are kept
        const pb::EpochTable T = release({vote(rp, 1, kR1, 0)});
        check(pb::ratchet_kept_windows(rp) == 2 && pb::locked(rp, s, 40, T) && pb::h_act(rp, s, 40, T) == std::optional<std::uint64_t>(45),
              "6 regtest W_R 2: the lock-in window is the earliest of the kept (newest W_R) windows");
        check(pb::h_hold(rp, s, 40, release({})) == 45, "6 regtest W_R 2: H_hold from the kept windows only");
    }
    pb::Deployment big = vote(P, 1, kR1, 0);
    big.epoch_no = pb::kEpochMax + 1;
    check(!ok(release({big})), "6 epoch_no above 2^15 - 1 refused");
    // F3: a re-proposal of e before timeout(a) + GRACE of an earlier attempt a
    check(!ok(release({vote(P, 1, kR1, 0), vote(P, 1, kR2, 29 * L)})), "6 F3: re-proposal before timeout(a) + GRACE refused");
    check(ok(release({vote(P, 1, kR1, 0), vote(P, 1, kR2, 30 * L)})), "6 F3: re-proposal at the first multiple of L >= timeout(a) + GRACE accepted");
    check(!ok(release({vote(P, 1, kR1, 0), vote(P, 1, kR2, 30 * L), vote(P, 1, dg(0xd1), 57 * L)})),
          "6 F3: every earlier attempt counts (third attempt before timeout(second) + GRACE)");
}

// The chain of 8: release A's attempt of 1 fails in windows 0..25 (70 %), B
// re-proposes 1 from 30 L and 80 % runs B: lock-in in window 30.
struct Reprop {
    std::uint64_t h = 0;
};

void failure_and_reproposal() {
    const std::uint64_t S_B = 30 * L;
    const std::uint64_t H = pb::window_h_act(P, 30);
    const std::uint64_t seventy = (7 * L) / 10;
    const std::uint64_t eighty = (8 * L) / 10;
    Sim sim(P);
    Node B("B", release({vote(P, 1, kR1, 0), vote(P, 1, kR2, S_B)}));
    Node A("A", release({vote(P, 1, kR1, 0)}));
    Node P0("P0", release({}));
    Node R("R", release({vote(P, 1, kR1, 0), vote(P, 2, kQ2, 56 * L)}));
    check(pb::deployment_table_valid(P, pb::LaneNet::Mainnet, B.T).ok && pb::deployment_table_valid(P, pb::LaneNet::Mainnet, R.T).ok,
          "8 B (S_B = S_A + 26 L + GRACE rounded up to 30 L) and R (start(e+1) = timeout(e) + 30 L) are valid tables");
    sim.nodes = {&B, &A, &P0, &R};
    Node Rj("Rj", R.T);
    bool dec_agree = true;
    bool all_zero_at_SB = false;
    std::optional<pb::RatchetState> s_before;
    const bool ran = sim.run_ballots(B, H + 3, [&](std::uint64_t x) -> std::optional<std::uint16_t> {
        if (x == S_B) all_zero_at_SB = B.S.all.is_zero() && B.S.y1.is_zero() && B.S.y2.is_zero();
        if (x == S_B + 10) s_before = B.S;
        if (x == 31 * L) {  // an R joiner with p0 before H_act
            Rj.S = R.S;
            Rj.h = R.h;
            Rj.ar.seed_joiner(R.S, R.h);
            sim.nodes.push_back(&Rj);
        }
        if (x > 31 * L && Rj.h == R.h && Rj.h == x) {
            dec_agree = dec_agree && pb::e_impl(P, Rj.S, x, Rj.T).value == pb::e_impl(P, R.S, x, R.T).value
                        && pb::h_hold(P, Rj.S, x, Rj.T) == pb::h_hold(P, R.S, x, R.T)
                        && pb::ballot_to_write(P, Rj.S, x, Rj.T, std::nullopt, false) == pb::ballot_to_write(P, R.S, x, R.T, std::nullopt, false);
            for (const pb::Deployment& d : R.T.attempts)
                if (pb::own_attempt(R.T, d.epoch_no) == &d)
                    dec_agree = dec_agree && pb::step(P, Rj.S, x, Rj.T, d) == pb::step(P, R.S, x, R.T, d)
                                && pb::h_act(P, Rj.S, x, Rj.T) == pb::h_act(P, R.S, x, R.T);
        }
        if (x < NW * L) return pb::make_ballot(x % L < seventy ? 1 : 0, false);
        if (x / L == 30) return x % L < eighty ? std::nullopt : std::optional<std::uint16_t>(pb::make_ballot(0, false));
        return pb::make_ballot(0, false);
    });
    check(ran && B.S.epoch_cur == 1 && B.S.rules_cur == kR2 && B.ar.rows().size() == 1 && B.ar.rows()[0].h_act == H,
          "8 R5-B1: e activates on B at h_L + GRACE with B's digest");
    check(A.first_hold == std::optional<std::uint64_t>(H) && P0.first_hold == A.first_hold,
          "8 R5-B1: an A node (its e FAILED) and a pre-A node HOLD at h_L + GRACE - 1");
    check(A.strikes + P0.strikes + R.strikes + B.strikes == 0, "8 R5-B1: nobody diverges (no strike)");
    check(all_zero_at_SB, "8 R5-B1: B's first window sums start from zero");
    // an A joiner arriving after e activated under B adopts rules_cur = B's digest and HOLDs at once
    Node Aj("Aj", A.T);
    Aj.S = B.S;
    Aj.h = B.h;
    check(pb::e_impl(P, Aj.S, Aj.h, Aj.T).below && Aj.held(P), "8 R5-B1: an A joiner after H_act HOLDs at once");
    // R6-M1: R's E_impl stays e - 1 (the prefix rule), R holds at H_act - 1, strikes nothing, S equal to the majority's
    check(R.first_hold == std::optional<std::uint64_t>(H) && R.strikes == 0, "8 R6-M1: R HOLDs at exactly H_act - 1 and strikes nothing");
    check(pb::e_impl(P, R.S, R.h, R.T).value == 0 && !pb::e_impl(P, R.S, R.h, R.T).below,
          "8 R6-M1: R's E_impl stays e - 1 (e + 1 does not count past the not-implemented e)");
    const auto bj = B.journal_state(H - 1);
    check(bj.has_value() && R.S == *bj, "8 R6-M1: R's S equals the majority's at the last position R judges");
    // R6-M2: an R joiner with p0 before H_act agrees with the R follower and holds at H_act - 1
    check(dec_agree && Rj.first_hold == R.first_hold, "8 R6-M2: an R joiner with p0 before H_act derives the follower's Dec and holds at H_act - 1");
    Node Rlate("Rlate", R.T);
    Rlate.S = B.S;
    Rlate.h = B.h;
    check(Rlate.held(P) && pb::e_impl(P, Rlate.S, Rlate.h, Rlate.T).below, "8 R6-M2: an R joiner with p0 after H_act HOLDs at once");
    // predecessor digest (R6-m3): another release's attempt of e - 1 (B's kR2) activated before S_e of R's own attempt of e
    const pb::EpochTable Rp = release({vote(P, 1, kR1, 0), vote(P, 2, kQ2, 35 * L)});
    const std::uint64_t x2 = 35 * L + 5;
    check(!pb::open(P, B.S, x2, Rp) && pb::ballot_to_write(P, B.S, x2, Rp, std::nullopt, false).ballot == pb::make_ballot(1, false)
              && pb::e_impl(P, B.S, x2, Rp).below && pb::h_hold(P, B.S, x2, Rp) == x2,
          "7 predecessor digest: R's attempt of e never opens, no yes ballot for e, HOLD at once");
    check(pb::step(P, B.S, x2, Rp, *pb::own_attempt(Rp, 2)) == pb::DeploymentState::Waiting,
          "7 predecessor not in force: WAITING while e = epoch_cur + 1 and ~base");
    // predecessor not in force: R's attempt of 2 while epoch 1 is not active (e > epoch_cur + 1): FAILED, never STARTED
    bool never_started = s_before.has_value();
    for (std::uint64_t x : {35 * L, 40 * L, 60 * L})
        never_started = never_started && pb::step(P, *s_before, x, Rp, *pb::own_attempt(Rp, 2)) == pb::DeploymentState::Failed
                        && pb::ballot_epoch(pb::ballot_to_write(P, *s_before, x, Rp, std::nullopt, false).ballot) == 0;
    check(never_started, "7 predecessor not in force: FAILED while e > epoch_cur + 1, never STARTED, no yes ballot");
}

void same_digest_reproposal() {
    const std::uint64_t S_B = 30 * L;
    const std::uint64_t H = pb::window_h_act(P, 30);
    Sim sim(P);
    Node B("B", release({vote(P, 1, kR1, 0), vote(P, 1, kR1, S_B)}));  // same digest as R's
    Node R("R", release({vote(P, 1, kR1, 0)}));
    sim.nodes = {&B, &R};
    const bool ran = sim.run_ballots(B, H + 50, [&](std::uint64_t x) -> std::optional<std::uint16_t> {
        if (x / L == 30) return x % L < kYesLock ? std::nullopt : std::optional<std::uint16_t>(pb::make_ballot(0, false));
        return pb::make_ballot(B.S.epoch_cur, false);
    });
    check(ran && B.S.epoch_cur == 1 && B.S.rules_cur == kR1, "8 R6-m1: B's same-digest re-proposal activates");
    check(R.first_hold == std::optional<std::uint64_t>(H) && R.strikes == 0, "8 R6-m1: an R follower HOLDs at H_act - 1 (it did not implement B's attempt)");
    // an R joiner / resynced R node starting after H_act runs: the rules in force are R's own
    Sim s2(P);
    s2.pos = sim.pos;
    Node Rj("Rj", R.T);
    Rj.S = B.S;
    Rj.h = B.h;
    s2.nodes = {&B, &Rj};
    s2.run(B, sim.pos + 500, [](std::uint64_t) { return false; });
    check(!pb::e_impl(P, Rj.S, Rj.h, Rj.T).below && Rj.first_hold == std::nullopt && Rj.strikes == 0 && Rj.S == B.S,
          "8 R6-m1: an R joiner starting after H_act runs and strikes no honest carrier");
}

void layout_mt() {
    // R1: 1 at 0 (fails); R2: 1 re-proposed at 30 L with R1's digest; R1b: 1 at 0 and 2 at 30 L;
    // R3: 1 at 30 L (same digest) and 2 at CeilL(timeout(R1b's 2) + GRACE) = 60 L.
    const pb::EpochTable T2 = release({vote(P, 1, kR1, 0), vote(P, 1, kR1, 30 * L)});
    const pb::EpochTable T1b = release({vote(P, 1, kR1, 0), vote(P, 2, kQ2, 30 * L)});
    // R3 records R1's and R2's attempts of 1 and its own attempt of 2 (as the model's R3; recording R1b's attempt of 2,
    // which started before R2's attempt of 1 timed out, would fail the K30h check against the last attempt of 1)
    const pb::EpochTable T3 = release({vote(P, 1, kR1, 0), vote(P, 1, kR1, 30 * L), vote(P, 2, kQ3, 60 * L)});
    check(pb::deployment_table_valid(P, pb::LaneNet::Mainnet, T2).ok && pb::deployment_table_valid(P, pb::LaneNet::Mainnet, T1b).ok
              && pb::deployment_table_valid(P, pb::LaneNet::Mainnet, T3).ok,
          "8 MT: the three tables pass the start-up checks (R3 carries R1b's attempt of 2)");
    const std::uint64_t H1 = pb::window_h_act(P, 30);
    const std::uint64_t H2 = pb::window_h_act(P, 55);  // the last window of R1b's attempt of 2: [55 L, 56 L)
    Sim sim(P);
    Node N2("R2", T2), N3("R3", T3);
    sim.nodes = {&N2, &N3};
    // R2 builds through the activation of 1 (same digest re-proposal, lock-in in window 30)
    bool ran = sim.run_ballots(N2, H1 + 10, [&](std::uint64_t x) -> std::optional<std::uint16_t> {
        return x / L == 30 && x % L < kYesLock ? std::nullopt : std::optional<std::uint16_t>(pb::make_ballot(N2.S.epoch_cur, false));
    });
    check(ran && N2.S.epoch_cur == 1 && N3.S.epoch_cur == 1, "8 MT: the same-digest re-proposal of 1 activates");
    // a joiner of R1b arrives and revives its attempt of 2 (base holds: the rules in force are R1b's digest)
    Node J1b("J1b", T1b);
    J1b.S = N2.S;
    J1b.h = N2.h;
    J1b.ar.seed_joiner(N2.S, N2.h);
    sim.nodes.push_back(&J1b);
    check(pb::step(P, J1b.S, J1b.h, J1b.T, *pb::own_attempt(J1b.T, 2)) == pb::DeploymentState::Started,
          "8 MT: R1b's attempt of 2 revives (STARTED)");
    ran = sim.run_ballots(J1b, H2 + 3, [&](std::uint64_t x) -> std::optional<std::uint16_t> {
        return x / L == 55 && x % L < kYesLock ? std::nullopt : std::optional<std::uint16_t>(pb::make_ballot(J1b.S.epoch_cur, false));
    });
    check(ran && J1b.S.epoch_cur == 2 && J1b.ar.rows().back().h_act == H2, "8 MT: the joiner locks 2 in in its last window and activates at H_act");
    check(N3.first_hold == std::optional<std::uint64_t>(H2) && N2.first_hold == N3.first_hold,
          "8 MT: R3 (re-proposing 2 from timeout + GRACE) and R2 hold at H_act - 1");
    check(N2.strikes + N3.strikes + J1b.strikes == 0, "8 MT: nobody forks");
}

}  // namespace

int main() {
    tally();
    grace_and_failure();
    step1_vectors();
    rewind_across_hl();
    junk_and_supermajority();
    startup_checks();
    failure_and_reproposal();
    same_digest_reproposal();
    layout_mt();
    return finish("xmr_epoch_tally_kat");
}
