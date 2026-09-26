// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_epoch_rule_kat -- LANE-EPOCH (E1): the chain-data rule
// (xmr/xmr_lane_epoch.hpp) over synthetic chain views, D_conf 10, N 40.
//
//   a FALSE START   30 epoch-0 lane blocks, 40+ silent heights, an opener:
//                   valid; the view moves to epoch 1; an epoch-0 block above
//                   it is STALE; the unresolvable epoch-0 blocks below it are
//                   decided "epoch-closed" (never held), a live lineage's are not.
//   b TOO EARLY     the same opener at last + 39 is INVALID, at last + 40 valid.
//   c SHAPE         wrong parent / non-empty root / no cut -> invalid; seq + 2,
//                   an unknown version, a malformed field -> UNKNOWN + fuse.
//   d NO SPLIT (M3) a holder view (origin just below the lineage) and a fresh
//                   view (origin at 1) of the SAME chain: identical verdicts,
//                   opener, state and builder plan (the plan's "holds" input
//                   changes only continue-vs-wait, never the opener).
//   e BOTH LIVE     two builders alternating lane blocks every <= 20 heights
//                   for 400 heights: no height plans an opener, an injected
//                   opener is invalid everywhere.
//   f REORG         a re-delivered epoch-0 block below the opener (put) turns
//                   the opener invalid; truncate_above undoes an orphaned opener.
//   g TWO OPENERS   a second seq-1 block with the same parent is same-epoch.
// ---------------------------------------------------------------------------
#include <cstdio>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/xmr_lane_epoch.hpp"

namespace ep     = c2pool::v37n::xmr::epoch;
namespace credit = c2pool::v37n::xmr::credit;
using bytes32 = ::v37::bytes32;

namespace {
int g_fail = 0, g_pass = 0;
void check(bool ok, const std::string& what) {
    if (ok) { ++g_pass; std::printf("  ok   %s\n", what.c_str()); }
    else    { ++g_fail; std::printf("  FAIL %s\n", what.c_str()); }
}
bytes32 b32(std::uint64_t tag, std::uint8_t dom) {
    bytes32 b{}; b[0] = dom;
    for (int i = 0; i < 8; ++i) b[1 + i] = static_cast<std::uint8_t>(tag >> (8 * i));
    return b;
}
const bytes32 kEmpty = b32(0, 0xEE);
constexpr std::uint64_t kN = 40;

ep::ChainFact plain(std::uint64_t h) { ep::ChainFact c; c.h = h; c.bid = b32(h, 0xB0); return c; }
ep::ChainFact lane(std::uint64_t h, std::uint32_t seq, const bytes32& parent, const bytes32& root, bool field = true) {
    ep::ChainFact c = plain(h);
    c.own = true; c.has_root = true; c.root = root; c.has_cut = true;
    if (field) { c.ep = credit::EpochParse::Present; c.f = credit::EpochField{seq, ep::kEpochRuleVersion, parent}; }
    return c;
}
bytes32 root_of(std::uint64_t h) { return b32(h, 0x77); }

// the false-start chain: epoch-0 lane blocks at 1001..1030 (no V37E: pre-flip
// shape reads as seq 0), plain blocks up to `tip`
ep::EpochView chain_view(std::uint64_t origin, std::uint64_t tip) {
    ep::EpochView v(kN, kEmpty);
    v.set_origin(origin);
    for (std::uint64_t h = origin; h <= tip; ++h)
        (void)v.put(h >= 1001 && h <= 1030 ? lane(h, 0, bytes32{}, root_of(h), h % 2 == 0) : plain(h));
    return v;
}
bytes32 parent_after_1030() { return ep::parent_digest(0, b32(1030, 0xB0), root_of(1030)); }

void suite_a() {
    std::printf("-- a: FALSE START --\n");
    ep::EpochView v = chain_view(900, 1070);
    const auto p = v.plan(1071, /*holds=*/false);
    check(p.mode == ep::EpochView::Plan::Mode::Open && p.f.seq == 1 && p.f.parent == parent_after_1030(),
          "plan at h=1071 (41 silent heights) = OPEN seq 1 with parent(0, bid1030, root1030): " + p.why);
    (void)v.put(lane(1071, 1, parent_after_1030(), kEmpty));
    const auto d = v.decide(1071);
    check(d.v == ep::Verdict::Opener, std::string("opener at 1071 -> ") + ep::to_string(d.v) + " " + d.why);
    for (std::uint64_t h = 1072; h <= 1080; ++h) (void)v.put(plain(h));
    (void)v.put(lane(1081, 0, bytes32{}, root_of(1081)));
    const auto ds = v.decide(1081);
    check(ds.v == ep::Verdict::Stale && ep::decided_why(ds).value_or("").rfind("epoch-stale:", 0) == 0,
          std::string("epoch-0 block above the opener -> ") + ep::to_string(ds.v) + " (" + ep::decided_why(ds).value_or("-") + ")");
    const ep::State s = v.state_before(1082);
    check(s.cur_seq == 1 && s.opened && s.open_h == 1071 && s.last_h == 1071, "state: cur_seq 1, open_h 1071, last lane 1071 (stale block not counted)");
    int closed = 0;
    for (std::uint64_t h = 1001; h <= 1030; ++h) {
        const auto dd = v.decide(h);
        if (dd.v != ep::Verdict::SameEpoch) continue;
        const auto w = ep::undecided_to_decided(v, dd, "lane-root-unknown: 03 root matches none");
        if (w && w->rfind("epoch-closed:", 0) == 0) ++closed;
    }
    check(closed == 30, "30/30 unresolvable epoch-0 blocks below the opener -> epoch-closed (never HELD), got " + std::to_string(closed));
    // before the opener exists, with the lineage DEAD at the frontier: epoch-dead
    ep::EpochView w = chain_view(900, 1070);
    const auto dw = ep::undecided_to_decided(w, w.decide(1015), "cut-pending: relay repair of P=3 (no connected peer serves that order yet)");
    check(dw && dw->rfind("epoch-dead:", 0) == 0, "dead lineage, no opener yet: an unresolvable block -> " + dw.value_or("nullopt"));
    // a LIVE lineage (frontier 1060 < 1030 + N): stays undecided (retry / hold / bootstrap)
    ep::EpochView l = chain_view(900, 1060);
    check(!ep::undecided_to_decided(l, l.decide(1015), "lane-root-unknown: x").has_value(),
          "live lineage (30 silent < N): the unresolvable block is NOT decided (bootstrap / hold, as today)");
    check(l.plan(1061, false).mode == ep::EpochView::Plan::Mode::Wait, "live lineage, history not held: plan WAIT (" + l.plan(1061, false).why + ")");
    check(l.plan(1061, true).mode == ep::EpochView::Plan::Mode::Continue && l.plan(1061, true).f.seq == 0,
          "live lineage, history held: plan CONTINUE epoch 0");
    // a booked block is untouched
    check(!ep::undecided_to_decided(v, v.decide(1015), "booked").has_value(), "a non-undecided outcome is never reclassified");
}

void suite_b() {
    std::printf("-- b: TOO EARLY --\n");
    for (std::uint64_t off : {39ull, 40ull}) {
        ep::EpochView v = chain_view(900, 1030 + off - 1);
        (void)v.put(lane(1030 + off, 1, parent_after_1030(), kEmpty));
        const auto d = v.decide(1030 + off);
        const bool want = off >= kN;
        check((d.v == ep::Verdict::Opener) == want, "opener at last+" + std::to_string(off) + " -> " + ep::to_string(d.v) + " " + d.why);
        check((v.plan(1030 + off, false).mode == ep::EpochView::Plan::Mode::Open) == want,
              "builder plan at last+" + std::to_string(off) + " -> " + ep::EpochView::to_string(v.plan(1030 + off, false).mode));
    }
}

void suite_c() {
    std::printf("-- c: SHAPE --\n");
    auto one = [&](ep::ChainFact c, ep::Verdict want, bool fuse, const char* what) {
        ep::EpochView v = chain_view(900, 1070);
        c.h = 1071; c.bid = b32(1071, 0xB0);
        (void)v.put(c);
        const auto d = v.decide(1071);
        check(d.v == want && d.fuse == fuse, std::string(what) + " -> " + ep::to_string(d.v) + (d.fuse ? "+fuse" : "") + " " + d.why);
    };
    one(lane(0, 1, ep::parent_digest(0, b32(1029, 0xB0), root_of(1029)), kEmpty), ep::Verdict::InvalidOpener, false, "wrong parent (bid1029)");
    one(lane(0, 1, parent_after_1030(), root_of(5)), ep::Verdict::InvalidOpener, false, "non-empty root (E1)");
    { auto c = lane(0, 1, parent_after_1030(), kEmpty); c.has_cut = false; one(c, ep::Verdict::InvalidOpener, false, "no credit cut"); }
    one(lane(0, 3, parent_after_1030(), kEmpty), ep::Verdict::Unknown, true, "seq 3 (current 0)");
    { auto c = lane(0, 1, parent_after_1030(), kEmpty); c.f.version = 2; one(c, ep::Verdict::Unknown, true, "unknown epoch version 2"); }
    { auto c = lane(0, 1, parent_after_1030(), kEmpty); c.ep = credit::EpochParse::Malformed; one(c, ep::Verdict::Unknown, true, "malformed V37E"); }
    one(lane(0, 0, b32(1, 1), root_of(9)), ep::Verdict::Sibling, false, "seq 0 with a non-zero parent");
    // a fuse in the view -> the builder plan is FUSE
    ep::EpochView v = chain_view(900, 1040);
    (void)v.put(lane(1041, 5, bytes32{}, kEmpty));
    check(v.plan(1042, true).mode == ep::EpochView::Plan::Mode::Fuse, "an unreadable epoch in the view -> plan FUSE (lane suspended)");
}

void suite_d() {
    std::printf("-- d: NO SPLIT (holder view vs fresh view) --\n");
    ep::EpochView holder = chain_view(990, 1070), fresh = chain_view(1, 1070);
    for (auto* v : {&holder, &fresh}) {
        (void)v->put(lane(1071, 1, parent_after_1030(), kEmpty));
        for (std::uint64_t h = 1072; h <= 1100; ++h)
            (void)v->put(h % 3 == 0 ? lane(h, 1, parent_after_1030(), root_of(h)) : plain(h));
        (void)v->put(lane(1101, 0, bytes32{}, root_of(1101)));
    }
    check(holder.classification() == fresh.classification(), "verdict string equal: " + holder.classification().substr(0, 120) + " ...");
    check(holder.state_before(1102) == fresh.state_before(1102), "state after the chain equal (cur_seq, opener, last lane block)");
    const auto ph = holder.plan(1102, true), pf = fresh.plan(1102, true);
    check(ph.mode == pf.mode && ph.f == pf.f, std::string("builder plan equal: ") + ep::EpochView::to_string(ph.mode) + " seq " + std::to_string(ph.f.seq));
    ep::EpochView h2 = chain_view(990, 1070), f2 = chain_view(1, 1070);
    const auto a = h2.plan(1071, true), b = f2.plan(1071, false);
    check(a.mode == ep::EpochView::Plan::Mode::Open && b.mode == a.mode && a.f == b.f,
          "dead lineage: a holder (holds=1) and a fresh node (holds=0) plan the SAME opener");
}

void suite_e() {
    std::printf("-- e: PARTITION, BOTH SIDES LIVE --\n");
    ep::EpochView v(kN, kEmpty);
    v.set_origin(1);
    std::uint64_t next_a = 5, next_b = 12, opens = 0, invalid = 0, injected = 0;
    for (std::uint64_t h = 1; h <= 400; ++h) {
        if (v.plan(h, true).mode == ep::EpochView::Plan::Mode::Open && h > kN) ++opens;
        if (h == next_a) { (void)v.put(lane(h, 0, bytes32{}, root_of(h))); next_a += 17; }
        else if (h == next_b) { (void)v.put(lane(h, 0, bytes32{}, root_of(h + 1000))); next_b += 19; }
        else if (h % 37 == 0 && h > kN) {
            const ep::State s = v.state_before(h);
            (void)v.put(lane(h, 1, ep::parent_digest(0, s.last_bid, s.last_root), kEmpty));
            ++injected;
            if (v.decide(h).v == ep::Verdict::InvalidOpener) ++invalid;
        } else (void)v.put(plain(h));
    }
    check(opens == 0, "no height in 400 plans an opener while both builders land blocks (opens=" + std::to_string(opens) + ")");
    check(injected > 0 && invalid == injected, "every injected opener is invalid (" + std::to_string(invalid) + "/" + std::to_string(injected) + ")");
}

void suite_f() {
    std::printf("-- f: REORG < D_conf --\n");
    ep::EpochView v = chain_view(900, 1070);
    (void)v.put(lane(1071, 1, parent_after_1030(), kEmpty));
    check(v.decide(1071).v == ep::Verdict::Opener, "opener valid at 1071");
    ep::ChainFact re = lane(1066, 0, bytes32{}, root_of(1066));
    re.bid = b32(1066, 0xB7);                                 // another block at 1066 (the new branch): a different id
    (void)v.put(re);   // re-delivered on the new branch below the opener
    const auto d = v.decide(1071);
    check(d.v == ep::Verdict::InvalidOpener, std::string("an epoch-0 block re-delivered at 1066 -> the opener is ") + ep::to_string(d.v) + " " + d.why);
    check(v.decide(1066).v == ep::Verdict::SameEpoch, "the re-delivered block books as same-epoch");
    ep::EpochView w = chain_view(900, 1070);
    (void)w.put(lane(1071, 1, parent_after_1030(), kEmpty));
    for (std::uint64_t h = 1072; h <= 1075; ++h) (void)w.put(plain(h));
    w.truncate_above(1070);
    check(w.state_before(2000).cur_seq == 0, "orphaned opener (truncate_above) -> back to epoch 0 (undone like the pending set)");
}

void suite_g() {
    std::printf("-- g: TWO OPENERS --\n");
    ep::EpochView v = chain_view(900, 1070);
    (void)v.put(lane(1071, 1, parent_after_1030(), kEmpty));
    for (std::uint64_t h = 1072; h <= 1073; ++h) (void)v.put(plain(h));
    (void)v.put(lane(1074, 1, parent_after_1030(), kEmpty));
    check(v.decide(1071).v == ep::Verdict::Opener && v.decide(1074).v == ep::Verdict::SameEpoch,
          "first seq-1 block opens, the second (same parent, empty root) is same-epoch (its root: the ring + stale-root rule)");
}
} // namespace

int main() {
    std::printf("v37_xmr_epoch_rule_kat: LANE-EPOCH E1 rule, D_conf 10, N %llu\n", static_cast<unsigned long long>(kN));
    suite_a(); suite_b(); suite_c(); suite_d(); suite_e(); suite_f(); suite_g();
    std::printf("v37_xmr_epoch_rule_kat: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
