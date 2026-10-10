// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_joiner_kat (pathb_join.hpp, pathb_joiner.hpp; C43; S3.1a): the
// joiner J joins a chain built by a full node A and reaches A's lane digest at
// L and L + 200. Sections (argv[1] runs one): span (span_bounds at L'), young,
// buckets (fetch A / B at the at header, at-header claims, re-ask scope),
// afterl (the attempt server's regime, AR seed, forged top, P-50), claims
// (span claims, PRE, Boundary, one variant per id), attempts (ends, re-queue,
// L from the reply, P-51 hold, an unresolved P_r, fake and starved
// candidates), candidates (the bound-work rule, P-52, two states, own switch),
// scope (the fork with A's chain through a held side branch, no body before
// it, A's kept profile, the lost count), d1 (retarget claims), fastpool,
// ratchet (rs_step_at in the joined tree), jc1-jc5 (ruling 53: the claimed
// prefix from x_pre, d below the root a claim, the claimed view at a prefix
// fork, side bins from served buckets, no below-root best; V1-V16, V2b).
// ---------------------------------------------------------------------------
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include "pathb_kat_join.hpp"
using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;
namespace {
const std::uint64_t kJ0 = pb::admit_j0(pb::kRuledLaneParams);
const std::uint64_t kNrt = pb::join_n_rt(pb::kRuledLaneParams);           // 2,160
const std::uint64_t kSpan = pb::join_span(pb::kRuledLaneParams, 0);       // 1,176
constexpr std::uint64_t kP53 = 11;  // the abandon timeout of the KAT (a parameter; P-53's derived value)
double secs(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}
// ---------------------------------------------------------------------------
// span: span_bounds at L' (E-75; E-16 read at L'; the young chain E-69)
// ---------------------------------------------------------------------------
// The heights of a chain whose 1,176 positions before L' = L - N_rt advance v
// Monero heights (12 per height elsewhere).
HOf span_heights(std::uint64_t L, std::uint64_t v) {
    const std::uint64_t lp = L - kNrt, lo = lp - kSpan;
    const std::uint64_t h_lo = kLaneB0 + lo / 12, h_lp = h_lo + v;
    return [=](std::uint64_t x) {
        if (x <= lo) return kLaneB0 + x / 12;
        if (x <= lp) return h_lo + (x - lo) * v / kSpan;
        return h_lp + (x - lp) / 12;
    };
}

// The definitions of E-75, by brute force over a record function.
pb::SpanBounds span_reference(std::uint64_t L, const HOf& H) {
    pb::SpanBounds b;
    const std::uint64_t fr = 98;
    if (L < kNrt || H(L) < fr) return pb::SpanBounds{true, 0, 1, 1};
    std::optional<std::uint64_t> last;
    for (std::uint64_t x = 0; x <= L; ++x)
        if (H(x) <= H(L) - fr) last = x;
    if (!last) return pb::SpanBounds{true, 0, 1, 1};
    const std::uint64_t lp = std::min(L - kNrt, *last);
    std::optional<std::uint64_t> first;
    for (std::uint64_t x = 0; x <= lp && !first; ++x)
        if (H(x) > H(lp) - fr) first = x;
    const std::int64_t x0 = std::min<std::int64_t>(static_cast<std::int64_t>(lp) - 1175, static_cast<std::int64_t>(*first));
    if (x0 <= 0) return pb::SpanBounds{true, 0, 1, 1};
    std::uint64_t x1 = static_cast<std::uint64_t>(x0);
    while (H(x1) < H(static_cast<std::uint64_t>(x0) - 1) + fr) ++x1;
    b.young = false;
    b.l_prime = lp;
    b.x0 = static_cast<std::uint64_t>(x0);
    b.x1 = x1;
    return b;
}

// The P-51 header floor at x0 (ruling 53, E-102) by its definitions: the prefix start x_pre = max(1, min(x0 - N_rt,
// g)), g = the first x with H(x) > H(max(0, x0 - 1 - J_0)) - F - Fresh, with the record below it that fixes it where g
// decides (g <= x0 - N_rt, g >= 2); 0 (position 1 on) where x0 <= N_rt.
std::uint64_t header_floor_ref(std::uint64_t x0, const HOf& hof) {
    if (x0 <= kNrt) return 0;
    const auto H = [&](std::uint64_t x) { return x == 0 ? kLaneB0 : hof(x); };
    const std::uint64_t y = x0 >= 1 + kJ0 ? x0 - 1 - kJ0 : 0;
    const std::int64_t thr = static_cast<std::int64_t>(H(y)) - 98;
    std::uint64_t g = 0;
    while (static_cast<std::int64_t>(H(g)) <= thr) ++g;
    if (g > x0 - kNrt) return x0 - kNrt;
    return g >= 2 ? g - 1 : 1;
}

pb::SpanResult span_of(std::uint64_t L, const HOf& H, std::uint64_t lo = 0) {
    return pb::span_bounds(pb::kRuledLaneParams, L, [&](std::uint64_t x) -> std::optional<std::uint64_t> {
        if (x != 0 && x < lo) return std::nullopt;
        return x == 0 ? kLaneB0 : H(x);
    });
}

bool same(const pb::SpanBounds& a, const pb::SpanBounds& b) {
    return a.young == b.young && a.x0 == b.x0 && a.x1 == b.x1 && (a.young || a.l_prime == b.l_prime);
}

// The expected counters of a join of A's chain at L: bodies whose tip lies at or above x1, and below it.
std::pair<std::uint64_t, std::uint64_t> expected_counts(KatNode& a, std::uint64_t x0, std::uint64_t x1, std::uint64_t L) {
    std::uint64_t full = 0, claims = 0;
    for (std::uint64_t x = x0; x <= L; ++x) {
        const pb::CarrierBodyV3* b = a.bodies.get(at_pos(a, x));
        const std::uint64_t n = 1 + (b ? b->carried.size() : 0);
        (x - 1 >= x1 ? full : claims) += n;
    }
    return {full, claims};
}

void span() {
    // span_bounds against the definitions
    {
        const std::uint64_t L = 4700;
        for (std::uint64_t v : {90, 93, 97, 98, 104}) {
            const HOf hof = span_heights(L, v);
            const pb::SpanResult r = span_of(L, hof);
            const pb::SpanBounds ref = span_reference(L, hof);
            const std::string tag = "span bounds v=" + std::to_string(v);
            check(r.status == pb::SpanStatus::Ok && same(r.bounds, ref), tag + ": span_bounds == the definitions of E-75");
            check(hof(r.bounds.l_prime) - hof(r.bounds.l_prime - kSpan) == v, tag + ": H(L') - H(L' - 1,176) == v");
            check(r.bounds.x1 <= r.bounds.l_prime && r.bounds.l_prime <= L - kNrt, tag + ": x1 <= L' <= L - N_rt");
            check(L - r.bounds.x0 + 1 >= kNrt + kSpan, tag + ": the span holds at least N_rt + 1,176 = 3,336 positions");
            check((v < 98) == (r.bounds.x0 < r.bounds.l_prime - 1175), tag + ": the height bound takes x0 lower iff v < 98");
            // a record function holding less than the span names the position it needs
            const pb::SpanResult part = span_of(L, hof, r.bounds.x0);
            check(part.status == pb::SpanStatus::NeedRecord && part.need == r.bounds.x0 - 1,
                  tag + ": records from x0 only -> the record of x0 - 1 is named");
        }
        // the young chain: no L' (L < N_rt), x0 <= 0 at L' (L' <= 1,175), H(L') - H(0) < 98
        for (std::uint64_t L : {0, 600, 1175, 2159, 3335}) {
            const pb::SpanResult r = span_of(L, h_pos);
            check(r.status == pb::SpanStatus::Ok && r.bounds.young && r.bounds.x0 == 1 && r.bounds.x1 == 1 &&
                          same(r.bounds, span_reference(L, h_pos)),
                  "span bounds L=" + std::to_string(L) + ": the young chain, x0 = x1 = 1");
        }
        {
            const pb::SpanResult r = span_of(3336, h_pos);
            check(r.status == pb::SpanStatus::Ok && !r.bounds.young && r.bounds.x0 == 1 && r.bounds.l_prime == 1176 &&
                          same(r.bounds, span_reference(3336, h_pos)),
                  "span bounds L=3,336: the E-75 formula (no b0) gives x0 = 1 at L' = 1,176");
            // with b0 (ruling 47, E-79): x0 = 1 has no bin sealed before it (lc(H(0)) = 0): the young chain
            const pb::SpanResult y = pb::span_bounds(pb::kRuledLaneParams, 3336, [](std::uint64_t x) -> std::optional<std::uint64_t> {
                return x == 0 ? kLaneB0 : h_pos(x); }, kLaneB0);
            check(y.status == pb::SpanStatus::Ok && y.bounds.young && y.bounds.x0 == 1 && y.bounds.x1 == 1,
                  "span bounds L=3,336 with b0: x0 = 1 is the young chain, x0 = x1 = 1");
        }
        {
            const HOf slow = [](std::uint64_t x) { return kLaneB0 + x / 30; };  // H(L') - H(0) < 98
            const pb::SpanResult r = span_of(5000, slow);
            check(r.status == pb::SpanStatus::Ok && r.bounds.young && same(r.bounds, span_reference(5000, slow)),
                  "span bounds: H(L') - H(0) < F + Fresh -> the young chain");
        }
        {
            // a fast pool: H(L) - H(L - N_rt) < F + Fresh, L' taken by height below L - N_rt
            const std::uint64_t L = 6000;
            const HOf fast = [](std::uint64_t x) { return x <= 3800 ? kLaneB0 + x / 12 : kLaneB0 + 3800 / 12 + (x - 3800) / 24; };
            const pb::SpanResult r = span_of(L, fast);
            check(r.status == pb::SpanStatus::Ok && !r.bounds.young && r.bounds.l_prime < L - kNrt &&
                          same(r.bounds, span_reference(L, fast)),
                  "span bounds, fast pool: L' below L - N_rt by height");
        }
    }
    // end to end: J's lane digest == A's at L and at L + 200 for every v
    const std::uint64_t L = 4700;
    JoinNet net(900);
    for (std::uint64_t v : {90, 93, 97, 98, 104}) {
        const std::string tag = "span v=" + std::to_string(v);
        const auto t0 = std::chrono::steady_clock::now();
        KatNode a(net, kJ0);
        ChainShape shape;
        shape.hof = span_heights(L, v);
        grow(a, L + 200, shape);
        KatServer s(a, 21);
        s.top = L;
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        bool claims_during = true, ever = false;
        j.set_on_step([&](pb::JoinedState&, std::uint64_t) {
            ever = true;
            claims_during = claims_during && j.rests_on_claims();
        });
        j.offer(at_pos(a, L), s);
        const std::optional<pb::AttemptReport> r = j.run_next();
        check(r && r->end == pb::AttemptEnd::Completed, tag + ": the honest attempt completes" + (r ? ": " + rep_desc(*r) : ""));
        if (!j.adopted()) continue;
        pb::JoinedState& js = *j.adopted();
        const pb::SpanBounds ref = span_reference(L, shape.hof);
        check(js.x0 == ref.x0 && js.x1 == ref.x1 && !js.young, tag + ": the joined span is E-75's");
        check(ever && claims_during && !j.rests_on_claims(),
              tag + ": no template before L + 1 (rests_on_claims through the replay), templates from L + 1");
        const auto [full, claims] = expected_counts(a, js.x0, js.x1, L);
        check(js.full_bodies == full && js.span_claims == claims,
              tag + ": fully verified bodies " + std::to_string(js.full_bodies) + " == " + std::to_string(full) +
                      ", span claims " + std::to_string(js.span_claims) + " == " + std::to_string(claims));
        bool roots = true, wroots = true;
        for (std::uint64_t x = js.x0; x <= L; ++x) {
            const pb::Hash32 id = at_pos(a, x);
            const pb::LaneView jv = js.store->view_at(id), av = a.store.view_at(id);
            roots = roots && jv.ok() && av.ok() && jv.mmr_root() == av.mmr_root();
            if (x >= js.x1) {
                const pb::Hash32 pt = a.prev_of(id);
                const pb::TipWindow jw = pb::evaluate_window_at(*js.store, id, pt, je.mon, 16, net.author_id);
                const pb::TipWindow aw = a.window(id, 16);
                wroots = wroots && jw.ok() && aw.ok() && jw.window_root == aw.window_root;
            }
        }
        check(roots, tag + ": every span mmr_root of J == A's");
        check(wroots, tag + ": window_root of J == A's for every x >= x1");
        check(digest_of(js, at_pos(a, L)) == digest_of(a, at_pos(a, L)), tag + ": J's lane digest == A's at L");
        check(follow(js, a, L, L + 200), tag + ": J admits A's next 200 carriers (a template at L + 1 equal to A's)");
        check(digest_of(js, at_pos(a, L + 200)) == digest_of(a, at_pos(a, L + 200)),
              tag + ": J's lane digest == A's at L + 200");
        std::printf("  %s: %.1f s\n", tag.c_str(), secs(t0));
    }
}

// ---------------------------------------------------------------------------
// young: the young chain (E-69 at L', E-75 (iii)); the empty-store start
// ---------------------------------------------------------------------------
// One attempt of J at A's chain with top L; the report (and J adopted when it completed).
struct OneJoin {
    std::unique_ptr<JoinerEnv> je;
    std::unique_ptr<pb::Joiner> j;
    std::optional<pb::AttemptReport> r;
};
OneJoin join_at(const KatNet& net, KatServer& s, std::uint64_t L) {
    OneJoin o;
    o.je = std::make_unique<JoinerEnv>(net);
    o.j = std::make_unique<pb::Joiner>(o.je->in, kP53);
    s.top = L;
    o.j->offer(s.best_id(), s);
    o.r = o.j->run_next();
    return o;
}

void young() {
    JoinNet net(900);
    KatNode a(net, kJ0);
    grow(a, 3336 + 200);
    KatServer s(a, 31);
    for (std::uint64_t L : {0, 600, 1175, 3335, 3336}) {
        const std::string tag = "young L=" + std::to_string(L);
        OneJoin o = join_at(net, s, L);
        check(o.r && o.r->end == pb::AttemptEnd::Completed && o.r->span.young,
              tag + ": completes as the young chain" + (o.r ? ": " + rep_desc(*o.r) : ""));
        if (!o.j->adopted()) continue;
        pb::JoinedState& js = *o.j->adopted();
        check(js.young && js.x0 == 1 && js.x1 == 1, tag + ": x0 = x1 = 1");
        check(js.span_claims == 0 && js.claimed.empty() && js.store->first_leaf() == 0, tag + ": no claim, no adopted leaf");
        const auto [full, claims] = expected_counts(a, 1, 0, L);
        check(js.full_bodies == full && claims == 0, tag + ": every body of [1, L] checked in full (" +
                                                             std::to_string(js.full_bodies) + ")");
        check(js.ar.rows().empty() && !js.ar.joiner_p0() && a.ar.rows() == js.ar.rows(),
              tag + ": AR is the genesis AR (no rows, no joiner flag), J's == A's");
        check(js.tree->genesis().id == net.pool_id && js.store->b0() == kLaneB0 &&
                      js.tree->genesis().rs == pb::genesis_ratchet_state(net.rules_g),
              tag + ": position 0 and S_0 from the pool identity");
        check(digest_of(js, at_pos(a, L)) == digest_of(a, at_pos(a, L)), tag + ": J's lane digest == A's");
        if (L == 600 || L == 3336) {
            // a receipt whose tip is position 0 with rules_epoch 1: STRIKE on J and on A
            const pb::ReceiptBodyV3 r = body_on(a, a.tree.genesis().id, kLaneB0 + 1, 5, 7777001,
                                                [](pb::ReceiptBodyV3& b) { b.side.rules_epoch = 1; });
            const std::vector<std::uint8_t> bytes = bytes_of(r);
            const pb::AdmitResult ra = pb::admit_receipt(a.env(), bytes, pb::Role::Pending);
            pb::AdmitEnv env = js.env();
            const pb::AdmitResult rj = pb::admit_receipt(env, bytes, pb::Role::Pending);
            check(ra.verdict == pb::AdmitVerdict::Strike && ra.row == pb::RowId::R18 &&
                          rj.verdict == pb::AdmitVerdict::Strike && rj.row == pb::RowId::R18,
                  tag + ": a receipt on position 0 with rules_epoch 1 -> STRIKE on J (" + desc(rj) + ") and on A (" +
                          desc(ra) + ")");
        }
        if (L == 0) {
            check(js.tree->best().id == net.pool_id && js.store->tip_pos() == 0, tag + ": the result is position 0");
            check(follow(js, a, 0, 200) && digest_of(js, at_pos(a, 200)) == digest_of(a, at_pos(a, 200)),
                  tag + ": the empty-store start follows A to 200 with A's digest");
        }
        if (L == 3336)  // x0 = 1 at L' = 1,176 by the formula: the young chain (ruling 47, E-79)
            check(follow(js, a, 3336, 3536) && digest_of(js, at_pos(a, 3536)) == digest_of(a, at_pos(a, 3536)),
                  tag + ": J's digest == A's at L + 200");
    }
    {
        // H(L') - H(0) < F + Fresh: the raw form launched at the Monero tip
        KatNode b(net, kJ0);
        ChainShape slow;
        slow.hof = [](std::uint64_t x) { return kLaneB0 + x / 30; };
        grow(b, 5000, slow);
        KatServer sb(b, 32);
        OneJoin o = join_at(net, sb, 5000);
        check(o.r && o.r->end == pb::AttemptEnd::Completed && o.r->span.young,
              "young H(L') - H(0) < 98: the whole chain in full" + (o.r ? ": " + rep_desc(*o.r) : ""));
        if (o.j->adopted())
            check(digest_of(*o.j->adopted(), at_pos(b, 5000)) == digest_of(b, at_pos(b, 5000)) &&
                          o.j->adopted()->span_claims == 0,
                  "young H(L') - H(0) < 98: J's digest == A's, no claim");
    }
    {
        // empty store: position 0 from the identity, never from a peer. A server whose chain stands on another
        // position 0 is not joined; the honest server is.
        KatNode f(net, kJ0);
        const pb::Hash32 g2 = seq32(0xE1);
        f.tree = pb::CarrierTree(f.P, g2, kLaneB0, f.T, {}, f.RP, net.rules_g);
        f.store = pb::BinStore(f.P, kJ0, g2, kLaneB0);
        ChainShape fs;
        fs.nonce0 = 50000;
        grow(f, 700, fs);
        KatServer sf(f, 33), sh(a, 34);
        sf.top = 600;
        sh.top = 600;
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(sf.best_id(), sf);
        j.offer(sh.best_id(), sh);
        const std::optional<pb::AttemptReport> r1 = j.run_next();
        check(r1 && r1->end != pb::AttemptEnd::Completed && !j.adopted(),
              "empty store: a chain on another position 0 is not joined" + (r1 ? ": " + rep_desc(*r1) : ""));
        std::optional<pb::AttemptReport> r2;
        while (!j.adopted() && (r2 = j.run_next())) {}
        check(j.adopted() && j.adopted()->tree->genesis().id == net.pool_id &&
                      digest_of(*j.adopted(), at_pos(a, 600)) == digest_of(a, at_pos(a, 600)),
              "empty store: J with only b0, G and the identity reaches A's digest");
    }
    // ruling 47 (RULED 47 (a), E-79): the formula gives x0 >= 1 but lc(H(x0 - 1)) = 0 (no bin sealed before x0):
    // the whole chain [1, L] in full, no claim, from the genesis state, no fetch A. At 12 per height, every L in
    // [3,337, 4,487]; L = 4,488 (lc = 1) and 4,600 take the span at L'.
    {
        KatNode c(net, kJ0);
        grow(c, 4487 + 200);
        KatServer sc(c, 41);
        for (std::uint64_t L : {3337, 4000, 4487}) {
            const pb::SpanBounds fm = span_reference(L, h_pos);  // the E-75 formula (without ruling 47): x0 >= 1
            const std::uint64_t lc = pb::bin_leaf_count(h_pos(fm.x0 - 1), kLaneB0, pb::kRuledLaneParams.open_bins);
            OneJoin o = join_at(net, sc, L);
            const std::string tag = "ruling 47 L=" + std::to_string(L);
            check(!fm.young && fm.x0 > 1 && lc == 0, tag + ": the formula gives x0 = " + std::to_string(fm.x0) + " >= 2, lc(H(x0-1)) = 0");
            check(o.r && o.r->end == pb::AttemptEnd::Completed && o.r->span.young,
                  tag + ": the young path (x0 = x1 = 1, the whole chain)" + (o.r ? ": " + rep_desc(*o.r) : ""));
            check(o.j->adopted() && o.j->adopted()->span_claims == 0 && o.j->adopted()->claimed.empty() &&
                          digest_of(*o.j->adopted(), at_pos(c, L)) == digest_of(c, at_pos(c, L)),
                  tag + ": no claim, no adopted leaf, J's digest == A's");
        }
        for (std::uint64_t L : {4488, 4600}) {
            OneJoin o = join_at(net, sc, L);
            check(o.r && o.r->end == pb::AttemptEnd::Completed && !o.r->span.young && o.r->span.x0 > 1,
                  "ruling 47 L=" + std::to_string(L) + ": lc(H(x0-1)) >= 1 -> the span at L'" + (o.r ? ": " + rep_desc(*o.r) : ""));
        }
    }
    // ruling 47's record: a fast phase, 20 positions per height; the formula gives x0 >= 1 with
    // lc(H(x0 - 1)) = 0, so the young path; a server at the default P-51 retention serves it from position 1 by the
    // serving note.
    {
        KatNode d(net, kJ0);
        ChainShape fast;
        fast.hof = [](std::uint64_t x) { return kLaneB0 + x / 20; };
        grow(d, 5620 + 100, fast);
        const std::uint64_t L = 5620;
        const pb::SpanBounds fm = span_reference(L, fast.hof);
        const std::uint64_t lc = pb::bin_leaf_count(fast.hof(fm.x0 - 1), kLaneB0, pb::kRuledLaneParams.open_bins);
        KatServer sd(d, 42);
        sd.retention = true;  // the default P-51 retention: the serving note serves the young path from position 1
        sd.top = L;
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(sd.best_id(), sd);
        const std::optional<pb::AttemptReport> r = j.run_next();
        check(!fm.young && fm.x0 > 1 && lc == 0, "ruling 47 fast phase: the formula gives x0 = " + std::to_string(fm.x0) + " >= 2, lc = 0");
        check(r && r->end == pb::AttemptEnd::Completed && r->span.young && j.adopted() &&
                      digest_of(*j.adopted(), at_pos(d, L)) == digest_of(d, at_pos(d, L)),
              "ruling 47 fast phase: the young path completes at a default-retention server " + (r ? ": " + rep_desc(*r) : ""));
    }
    // the serving note of ruling 47's record (P-51): a server keeps everything from position 1 while no bin is sealed
    // at or before its body floor x0(L') - J_0 - 1 (lc(H(x0(L') - J_0 - 1)) = 0), else bodies from x0(L') - J_0 - 1 and
    // headers from the prefix start x_pre(L') with the record that fixes it (ruling 53, E-102). join_serve_floors
    // against that, for every L in [3,400, 7,000] at 12 per height; the
    // note reaches past the young chain (lc(H(x0 - 1)) >= 1: the young path of a side branch whose fork has no sealed
    // bin, E-83).
    {
        const pb::LaneParams& P = pb::kRuledLaneParams;
        const std::uint64_t j0 = pb::journal_j0(P, pb::kSealDepth);
        const auto lc = [&](std::uint64_t H) { return pb::bin_leaf_count(H, kLaneB0, P.open_bins); };
        const auto rec = [](std::uint64_t x) -> std::optional<std::uint64_t> { return x == 0 ? kLaneB0 : h_pos(x); };
        std::uint64_t bad = 0, first_bad = 0, beyond = 0, lo = 0, hi = 0;
        for (std::uint64_t L = 3400; L <= 7000; ++L) {
            const pb::SpanBounds f = span_reference(L, h_pos);  // the E-75 formula (no b0)
            pb::JoinServeFloors want{0, 0};
            if (!f.young && lc(h_pos(f.x0 - 1)) > 0) {  // not the young chain (E-79)
                const std::uint64_t body = f.x0 > j0 + 1 ? f.x0 - j0 - 1 : 0;
                if (lc(*rec(body)) > 0) {
                    want = pb::JoinServeFloors{body, header_floor_ref(f.x0, h_pos)};
                } else {
                    if (beyond++ == 0) lo = L;
                    hi = L;
                }
            }
            const pb::JoinServeFloors got = pb::join_serve_floors(P, L, rec, kLaneB0);
            if (got.bodies != want.bodies || got.headers != want.headers) {
                if (bad++ == 0) first_bad = L;
            }
        }
        check(bad == 0 && beyond > 0,
              "serving note: join_serve_floors keeps everything from position 1 exactly while lc(H(x0(L') - J_0 - 1)) = 0 (" +
                      std::to_string(beyond) + " L past the young chain, L in [" + std::to_string(lo) + ", " +
                      std::to_string(hi) + "]; " + std::to_string(bad) + " L differ, the first " + std::to_string(first_bad) + ")");
    }
}

// ---------------------------------------------------------------------------
// buckets: FC_BUCKETS at a joiner (3.4): at's own header, fetch C none, the
// adopt bound, (peer, at) assemblies, at-header claims, the re-ask scope
// ---------------------------------------------------------------------------
pb::BucketsAnchor anchor_of(KatNode& a, const pb::Hash32& at) {
    const pb::CarrierNode& n = a.node(at);
    const pb::CarrierBodyV3& b = *a.bodies.get(at);
    std::vector<pb::Hash32> ids;
    for (const pb::ReceiptBodyV3& r : b.carried) ids.push_back(pb::receipt_id(r));
    return pb::BucketsAnchor{true, a.node(n.parent).H, b.own.side.mmr_root, b.own.side.receipts_root, ids};
}
pb::AtHeader at_header_of(KatNode& a, const pb::Hash32& at) {
    return pb::AtHeader{at, pb::header_digest(pb::header_of(*a.bodies.get(at))).value_or(pb::Hash32{})};
}
std::uint64_t lc_of(std::uint64_t H) { return pb::bin_leaf_count(H, kLaneB0, pb::kRuledLaneParams.open_bins); }

// Re-encodes every frame of a reply after `edit`.
void edit_frames(pb::BucketFrames& out, const std::function<void(pb::BucketsReply&)>& edit) {
    for (std::vector<std::uint8_t>& f : out.frames) {
        pb::BucketsReply r;
        if (pb::decode_buckets(f, 0, r) != pb::BucketsWireError::None) continue;
        edit(r);
        if (std::optional<std::vector<std::uint8_t>> e = pb::encode_buckets(r)) f = std::move(*e);
    }
}

void buckets() {
    JoinNet net(900);
    KatNode a(net, kJ0);
    grow(a, 4810);
    const std::uint64_t F = pb::kRuledLaneParams.open_bins;
    const std::uint64_t fb = KatServer::frame_bytes();
    // the bucket pass of the retired joiner_bucket_pass, on BucketsAssembly
    {
        check(pb::journal_j0(pb::kRuledLaneParams, 0) == 1152 && kSpan == 1176 && kNrt == 2160,
              "J_0 == 1,152; join_span == 1,176; N_rt == 2,160");
        const pb::Hash32 at = at_pos(a, 3000);
        const pb::BucketsAnchor an = anchor_of(a, at);
        const std::uint64_t lc = lc_of(an.tip_record);
        const pb::GetBuckets q{0, at, kLaneB0 + 5, kLaneB0 + 15};
        const std::optional<pb::RatchetStateBytes> sp = pb::encode_ratchet_state(a.node(a.node(at).parent).rs);
        const std::vector<std::vector<std::uint8_t>> frames = pb::serve_buckets(a.store, q, sp, fb, UINT64_MAX / 4);
        pb::BucketsReply rep;
        check(!frames.empty() && pb::decode_buckets(frames[0], 0, rep) == pb::BucketsWireError::None &&
                      rep.leaf_count == lc && pb::peaks_match_root(rep.peaks, rep.leaf_count, an.mmr_root),
              "the at carrier's peaks bag to its mmr_root under leaf_count(tip(at))");
        pb::BucketsAssembly ok(q, kLaneB0, F, fb);
        bool acc = true;
        for (const auto& f : frames) acc = acc && ok.add_frame(1, f, an).verdict == pb::BucketsFrameVerdict::Accepted;
        check(acc && ok.complete() && ok.bins().size() == 11, "every served bucket verifies with its MMR proof");
        const auto refused = [&](const std::function<void(pb::BucketsReply&)>& edit, pb::BucketsFault want) {
            pb::BucketFrames bf{pb::LinkStatus::Served, frames};
            edit_frames(bf, edit);
            pb::BucketsAssembly x(q, kLaneB0, F, fb);
            const pb::FrameOutcome o = x.add_frame(2, bf.frames[0], an);
            return o.verdict == pb::BucketsFrameVerdict::Refused && o.fault == want;
        };
        check(refused([](pb::BucketsReply& r) { r.peaks.front()[0] ^= 1; }, pb::BucketsFault::Peaks), "forged peaks refused");
        check(refused([](pb::BucketsReply& r) { r.entries[4].payload.comp_root_v[0] ^= 1; }, pb::BucketsFault::Proof),
              "a forged bucket (its composition changed) refused by its MMR proof");
        check(refused([](pb::BucketsReply& r) { r.entries[4].path = r.entries[7].path; }, pb::BucketsFault::Proof),
              "a bucket without a matching proof refused");
    }
    // at's own header: fetch A at c_x0 serves leaf_count(tip(c_x0)) = lc(H(x0 - 1)); a bin sealed at x0 is not served there
    {
        const std::uint64_t L = 4607;  // x0 = 1,272 = the first position of a new Monero height
        KatServer s(a, 41);
        std::vector<pb::GetBuckets> reqs;
        std::map<pb::Hash32, std::uint64_t> served_lc;
        s.on_buckets = [&](const pb::GetBuckets& q, pb::BucketFrames& out) {
            reqs.push_back(q);
            pb::BucketsReply r;
            if (!out.frames.empty() && pb::decode_buckets(out.frames[0], 0, r) == pb::BucketsWireError::None &&
                !r.entries.empty())
                served_lc.emplace(q.at, r.leaf_count);
        };
        OneJoin o = join_at(net, s, L);
        check(o.r && o.r->end == pb::AttemptEnd::Completed, "at's own header: the join completes" + (o.r ? ": " + rep_desc(*o.r) : ""));
        if (o.j->adopted()) {
            const pb::JoinedState& js = *o.j->adopted();
            const pb::Hash32 cx0 = at_pos(a, js.x0);
            check(a.node(cx0).H > a.node(at_pos(a, js.x0 - 1)).H, "at's own header: a bin seals at x0 (H(x0) > H(x0 - 1))");
            check(served_lc.count(cx0) && served_lc[cx0] == lc_of(a.node(at_pos(a, js.x0 - 1)).H),
                  "at's own header: fetch A at c_x0 serves leaf_count(tip(c_x0)) = lc(H(x0 - 1))");
            const std::uint64_t bin_at_x0 = kLaneB0 + lc_of(a.node(cx0).H) - 1;
            const pb::GetBuckets q{0, cx0, bin_at_x0, bin_at_x0};
            const auto f = pb::serve_buckets(a.store, q, pb::encode_ratchet_state(a.node(at_pos(a, js.x0 - 1)).rs), fb, UINT64_MAX / 4);
            pb::BucketsReply r;
            check(f.size() == 1 && pb::decode_buckets(f[0], 0, r) == pb::BucketsWireError::None && r.entries.empty(),
                  "at's own header: a bin sealed at x0 is not served at c_x0");
        }
    }
    // fetch C none (ruling 44: no bucket fetch at a child of L); the adopt bound
    {
        const std::uint64_t L = 4608;  // H(L) > H(L - 1): bins seal at L
        KatServer s(a, 42);
        std::set<pb::Hash32> ats;
        s.on_buckets = [&](const pb::GetBuckets& q, pb::BucketFrames&) { ats.insert(q.at); };
        OneJoin o = join_at(net, s, L);
        check(o.r && o.r->end == pb::AttemptEnd::Completed, "fetch C none: the join completes" + (o.r ? ": " + rep_desc(*o.r) : ""));
        if (o.j->adopted()) {
            pb::JoinedState& js = *o.j->adopted();
            const pb::Hash32 cl = at_pos(a, L), cx0 = at_pos(a, js.x0);
            check(a.node(cl).H > a.node(at_pos(a, L - 1)).H, "fetch C none: bins seal at L");
            bool only = true;
            for (const pb::Hash32& at : ats) only = only && (at == cx0 || at == cl);
            check(only && !ats.empty(), "fetch C none: no FC_GETBUCKETS at a child of L (every at is c_x0 or c_L)");
            const pb::LaneDelta* jd = js.store->delta(cl);
            const pb::LaneDelta* ad = a.store.delta(cl);
            bool same_seal = jd && ad && !jd->sealed.empty() && jd->sealed.size() == ad->sealed.size();
            for (std::size_t i = 0; same_seal && i < jd->sealed.size(); ++i)
                same_seal = jd->sealed[i].leaf == ad->sealed[i].leaf && js.claimed.count(jd->sealed[i].bucket.bin_lo) == 0;
            check(same_seal, "fetch C none: every bin sealed at L is recomputed from J's placements and equals A's");
            check(follow(js, a, L, L + 1) && digest_of(js, at_pos(a, L + 1)) == digest_of(a, at_pos(a, L + 1)),
                  "fetch C none: a child of L admitted with no MissingBucket of the join; J's digest == A's at L + 1");
            // the adopt bound: a bin b <= H(x0 - 1) + Fresh sealed inside the span is the served bucket
            const std::uint64_t hx = a.node(at_pos(a, js.x0 - 1)).H;
            const std::uint64_t b = hx;  // a bin with placements before x0, sealed inside the span
            const pb::LaneView jv = js.store->view_at(cl), av = a.store.view_at(cl);
            const pb::SealedBin* jb = jv.ok() ? jv.bucket(b) : nullptr;
            const pb::SealedBin* ab = av.ok() ? av.bucket(b) : nullptr;
            check(js.claimed.count(b) && jb && ab && jb->leaf == ab->leaf, "adopt bound: bin H(x0 - 1) is the served bucket, A's");
            std::vector<pb::WinEntry> partial;
            for (const pb::Placement* x : jv.live_entries(b, jv.pos())) partial.push_back(pb::win_entry_of(*x));
            check(ab && pb::mmr_leaf_of(pb::seal_from_entries(b, partial)) != ab->leaf,
                  "adopt bound: J's own placements of that bin (no pre-x0 ones) would seal another leaf");
        }
    }
    // (peer, at): outside an attempt, a server abandoned for at -> its late frame DROPs, no strike; the next request
    // for at goes to another peer
    {
        const pb::Hash32 at = at_pos(a, 3000);
        const pb::BucketsAnchor an = anchor_of(a, at);
        KatServer s1(a, 51), s2(a, 52);
        std::vector<std::vector<std::uint8_t>> late;
        std::uint64_t n1 = 0;
        s1.on_buckets = [&](const pb::GetBuckets& q, pb::BucketFrames& out) {
            if (n1++ == 0) {  // a prefix: the first bin only
                out.frames = pb::serve_buckets(a.store, pb::GetBuckets{0, q.at, q.bin_lo, q.bin_lo},
                                               pb::encode_ratchet_state(a.node(a.node(q.at).parent).rs), KatServer::frame_bytes(),
                                               UINT64_MAX / 4);
            } else {  // then nothing in time; its frame arrives late
                late = out.frames;
                out.frames.clear();
                out.status = pb::LinkStatus::NoReply;
            }
        };
        pb::JoinBuckets jb(kLaneB0, F, fb, 0);
        std::optional<std::uint64_t> by;
        const pb::BucketsFetch f = jb.fetch_any({&s1, &s2}, an, at_header_of(a, at), kLaneB0 + 5, kLaneB0 + 15, kP53, &by);
        check(f.end == pb::BucketsEnd::Complete && by && *by == 52 && s2.bucket_requests == 1,
              "(peer, at): the abandoned server's range is asked at another peer, which completes it");
        bool dropped = !late.empty();
        for (const auto& fr : late) {
            const pb::FrameOutcome o = jb.late_frame(51, at, fr, an);
            dropped = dropped && o.verdict == pb::BucketsFrameVerdict::Drop && o.strike == 0;
        }
        check(dropped, "(peer, at): the abandoned server's late frame for at -> DROP, no strike");
    }
    // at-header claims: a proof, a leaf_count or an S_parent against the claimed at header -> alarm, the
    // attempt ends, 0 tokens; a frame that does not decode -> 1 strike
    {
        const std::uint64_t L = 4600;
        KatServer fp(a, 61), fl(a, 62), fs(a, 63), fw(a, 64), h(a, 65);
        for (KatServer* x : {&fp, &fl, &fs, &fw, &h}) x->top = L;
        const pb::Hash32 cx0 = at_pos(a, 1265);  // x0 at L = 4,600
        const auto on_x0 = [&](const std::function<void(pb::BucketsReply&)>& e) {
            return [=](const pb::GetBuckets& q, pb::BucketFrames& out) {
                if (q.at == cx0) edit_frames(out, e);
            };
        };
        fp.on_buckets = on_x0([](pb::BucketsReply& r) {
            if (!r.entries.empty() && !r.entries[0].path.empty()) r.entries[0].path[0][0] ^= 1;
        });
        fl.on_buckets = on_x0([](pb::BucketsReply& r) {
            // another leaf_count with the same popcount (the frame still decodes)
            const std::uint64_t lc = r.leaf_count;
            const std::uint64_t low = lc & (~lc + 1);
            if ((lc & (low << 1)) == 0) r.leaf_count = lc - low + (low << 1);
        });
        fs.on_buckets = on_x0([](pb::BucketsReply& r) { r.s_parent[2] ^= 1; });
        fw.on_buckets = [&](const pb::GetBuckets& q, pb::BucketFrames& out) {
            if (q.at == cx0 && !out.frames.empty()) out.frames[0].resize(out.frames[0].size() - 3);
        };
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        for (KatServer* x : {&fp, &fl, &fs, &fw, &h}) j.offer(x->best_id(), *x);
        std::map<std::uint64_t, pb::AttemptReport> reps;
        for (int i = 0; i < 8 && !j.adopted(); ++i)
            if (std::optional<pb::AttemptReport> r = j.run_next()) reps.emplace(r->server, std::move(*r));
        for (std::uint64_t sv : {61, 62, 63}) {
            const auto it = reps.find(sv);
            check(it != reps.end() && it->second.end == pb::AttemptEnd::Alarm && it->second.strike == 0 &&
                          j.queue().excluded(sv),
                  "at-header claims: server " + std::to_string(sv) + " -> alarm, the attempt ends, 0 tokens, excluded" +
                          (it != reps.end() ? ": " + rep_desc(it->second) : ""));
        }
        const auto w = reps.find(64);
        check(w != reps.end() && w->second.strike == 1 && w->second.end != pb::AttemptEnd::Completed,
              "at-header claims: a frame that does not decode -> 1 strike" + (w != reps.end() ? ": " + rep_desc(w->second) : ""));
        check(j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == digest_of(a, at_pos(a, L)),
              "at-header claims: J reaches A's digest from the honest server");
    }
    // the re-ask scope (3.4): the claimed leaves whose at header (id and digest) is not a bound carrier of the
    // heavier chain, and those a claim-leaf mismatch entered; each at a carrier of that chain whose leaf_count
    // covers the bin; a seal below the journal base -> the joiner path
    {
        const pb::Hash32 cl{seq32(0xC1)}, cl_variant_digest{seq32(0xC7)}, kept{seq32(0xC2)};
        std::map<std::uint64_t, pb::AtHeader> claimed{{kLaneB0 + 10, {cl, seq32(0xD1)}},
                                                      {kLaneB0 + 11, {cl, seq32(0xD1)}},
                                                      {kLaneB0 + 40, {kept, seq32(0xD2)}},
                                                      {kLaneB0 + 41, {kept, seq32(0xD2)}},
                                                      {kLaneB0 + 12, {cl, cl_variant_digest}}};
        // the heavier chain has bound `kept` (digest D2) and cl with ANOTHER digest (D1 is a variant of cl)
        const std::vector<pb::AtHeader> bound{{kept, seq32(0xD2)}, {cl, cl_variant_digest}};
        // carriers of the heavier chain by position, with leaf_count(tip(at))
        const std::vector<std::pair<pb::Hash32, std::uint64_t>> heavier{{seq32(0xA1), 11}, {seq32(0xA2), 12}, {seq32(0xA3), 60}};
        const std::vector<pb::JoinBuckets::Reask> r = pb::JoinBuckets::reask_scope(claimed, bound, {kLaneB0 + 41}, heavier, kLaneB0);
        std::map<std::uint64_t, pb::Hash32> got;
        for (const auto& x : r) got[x.bin] = x.at;
        check(got.size() == 3 && got.count(kLaneB0 + 10) && got.count(kLaneB0 + 11) && got.count(kLaneB0 + 41) &&
                      !got.count(kLaneB0 + 40) && !got.count(kLaneB0 + 12),
              "re-ask scope: the leaves at a c_L variant not bound on the heavier chain and the mismatched one, only");
        check(got[kLaneB0 + 10] == seq32(0xA1) && got[kLaneB0 + 11] == seq32(0xA2) && got[kLaneB0 + 41] == seq32(0xA3),
              "re-ask scope: each asked at the first carrier whose leaf_count covers its bin");
        check(!pb::reask_replay(5000, 4000).joiner_path && pb::reask_replay(5000, 4000).from == 4999 &&
                      pb::reask_replay(3000, 4000).joiner_path,
              "re-ask: replay from the bin's seal; a seal below the journal base -> the joiner path");
    }
}

// ---------------------------------------------------------------------------
// afterl: the joined node after L and the attempt's regime during the replay:
// the AR seed, the attempt server's copies during the replay, every peer's copy
// after L, the forged top (E-72), the P-50 budget
// ---------------------------------------------------------------------------
// A forged tip on `tip` at A whose committed mmr_root differs from the honest one in the leaf of bin `bin`
// (its coinbase canonical over the forged side_data).
pb::CarrierBodyV3 forged_top(KatNode& a, const pb::Hash32& tip, std::uint64_t bin, std::uint64_t nonce) {
    const pb::LaneView v = a.store.view_at(tip);
    const std::uint64_t lc = v.leaf_count();
    pb::BinMmr m;
    for (std::uint64_t i = 0; i < lc; ++i) {
        pb::Hash32 leaf = a.store.best_mmr().leaf(i).value_or(pb::Hash32{});
        if (i == bin - kLaneB0) leaf[0] ^= 0x5a;
        m.append(leaf);
    }
    const pb::Hash32 root = m.root();
    const std::uint64_t h = a.node(tip).h;
    return carrier_on(a, tip, h, {}, 3, nonce, {}, [&](pb::ReceiptBodyV3& r) { r.side.mmr_root = root; });
}

void afterl() {
    JoinNet net(900);
    KatNode a(net, kJ0);
    grow(a, 4810);
    const std::uint64_t L = 4600;
    const std::uint64_t kB = 81;  // a peer relaying to J
    // the attempt's regime during the replay: copies from another peer are DEFERred (CopyDeferred, 0 tokens)
    KatServer s(a, 71);
    s.top = L;
    JoinerEnv je(net);
    pb::Joiner j(je.in, kP53);
    bool b_frame = false, b_receipt = false, b_checked = false;
    std::uint64_t deferred_alarms = 0;
    j.set_on_step([&](pb::JoinedState& st, std::uint64_t x) {
        if (b_checked || st.young || x + 1 > st.x1 || (x + 1) % 3 != 0) return;
        b_checked = true;
        // B relays the next span carrier with its carried body's payee substituted (the tip below x1: #12 a claim)
        pb::CarrierBodyV3 c = *a.bodies.get(at_pos(a, x + 1));
        if (c.carried.empty()) return;
        c.carried[0].side.payee = net.ids[20];
        c.carried[0].payee = net.refs[20];
        const std::vector<std::uint8_t> f = frame_of(c);
        pb::AdmitEnv env = st.env();
        const std::size_t al0 = st.alarm.count();
        const pb::AdmitResult r = pb::admit_frame_from(env, kB, f, pb::CarrierRole::Frame);
        b_frame = r.verdict == pb::AdmitVerdict::Defer && r.missing == pb::Missing::CopyDeferred && r.strike == 0;
        if (r.verdict == pb::AdmitVerdict::AdmitCarrier)  // a node places what it admits
            (void)pb::place_admitted(*st.tree, *st.store, st.ar, st.bodies, r, &st.alarm);
        // an honest receipt at a span tip relayed by B
        const pb::ReceiptBodyV3 rb = body_on(a, at_pos(a, x), a.node(at_pos(a, x)).h, 9, 8100000 + x);
        const pb::AdmitResult rr = pb::admit_receipt_from(env, kB, bytes_of(rb));
        b_receipt = rr.verdict == pb::AdmitVerdict::Defer && rr.missing == pb::Missing::CopyDeferred && rr.strike == 0;
        deferred_alarms = st.alarm.count() - al0;
    });
    j.offer(s.best_id(), s);
    const std::optional<pb::AttemptReport> r = j.run_next();
    check(r && r->end == pb::AttemptEnd::Completed, "afterl: the join completes" + (r ? ": " + rep_desc(*r) : ""));
    check(b_checked && b_frame && deferred_alarms == 0,
          "attempt server: B's copy of a span frame (a substituted payee in a carried body below x1) -> CopyDeferred, 0 tokens");
    check(b_receipt, "attempt server: an honest receipt at a span tip relayed by B during the replay -> DEFER, 0 tokens");
    if (!j.adopted()) return;
    pb::JoinedState& js = *j.adopted();
    check(digest_of(js, at_pos(a, L)) == digest_of(a, at_pos(a, L)), "attempt server: J places the server's copy: J's digest == A's at L");
    // the AR seed: rows == [(e, x0 - 1, rules)]; a restore below x0 - 1 refused, AR unchanged
    {
        const pb::RatchetState& s0 = a.node(at_pos(a, js.x0 - 1)).rs;
        const std::vector<pb::ActivationRow> want{pb::ActivationRow{s0.epoch_cur, js.x0 - 1, s0.rules_cur}};
        check(js.ar.rows() == want && js.ar.joiner_p0() == js.x0, "AR seed: AR rows == [(e, x0 - 1, rules)], p0 = x0");
        pb::ActivationRecord copy = js.ar;
        check(copy.rewind(js.x0 - 2) == pb::ArRewind::BelowJoinerSeed && copy.rows() == want,
              "AR seed: a restore below x0 - 1 refused, AR unchanged");
    }
    // after L every peer's copy is judged as at a full node
    check(follow(js, a, L, L + 1, kB) && js.tree->find(at_pos(a, L + 1)) != nullptr,
          "after L: an honest frame relayed by B is judged and placed");
    // the forged top: a #13 mismatch into which an adopted leaf enters -> alarm + DEFER at J, no token; A BANs it
    {
        check(!js.claimed.empty(), "forged top: J holds leaves adopted from fetch B");
        const std::uint64_t bin = js.claimed.begin()->first;
        const pb::CarrierBodyV3 lstar = forged_top(a, at_pos(a, L + 1), bin, 9100001);
        const std::vector<std::uint8_t> f = frame_of(lstar);
        pb::AdmitEnv env = js.env();
        const pb::AdmitResult rj = pb::admit_frame_from(env, kB, f, pb::CarrierRole::Frame);
        const pb::AdmitResult ra = pb::admit_carrier(a.env(), f, pb::CarrierRole::Frame);
        check(rj.verdict == pb::AdmitVerdict::Defer && rj.missing == pb::Missing::ClaimAlarm && rj.alarm && rj.strike == 0,
              "forged top: J's #13 at L* -> local alarm + DEFER, no token, no BAN (" + desc(rj) + ")");
        check(ra.verdict == pb::AdmitVerdict::Ban && ra.row == pb::RowId::R10, "forged top: A, a full node, BANs it (" + desc(ra) + ")");
        check(follow(js, a, L + 1, L + 2) && js.tree->find(at_pos(a, L + 2)) != nullptr, "forged top: the honest child is placed");
    }
    // P-50: 18 claim-leaf alarms at once from one peer -> 18 DEFERs, 0 tokens, the peer disconnected at the 18th; a peer
    // with one per T stays connected
    {
        pb::ClaimAlarmBudget budget(js.inputs().p);
        const std::uint64_t T = js.inputs().p.carrier_interval_s;
        const std::uint64_t bin = js.claimed.begin()->first;
        std::uint64_t alarms = 0, tokens = 0, cut_at = 0;
        for (std::uint64_t k = 1; k <= 18; ++k) {
            const pb::CarrierBodyV3 c = forged_top(a, at_pos(a, L + 2), bin, 9200000 + k);
            pb::AdmitEnv env = js.env();
            const pb::AdmitResult x = pb::admit_frame_from(env, 91, frame_of(c), pb::CarrierRole::Frame);
            alarms += x.missing == pb::Missing::ClaimAlarm ? 1 : 0;
            tokens += x.strike;
            if (!budget.charge(91, 1000, true) && cut_at == 0) cut_at = k;
        }
        check(alarms == 18 && tokens == 0 && cut_at == 18,
              "P-50: 18 frames at once -> 18 alarms and DEFERs, 0 tokens, the peer disconnected at the 18th (cut at " +
                      std::to_string(cut_at) + ")");
        bool connected = true;
        for (std::uint64_t k = 1; k <= 40; ++k) {
            const pb::CarrierBodyV3 c = forged_top(a, at_pos(a, L + 2), bin, 9300000 + k);
            pb::AdmitEnv env = js.env();
            (void)pb::admit_frame_from(env, 92, frame_of(c), pb::CarrierRole::Frame);
            connected = connected && budget.charge(92, 2000 + k * T, true);
        }
        check(connected, "P-50: a peer relaying one such frame per T stays connected");
        check(follow(js, a, L + 2, L + 200) && digest_of(js, at_pos(a, L + 200)) == digest_of(a, at_pos(a, L + 200)),
              "P-50: J reaches A's digest at L + 200");
    }
}

// ---------------------------------------------------------------------------
// claims: span claims (ruling 42), the PRE (ruling 43), the span's d (E-76) at
// the joiner; ended attempts; Boundary / Closure in the replay; one variant
// per id and attempt; every mmr_root of the span
// ---------------------------------------------------------------------------
// A chain for joins at L = 4,600 (x0 = 1,265, x1 = 2,436) with races: side carrier s on 2,426 (carrying one
// receipt) and a carrier at 2,441 carrying a receipt on s; side carrier s2 on 1,266 (for a deep-tip carrier at
// 2,420); a carrier at 1,270 carrying a receipt whose P_r is a Monero side block.
struct RaceChain {
    pb::Hash32 s{}, s2{};
    std::uint64_t c_s = 2441;     // carries a receipt on s
    std::uint64_t c_deep = 2420;  // a span carrier whose forged copy carries a receipt on s2 (J_0 + 1 below its parent)
    std::uint64_t c_alt = 1270;   // carries a receipt whose P_r is on the Monero side branch
    pb::Hash32 alt_pr{};
    std::unique_ptr<KatNode> b;   // an adversary: A's chain to 2,419, then a carrier carrying a receipt on s2 at
                                  // 2,420 (placed without admission: every node DEFERs it) and its own chain on it
    pb::Hash32 deep{};            // that carrier
};
RaceChain grow_race(KatNode& a) {
    RaceChain rc;
    ChainShape sh;
    grow(a, 1263, sh);
    {
        // P-11 at x0 - 1 = 1,264: a carrier carrying a receipt of bin H(x0 - 1) + Fresh + 2 (its tip a side carrier
        // two heights above its parent) is refused by A, so no placement before x0 lies above H(x0 - 1) + Fresh
        const pb::Hash32 p = at_pos(a, 1261);
        const pb::CarrierBodyV3 s3 = carrier_on(a, p, a.node(p).h + 2, {}, 6, 3300010);
        const Admitted as3 = admit_place(a, s3);
        const pb::Hash32 s3id = pb::receipt_id(s3.own);
        const pb::ReceiptBodyV3 r3 = body_on(a, s3id, a.node(s3id).h + 2, 7, 3300011);
        const pb::Hash32 tip = at_pos(a, 1263);
        const pb::CarrierBodyV3 c = carrier_on(a, tip, h_pos(1264), {r3}, 1264 % 4, 3300012);
        const Admitted ac = admit_place(a, c);
        check(as3.placed && !ac.placed && ac.r.verdict == pb::AdmitVerdict::Strike && ac.r.row == pb::RowId::R21,
              "race chain: a receipt above h(c) + Fresh carried at x0 - 1 is refused by A (P-11): " + desc(ac.r));
        if (!ac.placed) grow(a, 1, sh);
    }
    grow(a, rc.c_alt - 1 - 1264, sh);
    {
        const pb::Hash32 tip = at_pos(a, rc.c_alt - 1);
        const std::uint64_t hr = a.node(tip).h;
        rc.alt_pr = block_id(kAltTag, hr - 1);
        const pb::ReceiptBodyV3 r = body_on(a, tip, hr, 6, 3300001, [&](pb::ReceiptBodyV3& b) { b.blob.prev_id = rc.alt_pr; });
        const pb::CarrierBodyV3 c = carrier_on(a, tip, h_pos(rc.c_alt), {r}, rc.c_alt % 4, 1 + rc.c_alt);
        check(admit_place(a, c).placed, "race chain: the carrier with a side-block P_r placed");
    }
    grow(a, 1300 - rc.c_alt, sh);
    {
        const pb::Hash32 f = at_pos(a, 1266);
        const pb::CarrierBodyV3 c = carrier_on(a, f, h_pos(1267), {}, 5, 3300002);
        const Admitted ad = admit_place(a, c);
        rc.s2 = pb::receipt_id(c.own);
        check(ad.placed && a.store.best_at(1267) != rc.s2, "race chain: s2 placed on a side branch at 1,267");
    }
    grow(a, rc.c_deep - 1 - 1300, sh);
    {
        rc.b = std::make_unique<KatNode>(a);
        KatNode& b = *rc.b;
        const pb::Hash32 tip = at_pos(b, rc.c_deep - 1);
        const pb::ReceiptBodyV3 r2 = body_on(b, rc.s2, b.node(rc.s2).h + 1, 9, 3300006);
        const pb::CarrierBodyV3 c = carrier_on(b, tip, h_pos(rc.c_deep), {r2}, rc.c_deep % 4, 3300007);
        rc.deep = pb::receipt_id(c.own);
        const pb::WriteResult w = place_direct(b, c);
        check(w.outcome == pb::WriteOutcome::Extended, "race chain: the adversary's deep-tip carrier placed (scaffold)");
        ChainShape bs;
        bs.nonce0 = 70000;
        grow(b, 4610 - rc.c_deep, bs);
    }
    grow(a, 2426 - (rc.c_deep - 1), sh);
    grow(a, rc.c_s - 1 - 2426, sh);
    {
        const pb::Hash32 p = at_pos(a, 2426);
        const pb::ReceiptBodyV3 r = body_on(a, p, h_pos(2427), 7, 3300003);
        const pb::CarrierBodyV3 c = carrier_on(a, p, h_pos(2427), {r}, 5, 3300004);
        const Admitted ad = admit_place(a, c);
        rc.s = pb::receipt_id(c.own);
        check(ad.placed && a.store.best_at(2427) != rc.s, "race chain: s placed on a side branch at 2,427");
    }
    {
        const pb::Hash32 tip = at_pos(a, rc.c_s - 1);
        const pb::ReceiptBodyV3 r = body_on(a, rc.s, a.node(rc.s).h, 8, 3300005);
        const pb::CarrierBodyV3 c = carrier_on(a, tip, h_pos(rc.c_s), {r}, rc.c_s % 4, 1 + rc.c_s);
        check(admit_place(a, c).placed, "race chain: the carrier at 2,441 carrying a receipt on s placed");
    }
    grow(a, 4810 - rc.c_s, sh);
    return rc;
}

// A header and a body edited alike (the id, its blob, unchanged).
void edit_carrier(KatServer& s, const pb::Hash32& id, const std::function<void(pb::CarrierBodyV3&)>& edit) {
    const auto prev_h = s.on_headers;
    const auto prev_b = s.on_bodies;
    s.on_headers = [=](const pb::Hash32& stop, pb::ChainHeaders& out) {
        if (prev_h) prev_h(stop, out);
        for (pb::CarrierHeader& h : out.headers)
            if (pb::receipt_id(h.own) == id) {
                pb::CarrierBodyV3 c;
                c.own = h.own;
                c.carried.resize(h.n_carried);
                edit(c);
                h.own = c.own;
                h.n_carried = static_cast<std::uint8_t>(c.carried.size());
            }
    };
    s.on_bodies = [=](const std::vector<pb::Hash32>& ids, pb::CarrierFrames& out) {
        if (prev_b) prev_b(ids, out);
        for (pb::CarrierBodyV3& c : out.bodies)
            if (pb::receipt_id(c.own) == id) edit(c);
    };
}

// Runs J over the servers in order until it adopts (at most `rounds` attempts); the reports by server.
std::map<std::uint64_t, pb::AttemptReport> run_until(pb::Joiner& j, int rounds = 8) {
    std::map<std::uint64_t, pb::AttemptReport> reps;
    for (int i = 0; i < rounds && !j.adopted(); ++i)
        if (std::optional<pb::AttemptReport> r = j.run_next()) reps.insert_or_assign(r->server, std::move(*r));
    return reps;
}

// ruling 47 (RULED 47, E-84): the retarget-prefix headers [x0 - N_rt, x0 - 1] are claimed nodes of the joined tree, so
// a receipt carried by a span carrier whose tip lies on the carrier's own chain below x0 - 1 (a lost race at x0 - 1,
// or a late receipt) is walked and placed as a full node does, and the join completes (ruling 47, E-84).
void lost_race(const JoinNet& net) {
    const std::uint64_t L = 4700;
    KatNode a(net, kJ0);
    const pb::SpanResult sr = pb::span_bounds(pb::kRuledLaneParams, L, [](std::uint64_t x) -> std::optional<std::uint64_t> {
        return x == 0 ? kLaneB0 : h_pos(x); }, kLaneB0);
    const std::uint64_t x0 = sr.bounds.x0;  // 1,365 at 12 per height
    grow(a, x0 - 1);
    for (std::uint64_t k : {1, 5, 600, 1100}) {  // the share lost the race at x0 - 1 (tip x0 - 1 - k); late receipts
        const pb::Hash32 tip = at_pos(a, x0 - 1 - k);
        const std::uint64_t hr = std::min(h_pos(x0), a.node(tip).h + 1);  // fresh on its own tip, its bin open at x0
        const pb::ReceiptBodyV3 r = body_on(a, tip, hr, 7, 990000 + k);
        const pb::CarrierBodyV3 c = carrier_on(a, at_pos(a, x0 - 1), h_pos(x0), {r}, x0 % 4, 880000 + k);
        check(x0 - 1 - k >= a.node(at_pos(a, x0 - 1)).pos - kJ0, "lost race: the tip is within J_0 of the carrier");
        if (k == 1) {  // the control (tip x0 - 1, the root) and the lost-race tip x0 - 2 are placed by A
            check(admit_place(a, c).placed, "lost race: A places the carrier at x0 (its receipt's tip at x0 - 1 - k)");
            break;
        }
    }
    // one chain: the carrier at x0 carries the losing share whose tip is x0 - 2 (a PRE position, below the root)
    grow(a, L + 200 - a.store.tip_pos());
    for (std::uint64_t k : {2, 6, 601, 1101}) {
        KatNode b(net, kJ0);
        grow(b, x0 - 1);
        const pb::Hash32 tip = at_pos(b, x0 - 1 - k);
        const std::uint64_t hr = std::min(h_pos(x0), b.node(tip).h + 1);
        const pb::ReceiptBodyV3 r = body_on(b, tip, hr, 7, 970000 + k);
        const pb::CarrierBodyV3 c = carrier_on(b, at_pos(b, x0 - 1), h_pos(x0), {r}, x0 % 4, 860000 + k);
        check(admit_place(b, c).placed, "lost race k=" + std::to_string(k) + ": A places the carrier at x0");
        grow(b, L + 200 - b.store.tip_pos());
        const pb::Hash32 dL = digest_of(b, at_pos(b, L));
        KatServer s(b, 125 + static_cast<std::uint64_t>(k));
        OneJoin o = join_at(net, s, L);
        check(o.r && o.r->end == pb::AttemptEnd::Completed && o.j->adopted() &&
                      digest_of(*o.j->adopted(), at_pos(b, L)) == dL,
              "lost race k=" + std::to_string(k) + ": J places the receipt (tip x0 - 1 - k on the carrier's own chain) "
              "and completes" + (o.r ? ": " + rep_desc(*o.r) : ""));
    }
}

// ruling 47 (RULED 47, E-83): a receipt carried by a span carrier whose tip lies on a SIDE branch forking at a PRE
// node below x0 - 1 is judged with S(f), fetched from the attempt's server by FC_GETBUCKETS at the first side carrier.
// A forged variant of the side carrier served first -> the S(f) fold against the forged receipts_root mismatches: a
// local alarm + DEFER, no token, the attempt ends, the server excluded. The honest server: S(f) asked at the side
// carrier, the fold matches (no alarm, no token); lc(H(f)) > 0, so no young mark (the young path only at lc = 0,
// ruling 51); the honest attempt completes and J reaches A's digest at L (ruling 53: d below the root a claim, the
// claimed view at f).
void span_claims_iii(const JoinNet& net) {
    KatNode a(net, 6000);  // the server keeps side views deep enough to serve S(f) (P-51)
    const std::uint64_t L = 4600, x0 = 1265;
    grow(a, x0);
    const pb::Hash32 root = at_pos(a, x0 - 1), fork = at_pos(a, x0 - 3);
    const pb::CarrierBodyV3 s = carrier_on(a, fork, a.node(fork).h, {}, 5, 3400001);  // h(s) = h(fork): no new bin
    const pb::Hash32 sid = pb::receipt_id(s.own);
    const Admitted as = admit_place(a, s);
    const pb::ReceiptBodyV3 r = body_on(a, sid, a.node(sid).h, 7, 3400002);
    const pb::CarrierBodyV3 c = carrier_on(a, at_pos(a, x0), h_pos(x0 + 1), {r}, (x0 + 1) % 4, 3400003);
    const Admitted ac = admit_place(a, c);
    grow(a, 4810 - (x0 + 1));
    const pb::CarrierNode* sn = a.tree.find(sid);
    const std::uint64_t lcf = pb::bin_leaf_count(a.node(fork).H, kLaneB0, pb::kRuledLaneParams.open_bins);
    check(as.placed && ac.placed && sn != nullptr && a.store.best_at(sn->pos) != sid && a.node(fork).pos + 1 < x0 - 1 &&
                  a.node(at_pos(a, x0)).pos - a.node(fork).pos <= kJ0 && a.store.best_at(x0 + 1) == pb::receipt_id(c.own) &&
                  lcf > 0,
          "span claims (iii): A places c, whose receipt's tip lies on a side branch forking at x0 - 3 (within J_0), "
          "lc(H(f)) = " + std::to_string(lcf));
    const pb::Hash32 dL = digest_of(a, at_pos(a, L));
    {
        // (forged) a server serves a variant of s whose receipts_root is built on the root (not on S(f)): the S(f)
        // fold the joiner fetches at the side carrier mismatches it -> a ruling-42 claim mismatch
        const pb::CarrierBodyV3 on_root = carrier_on(a, root, a.node(sid).h, {}, 5, 3400004);
        pb::CarrierHeader forged = pb::header_of(s);
        forged.own.side = on_root.own.side;
        forged.own.side.tip = fork;  // keep the parent link at the fork, but the receipts_root is built on the root
        check(pb::receipt_id(forged.own) == sid && !(forged.own.side == s.own.side),
              "span claims (iii) forged: the variant keeps s's id and its fork link, but a receipts_root built on the root");
        KatServer f(a, 118), h(a, 119);
        f.top = L;
        h.top = L;
        f.on_headers = [&](const pb::Hash32&, pb::ChainHeaders& out) {
            for (pb::CarrierHeader& hh : out.headers)
                if (pb::receipt_id(hh.own) == sid) hh = forged;
        };
        std::set<pb::Hash32> h_ats;  // the at headers of the honest server's FC_GETBUCKETS
        h.on_buckets = [&](const pb::GetBuckets& q, pb::BucketFrames&) { h_ats.insert(q.at); };
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(f.best_id(), f);
        j.offer(h.best_id(), h);
        std::vector<pb::AttemptReport> reps;
        for (int i = 0; i < 3 && !j.adopted(); ++i)
            if (std::optional<pb::AttemptReport> rr = j.run_next()) reps.push_back(std::move(*rr));
        check(!reps.empty() && reps[0].server == 118 && reps[0].end == pb::AttemptEnd::Alarm && reps[0].strike == 0 &&
                      reps[0].alarms > 0 && j.queue().excluded(118),
              "span claims (iii) forged: the S(f) fetch at the side carrier, its fold against the forged receipts_root "
              "-> a ruling-42 alarm + DEFER, 0 tokens, the server excluded" +
                      (reps.empty() ? std::string() : ": " + rep_desc(reps[0])));
        const pb::AttemptReport* hr = nullptr;
        for (const pb::AttemptReport& x : reps)
            if (x.server == 119 && hr == nullptr) hr = &x;
        check(hr != nullptr && h_ats.count(sid) != 0 && hr->end != pb::AttemptEnd::Alarm && hr->alarms == 0 &&
                      hr->strike == 0 && !hr->force_young &&
                      (j.adopted() == nullptr || digest_of(*j.adopted(), at_pos(a, L)) == dL),
              "span claims (iii) honest: S(f) asked at the side carrier and its fold matches (no alarm, no token); no "
              "young mark at lc(H(f)) > 0; J holds no state other than A's" +
                      (hr != nullptr ? ": " + rep_desc(*hr) : std::string()));
        check(hr != nullptr && hr->end == pb::AttemptEnd::Completed && j.adopted() &&
                      digest_of(*j.adopted(), at_pos(a, L)) == dL,
              "span claims (iii) honest: the attempt completes; J's digest == A's");
    }
}

// The same shape with the side carrier s carrying one receipt (its n_carried = 1): the S(f) fold runs over s's carried
// list, so the joiner takes s's body set before it folds. The honest server: no alarm, no token; J holds no state
// other than A's; the honest attempt completes and J reaches A's digest at L (ruling 53).
void span_claims_iii_carried(const JoinNet& net) {
    KatNode a(net, 6000);
    const std::uint64_t L = 4600, x0 = 1265;
    grow(a, x0);
    const pb::Hash32 fork = at_pos(a, x0 - 3), below = at_pos(a, x0 - 4);
    const pb::ReceiptBodyV3 rs = body_on(a, below, a.node(below).h, 3, 3420011);  // carried by s (its tip below the fork)
    const pb::CarrierBodyV3 s = carrier_on(a, fork, a.node(fork).h, {rs}, 5, 3420001);
    const pb::Hash32 sid = pb::receipt_id(s.own);
    const Admitted as = admit_place(a, s);
    const pb::ReceiptBodyV3 r = body_on(a, sid, a.node(sid).h, 7, 3420002);
    const pb::CarrierBodyV3 c = carrier_on(a, at_pos(a, x0), h_pos(x0 + 1), {r}, (x0 + 1) % 4, 3420003);
    const Admitted ac = admit_place(a, c);
    grow(a, 4810 - (x0 + 1));
    const pb::CarrierNode* sn = a.tree.find(sid);
    check(as.placed && ac.placed && sn != nullptr && a.store.best_at(sn->pos) != sid && s.carried.size() == 1 &&
                  a.store.best_at(x0 + 1) == pb::receipt_id(c.own),
          "span claims (iii) carried: A places s (carrying one receipt) on a side branch forking at x0 - 3, and c");
    const pb::Hash32 dL = digest_of(a, at_pos(a, L));
    KatServer h(a, 120);
    h.top = L;
    std::set<pb::Hash32> h_ats;
    h.on_buckets = [&](const pb::GetBuckets& q, pb::BucketFrames&) { h_ats.insert(q.at); };
    JoinerEnv je(net);
    pb::Joiner j(je.in, kP53);
    j.offer(h.best_id(), h);
    const std::optional<pb::AttemptReport> hr = j.run_next();
    check(hr && h_ats.count(sid) != 0 && hr->end != pb::AttemptEnd::Alarm && hr->alarms == 0 && hr->strike == 0 &&
                  !hr->force_young && (j.adopted() == nullptr || digest_of(*j.adopted(), at_pos(a, L)) == dL),
          "span claims (iii) carried: the S(f) fold over s's carried list matches at the honest server (no alarm, no "
          "token, no young mark); J holds no state other than A's" + (hr ? ": " + rep_desc(*hr) : std::string()));
    check(hr && hr->end == pb::AttemptEnd::Completed && j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == dL,
          "span claims (iii) carried: the attempt completes; J's digest == A's");
}

// ruling 47 at lc(tip(at)) = 0 (RULED 47, E-83): a side branch whose first carrier forks at f with lc(H(f)) = 0 (no bin
// sealed at or before f), while lc(H(x0 - 1)) >= 1: the S(f) fetch finds no bin, so the attempt ends with no alarm, no
// token and no exclusion, and the pair's next attempt runs the young path at the same server and completes; J's
// digest == A's. Served by a server at P-51's default (its serving note keeps everything from position 1 while
// lc(H(x0(L') - J_0 - 1)) = 0) and by an archival one.
void span_fold_lc0(const JoinNet& net) {
    const std::uint64_t L = 4535;
    KatNode a(net, 6000);
    const pb::SpanResult sr = pb::span_bounds(pb::kRuledLaneParams, L, [](std::uint64_t x) -> std::optional<std::uint64_t> {
        return x == 0 ? kLaneB0 : h_pos(x); }, kLaneB0);
    const std::uint64_t x0 = sr.bounds.x0;  // ~1,200 at 12 per height (lc(H(x0 - 1)) >= 1)
    check(!sr.bounds.young && x0 > 1152, "span fold lc0: x0 = " + std::to_string(x0) + " (lc(H(x0-1)) >= 1)");
    grow(a, x0 + 1);
    const std::uint64_t ff = 200;  // the fork: lc(H(200)) = 0, within J_0 of the carrier at x0 + 1
    const pb::Hash32 fork = at_pos(a, ff);
    const pb::CarrierBodyV3 s = carrier_on(a, fork, a.node(fork).h, {}, 5, 3410001);  // h(s) = h(fork)
    const pb::Hash32 sid = pb::receipt_id(s.own);
    const Admitted as = admit_place(a, s);
    const pb::ReceiptBodyV3 r = body_on(a, sid, a.node(sid).h, 7, 3410002);
    const pb::CarrierBodyV3 c = carrier_on(a, at_pos(a, x0 + 1), h_pos(x0 + 2), {r}, (x0 + 2) % 4, 3410003);
    const Admitted ac = admit_place(a, c);
    grow(a, 4810 - a.store.tip_pos());
    const std::uint64_t lcf = pb::bin_leaf_count(a.node(fork).H, kLaneB0, pb::kRuledLaneParams.open_bins);
    check(as.placed && ac.placed && lcf == 0 && a.node(at_pos(a, x0 + 1)).pos - ff <= kJ0,
          "span fold lc0: A places c; the side branch forks at f = 200, lc(H(f)) = 0, within J_0");
    const pb::Hash32 dL = digest_of(a, at_pos(a, L));
    for (const bool retention : {true, false}) {
        const std::string tag = std::string("span fold lc0 (") + (retention ? "P-51 default" : "archival") + ")";
        const std::uint64_t peer = retention ? 126 : 127;
        KatServer s0(a, peer);
        s0.top = L;
        s0.retention = retention;
        if (retention) {
            const pb::JoinServeFloors fl = s0.floors_now();
            check(fl.bodies == 0 && fl.headers == 0,
                  tag + ": lc(H(x0(L') - J_0 - 1)) = 0, so the server keeps everything from position 1 (floors " +
                          std::to_string(fl.bodies) + ", " + std::to_string(fl.headers) + ")");
        }
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(s0.best_id(), s0);
        const std::optional<pb::AttemptReport> r1 = j.run_next();
        check(r1 && r1->end == pb::AttemptEnd::NotServed && r1->force_young && r1->strike == 0 && r1->alarms == 0 &&
                      !j.queue().excluded(peer),
              tag + ": the first attempt ends NotServed (no alarm, no token, no exclusion), the pair marked young" +
                      (r1 ? ": " + rep_desc(*r1) : ""));
        check(j.queue().size() == 1 && j.queue().pairs().front().young,
              tag + ": the pair is re-queued with the young mark (the next attempt runs the young path)");
        const std::optional<pb::AttemptReport> r2 = j.run_next();
        check(r2 && r2->end == pb::AttemptEnd::Completed && r2->server == peer && r2->span.young && j.adopted() &&
                      digest_of(*j.adopted(), at_pos(a, L)) == dL,
              tag + ": the pair's next attempt runs the young path at the same server and completes; J's digest == A's" +
                      (r2 ? ": " + rep_desc(*r2) : ""));
        check(j.adopted() && j.adopted()->young && j.adopted()->span_claims == 0 && j.adopted()->claimed.empty(),
              tag + ": the young result holds no claim");
    }
}

void claims() {
    JoinNet net(900);
    KatNode a(net, kJ0);
    const RaceChain rc = grow_race(a);
    const std::uint64_t L = 4600, x0 = 1265, x1 = 2436;
    const pb::Hash32 dL = digest_of(a, at_pos(a, L));
    const auto honest = [&](std::uint64_t id) {
        auto s = std::make_unique<KatServer>(a, id);
        s->top = L;
        return s;
    };
    // (honest) the race chain joins, s placed as a claim, the side-block P_r fetched as at a full node
    {
        auto h = honest(100);
        JoinerEnv je(net);
        je.hidden.insert(rc.alt_pr);
        pb::Joiner j(je.in, kP53);
        j.offer(h->best_id(), *h);
        const auto reps = run_until(j);
        const auto it = reps.find(100);
        check(it != reps.end() && it->second.end == pb::AttemptEnd::Completed && it->second.span.x0 == x0 &&
                      it->second.span.x1 == x1,
              "claims: the race chain joins" + (it != reps.end() ? ": " + rep_desc(it->second) : ""));
        check(j.adopted() && j.adopted()->tree->find(rc.s) != nullptr && digest_of(*j.adopted(), at_pos(a, L)) == dL,
              "claims: the side carrier s below x1 placed (a claim); J's digest == A's");
        check(je.ctx_fetches >= 1 && !j.queue().excluded(100),
              "forged Boundary (peer-served data): a span receipt's P_r on a Monero side block is fetched as at a full "
              "node, the attempt completes, its server not excluded");
    }
    // span claims (i): one span carrier's blob with substituted side_data (a carried receipt omitted, receipts_root
    // refolded): alarm at the first mismatching computed row, 0 tokens, the span from the next server
    {
        const std::uint64_t x = 2001;  // carries a receipt (x % 3 == 0 is 2001? 2001 = 3 x 667)
        const pb::Hash32 cx = at_pos(a, x);
        auto f = honest(101), h = honest(102);
        const pb::RatchetState s_prev = a.node(at_pos(a, x - 1)).rs;
        edit_carrier(*f, cx, [&](pb::CarrierBodyV3& c) {
            c.carried.clear();
            c.own.side.receipts_root = pb::carrier_receipts_root_over(std::vector<pb::Hash32>{}, s_prev);
        });
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(f->best_id(), *f);
        j.offer(h->best_id(), *h);
        const auto reps = run_until(j);
        const auto it = reps.find(101);
        check(!a.bodies.get(cx)->carried.empty() && it != reps.end() && it->second.end == pb::AttemptEnd::Alarm &&
                      it->second.strike == 0 && it->second.at == x + 1 && j.queue().excluded(101),
              "span claims (i): alarm + DEFER at the first mismatching computed row (the fold at x + 1), 0 tokens, no BAN" +
                      (it != reps.end() ? ": " + rep_desc(it->second) : ""));
        check(j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == dL, "span claims (i): J reaches A's digest from the next server");
    }
    // span claims (ii): a substituted mmr_root on c_L with fetch B's buckets proved against it (a forged leaf):
    // alarm inside the replay, 0 tokens; A's digest from the next server
    {
        auto f = honest(103), h = honest(104);
        const pb::Hash32 cl = at_pos(a, L);
        const std::uint64_t lc = lc_of(a.node(at_pos(a, L - 1)).H);
        const std::uint64_t bad_bin = a.node(at_pos(a, x0 - 1)).H;  // a fetch-B bin
        const pb::LaneView v = a.store.view_at(cl);
        const pb::SealedBin* hb = v.bucket(bad_bin);
        auto forged_sb = std::make_shared<pb::SealedBin>(*hb);
        {
            std::vector<pb::WinEntry> es;
            for (const pb::BucketRow& row : hb->bucket.rows) {
                pb::WinEntry e;
                e.miner = row.miner;
                e.work = 2 * pb::kRuledLaneParams.d_min;
                es.push_back(e);
            }
            forged_sb->bucket = pb::seal_from_entries(bad_bin, es);
            forged_sb->leaf = pb::mmr_leaf_of(forged_sb->bucket);
        }
        auto fm = std::make_shared<pb::BinMmr>();
        for (std::uint64_t i = 0; i < lc; ++i)
            fm->append(i == bad_bin - kLaneB0 ? forged_sb->leaf : a.store.best_mmr().leaf(i).value());
        const pb::Hash32 forged_root = fm->root();
        edit_carrier(*f, cl, [=](pb::CarrierBodyV3& c) { c.own.side.mmr_root = forged_root; });
        f->on_buckets = [&, fm, forged_sb, cl, lc, bad_bin](const pb::GetBuckets& q, pb::BucketFrames& out) {
            if (q.at != cl) return;
            pb::BucketServeSource src;
            src.b0 = kLaneB0;
            src.leaf_count = lc;
            src.mmr = fm.get();
            src.bucket = [&, forged_sb, bad_bin](std::uint64_t bin) -> const pb::SealedBin* {
                return bin == bad_bin ? forged_sb.get() : a.store.view_at(cl).bucket(bin);
            };
            src.s_parent = pb::encode_ratchet_state(a.node(at_pos(a, L - 1)).rs);
            out.frames = pb::serve_buckets_from(src, q, KatServer::frame_bytes(), UINT64_MAX / 4);
        };
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(f->best_id(), *f);
        j.offer(h->best_id(), *h);
        const auto reps = run_until(j);
        const auto it = reps.find(103);
        check(it != reps.end() && it->second.end == pb::AttemptEnd::Alarm && it->second.strike == 0 && it->second.at > x0 &&
                      it->second.at <= x1 + 1 && j.queue().excluded(103),
              "span claims (ii): a forged leaf of fetch B -> alarm inside the replay at the first root that covers it "
              "(at or before x1 + 1), 0 tokens" + (it != reps.end() ? ": " + rep_desc(it->second) : ""));
        check(j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == dL, "span claims (ii): J reaches A's digest from the next server");
    }
    // every mmr_root of the span: a substituted mmr_root at x0 + 1 (its #13 not run by the pipeline below x1)
    {
        auto f = honest(105), h = honest(106);
        edit_carrier(*f, at_pos(a, x0 + 1), [](pb::CarrierBodyV3& c) { c.own.side.mmr_root[0] ^= 1; });
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(f->best_id(), *f);
        j.offer(h->best_id(), *h);
        const auto reps = run_until(j);
        const auto it = reps.find(105);
        check(it != reps.end() && it->second.end == pb::AttemptEnd::Alarm && it->second.at == x0 + 1 && it->second.strike == 0,
              "every span mmr_root: a wrong mmr_root at x0 + 1 -> alarm there" + (it != reps.end() ? ": " + rep_desc(it->second) : ""));
        check(j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == dL, "every span mmr_root: J joins from the next server");
    }
    // ended attempt (it leaves nothing): attempt 1 from a forging server ends on an alarm; attempt 2 over the same tip ids joins
    {
        auto f = honest(107), h = honest(108);
        edit_carrier(*f, at_pos(a, x1 - 2), [&](pb::CarrierBodyV3& c) {
            c.own.side.payee = net.ids[21];
            c.own.payee = net.refs[21];
        });
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(f->best_id(), *f);
        j.offer(h->best_id(), *h);
        const auto reps = run_until(j);
        const auto it = reps.find(107);
        check(it != reps.end() && it->second.end == pb::AttemptEnd::Alarm && it->second.at == x1 + 1,
              "ended attempt: a substituted payee below x1 -> alarm at the first computed #9" +
                      (it != reps.end() ? ": " + rep_desc(it->second) : ""));
        const auto it2 = reps.find(108);
        check(it2 != reps.end() && it2->second.end == pb::AttemptEnd::Completed && j.adopted() &&
                      digest_of(*j.adopted(), at_pos(a, L)) == dL,
              "ended attempt: attempt 2 over the same tip ids reaches A's digest (nothing of attempt 1 kept)" +
                      (it2 != reps.end() ? ": " + rep_desc(it2->second) : ""));
    }
    // the PRE (RULED 43; E-75 (ii)): work moved between two PRE entries changes d_at at a computed position inside
    // the replay: alarm, 0 tokens, the next server; no template during the replay
    {
        auto f = honest(109), h = honest(110);
        const std::uint64_t delta = 18000;
        edit_carrier(*f, at_pos(a, x0 - 2), [&](pb::CarrierBodyV3& c) { c.own.side.t_origin -= delta; });
        edit_carrier(*f, at_pos(a, x0 - 1), [&](pb::CarrierBodyV3& c) { c.own.side.t_origin += delta; });
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        bool claims_during = true;
        j.set_on_step([&](pb::JoinedState&, std::uint64_t) { claims_during = claims_during && j.rests_on_claims(); });
        j.offer(f->best_id(), *f);
        j.offer(h->best_id(), *h);
        const auto reps = run_until(j);
        const auto it = reps.find(109);
        check(it != reps.end() && it->second.end == pb::AttemptEnd::Alarm && it->second.row == pb::RowId::R9 &&
                      it->second.at == x0 + kNrt - 1 && it->second.at > x1 + 1 && it->second.at < L && it->second.strike == 0,
              "PRE: a PRE shift -> alarm at the computed S1.3 #8 at x0 + N_rt - 1 (inside the replay, after the first "
              "computed #9), 0 tokens" + (it != reps.end() ? ": " + rep_desc(it->second) : ""));
        check(claims_during, "PRE: no template during the first replay (rests_on_claims)");
        check(j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == dL, "PRE: J reaches A's digest from the next server");
    }
    // boundary in span: an adversarial chain whose span carrier carries a receipt forked J_0 + 1 below its parent
    // -> J DEFERs it as A does
    {
        KatNode& b = *rc.b;
        KatServer f(b, 111);
        f.top = L;
        auto h = honest(112);
        const pb::AdmitResult ra = pb::admit_carrier(b.env(), frame_of(*b.bodies.get(rc.deep)), pb::CarrierRole::Closure);
        check(ra.verdict == pb::AdmitVerdict::Defer && ra.missing == pb::Missing::Boundary,
              "boundary in span: a full node DEFERs the carrier (Boundary): " + desc(ra));
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(f.best_id(), f);
        j.offer(h->best_id(), *h);
        const auto reps = run_until(j);
        const auto it = reps.find(111);
        check(it != reps.end() && it->second.end == pb::AttemptEnd::Unplaceable && it->second.at == rc.c_deep &&
                      it->second.missing == pb::Missing::Boundary && it->second.alarms == 0,
              "boundary in span: J DEFERs it as A does (Boundary), nothing to fetch: the attempt ends, no alarm" +
                      (it != reps.end() ? ": " + rep_desc(it->second) : ""));
        check(j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == dL, "boundary in span: J joins from the next server");
    }
    // forged Boundary in the replay: the attempt's server serves s with its parent link J_0 + 1 below the
    // parent of the span carrier that carries a receipt on s -> unplaceable, the attempt ends (no alarm, 0 tokens),
    // the server not asked again; J joins from the next server
    {
        auto f = honest(113), h = honest(114);
        const std::uint64_t deep = rc.c_s - 1 - kJ0 - 1;
        const pb::Hash32 dp = at_pos(a, deep);
        const auto prev_h = f->on_headers;
        f->on_headers = [&, dp](const pb::Hash32& stop, pb::ChainHeaders& out) {
            for (pb::CarrierHeader& hh : out.headers)
                if (pb::receipt_id(hh.own) == rc.s) hh.own.side.tip = dp;
        };
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(f->best_id(), *f);
        j.offer(h->best_id(), *h);
        const auto reps = run_until(j);
        const auto it = reps.find(113);
        check(deep >= x0 - 1 && it != reps.end() && it->second.end == pb::AttemptEnd::Unplaceable &&
                      it->second.at == rc.c_s && it->second.alarms == 0 && it->second.strike == 0 && j.queue().excluded(113),
              "forged Boundary: J DEFERs c, nothing left to fetch: the attempt ends (no alarm, 0 tokens), the server "
              "excluded" + (it != reps.end() ? ": " + rep_desc(it->second) : ""));
        check(j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == dL &&
                      follow(*j.adopted(), a, L, L + 200) && digest_of(*j.adopted(), at_pos(a, L + 200)) == digest_of(a, at_pos(a, L + 200)),
              "forged Boundary: J reaches A_full's digest at L + 200 from the next server");
    }
    // one variant per id and attempt: a second, different variant of a side carrier id; a second body set
    {
        auto f1 = honest(115), f2 = honest(116), h = honest(117);
        f1->on_headers = [&](const pb::Hash32&, pb::ChainHeaders& out) {
            for (std::size_t i = 0; i < out.headers.size(); ++i)
                if (pb::receipt_id(out.headers[i].own) == rc.s) {
                    pb::CarrierHeader v2 = out.headers[i];
                    v2.own.side.ballot ^= 1;
                    out.headers.push_back(v2);
                    break;
                }
        };
        f2->on_bodies = [&](const std::vector<pb::Hash32>& ids, pb::CarrierFrames& out) {
            if (ids.size() == 1 && ids[0] == rc.s && !out.bodies.empty()) {
                pb::CarrierBodyV3 b2 = out.bodies[0];
                b2.carried.clear();
                out.bodies.push_back(b2);
            }
        };
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(f1->best_id(), *f1);
        j.offer(f2->best_id(), *f2);
        j.offer(h->best_id(), *h);
        const auto reps = run_until(j);
        for (std::uint64_t sv : {115, 116}) {
            const auto it = reps.find(sv);
            check(it != reps.end() && it->second.end == pb::AttemptEnd::Contradiction && it->second.alarms == 0 &&
                          it->second.strike == 0 && j.queue().excluded(sv),
                  "one variant per id and attempt (server " + std::to_string(sv) +
                          "): a second variant / body set -> the attempt ends, no alarm, no token, excluded" +
                          (it != reps.end() ? ": " + rep_desc(it->second) : ""));
        }
        check(j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == dL, "one variant per id: J joins from the next server");
        pb::HeaderIndex hi;
        pb::CarrierHeader v = pb::header_of(*a.bodies.get(rc.s)), w = v;
        w.own.side.ballot ^= 1;
        hi.add(1, v, a.node(rc.s).h);
        hi.add(2, w, a.node(rc.s).h);
        check(hi.variants(rc.s).size() == 2, "one variant per id: another peer's different variant is held by 1.6 (b)");
    }
    lost_race(net);        // ruling 47: the retarget-prefix headers as claimed nodes (E-84)
    span_claims_iii(net);  // ruling 47: S(f) for a side branch forking below x0 - 1 (E-83)
    span_claims_iii_carried(net);  // the same with a side carrier that carries a receipt (the fold over its carried list)
    span_fold_lc0(net);    // ruling 47 at lc(tip(at)) = 0: the young fallback (the record)
}

// ---------------------------------------------------------------------------
// attempts: what ends an attempt (ruling 44 item (3); E-78), the attempt's L and
// the server's held floor (3.3 step 2a, P-51), the attempt order (P-52)
// ---------------------------------------------------------------------------
// A chain whose carriers have the roots of their own windows and NO canonical
// coinbase (a fake: Monero blocks would not commit the canonical split),
// placed without admission.
void grow_fake(KatNode& n, std::uint64_t count, std::uint64_t nonce0) {
    pb::Hash32 prev = n.tree.best().id;
    const std::uint64_t base = n.node(prev).pos;
    for (std::uint64_t i = 1; i <= count; ++i) {
        const std::uint64_t x = base + i;
        pb::CarrierBodyV3 c;
        c.own = body_on(n, prev, h_pos(x), x % 4, nonce0 + x,
                        [&](pb::ReceiptBodyV3& r) { r.side.receipts_root = n.tree.next_receipts_root(prev, {}).value_or(pb::Hash32{}); },
                        {}, false);
        if (place_direct(n, c).outcome != pb::WriteOutcome::Extended) {
            check(false, "grow_fake: not placed at " + std::to_string(x));
            return;
        }
        prev = pb::receipt_id(c.own);
    }
}

void attempts() {
    JoinNet net(900);
    KatNode a(net, kJ0);
    grow(a, 4810);
    const std::uint64_t L = 4600, x0 = 1265;
    const pb::Hash32 dL = digest_of(a, at_pos(a, L));
    // the attempt's server withholds: no reply after x0 + 10; NotServed for fetch B; a short FC_HEADERS reply.
    // Each ends the attempt as non-service: no alarm, no token, the pair re-queued; FC_BUCKETS prefixes are continued.
    {
        KatServer w1(a, 121), w2(a, 122), sh(a, 123), sp(a, 124), h(a, 125);
        for (KatServer* x : {&w1, &w2, &sh, &sp, &h}) x->top = L;
        w1.carriers_withheld = [&](std::uint64_t pos) { return pos > x0 + 10 && pos < L; };
        w1.stall_after = 3000;
        const pb::Hash32 cl = at_pos(a, L);
        w2.on_buckets = [&](const pb::GetBuckets& q, pb::BucketFrames& out) {
            if (q.at == cl) {
                out.frames = {pb::encode_buckets_not_served(0, q.at)};
            }
        };
        sh.on_headers = [](const pb::Hash32&, pb::ChainHeaders& out) {
            const std::size_t cut = out.headers.size() / 2;
            if (cut > 0) {
                out.headers.erase(out.headers.begin(), out.headers.begin() + static_cast<std::ptrdiff_t>(cut));
                out.first_pos += cut;
            }
        };
        sp.on_buckets = [&](const pb::GetBuckets& q, pb::BucketFrames& out) {  // one bin per reply (a prefix)
            out.frames = pb::serve_buckets(a.store, pb::GetBuckets{0, q.at, q.bin_lo, q.bin_lo},
                                           pb::encode_ratchet_state(a.node(a.node(q.at).parent).rs), KatServer::frame_bytes(),
                                           UINT64_MAX / 4);
        };
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        for (KatServer* x : {&w1, &w2, &sh}) j.offer(x->best_id(), *x);
        std::map<std::uint64_t, pb::AttemptReport> reps;
        for (int i = 0; i < 3; ++i)
            if (std::optional<pb::AttemptReport> r = j.run_next()) reps.insert_or_assign(r->server, std::move(*r));
        const auto ns = [&](std::uint64_t sv, const std::string& what) {
            const auto it = reps.find(sv);
            check(it != reps.end() && it->second.end == pb::AttemptEnd::NotServed && it->second.alarms == 0 &&
                          it->second.strike == 0 && !j.queue().excluded(sv),
                  what + " -> the attempt ends NotServed, no alarm, no token, no exclusion" +
                          (it != reps.end() ? ": " + rep_desc(it->second) : ""));
        };
        ns(121, "withholds: no reply after x0 + 10");
        check(reps.count(121) && reps.at(121).what == "bodies not served" && reps.at(121).at < x0 + 11 &&
                      w1.last_timeout == kP53,
              "withholds: the attempt ended at the abandon timeout of the body request past x0 + 10 (P-53 per request)");
        ns(122, "withholds: NotServed for fetch B");
        ns(123, "E-78: a short FC_HEADERS reply");
        bool requeued = true;
        for (std::uint64_t sv : {121, 122, 123}) {
            bool in = false;
            for (const auto& p : j.queue().pairs()) in = in || p.server == sv;
            requeued = requeued && in;
        }
        check(requeued, "withholds: each pair queued again at the end (P-52)");
        j.offer(sp.best_id(), sp);
        j.offer(h.best_id(), h);
        // the re-queued pairs come first again; then the prefix server completes
        std::optional<pb::AttemptReport> last;
        for (int i = 0; i < 6 && !j.adopted(); ++i) last = j.run_next();
        check(j.adopted() && last && last->server == 124 && sp.bucket_requests > 2,
              "an FC_BUCKETS prefix (one bin per reply) is continued at the same server: the attempt completes" +
                      (last ? ": " + rep_desc(*last) : ""));
        check(h.requests == 0 && j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == dL,
              "withholds: J reaches A's digest from the next server, with one server's data only");
    }
    // a header whose P_r the follower does not hold and no peer serves (FB_GETCTX not resolved within the abandon
    // timeout): the header phase ends the attempt as non-service, before any body (never read as height 0); with the
    // block served, the next attempt of the pair completes
    {
        KatServer s(a, 126);
        s.top = L;
        const pb::Hash32 pr = a.bodies.get(at_pos(a, L))->own.blob.prev_id;
        JoinerEnv je(net);
        je.hidden.insert(pr);
        je.unservable.insert(pr);
        pb::Joiner j(je.in, kP53);
        j.offer(s.best_id(), s);
        const std::optional<pb::AttemptReport> r = j.run_next();
        check(r && r->end == pb::AttemptEnd::NotServed && r->what == "a header's P_r not resolved" && r->alarms == 0 &&
                      r->strike == 0 && !j.queue().excluded(126) && j.queue().size() == 1 && s.body_requests == 0 &&
                      s.bucket_requests == 0,
              "unresolved P_r: the header phase ends the attempt NotServed (no body asked, no alarm, no token, re-queued)" +
                      (r ? ": " + rep_desc(*r) : ""));
        je.unservable.erase(pr);
        const std::optional<pb::AttemptReport> r2 = j.run_next();
        check(r2 && r2->end == pb::AttemptEnd::Completed && j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == dL,
              "unresolved P_r: with the block served, the pair's next attempt completes and reaches A's digest" +
                      (r2 ? ": " + rep_desc(*r2) : ""));
    }
    // the attempt's L from the server's reply; the server holds its P-51 floor for the open attempt. The chain
    // is long enough that the header floor (the prefix start, ruling 53) lies above position 1, so a floor taken at
    // the moved tip would cut the attempt's retarget prefix.
    {
        grow(a, 6100 - 4810);
        const std::uint64_t Lm = 6000;  // above the serving note's region (L >= 5,640 at 12 per height)
        KatServer m(a, 131);
        m.retention = true;
        m.top = Lm;
        const pb::Hash32 hello = m.best_id();
        const std::uint64_t floor_hello = m.floors_now().headers;
        m.top = Lm + 24;
        const std::uint64_t floor_moved = m.floors_now().headers;
        m.top = Lm;
        check(floor_hello > 1 && floor_moved > floor_hello,
              "moved tip: the header floor binds (" + std::to_string(floor_hello) + " at the HELLO tip, " +
                      std::to_string(floor_moved) + " after the moves)");
        m.before = [&](KatServer& k) {
            if (k.requests == 1) k.top = Lm + 12;       // the tip moved one Monero height since its HELLO
            else if (k.requests == 2) k.top = Lm + 24;  // and again after the attempt's first reply
        };
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(hello, m);
        const std::optional<pb::AttemptReport> r = j.run_next();
        check(r && r->end == pb::AttemptEnd::Completed && r->L == Lm + 12,
              "moved tip: the attempt takes L from the server's reply and completes while the tip moves" +
                      (r ? ": " + rep_desc(*r) : ""));
        check(j.adopted() && digest_of(*j.adopted(), at_pos(a, Lm + 12)) == digest_of(a, at_pos(a, Lm + 12)),
              "moved tip: J's digest == A's at the attempt's L");
    }
    // a fake candidate: a chain of >= 3,336 carriers with no canonical coinbase, offered by three servers
    // before the honest one: every attempt on it ends at its first computed #9; J joins the honest chain; a fourth
    // fake server joining after that changes nothing; P-52 (the pair queue): a server naming the honest tip that forges is
    // excluded, and the honest pair is next whatever stream of new candidates follows
    {
        KatNode fk(net, kJ0);
        grow_fake(fk, 4610, 600000);
        std::vector<std::unique_ptr<KatServer>> fakes;
        for (std::uint64_t k = 0; k < 8; ++k) {
            fakes.push_back(std::make_unique<KatServer>(fk, 140 + k));
            fakes.back()->top = 4600 - k;  // a new candidate each
        }
        KatServer h(a, 139);
        h.top = L;
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        const pb::U128 big{~std::uint64_t{0}, 1};
        for (std::uint64_t k = 0; k < 3; ++k) j.offer(fakes[0]->best_id(), *fakes[k], big);
        j.offer(h.best_id(), h, pb::U128{1, 0});
        std::vector<pb::AttemptReport> reps;
        for (int i = 0; i < 8 && !j.adopted(); ++i) {
            if (std::optional<pb::AttemptReport> r = j.run_next()) reps.push_back(std::move(*r));
            j.offer(fakes[3 + std::min<std::size_t>(i, 4)]->best_id(), *fakes[3 + std::min<std::size_t>(i, 4)], big);  // a stream
        }
        bool first9 = reps.size() >= 3;
        for (std::size_t i = 0; i < 3 && i < reps.size(); ++i)
            first9 = first9 && reps[i].end == pb::AttemptEnd::Alarm && reps[i].at == reps[i].span.x1 + 1 && reps[i].strike == 0;
        check(first9, "fake candidate: every attempt on it ends at its first computed #9 (x1 + 1), 0 tokens" +
                              (reps.empty() ? std::string() : ": " + rep_desc(reps[0])));
        check(reps.size() == 4 && j.adopted() && reps.back().server == 139 && digest_of(*j.adopted(), at_pos(a, L)) == dL,
              "fake candidate: J joins the honest chain after the three fake servers, whatever stream follows (claimed work orders nothing)");
        const pb::Hash32 tip0 = j.adopted() ? j.adopted()->tip() : pb::Hash32{};
        for (int i = 0; i < 2; ++i) (void)j.run_next();
        check(j.adopted() && j.adopted()->tip() == tip0, "fake candidate: a fake server joining after that changes nothing");
    }
    {
        // P-52: a P0 server names H first and the honest server names H next, both before the stream; the P0 server
        // forges (excluded); then one new candidate per attempt: H is attempted at the honest server next
        KatNode fk(net, kJ0);
        grow_fake(fk, 4610, 700000);
        KatServer p0(a, 151), h(a, 152);
        p0.top = L;
        h.top = L;
        edit_carrier(p0, at_pos(a, 2000), [&](pb::CarrierBodyV3& c) {
            c.own.side.payee = net.ids[22];
            c.own.payee = net.refs[22];
        });
        std::vector<std::unique_ptr<KatServer>> stream;
        for (std::uint64_t k = 0; k < 6; ++k) {
            stream.push_back(std::make_unique<KatServer>(fk, 160 + k));
            stream.back()->top = 4600 - k;
        }
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(p0.best_id(), p0);
        j.offer(h.best_id(), h);
        std::vector<pb::AttemptReport> reps;
        for (std::size_t i = 0; i < 6 && !j.adopted(); ++i) {
            j.offer(stream[i]->best_id(), *stream[i]);
            if (std::optional<pb::AttemptReport> r = j.run_next()) reps.push_back(std::move(*r));
        }
        check(reps.size() == 2 && reps[0].server == 151 && reps[0].end == pb::AttemptEnd::Alarm && j.queue().excluded(151) &&
                      reps[1].server == 152 && j.adopted(),
              "starved candidate: the forging P0 server excluded, H attempted at the honest server next, J joins");
    }
}

// ---------------------------------------------------------------------------
// candidates: the candidate rule (E-77 as ruling 45 amends it), the two states
// (3.3a), no re-pend on a switch by the joiner path, a joined node's own switch
// ---------------------------------------------------------------------------
// A full node's own chain as A (a deep switch): every carrier's #9 its own.
struct FullChain final : pb::AdoptedChain {
    KatNode* n;
    mutable pb::Hash32 profile_tip{};
    mutable std::shared_ptr<const pb::BoundWork> profile;
    explicit FullChain(KatNode& k) : n(&k) {}
    bool holds(const pb::Hash32& id) const override { return n->tree.find(id) != nullptr; }
    bool on_chain(const pb::Hash32& id) const override {
        const pb::CarrierNode* c = n->tree.find(id);
        return c != nullptr && n->store.best_at(c->pos) == id;
    }
    std::optional<std::uint64_t> pos_of(const pb::Hash32& id) const override {
        const pb::CarrierNode* c = n->tree.find(id);
        if (c == nullptr) return std::nullopt;
        return c->pos;
    }
    std::optional<std::uint64_t> joined_x1() const override { return std::nullopt; }
    std::uint64_t store_base() const override { return n->store.base_pos(); }
    // the KAT's profile: walked once per best tip
    std::shared_ptr<const pb::BoundWork> bound_work() const override {
        if (profile && profile_tip == n->store.best_tip()) return profile;
        auto w = std::make_shared<pb::BoundWork>();
        for (std::uint64_t x = n->store.tip_pos(); x >= 1; --x) {
            const pb::CarrierNode* c = n->tree.find(*n->store.best_at(x));
            w->add(c->h, c->d);
        }
        profile = w;
        profile_tip = n->store.best_tip();
        return profile;
    }
    pb::Hash32 tip() const override { return n->store.best_tip(); }
    std::uint64_t open_placements() const override { return pb::open_bin_placements(n->store); }
};

pb::Hash32 hid(std::uint8_t b) { pb::Hash32 h{}; h.fill(b); return h; }

void candidates() {
    // the rule on profiles: (b) a stale fake, (d) equal work, the U128 extreme
    {
        pb::BoundWork cur, stale;
        for (std::uint64_t h = 300; h <= 400; ++h) cur.add(h, 12 * 18180);
        for (std::uint64_t h = 100; h <= 200; ++h) stale.add(h, 40 * 18180);
        check(pb::candidate_replaces(cur, hid(9), stale, hid(1)) && !pb::candidate_replaces(stale, hid(1), cur, hid(9)),
              "candidates (b): a stale fake (its bound part below the honest one's) has 0 from h_f: the honest is followed");
        pb::BoundWork e1, e3;
        for (std::uint64_t h = 10; h <= 20; ++h) e1.add(h, 1000);
        for (std::uint64_t h = 15; h <= 20; ++h) e3.add(h, 1000);
        check(pb::candidate_replaces(e3, hid(2), e1, hid(3)) && !pb::candidate_replaces(e3, hid(4), e1, hid(3)),
              "candidates (d): equal bound work from h_f up -> the lower tip id");
        // 2^16 carriers at d = 2^64 - 1, one per height, against one such carrier at the same lowest height: the
        // sum 2^80 - 2^16 in U128 (a u64 sum would wrap below the single carrier's 2^64 - 1)
        pb::BoundWork big, one;
        for (std::uint64_t k = 0; k < (1u << 16); ++k) big.add(1000 + k, UINT64_MAX);
        one.add(1000, UINT64_MAX);
        const pb::U128 sum = big.from(1000);
        check(sum.hi == (1u << 16) - 1 && sum.lo == UINT64_MAX - ((1u << 16) - 1),
              "bound work in U128: 2^16 carriers at d = 2^64 - 1 sum to 2^80 - 2^16 (no wrap)");
        check(pb::candidate_replaces(big, hid(9), one, hid(1)) && !pb::candidate_replaces(one, hid(1), big, hid(9)),
              "bound work in U128: the 2^16 carriers outweigh one carrier at d = 2^64 - 1");
    }
    // (c) a stream of new candidates offered after the honest one (lower tip ids, more claimed work): the honest
    // pair is tried next (P-52)
    {
        pb::AttemptQueue q;
        q.offer(hid(0x80), 1, pb::U128{1, 0});
        for (std::uint8_t k = 1; k < 9; ++k) q.offer(hid(k), 10 + k, pb::U128{~std::uint64_t{0}, 7});
        const std::optional<pb::AttemptQueue::Pair> p = q.next();
        check(p && p->candidate == hid(0x80) && p->server == 1, "candidates (c): the honest pair is tried next (neither tip id nor claimed work orders)");
        q.offer(hid(0x80), 1);
        check(q.size() == 8, "P-52: each pair attempted once (an offer of an attempted pair is not queued again)");
        q.exclude(12);
        q.offer(hid(0x77), 12);
        bool none12 = true;
        for (const auto& x : q.pairs()) none12 = none12 && x.server != 12;
        check(none12 && q.size() == 7, "P-52: an excluded server's pairs and later offers are dropped");
    }
    JoinNet net(900);
    KatNode a(net, kJ0);
    std::unique_ptr<KatNode> fork;
    grow(a, 2436);
    fork = std::make_unique<KatNode>(a);
    grow(a, 5410 - 2436);
    // (a) a P< fake (real PoW at d_min, 10 carriers per Monero height, one receipt per carrier) completes first and
    // is adopted; the honest candidate then completes and replaces it although the fake grew during the attempt
    {
        KatNode p(net, kJ0);
        ChainShape ps;
        ps.hof = [](std::uint64_t x) { return kLaneB0 + x / 10; };
        ps.carry_every = 1;
        ps.nonce0 = 400000;
        grow(p, 5100, ps);
        KatServer sp(p, 171), sh(a, 172);
        sp.top = 4500;
        sh.top = 5400;
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(sp.best_id(), sp, pb::U128{~std::uint64_t{0}, 9});
        j.offer(sh.best_id(), sh, pb::U128{1, 0});
        const std::optional<pb::AttemptReport> r1 = j.run_next();
        check(r1 && r1->end == pb::AttemptEnd::Completed && j.adopted() && j.last_switch().adopted && !j.rests_on_claims(),
              "candidates (a): the fake completes first and is adopted (J builds templates on it)" + (r1 ? ": " + rep_desc(*r1) : ""));
        if (!j.adopted()) return;
        check(digest_of(*j.adopted(), at_pos(p, 4500)) == digest_of(p, at_pos(p, 4500)), "candidates (a): J's state == the fake's");
        // the fake keeps growing while the honest attempt runs (A follows it as a full node)
        std::uint64_t next = 4500;
        pb::BoundWork a_end;  // A's profile at the end of the honest attempt (the test)
        pb::Hash32 a_end_tip{};
        j.set_on_step([&](pb::JoinedState&, std::uint64_t x) {
            if (x % 6 == 0 && next < 5100 && follow(*j.adopted(), p, next, next + 1, 9)) ++next;
            a_end = *j.adopted()->bound_work();
            a_end_tip = j.adopted()->tip();
        });
        const std::optional<pb::AttemptReport> r2 = j.run_next();
        j.set_on_step({});
        check(next >= 4900, "candidates (a): the fake grew by " + std::to_string(next - 4500) + " carriers during the honest attempt");
        if (r2 && j.adopted() && j.last_switch().replaced) {
            const pb::BoundWork hw = *j.adopted()->bound_work();
            const pb::Hash32 ht = j.adopted()->tip();
            check(!pb::candidate_replaces(hw, ht, a_end, a_end_tip),
                  "candidates (a): read at the test, A's grown profile would keep the fake (the growth flips the rule)");
        }
        check(r2 && r2->end == pb::AttemptEnd::Completed && r2->a_profile_read && j.last_switch().replaced,
              "candidates (a): the honest candidate completes and replaces the fake (A's profile read when the attempt took its L)" +
                      (r2 ? ": " + rep_desc(*r2) : ""));
        check(j.adopted() && j.adopted()->pending.empty() && j.last_switch().lost > 0,
              "no re-pend: the switch by the joiner path re-pends nothing (pending set empty); the abandoned open-bin "
              "placements are counted lost (" + std::to_string(j.last_switch().lost) + ")");
        check(j.adopted() && digest_of(*j.adopted(), at_pos(a, 5400)) == digest_of(a, at_pos(a, 5400)),
              "candidates (a): J's digest == A_full's after the replacement");
    }
    // the stale top (ruling 45): J adopts the honest chain at L_A; a P< server mines k carriers on x1_A at the
    // height h(x1_A + 1) until their work there exceeds A's there; J completes that attempt and keeps A
    {
        const std::uint64_t LA = 4600, x1a = 2436;
        KatServer sh(a, 181);
        sh.top = LA;
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(sh.best_id(), sh);
        (void)j.run_next();
        check(j.adopted() && j.adopted()->x1 == x1a, "stale top: J adopts the honest A at L_A");
        const std::uint64_t h1 = a.node(at_pos(a, x1a + 1)).h;
        std::uint64_t at_h1 = 0;
        for (std::uint64_t x = x1a + 1; a.node(at_pos(a, x)).h == h1; ++x) ++at_h1;
        const std::uint64_t k = at_h1 + 2;
        KatNode& f = *fork;
        for (std::uint64_t i = 0; i < k; ++i) {
            const pb::Hash32 tip = f.tree.best().id;
            const pb::CarrierBodyV3 c = carrier_on(f, tip, h1, {}, i % 4, 500000 + i);
            check(admit_place(f, c).placed, "stale top: the P< carrier " + std::to_string(i) + " placed");
        }
        KatServer sf(f, 182);
        j.offer(sf.best_id(), sf);
        const std::optional<pb::AttemptReport> r = j.run_next();
        check(r && r->end == pb::AttemptEnd::Completed && !j.last_switch().replaced && j.adopted()->tip() == at_pos(a, LA),
              "stale top: J completes the fork's attempt and keeps A" + (r ? ": " + rep_desc(*r) : ""));
        check(j.adopted() && follow(*j.adopted(), a, LA, LA + 600) &&
                      digest_of(*j.adopted(), at_pos(a, LA + 600)) == digest_of(a, at_pos(a, LA + 600)),
              "stale top: J's digest == A_full's at L_A + 600");
        // two states: while each attempt of a stream runs, A builds templates equal to A_full's, judges every peer's copy
        // and no attempt's cache is A's; a candidate whose tip A holds is no candidate
        KatNode fk(net, kJ0);
        grow_fake(fk, 4610, 800000);
        pb::JoinedState& A = *j.adopted();
        const pb::Hash32 atip = A.tip();
        const pb::TipWindow full_w = a.window(atip, 16);
        bool steps = false, ok_claims = true, ok_tpl = true, ok_copies = true, own_caches = true;
        j.set_on_step([&](pb::JoinedState& st, std::uint64_t) {
            steps = true;
            ok_claims = ok_claims && !j.rests_on_claims();
            const pb::TipWindow w = A.windows().get(atip, 16, [&] {
                return pb::evaluate_window_at(*A.store, atip, *A.prev_of(atip), *A.inputs().monero, 16, net.author_id);
            });
            ok_tpl = ok_tpl && w.ok() && full_w.ok() && w.window_root == full_w.window_root;
            ok_copies = ok_copies && A.claims().judge_copy(999, pb::Hash32{});
            own_caches = own_caches && &st.windows() != &A.windows() && &st.keys() != &A.keys();
        });
        std::vector<std::unique_ptr<KatServer>> stream;
        for (std::uint64_t i = 0; i < 2; ++i) {
            stream.push_back(std::make_unique<KatServer>(fk, 190 + i));
            stream.back()->top = 4600 - i;
            j.offer(stream.back()->best_id(), *stream.back());
        }
        KatServer same(a, 195);
        same.top = LA + 300;  // a tip A holds
        j.offer(same.best_id(), same);
        std::vector<pb::AttemptReport> reps;
        for (int i = 0; i < 3; ++i)
            if (std::optional<pb::AttemptReport> rr = j.run_next()) reps.push_back(std::move(*rr));
        j.set_on_step({});
        check(reps.size() == 3 && reps[0].end == pb::AttemptEnd::Alarm && reps[1].end == pb::AttemptEnd::Alarm &&
                      reps[2].end == pb::AttemptEnd::OutOfScope,
              "two states: the stream's attempts run and end; a tip A holds is no candidate");
        check(same.header_requests >= 1 && same.body_requests == 0 && same.bucket_requests == 0,
              "two states: the attempt on a tip A holds ends before any body or bucket is asked (the fork is known first)");
        check(steps && ok_claims, "two states: rests_on_claims stays false while later attempts run (A's answer)");
        check(steps && ok_tpl, "two states: A builds templates equal to A_full's while the attempts run");
        check(steps && ok_copies, "two states: A judges every peer's copy while the attempts run");
        check(steps && own_caches, "two states: each state owns its own window and key cache instances");
        check(j.adopted() && j.adopted()->tip() == atip, "two states: no attempt changes A");
    }
    // the cache level (one instance per state, both legs): an entry the attempt state computed at tip t (substituted side_data) is not
    // A's: the window leg (key {tip, v}) and the key leg (same payees, another key reference)
    {
        JoinerEnv je(net);
        pb::JoinedState A(je.in, 1), att(je.in, 2);
        // t: a tip id no state of this KAT has looked up (each leg starts from empty entries)
        pb::Hash32 t = at_pos(a, 4000);
        t[31] ^= 0x5a;
        pb::TipWindow honest = a.window(at_pos(a, 4000), 16);
        honest.tip = t;  // the cache stores an evaluation under its own (tip, v)
        pb::TipWindow forged = honest;
        forged.window_root[0] ^= 1;
        (void)att.windows().get(t, 16, [&] { return forged; });
        const pb::TipWindow got = A.windows().get(t, 16, [&] { return honest; });
        check(got.window_root == honest.window_root, "two states (window leg): A computes its own entry at t");
        const std::vector<pb::Hash32> payees{net.ids[1], net.ids[2]};
        const pb::Hash32 pr = mon_block(kAnchorH + 300);
        const auto ka = att.keys().get(net.pool_id, t, pr, kAnchorH + 301, payees, false,
                                       [&](std::size_t i) -> std::optional<pb::XmrKeyRef> { return net.refs[i == 0 ? 3 : 2]; });
        const auto kb = A.keys().get(net.pool_id, t, pr, kAnchorH + 301, payees, false,
                                     [&](std::size_t i) -> std::optional<pb::XmrKeyRef> { return net.refs[i == 0 ? 1 : 2]; });
        check(ka.keys && kb.keys && !(ka.keys->keys == kb.keys->keys), "two states (key leg): A derives its own keys at t");
    }
    // a full node whose deep-switch trigger fires keeps its chain until a completed candidate replaces it
    {
        FullChain full(a);
        KatNode fk(net, kJ0);
        grow_fake(fk, 4610, 900000);
        KatServer sf(fk, 201);
        sf.top = 4600;
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.set_own_chain(&full);
        check(!j.rests_on_claims() && j.a() == &full, "deep switch: the full node's own chain is A");
        j.offer(sf.best_id(), sf);
        check(!j.rests_on_claims() && j.a() == &full, "deep switch: a trigger never discards A (templates go on)");
        const std::optional<pb::AttemptReport> r = j.run_next();
        check(r && r->end == pb::AttemptEnd::Alarm && j.a() == &full && !j.rests_on_claims(),
              "deep switch: the failed attempt leaves the full node's chain" + (r ? ": " + rep_desc(*r) : ""));
    }
    // a joined node's own switch at or below x1 takes the joiner path whatever its P-01
    {
        JoinerEnv je(net, 3000);  // P-01 raised above L - x1
        KatServer sh(a, 211);
        sh.top = 4600;
        pb::Joiner j(je.in, kP53);
        j.offer(sh.best_id(), sh);
        (void)j.run_next();
        check(j.adopted() != nullptr, "own switch: J joined with P-01 = 3,000");
        if (j.adopted()) {
            const pb::JoinedState& js = *j.adopted();
            check(js.store_base() < js.x1 && js.L - js.x1 < 3000, "own switch: the raised journal reaches below x1");
            check(pb::own_switch_path(js, js.x1 - 1) == pb::SwitchPath::Joiner,
                  "own switch: a heavier branch forking at x1 - 1 takes the joiner path, never a rewind");
            check(pb::own_switch_path(js, js.x1 + 100) == pb::SwitchPath::Rewind &&
                          pb::own_switch_path(js, js.store_base() - 1) == pb::SwitchPath::Joiner,
                  "own switch: above x1 and at or above the base a rewind; below the base the joiner path");
        }
    }
}

// ---------------------------------------------------------------------------
// scope: the fork of L with A's chain (3.3 step 2a, 3.3a (4)) when A holds a
// part of the candidate's branch as a side branch, for a full node's own chain
// and for a joined state; no body before the fork is known; A's bound-work
// profile kept along its chain; the lost count of a replaced own chain
// ---------------------------------------------------------------------------
void scope() {
    JoinNet net(900);
    ChainShape sb;
    sb.nonce0 = 7000000;
    // (full node) a and b share 3,000 carriers; a grows 2 per 1 of b while b's carriers are admitted into a's tree as
    // a side branch (the fork g = 3,000 at or above a's base); a grows to 4,200 (its base above g, the held side top at
    // or above the base) and b to 4,700 (heavier): b's tip at a's Joiner, a's own chain as A
    {
        KatNode a(net, kJ0);
        grow(a, 3000);
        KatNode b(a);
        std::uint64_t placed = 0;
        for (int i = 0; i < 560; ++i) {
            grow(a, 2);
            const std::vector<pb::Hash32> ids = grow(b, 1, sb);
            if (!ids.empty() && admit_place(a, *b.bodies.get(ids.back())).placed) ++placed;
        }
        const pb::Hash32 q = b.store.best_tip();  // the held side top
        // b's tip 40 carriers above it (not held by a) while g lies at or above a's base: out of scope at the first
        // reply, before any body
        grow(b, 40, sb);
        {
            FullChain full(a);
            KatServer s(b, 301);
            JoinerEnv je(net);
            pb::Joiner j(je.in, kP53);
            j.set_own_chain(&full);
            j.offer(s.best_id(), s);
            const std::optional<pb::AttemptReport> r = j.run_next();
            check(a.store.base_pos() <= 3000 && r && r->end == pb::AttemptEnd::OutOfScope && s.header_requests == 1 &&
                          s.body_requests == 0 && s.bucket_requests == 0 && !j.last_switch().replaced && j.a() == &full,
                  "scope (full node): a branch forking at or above A's base ends at its first reply (one FC_GETHEADERS), "
                  "before any body or bucket is asked; A kept (" + std::to_string(s.header_requests) + " header requests)" +
                          (r ? ": " + rep_desc(*r) : ""));
        }
        grow(a, 4200 - a.store.tip_pos());
        grow(b, 4700 - b.store.tip_pos(), sb);
        const pb::CarrierNode* qn = a.tree.find(q);
        const std::uint64_t base = a.store.base_pos();
        check(placed == 560 && qn != nullptr && a.store.best_at(qn->pos) != q && base > 3000 && qn->pos >= base &&
                      a.store.best_at(3000) == b.store.best_at(3000) && a.store.best_at(3001) != b.store.best_at(3001),
              "scope (full node): A holds b's carriers to " + std::to_string(qn ? qn->pos : 0) +
                      " as a side branch at or above its base " + std::to_string(base) + "; the fork 3,000 lies below it");
        FullChain full(a);
        KatServer s(b, 302);
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.set_own_chain(&full);
        j.offer(s.best_id(), s);
        const std::uint64_t lost = pb::open_bin_placements(a.store);
        const std::optional<pb::AttemptReport> r = j.run_next();
        check(r && r->end == pb::AttemptEnd::Completed && j.last_switch().replaced,
              "scope (full node): the fork with A's chain, not the held side top, decides: below A's base, the attempt "
              "completes and replaces A" + (r ? ": " + rep_desc(*r) : ""));
        check(lost > 0 && j.last_switch().lost == lost,
              "lost count: the replaced own chain's open-bin placements are counted (" +
                      std::to_string(j.last_switch().lost) + " of " + std::to_string(lost) + ")");
        check(j.adopted() && digest_of(*j.adopted(), b.store.best_tip()) == digest_of(b, b.store.best_tip()),
              "scope (full node): J's digest == b's at its tip");
    }
    // (joined state) J joins a at 4,600 (x1 = 2,436); b forks from a at g = 4,600; J's state follows a (2 per 1 of b)
    // and admits b's carriers as a side branch while g is at or above its base; a grows to 5,800 (J's base above g, the
    // held side top at or above it) and b to 6,300 (heavier): b's tip at J
    {
        KatNode a(net, kJ0);
        grow(a, 4600);
        KatServer sa(a, 311);
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(sa.best_id(), sa);
        (void)j.run_next();
        check(j.adopted() && j.adopted()->x1 == 2436 && j.adopted()->tip() == at_pos(a, 4600),
              "scope (joined state): J adopts a at 4,600");
        if (!j.adopted()) return;
        pb::JoinedState& A = *j.adopted();
        // the kept profile: one instance while A is unchanged, equal to a walk of its chain; a switch recounts it above
        // the fork; an instance a reader holds never changes
        const std::shared_ptr<const pb::BoundWork> p0 = A.bound_work();
        const pb::BoundWork ref0 = profile_walk(A);
        check(p0 && A.bound_work() == p0 && same_profile(*p0, ref0),
              "profile: one instance while A is unchanged, equal to a walk from x1 + 1");
        KatNode b(a);
        {
            // a switch to a branch one Monero height above a's (its profile differs), then back
            KatNode w(a);
            ChainShape sw;
            sw.nonce0 = 7100000;
            sw.hof = [](std::uint64_t x) { return h_pos(x) + 1; };
            bool ok = true;
            const std::vector<pb::Hash32> a1 = grow(a, 1);
            for (const pb::Hash32& id : a1) ok = admit_into(A, *a.bodies.get(id)) && ok;
            const std::shared_ptr<const pb::BoundWork> p1 = A.bound_work();
            check(ok && A.tip() == at_pos(a, 4601) && p1 != p0 && same_profile(*p1, profile_walk(A)),
                  "profile: after one placement on the best chain a new instance, equal to a walk");
            const std::vector<pb::Hash32> b2 = grow(w, 2, sw);
            for (const pb::Hash32& id : b2) ok = admit_into(A, *w.bodies.get(id)) && ok;
            check(ok && b2.size() == 2 && A.tip() == b2.back() && !same_profile(*A.bound_work(), *p1) &&
                          same_profile(*A.bound_work(), profile_walk(A)),
                  "profile: after a switch to another branch (2 over 1) it equals a walk of the new chain");
            const std::vector<pb::Hash32> a2 = grow(a, 2);
            for (const pb::Hash32& id : a2) ok = admit_into(A, *a.bodies.get(id)) && ok;
            check(ok && a2.size() == 2 && A.tip() == a2.back() && same_profile(*A.bound_work(), profile_walk(A)),
                  "profile: after a switch back to a's branch (3 over 2) it equals a walk of the new chain");
            check(same_profile(*p0, ref0), "profile: the instance a reader holds is unchanged by A's placements and switches");
        }
        bool follows = true;
        std::uint64_t placed = 0;
        for (int i = 0; i < 560; ++i) {
            for (const pb::Hash32& id : grow(a, 2)) follows = admit_into(A, *a.bodies.get(id)) && follows;
            const std::vector<pb::Hash32> ids = grow(b, 1, sb);
            if (!ids.empty() && admit_into(A, *b.bodies.get(ids.back()))) ++placed;
        }
        const pb::Hash32 q = b.store.best_tip();
        for (const pb::Hash32& id : grow(a, 5800 - a.store.tip_pos())) follows = admit_into(A, *a.bodies.get(id)) && follows;
        grow(b, 6300 - b.store.tip_pos(), sb);
        const std::optional<std::uint64_t> qp = A.pos_of(q);
        const std::uint64_t base = A.store_base();
        check(follows && A.tip() == at_pos(a, 5800) && placed == 560 && qp && !A.on_chain(q) && base > 4600 && *qp >= base &&
                      A.on_chain(at_pos(a, 4600)) && same_profile(*A.bound_work(), profile_walk(A)),
              "scope (joined state): A holds b's carriers to " + std::to_string(qp.value_or(0)) +
                      " as a side branch at or above its base " + std::to_string(base) + "; the fork 4,600 lies below it");
        const std::uint64_t lost = A.open_placements();
        KatServer s(b, 312);
        j.offer(s.best_id(), s);
        const std::optional<pb::AttemptReport> r = j.run_next();
        check(r && r->end == pb::AttemptEnd::Completed && j.last_switch().replaced,
              "scope (joined state): the fork with A's chain, not the held side top, decides: below A's base, the attempt "
              "completes and replaces A" + (r ? ": " + rep_desc(*r) : ""));
        check(lost > 0 && j.last_switch().lost == lost, "lost count: the replaced joined state's open-bin placements are counted");
        check(j.adopted() && digest_of(*j.adopted(), b.store.best_tip()) == digest_of(b, b.store.best_tip()),
              "scope (joined state): J's digest == b's at its tip");
    }
    // ruling 47 (RULED 47 (a), E-82): a fork below the candidate's retarget-prefix start, served by a server at the
    // default P-51 retention. The scope scan asks no header below x0(L') - N_rt; the links do not meet A's chain there,
    // so the candidate is in scope and rule (4) replaces A. (Round 1's probe_partition.)
    {
        KatNode a(net, kJ0);
        grow(a, 2000);
        KatNode b(a);                 // the fork g = 2,000
        grow(a, 2000);                // a to 4,000 (base > 2,000)
        ChainShape sb;
        sb.nonce0 = 6000000;
        grow(b, 7000, sb);            // b to 9,000, heavier
        FullChain full(a);
        KatServer s(b, 320);
        s.retention = true;           // the default P-51 floors (headers from the prefix start x_pre(L'))
        const pb::JoinServeFloors f = s.floors_now();
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.set_own_chain(&full);
        j.offer(s.best_id(), s);
        const std::optional<pb::AttemptReport> r = j.run_next();
        check(f.headers > a.store.base_pos() && a.store.base_pos() > 2000,
              "ruling 47: the fork 2,000 lies below A's base " + std::to_string(a.store.base_pos()) +
                      " and below the server's header floor " + std::to_string(f.headers));
        check(r && r->end == pb::AttemptEnd::Completed && j.last_switch().replaced,
              "ruling 47: the scan asks no header below x0(L') - N_rt; the fork is below it, the candidate in scope, A replaced" +
                      (r ? ": " + rep_desc(*r) : ""));
        check(j.adopted() && digest_of(*j.adopted(), b.store.best_tip()) == digest_of(b, b.store.best_tip()),
              "ruling 47: J's digest == b's at its tip");
    }
}

// ---------------------------------------------------------------------------
// d1: work moved between two span carriers (E-75 (i), E-76) of
// one bin with the retarget prefix and the receipts_roots forged to match
// (the forgery constructed in exact S1.4 integers)
// ---------------------------------------------------------------------------
// Monero heights with 10..14 carriers each (a deterministic walk), and an inherited window at d = 10^8: the d vary.
HOf jitter_heights(std::uint64_t n) {
    auto h = std::make_shared<std::vector<std::uint64_t>>(n + 1);
    Rng rng(4242);
    std::uint64_t height = kLaneB0, next = 0;
    for (std::uint64_t x = 0; x <= n; ++x) {
        while (x >= next) {
            if (x > 0) ++height;
            next += 10 + rng.below(5);
        }
        (*h)[x] = height;
    }
    (*h)[0] = kLaneB0;
    return [h](std::uint64_t x) { return (*h)[x]; };
}

struct D1Forgery {
    bool ok = false;
    std::string why;
    std::uint64_t a = 0, b = 0, delta = 0;
    std::map<std::uint64_t, std::uint64_t> t_origin;   // position -> the forged t_origin
    std::map<std::uint64_t, pb::Hash32> receipts_root; // position -> the refolded receipts_root
};

// The forgery against a joiner whose span starts at x0 (its retarget prefix [x0 - N_rt, x0) forged): a < b <= x1 of
// one bin with equal payee; delta from b to a.
D1Forgery solve_d1(KatNode& n, std::uint64_t x0, std::uint64_t x1, std::uint64_t L, std::uint64_t delta, std::uint64_t b_max) {
    D1Forgery out;
    out.delta = delta;
    const pb::LaneParams& P = pb::kRuledLaneParams;
    const std::uint64_t nrt = P.retarget_span, dmin = P.d_min;
    const auto d = [&](std::uint64_t p) { return n.node(at_pos(n, p)).d; };
    const auto H = [&](std::uint64_t p) { return n.node(at_pos(n, p)).H; };
    using u128 = unsigned __int128;
    for (std::uint64_t b = std::min(x1, b_max); b > x0 + 4 && !out.ok; --b) {
        const std::uint64_t a = b - 4;  // the same payee (payees cycle by 4)
        if (H(a) != H(b)) continue;
        std::uint64_t binmin = UINT64_MAX;
        for (std::uint64_t k = x0; k <= std::min(L, x1 + 2000); ++k)
            if (n.node(at_pos(n, k)).h == H(b)) binmin = std::min(binmin, d(k));
        if (d(b) < delta || d(b) - delta < binmin || d(b) - delta <= dmin) continue;
        std::map<std::uint64_t, std::uint64_t> tgt;
        for (std::uint64_t k = x0; k <= L; ++k) tgt[k] = d(k);
        tgt[a] += delta;
        tgt[b] -= delta;
        const std::uint64_t kmax = std::min(L, x0 + nrt - 1);
        const auto Sp = [&](std::uint64_t k) {
            u128 s = 0;
            for (std::uint64_t x = x0; x < k; ++x) s += tgt[x];
            return s;
        };
        const auto Pstar = [&](std::uint64_t k) {
            u128 s = 0;
            for (std::uint64_t p = k > nrt ? k - nrt : 0; p < x0; ++p) s += d(p);
            return s;
        };
        std::map<std::uint64_t, u128> Pk;
        Pk[kmax + 1] = kmax + 1 - nrt < x0 ? Pstar(kmax + 1) : 0;
        bool feasible = true;
        u128 s = Sp(kmax);
        for (std::uint64_t k = kmax; k >= x0 && feasible; --k) {
            if (k < kmax) s -= tgt[k];
            const std::uint64_t dh = H(k - 1) - H(k - nrt);
            const u128 u = static_cast<u128>(120) * std::max(dh, pb::retarget_min_span(P));
            const u128 lo = (static_cast<u128>(tgt[k]) * u + P.carrier_interval_s - 1) / P.carrier_interval_s;
            const u128 hi = (static_cast<u128>(tgt[k] + 1) * u + P.carrier_interval_s - 1) / P.carrier_interval_s - 1;
            u128 want = Pstar(k);
            if (want + s < lo) want = lo - s;
            if (want + s > hi) want = hi - s;
            const u128 need_min = Pk[k + 1] + dmin;
            if (want < need_min) {
                want = need_min;
                if (want + s > hi) feasible = false;
            }
            Pk[k] = want;
            if (k == x0) break;
        }
        if (!feasible) continue;
        std::map<std::uint64_t, std::uint64_t> pre;
        for (std::uint64_t k = x0; k <= kmax; ++k) pre[k - nrt] = static_cast<std::uint64_t>(Pk[k] - Pk[k + 1]);
        // the joiner's d_at over the forged prefix and the forged span equals the targets through kmax
        const auto jd = [&](std::uint64_t p) {
            if (p < x0) return pre.count(p) ? pre[p] : d(p);
            return tgt[p];
        };
        bool match = true;
        for (std::uint64_t k = x0; k <= kmax && match; ++k) {
            std::vector<pb::RetargetEntry> w;
            for (std::uint64_t p = k - nrt; p < k; ++p) w.push_back(pb::RetargetEntry{jd(p), H(p)});
            match = pb::retarget(P, w) == tgt[k];
        }
        if (!match) continue;
        // S: rs_step_at with the moved work from a; equal again at b
        pb::RatchetState S = n.node(at_pos(n, a - 1)).rs;
        bool s_back = true;
        std::map<std::uint64_t, pb::Hash32> roots;
        for (std::uint64_t x = a; x <= b; ++x) {
            const pb::CarrierNode& c = n.node(at_pos(n, x));
            if (x > a) roots[x] = pb::carrier_receipts_root_over(std::vector<pb::Hash32>{}, S);
            const std::vector<pb::RatchetPlacement> pl{pb::RatchetPlacement{tgt[x], c.ballot}};
            S = pb::rs_step_at(n.RP, S, x, pl, n.T).s;
        }
        s_back = S == n.node(at_pos(n, b)).rs;
        if (!s_back) continue;
        out.ok = true;
        out.a = a;
        out.b = b;
        for (const auto& [p, v] : pre)
            if (v != d(p)) out.t_origin[p] = v;
        out.t_origin[a] = tgt[a];
        out.t_origin[b] = tgt[b];
        out.receipts_root = roots;
    }
    if (!out.ok) out.why = "no feasible pair";
    return out;
}

void apply_d1(KatServer& f, KatNode& n, const D1Forgery& g) {
    for (const auto& [p, v] : g.t_origin) {
        const std::uint64_t vv = v;
        edit_carrier(f, at_pos(n, p), [vv](pb::CarrierBodyV3& c) { c.own.side.t_origin = vv; });
    }
    for (const auto& [p, r] : g.receipts_root) {
        const pb::Hash32 rr = r;
        edit_carrier(f, at_pos(n, p), [rr](pb::CarrierBodyV3& c) { c.own.side.receipts_root = rr; });
    }
}

void d1() {
    JoinNet net(1000);
    const std::uint64_t L = 5800;
    std::vector<pb::RetargetEntry> inherited;
    for (std::uint64_t i = 0; i < kNrt; ++i) inherited.push_back(pb::RetargetEntry{100000000, kLaneB0 - 180 + i * 180 / kNrt});
    KatNode a(net, kJ0, pb::kRuledRatchetParams, std::nullopt, inherited);
    ChainShape sh;
    sh.hof = jitter_heights(L + 1100);
    sh.carry_every = 0;
    grow(a, L + 1060, sh);
    const pb::SpanResult sr = pb::span_bounds(pb::kRuledLaneParams, L, [&](std::uint64_t x) -> std::optional<std::uint64_t> {
        return x == 0 ? kLaneB0 : a.node(at_pos(a, x)).H;
    });
    const std::uint64_t x0 = sr.bounds.x0, x1 = sr.bounds.x1;
    check(sr.status == pb::SpanStatus::Ok && !sr.bounds.young && x0 > kNrt, "moved work: the span at L' (x0 above N_rt)");
    const pb::Hash32 dL = digest_of(a, at_pos(a, L));
    // (i) at the joiner's span: the mismatch at a computed S1.3 #8 in (a + N_rt, b + N_rt], inside the replay
    {
        const D1Forgery g = solve_d1(a, x0, x1, L, 10000, x1);
        check(g.ok && g.b <= x1 && g.a < g.b, "moved work (i): a feasible forgery: a < b <= x1 of one bin, delta 10,000 (" + g.why + ")");
        KatServer f(a, 221), h(a, 222);
        f.top = h.top = L;
        apply_d1(f, a, g);
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(f.best_id(), f);
        j.offer(h.best_id(), h);
        const auto reps = run_until(j);
        const auto it = reps.find(221);
        check(it != reps.end() && it->second.end == pb::AttemptEnd::Alarm && it->second.row == pb::RowId::R9 &&
                      it->second.at > g.a + kNrt && it->second.at <= g.b + kNrt && it->second.at <= L && it->second.strike == 0,
              "moved work (i): J raises a local alarm + DEFER at a computed S1.3 #8 in (a + N_rt, b + N_rt] inside the replay, 0 tokens" +
                      (it != reps.end() ? ": " + rep_desc(it->second) : ""));
        check(j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == dL && follow(*j.adopted(), a, L, L + 200) &&
                      digest_of(*j.adopted(), at_pos(a, L + 200)) == digest_of(a, at_pos(a, L + 200)),
              "moved work (i): J reaches A's lane digest at L and at L + 200 from the next server");
    }
    // (i') the same shift built for E-16's span at L (the old rule): the prefix forgery lies inside the joiner's span
    // at L' and is refused there; never adopted
    {
        const pb::SpanResult e16 = pb::span_bounds(pb::kRuledLaneParams, L + kNrt, [&](std::uint64_t x) -> std::optional<std::uint64_t> {
            return x == 0 ? kLaneB0 : (x <= L ? a.node(at_pos(a, x)).H : a.node(at_pos(a, L)).H + 1000);
        });
        // E-16's x0 at L: min(L - 1,175, the first x with H(x) > H(L) - F - Fresh)
        std::uint64_t ex0 = L - 1175;
        while (ex0 > 0 && a.node(at_pos(a, ex0 - 1)).H > a.node(at_pos(a, L)).H - 98) --ex0;
        std::uint64_t ex1 = ex0;
        while (a.node(at_pos(a, ex1)).H < a.node(at_pos(a, ex0 - 1)).H + 98 && ex1 < L) ++ex1;
        (void)e16;
        const D1Forgery g = solve_d1(a, ex0, ex1, L, 10000, L + 1000 - kNrt);
        check(g.ok && g.a > ex0 && g.b + kNrt > L && g.b + kNrt <= L + 1000,
              "moved work (i'): a feasible forgery against E-16's span at L (its mismatch past L) (" + g.why + ")");
        KatServer f(a, 223), h(a, 224);
        f.top = h.top = L;
        apply_d1(f, a, g);
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(f.best_id(), f);
        j.offer(h.best_id(), h);
        const auto reps = run_until(j);
        const auto it = reps.find(223);
        check(it != reps.end() && it->second.end == pb::AttemptEnd::Alarm && it->second.row == pb::RowId::R9 &&
                      it->second.at <= L && it->second.strike == 0,
              "moved work (i'): with the span at L' the forgery mismatches a computed S1.3 #8 inside the replay, 0 tokens" +
                      (it != reps.end() ? ": " + rep_desc(it->second) : ""));
        check(j.adopted() && j.adopted()->tip() == at_pos(a, L) && follow(*j.adopted(), a, L, L + 1050) &&
                      digest_of(*j.adopted(), at_pos(a, L + 1050)) == digest_of(a, at_pos(a, L + 1050)),
              "moved work (i'): J joins the honest chain and follows A past b + N_rt with A's digest");
    }
}

// ---------------------------------------------------------------------------
// fastpool: H(L) - H(L - N_rt) < F + Fresh (E-75 (iv))
// ---------------------------------------------------------------------------
void fastpool() {
    JoinNet net(900);
    const std::uint64_t L = 6000;
    KatNode a(net, kJ0);
    ChainShape fs;
    fs.hof = [](std::uint64_t x) { return x <= 3800 ? kLaneB0 + x / 12 : kLaneB0 + 3800 / 12 + (x - 3800) / 24; };
    grow(a, L + 200, fs);
    check(fs.hof(L) - fs.hof(L - kNrt) < 98, "fast pool: H(L) - H(L - N_rt) < F + Fresh");
    KatServer s(a, 231);
    OneJoin o = join_at(net, s, L);
    check(o.r && o.r->end == pb::AttemptEnd::Completed && o.r->span.l_prime < L - kNrt,
          "fast pool: L' is taken by height below L - N_rt; the join completes" + (o.r ? ": " + rep_desc(*o.r) : ""));
    if (!o.j->adopted()) return;
    pb::JoinedState& js = *o.j->adopted();
    // E-16's x1 at L' = L - N_rt (no height condition)
    const HOf hof = fs.hof;
    const std::uint64_t lp0 = L - kNrt;
    std::uint64_t ex0 = lp0 - 1175;
    while (ex0 > 0 && hof(ex0 - 1) > hof(lp0) - 98) --ex0;
    std::uint64_t ex1 = ex0;
    while (hof(ex1) < hof(ex0 - 1) + 98) ++ex1;
    check(ex1 > js.x1, "fast pool: x1 at L' (" + std::to_string(js.x1) + ") below x1 at L - N_rt (" + std::to_string(ex1) + ")");
    bool tips_above = true;
    for (std::uint64_t x = L + 1; x <= L + 200; ++x)
        for (const pb::ReceiptBodyV3& r : a.bodies.get(at_pos(a, x))->carried) tips_above = tips_above && a.node(r.side.tip).pos > js.x1;
    check(tips_above, "fast pool: no receipt carried after L has its tip at or below x1");
    // a receipt carried at L + 1 whose tip lies in (x1, x1(L - N_rt)] with a non-canonical coinbase: J and A refuse it
    const std::uint64_t tp = std::max(js.x1 + 1, ex1 - 20);
    const pb::Hash32 t = at_pos(a, tp);
    pb::ReceiptBodyV3 bad = body_on(a, t, a.node(t).h, 5, 6600001);
    bad.side.payee = net.ids[23];
    bad.payee = net.refs[23];
    const pb::Hash32 lt = at_pos(a, L);
    const pb::CarrierBodyV3 c = carrier_on(a, lt, a.node(at_pos(a, L + 1)).h, {bad}, 2, 6600002);
    const pb::AdmitResult ra = pb::admit_carrier(a.env(), frame_of(c), pb::CarrierRole::Frame);
    js.learn_refs(bad);
    pb::AdmitEnv env = js.env();
    const pb::AdmitResult rj = pb::admit_frame_from(env, 9, frame_of(c), pb::CarrierRole::Frame);
    check(tp <= ex1 && ra.verdict == pb::AdmitVerdict::Ban && rj.verdict == pb::AdmitVerdict::Ban && rj.row == pb::RowId::R26,
          "fast pool: a receipt at L + 1 on a tip in (x1, x1(L - N_rt)] with a substituted payee: J (#12 computed) and A refuse it (J " +
                  desc(rj) + ", A " + desc(ra) + ")");
    check(follow(js, a, L, L + 200) && digest_of(js, at_pos(a, L + 200)) == digest_of(a, at_pos(a, L + 200)),
          "fast pool: J's digest == A's at L + 200");
}

// ---------------------------------------------------------------------------
// ratchet: rs_step_at with the compiled table in the replay (S4.5 vector (i)):
// a join during GRACE activates at the follower's H_act
// ---------------------------------------------------------------------------
void ratchet() {
    JoinNet net(900);
    const pb::RatchetParams rp{1000, 500, 26000};
    const pb::Hash32 r1 = seq32(0xA1);
    pb::EpochTable T;
    T.compiled.push_back(pb::CompiledEpoch{0, net.rules_g, std::nullopt});
    T.compiled.push_back(pb::CompiledEpoch{1, r1, std::nullopt});
    T.attempts.push_back(pb::Deployment{1, r1, pb::kKindVote, 0, 26000, 0});
    const std::uint64_t h_act = pb::window_h_act(rp, 0);  // locked in window 0: GRACE ends at 1,499 (x0 = 1,265 inside)
    KatNode a(net, kJ0, rp, T);
    ChainShape sh;
    sh.tweak = [&](pb::ReceiptBodyV3& r, std::uint64_t x) {
        r.side.ballot = pb::make_ballot(1, false);
        if (x >= h_act) r.side.rules_epoch = 1;
    };
    grow(a, 4810, sh);
    check(a.ar.rows().size() == 1 && a.ar.rows()[0].h_act == h_act && a.ar.rows()[0].epoch == 1,
          "ratchet: the follower activates epoch 1 at H_act = " + std::to_string(h_act));
    KatServer s(a, 241);
    s.top = 4600;
    JoinerEnv je(net);
    je.in.rp = rp;
    je.in.T = T;
    pb::Joiner j(je.in, kP53);
    j.offer(s.best_id(), s);
    const std::optional<pb::AttemptReport> r = j.run_next();
    check(r && r->end == pb::AttemptEnd::Completed && r->span.x0 > rp.window && r->span.x0 < h_act,
          "ratchet: a join during GRACE (x0 between the lock-in and H_act) completes" + (r ? ": " + rep_desc(*r) : ""));
    if (!j.adopted()) return;
    const pb::JoinedState& js = *j.adopted();
    check(js.ar.rows().size() == 2 && js.ar.rows()[1] == a.ar.rows()[0],
          "ratchet: J activates at the follower's H_act (rs_step_at with the compiled table): the AR row matches");
    check(js.tree->find(at_pos(a, 4600))->rs == a.node(at_pos(a, 4600)).rs && digest_of(js, at_pos(a, 4600)) == digest_of(a, at_pos(a, 4600)),
          "ratchet: J's S and lane digest == A's at L");
}

// ---------------------------------------------------------------------------
// header: the header phase of an attempt (RULED 47 (a), RULED 48 (a);
// E-81, E-87). A no-PoW server names a huge top position and serves full, prompt
// pages; the checks on arrival end the attempt at the first bad header and (for
// (4), (5)) exclude the server with all its pairs, no token. The server serves a
// finite number of pages then a short reply , so a mutant with the checks
// removed ends NotServed rather than at the CTest timeout. The honest pair queued
// behind it completes.
// ---------------------------------------------------------------------------
struct FakeHeaderServer final : pb::JoinLink {
    std::uint64_t id;
    std::uint64_t top_pos;
    std::uint64_t page_limit;
    std::vector<pb::CarrierHeader> chain;  // oldest first; chain.back() = the top
    std::uint64_t pages = 0;
    std::size_t served_lo = 0;

    // mode: 0 flat unique blobs (no PoW); 1 cycle (2 alternating blobs, real PoW); 2 h decreases inside the top page;
    // 3 h decreases at the top page's boundary (its lowest header one height below the header under it); 4 flat unique
    // blobs, one header of the top page claiming t_origin = d_min - 1
    FakeHeaderServer(const KatNet& net, std::uint64_t peer, std::uint64_t top, std::uint64_t n, std::uint64_t limit,
                     int mode, std::uint64_t page)
        : id(peer), top_pos(top), page_limit(limit) {
        pb::Hash32 parent = seq32(0x33);
        chain.reserve(n);
        for (std::uint64_t k = 0; k < n; ++k) {
            pb::CarrierHeader h;
            pb::ReceiptBodyV3& r = h.own;
            r.blob.major = 16;
            r.blob.minor = 16;
            // mode 2: one dip near the top (inside the top page); mode 3: the top page one height below the rest (the
            // dip at its boundary); else one held P_r
            const std::uint64_t ph = mode == 2   ? (k + 5 == n ? kAnchorH + 750 : kAnchorH + 800)
                                     : mode == 3 ? (k + page >= n ? kAnchorH + 750 : kAnchorH + 800)
                                                 : kAnchorH + 500;
            r.blob.timestamp = mon_ts(ph) + 1;
            r.blob.prev_id = mon_block(ph);
            const std::uint64_t b = mode == 1 ? k % 2 : k;  // the cycle repeats 2 blobs; else unique
            r.blob.nonce = static_cast<std::uint32_t>(b);
            for (int i = 0; i < 8; ++i) r.blob.tree_root[i] = static_cast<std::uint8_t>(b >> (8 * i));
            r.payee = net.refs[0];
            r.side.pool_id = net.pool_id;
            r.side.payee = net.ids[0];
            r.side.t_origin = mode == 4 && k + 2 == n ? pb::kRuledLaneParams.d_min - 1 : pb::kRuledLaneParams.d_min;
            r.side.tip = parent;
            r.side.give_author_bp = 10;
            r.reward_total = kReward;
            r.side.ballot = static_cast<std::uint16_t>(k);
            chain.push_back(h);
            parent = pb::receipt_id(r);
        }
    }
    std::uint64_t peer() const override { return id; }
    pb::Hash32 best_id() const { return pb::receipt_id(chain.back().own); }
    pb::ChainHeaders headers(const pb::Hash32& stop, std::uint64_t max, std::uint64_t) override {
        ++pages;
        pb::ChainHeaders out;
        if (pages > page_limit) {  // a short reply : a mutant with the checks removed ends NotServed, not at timeout
            out.status = pb::LinkStatus::Served;
            return out;
        }
        out.status = pb::LinkStatus::Served;
        std::size_t end;
        if (stop == pb::Hash32{}) {
            end = chain.size() - 1;
        } else {
            if (served_lo == 0 || pb::receipt_id(chain[served_lo - 1].own) != stop) {
                out.status = pb::LinkStatus::NotServed;
                return out;
            }
            end = served_lo - 1;
        }
        const std::size_t n = std::min<std::size_t>(max, end + 1);
        const std::size_t lo = end + 1 - n;
        for (std::size_t i = lo; i <= end; ++i) out.headers.push_back(chain[i]);
        served_lo = lo;
        out.first_pos = top_pos - (chain.size() - 1 - lo);
        return out;
    }
    pb::CarrierFrames carriers(const std::vector<pb::Hash32>&, bool, std::uint64_t) override {
        return pb::CarrierFrames{pb::LinkStatus::NotServed, {}};
    }
    pb::BucketFrames buckets(const pb::GetBuckets&, std::uint64_t) override {
        return pb::BucketFrames{pb::LinkStatus::NotServed, {}};
    }
};

void header() {
    JoinNet net(900);
    KatNode a(net, kJ0);
    grow(a, 4810);
    const std::uint64_t L = 4600;
    const pb::Hash32 dL = digest_of(a, at_pos(a, L));
    const std::uint64_t page = std::min<std::uint64_t>(kJ0, kNrt);
    // (5) a no-PoW server: flat unique blobs at top position 10^12; the attempt ends at the first bad PoW, excluded
    {
        FakeHeaderServer f(net, 401, 1000000000000ull, page * 3, 100, 0, page);
        KatServer h(a, 402);
        h.top = L;
        JoinerEnv je(net);
        for (const pb::CarrierHeader& hd : f.chain) je.bad_pow.insert(pb::receipt_id(hd.own));  // no PoW
        pb::Joiner j(je.in, kP53);
        j.offer(f.best_id(), f);
        j.offer(h.best_id(), h);
        const std::optional<pb::AttemptReport> r = j.run_next();
        check(r && r->end == pb::AttemptEnd::Header && r->strike == 0 && f.pages <= 2 && j.queue().excluded(401),
              "header (5): a no-PoW server ends the attempt at the first bad-PoW header, excluded, 0 tokens" +
                      (r ? ": " + rep_desc(*r) : ""));
        const std::optional<pb::AttemptReport> r2 = j.run_next();
        check(r2 && r2->end == pb::AttemptEnd::Completed && j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == dL,
              "header (5): the honest pair queued behind it completes and reaches A's digest" +
                      (r2 ? ": " + rep_desc(*r2) : ""));
    }
    // (2) a server serving two alternating blobs (ids repeat), real PoW: the first repeated id is a contradiction
    {
        FakeHeaderServer f(net, 403, 1000000000000ull, page * 3, 100, 1, page);
        JoinerEnv je(net);  // the cycle blobs are NOT in bad_pow: they pass (5), so (2) fires first
        pb::Joiner j(je.in, kP53);
        j.offer(f.best_id(), f);
        const std::optional<pb::AttemptReport> r = j.run_next();
        check(r && r->end == pb::AttemptEnd::Contradiction && r->strike == 0 && f.pages == 1 && j.queue().excluded(403),
              "header (2): a repeated header id in the header phase is a contradiction, excluded, 0 tokens" +
                      (r ? ": " + rep_desc(*r) : ""));
    }
    // (4) a real-PoW server whose chain carries a header whose h is below its predecessor's (going up the chain):
    // the attempt ends, excluded, 0 tokens (the honest pair behind it completes)
    {
        FakeHeaderServer f(net, 404, 1000000000000ull, page * 3, 100, 2, page);
        KatServer h(a, 405);
        h.top = L;
        JoinerEnv je(net);  // real PoW (not in bad_pow); the dip in h triggers (4)
        pb::Joiner j(je.in, kP53);
        j.offer(f.best_id(), f);
        j.offer(h.best_id(), h);
        const std::optional<pb::AttemptReport> r = j.run_next();
        check(r && r->end == pb::AttemptEnd::Header && r->strike == 0 && r->what == "h decreases along the header chain" &&
                      j.queue().excluded(404),
              "header (4): h below its predecessor ends the attempt, excluded, 0 tokens" + (r ? ": " + rep_desc(*r) : ""));
        const std::optional<pb::AttemptReport> r2 = j.run_next();
        check(r2 && r2->end == pb::AttemptEnd::Completed && j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == dL,
              "header (4): the honest pair queued behind it completes" + (r2 ? ": " + rep_desc(*r2) : ""));
    }
    // (4) at a page boundary: every header of the top page one height below the header under it (real PoW, P_r
    // resolving): the second reply's top header is above the held lowest one -> the end, excluded, 0 tokens
    {
        FakeHeaderServer f(net, 406, 1000000000000ull, page * 3, 100, 3, page);
        KatServer h(a, 407);
        h.top = L;
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(f.best_id(), f);
        j.offer(h.best_id(), h);
        const std::optional<pb::AttemptReport> r = j.run_next();
        check(r && r->end == pb::AttemptEnd::Header && r->strike == 0 && r->what == "h decreases at a page boundary" &&
                      f.pages == 2 && j.queue().excluded(406),
              "header (4) at a page boundary: the end at the second reply, excluded, 0 tokens" + (r ? ": " + rep_desc(*r) : ""));
        const std::optional<pb::AttemptReport> r2 = j.run_next();
        check(r2 && r2->end == pb::AttemptEnd::Completed && j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == dL,
              "header (4) at a page boundary: the honest pair queued behind it completes" + (r2 ? ": " + rep_desc(*r2) : ""));
    }
    // (5) t_origin >= d_min: a header whose PoW passes at its own claimed t_origin = d_min - 1 -> the end, excluded,
    // 0 tokens
    {
        FakeHeaderServer f(net, 408, 1000000000000ull, page * 3, 100, 4, page);
        KatServer h(a, 409);
        h.top = L;
        JoinerEnv je(net);  // every blob passes the PoW at its claimed t_origin (none in bad_pow)
        pb::Joiner j(je.in, kP53);
        j.offer(f.best_id(), f);
        j.offer(h.best_id(), h);
        const std::optional<pb::AttemptReport> r = j.run_next();
        check(r && r->end == pb::AttemptEnd::Header && r->strike == 0 && r->what == "a header's PoW at its own t_origin" &&
                      f.pages == 1 && j.queue().excluded(408),
              "header (5): t_origin = d_min - 1 with a passing PoW ends the attempt at the first reply, excluded, 0 tokens" +
                      (r ? ": " + rep_desc(*r) : ""));
        const std::optional<pb::AttemptReport> r2 = j.run_next();
        check(r2 && r2->end == pb::AttemptEnd::Completed && j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == dL,
              "header (5) t_origin: the honest pair queued behind it completes" + (r2 ? ": " + rep_desc(*r2) : ""));
    }
    // the young path's header phase (the pair's young mark): (5) on arrival, page by page; a server whose top page has
    // real PoW and every lower header none ends the attempt at its second reply, excluded, 0 tokens
    {
        FakeHeaderServer f(net, 410, 1000000000000ull, page * 3, 100, 0, page);
        JoinerEnv je(net);
        for (std::size_t k = 0; k + page < f.chain.size(); ++k) je.bad_pow.insert(pb::receipt_id(f.chain[k].own));
        pb::JoinAttempt att(je.in, f, kP53, nullptr);
        att.set_force_young(true);
        const pb::AttemptReport r = att.run(f.best_id());
        check(r.end == pb::AttemptEnd::Header && pb::attempt_excludes(r.end) && r.strike == 0 && f.pages == 2,
              "header (5) on the young path: checked page by page, the end at the second reply (" + std::to_string(f.pages) +
                      " pages), excluded, 0 tokens: " + rep_desc(r));
    }
    // the records of the header phase, kept page by page: each held header's P_r resolved once
    {
        KatServer h(a, 411);
        h.top = L;
        JoinerEnv je(net);
        std::uint64_t resolves = 0, at_body = 0, served = 0;
        bool bodies = false;
        const auto base = je.in.resolve_pr;
        je.in.resolve_pr = [&](const pb::Hash32& p_r) {
            ++resolves;
            return base(p_r);
        };
        h.on_headers = [&](const pb::Hash32&, pb::ChainHeaders& out) {
            if (!bodies) served += out.headers.size();
        };
        h.on_bodies = [&](const std::vector<pb::Hash32>&, pb::CarrierFrames&) {
            if (!bodies) at_body = resolves;
            bodies = true;
        };
        pb::Joiner j(je.in, kP53);
        j.offer(h.best_id(), h);
        const std::optional<pb::AttemptReport> r = j.run_next();
        check(r && r->end == pb::AttemptEnd::Completed && bodies && served > kNrt && at_body == served,
              "header records: the header phase resolves each held header's P_r once (" + std::to_string(at_body) +
                      " resolves for " + std::to_string(served) + " headers)" + (r ? ": " + rep_desc(*r) : ""));
    }
}

// ---------------------------------------------------------------------------
// jc: ruling 53 (JC-1ii-M (a); E-99..E-105): the claimed retarget
// prefix [x_pre, x0 - 1]; d at or below the root a claim; the claimed view at a
// prefix fork f, one S(f) fetch per walked branch forking at a prefix node (the
// closure's included), at the branch's first carrier; a bin sealed on such a
// branch from a served bucket of its next carrier; no node below the root the
// joined tree's best. Vectors V1-V16 and V2b (sections jc1-jc5).
// ---------------------------------------------------------------------------
const std::uint64_t kF = pb::kRuledLaneParams.open_bins;      // F
const std::uint64_t kFresh = pb::kRuledLaneParams.fresh_max;  // Fresh

HOf rate_of(std::uint64_t per_height) {
    return [per_height](std::uint64_t x) { return kLaneB0 + x / per_height; };
}

struct JcBounds {
    bool young = true;
    std::uint64_t x0 = 0, x1 = 0, x_pre = 0;
};
JcBounds jc_bounds(std::uint64_t L, const HOf& hof) {
    const auto rec = [&](std::uint64_t x) -> std::optional<std::uint64_t> {
        if (x > L) return std::nullopt;  // the chain ends at L
        return x == 0 ? kLaneB0 : hof(x);
    };
    const pb::SpanResult s = pb::span_bounds(pb::kRuledLaneParams, L, rec, kLaneB0);
    JcBounds o;
    o.young = s.bounds.young;
    o.x0 = s.bounds.x0;
    o.x1 = s.bounds.x1;
    if (!o.young) {
        const pb::PreStart ps = pb::pre_start(pb::kRuledLaneParams, o.x0, rec);
        o.x_pre = ps.status == pb::SpanStatus::Ok ? ps.x_pre : 0;
    }
    return o;
}

// x_pre by its definition (E-99), by brute force over a record function.
std::uint64_t x_pre_ref(std::uint64_t x0, const HOf& hof) {
    const auto H = [&](std::uint64_t x) { return x == 0 ? kLaneB0 : hof(x); };
    const std::uint64_t y = x0 >= 1 + kJ0 ? x0 - 1 - kJ0 : 0;
    const std::int64_t thr = static_cast<std::int64_t>(H(y)) - 98;
    std::uint64_t g = 0;
    while (static_cast<std::int64_t>(H(g)) <= thr) ++g;
    const std::int64_t m = std::min<std::int64_t>(static_cast<std::int64_t>(x0) - static_cast<std::int64_t>(kNrt),
                                                  static_cast<std::int64_t>(g));
    return static_cast<std::uint64_t>(std::max<std::int64_t>(1, m));
}

// One run of J's queue: the reports in order; at every replay step the store's and the tree's best is the replayed
// carrier of the candidate's chain (the candidate node `cand`).
struct JcRun {
    std::vector<pb::AttemptReport> reps;
    bool best_each_step = true;
    std::uint64_t steps = 0;
};
JcRun jc_run(pb::Joiner& j, KatNode& cand, int rounds) {
    JcRun o;
    j.set_on_step([&o, &cand](pb::JoinedState& s, std::uint64_t x) {
        ++o.steps;
        const pb::Hash32 cx = at_pos(cand, x);
        o.best_each_step = o.best_each_step && s.store->best_tip() == cx && s.tree->best().id == cx;
    });
    for (int i = 0; i < rounds && !j.adopted(); ++i) {
        std::optional<pb::AttemptReport> r = j.run_next();
        if (!r) break;
        o.reps.push_back(std::move(*r));
    }
    j.set_on_step({});
    return o;
}

// "J completes": the last attempt Completed at L, J's digest == A's, 0 alarms, 0 tokens, no server excluded; the
// best of the store and the tree is the replayed carrier at every step, and at L both are L.
void jc_completes(const std::string& tag, const pb::Joiner& j, const JcRun& run, KatNode& cand, std::uint64_t L) {
    const pb::AttemptReport* last = run.reps.empty() ? nullptr : &run.reps.back();
    bool clean = !run.reps.empty();
    for (const pb::AttemptReport& r : run.reps) clean = clean && r.alarms == 0 && r.strike == 0 && !j.queue().excluded(r.server);
    const pb::JoinedState* s = j.adopted();
    check(last != nullptr && last->end == pb::AttemptEnd::Completed && last->L == L && clean && s != nullptr &&
                  digest_of(*s, at_pos(cand, L)) == digest_of(cand, at_pos(cand, L)),
          tag + ": J completes at L; J's digest == A's; 0 alarms, 0 tokens, no server excluded" +
                  (last != nullptr ? ": " + rep_desc(*last) : std::string()));
    check(run.steps > 0 && run.best_each_step,
          tag + ": at every replay step store.best_tip() == tree.best() == the replayed carrier (" +
                  std::to_string(run.steps) + " steps)");
    check(s != nullptr && s->tree->best().id == s->store->best_tip() && s->store->best_tip() == at_pos(cand, L),
          tag + ": at L tree.best() == the store tip == L");
}

// h(r) for a receipt on a side carrier s carried by the span carrier at q: fresh on s, its bin open at q - 1, live at q.
std::uint64_t carried_h(KatNode& a, const pb::Hash32& s, std::uint64_t q) {
    const pb::CarrierNode& sn = a.node(s);
    const std::uint64_t open_lo = a.node(at_pos(a, q - 1)).H + 1 > kF ? a.node(at_pos(a, q - 1)).H + 1 - kF : 0;
    const std::uint64_t live_lo = a.node(at_pos(a, std::min(q - 1, sn.pos + 1))).H;
    return std::max({sn.h, open_lo, live_lo});
}

// A receipt on s (its h from carried_h) carried by a new carrier at q on A's best chain: placed; true when placed and
// the receipt live there.
struct Carried {
    pb::Hash32 cid{};
    bool placed = false;
    bool live = false;
};
Carried carry_on_side(KatNode& a, const pb::Hash32& s, std::uint64_t q, const HOf& hof, std::uint64_t nonce) {
    Carried o;
    const std::uint64_t hr = carried_h(a, s, q);
    const pb::ReceiptBodyV3 r = body_on(a, s, hr, 7, nonce);
    const pb::CarrierBodyV3 c = carrier_on(a, at_pos(a, q - 1), hof(q), {r}, q % 4, nonce + 1);
    o.cid = pb::receipt_id(c.own);
    const Admitted ac = admit_place(a, c);
    o.placed = ac.placed && a.store.best_at(q) == o.cid && hr <= a.node(s).h + kFresh;
    if (o.placed)
        if (const pb::LaneDelta* d = a.store.delta(o.cid))
            o.live = !d->placed.empty() && d->placed[0].live;
    return o;
}

// A side branch of `len` carriers on the carrier `on` at heights hs(i) (i = 1 .. len); carrying `first_carries` on
// its first carrier. The ids in branch order.
std::vector<pb::Hash32> side_branch(KatNode& a, const pb::Hash32& on, std::uint64_t len,
                                    const std::function<std::uint64_t(std::uint64_t)>& hs, std::uint64_t nonce,
                                    const std::vector<pb::ReceiptBodyV3>& first_carries = {}) {
    std::vector<pb::Hash32> out;
    pb::Hash32 p = on;
    for (std::uint64_t i = 1; i <= len; ++i) {
        const pb::CarrierBodyV3 s = carrier_on(a, p, hs(i), i == 1 ? first_carries : std::vector<pb::ReceiptBodyV3>{},
                                               5 + i % 3, nonce + i);
        const Admitted ad = admit_place(a, s);
        if (!ad.placed) {
            check(false, "side branch: carrier " + std::to_string(i) + " not placed: " + desc(ad.r));
            break;
        }
        p = pb::receipt_id(s.own);
        out.push_back(p);
    }
    return out;
}

std::unique_ptr<KatServer> jc_server(KatNode& a, std::uint64_t id, std::uint64_t L, bool retention) {
    auto s = std::make_unique<KatServer>(a, id);
    s->top = L;
    s->retention = retention;  // P-51's default floors (join_serve_floors)
    return s;
}

// V1's chain: a side carrier s on the prefix node f = x0 - 3 carrying one receipt (its tip at x0 - 4); a receipt r on
// s carried by the span carrier at x0 + 1.
struct V1Chain {
    std::unique_ptr<KatNode> a;
    JcBounds b;
    std::uint64_t L = 7000;
    pb::Hash32 sid{}, cid{};
};
V1Chain v1_chain(const JoinNet& net, std::uint64_t per_h, std::uint64_t nonce, std::uint64_t top = 210) {
    V1Chain v;
    const HOf hof = rate_of(per_h);
    v.b = jc_bounds(v.L, hof);
    v.a = std::make_unique<KatNode>(net, 9000);  // A keeps its side views (it serves S(f) and the side bodies)
    KatNode& a = *v.a;
    ChainShape sh;
    sh.hof = hof;
    const std::uint64_t x0 = v.b.x0;
    grow(a, x0, sh);
    const pb::Hash32 fork = at_pos(a, x0 - 3), below = at_pos(a, x0 - 4);
    const pb::ReceiptBodyV3 rs = body_on(a, below, a.node(below).h, 3, nonce + 1);
    const pb::CarrierBodyV3 s = carrier_on(a, fork, a.node(fork).h, {rs}, 5, nonce + 2);
    v.sid = pb::receipt_id(s.own);
    const Admitted as = admit_place(a, s);
    const Carried c = carry_on_side(a, v.sid, x0 + 1, hof, nonce + 3);
    v.cid = c.cid;
    grow(a, v.L + top - (x0 + 1), sh);
    check(!v.b.young && as.placed && c.placed && c.live && a.store.best_at(x0 - 2) != v.sid,
          "V1 chain (" + std::to_string(per_h) + " per height): A places s on f = x0 - 3 (a side branch), and the span "
          "carrier at x0 + 1 carrying a live receipt on s; x0 = " + std::to_string(x0) + ", x_pre = " +
                  std::to_string(v.b.x_pre));
    return v;
}

// V1 (5.3 (iii) honest; P1, P2; E-99 A (1), E-100 A (2), E-105) at a P-51-default server, and V5 (B6) on its
// joined state; a second leg at 10 positions per height, where x_pre = x0 - N_rt and the window at f leaves it.
void jc_v1_v5(const JoinNet& net) {
    for (const std::uint64_t per_h : {std::uint64_t{12}, std::uint64_t{10}}) {
        const std::string tag = "V1 (" + std::to_string(per_h) + " per height)";
        V1Chain v = v1_chain(net, per_h, 5100000 + per_h * 1000);
        KatNode& a = *v.a;
        auto s = jc_server(a, 501, v.L, true);
        std::set<pb::Hash32> ats;
        s->on_buckets = [&](const pb::GetBuckets& q, pb::BucketFrames&) { ats.insert(q.at); };
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(s->best_id(), *s);
        const JcRun run = jc_run(j, a, 1);  // the first attempt
        jc_completes(tag, j, run, a, v.L);
        const pb::JoinedState* js = j.adopted();
        check(js != nullptr && ats.count(v.sid) != 0 && js->tree->find(v.sid) != nullptr && !run.reps.empty() &&
                      !run.reps[0].force_young,
              tag + ": S(f) and the claimed view at f from FC_GETBUCKETS at s; s placed in J's tree; no young mark");
        const HOf hof = rate_of(per_h);
        check(js != nullptr && v.b.x_pre == x_pre_ref(v.b.x0, hof) && js->store->first_record_pos() == v.b.x_pre &&
                      js->tree->find(at_pos(a, v.b.x_pre)) != nullptr &&
                      (v.b.x_pre == 1 || js->tree->find(at_pos(a, v.b.x_pre - 1)) == nullptr),
              tag + ": the claimed prefix starts at x_pre = " + std::to_string(v.b.x_pre) + " (x0 - x_pre = " +
                      std::to_string(v.b.x0 - v.b.x_pre) + "): nodes from x_pre, none below");
        if (per_h == 12)
            check(v.b.x0 - v.b.x_pre >= 2317 && v.b.x0 - v.b.x_pre <= 2328, tag + ": x0 - x_pre in [2,317, 2,328]");
        else
            check(v.b.x_pre == v.b.x0 - kNrt, tag + ": below about 10.4 per height x_pre = x0 - N_rt");
        if (per_h != 12 || js == nullptr) continue;
        // V1, the S(f) fold over the first carrier's carried list (FX-5): J's header path of s fails (its PoW), so the
        // walk ends before it takes s's body set; the S(f) fetch takes it first and its fold matches: the attempt ends
        // as an unplaceable span carrier, no alarm
        {
            auto sp = jc_server(a, 502, v.L, true);
            JoinerEnv jp(net);
            jp.bad_pow.insert(v.sid);
            pb::Joiner jj(jp.in, kP53);
            jj.offer(sp->best_id(), *sp);
            const std::optional<pb::AttemptReport> rp = jj.run_next();
            check(rp && rp->end == pb::AttemptEnd::Unplaceable && rp->alarms == 0 && rp->strike == 0,
                  tag + ", s's header path failing at J: the S(f) fold runs over s's carried list (no alarm); the "
                  "attempt ends as an unplaceable span carrier" + (rp ? ": " + rep_desc(*rp) : std::string()));
        }
        // V5 (B6): no padded d below the root: after every prefix node at or below x0 - 2 the joined tree's d is
        // absent (its window leaves the held prefix) or equals A's (a held window)
        std::uint64_t absent = 0, equal = 0, differ = 0;
        for (std::uint64_t x = v.b.x_pre; x + 2 <= v.b.x0; ++x) {
            const pb::Hash32 id = at_pos(a, x);
            const std::optional<std::uint64_t> dj = js->tree->next_difficulty(id);
            if (!dj)
                ++absent;
            else if (dj == a.tree.next_difficulty(id))
                ++equal;
            else
                ++differ;
        }
        check(absent > 0 && equal > 0 && differ == 0,
              "V5 (B6): after a prefix node no padded d: " + std::to_string(absent) + " absent (window leaves the prefix), " +
                      std::to_string(equal) + " equal to A's, " + std::to_string(differ) + " differ");
        check(js->tree->find(v.sid) != nullptr && js->tree->find(v.sid)->d == a.node(v.sid).d,
              "V5 (B6): s's d in J's tree (its claimed t_origin, A (1)) == A's");
    }
}

// V16 (S(f) not served; card fact 5): V1's shape; the attempt's server answers the S(f) fetch NotServed (leg 1) or
// lets it run to the abandon timer (leg 2, no frame); an honest server queued second.
void jc_v16(const JoinNet& net) {
    V1Chain v = v1_chain(net, 12, 5160000);
    KatNode& a = *v.a;
    const pb::Hash32 dL = digest_of(a, at_pos(a, v.L));
    for (const int leg : {0, 1}) {
        const std::string tag = std::string("V16 (S(f) ") + (leg == 0 ? "not served" : "no reply, the abandon timer") + ")";
        auto f = jc_server(a, 510 + leg, v.L, true);
        auto h = jc_server(a, 520 + leg, v.L, true);
        f->on_buckets = [&, leg](const pb::GetBuckets& q, pb::BucketFrames& out) {
            if (q.at != v.sid) return;
            out.frames.clear();
            out.status = leg == 0 ? pb::LinkStatus::NotServed : pb::LinkStatus::NoReply;
        };
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(f->best_id(), *f);
        j.offer(h->best_id(), *h);
        const std::optional<pb::AttemptReport> r1 = j.run_next();
        bool requeued = false;
        for (const pb::AttemptQueue::Pair& p : j.queue().pairs()) requeued = requeued || p.server == f->id;
        check(r1 && r1->server == f->id && r1->end == pb::AttemptEnd::NotServed && r1->alarms == 0 && r1->strike == 0 &&
                      !r1->force_young && !j.queue().excluded(f->id) && requeued && j.adopted() == nullptr,
              tag + ": the attempt ends as non-service: no alarm, no token, no exclusion, the pair re-queued, nothing "
              "placed" + (r1 ? ": " + rep_desc(*r1) : std::string()));
        const std::optional<pb::AttemptReport> r2 = j.run_next();
        check(r2 && r2->server == h->id && r2->end == pb::AttemptEnd::Completed && r2->alarms == 0 && j.adopted() &&
                      digest_of(*j.adopted(), at_pos(a, v.L)) == dL,
              tag + ": the next server's attempt completes; J's digest == A's" + (r2 ? ": " + rep_desc(*r2) : std::string()));
    }
}

// A nested shape (V2, V2b, V3): s on the carrier at f carrying b' whose tip t' lies on c's chain at t (h(b') =
// h(t') + 2); a receipt on s carried at q.
struct Nested {
    pb::Hash32 sid{}, tid{};
    bool placed = false;
};
Nested nested_shape(KatNode& a, std::uint64_t f, std::uint64_t t, std::uint64_t q, const HOf& hof, std::uint64_t nonce) {
    Nested o;
    const pb::Hash32 fork = at_pos(a, f);
    o.tid = at_pos(a, t);
    const pb::ReceiptBodyV3 bp = body_on(a, o.tid, a.node(o.tid).h + 2, 1, nonce + 1);
    const pb::CarrierBodyV3 s = carrier_on(a, fork, a.node(fork).h, {bp}, 5, nonce + 2);
    o.sid = pb::receipt_id(s.own);
    const Admitted as = admit_place(a, s);
    const Carried c = carry_on_side(a, o.sid, q, hof, nonce + 3);
    o.placed = as.placed && c.placed && c.live;
    if (!as.placed) std::printf("  nested shape: s not placed: %s\n", desc(as.r).c_str());
    return o;
}

// V2 (Q; E-99 A (3)): f = x0 - 1,100, the nested tip at x0 - 2,200 (between x_pre and x0 - N_rt); the boundary leg
// f = x0 - 1 - J_0 with the nested tip exactly at g(x0 - 1 - J_0) = x_pre (one position lower: refused by A).
// V2b (24 per height, L = 10,000): the nested tip between g(x0 - 1 - J_0) and x0 - N_rt - J_0.
// V3 (F-2; E-99 A (1)): a fork above the root (x0 + 1), the nested tip at x0 - 1,160.
void jc_nested(const JoinNet& net) {
    struct Leg {
        std::string name;
        std::uint64_t per_h, L;
        std::int64_t f, t, q;  // offsets from x0 (t: 0 with at_x_pre)
        bool at_x_pre;
        bool boundary;
    };
    const std::int64_t j0 = static_cast<std::int64_t>(kJ0);
    const std::vector<Leg> legs{
            {"V2 (Q)", 12, 7000, -1100, -2200, 1, false, false},
            {"V2 (boundary)", 12, 7000, -1 - j0, 0, 0, true, true},
            {"V2b (24 per height)", 24, 10000, -1 - j0, 0, 0, false, false},
            {"V3 (F-2)", 12, 7000, 1, -1160, 4, false, false},
    };
    std::uint64_t k = 0;
    for (const Leg& lg : legs) {
        ++k;
        const HOf hof = rate_of(lg.per_h);
        const JcBounds b = jc_bounds(lg.L, hof);
        const std::int64_t x0 = static_cast<std::int64_t>(b.x0);
        std::uint64_t t = static_cast<std::uint64_t>(x0 + lg.t);
        if (lg.at_x_pre) t = b.x_pre;
        if (lg.per_h == 24) t = (b.x_pre + (b.x0 - kNrt - kJ0)) / 2;  // between g(x0 - 1 - J_0) and x0 - N_rt - J_0
        const std::uint64_t f = static_cast<std::uint64_t>(x0 + lg.f), q = static_cast<std::uint64_t>(x0 + lg.q);
        const std::string tag = lg.name;
        check(!b.young && b.x_pre == x_pre_ref(b.x0, hof) && t >= b.x_pre && f + 1 + kJ0 >= q,
              tag + ": x0 = " + std::to_string(b.x0) + ", x_pre = " + std::to_string(b.x_pre) + ", fork " + std::to_string(f) +
                      ", nested tip " + std::to_string(t) + ", carried at " + std::to_string(q));
        if (lg.per_h == 24)
            check(t < b.x0 - kNrt - kJ0 && b.x_pre < b.x0 - kNrt - kJ0, tag + ": the nested tip lies below x0 - N_rt - J_0");
        if (lg.name == "V2 (Q)") check(t > b.x_pre && t < b.x0 - kNrt, tag + ": the nested tip lies in (x_pre, x0 - N_rt)");
        KatNode a(net, 9000);
        ChainShape sh;
        sh.hof = hof;
        grow(a, q - 1, sh);
        const Nested n = nested_shape(a, f, t, q, hof, 5200000 + k * 1000);
        check(n.placed, tag + ": A places s (carrying b' on the nested tip) and the span carrier carrying a live receipt on s");
        if (lg.boundary) {
            // one position lower: a full node refuses it (#7 / #6), so no honest server serves it
            const pb::Hash32 low = at_pos(a, t - 1);
            const pb::ReceiptBodyV3 bl = body_on(a, low, a.node(low).h + 2, 2, 5290001);
            const pb::CarrierBodyV3 sl = carrier_on(a, at_pos(a, f), a.node(at_pos(a, f)).h, {bl}, 6, 5290002);
            const pb::AdmitResult rl = pb::admit_carrier(a.env(), frame_of(sl), pb::CarrierRole::Frame);
            check(rl.verdict == pb::AdmitVerdict::Strike || rl.verdict == pb::AdmitVerdict::Refuse,
                  tag + ": a nested tip one position below g(x0 - 1 - J_0) is refused by a full node: " + desc(rl));
        }
        grow(a, lg.L + 210 - q, sh);
        auto s = jc_server(a, 530 + k, lg.L, true);
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(s->best_id(), *s);
        const JcRun run = jc_run(j, a, 1);
        jc_completes(tag, j, run, a, lg.L);
        check(j.adopted() && j.adopted()->tree->find(n.tid) != nullptr && j.adopted()->tree->find(n.sid) != nullptr,
              tag + ": the nested tip is a node of J's tree; s placed");
    }
}

// V15 (DF-6; the clamps of E-99): short mature spans with lc(H(x0 - 1)) > 0: leg 1 (12 per height, L = 5,000:
// x0 - N_rt <= 0), leg 2 (10 per height, x0 <= J_0: max(0, x0 - 1 - J_0) acts), leg 3 (12 per height, L = 5,650,
// x0 > N_rt with g(x0 - 1 - J_0) <= 1: the scan reaches position 0 and max(1, .) takes x_pre = 1); x_pre = 1, J
// completes.
void jc_v15(const JoinNet& net) {
    struct Leg {
        std::uint64_t per_h, L;
    };
    std::uint64_t k = 0;
    for (const Leg lg : {Leg{12, 5000}, Leg{10, 4435}, Leg{12, 5650}}) {
        ++k;
        const HOf hof = rate_of(lg.per_h);
        const JcBounds b = jc_bounds(lg.L, hof);
        const std::string tag = "V15 leg " + std::to_string(k) + " (" + std::to_string(lg.per_h) + " per height, L = " +
                                std::to_string(lg.L) + ", x0 = " + std::to_string(b.x0) + ")";
        const std::uint64_t lc = pb::bin_leaf_count(hof(b.x0 - 1), kLaneB0, kF);
        const bool shape = k == 1 ? (b.x0 <= kNrt && b.x0 > kJ0) : k == 2 ? b.x0 <= kJ0 : b.x0 > kNrt;
        check(!b.young && lc > 0 && shape && b.x_pre == 1 && x_pre_ref(b.x0, hof) == 1,
              tag + ": a mature span (lc(H(x0 - 1)) = " + std::to_string(lc) + "), x_pre = 1" +
                      (k == 1 ? " (x0 - N_rt <= 0)"
                              : k == 2 ? " (x0 - 1 - J_0 < 0 taken as 0)" : " (x0 > N_rt, the first x above the threshold is 0)"));
        KatNode a(net, 9000);
        ChainShape sh;
        sh.hof = hof;
        grow(a, lg.L + 210, sh);
        auto s = jc_server(a, 540 + k, lg.L, true);
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(s->best_id(), *s);
        const JcRun run = jc_run(j, a, 1);
        jc_completes(tag, j, run, a, lg.L);
        check(j.adopted() && j.adopted()->store->first_record_pos() == 1 && j.adopted()->tree->find(at_pos(a, 1)) != nullptr,
              tag + ": the claimed prefix starts at position 1");
    }
}

// V4 (P3; E-100, INV-31): a full node whose own chain A is lighter (a partition deeper than its journal); the heavier
// honest candidate carries V1's shape: the attempt completes and rule (4) replaces A; the lost count is logged.
void jc_v4(const JoinNet& net) {
    const std::uint64_t g = 1000;
    KatNode a(net, kJ0);
    grow(a, g);
    ChainShape sa;
    sa.nonce0 = 6200000;
    grow(a, 3000, sa);  // A: 4,000, its base above g
    V1Chain v = v1_chain(net, 12, 5400000);  // the candidate: the same first g carriers (one chain shape)
    KatNode& b = *v.a;
    check(a.store.best_at(g) == b.store.best_at(g) && a.store.best_at(g + 1) != b.store.best_at(g + 1) &&
                  a.store.base_pos() > g && g < v.b.x0 - kNrt,
          "V4: A and the candidate share positions to " + std::to_string(g) + "; the fork lies below A's base " +
                  std::to_string(a.store.base_pos()) + " and below x0(L') - N_rt");
    FullChain full(a);
    auto s = jc_server(b, 550, v.L, true);
    JoinerEnv je(net);
    pb::Joiner j(je.in, kP53);
    j.set_own_chain(&full);
    j.offer(s->best_id(), *s);
    const std::uint64_t lost = pb::open_bin_placements(a.store);
    const JcRun run = jc_run(j, b, 1);
    jc_completes("V4", j, run, b, v.L);
    check(j.last_switch().replaced && j.last_switch().lost == lost && lost > 0,
          "V4: rule (4) replaces A (the lighter own chain); the lost count " + std::to_string(j.last_switch().lost) +
                  " is A's open-bin placements");
}

// V6 (no claim after L; E-75, E-99, E-100): the attempt server serves a forged header in [x_pre, x0 - N_rt):
// (i) another blob (another id): its hash link (check (1)) ends the attempt at its arrival, before any body or
// bucket; (ii) the same blob with a forged t_origin (its d; the link is the receipt id, so it holds): a claim no row
// reads (A (1) takes the receipt's own t_origin below the root; no window of a position >= x0 reaches below
// x0 - N_rt): J reaches A's digest at L. Then, from L + 1 to L + J_0 + 200, J judges every peer's frame as A; a
// joined node's switch to a branch forking at or below x1 takes the joiner path at a raised P-01.
void jc_v6(const JoinNet& net) {
    V1Chain v = v1_chain(net, 12, 5500000, 210 + kJ0 + 200);
    KatNode& a = *v.a;
    const std::uint64_t p = v.b.x0 - 2200;  // in [x_pre, x0 - N_rt)
    auto f = jc_server(a, 560, v.L, true);
    auto h = jc_server(a, 561, v.L, true);
    const pb::Hash32 forged_id = at_pos(a, p);
    f->on_headers = [&](const pb::Hash32&, pb::ChainHeaders& out) {
        for (pb::CarrierHeader& hh : out.headers)
            if (pb::receipt_id(hh.own) == forged_id) hh.own.blob.nonce ^= 1;  // another blob: another id
    };
    {
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(f->best_id(), *f);
        const std::optional<pb::AttemptReport> r1 = j.run_next();
        check(p >= v.b.x_pre && p < v.b.x0 - kNrt && r1 && r1->server == f->id && r1->end == pb::AttemptEnd::NotServed &&
                      r1->alarms == 0 && r1->strike == 0 && f->body_requests == 0 && f->bucket_requests == 0 &&
                      j.adopted() == nullptr,
              "V6 (i): a forged header (another blob) in [x_pre, x0 - N_rt) ends the attempt at its arrival (its hash "
              "link, check (1)), before any body or bucket, no alarm, no token" + (r1 ? ": " + rep_desc(*r1) : std::string()));
    }
    auto g = jc_server(a, 562, v.L, true);
    g->on_headers = [&](const pb::Hash32&, pb::ChainHeaders& out) {
        for (pb::CarrierHeader& hh : out.headers)
            if (pb::receipt_id(hh.own) == forged_id) hh.own.side.t_origin += 1;  // a forged d: the id unchanged
    };
    {
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(g->best_id(), *g);
        const std::optional<pb::AttemptReport> r = j.run_next();
        const pb::CarrierNode* fn = j.adopted() ? j.adopted()->tree->find(forged_id) : nullptr;
        check(r && r->end == pb::AttemptEnd::Completed && r->alarms == 0 && fn != nullptr && fn->d == a.node(forged_id).d + 1 &&
                      digest_of(*j.adopted(), at_pos(a, v.L)) == digest_of(a, at_pos(a, v.L)),
              "V6 (ii): a forged d in [x_pre, x0 - N_rt) (the id unchanged) is a claim no row reads: J reaches A's digest "
              "at L" + (r ? ": " + rep_desc(*r) : std::string()));
    }
    JoinerEnv je(net, 6000);  // a raised P-01
    pb::Joiner j(je.in, kP53);
    j.offer(h->best_id(), *h);
    JcRun run;
    if (std::optional<pb::AttemptReport> r2 = j.run_next()) run.reps.push_back(std::move(*r2));
    check(!run.reps.empty() && run.reps.back().end == pb::AttemptEnd::Completed && j.adopted() &&
                  digest_of(*j.adopted(), at_pos(a, v.L)) == digest_of(a, at_pos(a, v.L)),
          "V6: the honest server's attempt completes; J's digest == A's at L");
    if (!j.adopted()) return;
    pb::JoinedState& js = *j.adopted();
    const std::uint64_t to = v.L + kJ0 + 200;
    check(follow(js, a, v.L, to) && digest_of(js, at_pos(a, to)) == digest_of(a, at_pos(a, to)),
          "V6: from L + 1 to L + J_0 + 200 J admits every peer's frame as A does; J's digest == A's at L + J_0 + 200");
    check(js.store_base() <= js.x1 && pb::own_switch_path(js, js.x1 - 1) == pb::SwitchPath::Joiner &&
                  pb::own_switch_path(js, js.x1) == pb::SwitchPath::Joiner &&
                  pb::own_switch_path(js, js.x1 + 1) == pb::SwitchPath::Rewind,
          "V6: at a raised P-01 (base " + std::to_string(js.store_base()) + " <= x1 = " + std::to_string(js.x1) +
                  ") a switch to a branch forking at or below x1 takes the joiner path, above it the rewind");
}

// V14 (DF-5; E-104): A grew fewer than P-01 positions above a fork f in [x_pre, x0 - N_rt) of the candidate; the
// candidate grew >= 5,500 positions: the scope scan stops at x0(L') - N_rt without meeting A, the candidate is in
// scope, the attempt completes and rule (4) replaces A.
void jc_v14(const JoinNet& net) {
    const std::uint64_t L = 7000;
    const HOf hof = rate_of(12);
    const JcBounds b = jc_bounds(L, hof);
    const std::uint64_t g = (b.x_pre + b.x0 - kNrt) / 2;
    KatNode a(net, kJ0);
    grow(a, g);
    ChainShape sa;
    sa.nonce0 = 6300000;
    grow(a, 1000, sa);  // A: g + 1,000 (< P-01 above g)
    KatNode c(net, 9000);
    grow(c, L + 210);
    check(g >= b.x_pre && g < b.x0 - kNrt && a.store.best_at(g) == c.store.best_at(g) &&
                  a.store.best_at(g + 1) != c.store.best_at(g + 1) && a.store.base_pos() <= g && L - g >= 5500,
          "V14: the fork " + std::to_string(g) + " in [x_pre, x0 - N_rt) = [" + std::to_string(b.x_pre) + ", " +
                  std::to_string(b.x0 - kNrt) + "), at or above A's base " + std::to_string(a.store.base_pos()) +
                  "; the candidate grew " + std::to_string(L - g));
    FullChain full(a);
    auto s = jc_server(c, 570, L, true);
    JoinerEnv je(net);
    pb::Joiner j(je.in, kP53);
    j.set_own_chain(&full);
    j.offer(s->best_id(), *s);
    const JcRun run = jc_run(j, c, 1);
    jc_completes("V14", j, run, c, L);
    check(j.last_switch().replaced, "V14: the candidate is in scope (the scan never reads below x0(L') - N_rt); rule (4) "
                                    "replaces A");
}

// V7 (lc = 0, C-3; E-79, E-83): a side branch forking at f with lc(H(f)) = 0 while lc(H(x0 - 1)) >= 1, at a P-51
// default server: attempt 1 ends with no alarm, no token, no exclusion, the pair marked young; attempt 2 runs the
// young path at the same server and completes.
void jc_v7(const JoinNet& net) {
    const std::uint64_t L = 4535;
    const HOf hof = rate_of(12);
    const JcBounds b = jc_bounds(L, hof);
    KatNode a(net, 9000);
    ChainShape sh;
    grow(a, b.x0 + 1, sh);
    const std::uint64_t ff = 200;
    const pb::Hash32 fork = at_pos(a, ff);
    const pb::CarrierBodyV3 s = carrier_on(a, fork, a.node(fork).h, {}, 5, 5700001);
    const pb::Hash32 sid = pb::receipt_id(s.own);
    const Admitted as = admit_place(a, s);
    const Carried c = carry_on_side(a, sid, b.x0 + 2, hof, 5700002);
    grow(a, L + 210 - (b.x0 + 2), sh);
    const std::uint64_t lcf = pb::bin_leaf_count(a.node(fork).H, kLaneB0, kF);
    const std::uint64_t lcx = pb::bin_leaf_count(hof(b.x0 - 1), kLaneB0, kF);
    check(!b.young && as.placed && c.placed && lcf == 0 && lcx >= 1 && b.x0 >= 1155 && b.x0 <= 2304,
          "V7: the fork f = 200 (lc(H(f)) = 0), x0 = " + std::to_string(b.x0) + " (lc(H(x0 - 1)) = " + std::to_string(lcx) + ")");
    auto s0 = jc_server(a, 580, L, true);
    const pb::JoinServeFloors fl = s0->floors_now();
    JoinerEnv je(net);
    pb::Joiner j(je.in, kP53);
    j.offer(s0->best_id(), *s0);
    const std::optional<pb::AttemptReport> r1 = j.run_next();
    check(r1 && r1->end == pb::AttemptEnd::NotServed && r1->force_young && r1->strike == 0 && r1->alarms == 0 &&
                  !j.queue().excluded(580) && j.queue().size() == 1 && j.queue().pairs().front().young,
          "V7: attempt 1 ends with no alarm, no token, no exclusion; the pair re-queued with the young mark" +
                  (r1 ? ": " + rep_desc(*r1) : std::string()));
    const std::optional<pb::AttemptReport> r2 = j.run_next();
    check(fl.bodies == 0 && fl.headers == 0 && r2 && r2->end == pb::AttemptEnd::Completed && r2->server == 580 &&
                  r2->span.young && j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == digest_of(a, at_pos(a, L)),
          "V7: attempt 2 runs the young path [1, L] at the same default-retention server and completes; J's digest == A's" +
                  (r2 ? ": " + rep_desc(*r2) : std::string()));
}

// V8 (a fold mismatch; ruling 47's alarm, E-83): a forged S(f) served against the honest side carrier s; an honest
// server queued second.
void jc_v8(const JoinNet& net) {
    V1Chain v = v1_chain(net, 12, 5800000);
    KatNode& a = *v.a;
    auto f = jc_server(a, 590, v.L, true);
    auto h = jc_server(a, 591, v.L, true);
    f->on_buckets = [&](const pb::GetBuckets& q, pb::BucketFrames& out) {
        if (q.at == v.sid) edit_frames(out, [](pb::BucketsReply& r) { r.s_parent[2] ^= 1; });
    };
    JoinerEnv je(net);
    pb::Joiner j(je.in, kP53);
    j.offer(f->best_id(), *f);
    j.offer(h->best_id(), *h);
    const std::optional<pb::AttemptReport> r1 = j.run_next();
    check(r1 && r1->server == 590 && r1->end == pb::AttemptEnd::Alarm && r1->alarms > 0 && r1->strike == 0 &&
                  j.queue().excluded(590),
          "V8: a forged S(f) against the honest side carrier: an alarm, the server excluded, 0 tokens" +
                  (r1 ? ": " + rep_desc(*r1) : std::string()));
    const std::optional<pb::AttemptReport> r2 = j.run_next();
    check(r2 && r2->server == 591 && r2->end == pb::AttemptEnd::Completed && j.adopted() &&
                  digest_of(*j.adopted(), at_pos(a, v.L)) == digest_of(a, at_pos(a, v.L)),
          "V8: the next server's attempt completes; J's digest == A's" + (r2 ? ": " + rep_desc(*r2) : std::string()));
}

// V9 (B7; E-83), V10 (B8; E-100), V12 (N-W2; E-105): multi-carrier side branches on prefix nodes.
void jc_branches(const JoinNet& net) {
    const std::uint64_t L = 7000;
    const HOf hof = rate_of(12);
    const JcBounds b = jc_bounds(L, hof);
    const std::uint64_t x0 = b.x0;
    ChainShape sh;
    sh.hof = hof;
    // V9: a 2-carrier branch on x0 - 3 (its first carrier one Monero height up: it seals a bin, held from a served
    // bucket at the second carrier), the span receipt's tip on its second carrier
    {
        KatNode a(net, 9000);
        grow(a, x0, sh);
        const pb::Hash32 f = at_pos(a, x0 - 3);
        const std::uint64_t hf = a.node(f).h;
        const std::vector<pb::Hash32> br = side_branch(a, f, 2, [&](std::uint64_t) { return hf + 1; }, 5910000);
        const Carried c = br.size() == 2 ? carry_on_side(a, br[1], x0 + 1, hof, 5910100) : Carried{};
        grow(a, L + 210 - (x0 + 1), sh);
        const std::uint64_t sealed = br.size() == 2 && a.store.delta(br[0]) ? a.store.delta(br[0])->sealed.size() : 0;
        check(c.placed && c.live && sealed == 1, "V9: A places the 2-carrier branch on x0 - 3 (its first carrier seals " +
                                                         std::to_string(sealed) + " bin) and the span receipt on its second");
        auto s = jc_server(a, 600, L, true);
        std::vector<pb::Hash32> ats;
        s->on_buckets = [&](const pb::GetBuckets& q, pb::BucketFrames&) { ats.push_back(q.at); };
        JoinerEnv je(net, 9000);  // J's store keeps the side deltas to L (P-01 raised) so they can be read after it
        pb::Joiner j(je.in, kP53);
        j.offer(s->best_id(), *s);
        const JcRun run = jc_run(j, a, 1);
        jc_completes("V9", j, run, a, L);
        const auto has = [&](const pb::Hash32& id) { return std::find(ats.begin(), ats.end(), id) != ats.end(); };
        check(br.size() == 2 && has(br[0]) && has(br[1]),
              "V9: S(f) asked at the branch's first carrier (its fork = that carrier's parent), the bin sealed on it at "
              "its second carrier");
        const pb::LaneDelta* d = j.adopted() && br.size() == 2 ? j.adopted()->store->delta(br[0]) : nullptr;
        check(d != nullptr && d->pending.empty() && d->sealed.size() == 1 &&
                      d->sealed[0].leaf == a.store.delta(br[0])->sealed[0].leaf,
              "V9: the bin sealed on the branch held from the served bucket (its leaf equal to A's)");
    }
    // V10: s on x0 - 3 carries a receipt whose tip lies on a second branch forking at x0 - 5 (a closure branch)
    {
        KatNode a(net, 9000);
        grow(a, x0, sh);
        const pb::Hash32 f2 = at_pos(a, x0 - 5), f1 = at_pos(a, x0 - 3);
        const std::vector<pb::Hash32> b2 = side_branch(a, f2, 1, [&](std::uint64_t) { return a.node(f2).h; }, 5920000);
        const pb::ReceiptBodyV3 bp = body_on(a, b2.at(0), a.node(b2.at(0)).h, 2, 5920100);
        const std::vector<pb::Hash32> b1 =
                side_branch(a, f1, 1, [&](std::uint64_t) { return a.node(f1).h; }, 5920200, {bp});
        const Carried c = b1.size() == 1 ? carry_on_side(a, b1[0], x0 + 1, hof, 5920300) : Carried{};
        grow(a, L + 210 - (x0 + 1), sh);
        check(c.placed && c.live, "V10: A places the closure branch on x0 - 5, s on x0 - 3 carrying a receipt on it, and c");
        auto s = jc_server(a, 610, L, true);
        std::set<pb::Hash32> ats;
        s->on_buckets = [&](const pb::GetBuckets& q, pb::BucketFrames&) { ats.insert(q.at); };
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(s->best_id(), *s);
        const JcRun run = jc_run(j, a, 1);
        jc_completes("V10", j, run, a, L);
        check(b1.size() == 1 && ats.count(b1[0]) != 0 && ats.count(b2[0]) != 0,
              "V10: two S(f) fetches, one per branch forking at a prefix node (the closure branch's at its own first carrier)");
    }
    // V12: a 2-carrier branch on x0 - 3 carried at x0 + 1, and a 5-carrier branch on x0 - 10 carried at x0 + 2
    {
        KatNode a(net, 9000);
        grow(a, x0, sh);
        const pb::Hash32 fa = at_pos(a, x0 - 3), fb = at_pos(a, x0 - 10);
        const std::vector<pb::Hash32> ba = side_branch(a, fa, 2, [&](std::uint64_t) { return a.node(fa).h; }, 5930000);
        const std::vector<pb::Hash32> bb = side_branch(a, fb, 5, [&](std::uint64_t) { return a.node(fb).h; }, 5930100);
        const Carried ca = ba.size() == 2 ? carry_on_side(a, ba[1], x0 + 1, hof, 5930200) : Carried{};
        const Carried cb = bb.size() == 5 ? carry_on_side(a, bb[4], x0 + 2, hof, 5930300) : Carried{};
        grow(a, L + 210 - (x0 + 2), sh);
        check(ca.placed && ca.live && cb.placed && cb.live,
              "V12: A places the 2-carrier branch on x0 - 3 (carried at x0 + 1) and the 5-carrier branch on x0 - 10 "
              "(carried at x0 + 2)");
        auto s = jc_server(a, 620, L, true);
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(s->best_id(), *s);
        const JcRun run = jc_run(j, a, 1);
        jc_completes("V12", j, run, a, L);
        const pb::JoinedState* js = j.adopted();
        check(js != nullptr && ba.size() == 2 && bb.size() == 5 && js->tree->find(ba[1]) != nullptr &&
                      js->tree->find(bb[4]) != nullptr && js->store->best_tip() == at_pos(a, L),
              "V12: both below-root branches placed in J's tree, never its best; the store's best is L");
    }
}

// V11 (N-W1; S2.3 #5): a nested body whose Monero P_r the follower lacks until FB_GETCTX (a block of the Monero
// side branch, no other receipt's P_r): inside the walk a DEFER MoneroBlock and a fetch; J completes.
void jc_v11(const JoinNet& net) {
    const std::uint64_t L = 4600;
    const HOf hof = rate_of(12);
    const JcBounds b = jc_bounds(L, hof);
    const std::uint64_t x0 = b.x0;
    KatNode a(net, 9000);
    ChainShape sh;
    grow(a, x0, sh);
    const pb::Hash32 fork = at_pos(a, x0 - 3), below = at_pos(a, x0 - 4);
    const std::uint64_t hr = a.node(below).h;
    const pb::Hash32 alt_pr = block_id(kAltTag, hr - 1);
    const pb::ReceiptBodyV3 rs = body_on(a, below, hr, 3, 5940001, [&](pb::ReceiptBodyV3& r) { r.blob.prev_id = alt_pr; });
    const pb::CarrierBodyV3 s = carrier_on(a, fork, a.node(fork).h, {rs}, 5, 5940002);
    const pb::Hash32 sid = pb::receipt_id(s.own);
    const Admitted as = admit_place(a, s);
    const Carried c = carry_on_side(a, sid, x0 + 1, hof, 5940003);
    grow(a, L + 210 - (x0 + 1), sh);
    check(hr - 1 > kAltFrom && hr - 1 <= kAltFrom + kAltLen && as.placed && c.placed && c.live,
          "V11: A places s carrying a receipt whose P_r is a Monero side block (" + desc(as.r) + ")");
    auto sv = jc_server(a, 630, L, true);
    JoinerEnv je(net);
    je.hidden.insert(alt_pr);
    pb::Joiner j(je.in, kP53);
    j.offer(sv->best_id(), *sv);
    const JcRun run = jc_run(j, a, 1);
    jc_completes("V11", j, run, a, L);
    check(je.ctx_fetches >= 1 && je.hidden.count(alt_pr) == 0,
          "V11: the walk DEFERs on the missing P_r and fetches it (FB_GETCTX); then it passes");
}

// V13 (DF-4; E-100, E-101): 10 positions per height (x1 - x0 <= J_0 - 2); a branch of >= x1 - x0 + 2 carriers on the
// prefix node f = x0 - 2, its records one to two Monero heights behind c's chain, its tip t at >= x1 with H(t) <
// H(f) + F + Fresh; Monero rows at difficulty 10^8, so the window at t reaches back past H(f) + Fresh and reads a bin
// open at f still open at t; a placement below x0 in such a bin (the carrier at f carries a receipt of bin H(f) + 1).
// J completes, 0 alarms: those rows are not computed.
void jc_v13(const JoinNet& net) {
    const std::uint64_t L = 7000;
    const HOf hof = rate_of(10);
    const JcBounds b = jc_bounds(L, hof);
    const std::uint64_t x0 = b.x0, x1 = b.x1;
    const std::uint64_t f = x0 - 2;
    KatNode a(net, 9000);
    ChainShape sh;
    sh.hof = hof;
    grow(a, f - 1, sh);
    {
        // the carrier at f carries a receipt of bin H(f) + 1 (on its parent; P-11: h(r) <= h(c) + Fresh)
        const pb::Hash32 p = at_pos(a, f - 1);
        const pb::ReceiptBodyV3 rb = body_on(a, p, a.node(p).h + 1, 2, 5950001);
        const pb::CarrierBodyV3 cf = carrier_on(a, p, hof(f), {rb}, f % 4, 5950002);
        check(admit_place(a, cf).placed, "V13: the carrier at f carries a receipt of bin H(f) + 1");
    }
    const std::uint64_t q = f + 1100;
    grow(a, q - 1 - f, sh);  // the best chain first: always heavier than the branch
    const std::uint64_t Hf = a.node(at_pos(a, f)).H;
    const std::uint64_t k = x1 - f + 3;  // the branch's tip at x1 + 3
    const std::uint64_t rise = kF;       // H(t) = H(f) + F (< H(f) + F + Fresh)
    const auto hs = [&](std::uint64_t i) { return Hf + std::min<std::uint64_t>(rise, rise * i / (k - 5)); };
    const std::vector<pb::Hash32> br = side_branch(a, at_pos(a, f), k, hs, 5950100);
    const Carried c = br.size() == k ? carry_on_side(a, br.back(), q, hof, 5950200) : Carried{};
    grow(a, L + 210 - q, sh);
    const pb::CarrierNode& tn = a.node(br.empty() ? pb::Hash32{} : br.back());
    const pb::TipWindow tw = br.empty() ? pb::TipWindow{} : a.window(br.back());
    check(tw.ok() && tw.oldest_bin != 0 && tw.oldest_bin <= Hf + kFresh,
          "V13: the window at t reads a bin open at f (its oldest bin " + std::to_string(tw.oldest_bin) + " <= H(f) + Fresh = " +
                  std::to_string(Hf + kFresh) + ")");
    check(!b.young && x1 - x0 + 2 <= kJ0 && br.size() == k && tn.pos >= x1 && tn.H < Hf + kF + kFresh && c.placed &&
                  c.live && q - 1 - f <= kJ0,
          "V13: x1 - x0 = " + std::to_string(x1 - x0) + "; a branch of " + std::to_string(br.size()) +
                  " carriers on f = x0 - 2, its tip at " + std::to_string(tn.pos) + " (x1 = " + std::to_string(x1) +
                  "), H(t) - H(f) = " + std::to_string(tn.H - Hf) + "; carried at " + std::to_string(q));
    auto s = jc_server(a, 640, L, true);
    JoinerEnv je(net);
    pb::Joiner j(je.in, kP53);
    j.offer(s->best_id(), *s);
    const JcRun run = jc_run(j, a, 1);
    jc_completes("V13", j, run, a, L);
    check(j.adopted() && j.adopted()->tree->find(br.back()) != nullptr, "V13: the branch's tip placed in J's tree");
}

// N-1 (the cards check; E-86): FC_HEADERS frames of B bytes holding headers at their maximum size h_max, with
// (B - 8) mod h_max < 8: an honest full frame holds (B - 16) / h_max headers after its v0x02 head (FH 6 | u64
// first_pos | u16 n); the attempt takes such replies as full and completes (a head of 8 B would expect one more header
// and end the attempt as a short reply).
void jc_n1(const JoinNet& net) {
    const std::uint64_t L = 4600;
    KatNode a(net, 9000);
    grow(a, L + 10);
    JoinerEnv je(net);
    const std::uint64_t h_max = 1 + je.in.buffers.receipt + 1 + 2 * sizeof(std::uint64_t);
    const std::uint64_t n = 3, B = (n + 1) * h_max + 8 + 3;
    je.in.headers_frame_bytes = B;
    auto s = jc_server(a, 650, L, false);
    s->max_size_frame = B;
    pb::Joiner j(je.in, kP53);
    j.offer(s->best_id(), *s);
    const JcRun run = jc_run(j, a, 1);
    check((B - 8) % h_max < 8 && (B - 16) / h_max == n && (B - 8) / h_max == n + 1,
          "N-1: B = " + std::to_string(B) + ", h_max = " + std::to_string(h_max) + ": a full frame holds " +
                  std::to_string(n) + " headers after the 16 B head ((B - 8) mod h_max = " + std::to_string((B - 8) % h_max) + ")");
    jc_completes("N-1 (E-86)", j, run, a, L);
    check(s->header_requests >= L / n, "N-1: the header phase took full frames of " + std::to_string(n) + " headers (" +
                                               std::to_string(s->header_requests) + " requests)");
}

// N-3 (the review of the round-4 PR; E-102): P-51's header floor at the claimed prefix start x_pre(L') (with the
// record below it that fixes it), below x0(L') - N_rt at 12 per height; the body floor x0(L') - J_0 - 1 unchanged.
void jc_n3() {
    const pb::LaneParams& P = pb::kRuledLaneParams;
    const auto rec = [](std::uint64_t x) -> std::optional<std::uint64_t> { return x == 0 ? kLaneB0 : h_pos(x); };
    std::uint64_t n = 0, bad = 0, first_bad = 0, below = 0;
    for (std::uint64_t L = 5700; L <= 9000; ++L) {
        const JcBounds b = jc_bounds(L, h_pos);
        const pb::JoinServeFloors got = pb::join_serve_floors(P, L, rec, kLaneB0);
        const std::uint64_t want_h = header_floor_ref(b.x0, h_pos);
        ++n;
        if (got.headers != want_h || got.headers + 1 != b.x_pre || got.bodies != b.x0 - kJ0 - 1) {
            if (bad++ == 0) first_bad = L;
        }
        if (b.x_pre < b.x0 - kNrt) ++below;
    }
    check(bad == 0 && below == n,
          "N-3 (E-102): join_serve_floors keeps headers from x_pre(L') - 1 (the record that fixes x_pre) and bodies from "
          "x0(L') - J_0 - 1, for every L in [5,700, 9,000] at 12 per height (x_pre below x0 - N_rt at " +
                  std::to_string(below) + " of " + std::to_string(n) + "; " + std::to_string(bad) + " differ, the first " +
                  std::to_string(first_bad) + ")");
}

void jc1() {
    JoinNet net(900);
    jc_v1_v5(net);
    jc_v16(net);
}
void jc2() {
    JoinNet net(900);
    jc_nested(net);
    jc_v15(net);
}
void jc3() {
    JoinNet net(900);
    jc_v4(net);
    jc_v6(net);
    jc_v14(net);
}
void jc4() {
    JoinNet net(900);
    jc_v7(net);
    jc_v8(net);
    jc_branches(net);
    jc_v11(net);
}
void jc5() {
    JoinNet net(900, 100000000);  // D_net 10^8: the windows reach back past F bins
    jc_v13(net);
}
void jc6() {
    JoinNet net(900);
    jc_n1(net);
    jc_n3();
}

}  // namespace
int main(int argc, char** argv) {
    const std::string only = argc > 1 ? argv[1] : "";
    const auto run = [&](const char* name, void (*f)()) {
        if (!only.empty() && only != name) return;
        const auto t0 = std::chrono::steady_clock::now();
        const int f0 = g_fail;
        run_part(name, f);
        std::printf("[%s] %.1f s%s\n", name, secs(t0), g_fail != f0 ? " FAIL" : "");
        std::fflush(stdout);
    };
    run("span", span);
    run("young", young);
    run("buckets", buckets);
    run("afterl", afterl);
    run("claims", claims);
    run("attempts", attempts);
    run("candidates", candidates);
    run("scope", scope);
    run("header", header);
    run("d1", d1);
    run("fastpool", fastpool);
    run("ratchet", ratchet);
    run("jc1", jc1);  // ruling 53: V1, V5, V16
    run("jc2", jc2);  // ruling 53: V2, V2b, V3, V15
    run("jc3", jc3);  // ruling 53: V4, V6, V14
    run("jc4", jc4);  // ruling 53: V7, V8, V9, V10, V11, V12
    run("jc5", jc5);  // ruling 53: V13
    run("jc6", jc6);  // N-1 (E-86): the FC_HEADERS v0x02 frame head; N-3 (E-102): the header floor
    return finish("v37_xmr_joiner_kat");
}
