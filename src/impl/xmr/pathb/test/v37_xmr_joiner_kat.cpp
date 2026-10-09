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
// L from the reply, P-51 hold, fake and starved candidates), candidates (the
// bound-work rule, P-52, two states, own switch), d1 (retarget claims),
// fastpool, ratchet (rs_step_at in the joined tree).
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
                  "span bounds L=3,336: x0 = 1 at L' = 1,176 (not young)");
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
    for (std::uint64_t L : {0, 600, 1175, 3335}) {
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
        if (L == 600) {
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
    }
    {
        // L = 3,336: x0 = 1 at L' = 1,176, not young; J's digest == A's at L and L + 200
        OneJoin o = join_at(net, s, 3336);
        check(o.r && o.r->end == pb::AttemptEnd::Completed && !o.r->span.young && o.r->span.x0 == 1,
              "young L=3,336: completes with x0 = 1 (not young)" + (o.r ? ": " + rep_desc(*o.r) : ""));
        if (o.j->adopted()) {
            pb::JoinedState& js = *o.j->adopted();
            check(digest_of(js, at_pos(a, 3336)) == digest_of(a, at_pos(a, 3336)), "young L=3,336: J's digest == A's at L");
            check(follow(js, a, 3336, 3536) && digest_of(js, at_pos(a, 3536)) == digest_of(a, at_pos(a, 3536)),
                  "young L=3,336: J's digest == A's at L + 200");
        }
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
    // fetch C none (F-2 under ruling 44); the adopt bound
    {
        const std::uint64_t L = 4608;  // H(L) > H(L - 1): bins seal at L
        KatServer s(a, 42);
        std::set<pb::Hash32> ats;
        s.on_buckets = [&](const pb::GetBuckets& q, pb::BucketFrames&) { ats.insert(q.at); };
        OneJoin o = join_at(net, s, L);
        check(o.r && o.r->end == pb::AttemptEnd::Completed, "F-2: the join completes" + (o.r ? ": " + rep_desc(*o.r) : ""));
        if (o.j->adopted()) {
            pb::JoinedState& js = *o.j->adopted();
            const pb::Hash32 cl = at_pos(a, L), cx0 = at_pos(a, js.x0);
            check(a.node(cl).H > a.node(at_pos(a, L - 1)).H, "F-2: bins seal at L");
            bool only = true;
            for (const pb::Hash32& at : ats) only = only && (at == cx0 || at == cl);
            check(only && !ats.empty(), "F-2: no FC_GETBUCKETS at a child of L (every at is c_x0 or c_L)");
            const pb::LaneDelta* jd = js.store->delta(cl);
            const pb::LaneDelta* ad = a.store.delta(cl);
            bool same_seal = jd && ad && !jd->sealed.empty() && jd->sealed.size() == ad->sealed.size();
            for (std::size_t i = 0; same_seal && i < jd->sealed.size(); ++i)
                same_seal = jd->sealed[i].leaf == ad->sealed[i].leaf && js.claimed.count(jd->sealed[i].bucket.bin_lo) == 0;
            check(same_seal, "F-2: every bin sealed at L is recomputed from J's placements and equals A's");
            check(follow(js, a, L, L + 1) && digest_of(js, at_pos(a, L + 1)) == digest_of(a, at_pos(a, L + 1)),
                  "F-2: a child of L admitted with no MissingBucket of the join; J's digest == A's at L + 1");
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
    // at-header claims (BA-9): a proof, a leaf_count or an S_parent against the claimed at header -> alarm, the
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
// the AR seed, the attempt server's copies (BA-7, BA-11), every peer's copy
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
    // ended attempt (BA-10): attempt 1 from a forging server ends on an alarm; attempt 2 over the same tip ids joins
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
    // forged Boundary in the replay (CK4-5): the attempt's server serves s with its parent link J_0 + 1 below the
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
    // one variant per id and attempt (CK4-6): a second, different variant of a side carrier id; a second body set
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
    // the attempt's L from the server's reply; the server holds its P-51 floor for the open attempt (B-4)
    {
        KatServer m(a, 131);
        m.retention = true;
        m.top = L;
        const pb::Hash32 hello = m.best_id();
        m.before = [&](KatServer& k) {
            if (k.requests == 1) k.top = L + 12;       // the tip moved one Monero height since its HELLO
            else if (k.requests == 2) k.top = L + 24;  // and again after the attempt's first reply
        };
        JoinerEnv je(net);
        pb::Joiner j(je.in, kP53);
        j.offer(hello, m);
        const std::optional<pb::AttemptReport> r = j.run_next();
        check(r && r->end == pb::AttemptEnd::Completed && r->L == L + 12,
              "moved tip: the attempt takes L from the server's reply and completes while the tip moves" +
                      (r ? ": " + rep_desc(*r) : ""));
        check(j.adopted() && digest_of(*j.adopted(), at_pos(a, L + 12)) == digest_of(a, at_pos(a, L + 12)),
              "moved tip: J's digest == A's at the attempt's L");
    }
    // a fake candidate (CK4-3): a chain of >= 3,336 carriers with no canonical coinbase, offered by three servers
    // before the honest one: every attempt on it ends at its first computed #9; J joins the honest chain; a fourth
    // fake server joining after that changes nothing; P-52 (S3b4-8): a server naming the honest tip that forges is
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
        // S3b4-8: a P0 server names H first and the honest server names H next, both before the stream; the P0 server
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
    explicit FullChain(KatNode& k) : n(&k) {}
    bool holds(const pb::Hash32& id) const override { return n->tree.find(id) != nullptr; }
    std::optional<std::uint64_t> pos_of(const pb::Hash32& id) const override {
        const pb::CarrierNode* c = n->tree.find(id);
        if (c == nullptr) return std::nullopt;
        return c->pos;
    }
    std::optional<std::uint64_t> joined_x1() const override { return std::nullopt; }
    std::uint64_t store_base() const override { return n->store.base_pos(); }
    pb::BoundWork bound_work() const override {
        pb::BoundWork w;
        for (std::uint64_t x = n->store.tip_pos(); x >= 1; --x) {
            const pb::CarrierNode* c = n->tree.find(*n->store.best_at(x));
            w.add(c->h, c->d);
        }
        return w;
    }
    pb::Hash32 tip() const override { return n->store.best_tip(); }
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
        pb::BoundWork big, less;
        for (std::uint64_t k = 0; k < (1u << 16); ++k) big.add(1000 + k, UINT64_MAX);
        for (std::uint64_t k = 0; k + 1 < (1u << 16); ++k) less.add(1000 + k, UINT64_MAX);
        less.add(1000 + (1u << 16) - 1, UINT64_MAX - 1);
        check(pb::candidate_replaces(big, hid(9), less, hid(1)) && !pb::candidate_replaces(less, hid(1), big, hid(9)),
              "bound work in U128: 2^16 carriers at d = 2^64 - 1 do not wrap");
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
        grow(p, 4950, ps);
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
        j.set_on_step([&](pb::JoinedState&, std::uint64_t x) {
            if (x % 6 == 0 && next < 4950 && follow(*j.adopted(), p, next, next + 1, 9)) ++next;
        });
        const std::optional<pb::AttemptReport> r2 = j.run_next();
        j.set_on_step({});
        check(next >= 4900, "candidates (a): the fake grew by " + std::to_string(next - 4500) + " carriers during the honest attempt");
        check(r2 && r2->end == pb::AttemptEnd::Completed && r2->a_profile_read && j.last_switch().replaced,
              "candidates (a): the honest candidate completes and replaces the fake (A's profile read when the attempt took its L)" +
                      (r2 ? ": " + rep_desc(*r2) : ""));
        check(j.adopted() && j.adopted()->pending.empty() && j.last_switch().lost > 0,
              "no re-pend: the switch by the joiner path re-pends nothing (pending set empty); the abandoned open-bin "
              "placements are counted lost (" + std::to_string(j.last_switch().lost) + ")");
        check(j.adopted() && digest_of(*j.adopted(), at_pos(a, 5400)) == digest_of(a, at_pos(a, 5400)),
              "candidates (a): J's digest == A_full's after the replacement");
    }
    // the stale top (B-1; ruling 45): J adopts the honest chain at L_A; a P< server mines k carriers on x1_A at the
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
        check(steps && ok_claims, "two states: rests_on_claims stays false while later attempts run (A's answer)");
        check(steps && ok_tpl, "two states: A builds templates equal to A_full's while the attempts run");
        check(steps && ok_copies, "two states: A judges every peer's copy while the attempts run");
        check(steps && own_caches, "two states: each state owns its own window and key cache instances");
        check(j.adopted() && j.adopted()->tip() == atip, "two states: no attempt changes A");
    }
    // the cache level (MU-J43; N-3): an entry the attempt state computed at tip t (substituted side_data) is not
    // A's: the window leg (key {tip, v}) and the key leg (same payees, another key reference)
    {
        JoinerEnv je(net);
        pb::JoinedState A(je.in, 1), att(je.in, 2);
        const pb::Hash32 t = at_pos(a, 4000);
        pb::TipWindow forged = a.window(t, 16);
        forged.window_root[0] ^= 1;
        (void)att.windows().get(t, 16, [&] { return forged; });
        const pb::TipWindow honest = a.window(t, 16);
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
// d1: the D-1 vector (E-75 (i), E-76): work moved between two span carriers of
// one bin with the retarget prefix and the receipts_roots forged to match
// (CK6 2.2, 2.3; the construction of s3b/ck6/d1_sim.py in exact S1.4 integers)
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
    check(sr.status == pb::SpanStatus::Ok && !sr.bounds.young && x0 > kNrt, "D-1: the span at L' (x0 above N_rt)");
    const pb::Hash32 dL = digest_of(a, at_pos(a, L));
    // (i) at the joiner's span: the mismatch at a computed S1.3 #8 in (a + N_rt, b + N_rt], inside the replay
    {
        const D1Forgery g = solve_d1(a, x0, x1, L, 10000, x1);
        check(g.ok && g.b <= x1 && g.a < g.b, "D-1 (i): a feasible forgery: a < b <= x1 of one bin, delta 10,000 (" + g.why + ")");
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
              "D-1 (i): J raises a local alarm + DEFER at a computed S1.3 #8 in (a + N_rt, b + N_rt] inside the replay, 0 tokens" +
                      (it != reps.end() ? ": " + rep_desc(it->second) : ""));
        check(j.adopted() && digest_of(*j.adopted(), at_pos(a, L)) == dL && follow(*j.adopted(), a, L, L + 200) &&
                      digest_of(*j.adopted(), at_pos(a, L + 200)) == digest_of(a, at_pos(a, L + 200)),
              "D-1 (i): J reaches A's lane digest at L and at L + 200 from the next server");
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
              "D-1 (i'): a feasible forgery against E-16's span at L (its mismatch past L) (" + g.why + ")");
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
              "D-1 (i'): with the span at L' the forgery mismatches a computed S1.3 #8 inside the replay, 0 tokens" +
                      (it != reps.end() ? ": " + rep_desc(it->second) : ""));
        check(j.adopted() && j.adopted()->tip() == at_pos(a, L) && follow(*j.adopted(), a, L, L + 1050) &&
                      digest_of(*j.adopted(), at_pos(a, L + 1050)) == digest_of(a, at_pos(a, L + 1050)),
              "D-1 (i'): J joins the honest chain and follows A past b + N_rt with A's digest");
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
    run("d1", d1);
    run("fastpool", fastpool);
    run("ratchet", ratchet);
    return finish("v37_xmr_joiner_kat");
}
