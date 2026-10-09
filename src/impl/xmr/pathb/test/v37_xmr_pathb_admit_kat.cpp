// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_pathb_admit_kat.cpp
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "pathb_kat_admit.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

using pb::AdmitVerdict;
using pb::CarrierRole;
using pb::Missing;
using pb::RowId;

const std::uint64_t kJ0 = pb::admit_j0(pb::kRuledLaneParams);

bool is(const pb::AdmitResult& r, AdmitVerdict v, RowId row) { return r.verdict == v && r.row == row; }
bool deferred(const pb::AdmitResult& r, Missing m) { return r.verdict == AdmitVerdict::Defer && r.missing == m; }

// A pipeline chain of `count` carriers on the best tip (every carrier admitted
// and placed through the pipeline), heights hof(pos).
std::vector<pb::Hash32> pipeline_chain(KatNode& n, std::uint64_t count, std::uint64_t nonce0 = 1,
                                       const std::function<std::uint64_t(std::uint64_t)>& hof = h_pos) {
    std::vector<pb::Hash32> out;
    pb::Hash32 prev = n.tree.best().id;
    const std::uint64_t base = n.node(prev).pos;
    for (std::uint64_t i = 1; i <= count; ++i) {
        const pb::CarrierBodyV3 c = carrier_on(n, prev, hof(base + i), {}, (base + i) % 4, nonce0 + base + i);
        const Admitted a = admit_place(n, c);
        if (!a.placed) {
            check(false, "pipeline chain: carrier not placed at " + std::to_string(base + i) + ": " + desc(a.r));
            break;
        }
        prev = pb::receipt_id(c.own);
        out.push_back(prev);
    }
    return out;
}

pb::AdmitResult admit(KatNode& n, const pb::CarrierBodyV3& c, CarrierRole role = CarrierRole::Frame) {
    return pb::admit_carrier(n.env(), frame_of(c), role);
}

// The offset of side_data in an encoded receipt body.
std::size_t side_offset(const pb::ReceiptBodyV3& r) {
    std::vector<std::uint8_t> blob;
    pb::encode_hashing_blob(r.blob, blob);
    return 1 + blob.size() + pb::kExtraNonceBytes + 1 + pb::kHashBytes * r.branch.size();
}

void put_u16(std::vector<std::uint8_t>& b, std::size_t o, std::uint16_t v) {
    b[o] = static_cast<std::uint8_t>(v);
    b[o + 1] = static_cast<std::uint8_t>(v >> 8);
}

// ---------------------------------------------------------------------------
// S1.3 rows 1-9 and S2.3 rows 14-16 on one node (J = J_0)
// ---------------------------------------------------------------------------
void rows_head() {
    run_part("rows 1-9, 14-16", [] {
        KatNet net;
        KatNode n(net, kJ0);
        const std::vector<pb::Hash32> chain = pipeline_chain(n, 40);
        const pb::Hash32 tip = chain.back();
        const std::uint64_t ht = h_pos(41);

        // row 1: the frame buffer P-11, before parsing
        {
            const std::vector<std::uint8_t> big(n.buffers.frame + 1, 0), exact(n.buffers.frame, 0);
            const pb::AdmitResult a = pb::admit_carrier(n.env(), big, CarrierRole::Frame);
            const pb::AdmitResult b = pb::admit_carrier(n.env(), exact, CarrierRole::Frame);
            check(is(a, AdmitVerdict::Drop, RowId::R1) && a.strike == 0, "row 1: a frame of P-11 + 1 B -> DROP, 0 tokens");
            check(b.verdict == AdmitVerdict::Strike && b.row == RowId::R2, "row 1: a frame of P-11 exactly is parsed (#1b refuses it)");
        }
        // row 2: ver, n_carried <= R_MAX, trailing bytes; no fetch
        {
            const pb::CarrierBodyV3 c = carrier_on(n, tip, ht, {}, 1, 4101);
            std::vector<std::uint8_t> v2 = frame_of(c), tr = frame_of(c);
            v2[pb::kFrameHeaderBytes] = 2;
            tr.push_back(0);
            std::vector<pb::ReceiptBodyV3> rs;
            for (std::uint64_t k = 0; k < 17; ++k) rs.push_back(body_on(n, tip, ht, 2 + k % 3, 4110 + k));
            const pb::CarrierBodyV3 c17 = carrier_on(n, tip, ht, rs, 1, 4102);
            const std::vector<std::uint8_t> f17 = pb::carrier_frame(c17, 17).value_or(std::vector<std::uint8_t>{});
            const std::uint64_t pr0 = n.pr_calls;
            const pb::AdmitResult a = pb::admit_carrier(n.env(), v2, CarrierRole::Frame);
            const pb::AdmitResult b = pb::admit_carrier(n.env(), f17, CarrierRole::Frame);
            const pb::AdmitResult d = pb::admit_carrier(n.env(), tr, CarrierRole::Frame);
            check(is(a, AdmitVerdict::Strike, RowId::R2) && a.strike == 1, "row 2: ver 2 -> STRIKE");
            check(is(b, AdmitVerdict::Strike, RowId::R2) && b.strike == 1, "row 2: n_carried 17 -> STRIKE");
            check(is(d, AdmitVerdict::Strike, RowId::R2), "row 2: a trailing byte -> STRIKE");
            check(n.pr_calls == pr0, "row 2: no fetch before #1b passes");
            check(admit(n, c).verdict == AdmitVerdict::AdmitCarrier, "row 2: the frame itself is admitted");
        }
        // row 14: the receipt buffer P-10
        {
            const pb::ReceiptBodyV3 big = body_on(n, tip, ht, 3, 4120, [](pb::ReceiptBodyV3& r) {
                for (int i = 0; i < 18; ++i) r.branch.push_back(seq32(static_cast<std::uint8_t>(0x30 + i)));
            });
            const std::vector<std::uint8_t> bb = bytes_of(big);
            check(bb.size() > n.buffers.receipt && bb.size() < n.buffers.frame, "row 14: a body above P-10");
            const pb::AdmitResult a = pb::admit_receipt(n.env(), bb, pb::Role::Pending);
            check(is(a, AdmitVerdict::Drop, RowId::R14) && a.strike == 0, "row 14: a body of P-10 + 1 B or more -> DROP, 0 tokens");
            const pb::CarrierBodyV3 c = carrier_on(n, tip, ht, {big}, 1, 4121);
            const std::vector<std::uint8_t> f = frame_of(c);
            const pb::AdmitResult b = pb::admit_carrier(n.env(), f, CarrierRole::Frame);
            check(f.size() <= n.buffers.frame && is(b, AdmitVerdict::Drop, RowId::R14) && b.strike == 0,
                  "row 14: a carried body above P-10 in a frame within P-11 -> the frame DROP, 0 tokens");
        }
        // row 15: ID-1 for every receipt, before any fetch and RandomX
        {
            const std::uint64_t pr0 = n.pr_calls, rx0 = n.rx_calls;
            pb::ReceiptBodyV3 bad = body_on(n, tip, ht, 4, 4130);
            bad.payee = net.refs[5];  // another key under side.payee
            const pb::AdmitResult a = pb::admit_receipt(n.env(), bytes_of(bad), pb::Role::Pending);
            check(is(a, AdmitVerdict::Strike, RowId::R15) && n.pr_calls == pr0 && n.rx_calls == rx0,
                  "row 15: payee_ref of another key -> STRIKE at #1b, 0 fetches, no RandomX");
            pb::ReceiptBodyV3 own = body_on(n, tip, ht, 4, 4131, [&](pb::ReceiptBodyV3& r) {
                r.side.fee_rate_bp = 100;
                r.owner = net.refs[6];
                r.side.owner = net.ids[6];
            });
            own.owner = net.refs[7];
            check(is(pb::admit_receipt(n.env(), bytes_of(own), pb::Role::Pending), AdmitVerdict::Strike, RowId::R15),
                  "row 15: owner_ref mismatch at p > 0 -> STRIKE");
            const pb::CarrierBodyV3 c = carrier_on(n, tip, ht, {bad}, 1, 4132);
            check(is(admit(n, c), AdmitVerdict::Strike, RowId::R15), "row 15: a carried body's ID-1 -> the frame STRIKE");
            // N1: the attacker names the victim's identity with its own key; the victim's receipt matches
            pb::ReceiptBodyV3 att = body_on(n, tip, ht, 8, 4133);
            att.side.payee = net.ids[9];
            const pb::ReceiptBodyV3 victim = body_on(n, tip, ht, 9, 4134);
            const pb::AdmitResult x = pb::admit_receipt(n.env(), bytes_of(att), pb::Role::Pending);
            const pb::AdmitResult y = pb::admit_receipt(n.env(), bytes_of(victim), pb::Role::Pending);
            check(x.verdict == AdmitVerdict::Strike && x.strike == 1 && y.verdict == AdmitVerdict::AdmitPending,
                  "row 15: N1 poisoning: the attacker STRIKE, the victim's receipt admitted (Match)");
        }
        // row 16: pool_id, E-11 (p + give_author_bp <= 10000)
        {
            const auto with_owner = [&](std::uint16_t p, std::uint16_t ga, std::uint64_t nonce) {
                return body_on(n, tip, ht, 10, nonce, [&](pb::ReceiptBodyV3& r) {
                    r.side.fee_rate_bp = p;
                    r.side.give_author_bp = ga;
                    if (p > 0) {
                        r.owner = net.refs[11];
                        r.side.owner = net.ids[11];
                    }
                });
            };
            const auto patched = [&](std::uint16_t p, std::uint16_t ga, std::uint64_t nonce) {
                pb::ReceiptBodyV3 r = with_owner(100, 10, nonce);
                std::vector<std::uint8_t> b = bytes_of(r);
                const std::size_t so = side_offset(r);
                put_u16(b, so + pb::side_v3::kFeeRateOff, p);
                put_u16(b, so + pb::side_v3::kGiveAuthorOff, ga);
                return b;
            };
            const pb::AdmitResult a = pb::admit_receipt(n.env(), patched(10000, 1, 4140), pb::Role::Pending);
            const pb::AdmitResult b = pb::admit_receipt(n.env(), patched(5001, 5000, 4141), pb::Role::Pending);
            check(is(a, AdmitVerdict::Strike, RowId::R16) && is(b, AdmitVerdict::Strike, RowId::R16),
                  "row 16: 10000 + 1 and 5001 + 5000 -> STRIKE");
            const pb::AdmitResult c = pb::admit_receipt(n.env(), bytes_of(with_owner(9990, 10, 4142)), pb::Role::Pending);
            const pb::AdmitResult d = pb::admit_receipt(n.env(), bytes_of(with_owner(10000, 0, 4143)), pb::Role::Pending);
            check(c.verdict == AdmitVerdict::AdmitPending && d.verdict == AdmitVerdict::AdmitPending,
                  "row 16: 9990 + 10 and 10000 + 0 -> admitted (" + desc(c) + ", " + desc(d) + ")");
            pb::ReceiptBodyV3 foreign = body_on(n, tip, ht, 10, 4144, [](pb::ReceiptBodyV3& r) { r.side.pool_id = seq32(0x11); });
            check(is(pb::admit_receipt(n.env(), bytes_of(foreign), pb::Role::Pending), AdmitVerdict::Strike, RowId::R16),
                  "row 16: a foreign pool_id -> STRIKE");
        }
        // row 3: pool_id of the frame, rules_epoch
        {
            const std::uint64_t pr0 = n.pr_calls;
            const pb::CarrierBodyV3 f = carrier_on(n, tip, ht, {}, 1, 4150, [](pb::ReceiptBodyV3& r) { r.side.pool_id = seq32(0x11); });
            const pb::AdmitResult a = admit(n, f);
            check(is(a, AdmitVerdict::Strike, RowId::R3) && n.pr_calls == pr0, "row 3: a foreign pool_id -> STRIKE, resolver calls 0");
            const pb::CarrierBodyV3 e = carrier_on(n, tip, ht, {}, 1, 4151, [](pb::ReceiptBodyV3& r) { r.side.rules_epoch = 1; });
            check(is(admit(n, e), AdmitVerdict::Strike, RowId::R3), "row 3: rules_epoch 1 at x < H_hold -> STRIKE");
        }
        // row 5: P_r
        {
            const pb::CarrierBodyV3 c = carrier_on(n, tip, ht, {}, 1, 4160);
            n.pr_missing.insert(c.own.blob.prev_id);
            const pb::AdmitResult a = admit(n, c);
            n.pr_missing.clear();
            n.bad_ctx.insert(c.own.blob.prev_id);
            const pb::AdmitResult b = admit(n, c);
            n.bad_ctx.clear();
            check(deferred(a, Missing::MoneroBlock) && a.fetch == c.own.blob.prev_id && a.strike == 0,
                  "row 5: P_r unknown -> DEFER + fetch");
            check(is(b, AdmitVerdict::Ban, RowId::R5) && b.strike == 0, "row 5: a served context block failing its PoW -> BAN");
        }
        // row 6: freshness
        {
            const pb::CarrierBodyV3 c = carrier_on(n, tip, n.node(tip).h + 3, {}, 1, 4170);
            const pb::AdmitResult a = admit(n, c);
            check(is(a, AdmitVerdict::Refuse, RowId::R6) && a.strike == 0, "row 6: h = h(tip) + 3 -> REFUSE, 0 tokens");
        }
        // row 8: header fields and the vote rule
        {
            const auto with_blob = [&](std::uint64_t major, std::uint64_t minor, std::uint64_t nonce, std::int64_t ts_back = 0) {
                pb::CarrierBodyV3 c = carrier_on(n, tip, ht, {}, 1, nonce, [&](pb::ReceiptBodyV3& r) {
                    r.blob.major = major;
                    r.blob.minor = minor;
                    if (ts_back) r.blob.timestamp = mon_ts(ht - 1) - static_cast<std::uint64_t>(ts_back);
                });
                return admit(n, c);
            };
            check(is(with_blob(16, 0, 4180), AdmitVerdict::Strike, RowId::R8), "row 8: minor 0 at hf 16 -> STRIKE (votes 1)");
            check(is(with_blob(16, 15, 4181), AdmitVerdict::Strike, RowId::R8), "row 8: minor 15 -> STRIKE");
            check(with_blob(16, 16, 4182).verdict == AdmitVerdict::AdmitCarrier, "row 8: minor 16 -> admitted");
            check(with_blob(16, 17, 4183).verdict == AdmitVerdict::AdmitCarrier, "row 8: minor 17 -> admitted");
            check(is(with_blob(17, 17, 4184), AdmitVerdict::Strike, RowId::R8), "row 8: major 17 at hf 16 -> STRIKE");
            check(is(with_blob(16, 16, 4185, 120 * 200), AdmitVerdict::Strike, RowId::R8),
                  "row 8: timestamp below median60 -> STRIKE");
        }
        // row 9: t_origin == d_at(parent)
        {
            const pb::CarrierBodyV3 c = carrier_on(n, tip, ht, {}, 1, 4190, [](pb::ReceiptBodyV3& r) { r.side.t_origin -= 1; });
            check(is(admit(n, c), AdmitVerdict::Strike, RowId::R9), "row 9: t_origin = d - 1 -> STRIKE");
        }
        // row 4: an unknown parent waits under (id, claimed parent); a forged-parent copy first, the honest copy placed
        {
            KatNode scratch(n);
            const pb::CarrierBodyV3 x = carrier_on(scratch, tip, ht, {}, 2, 4201);
            check(admit_place(scratch, x).placed, "row 4: X placed in a scratch copy");
            const pb::Hash32 xid = pb::receipt_id(x.own);
            const pb::CarrierBodyV3 y = carrier_on(scratch, xid, h_pos(42), {}, 3, 4202);
            const pb::Hash32 yid = pb::receipt_id(y.own);
            pb::CarrierBodyV3 yf = y;
            yf.own.side.tip = seq32(0xEE);  // a forged parent claim (same blob, same id)
            pb::DeferredCarriers store(pb::waiting_cap_default());
            const auto park = [&](const pb::CarrierBodyV3& c, std::uint64_t peer) {
                const std::vector<std::uint8_t> f = frame_of(c);
                const pb::AdmitResult r = pb::admit_carrier(n.env(), f, CarrierRole::Frame);
                pb::ParkedFrame pf;
                pf.digest = ::v37::sha256d(f);
                pf.id = pb::receipt_id(c.own);
                pf.parent = c.own.side.tip;
                pf.peer = peer;
                pf.frame = f;
                pf.cause = r.missing.value_or(Missing::NodeInternal);
                return std::make_pair(r, store.park(n.tree, pf));
            };
            const auto pa = park(yf, 2);
            const auto pb_ = park(y, 1);
            check(deferred(pa.first, Missing::ParentUnknown) && pa.first.fetch == seq32(0xEE) && pa.first.strike == 0
                          && deferred(pb_.first, Missing::ParentUnknown) && pb_.first.fetch == xid && pa.second && pb_.second,
                  "row 4: unknown parent -> DEFER + FC_GETCARRIER(tip); both copies parked");
            check(n.tree.waiting() == 2 && store.waiting_keys() == 2, "row 4: waiting (Y, Z) and (Y, X); tree and store in step");
            const Admitted ax = admit_place(n, x);
            check(ax.placed && ax.w.place.released == std::vector<pb::Hash32>{yid}, "row 4: X placed, Y released");
            bool placed = false;
            for (const pb::ParkedFrame& f : store.release(xid, ax.w.place.released)) {
                const pb::AdmitResult r = pb::admit_carrier(n.env(), f.frame, CarrierRole::Frame);
                if (r.verdict == AdmitVerdict::AdmitCarrier) {
                    const pb::WriteResult w = pb::place_admitted(n.tree, n.store, n.ar, n.bodies, r, &n.alarm);
                    placed = placed || w.outcome == pb::WriteOutcome::Extended;
                    if (placed) store.purge(r.id);
                }
            }
            check(placed && n.tree.find(yid) != nullptr && n.node(yid).parent == xid,
                  "row 4: the honest copy of Y placed on X's arrival");
            check(n.tree.waiting() == 0 && store.waiting_keys() == 0 && store.size() == 0,
                  "row 4: the forged claim dropped; tree and store hold no waiting entry");
        }
    });

    // row 3 at x >= H_hold: a kind-2 descriptor this build does not implement (fixed at 20)
    run_part("row 3 hold", [] {
        KatNet net;
        pb::EpochTable T = kat_table(net);
        constexpr std::uint64_t kFixed = 20;
        T.attempts.push_back(pb::Deployment{1, seq32(0x7c), pb::kKindFixed, 0, 1000000, kFixed});
        KatNode n(net, kJ0, pb::kRuledRatchetParams, T);
        const std::vector<pb::Hash32> chain = pipeline_chain(n, kFixed - 2);
        const pb::Hash32 tip = chain.back();  // position 18: x = 19 < H_hold
        const pb::CarrierBodyV3 c19 = carrier_on(n, tip, h_pos(19), {}, 1, 4300);
        check(admit_place(n, c19).placed, "row 3: x = 19 < H_hold 20: judged and placed");
        const pb::Hash32 t19 = pb::receipt_id(c19.own);
        const pb::CarrierBodyV3 c20 = carrier_on(n, t19, h_pos(20), {}, 1, 4301);
        const pb::AdmitResult a = admit(n, c20);
        check(deferred(a, Missing::Hold) && a.strike == 0, "row 3: rules_epoch 0 at x = H_hold -> DEFER into the P-34 store");
        const pb::CarrierBodyV3 bad = carrier_on(n, t19, h_pos(20), {}, 1, 4302,
                                                 [](pb::ReceiptBodyV3& r) { r.side.rules_epoch = pb::kEpochMax + 1; });
        check(is(admit(n, bad), AdmitVerdict::Strike, RowId::R3), "row 3: a value above 2^15 - 1 at x >= H_hold -> STRIKE");
    });

    // row 7: a carrier below its parent's record is not a carrier: the body continues as a receipt
    run_part("row 7", [] {
        KatNet net;
        KatNode n(net, kJ0, pb::kRuledRatchetParams, std::nullopt, {pb::RetargetEntry{18180, kLaneB0 + 5}});
        const pb::Hash32 g = n.tree.genesis().id;
        check(n.node(g).H == kLaneB0 + 5 && n.node(g).h == kLaneB0, "row 7: genesis record H(0) above h(0) (an inherited record)");
        const pb::CarrierBodyV3 c = carrier_on(n, g, kLaneB0 + 1, {}, 1, 4310);
        const pb::AdmitResult a = admit(n, c);
        check(a.verdict == AdmitVerdict::AdmitPending && a.strike == 0,
              "row 7: h < H(parent) -> not a carrier, admitted PENDING, 0 tokens (" + desc(a) + ")");
    });
}


// A carrier placed off the store's best chain (a side branch; the tree's best may move to it).
bool held_side(const pb::WriteResult& w) {
    return w.outcome == pb::WriteOutcome::SideBranch || w.outcome == pb::WriteOutcome::SwitchToCaller;
}

// One height per position (bins seal from position 96 on).
std::uint64_t h_fast(std::uint64_t pos) { return kLaneB0 + pos; }

// The lane digest of a placed carrier: S, its view's leaf_count and mmr_root,
// and its placements (id, live).
std::vector<std::uint8_t> lane_digest(const KatNode& n, const pb::Hash32& id) {
    std::vector<std::uint8_t> out;
    const pb::CarrierNode* c = n.tree.find(id);
    if (c == nullptr) return out;
    const pb::RatchetStateBytes sb = pb::encode_ratchet_state(c->rs);
    out.insert(out.end(), sb.begin(), sb.end());
    const pb::LaneView v = n.store.view_at(id);
    if (!v.ok()) return out;
    const pb::Hash32 root = v.mmr_root();
    out.insert(out.end(), root.begin(), root.end());
    pb::detail::put_le(out, v.leaf_count());
    if (const pb::LaneDelta* d = n.store.delta(id))
        for (const pb::Placement& x : d->placed) {
            out.insert(out.end(), x.id.begin(), x.id.end());
            out.push_back(x.live ? 1 : 0);
        }
    return out;
}

// ---------------------------------------------------------------------------
// S1.3 rows 10-13 and S2.3 rows 17-31 (carried bodies) on one node
// ---------------------------------------------------------------------------
void rows_body() {
    run_part("rows 10-13, 20-31", [] {
        KatNet net;
        KatNode n(net, kJ0);
        const std::vector<pb::Hash32> chain = pipeline_chain(n, 60);
        const pb::Hash32 L = chain.back();  // position 60
        const std::uint64_t hL = n.node(L).h;
        const std::uint64_t hc = h_pos(61);

        // row 10: a carrier whose coinbase pays the window of a sibling tip -> BAN, RandomX not called
        {
            const pb::CarrierBodyV3 s1 = scaffold_body(n, chain[58], hL, 0x5A, 9001, 7);
            check(held_side(place_direct(n, s1)), "row 10: a sibling S of the best tip held");
            const pb::Hash32 S = pb::receipt_id(s1.own);
            pb::CarrierBodyV3 c = carrier_on(n, S, hc, {}, 1, 5000);
            const pb::TipWindow wl = n.window(L);
            commit_miner_tx(c.own, *wl.window, S, c.own.blob.prev_id, hc, net.book, net.author);
            const std::uint64_t rx0 = n.rx_calls;
            const pb::AdmitResult a = admit(n, c);
            check(is(a, AdmitVerdict::Ban, RowId::R10) && n.rx_calls == rx0 && !a.randomx_called,
                  "row 10: the coinbase pays window(L), not window(parent(c)) -> BAN, RandomX not called (" + desc(a) + ")");
            const pb::CarrierBodyV3 h = carrier_on(n, S, hc, {}, 1, 5001);
            check(admit(n, h).verdict == AdmitVerdict::AdmitCarrier, "row 10: the honest carrier on S admitted");
        }
        // row 12: RandomX last, once per body
        {
            const pb::CarrierBodyV3 c = carrier_on(n, L, hc, {}, 1, 5010);
            n.bad_pow.insert(pb::receipt_id(c.own));
            const std::uint64_t rx0 = n.rx_calls;
            const pb::AdmitResult a = admit(n, c);
            n.bad_pow.clear();
            check(is(a, AdmitVerdict::Ban, RowId::R12) && n.rx_calls == rx0 + 1 && a.randomx_called,
                  "row 12: RandomX false on the own body -> BAN after every cheap row");
            n.no_seed.insert(c.own.blob.prev_id);
            const pb::AdmitResult b = admit(n, c);
            n.no_seed.clear();
            check(deferred(b, Missing::Seed) && b.strike == 0, "row 12: seed missing -> DEFER");
            pb::CarrierBodyV3 m = carrier_on(n, L, hc, {}, 1, 5011);
            m.own.side.ballot ^= 1;  // side_data changed after the coinbase was built
            const std::uint64_t rx1 = n.rx_calls;
            const pb::AdmitResult d = admit(n, m);
            check(is(d, AdmitVerdict::Ban, RowId::R10) && n.rx_calls == rx1, "row 12: a coinbase mismatch: BAN, RandomX 0");
        }
        // rows 26, 27, 29 and 11 on carried bodies of a carrier on L
        {
            const std::uint64_t pr0 = n.pr_calls;
            (void)pr0;
            // row 29: a carried body with a bad PoW -> the frame BAN, the store unchanged
            const pb::ReceiptBodyV3 r1 = body_on(n, L, hL + 1, 12, 5020);
            const pb::CarrierBodyV3 c = carrier_on(n, L, hc, {r1}, 1, 5021);
            n.bad_pow.insert(pb::receipt_id(r1));
            const pb::BmmrHead head = n.store.head();
            const std::size_t jsz = n.store.journal_size();
            const pb::AdmitResult a = admit(n, c);
            n.bad_pow.clear();
            check(is(a, AdmitVerdict::Ban, RowId::R29) && n.store.head() == head && n.store.journal_size() == jsz
                          && n.tree.find(pb::receipt_id(c.own)) == nullptr,
                  "row 29: a carried body with a bad PoW -> the frame BAN, the store and the tree unchanged");
            // row 11: two carried, carried_root 0 -> STRIKE; RandomX 0
            const pb::ReceiptBodyV3 r2 = body_on(n, L, hL + 1, 13, 5022);
            const pb::CarrierBodyV3 z = carrier_on(n, L, hc, {r1, r2}, 1, 5023, [&](pb::ReceiptBodyV3& r) {
                r.side.receipts_root = n.tree.next_receipts_root(L, {}).value();
            });
            const std::uint64_t rx0 = n.rx_calls;
            const pb::AdmitResult b = admit(n, z);
            check(is(b, AdmitVerdict::Strike, RowId::R11) && n.rx_calls == rx0 && !b.randomx_called,
                  "row 11: two carried with carried_root 0 -> STRIKE, RandomX not called");
            // row 11: a canonical order that is not bytewise ascending -> placed (in a scratch copy)
            for (std::uint64_t k = 0; k < 64; ++k) {
                std::vector<pb::ReceiptBodyV3> rs{body_on(n, L, hL + 1, 14, 5100 + 2 * k), body_on(n, L, hL + 1, 15, 5101 + 2 * k)};
                canonical_sort(net, rs, L);
                if (pb::receipt_id(rs[0]) < pb::receipt_id(rs[1])) continue;
                KatNode sc(n);
                const Admitted ad = admit_place(sc, carrier_on(sc, L, hc, rs, 1, 5200 + k));
                check(ad.placed, "row 11: a carried list in canonical order, not bytewise ascending -> placed");
                break;
            }
            // row 26: hf 17 -> REFUSE, 0 tokens, RandomX 0
            const pb::ReceiptBodyV3 r17 = body_on(n, L, hL + 2, 16, 5030, [](pb::ReceiptBodyV3& r) {
                r.blob.major = 17;
                r.blob.minor = 17;
                r.branch.push_back(seq32(0x44));
            });
            n.hf17.insert(r17.blob.prev_id);
            const pb::CarrierBodyV3 c17 = carrier_on(n, L, hL + 1, {r17}, 1, 5031);
            const std::uint64_t rx1 = n.rx_calls;
            const pb::AdmitResult f = admit(n, c17);
            n.hf17.clear();
            check(is(f, AdmitVerdict::Refuse, RowId::R26) && f.strike == 0 && n.rx_calls == rx1,
                  "row 26: hf 17 -> REFUSE, 0 tokens, RandomX 0 (" + desc(f) + ")");
            // row 27: a forged window_root -> BAN
            const pb::ReceiptBodyV3 rw_ = body_on(n, L, hL + 1, 17, 5040, {}, [](pb::ReceiptBodyV3& r) { r.side.window_root[0] ^= 1; });
            check(is(admit(n, carrier_on(n, L, hc, {rw_}, 1, 5041)), AdmitVerdict::Ban, RowId::R27),
                  "row 27: a forged window_root -> BAN");
            // row 26: weights != W -> DEFER + local alarm, 0 tokens
            const pb::ReceiptBodyV3 rv = body_on(n, L, hL + 1, 18, 5050);
            n.windows = pb::WindowCache{};
            (void)n.windows.get(L, 16, [&] {
                pb::TipWindow w = pb::evaluate_window_at(n.store, L, n.prev_of(L), n.mon, 16, net.author_id);
                pb::Window bad = *w.window;
                bad.W += pb::Work(1);
                w.window = std::make_shared<const pb::Window>(bad);
                return w;
            });
            const std::size_t al = n.alarm.count();
            const pb::AdmitResult g = pb::admit_receipt(n.env(), bytes_of(rv), pb::Role::Pending);
            n.windows = pb::WindowCache{};
            check(deferred(g, Missing::NodeInternal) && g.alarm && g.strike == 0 && n.alarm.count() == al + 1,
                  "row 26: window weights != W -> local alarm + DEFER, 0 tokens");
        }
        // row 26: a window payee without a held reference -> DEFER, admitted after the fetch
        {
            KatNode m(n);
            const pb::CarrierBodyV3 hx = scaffold_body(m, L, hc, 0x5B, 9002, 20);
            check(place_direct(m, hx).outcome == pb::WriteOutcome::Extended, "row 26: a carrier of payee 20 on L");
            const pb::Hash32 H = pb::receipt_id(hx.own);
            const pb::ReceiptBodyV3 r = body_on(m, H, hc, 19, 5060);
            m.hidden_refs.insert(net.ids[20]);
            const pb::AdmitResult a = pb::admit_receipt(m.env(), bytes_of(r), pb::Role::Pending);
            m.hidden_refs.clear();
            const pb::AdmitResult b = pb::admit_receipt(m.env(), bytes_of(r), pb::Role::Pending);
            check(deferred(a, Missing::MissingRef) && a.strike == 0 && b.verdict == AdmitVerdict::AdmitPending,
                  "row 26: a window payee without a held reference -> DEFER, admitted after the fetch");
        }
        // row 20: freshness of a carried body; h(r) < b0 -> REFUSE at #6, never Expired
        {
            const pb::ReceiptBodyV3 r3 = body_on(n, L, hL + 3, 12, 5070);
            const pb::AdmitResult a = admit(n, carrier_on(n, L, hL + 1, {r3}, 1, 5071));
            check(is(a, AdmitVerdict::Refuse, RowId::R20) && a.strike == 0, "row 20: h(r) = h(tip) + 3 -> the frame REFUSE, 0 tokens");
            const pb::ReceiptBodyV3 r0 = body_on(n, n.tree.genesis().id, kLaneB0 - 1, 12, 5072);
            const pb::AdmitResult b = admit(n, carrier_on(n, L, hc, {r0}, 1, 5073));
            check(is(b, AdmitVerdict::Refuse, RowId::R20) && b.strike == 0, "row 20: h(r) < b0 -> REFUSE at #6 (never Expired)");
        }
        // row 22: dedup on c's chain; a sibling's placement does not count; pending DUPLICATE
        {
            KatNode m(n);
            const pb::ReceiptBodyV3 r = body_on(m, L, hL + 1, 21, 5080);
            const pb::CarrierBodyV3 c1 = carrier_on(m, L, hc, {r}, 1, 5081);
            const Admitted a1 = admit_place(m, c1);
            check(a1.placed, "row 22: r placed by c1 on L");
            const pb::Hash32 C1 = pb::receipt_id(c1.own);
            const pb::AdmitResult again = admit(m, carrier_on(m, C1, hc, {r}, 2, 5082));
            check(is(again, AdmitVerdict::Strike, RowId::R22), "row 22: r placed on c's chain in an open bin -> STRIKE");
            const pb::AdmitResult sib = admit(m, carrier_on(m, L, hc, {r}, 3, 5083));
            check(sib.verdict == AdmitVerdict::AdmitCarrier, "row 22: r placed only on a sibling (c1) -> admitted on L");
            const pb::AdmitResult dup = pb::admit_receipt(m.env(), bytes_of(r), pb::Role::Pending);
            check(is(dup, AdmitVerdict::Duplicate, RowId::R22) && dup.strike == 0, "row 22: a pending duplicate -> DUPLICATE");
            // c on a side branch S2 (forked at L): r is placed on the best chain only
            const pb::CarrierBodyV3 s2 = scaffold_body(m, L, hc, 0x5C, 9003, 2);
            check(held_side(place_direct(m, s2)), "row 22: a side carrier S2 on L");
            const pb::Hash32 S2 = pb::receipt_id(s2.own);
            const pb::AdmitResult side = admit(m, carrier_on(m, S2, hc, {r}, 4, 5084));
            check(side.verdict == AdmitVerdict::AdmitCarrier, "row 22: on a side branch, r placed on the best chain only -> admitted");
        }
        // row 23: a carried body failing major / vote / median / n_tx / D / cap -> STRIKE
        {
            const auto rejected = [&](const Tweak& t, std::uint64_t nonce) {
                const pb::ReceiptBodyV3 r = body_on(n, L, hL + 1, 22, nonce, t);
                return admit(n, carrier_on(n, L, hc, {r}, 1, nonce + 1));
            };
            check(is(rejected([](pb::ReceiptBodyV3& r) { r.blob.major = 17; }, 5090), AdmitVerdict::Strike, RowId::R23),
                  "row 23: major -> STRIKE");
            check(is(rejected([](pb::ReceiptBodyV3& r) { r.blob.minor = 0; }, 5092), AdmitVerdict::Strike, RowId::R23),
                  "row 23: vote -> STRIKE");
            check(is(rejected([&](pb::ReceiptBodyV3& r) { r.blob.timestamp = mon_ts(hL) - 120 * 200; }, 5094),
                     AdmitVerdict::Strike, RowId::R23),
                  "row 23: median -> STRIKE");
            check(is(rejected([](pb::ReceiptBodyV3& r) {
                         r.blob.tx_count = 413;
                         for (int i = 0; i < 8; ++i) r.branch.push_back(seq32(static_cast<std::uint8_t>(0x60 + i)));
                     }, 5096), AdmitVerdict::Strike, RowId::R23),
                  "row 23: n_tx 412 at Z 300,000 -> STRIKE");
            check(is(rejected([](pb::ReceiptBodyV3& r) { r.branch.push_back(seq32(0x70)); }, 5098), AdmitVerdict::Strike,
                     RowId::R23),
                  "row 23: D -> STRIKE");
            // the cap alone: Z 24,000,000 for n_tx, Z_lt 300,000 for RECEIPT_CAP
            const pb::ReceiptBodyV3 big = body_on(n, L, hL + 1, 22, 5100, [&](pb::ReceiptBodyV3& r) {
                r.blob.tx_count = 32768;
                for (int i = 0; i < 15; ++i) r.branch.push_back(seq32(static_cast<std::uint8_t>(0x80 + i)));
                r.side.fee_rate_bp = 100;
                r.owner = net.refs[23];
                r.side.owner = net.ids[23];
            });
            n.pr_z[big.blob.prev_id] = {24000000, 300000};
            const std::uint64_t len = bytes_of(big).size();
            const pb::AdmitResult a = admit(n, carrier_on(n, L, hc, {big}, 1, 5101));
            n.pr_z.clear();
            check(len > pb::receipt_cap(16, 300000).value() && len <= n.buffers.receipt && is(a, AdmitVerdict::Strike, RowId::R23),
                  "row 23: a body above RECEIPT_CAP at Z_lt 300,000 (n_tx and D pass) -> STRIKE (" + desc(a) + ")");
        }
        // row 24: a payee's first receipt carried by a foreign carrier -> admitted
        {
            const pb::ReceiptBodyV3 r = body_on(n, L, hL + 1, 20, 5110);
            check(admit(n, carrier_on(n, L, hc, {r}, 1, 5111)).verdict == AdmitVerdict::AdmitCarrier,
                  "row 24: a payee's first receipt, no earlier share anywhere, carried by another payee's carrier -> admitted");
        }
        // row 28: order; a known pending receipt omitted -> admitted and logged
        {
            std::vector<pb::ReceiptBodyV3> rs{body_on(n, L, hL + 1, 12, 5120), body_on(n, L, hL + 1, 13, 5121)};
            canonical_sort(net, rs, L);
            std::reverse(rs.begin(), rs.end());
            check(is(admit(n, carrier_on(n, L, hc, rs, 1, 5122, {}, {}, false)), AdmitVerdict::Strike, RowId::R28),
                  "row 28: the order swapped -> STRIKE");
            const pb::ReceiptBodyV3 known = body_on(n, L, hL + 1, 14, 5123);
            const pb::CarrierBodyV3 c = carrier_on(n, L, hc, {rs[0]}, 1, 5124);
            const pb::AdmitResult a = admit(n, c);
            const std::vector<pb::Hash32> carried{pb::receipt_id(rs[0])}, pending{pb::receipt_id(known)};
            check(a.verdict == AdmitVerdict::AdmitCarrier && pb::carried_omissions(carried, pending) == 1,
                  "row 28: a known pending receipt omitted -> admitted; the omission logged (1)");
        }
        // row 25: t_origin off by one -> STRIKE; an off-chain tip whose t_origin is its side branch's d -> admitted
        {
            KatNode m(n);
            check(is(admit(m, carrier_on(m, L, hc, {body_on(m, L, hL + 1, 12, 5130, [](pb::ReceiptBodyV3& r) { r.side.t_origin += 1; })}, 1, 5131)),
                     AdmitVerdict::Strike, RowId::R25),
                  "row 25: t_origin off by one -> STRIKE");
            // a side branch from position 20 with flat heights: its d rises above d_min
            const pb::Hash32 f = chain[19];
            const std::uint64_t hf = m.node(f).h;
            const std::vector<pb::Hash32> side = scaffold_chain(m, f, 120, 0x5D, [&](std::uint64_t) { return hf; }, 3);
            const pb::Hash32 t = side.back();
            const std::uint64_t d_side = m.tree.next_difficulty(t).value(), d_l = m.tree.next_difficulty(L).value();
            check(d_side != d_l, "row 25: the side tip's d (" + std::to_string(d_side) + ") differs from L's (" + std::to_string(d_l) + ")");
            const pb::ReceiptBodyV3 r = body_on(m, t, hf + 1, 12, 5132);
            const pb::AdmitResult a = admit(m, carrier_on(m, L, hc, {r}, 1, 5133));
            check(a.verdict == AdmitVerdict::AdmitCarrier, "row 25: an off-chain tip whose t_origin is its branch's d -> admitted (" + desc(a) + ")");
        }
        // row 13 / 30: c on the best tip placed at pos + 1; on a held non-best parent: a side branch
        {
            KatNode m(n);
            const pb::CarrierBodyV3 c = carrier_on(m, L, hc, {}, 1, 5140);
            const Admitted a = admit_place(m, c);
            const pb::Hash32 C = pb::receipt_id(c.own);
            const pb::LaneView v = m.store.view_at(C);
            check(a.placed && a.w.outcome == pb::WriteOutcome::Extended && m.node(C).pos == 61 && m.tree.best().id == C
                          && m.store.best_tip() == C && m.store.tip_pos() == 61 && v.ok() && v.pos() == 61
                          && v.record(61) == m.node(C).H && v.leaf_count() == pb::bin_leaf_count(m.node(C).H, kLaneB0, 96),
                  "row 13: on the best tip: placed at pos + 1; tree.best() = c, store.best_tip() = c, tip_pos = pos(c); H and leaf_count agree");
            const pb::CarrierBodyV3 s = carrier_on(m, chain[58], hL, {}, 2, 5141);
            const Admitted b = admit_place(m, s);
            check(b.placed && held_side(b.w) && m.node(pb::receipt_id(s.own)).pos == 60,
                  "row 13: on a held non-best parent -> a side branch");
            const pb::ReceiptBodyV3 r = body_on(m, chain[58], hL, 12, 5142);
            const pb::AdmitResult p = pb::admit_receipt(m.env(), bytes_of(r), pb::Role::Pending);
            check(is(p, AdmitVerdict::AdmitPending, RowId::R30), "row 30: a receipt whose tip is not the best tip -> PENDING");
        }
        // row 31: a dead carried receipt placed with weight 0; S excludes it
        {
            KatNode m(n);
            std::uint64_t tp = 59;
            while (tp % 12 != 11) --tp;
            const pb::Hash32 t = chain[tp - 1];
            const pb::ReceiptBodyV3 r = body_on(m, t, m.node(t).h, 12, 5150);
            const pb::CarrierBodyV3 c = carrier_on(m, L, hc, {r}, 1, 5151);
            const Admitted a = admit_place(m, c);
            const pb::Hash32 C = pb::receipt_id(c.own);
            const pb::LaneDelta* d = m.store.delta(C);
            const pb::RatchetPlacement pr[2] = {pb::RatchetPlacement{0, r.side.ballot},
                                                pb::RatchetPlacement{m.node(C).d, c.own.side.ballot}};
            const pb::RatchetState expect = pb::rs_step_at(m.RP, m.node(L).rs, 61, pr, m.T).s;
            check(a.placed && a.r.placements.size() == 1 && !a.r.placements[0].live && d != nullptr && !d->placed[0].live
                          && d->placed[0].p_own == tp + 1 && m.node(C).rs == expect,
                  "row 31: a dead carried receipt: placed with weight 0, S excludes it, p(r) = pos(t) + 1");
        }
    });

    // rows 21, 27 and the tip predating the last seal: one height per position
    run_part("rows 21, 27 (sealed bins)", [] {
        KatNet net;
        KatNode n(net, kJ0);
        const std::vector<pb::Hash32> chain = pipeline_chain(n, 110, 1, h_fast);
        const pb::Hash32 P = chain.back();  // position 110, h = b0 + 110
        const std::uint64_t hP = n.node(P).h;
        check(n.store.head().leaf_count > 0, "rows 21, 27: bins sealed on the chain");
        // row 27: a carried receipt whose tip predates the last seal -> admitted
        {
            const pb::Hash32 t = chain[106];  // position 107
            const pb::ReceiptBodyV3 r = body_on(n, t, n.node(t).h + 2, 12, 6000);
            check(n.store.view_at(t).mmr_root() != n.store.view_at(P).mmr_root(), "row 27: bins sealed between t and parent(c)");
            const pb::AdmitResult a = admit(n, carrier_on(n, P, hP, {r}, 1, 6001));
            check(a.verdict == AdmitVerdict::AdmitCarrier, "row 27: a carried receipt whose tip predates the last seal -> admitted (" + desc(a) + ")");
        }
        // row 21: a sealed bin -> STRIKE; a pending body in a sealed bin -> REFUSE
        {
            const pb::Hash32 t = chain[110 - 98 - 1];  // h(t) = h(P) - 98
            const pb::ReceiptBodyV3 r = body_on(n, t, n.node(t).h + 2, 12, 6010);
            check(is(admit(n, carrier_on(n, P, hP, {r}, 1, 6011)), AdmitVerdict::Strike, RowId::R21),
                  "row 21: a carried body in a sealed bin -> STRIKE");
            const pb::AdmitResult p = pb::admit_receipt(n.env(), bytes_of(r), pb::Role::Pending);
            check(is(p, AdmitVerdict::Refuse, RowId::R21) && p.strike == 0, "row 21: a pending body in a sealed bin -> REFUSE");
        }
        // row 21: h(r) <= h(c) + Fresh (P-11), with a tip on a sibling branch ahead
        {
            KatNode m(n);
            const pb::CarrierBodyV3 ahead = scaffold_body(m, chain[108], hP + 1, 0x5E, 9010, 5);
            check(held_side(place_direct(m, ahead)), "row 21: a sibling tip t at h(P) + 1");
            const pb::Hash32 t = pb::receipt_id(ahead.own);
            const pb::ReceiptBodyV3 over = body_on(m, t, hP + 3, 12, 6020), at = body_on(m, t, hP + 2, 13, 6021);
            check(is(admit(m, carrier_on(m, P, hP, {over}, 1, 6022)), AdmitVerdict::Strike, RowId::R21),
                  "row 21: h(r) = h(c) + Fresh + 1 -> STRIKE");
            check(admit(m, carrier_on(m, P, hP, {at}, 1, 6023)).verdict == AdmitVerdict::AdmitCarrier,
                  "row 21: h(r) = h(c) + Fresh -> admitted");
        }
        // row 21 on a side carrier: the origin bin open on c's chain at its parent (sealed at the best tip)
        {
            KatNode m(n);
            const pb::Hash32 f = chain[104];  // position 105
            const std::vector<pb::Hash32> side = scaffold_chain(m, f, 3, 0x5F, [&](std::uint64_t) { return m.node(f).h; }, 6);
            const pb::Hash32 S = side.back();  // position 108, H(S) = h(105)
            const std::uint64_t HS = m.node(S).H;
            std::uint64_t tp = 1;
            while (h_fast(tp) + 2 < HS - 95) ++tp;
            const pb::Hash32 t = chain[tp - 1];
            const pb::ReceiptBodyV3 r = body_on(m, t, HS - 95, 12, 6030);
            check(!pb::open_at(m.node(P).H, HS - 95, 96) && pb::open_at(HS, HS - 95, 96),
                  "row 21: r's bin is open at S and sealed at the best tip");
            const pb::AdmitResult a = admit(m, carrier_on(m, S, HS, {r}, 1, 6031));
            check(a.verdict == AdmitVerdict::AdmitCarrier, "row 21: on a side carrier, open on its own chain -> admitted (" + desc(a) + ")");
        }
    });
}

// ---------------------------------------------------------------------------
// Section 4: the deep-tip boundary (ruling 40), the closure (ruling 41), F-1's
// view horizon and the row-4 gate on two nodes: N_floor (J = J_0) and N_raised
// (J = 3 x J_0, a KAT parameter), one scaffold chain.
// ---------------------------------------------------------------------------
constexpr std::uint64_t kL = 3611;  // the best tip (L = 11 mod 12)

struct Pair {
    std::unique_ptr<KatNode> nf, nr;
    std::vector<pb::Hash32> chain;  // chain[k - 1] = position k
    pb::Hash32 at(std::uint64_t k) const { return k == 0 ? nf->tree.genesis().id : chain[k - 1]; }
};

Pair make_pair_chain(const KatNet& net, std::uint64_t L) {
    Pair p;
    p.nf = std::make_unique<KatNode>(net, kJ0);
    p.nr = std::make_unique<KatNode>(net, 3 * kJ0);
    p.chain = scaffold_chain(*p.nf, p.nf->tree.genesis().id, L, 0x10, h_pos, 0);
    const std::vector<pb::Hash32> r = scaffold_chain(*p.nr, p.nr->tree.genesis().id, L, 0x10, h_pos, 0);
    check(r == p.chain, "section 4: both nodes hold one chain of " + std::to_string(L) + " carriers");
    return p;
}

// A header variant (and the body set of a carrier that carries) from `peer`'s reply.
void feed(KatNode& n, std::uint64_t peer, const pb::CarrierBodyV3& c, const pb::CarrierHeader* header = nullptr) {
    const pb::CarrierHeader h = header ? *header : pb::header_of(c);
    n.headers.add(peer, h, h_of(*n.net, h.own), true);
    if (!c.carried.empty())
        n.headers.add_body_set(peer, pb::receipt_id(c.own), c.carried, pb::header_digest(h));
}
void feed_set(KatNode& n, std::uint64_t peer, const pb::CarrierBodyV3& c) {
    n.headers.add_body_set(peer, pb::receipt_id(c.own), c.carried, std::nullopt);
}

struct Settled {
    pb::AdmitResult r;
    std::set<std::uint64_t> banned, struck;
    std::vector<std::pair<std::uint64_t, std::uint32_t>> tokens;
    int rounds = 0;
};

// Admits c; while it DEFERs TipBodies, binds and places the walked branches
// (a BANned server's variants released). Body sets a computed fold refutes
// are dropped and their servers struck once.
Settled settle(KatNode& n, const pb::CarrierBodyV3& c, int max_rounds = 12) {
    Settled out;
    for (int i = 0; i < max_rounds; ++i) {
        ++out.rounds;
        out.r = admit(n, c);
        for (const auto& [peer, id] : out.r.refuted_sets) {
            n.headers.drop_body_set(peer, id);
            out.struck.insert(peer);
        }
        out.tokens.insert(out.tokens.end(), out.r.peer_tokens.begin(), out.r.peer_tokens.end());
        if (!deferred(out.r, Missing::TipBodies)) return out;
        std::vector<pb::Hash32> ids = out.r.bind;  // fork upward first
        for (const pb::Hash32& w : out.r.walked)
            if (std::find(ids.begin(), ids.end(), w) == ids.end()) ids.push_back(w);
        const pb::BindReport rep = pb::bind_walked(n.env(), pb::NodeRefs{n.tree, n.store, n.ar, n.headers, n.bodies}, ids);
        for (std::uint64_t b : rep.banned) {
            out.banned.insert(b);
            n.headers.release_peer(b);
        }
        for (std::uint64_t s : rep.struck) out.struck.insert(s);
        if (rep.placed.empty() && rep.banned.empty() && rep.struck.empty()) break;
    }
    out.r = admit(n, c);
    return out;
}

bool same_judgement(KatNode& a, KatNode& b, const pb::CarrierBodyV3& c, const std::string& name) {
    const Settled sa = settle(a, c), sb = settle(b, c);
    bool ok = sa.r.verdict == AdmitVerdict::AdmitCarrier && sb.r.verdict == AdmitVerdict::AdmitCarrier;
    if (!ok) {
        std::printf("  %s: N_floor %s, N_raised %s\n", name.c_str(), desc(sa.r).c_str(), desc(sb.r).c_str());
        return false;
    }
    const pb::WriteResult wa = pb::place_admitted(a.tree, a.store, a.ar, a.bodies, sa.r, &a.alarm);
    const pb::WriteResult wb = pb::place_admitted(b.tree, b.store, b.ar, b.bodies, sb.r, &b.alarm);
    const pb::Hash32 id = pb::receipt_id(c.own);
    ok = wa.outcome != pb::WriteOutcome::NodeInternal && wb.outcome != pb::WriteOutcome::NodeInternal;
    ok = ok && sa.r.placements.size() == sb.r.placements.size();
    for (std::size_t i = 0; ok && i < sa.r.placements.size(); ++i)
        ok = sa.r.placements[i].id == sb.r.placements[i].id && sa.r.placements[i].live == sb.r.placements[i].live
             && sa.r.placements[i].work == sb.r.placements[i].work;
    ok = ok && a.node(id).rs == b.node(id).rs && lane_digest(a, id) == lane_digest(b, id) && !lane_digest(a, id).empty();
    if (!ok) std::printf("  %s: placements, S or the lane digest differ\n", name.c_str());
    return ok;
}

// A header variant of a carrier: the same blob (so the same id), side_data changed by f.
pb::CarrierHeader variant_of(const pb::CarrierBodyV3& c, const Tweak& f) {
    pb::CarrierHeader h = pb::header_of(c);
    if (f) f(h.own);
    return h;
}

// A cum_work_claim for h such that its digest sorts before `other` (the walk order of held variants).
pb::CarrierHeader sorted_before(pb::CarrierHeader h, const pb::Hash32& other) {
    for (std::uint64_t k = 1; k < 4096; ++k) {
        h.cum_work_claim.lo = k;
        if (*pb::header_digest(h) < other) return h;
    }
    check(false, "sorted_before: no claim found");
    return h;
}

// The closure-edge structure on a copy of the pair: c on L carries r with tip c_t1 at f1 + 1 (f1 = L - 576);
// c_t1 carries r1 with tip t2 at f2 + 1 (f2 = L - J_0). Built valid in a scratch copy of N_raised.
struct Edge {
    pb::CarrierBodyV3 t2, c1, c;
    pb::ReceiptBodyV3 r1;
    pb::Hash32 t2id{}, c1id{};
};

Edge make_edge(const Pair& q, std::uint64_t nonce) {
    Edge e;
    KatNode sc(*q.nr);
    const pb::Hash32 L = q.at(kL);
    const std::uint64_t f1 = kL - kJ0 / 2, f2 = kL - kJ0;
    const auto fresh_h = [](std::uint64_t h_tip, std::uint64_t H_parent) { return std::max(h_tip, H_parent - 95); };
    e.t2 = carrier_on(sc, q.at(f2), h_pos(f2 + 1), {}, 5, nonce);
    check(admit_place(sc, e.t2, CarrierRole::Closure).placed, "edge: t2 valid");
    e.t2id = pb::receipt_id(e.t2.own);
    e.r1 = body_on(sc, e.t2id, fresh_h(sc.node(e.t2id).h, sc.node(q.at(f1)).H), 13, nonce + 1);
    e.c1 = carrier_on(sc, q.at(f1), h_pos(f1 + 1), {e.r1}, 6, nonce + 2);
    check(admit_place(sc, e.c1, CarrierRole::Closure).placed, "edge: c_t valid");
    e.c1id = pb::receipt_id(e.c1.own);
    const pb::ReceiptBodyV3 r = body_on(sc, e.c1id, fresh_h(sc.node(e.c1id).h, sc.node(L).H), 12, nonce + 3);
    e.c = carrier_on(sc, L, h_pos(kL + 1), {r}, 1, nonce + 4);
    return e;
}

void section4() {
    run_part("section 4", [] {
        KatNet net;
        const Pair base = make_pair_chain(net, kL);
        const pb::Hash32 L = base.at(kL);
        const std::uint64_t HL = base.nf->node(L).H;
        check(base.nf->store.base_pos() == kL - kJ0 && base.nr->store.base_pos() == kL - 3 * kJ0,
              "section 4: N_floor base L - J_0, N_raised base L - 3 J_0");
        const auto fresh_h = [&](std::uint64_t h_tip, std::uint64_t H_parent) {
            return std::max(h_tip, H_parent > 95 ? H_parent - 95 : 0);
        };
        const auto copy = [&](const Pair& p) {
            Pair q;
            q.nf = std::make_unique<KatNode>(*p.nf);
            q.nr = std::make_unique<KatNode>(*p.nr);
            q.chain = p.chain;
            return q;
        };

        // J_0 - 1 and J_0: both judge; J_0 + 1: both DEFER (Boundary), no view of t's branch
        for (std::uint64_t dist : {kJ0 - 1, kJ0, kJ0 + 1}) {
            Pair q = copy(base);
            const std::uint64_t f = kL - dist;
            const pb::CarrierBodyV3 tb = scaffold_body(*q.nf, q.at(f), h_pos(f + 1), 0x21, f + 1, 5);
            const bool placed = held_side(place_direct(*q.nf, tb)) && held_side(place_direct(*q.nr, tb));
            const pb::Hash32 t = pb::receipt_id(tb.own);
            const pb::ReceiptBodyV3 r = body_on(*q.nf, t, fresh_h(q.nf->node(t).h, HL), 12, 7000 + dist);
            const pb::CarrierBodyV3 c = carrier_on(*q.nf, L, h_pos(kL + 1), {r}, 1, 7100 + dist);
            const std::string name = "section 4: pos(parent(c)) - f = " + std::to_string(dist);
            if (dist <= kJ0) {
                check(placed && same_judgement(*q.nf, *q.nr, c, name), name + ": both judge, one placement, S and lane digest");
            } else {
                q.nf->view_log.clear();
                q.nr->view_log.clear();
                const pb::AdmitResult a = admit(*q.nf, c), b = admit(*q.nr, c);
                check(placed && deferred(a, Missing::Boundary) && deferred(b, Missing::Boundary) && a.row == RowId::R17
                              && a.strike == 0 && b.strike == 0 && !a.claim_based,
                      name + ": both DEFER (boundary), no token, a bound decision");
                check(q.nf->views_of(t) == 0 && q.nr->views_of(t) == 0, name + ": neither calls view_at(t) (the spy counts 0)");
            }
        }

        // the late-sibling vector (F-1): c's parent one below the best tip, f = pos(parent(c)) - J_0;
        // t's branch arrives as headers and is placed as closure material
        {
            Pair q = copy(base);
            const std::uint64_t pc = kL - 1, f = pc - kJ0;
            const pb::CarrierBodyV3 tb = carrier_on(*q.nf, q.at(f), h_pos(f + 1), {}, 5, 7200);
            const pb::Hash32 t = pb::receipt_id(tb.own);
            feed(*q.nf, 1, tb);
            feed(*q.nr, 1, tb);
            KatNode sc(*q.nr);
            check(admit_place(sc, tb, CarrierRole::Closure).placed, "late sibling: t valid (scratch)");
            const pb::ReceiptBodyV3 r = body_on(sc, t, fresh_h(h_pos(f + 1), q.nf->node(q.at(pc)).H), 12, 7201);
            const pb::CarrierBodyV3 c = carrier_on(sc, q.at(pc), q.nf->node(q.at(pc)).H, {r}, 1, 7202);
            check(f < q.nf->store.base_pos(), "late sibling: t's fork lies below N_floor's base_pos");
            check(same_judgement(*q.nf, *q.nr, c, "late sibling"),
                  "late sibling: N_floor places t's branch as closure material and judges c as N_raised does");
        }

        // an on-chain tip 1,170 positions back (inside the 1,176-position open-bin span)
        {
            Pair q = copy(base);
            const pb::Hash32 t = q.at(kL - 1170);
            const pb::ReceiptBodyV3 r = body_on(*q.nf, t, q.nf->node(t).h + 2, 12, 7300);
            check(pb::open_at(HL, q.nf->node(t).h + 2, 96), "on-chain tip: r's bin open at L");
            check(same_judgement(*q.nf, *q.nr, carrier_on(*q.nf, L, h_pos(kL + 1), {r}, 1, 7301), "on-chain tip 1,170 back"),
                  "on-chain tip 1,170 positions back: both judge");
        }

        // c on a held side branch forked at g; t forking from c's side part at f_c > g:
        // pos(parent(c)) - f_c <= J_0 < pos(parent(c)) - g: both judge (the boundary is counted on c's chain)
        {
            Pair q = copy(base);
            const std::uint64_t g = kL - kJ0;
            const std::vector<pb::Hash32> s1 = scaffold_chain(*q.nf, q.at(g), kJ0 + 1, 0x22, h_pos, 6);
            const std::vector<pb::Hash32> s1r = scaffold_chain(*q.nr, q.at(g), kJ0 + 1, 0x22, h_pos, 6);
            const pb::Hash32 pc = s1.back();
            const std::uint64_t ppc = q.nf->node(pc).pos, fc = ppc - 1000;
            const pb::Hash32 fcid = s1[fc - g - 1];
            const pb::CarrierBodyV3 tb = scaffold_body(*q.nf, fcid, h_pos(fc + 1), 0x23, fc + 1, 7);
            const bool ok = s1 == s1r && held_side(place_direct(*q.nf, tb)) && held_side(place_direct(*q.nr, tb));
            const pb::Hash32 t = pb::receipt_id(tb.own);
            const pb::ReceiptBodyV3 r = body_on(*q.nf, t, fresh_h(q.nf->node(t).h, q.nf->node(pc).H), 12, 7400);
            check(ok && ppc - fc <= kJ0 && ppc - g > kJ0, "side branch: pos(parent(c)) - f_c <= J_0 < pos(parent(c)) - g");
            check(same_judgement(*q.nf, *q.nr, carrier_on(*q.nf, pc, q.nf->node(pc).H, {r}, 1, 7401), "side branch"),
                  "side branch: both judge (the boundary is counted on c's chain)");
        }

        // own chain below base_pos (the row-4 gate): N_floor DEFERs OwnChainDeep before any view or fetch;
        // N_raised judges c and places it on a side branch
        {
            Pair q = copy(base);
            const std::uint64_t pp = kL - kJ0 - 1;
            const pb::CarrierBodyV3 c = carrier_on(*q.nr, q.at(pp), h_pos(pp + 1), {}, 1, 7500);
            q.nf->view_log.clear();
            const std::uint64_t pr0 = q.nf->pr_calls;
            const pb::AdmitResult a = admit(*q.nf, c);
            check(deferred(a, Missing::OwnChainDeep) && a.row == RowId::R4 && a.strike == 0 && q.nf->view_log.empty()
                          && q.nf->pr_calls == pr0 && a.fetch == pb::Hash32{},
                  "gate: N_floor, parent J_0 + 1 below its tip: DEFER OwnChainDeep, 0 tokens, 0 view_at calls, no fetch");
            const Admitted b = admit_place(*q.nr, c);
            check(b.placed && held_side(b.w), "gate: N_raised judges c and places it on a side branch");
            // RR-FIX-5 (d): a copy with its parent replaced by the best-chain carrier J_0 + 1 below the tip, sent first
            const pb::CarrierBodyV3 honest = carrier_on(*q.nf, L, h_pos(kL + 1), {}, 2, 7501);
            pb::CarrierBodyV3 forged = honest;
            forged.own.side.tip = q.at(pp);
            pb::DeferredCarriers st(pb::waiting_cap_default());
            const std::vector<std::uint8_t> ff = frame_of(forged);
            const pb::AdmitResult fa = pb::admit_carrier(q.nf->env(), ff, CarrierRole::Frame);
            pb::ParkedFrame pf;
            pf.digest = ::v37::sha256d(ff);
            pf.id = pb::receipt_id(forged.own);
            pf.parent = forged.own.side.tip;
            pf.peer = 9;
            pf.frame = ff;
            pf.cause = fa.missing.value_or(Missing::NodeInternal);
            const bool parked = st.park(q.nf->tree, pf);
            const Admitted ha = admit_place(*q.nf, honest);
            check(deferred(fa, Missing::OwnChainDeep) && parked && ha.placed && st.waiting_keys() == 0,
                  "gate: a no-PoW copy naming an old best-chain parent DEFERs only itself; the honest copy is placed");
        }
        // RR-FIX-2: a frame naming position 1 as parent: DEFER after one tree lookup (no walk)
        {
            Pair q = copy(base);
            const pb::CarrierBodyV3 c = carrier_on(*q.nr, q.at(1), h_pos(2), {}, 1, 7510);
            const std::uint64_t steps = q.nf->tree.walk_steps();
            const pb::AdmitResult a = admit(*q.nf, c);
            check(deferred(a, Missing::OwnChainDeep) && q.nf->tree.walk_steps() == steps,
                  "gate: a parent at position 1: DEFER OwnChainDeep, the step counter at 0");
        }
        // RR-FIX-1: tree.best() on a closure-material branch whose switch_best answered Deep; a frame on it
        {
            Pair q = copy(base);
            KatNode& n = *q.nf;
            const std::uint64_t fb = n.store.base_pos() - 60;  // in [base_pos - J_0, base_pos)
            const std::vector<pb::Hash32> br = scaffold_chain(n, q.at(fb), kL - fb + 2, 0x24, h_pos, 8);
            const pb::Hash32 bt = br.back();
            pb::LaneBatch batch;
            check(n.tree.best().id == bt && n.store.best_tip() == L && n.store.switch_best(bt, &batch) == pb::SwitchVerdict::Deep,
                  "gate: tree.best() moved to a branch forked below base_pos; its switch_best answered Deep");
            const pb::CarrierBodyV3 c = carrier_on(*q.nr, q.at(kL), h_pos(kL + 1), {}, 1, 7520);  // a template
            pb::CarrierBodyV3 cb = carrier_on(n, bt, n.node(bt).H, {}, 1, 7521);
            (void)c;
            n.view_log.clear();
            const pb::AdmitResult a = admit(n, cb);
            check(deferred(a, Missing::OwnChainDeep) && n.view_log.empty(),
                  "gate: a frame on that branch: DEFER OwnChainDeep, 0 view_at calls (measured on store.best_tip())");
        }

        // the closure: the 2-level late sibling. parent(c) = L - 1; t = c_t at f1 + 1, f1 = L - 1,153;
        // c_t carries r' with tip t' at f2 + 1, f2 = f1 - 1,152
        {
            Pair q = copy(base);
            KatNode sc(*q.nr);
            const std::uint64_t pc = kL - 1, f1 = kL - 1153, f2 = f1 - 1152;
            const pb::CarrierBodyV3 tp = carrier_on(sc, q.at(f2), h_pos(f2 + 1), {}, 5, 7600);
            check(admit_place(sc, tp, CarrierRole::Closure).placed, "closure 2-level: t' valid (scratch)");
            const pb::Hash32 tpid = pb::receipt_id(tp.own);
            const pb::ReceiptBodyV3 r1 = body_on(sc, tpid, fresh_h(sc.node(tpid).h, sc.node(q.at(f1)).H), 13, 7601);
            const pb::CarrierBodyV3 ct = carrier_on(sc, q.at(f1), h_pos(f1 + 1), {r1}, 6, 7602);
            const Admitted act = admit_place(sc, ct, CarrierRole::Closure);
            check(act.placed, "closure 2-level: c_t valid (scratch): " + desc(act.r));
            const pb::Hash32 ctid = pb::receipt_id(ct.own);
            const pb::ReceiptBodyV3 r = body_on(sc, ctid, fresh_h(sc.node(ctid).h, sc.node(q.at(pc)).H), 12, 7603);
            const pb::CarrierBodyV3 c = carrier_on(sc, q.at(pc), sc.node(q.at(pc)).H, {r}, 1, 7604);
            for (KatNode* n : {q.nf.get(), q.nr.get()}) {
                n->headers.add(1, pb::header_of(tp), h_of(net, tp.own));
                n->headers.add(1, pb::header_of(ct), h_of(net, ct.own));
            }
            q.nf->view_log.clear();
            q.nr->view_log.clear();
            const pb::AdmitResult a0 = admit(*q.nf, c), b0 = admit(*q.nr, c);
            check(deferred(a0, Missing::ClosureBodies) && deferred(b0, Missing::ClosureBodies) && a0.fetch == ctid,
                  "closure 2-level: c_t's carried bodies not held: both DEFER ClosureBodies (FC_GETCARRIER c_t)");
            feed_set(*q.nf, 1, ct);
            feed_set(*q.nr, 1, ct);
            const pb::AdmitResult a = admit(*q.nf, c), b = admit(*q.nr, c);
            check(deferred(a, Missing::Closure) && deferred(b, Missing::Closure) && a.strike == 0 && b.strike == 0,
                  "closure 2-level: both DEFER r by the closure (pos(parent(c)) - f2 > J_0), no token");
            check(q.nf->views_of(ctid) == 0 && q.nf->views_of(tpid) == 0 && q.nr->views_of(ctid) == 0 && q.nr->views_of(tpid) == 0,
                  "closure 2-level: neither node calls view_at of a branch of the closure");
            const Settled sa = settle(*q.nf, c), sb = settle(*q.nr, c);
            check(deferred(sa.r, Missing::Closure) && deferred(sb.r, Missing::Closure) && q.nf->tree.find(ctid) == nullptr
                          && q.nr->tree.find(ctid) == nullptr,
                  "closure 2-level: nothing of the closure is placed; the verdict stays DEFER on both");
        }
        // the 3-level nest on the best tip: f1 = L - 1,152, f2 = L - 2,304, f3 = L - 3,456
        {
            Pair q = copy(base);
            KatNode sc(*q.nr);
            const std::uint64_t f1 = kL - kJ0, f2 = kL - 2 * kJ0, f3 = kL - 3 * kJ0;
            const pb::CarrierBodyV3 t3 = carrier_on(sc, q.at(f3), h_pos(f3 + 1), {}, 5, 7700);
            check(admit_place(sc, t3, CarrierRole::Closure).placed, "closure 3-level: t3 valid (scratch)");
            const pb::Hash32 t3id = pb::receipt_id(t3.own);
            const pb::ReceiptBodyV3 r2 = body_on(sc, t3id, fresh_h(sc.node(t3id).h, sc.node(q.at(f2)).H), 13, 7701);
            const pb::CarrierBodyV3 c2 = carrier_on(sc, q.at(f2), h_pos(f2 + 1), {r2}, 6, 7702);
            check(admit_place(sc, c2, CarrierRole::Closure).placed, "closure 3-level: c_t2 valid (scratch)");
            const pb::Hash32 c2id = pb::receipt_id(c2.own);
            const pb::ReceiptBodyV3 r1 = body_on(sc, c2id, fresh_h(sc.node(c2id).h, sc.node(q.at(f1)).H), 14, 7703);
            const pb::CarrierBodyV3 c1 = carrier_on(sc, q.at(f1), h_pos(f1 + 1), {r1}, 7, 7704);
            // c_t1's own closure reads t3's branch (2 J_0 below its parent): it is chain data only (placed directly)
            check(deferred(admit(sc, c1, CarrierRole::Closure), Missing::Closure) && held_side(place_direct(sc, c1)),
                  "closure 3-level: c_t1 (its own closure DEFERs; held in the scratch as data)");
            const pb::Hash32 c1id = pb::receipt_id(c1.own);
            const pb::ReceiptBodyV3 r = body_on(sc, c1id, fresh_h(sc.node(c1id).h, HL), 12, 7705);
            const pb::CarrierBodyV3 c = carrier_on(sc, L, h_pos(kL + 1), {r}, 1, 7706);
            for (KatNode* n : {q.nf.get(), q.nr.get()}) {
                feed(*n, 1, t3);
                feed(*n, 1, c2);
                feed(*n, 1, c1);
                n->view_log.clear();
            }
            const Settled sa = settle(*q.nf, c), sb = settle(*q.nr, c);
            check(deferred(sa.r, Missing::Closure) && deferred(sb.r, Missing::Closure) && sa.r.strike == 0,
                  "closure 3-level: both DEFER r by the closure");
            check(q.nf->views_of(c1id) + q.nf->views_of(c2id) + q.nf->views_of(t3id) == 0
                          && q.nr->views_of(c1id) + q.nr->views_of(c2id) + q.nr->views_of(t3id) == 0,
                  "closure 3-level: no view_at of a branch of the closure");
        }
        // the closure edge (judge): c on the best tip, f1 = L - 576, f2 = L - J_0
        {
            Pair q = copy(base);
            KatNode sc(*q.nr);
            const std::uint64_t f1 = kL - kJ0 / 2, f2 = kL - kJ0;
            const pb::CarrierBodyV3 t2 = carrier_on(sc, q.at(f2), h_pos(f2 + 1), {}, 5, 7800);
            check(admit_place(sc, t2, CarrierRole::Closure).placed, "closure edge: t2 valid (scratch)");
            const pb::Hash32 t2id = pb::receipt_id(t2.own);
            const pb::ReceiptBodyV3 r1 = body_on(sc, t2id, fresh_h(sc.node(t2id).h, sc.node(q.at(f1)).H), 13, 7801);
            const pb::CarrierBodyV3 c1 = carrier_on(sc, q.at(f1), h_pos(f1 + 1), {r1}, 6, 7802);
            check(admit_place(sc, c1, CarrierRole::Closure).placed, "closure edge: c_t valid (scratch)");
            const pb::Hash32 c1id = pb::receipt_id(c1.own);
            const pb::ReceiptBodyV3 r = body_on(sc, c1id, fresh_h(sc.node(c1id).h, HL), 12, 7803);
            const pb::CarrierBodyV3 c = carrier_on(sc, L, h_pos(kL + 1), {r}, 1, 7804);
            for (KatNode* n : {q.nf.get(), q.nr.get()}) {
                feed(*n, 1, t2);
                feed(*n, 1, c1);
            }
            check(same_judgement(*q.nf, *q.nr, c, "closure edge"),
                  "closure edge (pos(parent(c)) - f2 = J_0): both judge, one placement, S and lane digest");
            check(q.nf->tree.find(t2id) != nullptr && q.nf->store.view_at(t2id).ok(),
                  "closure edge: N_floor holds the nested branch inside its view horizon");
        }

        // forged variants first, the honest ones later from a second peer: the claim-based DEFER is walked
        // again and both nodes judge c as a node fed only honest data; the forged variants are refuted
        {
            Pair q = copy(base);
            const Edge e = make_edge(q, 7900);
            const pb::CarrierHeader deep_parent = variant_of(e.c1, [&](pb::ReceiptBodyV3& r) { r.side.tip = q.at(kL - 2 * kJ0); });
            const pb::ReceiptBodyV3 fb = body_on(*q.nr, q.at(kL - 2400), h_pos(kL - 2399), 14, 7910);
            const pb::CarrierHeader deep_list = variant_of(e.c1, [&](pb::ReceiptBodyV3& r) {
                r.side.receipts_root = q.nr->tree.next_receipts_root(q.at(kL - kJ0 / 2), std::vector<pb::Hash32>{pb::receipt_id(fb)}).value();
            });
            Pair h = copy(base);  // fed only honest data
            for (KatNode* n : {h.nf.get(), h.nr.get()}) {
                feed(*n, 1, e.t2);
                feed(*n, 1, e.c1);
            }
            for (int k = 0; k < 2; ++k) {
                KatNode& n = k == 0 ? *q.nf : *q.nr;
                KatNode& hn = k == 0 ? *h.nf : *h.nr;
                const std::string who = k == 0 ? "N_floor" : "N_raised";
                n.headers.add(2, deep_parent, h_of(net, deep_parent.own));
                n.headers.add(3, deep_list, h_of(net, deep_list.own));
                n.headers.add_body_set(3, e.c1id, {fb}, pb::header_digest(deep_list));
                pb::DeferredCarriers st(pb::waiting_cap_default());
                const std::vector<std::uint8_t> f = frame_of(e.c);
                const pb::AdmitResult a = pb::admit_carrier(n.env(), f, CarrierRole::Frame);
                pb::ParkedFrame pf;
                pf.digest = ::v37::sha256d(f);
                pf.id = pb::receipt_id(e.c.own);
                pf.parent = e.c.own.side.tip;
                pf.peer = 7;
                pf.frame = f;
                pf.cause = a.missing.value_or(Missing::NodeInternal);
                pf.claim_based = a.claim_based;
                pf.walked = a.walked;
                const bool parked = st.park(n.tree, pf);
                check(parked && a.verdict == AdmitVerdict::Defer && a.claim_based && a.strike == 0,
                      "forged variants (" + who + "): fed first, c DEFERs claim-based, no token (" + desc(a) + ")");
                feed(n, 1, e.t2);
                feed(n, 1, e.c1);
                st.touch({e.c1id, e.t2id});
                bool judged = false;
                Settled sr;
                for (const pb::Hash32& d : st.take_rewalks()) {
                    const std::optional<pb::ParkedFrame> again = st.take(n.tree, d);
                    if (!again) continue;
                    sr = settle(n, e.c);
                    judged = sr.r.verdict == AdmitVerdict::AdmitCarrier;
                }
                const Settled sh = settle(hn, e.c);
                bool same = judged && sh.r.verdict == AdmitVerdict::AdmitCarrier;
                if (same) {
                    pb::place_admitted(n.tree, n.store, n.ar, n.bodies, sr.r, &n.alarm);
                    pb::place_admitted(hn.tree, hn.store, hn.ar, hn.bodies, sh.r, &hn.alarm);
                    const pb::Hash32 id = pb::receipt_id(e.c.own);
                    same = n.node(id).rs == hn.node(id).rs && lane_digest(n, id) == lane_digest(hn, id);
                }
                check(same, "forged variants (" + who + "): re-walked on the honest data, c judged as a node fed only "
                            "honest data (same placement, S and lane digest)");
                check(sr.banned.count(1) == 0 && sr.struck.count(1) == 0 && n.headers.variants(e.c1id).size() == 1,
                      "forged variants (" + who + "): the honest server is never struck; one variant of c_t left (bound)");
            }
        }
        // variant order (BA-1): B's variant of c_t (receipts_root over a list with a deep tip) walked first,
        // A's honest variant second; both held before the walk; A is never struck
        {
            Pair q = copy(base);
            const Edge e = make_edge(q, 8000);
            const pb::ReceiptBodyV3 fb = body_on(*q.nr, q.at(kL - 2400), h_pos(kL - 2399), 14, 8010);
            const pb::Hash32 honest_dg = *pb::header_digest(pb::header_of(e.c1));
            const pb::CarrierHeader bv = sorted_before(variant_of(e.c1, [&](pb::ReceiptBodyV3& r) {
                r.side.receipts_root = q.nr->tree.next_receipts_root(q.at(kL - kJ0 / 2), std::vector<pb::Hash32>{pb::receipt_id(fb)}).value();
            }), honest_dg);
            for (int k = 0; k < 2; ++k) {
                KatNode& n = k == 0 ? *q.nf : *q.nr;
                n.headers.add(2, bv, h_of(net, bv.own));
                n.headers.add_body_set(2, e.c1id, {fb}, pb::header_digest(bv));
                feed(n, 1, e.t2);
                feed(n, 1, e.c1);
            }
            check(q.nf->headers.variants(e.c1id).size() == 2 && q.nf->headers.variants(e.c1id)[0]->peers.count(2) == 1,
                  "variant order: B's variant is walked first");
            check(same_judgement(*q.nf, *q.nr, e.c, "variant order"), "variant order: both nodes place c (same placement, S, lane digest)");
            const Settled again = settle(*q.nf, e.c);
            check(again.struck.count(1) == 0 && again.banned.count(1) == 0, "variant order: A is never struck");
        }
        // the honest variant first, a second peer's forged variant later: the honest one stays held
        {
            Pair q = copy(base);
            const Edge e = make_edge(q, 8050);
            const pb::ReceiptBodyV3 fb = body_on(*q.nr, q.at(kL - 2400), h_pos(kL - 2399), 14, 8060);
            const pb::CarrierHeader bv = variant_of(e.c1, [&](pb::ReceiptBodyV3& r) {
                r.side.receipts_root = q.nr->tree.next_receipts_root(q.at(kL - kJ0 / 2), std::vector<pb::Hash32>{pb::receipt_id(fb)}).value();
            });
            for (int k = 0; k < 2; ++k) {
                KatNode& n = k == 0 ? *q.nf : *q.nr;
                feed(n, 1, e.t2);
                feed(n, 1, e.c1);
                n.headers.add(2, bv, h_of(net, bv.own));
                n.headers.add_body_set(2, e.c1id, {fb}, pb::header_digest(bv));
            }
            check(q.nf->headers.variants(e.c1id).size() == 2, "variant order: a second peer's variant does not evict the first peer's");
            check(same_judgement(*q.nf, *q.nr, e.c, "honest first"), "variant order: honest first, forged later: both nodes place c");
        }
        // a body variant: a carried body of c_t with its tip substituted to a deep tip (same blob and id) served first
        {
            Pair q = copy(base);
            const Edge e = make_edge(q, 8100);
            pb::ReceiptBodyV3 sub = e.r1;
            sub.side.tip = q.at(kL - 2400);
            for (int k = 0; k < 2; ++k) {
                KatNode& n = k == 0 ? *q.nf : *q.nr;
                feed(n, 1, e.t2);
                n.headers.add(1, pb::header_of(e.c1), h_of(net, e.c1.own));
                n.headers.add_body_set(0, e.c1id, {sub}, std::nullopt);       // served first (peer 0)
                n.headers.add_body_set(1, e.c1id, e.c1.carried, std::nullopt);  // the honest set second
            }
            check(same_judgement(*q.nf, *q.nr, e.c, "body variant"), "body variant: both nodes place c");
        }

        // a fake parent and a mixed path (BA-2) on a flat branch where d grows with the position:
        // y (A) on a2; B serves a variant of a2 naming a0 (one position lower) and variants of y, one naming a
        // fake parent F (bodies never served; that variant of y from a peer other than F's server, so it stays
        // held and waits on F), one naming a2_B; both nodes place c; F and a2_B are refuted at their own #9
        // (servers BANned); A gets no token
        {
            Pair q = copy(base);
            const std::uint64_t g = kL - 900, flat = kL - 900 - 1;
            const std::uint64_t hg = q.nf->node(q.at(g)).H;
            std::vector<pb::Hash32> fb;
            for (KatNode* n : {q.nf.get(), q.nr.get()})
                fb = scaffold_chain(*n, q.at(g), flat - g + 597, 0x25, [&](std::uint64_t) { return hg; }, 9);
            KatNode sc(*q.nr);
            const pb::Hash32 a0 = fb.back();
            const pb::CarrierBodyV3 a1 = carrier_on(sc, a0, hg, {}, 10, 8200);
            const bool p1 = admit_place(sc, a1, CarrierRole::Closure).placed;
            const pb::Hash32 a1id = pb::receipt_id(a1.own);
            const pb::CarrierBodyV3 a2 = carrier_on(sc, a1id, hg, {}, 11, 8201);
            const bool p2 = admit_place(sc, a2, CarrierRole::Closure).placed;
            const pb::Hash32 a2id = pb::receipt_id(a2.own);
            const pb::CarrierBodyV3 y = carrier_on(sc, a2id, hg, {}, 12, 8202);
            const bool p3 = admit_place(sc, y, CarrierRole::Closure).placed;
            const pb::Hash32 yid = pb::receipt_id(y.own);
            const pb::ReceiptBodyV3 r = body_on(sc, yid, std::max(hg, q.nf->node(L).H - 95), 13, 8203);
            const pb::CarrierBodyV3 c = carrier_on(sc, L, h_pos(kL + 1), {r}, 1, 8204);
            check(p1 && p2 && p3, "fake parent: a1, a2, y valid (scratch)");
            const std::uint64_t d_a0 = q.nr->tree.next_difficulty(a0).value();
            // B's a2: one position lower, its claims consistent on that path
            const pb::CarrierHeader a2b = sorted_before(variant_of(a2, [&](pb::ReceiptBodyV3& v) {
                v.side.tip = a0;
                v.side.t_origin = d_a0;
                v.side.receipts_root = q.nr->tree.next_receipts_root(a0, {}).value();
            }), *pb::header_digest(pb::header_of(a2)));
            // the d after y on the path through a2_B (a claim) differs from the honest d after y
            pb::RetargetWindow wm = *q.nr->tree.window_after(a0);
            wm.push(pb::RetargetEntry{d_a0, hg});
            const std::uint64_t d_y_mixed = wm.next_difficulty();
            const std::uint64_t d_y_honest = sc.tree.next_difficulty(a2id).value();
            wm.push(pb::RetargetEntry{d_y_mixed, hg});
            const std::uint64_t d_after_y_mixed = wm.next_difficulty();
            check(d_y_mixed != d_y_honest && d_after_y_mixed != sc.tree.next_difficulty(yid).value(),
                  "fake parent: d at y's position differs on the path through a2_B (" + std::to_string(d_y_mixed) + " / "
                          + std::to_string(d_y_honest) + ")");
            const pb::Hash32 y_dg = *pb::header_digest(pb::header_of(y));
            // B's y on a2_B (the same id as a2), with claims consistent on that path
            const pb::RatchetPlacement a2b_pl[1] = {pb::RatchetPlacement{d_a0, a2.own.side.ballot}};
            const pb::RatchetState s_a2b = pb::rs_step_at(q.nr->RP, q.nr->node(a0).rs, q.nr->node(a0).pos + 1, a2b_pl, q.nr->T).s;
            const pb::CarrierHeader yb2 = sorted_before(variant_of(y, [&](pb::ReceiptBodyV3& v) {
                v.side.t_origin = d_y_mixed;
                v.side.receipts_root = pb::carrier_receipts_root_over({}, s_a2b);
            }), y_dg);
            // the fake parent F: a header on a0 with forged side_data and one carried body never served
            pb::ReceiptBodyV3 fown = body_on(sc, a0, hg, 14, 8205);
            fown.side.ballot ^= 1;  // forged after its coinbase was built
            pb::CarrierHeader F;
            F.own = fown;
            F.n_carried = 1;
            const pb::Hash32 fid = pb::receipt_id(fown);
            const pb::CarrierHeader yb = sorted_before(variant_of(y, [&](pb::ReceiptBodyV3& v) { v.side.tip = fid; }), y_dg);
            for (int k = 0; k < 2; ++k) {
                KatNode& n = k == 0 ? *q.nf : *q.nr;
                const std::string who = k == 0 ? "N_floor" : "N_raised";
                feed(n, 1, a1);
                feed(n, 1, a2);
                n.headers.add(2, a2b, hg);
                n.headers.add(3, F, hg);
                n.headers.add(5, yb, hg);  // y on F from another peer: it waits on F, which is never placed
                n.headers.add(4, yb2, hg);
                feed(n, 1, y);
                {
                    const pb::AdmitEnv env = n.env();
                    const pb::OwnChain own(env, L);
                    pb::ClosureWalk w(env, own);
                    const pb::WalkResult wr = w.walk_tip(yid);
                    check(wr.v == pb::WalkVerdict::Bind && wr.d_tip == d_after_y_mixed && wr.claim_based,
                          "fake parent (" + who + "): the first passing assignment is the mixed path (a claim; d after y differs)");
                }
                const Settled st = settle(n, c);
                bool tok1 = false;
                for (const auto& [peer, t] : st.tokens) tok1 = tok1 || peer == 1;
                check(st.r.verdict == AdmitVerdict::AdmitCarrier, "fake parent (" + who + "): c judged (" + desc(st.r) + ")");
                check(!tok1 && st.struck.count(1) == 0 && st.banned.count(1) == 0,
                      "fake parent (" + who + "): the honest server of y gets no token along the mixed path");
                check(st.banned.count(3) == 1 && st.banned.count(2) == 1 && n.tree.find(fid) == nullptr,
                      "fake parent (" + who + "): F refuted at its own #9 without its bodies, a2_B refuted (servers BANned)");
                check(st.banned.count(4) + st.struck.count(4) == 1 && n.headers.variants(yid).size() == 1,
                      "fake parent (" + who + "): y_B refuted at its own #8 on the bound chain (its server struck)");
            }
        }
    });
}

// The nested on-chain tip (P-37): heights of [L - 2 J_0, L - J_0] span 90; c on the best tip; r's tip
// c_t at f + 1 (f = L - J_0); c_t carries r' with h(r') = H(f) - F + 1 whose tip lies on c's chain at
// H(f) - F - Fresh + 1; N_floor with P-37 at its floor and N_raised judge alike.
void nested_on_chain_tip() {
    run_part("nested on-chain tip (P-37)", [] {
        KatNet net;
        const std::uint64_t lo = kL - 2 * kJ0, hi = kL - kJ0;
        const auto hof = [&](std::uint64_t pos) -> std::uint64_t {
            if (pos <= lo) return h_pos(pos);
            if (pos <= hi) return h_pos(lo) + 90 * (pos - lo) / kJ0;
            return h_pos(lo) + 90 + (pos - hi) / 12;
        };
        Pair q;
        q.nf = std::make_unique<KatNode>(net, kJ0);
        q.nr = std::make_unique<KatNode>(net, 3 * kJ0);
        q.chain = scaffold_chain(*q.nf, q.nf->tree.genesis().id, kL, 0x30, hof, 0);
        check(scaffold_chain(*q.nr, q.nr->tree.genesis().id, kL, 0x30, hof, 0) == q.chain, "nested tip: one chain");
        check(hof(hi) - hof(lo) == 90, "nested tip: the heights of [L - 2 J_0, L - J_0] span 90");
        KatNode sc(*q.nr);
        const std::uint64_t f = hi;
        const std::uint64_t Hf = q.nf->node(q.at(f)).H;
        const std::uint64_t ht = Hf - 96 - 2 + 1;  // H(f) - F - Fresh + 1
        std::uint64_t tp = 1;
        while (hof(tp + 1) <= ht) ++tp;
        check(hof(tp) == ht, "nested tip: t' on c's chain at H(f) - F - Fresh + 1");
        const pb::ReceiptBodyV3 r1 = body_on(sc, q.at(tp), Hf - 96 + 1, 13, 8300);
        const pb::CarrierBodyV3 ct = carrier_on(sc, q.at(f), Hf, {r1}, 6, 8301);
        const Admitted act = admit_place(sc, ct, CarrierRole::Closure);
        check(act.placed, "nested tip: c_t valid (scratch): " + desc(act.r));
        const pb::Hash32 ctid = pb::receipt_id(ct.own);
        const pb::ReceiptBodyV3 r = body_on(sc, ctid, std::max(Hf, q.nf->node(q.at(kL)).H - 95), 12, 8302);
        const pb::CarrierBodyV3 c = carrier_on(sc, q.at(kL), hof(kL + 1), {r}, 1, 8303);
        const std::uint64_t floor = q.nf->store.prune_entries(UINT64_MAX);
        check(floor == q.nf->store.entry_floor_limit(), "nested tip: N_floor's P-37 at its floor");
        for (KatNode* n : {q.nf.get(), q.nr.get()}) feed(*n, 1, ct);
        check(same_judgement(*q.nf, *q.nr, c, "nested on-chain tip"),
              "nested on-chain tip: N_floor at the P-37 floor and N_raised judge alike (no MissingEntries)");
    });
}

// ---------------------------------------------------------------------------
// 5.2: the contract rows, the deferred store (P-47), the extension point
// (a test double), the P-50 budget, the write step
// ---------------------------------------------------------------------------
pb::ParkedFrame parked_of(const pb::CarrierBodyV3& c, std::uint64_t peer, const pb::AdmitResult& r) {
    pb::ParkedFrame pf;
    pf.frame = frame_of(c);
    pf.digest = ::v37::sha256d(pf.frame);
    pf.id = pb::receipt_id(c.own);
    pf.parent = c.own.side.tip;
    pf.peer = peer;
    pf.cause = r.missing.value_or(Missing::NodeInternal);
    pf.claim_based = r.claim_based;
    pf.walked = r.walked;
    return pf;
}

// A ClaimView double: a basis per row class (for every tip, or one tip), judge_copy, the serve answers.
struct DoubleView final : pb::ClaimView {
    std::map<pb::RowClass, pb::Basis> by_class;
    std::optional<pb::Hash32> only_tip;
    bool copies = true;
    pb::Basis basis(pb::RowClass k, const pb::Hash32& tip, std::uint64_t) const override {
        if (only_tip && !(tip == *only_tip)) return pb::Basis::Computed;
        const auto it = by_class.find(k);
        return it == by_class.end() ? pb::Basis::Computed : it->second;
    }
    pb::Basis header_binding(const pb::Hash32&, const pb::Hash32&) const override { return pb::Basis::Computed; }
    bool judge_copy(std::uint64_t, const pb::Hash32&) const override { return copies; }
    bool leaf_servable(std::uint64_t) const override { return true; }
    bool at_servable(const pb::Hash32&, const pb::Hash32&) const override { return true; }
    bool rests_on_claims() const override { return false; }
};

// A store whose seal fails (a node-internal outcome of the write step).
struct FailingSealStore {
    pb::BinStore& s;
    pb::AddVerdict add_carrier(const pb::Hash32& id, const pb::Hash32& parent, std::uint64_t h) { return s.add_carrier(id, parent, h); }
    std::optional<pb::Ingest> ingest(const pb::Hash32& c, pb::Placement r) { return s.ingest(c, std::move(r)); }
    std::optional<std::uint64_t> seal(const pb::Hash32&) { return std::nullopt; }
    const pb::LaneDelta* delta(const pb::Hash32& id) const { return s.delta(id); }
    const pb::Hash32& best_tip() const { return s.best_tip(); }
    pb::SwitchVerdict switch_best(const pb::Hash32& t, pb::LaneBatch* b) { return s.switch_best(t, b); }
};

void contract() {
    run_part("5.2 contract", [] {
        KatNet net;
        KatNode n(net, kJ0);
        const std::vector<pb::Hash32> chain = pipeline_chain(n, 60);
        const pb::Hash32 L = chain.back();
        const std::uint64_t hL = n.node(L).h, hc = h_pos(61);

        // C-2 / C-3: carried body 3 fails #9, body 5 fails #12 -> STRIKE (row 23, body 3), #12 not computed for
        // body 5 (its tip's keys never derived), nothing stored. Bodies 1-4 and 6 on L, body 5 on chain[56]; the
        // list in canonical order with the two failing bodies at positions 3 and 5.
        {
            const std::uint64_t hr = n.node(L).h + 1;
            const pb::Hash32 deep = chain[56];
            std::vector<pb::ReceiptBodyV3> rs;
            bool laid = false;
            for (std::uint64_t s = 0; s < 256 && !laid; ++s) {
                rs.clear();
                for (std::uint64_t k = 0; k < 6; ++k) {
                    pb::ReceiptBodyV3 r = body_on(n, k == 4 ? deep : L, hr, 12 + k, 9100 + 8 * s + k,
                                                  k == 2 ? Tweak([](pb::ReceiptBodyV3& b) { b.blob.minor = 0; }) : Tweak{});
                    if (k == 4) r.side.ballot ^= 1;  // after its coinbase was built: #12 mismatches
                    rs.push_back(r);
                }
                canonical_sort(*n.net, rs, L);
                laid = rs[2].blob.minor == 0 && rs[4].side.tip == deep;
            }
            check(laid, "C-2: a canonical list with the #9 failure at body 3 and the #12 failure at body 5");
            std::vector<pb::ReceiptBodyV3> without5 = rs;
            without5.erase(without5.begin() + 4);
            const pb::CarrierBodyV3 bad = carrier_on(n, L, hc, rs, 1, 9110, {}, {}, false);
            const pb::CarrierBodyV3 ref = carrier_on(n, L, hc, without5, 1, 9111, {}, {}, false);
            const pb::BmmrHead head = n.store.head();
            n.keys = pb::KeyCache{};
            const pb::AdmitResult a = admit(n, bad);
            const std::uint64_t ka = n.keys.computations();
            n.keys = pb::KeyCache{};
            const pb::AdmitResult b = admit(n, ref);
            const std::uint64_t kb = n.keys.computations();
            check(a.verdict == AdmitVerdict::Strike && a.row == RowId::R23 && a.body == 3 && is(b, AdmitVerdict::Strike, RowId::R23)
                          && ka == kb && n.store.head() == head && n.tree.find(pb::receipt_id(bad.own)) == nullptr,
                  "C-2: the first failing row decides (" + desc(a) + "); #12 not computed for body 5 (keys " +
                          std::to_string(ka) + " / " + std::to_string(kb) + " without body 5); nothing stored");
        }
        // A-3: a substituted carried body -> FoldMismatch (STRIKE), the sender struck once; the honest copy placed
        {
            KatNode m(n);
            const pb::ReceiptBodyV3 r1 = body_on(m, L, hL + 1, 12, 9200), r2 = body_on(m, L, hL + 1, 13, 9201);
            const pb::ReceiptBodyV3 r3 = body_on(m, L, hL + 1, 14, 9202);
            const pb::CarrierBodyV3 honest = carrier_on(m, L, hc, {r1, r2}, 1, 9203);
            pb::CarrierBodyV3 sub = honest;
            sub.carried.back() = r3;
            std::vector<pb::ReceiptBodyV3> cs = sub.carried;
            canonical_sort(net, cs, L);
            sub.carried = cs;
            const pb::AdmitResult a = admit(m, sub);
            const Admitted h = admit_place(m, honest);
            check(is(a, AdmitVerdict::Strike, RowId::R11) && a.strike == 1 && h.placed,
                  "A-3: a substituted carried body -> STRIKE (fold), the sender struck once; the honest copy placed");
        }
        // P-47: the waiting cap (3, a KAT parameter)
        {
            KatNode m(n);
            KatNode sc(n);
            std::vector<pb::CarrierBodyV3> xs, ys;
            pb::Hash32 prev = L;
            for (std::uint64_t k = 0; k < 6; ++k) {
                const pb::CarrierBodyV3 x = carrier_on(sc, prev, h_pos(61 + k), {}, 2, 9300 + k);
                check(admit_place(sc, x).placed, "P-47: scratch chain");
                xs.push_back(x);
                prev = pb::receipt_id(x.own);
                ys.push_back(carrier_on(sc, prev, h_pos(62 + k), {}, 3, 9310 + k));
            }
            pb::DeferredCarriers st(3);
            const auto park = [&](const pb::CarrierBodyV3& c, std::uint64_t peer) {
                const pb::AdmitResult r = admit(m, c);
                return st.park(m.tree, parked_of(c, peer, r));
            };
            bool step = park(ys[1], 2) && m.tree.waiting() == st.waiting_keys();
            step = step && park(ys[2], 1) && m.tree.waiting() == st.waiting_keys();
            step = step && park(ys[3], 1) && m.tree.waiting() == st.waiting_keys();
            const pb::Hash32 a_oldest = ::v37::sha256d(frame_of(ys[2])), b_only = ::v37::sha256d(frame_of(ys[1]));
            step = step && park(ys[4], 3);
            check(step && st.size() == 3 && !st.holds(a_oldest) && st.holds(b_only) && m.tree.waiting() == st.waiting_keys()
                          && m.tree.waiting() == 3,
                  "P-47: cap 3, A holds 2, B 1: a fourth frame drops A's oldest, no token; tree.waiting() == the store's keys");
            // one key, two frames: a forged copy of Y naming Y's true parent first, the honest copy second
            KatNode w(n);
            pb::DeferredCarriers sk(3);
            pb::CarrierBodyV3 forged = ys[0];
            forged.own.side.ballot ^= 1;
            const auto park_w = [&](pb::DeferredCarriers& d, const pb::CarrierBodyV3& c, std::uint64_t peer) {
                const pb::AdmitResult r = admit(w, c);
                return d.park(w.tree, parked_of(c, peer, r));
            };
            check(park_w(sk, forged, 5) && park_w(sk, ys[0], 6) && w.tree.waiting() == 1 && sk.waiting_keys() == 1 && sk.size() == 2,
                  "P-47: one waiting key, two frames");
            // the forged copy evicted first by the cap: the honest copy stays under the key
            check(park_w(sk, ys[2], 5) && park_w(sk, ys[3], 5) && !sk.holds(::v37::sha256d(frame_of(forged)))
                          && sk.holds(::v37::sha256d(frame_of(ys[0]))) && w.tree.waiting() == sk.waiting_keys(),
                  "P-47: the forged copy evicted; the key stays (unwait only when its last frame leaves)");
            const Admitted ax = admit_place(w, xs[0]);
            bool placed = false;
            for (const pb::ParkedFrame& f : sk.release(pb::receipt_id(xs[0].own), ax.w.place.released)) {
                const pb::AdmitResult r = pb::admit_carrier(w.env(), f.frame, CarrierRole::Frame);
                if (r.verdict == AdmitVerdict::AdmitCarrier) {
                    placed = pb::place_admitted(w.tree, w.store, w.ar, w.bodies, r, &w.alarm).outcome != pb::WriteOutcome::NodeInternal;
                    sk.purge(r.id);
                }
            }
            check(ax.placed && placed && w.tree.find(pb::receipt_id(ys[0].own)) != nullptr,
                  "P-47: the honest copy is placed on the parent's arrival");
            // both frames present when the parent arrives: the forged copy refuted at #9, the honest placed
            KatNode v(n);
            pb::DeferredCarriers sv(8);
            const auto park_v = [&](const pb::CarrierBodyV3& c, std::uint64_t peer) {
                return sv.park(v.tree, parked_of(c, peer, admit(v, c)));
            };
            check(park_v(forged, 5) && park_v(ys[0], 6), "P-47: forged and honest copies parked under one key");
            const Admitted vx = admit_place(v, xs[0]);
            bool banned = false, vplaced = false;
            for (const pb::ParkedFrame& f : sv.release(pb::receipt_id(xs[0].own), vx.w.place.released)) {
                const pb::AdmitResult r = pb::admit_carrier(v.env(), f.frame, CarrierRole::Frame);
                banned = banned || (f.peer == 5 && r.verdict == AdmitVerdict::Ban);
                if (r.verdict == AdmitVerdict::AdmitCarrier)
                    vplaced = pb::place_admitted(v.tree, v.store, v.ar, v.bodies, r, &v.alarm).outcome != pb::WriteOutcome::NodeInternal;
            }
            check(banned && vplaced, "P-47: the forged copy refuted at #9 (its sender BANned), the honest copy placed");
        }
        // guarantee 4: CarriedPlacement.live equals the store's live for every placement of a 400-carrier random tree
        {
            KatNode m(n);
            Rng rng(0x47);
            std::vector<pb::Hash32> held(chain.end() - 12, chain.end());
            std::uint64_t ok = 0, placements = 0, dead = 0;
            bool equal = true;
            for (std::uint64_t i = 0; i < 400; ++i) {
                const pb::Hash32 parent = held[held.size() - 1 - rng.below(std::min<std::size_t>(held.size(), 10))];
                const pb::CarrierNode& pn = m.node(parent);
                std::vector<pb::ReceiptBodyV3> rs;
                const std::uint64_t k = rng.below(4);
                pb::Hash32 t = parent;
                for (std::uint64_t j = 0; j < k; ++j) {
                    const std::uint64_t back = rng.below(6);
                    const std::optional<pb::Hash32> a = m.tree.ancestor_at(parent, pn.pos > back ? pn.pos - back : 0);
                    t = a.value_or(parent);
                    rs.push_back(body_on(m, t, m.node(t).h + rng.below(2), j % 6, 10000 + 10 * i + j));
                }
                const pb::CarrierBodyV3 c = carrier_on(m, parent, pn.H + (rng.below(3) == 0 ? 1 : 0), rs, i % 5, 20000 + i);
                const Admitted a = admit_place(m, c);
                if (!a.placed) continue;
                ++ok;
                const pb::LaneDelta* d = m.store.delta(pb::receipt_id(c.own));
                for (std::size_t q = 0; d && q < a.r.placements.size(); ++q) {
                    ++placements;
                    dead += a.r.placements[q].live ? 0 : 1;
                    equal = equal && d->placed[q].live == a.r.placements[q].live;
                }
                held.push_back(pb::receipt_id(c.own));
            }
            check(ok == 400 && equal && placements > 300 && dead > 0,
                  "guarantee 4: 400 carriers placed (" + std::to_string(ok) + "), " + std::to_string(placements) +
                          " carried placements (" + std::to_string(dead) + " dead): live equals the store's for every one");
        }
        // the write step: a node-internal store outcome leaves c placed but not chain-valid; tree.drop removes it
        {
            KatNode m(n);
            const pb::CarrierBodyV3 c = carrier_on(m, L, hc, {}, 1, 9400);
            const pb::AdmitResult r = admit(m, c);
            FailingSealStore fs{m.store};
            const pb::Hash32 best = m.tree.best().id;
            const pb::WriteResult w = pb::place_admitted(m.tree, fs, m.ar, m.bodies, r, &m.alarm);
            check(r.verdict == AdmitVerdict::AdmitCarrier && w.outcome == pb::WriteOutcome::NodeInternal
                          && m.tree.find(pb::receipt_id(c.own)) == nullptr && m.tree.best().id == best,
                  "write step: seal fails -> node-internal; c dropped from the tree (not chain-valid), the best tip unchanged");
            // a FoldMismatch at tree.place leaves no delta
            KatNode m2(n);
            pb::AdmitResult bad = r;
            bad.announce.receipts_root[0] ^= 1;
            const std::size_t jsz = m2.store.journal_size();
            const pb::WriteResult wb = pb::place_admitted(m2.tree, m2.store, m2.ar, m2.bodies, bad, &m2.alarm);
            check(wb.outcome == pb::WriteOutcome::NodeInternal && m2.store.journal_size() == jsz && !m2.store.holds(bad.announce.id),
                  "write step: a FoldMismatch at tree.place: node-internal, nothing written to the store");
        }
        // the extension point: a test double
        {
            KatNode m(n);
            DoubleView dv;
            m.claims = &dv;
            // #12 mismatch on a carried body under ClaimLeaf / ClaimSpan: ClaimAlarm, 0 tokens, no BAN, RandomX 0
            pb::ReceiptBodyV3 r = body_on(m, L, hL + 1, 12, 9500);
            r.side.ballot ^= 1;
            const pb::CarrierBodyV3 c = carrier_on(m, L, hc, {r}, 1, 9501);
            for (pb::Basis b : {pb::Basis::ClaimLeaf, pb::Basis::ClaimSpan}) {
                dv.by_class = {{pb::RowClass::Coinbase, b}};
                const std::uint64_t rx = m.rx_calls;
                const std::size_t al = m.alarm.count();
                const pb::AdmitResult a = admit(m, c);
                check(deferred(a, Missing::ClaimAlarm) && a.alarm && a.strike == 0 && a.verdict != AdmitVerdict::Ban
                              && m.rx_calls == rx && m.alarm.count() == al + 1 && m.alarm.entries.back().basis == b,
                      std::string("extension point: #12 mismatch on a ") + (b == pb::Basis::ClaimLeaf ? "ClaimLeaf" : "ClaimSpan")
                              + " basis -> DEFER + local alarm, 0 tokens, no BAN, RandomX 0");
            }
            // S1.3 #8 on a ClaimSpan basis (Retarget)
            dv.by_class = {{pb::RowClass::Retarget, pb::Basis::ClaimSpan}};
            const pb::CarrierBodyV3 t1 = carrier_on(m, L, hc, {}, 1, 9502, [](pb::ReceiptBodyV3& b) { b.side.t_origin -= 1; });
            const pb::AdmitResult at = admit(m, t1);
            check(deferred(at, Missing::ClaimAlarm) && at.row == RowId::R9 && at.strike == 0,
                  "extension point: S1.3 #8 mismatch on a ClaimSpan basis -> DEFER + alarm, 0 tokens");
            // NotComputed: #12 not run (the key-cache counter 0)
            dv.by_class = {{pb::RowClass::Coinbase, pb::Basis::NotComputed}};
            dv.only_tip = L;
            m.keys = pb::KeyCache{};
            const pb::AdmitResult nc = pb::admit_receipt(m.env(), bytes_of(r), pb::Role::Pending);
            check(nc.verdict == AdmitVerdict::AdmitPending && m.keys.computations() == 0,
                  "extension point: a NotComputed #12 is not run (key-cache counter 0)");
            dv.only_tip.reset();
            // judge_copy false: CopyDeferred, 0 tokens, no row run
            dv.by_class.clear();
            dv.copies = false;
            const std::uint64_t pr0 = m.pr_calls;
            const pb::AdmitResult cd = pb::admit_frame_from(m.env(), 4, frame_of(c), CarrierRole::Frame);
            check(deferred(cd, Missing::CopyDeferred) && cd.strike == 0 && m.pr_calls == pr0,
                  "extension point: judge_copy false -> CopyDeferred, 0 tokens, no row run");
            dv.copies = true;
            // a double that answers as the null view: the null view's verdicts
            std::vector<pb::CarrierBodyV3> vs{c, t1, carrier_on(m, L, hc, {}, 1, 9503),
                                              carrier_on(m, L, hc, {body_on(m, L, hL + 1, 13, 9504)}, 1, 9505)};
            bool same = true;
            for (const pb::CarrierBodyV3& x : vs) {
                m.claims = nullptr;
                const pb::AdmitResult a0 = admit(m, x);
                m.claims = &dv;
                const pb::AdmitResult a1 = admit(m, x);
                same = same && a0.verdict == a1.verdict && a0.row == a1.row && a0.strike == a1.strike && a0.missing == a1.missing;
            }
            check(same, "extension point: a double answering as the null view gives the null view's verdicts");
            m.claims = nullptr;
            check(!dv.rests_on_claims(), "extension point: the null view's state rests on no claim");
        }
        // P-50: the claim-leaf alarm budget
        {
            KatNode m(n);
            DoubleView dv;
            dv.by_class = {{pb::RowClass::Roots, pb::Basis::ClaimLeaf}};
            dv.only_tip = L;
            m.claims = &dv;
            pb::ClaimAlarmBudget budget(m.P);
            std::uint64_t alarms = 0, tokens = 0;
            int disconnected_at = 0;
            for (int k = 1; k <= 18; ++k) {
                const pb::ReceiptBodyV3 r = body_on(m, L, hL + 1, 12, 9600 + k, {}, [](pb::ReceiptBodyV3& b) { b.side.window_root[0] ^= 1; });
                const pb::AdmitResult a = admit(m, carrier_on(m, L, hc, {r}, 1, 9700 + k));
                if (deferred(a, Missing::ClaimAlarm)) {
                    ++alarms;
                    if (!budget.charge(1, 1000, true) && disconnected_at == 0) disconnected_at = k;
                }
                tokens += a.strike;
            }
            check(alarms == 18 && tokens == 0 && disconnected_at == 18,
                  "P-50: 18 relayed frames at once whose #13 mismatches on a ClaimLeaf basis: 18 alarms, 0 tokens, "
                  "the peer disconnected at the 18th (" + std::to_string(disconnected_at) + ")");
            bool stays = true;
            for (std::uint64_t k = 0; k < 40; ++k) stays = stays && budget.charge(2, 1000 + k * m.P.carrier_interval_s, true);
            check(stays, "P-50: one such frame per T stays connected");
            bool replies = true;
            for (int k = 0; k < 40; ++k) replies = replies && budget.charge(3, 1000, false);
            check(replies, "P-50: a reply to the node's own request is not counted");
            m.claims = nullptr;
            const pb::ReceiptBodyV3 r = body_on(m, L, hL + 1, 12, 9650, {}, [](pb::ReceiptBodyV3& b) { b.side.window_root[0] ^= 1; });
            const pb::AdmitResult a = admit(m, carrier_on(m, L, hc, {r}, 1, 9651));
            check(a.verdict == AdmitVerdict::Ban && !a.alarm, "P-50: with claims == nullptr the mismatch is a computed BAN, no alarm");
        }
    });
}

// ---------------------------------------------------------------------------
// P-49: no count on the header variants or the body sets a walk needs
// ---------------------------------------------------------------------------
void p49() {
    run_part("P-49", [] {
        KatNet net;
        const Pair base = make_pair_chain(net, kL);
        const pb::Hash32 L = base.at(kL);
        // t on a branch of J_0 + 1 side carriers (pos(t) = pos(parent(c)) + 1), every carrier carrying 16
        // receipts; every header and body set served by one peer
        Pair q;
        q.nf = std::make_unique<KatNode>(*base.nf);
        q.nr = std::make_unique<KatNode>(*base.nr);
        q.chain = base.chain;
        KatNode sc(*q.nr);
        const std::uint64_t f = kL - kJ0;
        std::vector<pb::CarrierBodyV3> side;
        pb::Hash32 prev = q.at(f);
        bool valid = true;
        for (std::uint64_t k = 1; k <= kJ0 + 1 && valid; ++k) {
            std::vector<pb::ReceiptBodyV3> rs;
            for (std::uint64_t j = 0; j < pb::kRuledLaneParams.r_max; ++j)
                    rs.push_back(body_on(sc, prev, sc.node(prev).h, j % 5, 400000 + 16 * k + j));
            const pb::CarrierBodyV3 c = carrier_on(sc, prev, h_pos(f + k), rs, 7, 300000 + k);
            const Admitted a = admit_place(sc, c, CarrierRole::Closure);
            valid = a.placed;
            if (!valid) std::printf("  P-49 side carrier %llu: %s\n", static_cast<unsigned long long>(k), desc(a.r).c_str());
            side.push_back(c);
            prev = pb::receipt_id(c.own);
        }
        check(valid && sc.node(prev).pos == kL + 1, "P-49: a side branch of J_0 + 1 carriers, 16 receipts each, t at pos(parent(c)) + 1");
        const pb::Hash32 t = prev;
        const pb::ReceiptBodyV3 r = body_on(sc, t, std::max(sc.node(t).h, q.nf->node(L).H - 95), 12, 8400);
        const pb::CarrierBodyV3 c = carrier_on(sc, L, h_pos(kL + 1), {r}, 1, 8401);
        for (KatNode* n : {q.nf.get(), q.nr.get()})
            for (const pb::CarrierBodyV3& x : side) feed(*n, 1, x);
        check(q.nf->headers.held_by(1) == kJ0 + 1, "P-49: one peer holds J_0 + 1 unbound variants (no count cap)");
        check(same_judgement(*q.nf, *q.nr, c, "P-49 J_0 + 1 branch"),
              "P-49: N_floor and N_raised both place c (one peer served every header and body set)");
    });

    run_part("P-49 structure", [] {
        KatNet net;
        KatNode n(net, kJ0);
        const std::vector<pb::Hash32> chain = pipeline_chain(n, 30);
        const pb::Hash32 L = chain.back();
        KatNode sc(n);
        const pb::CarrierBodyV3 y = carrier_on(sc, L, h_pos(31), {}, 2, 8500);
        const pb::Hash32 yid = pb::receipt_id(y.own);
        const pb::CarrierHeader v1 = variant_of(y, [](pb::ReceiptBodyV3& r) { r.side.ballot ^= 1; });
        const pb::CarrierHeader v2 = variant_of(y, [](pb::ReceiptBodyV3& r) { r.side.ballot ^= 2; });
        pb::HeaderIndex& hx = n.headers;
        hx.add(5, v1, h_of(net, y.own));
        hx.add(6, pb::header_of(y), h_of(net, y.own));
        check(hx.add(5, v2, h_of(net, y.own)) == pb::IndexAdd::Replaced && hx.held_by(5) == 1 && hx.variants(yid).size() == 2,
              "P-49: a peer's second variant of an id replaces its first (held 1); another peer's variant stays");
        hx.release_peer(5);
        check(hx.variants(yid).size() == 1 && hx.held_by(5) == 0, "P-49: a disconnect releases the peer's variants");
        hx.add(5, v1, h_of(net, y.own));
        check(hx.bind(yid, *pb::header_digest(pb::header_of(y))) && hx.variants(yid).size() == 1 && hx.variants(yid)[0]->bound,
              "P-49: binding drops every unbound variant of the id");
        check(hx.add(7, v2, h_of(net, y.own)) == pb::IndexAdd::BoundDropped, "P-49: a later different variant of a bound id is dropped");
        const pb::CarrierBodyV3 low = carrier_on(sc, chain[0], h_pos(2), {}, 3, 8501);
        hx.add(8, pb::header_of(low), h_of(net, low.own));
        check(hx.drop_below(h_of(net, low.own) + 1) == 1 && hx.variants(pb::receipt_id(low.own)).empty() && !hx.variants(yid).empty(),
              "P-49: an unbound variant below the floor H(base_pos - J_0) is dropped; a bound one stays");
        // an honest relay R holds a walked header only as an unbound variant: asked for it, R answers without it
        KatNode R(n);
        R.headers = pb::HeaderIndex{};
        const pb::CarrierHeader junk = variant_of(y, [](pb::ReceiptBodyV3& r) { r.side.ballot ^= 4; });
        R.headers.add(9, junk, h_of(net, y.own));
        const std::vector<pb::CarrierHeader> reply = pb::serve_headers(R.tree, R.bodies, R.headers, chain[20], yid, 1152);
        check(reply.empty(), "P-49: an honest relay holding y only as an unbound variant serves no header for it (n = 0)");
        const std::vector<pb::CarrierHeader> placed = pb::serve_headers(R.tree, R.bodies, R.headers, chain[20], L, 1152);
        check(placed.size() == 9 && pb::receipt_id(placed.back().own) == L, "P-49: a relay serves the headers it placed");
        check(!pb::serve_carrier(R.tree, R.bodies, yid, true).has_value() && pb::serve_carrier(R.tree, R.bodies, L, true).has_value(),
              "P-49: FC_GETCARRIER served only for a placed carrier");
        // re-walks are scheduled: a peer answering every request with a new variant is asked once per walk
        KatNode m(n);
        m.headers = pb::HeaderIndex{};
        m.headers.add(10, variant_of(y, [](pb::ReceiptBodyV3& r) { r.side.tip = seq32(0xD1); }), h_of(net, y.own));
        const pb::ReceiptBodyV3 rr = body_on(sc, yid, h_pos(31), 12, 8502);  // its tip y is held as a variant only
        const pb::CarrierBodyV3 c = carrier_on(n, L, h_pos(31), {}, 1, 8503);
        (void)rr;
        pb::DeferredCarriers st(pb::waiting_cap_default());
        pb::ParkedFrame pf = parked_of(c, 3, pb::AdmitResult{});
        pf.cause = Missing::Closure;
        pf.claim_based = true;
        pf.walked = {yid};
        check(st.park(m.tree, pf), "P-49: a claim-based frame parked");
        std::uint64_t replies = 0;
        for (int round = 0; round < 10; ++round) {
            if (st.may_ask(pf.digest, 10)) {
                ++replies;
                m.headers.add(10, variant_of(y, [&](pb::ReceiptBodyV3& r) { r.side.tip = seq32(static_cast<std::uint8_t>(0xD2 + round)); }),
                              h_of(net, y.own));
                st.touch({yid});
            }
            for (const pb::Hash32& d : st.take_rewalks()) (void)d;
        }
        check(replies == 1 && st.get(pf.digest)->walks <= 1 && m.headers.held_by(10) == 1,
              "P-49: the peer is asked once per walk; the frame's re-walks stay within the peers plus the bindings");
    });
}

// ---------------------------------------------------------------------------
// Rows 18, 19, the window inputs on P_t's branch, the bucket fetch
// ---------------------------------------------------------------------------
void rows_more() {
    // row 18: EP-4 (ii) / (iii), CLAIMED; GRACE = 20 (L 5, a KAT parameter)
    run_part("row 18", [] {
        KatNet net;
        const pb::RatchetParams small{5, 20, 100};
        KatNode n(net, kJ0, small);
        const std::vector<pb::Hash32> chain = pipeline_chain(n, 60);
        const pb::Hash32 L = chain.back();
        const std::uint64_t hc = h_pos(61);
        // x within GRACE: AR epoch (ii) -> judged
        const pb::ReceiptBodyV3 r = body_on(n, chain[55], n.node(chain[55]).h + 1, 12, 9800);
        check(admit(n, carrier_on(n, L, hc, {r}, 1, 9801)).verdict == AdmitVerdict::AdmitCarrier,
              "row 18: x within GRACE -> the AR epoch (ii), judged");
        // mismatch at x < H_hold -> STRIKE
        const pb::ReceiptBodyV3 r1 = body_on(n, chain[55], n.node(chain[55]).h + 1, 13, 9802,
                                             [](pb::ReceiptBodyV3& b) { b.side.rules_epoch = 1; });
        check(is(admit(n, carrier_on(n, L, hc, {r1}, 1, 9803)), AdmitVerdict::Strike, RowId::R18),
              "row 18: rules_epoch mismatch at x < H_hold -> STRIKE");
        // x > f + GRACE although t's branch is held: c on a side branch forked 30 positions below the tip
        KatNode m(n);
        const pb::Hash32 g = chain[29];
        const std::vector<pb::Hash32> side = scaffold_chain(m, g, 28, 0x26, h_pos, 3);
        const pb::Hash32 sp = side.back();  // position 58 on the side branch
        const pb::ReceiptBodyV3 rs = body_on(m, side[25], m.node(side[25]).h + 1, 12, 9804);
        const pb::AdmitResult a = admit(m, carrier_on(m, sp, m.node(sp).H, {rs}, 1, 9805));
        check(deferred(a, Missing::EpochGrace) && a.strike == 0,
              "row 3 / 18: x > f + GRACE -> DEFER although t's branch is held (" + desc(a) + ")");
        // CLAIMED below a joiner's p0 (an AR seeded by seed_joiner)
        KatNode j(n);
        j.ar.seed_joiner(j.node(L).rs, j.node(L).pos + 1);
        const pb::AdmitResult cl = admit(j, carrier_on(j, L, hc, {r1}, 1, 9806));
        check(cl.verdict == AdmitVerdict::AdmitCarrier, "row 18: a tip below a joiner's p0 -> CLAIMED (the receipt's own epoch)");
    });

    run_part("row 19", [] {
        KatNet net;
        KatNode n(net, kJ0);
        const std::vector<pb::Hash32> chain = pipeline_chain(n, 60);
        const pb::Hash32 L = chain.back();
        const std::uint64_t hL = n.node(L).h, hc = h_pos(61);
        // row 19: a carried body whose served context block fails its PoW -> the frame BAN; P_r unknown -> DEFER
        {
            const pb::ReceiptBodyV3 r = body_on(n, L, hL + 1, 12, 9900);
            const pb::CarrierBodyV3 c = carrier_on(n, L, hc, {r}, 1, 9901);
            n.bad_ctx.insert(r.blob.prev_id);
            const pb::AdmitResult a = admit(n, c);
            n.bad_ctx.clear();
            n.pr_missing.insert(r.blob.prev_id);
            const pb::AdmitResult b = admit(n, c);
            n.pr_missing.clear();
            check(is(a, AdmitVerdict::Ban, RowId::R19) && deferred(b, Missing::MoneroBlock),
                  "row 19: a carried body's served context failing PoW -> BAN; P_r unknown -> DEFER");
            const pb::ReceiptBodyV3 p = body_on(n, L, hL + 1, 13, 9902);
            n.bad_ctx.insert(p.blob.prev_id);
            const pb::AdmitResult pa = pb::admit_receipt(n.env(), bytes_of(p), pb::Role::Pending);
            n.bad_ctx.clear();
            check(is(pa, AdmitVerdict::Ban, RowId::R19), "row 19: a pending body's served context failing PoW -> BAN");
        }
    });

    // row 26: the window of a tip whose P_t lies on another Monero branch reads its inputs there
    run_part("row 26 P_t's branch", [] {
        KatNet net;
        KatNode m(net, kJ0);
        const std::vector<pb::Hash32> chain = pipeline_chain(m, 125, 1, h_fast);
        const pb::Hash32 L = chain.back();
        pb::CarrierBodyV3 sb = scaffold_body(m, chain[118], kAltFrom + kAltLen + 1, 0x27, 9910, 4);
        sb.own.blob.prev_id = block_id(kAltTag, kAltFrom + kAltLen);
        check(held_side(place_direct(m, sb)), "row 26: a side carrier S whose P_t is an alt Monero block");
        const pb::Hash32 S = pb::receipt_id(sb.own);
        const pb::TipWindow ws = m.window(S);
        const pb::TipWindow wm = pb::evaluate_window_at(m.store, S, m.prev_of(L), m.mon, 16, net.author_id);
        check(ws.ok() && wm.ok() && !(ws.window_root == wm.window_root), "row 26: the alt branch's inputs give another window");
        const pb::ReceiptBodyV3 r = body_on(m, S, kAltFrom + kAltLen + 1, 12, 9911);
        const pb::CarrierBodyV3 c = carrier_on(m, L, h_fast(126), {r}, 1, 9912);
        m.windows = pb::WindowCache{};  // the pipeline computes every window itself
        const pb::AdmitResult a = admit(m, c);
        check(a.verdict == AdmitVerdict::AdmitCarrier, "row 26: a receipt on S: its window read on P_t's branch -> admitted (" + desc(a) + ")");
    });

    run_part("row 26 MissingBucket", [] {
        KatNet net;
        KatNode n(net, kJ0);
        const std::vector<pb::Hash32> chain = pipeline_chain(n, 110, 1, h_fast);
        const pb::Hash32 P = chain.back();
        const pb::CarrierBodyV3 sb = scaffold_body(n, chain[108], h_fast(110), 0x28, 9950, 4);
        check(held_side(place_direct(n, sb)), "MissingBucket: a sibling S of the best tip");
        const pb::Hash32 S = pb::receipt_id(sb.own);
        const pb::ReceiptBodyV3 r = body_on(n, S, h_fast(110) + 1, 12, 9951);
        n.store.prune_buckets(UINT64_MAX);
        n.windows = pb::WindowCache{};
        const pb::AdmitResult a = pb::admit_receipt(n.env(), bytes_of(r), pb::Role::Pending);
        const pb::LaneView fv = n.store.view_at(a.fetch);
        check(deferred(a, Missing::MissingBucket) && a.fetch == n.store.best_tip() && fv.ok() && fv.fork_pos() == fv.pos()
                      && n.tree.find(a.fetch) != nullptr && n.tree.find(a.fetch)->verified && a.strike == 0,
              "row 26: a bucket body not held -> DEFER + FC_GETBUCKETS at a bound carrier on the best chain (" + desc(a) + ")");
        (void)P;
    });
}

void smoke() {
    run_part("smoke", [] {
        KatNet net;
        KatNode n(net, pb::journal_j0(pb::kRuledLaneParams, pb::kSealDepth));
        pb::Hash32 prev = n.tree.genesis().id;
        bool ok = true;
        for (std::uint64_t pos = 1; pos <= 30 && ok; ++pos) {
            const pb::CarrierBodyV3 c = carrier_on(n, prev, h_pos(pos), {}, pos % 3, pos);
            const Admitted a = admit_place(n, c);
            ok = a.placed && a.w.outcome == pb::WriteOutcome::Extended;
            if (!ok) std::printf("  smoke pos %llu: %s\n", static_cast<unsigned long long>(pos), desc(a.r).c_str());
            prev = pb::receipt_id(c.own);
        }
        check(ok && n.store.best_tip() == prev && n.tree.best().id == prev && n.store.tip_pos() == 30,
              "smoke: 30 carriers admitted through the pipeline and placed on the best tip");
        // a carrier carrying three receipts on the tip
        std::vector<pb::ReceiptBodyV3> rs;
        for (std::uint64_t k = 0; k < 3; ++k) rs.push_back(body_on(n, prev, h_pos(31), 5 + k, 100 + k));
        const pb::CarrierBodyV3 c = carrier_on(n, prev, h_pos(31), rs, 1, 31);
        const Admitted a = admit_place(n, c);
        check(a.placed && a.r.placements.size() == 3, "smoke: a carrier with three carried receipts placed: " + desc(a.r));
    });
}

}  // namespace

int main(int argc, char** argv) {
    std::printf("v37_xmr_pathb_admit_kat\n");
    // an optional section name runs that section alone (the mutation driver's)
    const std::string only = argc > 1 ? argv[1] : "";
    const auto run = [&](const char* name, void (*f)()) {
        if (only.empty() || only == name) f();
    };
    run("smoke", smoke);
    run("rows_head", rows_head);
    run("rows_body", rows_body);
    run("section4", section4);
    run("nested_tip", nested_on_chain_tip);
    run("contract", contract);
    run("p49", p49);
    run("rows_more", rows_more);
    return finish("v37_xmr_pathb_admit_kat");
}
