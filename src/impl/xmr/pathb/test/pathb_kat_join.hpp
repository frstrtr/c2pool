// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/pathb_kat_join.hpp
// Helpers for v37_xmr_joiner_kat: a Monero chain long enough for joins
// (JoinNet), honest chains built by a full node A through the pipeline,
// servers over a node's chain (KatServer: the JoinLink of an attempt, with the
// serving floor of P-51 and hooks that forge replies), the joiner's inputs and
// the lane digest (a diagnostic: never on the wire).
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_join.hpp"
#include "pathb_kat_admit.hpp"

namespace pathb_kat {

namespace pb = ::c2pool::xmr::pathb;

// A KatNet whose main Monero rows reach kAnchorH + above.
struct JoinNet : KatNet {
    explicit JoinNet(std::uint64_t above) {
        const pb::RowWeights w = rw(kTailAgc, 300000, 300000);
        pb::Hash32 parent = mon_block(kMonTop);
        for (std::uint64_t h = kMonTop + 1; h <= kAnchorH + above; ++h)
            parent = rows.add(kMonTag, h, parent, mon_ts(h), kMonDiff, w);
    }
};

using HOf = std::function<std::uint64_t(std::uint64_t)>;

// The shape of an honest chain: carrier at position x at Monero height hof(x);
// every `carry_every`-th carrier carries one receipt of another payee on the
// same tip (its parent); payees cycle over `payees`.
struct ChainShape {
    HOf hof = h_pos;
    std::uint64_t carry_every = 3;
    std::size_t payees = 4;
    std::uint64_t nonce0 = 1;
    std::function<void(pb::ReceiptBodyV3&, std::uint64_t x)> tweak;  // on every body placed at x (before the roots)
    bool admit = false;  // A judges its own carriers through the pipeline (else placed directly: the bodies are canonical)
};

// Extends n's best chain by `count` carriers through the pipeline.
inline std::vector<pb::Hash32> grow(KatNode& n, std::uint64_t count, const ChainShape& s = {}) {
    std::vector<pb::Hash32> out;
    pb::Hash32 prev = n.tree.best().id;
    const std::uint64_t base = n.node(prev).pos;
    for (std::uint64_t i = 1; i <= count; ++i) {
        const std::uint64_t x = base + i;
        std::vector<pb::ReceiptBodyV3> carried;
        const Tweak tw = s.tweak ? Tweak([&](pb::ReceiptBodyV3& r) { s.tweak(r, x); }) : Tweak{};
        if (s.carry_every != 0 && x > 1 && x % s.carry_every == 0)
            carried.push_back(body_on(n, prev, s.hof(x), (x + 1) % s.payees, 900000000 + s.nonce0 + x, tw));
        const pb::CarrierBodyV3 c = carrier_on(n, prev, s.hof(x), carried, x % s.payees, s.nonce0 + x, tw);
        if (s.admit) {
            const Admitted a = admit_place(n, c);
            if (!a.placed) {
                check(false, "grow: carrier not placed at " + std::to_string(x) + ": " + desc(a.r));
                break;
            }
        } else if (place_direct(n, c).outcome != pb::WriteOutcome::Extended) {
            check(false, "grow: carrier not placed at " + std::to_string(x));
            break;
        }
        prev = pb::receipt_id(c.own);
        out.push_back(prev);
    }
    return out;
}

// The best chain's carrier at x.
inline pb::Hash32 at_pos(const KatNode& n, std::uint64_t x) { return n.store.best_at(x).value_or(pb::Hash32{}); }

// ---------------------------------------------------------------------------
// The joiner's environment: the follower over the net's rows and the node
// functors (as KatNode's env), shared by every attempt.
// ---------------------------------------------------------------------------
struct JoinerEnv {
    const KatNet* net;
    pb::FollowerBranchView mon;
    std::set<pb::Hash32> bad_pow;
    std::set<pb::Hash32> hidden;        // P_r the follower does not hold until fetched
    std::uint64_t ctx_fetches = 0;
    pb::JoinInputs in;

    explicit JoinerEnv(const KatNet& n, std::uint64_t journal = pb::admit_j0(pb::kRuledLaneParams))
        : net(&n), mon(n.rows) {
        in.T = kat_table(n);
        in.pool_id = n.pool_id;
        in.b0 = kLaneB0;
        in.genesis_prev = mon_block(kPoolH);
        in.rules_g = n.rules_g;
        in.journal_depth = journal;
        in.monero = &mon;
        in.author = n.author;
        in.buffers = pb::relay_buffers_default(16, 300000, in.p.r_max).value();
        in.headers_frame_bytes = pb::transport_ceiling(16, 300000).value_or(0);
        in.bucket_frame_bytes = in.headers_frame_bytes;
        in.resolve_pr = [this](const pb::Hash32& p_r) {
            pb::PrInfo out;
            if (hidden.count(p_r) != 0) return out;
            const std::optional<pb::BranchBlock> b = mon.block(p_r);
            if (!b) return out;
            out.status = pb::PrInfo::Status::Held;
            out.height = b->height;
            std::optional<std::uint64_t> m;
            const pb::BranchStatus st = pb::timestamp_median_for_child(mon, p_r, m);
            out.in = pb::HeaderInputs{16, st.selected() ? m : std::nullopt, 300000, 300000};
            return out;
        };
        in.seed_of = [](const pb::Hash32&) -> std::optional<pb::Hash32> { return seq32(0x99); };
        in.randomx = [this](const pb::HashingBlob& blob, std::uint64_t, const pb::Hash32&) {
            return bad_pow.count(pb::receipt_id(blob)) == 0;
        };
        in.fetch_context = [this](const pb::Hash32& id, std::uint64_t) {
            ++ctx_fetches;
            hidden.erase(id);
            return mon.block(id).has_value();
        };
    }
    JoinerEnv(const JoinerEnv&) = delete;
};

// ---------------------------------------------------------------------------
// KatServer: a node's chain as an attempt's server (the JoinLink).
// ---------------------------------------------------------------------------
struct StallError : std::runtime_error {
    StallError() : std::runtime_error("the joiner stalls at a withholding server") {}
};

struct KatServer final : pb::JoinLink {
    KatNode* n;
    std::uint64_t id;
    std::optional<std::uint64_t> top;   // serve as if the best tip were the carrier at this position
    // P-51 serving floors (off: serve everything held)
    bool retention = false;
    bool hold_floor = true;
    pb::JoinServeHold hold;
    std::uint64_t now = 0;              // the server's clock
    std::uint64_t step_s = 1;           // seconds per request
    std::uint64_t last_timeout = 0;
    // forging / withholding
    std::function<void(const pb::Hash32& stop, pb::ChainHeaders&)> on_headers;
    std::function<void(const std::vector<pb::Hash32>& ids, pb::CarrierFrames&)> on_bodies;
    std::function<void(const pb::GetBuckets&, pb::BucketFrames&)> on_buckets;
    std::function<void(KatServer&)> before;           // before each request
    std::function<bool(std::uint64_t pos)> carriers_withheld;  // no reply to a body request at such a position
    bool notserve_buckets = false;
    std::uint64_t requests = 0;
    std::uint64_t stall_after = 0;                    // throw StallError after this many requests (0: never)
    std::uint64_t header_requests = 0, body_requests = 0, bucket_requests = 0;

    KatServer(KatNode& node, std::uint64_t peer) : n(&node), id(peer) {}

    std::uint64_t peer() const override { return id; }

    pb::Hash32 best_id() const { return top ? at_pos(*n, *top) : n->store.best_tip(); }
    std::uint64_t best_pos() const { return n->node(best_id()).pos; }

    pb::JoinServeFloors floors_now() const {
        if (!retention) return pb::JoinServeFloors{0, 0};
        const pb::Hash32 b = best_id();
        const std::uint64_t L = n->node(b).pos;
        return pb::join_serve_floors(n->P, L, [&](std::uint64_t x) -> std::optional<std::uint64_t> {
            if (x > L) return std::nullopt;
            const std::optional<pb::Hash32> id = n->tree.ancestor_at(b, x);
            if (!id) return std::nullopt;
            return n->tree.find(*id)->H;
        });
    }

    void tick() {
        ++requests;
        now += step_s;
        if (stall_after != 0 && requests > stall_after) throw StallError();
        if (before) before(*this);
    }

    pb::ChainHeaders headers(const pb::Hash32& stop, std::uint64_t max, std::uint64_t timeout_s) override {
        tick();
        ++header_requests;
        last_timeout = timeout_s;
        pb::ChainHeaders out;
        const pb::Hash32 tip = stop == pb::Hash32{} ? best_id() : stop;
        const pb::CarrierNode* t = n->tree.find(tip);
        pb::JoinServeFloors f = floors_now();
        if (retention && hold_floor) {
            if (stop == pb::Hash32{})
                hold.first(1, now, best_pos(), f);
            else if (t != nullptr)
                f = hold.request(1, now, stop, t->pos, f, timeout_s);
        }
        if (t != nullptr && t->pos == 0 && stop == pb::Hash32{}) {  // a chain of position 0 only
            out.status = pb::LinkStatus::Served;
            return out;
        }
        if (t == nullptr || t->pos == 0 || t->pos < f.headers) {
            out.status = pb::LinkStatus::NotServed;
            return out;
        }
        std::vector<pb::Hash32> ids;
        for (const pb::CarrierNode* x = t; x != nullptr && x->pos >= 1 && x->pos >= f.headers && ids.size() < max;
             x = n->tree.find(x->parent))
            ids.push_back(x->id);
        std::reverse(ids.begin(), ids.end());
        out.status = pb::LinkStatus::Served;
        out.first_pos = t->pos + 1 - ids.size();
        for (const pb::Hash32& i : ids) out.headers.push_back(pb::header_of(*n->bodies.get(i)));
        if (on_headers) on_headers(stop, out);
        return out;
    }

    pb::CarrierFrames carriers(const std::vector<pb::Hash32>& ids, bool want_bodies, std::uint64_t timeout_s) override {
        tick();
        ++body_requests;
        last_timeout = timeout_s;
        pb::CarrierFrames out;
        pb::JoinServeFloors f = floors_now();
        if (retention && hold_floor && !ids.empty())
            if (const pb::CarrierNode* c = n->tree.find(ids.front())) f = hold.request(1, now, ids.front(), c->pos, f, timeout_s);
        out.status = pb::LinkStatus::Served;
        for (const pb::Hash32& i : ids) {
            const pb::CarrierNode* c = n->tree.find(i);
            if (c == nullptr || c->pos < f.bodies) continue;
            if (carriers_withheld && carriers_withheld(c->pos)) {
                out.status = pb::LinkStatus::NoReply;
                out.bodies.clear();
                return out;
            }
            if (std::optional<pb::CarrierBodyV3> b = pb::serve_carrier(n->tree, n->bodies, i, want_bodies))
                out.bodies.push_back(std::move(*b));
        }
        if (on_bodies) on_bodies(ids, out);
        return out;
    }

    pb::BucketFrames buckets(const pb::GetBuckets& q, std::uint64_t timeout_s) override {
        tick();
        ++bucket_requests;
        last_timeout = timeout_s;
        pb::BucketFrames out;
        if (notserve_buckets) {
            out.status = pb::LinkStatus::NotServed;
            return out;
        }
        const pb::CarrierNode* at = n->tree.find(q.at);
        std::optional<pb::RatchetStateBytes> s;
        if (at != nullptr)
            if (const pb::CarrierNode* p = n->tree.find(at->parent)) s = pb::encode_ratchet_state(p->rs);
        out.frames = pb::serve_buckets(n->store, q, s, n->P.r_max == 0 ? 0 : frame_bytes(), UINT64_MAX / 4);
        out.status = pb::LinkStatus::Served;
        if (on_buckets) on_buckets(q, out);
        return out;
    }

    static std::uint64_t frame_bytes() { return pb::transport_ceiling(16, 300000).value_or(0); }
};

// ---------------------------------------------------------------------------
// The lane digest (a diagnostic, never on the wire): sha256d over the mmr_root
// and leaf_count at t, window_root(t) at hf 16, the live open-bin placements
// at t in (bin, id) order, rs_root(S at t) and t.
// ---------------------------------------------------------------------------
inline pb::Hash32 lane_digest(const pb::CarrierTree& tree, const pb::BinStore& store, const pb::FollowerBranchView& mon,
                              const pb::Hash32& t, const pb::Hash32& p_t, const pb::Hash32& author_id) {
    std::vector<std::uint8_t> pre;
    const auto put = [&](const pb::Hash32& h) { pre.insert(pre.end(), h.begin(), h.end()); };
    const auto put64 = [&](std::uint64_t v) {
        for (int i = 0; i < 8; ++i) pre.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    };
    const pb::LaneView v = store.view_at(t);
    const pb::CarrierNode* n = tree.find(t);
    if (!v.ok() || n == nullptr) return pb::Hash32{};
    put(v.mmr_root());
    put64(v.leaf_count());
    const pb::TipWindow tw = pb::evaluate_window_at(store, t, p_t, mon, 16, author_id);
    put(tw.ok() ? tw.window_root : pb::Hash32{});
    const std::uint64_t H = v.record(v.pos());
    const std::uint64_t F = store.params().open_bins;
    std::vector<std::pair<std::uint64_t, pb::Hash32>> open;
    for (std::uint64_t b = std::max(store.b0(), H > F ? H - F + 1 : 0); b <= H + store.params().fresh_max; ++b)
        for (const pb::Placement* x : v.live_entries(b, v.pos())) open.emplace_back(b, x->id);
    std::sort(open.begin(), open.end());
    for (const auto& [b, id] : open) {
        put64(b);
        put(id);
    }
    put(pb::rs_root(n->rs));
    put(t);
    return ::v37::sha256d(pre);
}

inline pb::Hash32 digest_of(KatNode& a, const pb::Hash32& t) {
    return lane_digest(a.tree, a.store, a.mon, t, a.prev_of(t), a.net->author_id);
}
inline pb::Hash32 digest_of(const pb::JoinedState& j, const pb::Hash32& t) {
    return lane_digest(*j.tree, *j.store, *j.inputs().monero, t, j.prev_of(t).value_or(pb::Hash32{}),
                       pb::key_ref_identity(j.inputs().author));
}

// The joined node admits A's best-chain carriers (from, to] (every peer's copy, as a full node).
inline bool follow(pb::JoinedState& j, KatNode& a, std::uint64_t from, std::uint64_t to, std::uint64_t peer = 77) {
    for (std::uint64_t x = from + 1; x <= to; ++x) {
        const pb::CarrierBodyV3* b = a.bodies.get(at_pos(a, x));
        if (b == nullptr) return false;
        for (const pb::ReceiptBodyV3& r : b->carried) j.learn_refs(r);
        j.learn_refs(b->own);
        const std::vector<std::uint8_t> f = frame_of(*b);
        pb::AdmitEnv env = j.env();
        const pb::AdmitResult r = pb::admit_frame_from(env, peer, f, pb::CarrierRole::Frame);
        if (r.verdict != pb::AdmitVerdict::AdmitCarrier) {
            check(false, "follow: not admitted at " + std::to_string(x) + ": " + desc(r));
            return false;
        }
        const pb::WriteResult w = pb::place_admitted(*j.tree, *j.store, j.ar, j.bodies, r, &j.alarm);
        if (w.outcome != pb::WriteOutcome::Extended) {
            check(false, "follow: not extended at " + std::to_string(x));
            return false;
        }
    }
    return true;
}

inline const char* end_name(pb::AttemptEnd e) {
    switch (e) {
        case pb::AttemptEnd::Completed: return "Completed";
        case pb::AttemptEnd::Alarm: return "Alarm";
        case pb::AttemptEnd::NotServed: return "NotServed";
        case pb::AttemptEnd::Contradiction: return "Contradiction";
        case pb::AttemptEnd::Unplaceable: return "Unplaceable";
        case pb::AttemptEnd::OutOfScope: return "OutOfScope";
        case pb::AttemptEnd::Known: return "Known";
    }
    return "?";
}

inline std::string rep_desc(const pb::AttemptReport& r) {
    std::string s = end_name(r.end);
    s += " at " + std::to_string(r.at) + " row " + std::to_string(static_cast<int>(r.row));
    if (r.missing) s += " missing " + std::to_string(static_cast<int>(*r.missing));
    s += " strike " + std::to_string(r.strike) + " L " + std::to_string(r.L) + " x0 " + std::to_string(r.span.x0) +
         " x1 " + std::to_string(r.span.x1) + (r.span.young ? " young" : "") + ": " + r.what;
    return s;
}

}  // namespace pathb_kat
