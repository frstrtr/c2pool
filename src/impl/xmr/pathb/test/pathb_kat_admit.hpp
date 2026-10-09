// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/pathb_kat_admit.hpp
// Helpers for v37_xmr_pathb_admit_kat: a Monero chain and key references
// shared by the nodes (KatNet), one node (KatNode: tree, store, header index,
// bodies, caches, the env), carriers placed directly (scaffold) or built
// valid for the pipeline (a canonical coinbase on the tip's window).
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_admit.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_kat_lane.hpp"
#include "pathb_kat_miner.hpp"

namespace pathb_kat {

namespace pb = ::c2pool::xmr::pathb;

constexpr std::uint8_t kMonTag = 0x4d;
constexpr std::uint64_t kAnchorH = 3000000;            // the follower's anchor row
constexpr std::uint64_t kPoolH = kAnchorH + 100;       // the pool identity's Monero block H
constexpr std::uint64_t kLaneB0 = kPoolH + 1;          // b0 = H(0) = H + 1
constexpr std::uint64_t kMonTop = kAnchorH + 700;      // Monero rows held above the anchor
constexpr std::uint64_t kMonDiff = 1000000;
constexpr std::uint8_t kAltTag = 0x41;
constexpr std::uint64_t kAltFrom = kPoolH + 20;        // an alt branch of kAltLen blocks on main kAltFrom
constexpr std::uint64_t kAltLen = 100;
constexpr std::uint64_t kAltDiff = 1000000000000ull;
constexpr std::uint64_t kTs0 = 1600000000;
constexpr std::uint64_t kReward = 600000000000ull;

inline std::uint64_t mon_ts(std::uint64_t h) { return kTs0 + 120 * h; }
inline pb::Hash32 mon_block(std::uint64_t h) { return block_id(kMonTag, h); }
// One Monero height every 12 positions.
inline std::uint64_t h_pos(std::uint64_t pos) { return kLaneB0 + pos / 12; }

// The Monero chain, key references, the author and the pool identity.
struct KatNet {
    KatMoneroRows rows;
    RefBook book;
    std::vector<pb::XmrKeyRef> refs;
    std::vector<pb::Hash32> ids;
    pb::XmrKeyRef author;
    pb::Hash32 author_id{};
    pb::Hash32 pool_id{};
    pb::Hash32 rules_g{};

    KatNet() {
        const pb::RowWeights w = rw(kTailAgc, 300000, 300000);
        pb::Hash32 parent = rows.seed_anchor(kMonTag, kAnchorH, 800, kTs0, kMonDiff, w);
        for (std::uint64_t h = kAnchorH + 1; h <= kMonTop; ++h) parent = rows.add(kMonTag, h, parent, mon_ts(h), kMonDiff, w);
        pb::Hash32 alt = mon_block(kAltFrom);
        for (std::uint64_t h = kAltFrom + 1; h <= kAltFrom + kAltLen; ++h)
            alt = rows.add(kAltTag, h, alt, mon_ts(h) + 7, kAltDiff, w, false);
        for (std::uint64_t k = 0; k < 24; ++k) {
            refs.push_back(ref_from_secrets(7000 + k, 9000 + k));
            ids.push_back(book.add(refs.back()));
        }
        author = kat_author();
        author_id = pb::key_ref_identity(author);
        pool_id = seq32(0x5a);
        rules_g = seq32(0x6b);
    }
};

inline pb::EpochTable kat_table(const KatNet& net) {
    pb::EpochTable T;
    T.compiled.push_back(pb::CompiledEpoch{0, net.rules_g, std::nullopt});
    return T;
}

// A node: J = its journal depth (P-01).
struct KatNode {
    const KatNet* net;
    pb::LaneParams P = pb::kRuledLaneParams;
    pb::RatchetParams RP = pb::kRuledRatchetParams;
    pb::EpochTable T;
    pb::CarrierTree tree;
    pb::BinStore store;
    pb::ActivationRecord ar;
    pb::HeaderIndex headers;
    pb::CarrierBodies bodies;
    pb::FollowerBranchView mon;
    pb::WindowCache windows;
    pb::KeyCache keys;
    pb::AlarmSink alarm;
    pb::RelayBuffers buffers{};
    std::set<pb::Hash32> bad_pow;     // RandomX false for these receipt ids
    std::set<pb::Hash32> no_seed;     // P_r without a seed
    std::set<pb::Hash32> bad_ctx;     // P_r whose served context block fails its PoW
    std::set<pb::Hash32> pr_missing;  // P_r not held
    std::set<pb::Hash32> hf17;        // P_r whose child is at hf 17
    std::map<pb::Hash32, std::pair<std::uint64_t, std::uint64_t>> pr_z;  // P_r -> (Z, Z_lt) for the header inputs
    std::set<pb::Hash32> hidden_refs; // key references the node does not hold
    std::uint64_t rx_calls = 0;
    std::uint64_t pr_calls = 0;
    std::map<pb::Hash32, std::uint64_t> view_log;  // the store spy
    const pb::ClaimView* claims = nullptr;

    KatNode(const KatNet& n, std::uint64_t J, const pb::RatchetParams& rp = pb::kRuledRatchetParams,
            std::optional<pb::EpochTable> table = std::nullopt, std::vector<pb::RetargetEntry> inherited = {})
        : net(&n),
          RP(rp),
          T(table ? *table : kat_table(n)),
          tree(pb::kRuledLaneParams, n.pool_id, kLaneB0, T, inherited, rp, n.rules_g),
          store(pb::kRuledLaneParams, J, n.pool_id, kLaneB0),
          mon(n.rows) {
        buffers = pb::relay_buffers_default(16, 300000, P.r_max).value();
        spy();
    }
    // A copy starts with empty caches (the caches hold iterators into their own lists).
    KatNode(const KatNode& o)
        : net(o.net), P(o.P), RP(o.RP), T(o.T), tree(o.tree), store(o.store), ar(o.ar), headers(o.headers),
          bodies(o.bodies), mon(o.net->rows), buffers(o.buffers), bad_pow(o.bad_pow),
          no_seed(o.no_seed), bad_ctx(o.bad_ctx), pr_missing(o.pr_missing), hf17(o.hf17), pr_z(o.pr_z),
          hidden_refs(o.hidden_refs), claims(o.claims) {
        spy();
    }
    KatNode& operator=(const KatNode&) = delete;

    void spy() {
        store.set_view_spy([this](const pb::Hash32& id) { ++view_log[id]; });
    }
    std::uint64_t views_of(const pb::Hash32& id) const {
        const auto it = view_log.find(id);
        return it == view_log.end() ? 0 : it->second;
    }

    pb::AdmitEnv env() {
        return pb::AdmitEnv{
                tree,
                store,
                headers,
                bodies,
                mon,
                windows,
                keys,
                [this](const pb::Hash32& id) -> std::optional<pb::XmrKeyRef> {
                    if (hidden_refs.count(id) != 0) return std::nullopt;
                    const auto it = net->book.refs.find(id);
                    if (it == net->book.refs.end()) return std::nullopt;
                    return it->second;
                },
                net->author,
                P,
                RP,
                T,
                ar,
                net->pool_id,
                pb::admit_j0(P),
                buffers,
                mon_block(kPoolH),
                [this](const pb::Hash32& p_r) {
                    ++pr_calls;
                    pb::PrInfo out;
                    if (bad_ctx.count(p_r) != 0) {
                        out.status = pb::PrInfo::Status::BadServed;
                        return out;
                    }
                    const std::optional<pb::BranchBlock> b = pr_missing.count(p_r) ? std::nullopt : mon.block(p_r);
                    if (!b) return out;
                    out.status = pb::PrInfo::Status::Held;
                    out.height = b->height;
                    std::optional<std::uint64_t> m;
                    const pb::BranchStatus st = pb::timestamp_median_for_child(mon, p_r, m);
                    const auto z = pr_z.find(p_r);
                    out.in = pb::HeaderInputs{static_cast<std::uint8_t>(hf17.count(p_r) ? 17 : 16),
                                              st.selected() ? m : std::nullopt,
                                              z == pr_z.end() ? 300000 : z->second.first,
                                              z == pr_z.end() ? 300000 : z->second.second};
                    return out;
                },
                [this](const pb::Hash32& p_r) -> std::optional<pb::Hash32> {
                    if (no_seed.count(p_r) != 0) return std::nullopt;
                    return seq32(0x99);
                },
                [this](const pb::HashingBlob& blob, std::uint64_t, const pb::Hash32&) {
                    ++rx_calls;
                    return bad_pow.count(pb::receipt_id(blob)) == 0;
                },
                alarm,
                claims};
    }

    // P_t of a placed tip.
    pb::Hash32 prev_of(const pb::Hash32& tip) const {
        if (tip == tree.genesis().id) return mon_block(kPoolH);
        const pb::CarrierBodyV3* b = bodies.get(tip);
        return b ? b->own.blob.prev_id : pb::Hash32{};
    }

    pb::TipWindow window(const pb::Hash32& tip, std::uint8_t v = 16) {
        const pb::Hash32 pt = prev_of(tip);
        return windows.get(tip, v, [&] { return pb::evaluate_window_at(store, tip, pt, mon, v, net->author_id); });
    }

    const pb::CarrierNode& node(const pb::Hash32& id) const {
        static const pb::CarrierNode kNone{};
        const pb::CarrierNode* n = tree.find(id);
        return n ? *n : kNone;
    }
};

// h(r) of a body: height(P_r) + 1 on the net's chain.
inline std::uint64_t h_of(const KatNet& net, const pb::ReceiptBodyV3& r) {
    const std::optional<pb::BranchBlock> b = net.rows.block(r.blob.prev_id);
    return b ? b->height + 1 : 0;
}

// The canonical order of a carried list on `parent`.
inline void canonical_sort(const KatNet& net, std::vector<pb::ReceiptBodyV3>& carried, const pb::Hash32& parent) {
    std::sort(carried.begin(), carried.end(), [&](const pb::ReceiptBodyV3& a, const pb::ReceiptBodyV3& b) {
        const pb::CarriedKey ka{h_of(net, a), pb::receipt_id(a)}, kb{h_of(net, b), pb::receipt_id(b)};
        return pb::carried_key_less(ka, kb, parent);
    });
}

inline std::vector<pb::Hash32> ids_of(const std::vector<pb::ReceiptBodyV3>& rs) {
    std::vector<pb::Hash32> out;
    for (const pb::ReceiptBodyV3& r : rs) out.push_back(pb::receipt_id(r));
    return out;
}

using Tweak = std::function<void(pb::ReceiptBodyV3&)>;

// A receipt body on `tip` at h(r) = h_r: fields, then `pre`, then the roots of
// window(tip, v), then `post`, then the miner's own canonical coinbase.
inline pb::ReceiptBodyV3 body_on(KatNode& n, const pb::Hash32& tip, std::uint64_t h_r, std::size_t payee,
                                 std::uint64_t nonce, const Tweak& pre = {}, const Tweak& post = {},
                                 bool commit = true) {
    const KatNet& net = *n.net;
    pb::ReceiptBodyV3 r;
    r.blob.major = 16;
    r.blob.minor = 16;
    r.blob.timestamp = mon_ts(h_r - 1) + 1;
    r.blob.prev_id = mon_block(h_r - 1);
    r.blob.nonce = static_cast<std::uint32_t>(nonce);
    r.blob.tx_count = 1;
    for (int i = 0; i < 4; ++i) r.extra_nonce[i] = static_cast<std::uint8_t>(nonce >> (8 * i));
    r.payee = net.refs[payee];
    r.side.pool_id = net.pool_id;
    r.side.payee = net.ids[payee];
    r.side.t_origin = n.tree.next_difficulty(tip).value_or(0);
    r.side.tip = tip;
    r.side.give_author_bp = 10;
    r.reward_total = kReward;
    if (pre) pre(r);
    const pb::TipWindow tw = n.window(tip, r.blob.major == 17 ? 17 : 16);
    if (tw.ok()) {
        r.side.window_root = tw.window_root;
        r.side.mmr_root = tw.mmr_root;
    }
    if (post) post(r);
    if (commit && tw.ok()) commit_miner_tx(r, *tw.window, tip, r.blob.prev_id, h_r, net.book, net.author);
    return r;
}

// A carrier on `parent` at h carrying `carried` (sorted into the canonical order).
inline pb::CarrierBodyV3 carrier_on(KatNode& n, const pb::Hash32& parent, std::uint64_t h,
                                    std::vector<pb::ReceiptBodyV3> carried, std::size_t payee, std::uint64_t nonce,
                                    const Tweak& pre = {}, const Tweak& post = {}, bool sort = true) {
    if (sort) canonical_sort(*n.net, carried, parent);
    const std::vector<pb::Hash32> ids = ids_of(carried);
    pb::CarrierBodyV3 c;
    c.own = body_on(
            n, parent, h, payee, nonce,
            [&](pb::ReceiptBodyV3& r) {
                r.side.receipts_root = n.tree.next_receipts_root(parent, ids).value_or(pb::Hash32{});
                if (pre) pre(r);
            },
            post);
    c.carried = std::move(carried);
    return c;
}

inline std::vector<std::uint8_t> frame_of(const pb::CarrierBodyV3& c) {
    return pb::carrier_frame(c, pb::kRuledLaneParams.r_max).value_or(std::vector<std::uint8_t>{});
}

inline std::vector<std::uint8_t> bytes_of(const pb::ReceiptBodyV3& r) {
    std::vector<std::uint8_t> out;
    pb::encode_receipt_body_v3(r, out);
    return out;
}

// Admit a carrier frame and, when admitted, place it.
struct Admitted {
    pb::AdmitResult r;
    pb::WriteResult w;
    bool placed = false;
};

inline Admitted admit_place(KatNode& n, const pb::CarrierBodyV3& c, pb::CarrierRole role = pb::CarrierRole::Frame) {
    Admitted a;
    const std::vector<std::uint8_t> f = frame_of(c);
    a.r = pb::admit_carrier(n.env(), f, role);
    if (a.r.verdict == pb::AdmitVerdict::AdmitCarrier) {
        a.w = pb::place_admitted(n.tree, n.store, n.ar, n.bodies, a.r, &n.alarm);
        a.placed = a.w.outcome != pb::WriteOutcome::NodeInternal && a.w.outcome != pb::WriteOutcome::Duplicate;
    }
    return a;
}

// A carrier placed without the pipeline (scaffold): its body is built on the
// node's tree (t_origin, receipts_root over S at the parent), no coinbase.
inline pb::CarrierBodyV3 scaffold_body(const KatNode& n, const pb::Hash32& parent, std::uint64_t h, std::uint8_t tag,
                                       std::uint64_t k, std::size_t payee = 0,
                                       const std::vector<pb::ReceiptBodyV3>& carried = {}) {
    const KatNet& net = *n.net;
    pb::CarrierBodyV3 c;
    pb::ReceiptBodyV3& r = c.own;
    r.blob.major = 16;
    r.blob.minor = 16;
    r.blob.timestamp = mon_ts(h - 1) + 1;
    r.blob.prev_id = mon_block(h - 1);
    r.blob.nonce = static_cast<std::uint32_t>(k);
    r.blob.tree_root[0] = tag;
    for (int i = 0; i < 8; ++i) r.blob.tree_root[1 + i] = static_cast<std::uint8_t>(k >> (8 * i));
    r.blob.tx_count = 1;
    r.payee = net.refs[payee];
    r.side.pool_id = net.pool_id;
    r.side.payee = net.ids[payee];
    r.side.t_origin = n.tree.next_difficulty(parent).value_or(0);
    r.side.tip = parent;
    r.side.receipts_root = n.tree.next_receipts_root(parent, ids_of(carried)).value_or(pb::Hash32{});
    r.side.give_author_bp = 10;
    r.reward_total = kReward;
    c.carried = carried;
    return c;
}

// Places a scaffold carrier through place_admitted (no admission rows).
inline pb::WriteResult place_direct(KatNode& n, const pb::CarrierBodyV3& c) {
    pb::AdmitResult r;
    r.verdict = pb::AdmitVerdict::AdmitCarrier;
    const pb::Hash32 id = pb::receipt_id(c.own);
    const pb::Hash32& parent = c.own.side.tip;
    const pb::CarrierNode* pn = n.tree.find(parent);
    const std::uint64_t h = h_of(*n.net, c.own);
    r.id = id;
    r.announce = pb::CarrierAnnounce{id, parent, h, c.own.side.receipts_root, c.own.side.ballot};
    const pb::LaneView pv = n.store.view_at(parent);
    const std::uint64_t q = (pn ? pn->pos : 0) + 1;
    for (const pb::ReceiptBodyV3& b : c.carried) {
        const pb::Hash32 bid = pb::receipt_id(b);
        const pb::CarrierNode* t = n.tree.find(b.side.tip);
        const std::uint64_t p_own = (t ? t->pos : 0) + 1;
        const std::uint64_t hr = h_of(*n.net, b);
        const bool lv = pv.ok() && pb::live(hr, q, p_own, [&](std::uint64_t x) { return pv.record(x); });
        r.placements.push_back(pb::CarriedPlacement{bid, b.side.t_origin, b.side.ballot, lv});
        r.store_placements.push_back(pb::admit_detail::placement_of(b, bid, hr, p_own));
    }
    r.store_placements.push_back(pb::admit_detail::placement_of(c.own, id, h, q));
    r.carrier = c;
    return pb::place_admitted(n.tree, n.store, n.ar, n.bodies, r, &n.alarm);
}

// A scaffold chain of `count` carriers after `parent` at heights hof(pos), tag;
// returns the ids (position order).
template <class HOf>
inline std::vector<pb::Hash32> scaffold_chain(KatNode& n, const pb::Hash32& parent, std::uint64_t count, std::uint8_t tag,
                                              HOf&& hof, std::size_t payee = 0) {
    std::vector<pb::Hash32> out;
    pb::Hash32 p = parent;
    const std::uint64_t base = n.node(parent).pos;
    for (std::uint64_t i = 1; i <= count; ++i) {
        const pb::CarrierBodyV3 c = scaffold_body(n, p, hof(base + i), tag, base + i, payee);
        const pb::WriteResult w = place_direct(n, c);
        if (w.outcome == pb::WriteOutcome::NodeInternal || w.outcome == pb::WriteOutcome::Duplicate) {
            check(false, "scaffold: carrier not placed at " + std::to_string(base + i));
            break;
        }
        p = pb::receipt_id(c.own);
        out.push_back(p);
    }
    return out;
}

inline const char* verdict_name(pb::AdmitVerdict v) {
    switch (v) {
        case pb::AdmitVerdict::Strike: return "STRIKE";
        case pb::AdmitVerdict::Refuse: return "REFUSE";
        case pb::AdmitVerdict::Defer: return "DEFER";
        case pb::AdmitVerdict::Duplicate: return "DUPLICATE";
        case pb::AdmitVerdict::Ban: return "BAN";
        case pb::AdmitVerdict::AdmitCarrier: return "CARRIER";
        case pb::AdmitVerdict::AdmitPending: return "PENDING";
        case pb::AdmitVerdict::Drop: return "DROP";
    }
    return "?";
}

inline std::string desc(const pb::AdmitResult& r) {
    std::string s = verdict_name(r.verdict);
    s += " row " + std::to_string(static_cast<int>(r.row));
    if (r.missing) s += " missing " + std::to_string(static_cast<int>(*r.missing));
    s += " body " + std::to_string(r.body);
    return s;
}

}  // namespace pathb_kat
