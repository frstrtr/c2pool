// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_ring_c1_vectors.hpp
// The vectors of the K = 1 window golden (a SCAFFOLD golden: hf 16, v1's
// window function, a test tag):
//   (a) the inputs of the lane's window and coinbase KATs, as data
//       (xmr_window_kat, xmr_window_split_kat, xmr_window_spend_floor_kat,
//       xmr_window_merge_back_kat, v37_xmr_window_branch_kat,
//       v37_xmr_window_fork_height_kat, v37_xmr_pathb_coinbase_kat);
//   (b) the depth-0 corner vectors (lazy read, entries in the Fresh bins, V2, a
//       whole sealed bin) and the SealedCut vectors at depth 0;
//   (c) a seeded generator of K = 1 stores with generated payees.
// Every vector calls only window, window_from over ListedBins,
// select_window_bins, tip_window, evaluate_window_at, split, window_root and
// canonical_miner_tx. A Recorder turns each output into a byte record.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/pathb/pathb_bin_store.hpp"
#include "impl/xmr/pathb/pathb_branch.hpp"
#include "impl/xmr/pathb/pathb_branch_follower.hpp"
#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "impl/xmr/pathb/pathb_window_chain.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_branch_view.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_kat_lane.hpp"
#include "pathb_kat_miner.hpp"
#include "pathb_m2_blocks.hpp"

namespace ring_c1 {

namespace pb = ::c2pool::xmr::pathb;
using pathb_kat::Rng;

// ---------------------------------------------------------------------------
// The seeded generator's fixed inputs (set before its first run).
// ---------------------------------------------------------------------------
inline constexpr std::uint64_t kSeed = 0x52425F43315F4731ull;
inline constexpr std::size_t kListCases = 3000;
inline constexpr std::size_t kStoreCases = 60;
inline constexpr const char* kTestTag = "v37-ring-c1-test";

enum Regime : std::size_t {
    RgWmaxBound = 0,
    RgR12Cut,
    RgNDrop,
    RgNCut,
    RgOwnerMerge,
    RgAuthorMerge,
    RgEmpty,
    RgMissingBucket,
    RgMissingEntries,
    RgSealedCut,
    RgCount
};
inline constexpr const char* kRegimeName[RgCount] = {"wmax-bound",   "r12-first-bin-cut", "n-drop-bins",
                                                     "n-cut-first-bin", "owner-merge-back", "author-merge-back",
                                                     "empty-window", "missing-bucket", "missing-entries",
                                                     "sealed-cut"};
inline constexpr std::uint64_t kRegimeTarget[RgCount] = {150, 150, 150, 150, 150, 150, 100, 10, 10, 150};

// ---------------------------------------------------------------------------
// Byte records
// ---------------------------------------------------------------------------
struct Bytes {
    std::vector<std::uint8_t> b;
    void u8(std::uint8_t x) { b.push_back(x); }
    void u16(std::uint16_t x) { for (int i = 0; i < 2; ++i) b.push_back(static_cast<std::uint8_t>(x >> (8 * i))); }
    void u64(std::uint64_t x) { for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(x >> (8 * i))); }
    void h(const pb::Hash32& x) { b.insert(b.end(), x.begin(), x.end()); }
    void w(const pb::Work& x) {
        const auto l = pb::le256(x);
        b.insert(b.end(), l.begin(), l.end());
    }
    void raw(const std::vector<std::uint8_t>& x) {
        u64(x.size());
        b.insert(b.end(), x.begin(), x.end());
    }
};

// The canonical miner tx context of a window record: the receipt body, its
// reward and the payees' key references.
struct TxCtx {
    const pathb_kat::RefBook* book = nullptr;
    pb::XmrKeyRef author{};
    std::uint8_t body_seed = 0x20;
};

class Recorder {
public:
    struct Rec {
        std::string name;
        std::vector<std::uint8_t> bytes;
    };
    std::vector<Rec> recs;
    std::set<std::string> names;
    // hooks (the gate-off KAT reads the evaluations of every vector)
    std::function<void(const std::string&, const pb::WinEval&)> on_eval;
    std::function<void(const std::string&, const pb::TipWindow&)> on_tip;
    std::uint64_t regime[RgCount] = {};

    void add(const std::string& name, Bytes&& b) {
        std::string n = name;
        for (int k = 2; names.count(n) != 0; ++k) n = name + "#" + std::to_string(k);
        names.insert(n);
        recs.push_back(Rec{n, std::move(b.b)});
    }

    static void put_window(Bytes& o, const pb::Window& w, std::uint64_t R) {
        o.w(w.W);
        o.u64(w.weight.size());
        for (const auto& [id, wt] : w.weight) {
            o.h(id);
            o.w(wt);
        }
        o.u64(w.rows.size());
        for (const pb::BucketRow& r : w.rows) {
            const auto rb = pb::bucket_row_bytes(r);
            o.b.insert(o.b.end(), rb.begin(), rb.end());
        }
        o.u8(w.empty_finder_only ? 1 : 0);
        o.u8(w.merged_back ? 1 : 0);
        pb::Work sum;
        const pb::Hash32 wr = pb::window_root(w, &sum);
        o.h(wr);
        o.w(sum);
        const std::vector<pb::SplitOutput> s = pb::split(R, w);
        o.u64(R);
        o.u64(s.size());
        for (const pb::SplitOutput& x : s) {
            o.h(x.payee);
            o.u64(x.amount);
        }
    }

    static void put_tx(Bytes& o, const pb::CanonicalTx& c) {
        o.u8(static_cast<std::uint8_t>(c.stop));
        o.u8(c.tx ? 1 : 0);
        if (c.tx) {
            o.h(c.tx->tx_hash);
            o.u64(c.tx->outs.size());
            o.raw(c.tx->prefix);
        }
    }

    // canonical_miner_tx over a window evaluated for (tip, 16).
    static pb::CanonicalTx tx_of(const pb::Window* w, std::uint64_t R, const TxCtx& ctx, const pb::Hash32* tip_in,
                                 const pb::Hash32* wr, const pb::Hash32* mr) {
        pb::ReceiptBodyV3 r = pathb_kat::make_body(3, false, ctx.body_seed);
        r.reward_total = R;
        const pb::Hash32 tip = tip_in ? *tip_in : r.side.tip;
        r.side.tip = tip;
        pb::WindowAt at;
        at.window = w;
        at.tip = tip;
        at.v = 16;
        if (wr) at.window_root = *wr;
        if (mr) at.mmr_root = *mr;
        pb::KeyCache cache;
        static const pathb_kat::RefBook kEmpty;
        const pathb_kat::RefBook& book = ctx.book ? *ctx.book : kEmpty;
        return pb::canonical_miner_tx(r, at, tip, r.blob.prev_id, pathb_kat::kKatHeight, 16, cache, book.lookup(),
                                      ctx.author);
    }

    void eval(const std::string& name, const pb::WinEval& e, std::uint64_t R, const TxCtx* ctx = nullptr) {
        if (on_eval) on_eval(name, e);
        Bytes o;
        o.u8(0x01);
        o.u8(static_cast<std::uint8_t>(e.status));
        o.u64(e.missing_bin);
        o.u64(e.read);
        o.u64(e.oldest_bin);
        o.u8(e.n_dropped_bins ? 1 : 0);
        o.u8(e.n_cut_position ? 1 : 0);
        put_window(o, e.window, R);
        if (ctx && e.status == pb::WinStatus::Ok) put_tx(o, tx_of(&e.window, R, *ctx, nullptr, nullptr, nullptr));
        add(name, std::move(o));
    }

    void win(const std::string& name, const pb::Window& w, std::uint64_t R, const TxCtx* ctx = nullptr) {
        Bytes o;
        o.u8(0x02);
        put_window(o, w, R);
        if (ctx) put_tx(o, tx_of(&w, R, *ctx, nullptr, nullptr, nullptr));
        add(name, std::move(o));
    }

    void sel(const std::string& name, const std::vector<pb::WinBin>& bins) {
        Bytes o;
        o.u8(0x03);
        o.u64(bins.size());
        for (const pb::WinBin& b : bins) {
            o.u64(b.bin);
            o.u8(b.sealed ? 1 : 0);
            if (b.sealed) {
                o.w(b.sealed->raw_sum);
                o.u64(b.sealed->d_min);
                o.u64(b.sealed->rows.size());
            }
            o.u64(b.entries.size());
            for (const pb::WinEntry& x : b.entries) {
                o.h(x.miner);
                o.h(x.owner);
                o.u64(x.work);
                o.u16(x.p);
                o.u16(x.give_author_bp);
                o.u64(x.position);
                o.h(x.id);
            }
        }
        add(name, std::move(o));
    }

    static void put_tip(Bytes& o, const pb::TipWindow& t, std::uint64_t R) {
        o.u8(static_cast<std::uint8_t>(t.defer));
        o.h(t.tip);
        o.u8(t.v);
        o.h(t.missing_id);
        o.u64(t.missing_bin);
        o.u64(t.bins_read);
        o.u64(t.oldest_bin);
        o.u8(t.n_dropped_bins ? 1 : 0);
        o.u8(t.n_cut_position ? 1 : 0);
        o.u8(t.merged_back ? 1 : 0);
        o.u8(t.window ? 1 : 0);
        if (t.window) put_window(o, *t.window, R);
        o.h(t.window_root);
        o.w(t.sum);
        o.h(t.mmr_root);
    }

    void tip(const std::string& name, const pb::TipWindow& t, std::uint64_t R, const TxCtx* ctx = nullptr) {
        if (on_tip) on_tip(name, t);
        Bytes o;
        o.u8(0x04);
        put_tip(o, t, R);
        if (ctx && t.ok()) put_tx(o, tx_of(t.window.get(), R, *ctx, &t.tip, &t.window_root, &t.mmr_root));
        add(name, std::move(o));
    }

    void tx(const std::string& name, const pb::CanonicalTx& c) {
        Bytes o;
        o.u8(0x05);
        put_tx(o, c);
        add(name, std::move(o));
    }
};

// ---------------------------------------------------------------------------
// Shared helpers (as the KATs build their inputs)
// ---------------------------------------------------------------------------
inline pb::Hash32 rep(std::uint8_t b) {
    pb::Hash32 h{};
    h.fill(b);
    return h;
}
// identity with `i` in the last 8 bytes big-endian: memcmp order == numeric order.
inline pb::Hash32 id_of(std::uint64_t i) {
    pb::Hash32 h{};
    for (int b = 0; b < 8; ++b) h[31 - b] = static_cast<std::uint8_t>(i >> (8 * b));
    return h;
}
inline constexpr pb::DNet kHugeDnet = pb::DNet{1} << 100;
inline constexpr std::uint64_t kB = 600000000000ull;
inline std::uint64_t f16() { return pb::f_spend(kB, 300000, 16); }  // 12,530,000

inline pb::WindowParams wparams(pb::DNet d, std::uint64_t B, std::uint64_t f, std::uint64_t N,
                                const pb::Hash32& author = pb::Hash32{}) {
    pb::WindowParams wp;
    wp.d_net = d;
    wp.B = B;
    wp.f_spend = f;
    wp.N = N;
    wp.author = author;
    return wp;
}

// The three entry points over listed bins, recorded under one name.
inline void list3(Recorder& rec, const std::string& name, const std::vector<pb::WinBin>& bins, pb::DNet d,
                  std::uint64_t B, std::uint64_t f, std::uint64_t N, const pb::Hash32& author, std::uint64_t R,
                  const TxCtx* ctx = nullptr) {
    rec.eval(name + "/window_from", pb::window_from(pb::ListedBins{bins}, d, B, f, N, author), R, ctx);
    rec.win(name + "/window", pb::window(bins, d, B, f, N, author), R);
    rec.sel(name + "/select", pb::select_window_bins(bins, d, B, f));
}

// ===========================================================================
// (a) the lane's window and coinbase KATs, as data
// ===========================================================================

// ---- xmr_window_kat ----
inline pb::WinEntry wk_entry(std::uint8_t miner, std::uint64_t work, std::uint64_t pos) {
    pb::WinEntry e;
    e.miner = rep(miner);
    e.work = work;
    e.position = pos;
    e.id = rep(miner);
    return e;
}
inline pb::WinEntry wk_flagged(std::uint64_t miner, std::uint64_t pos) {
    pb::WinEntry e;
    e.miner = id_of(miner);
    e.work = 20000;
    e.position = pos;
    e.id = id_of(0x2000 + miner);
    return e;
}

inline void kat_xmr_window(Recorder& rec) {
    using namespace pathb_kat;
    const pb::Hash32 author{};
    const std::uint64_t B = kB, f1 = 1, N = 3747, R = kB + 5000000000ull;
    {   // the golden Merkle-SUM node (a window built by hand)
        pb::Window w;
        w.weight[rep(0xAA)] = pb::Work(119880);
        w.weight[rep(0xBB)] = pb::Work(89900);
        w.W = pb::Work(209780);
        rec.win("xmr_window_kat/golden-node", w, R);
    }
    {   // no decay
        std::vector<pb::WinBin> bins;
        bins.push_back({3, {wk_entry(0x01, 100, 30)}});
        bins.push_back({2, {wk_entry(0x02, 100, 20)}});
        bins.push_back({1, {wk_entry(0x03, 100, 10)}});
        list3(rec, "xmr_window_kat/no-decay", bins, 1000, B, f1, N, author, R);
    }
    {   // coverage
        std::vector<pb::WinBin> bins;
        for (int i = 0; i < 6; ++i)
            bins.push_back({static_cast<std::uint64_t>(6 - i), {wk_entry(static_cast<std::uint8_t>(0x40 + i), 100, 60 - i)}});
        list3(rec, "xmr_window_kat/coverage-75", bins, 75, B, f1, N, author, R);
    }
    {   // own tip
        std::vector<pb::WinBin> bins;
        for (int i = 0; i < 10; ++i)
            bins.push_back({static_cast<std::uint64_t>(10 - i), {wk_entry(static_cast<std::uint8_t>(0x50 + i), 100, 100 - i)}});
        list3(rec, "xmr_window_kat/own-tip-150", bins, 150, B, f1, N, author, R);
        list3(rec, "xmr_window_kat/own-tip-450", bins, 450, B, f1, N, author, R);
    }
    {   // empty
        std::vector<pb::WinBin> none;
        list3(rec, "xmr_window_kat/empty", none, 1000, B, f1, N, author, R);
    }
    {   // (i) the in-bin cut through the store
        const pb::LaneParams P = pb::kRuledLaneParams;
        constexpr std::uint64_t b0 = 3500000;
        pb::BinStore s(P, 64, idn(0xC0, 0), b0);
        for (std::uint64_t q = 1; q <= 14; ++q) {
            std::vector<pb::Placement> pls;
            if (q >= 10) pls.push_back(rcpt(idn(0xD0, q), b0, 19 - q, idn(0xE0, q), 20000));
            extend(s, idn(0xC0, q), idn(0xC0, q - 1), b0, pls, true);
        }
        rec.tip("xmr_window_kat/i-in-bin-cut", pb::tip_window(s, idn(0xC0, 14), wparams(kHugeDnet, kB, f16(), 3), 16), R);
    }
    {   // (ii) R-12
        std::vector<pb::WinBin> bins(1);
        bins[0].bin = 100;
        for (std::uint64_t i = 0; i < 300; ++i) {
            pb::WinEntry e;
            e.miner = id_of(i + 1);
            e.work = 4300000;
            e.position = 1000 - i;
            e.id = id_of(500000 + i);
            bins[0].entries.push_back(e);
        }
        pb::WinEntry small;
        small.miner = id_of(9999);
        small.work = 18180;
        small.position = 1;
        small.id = id_of(9999);
        bins[0].entries.push_back(small);
        list3(rec, "xmr_window_kat/ii-r12", bins, 1000000000ull, kB, f16(), 3747, pb::Hash32{}, R);
    }
    {   // (iii) R-13
        pb::WinEntry x;
        x.miner = id_of(0x0A);
        x.owner = id_of(0x0B);
        x.p = 10000;
        x.work = 20000;
        x.position = 21;
        x.id = id_of(0x100A);
        pb::WinEntry y;
        y.miner = id_of(0x0B);
        y.work = 20000;
        y.position = 20;
        y.id = id_of(0x100B);
        pb::WinEntry z;
        z.miner = id_of(0x0C);
        z.work = 20000;
        z.position = 10;
        z.id = id_of(0x100C);
        std::vector<pb::WinBin> bins{{2, {x, y}}, {1, {z}}};
        list3(rec, "xmr_window_kat/iii-n2", bins, kHugeDnet, kB, f16(), 2, pb::Hash32{}, R);
        pb::WinEntry a = y, b = y, c = z;
        a.miner = id_of(0x1A);
        a.give_author_bp = 10;
        a.position = 31;
        a.id = id_of(0x101A);
        b.miner = id_of(0x1B);
        b.position = 30;
        b.id = id_of(0x101B);
        c.miner = id_of(0x1C);
        c.id = id_of(0x101C);
        std::vector<pb::WinBin> donating{{2, {a, b}}, {1, {c}}};
        list3(rec, "xmr_window_kat/iii-n3-author", donating, kHugeDnet, kB, f16(), 3, id_of(0xAA), R);
    }
    {   // (iv) the (tip, v) window cache: the windows it evaluates
        const pb::LaneParams P = pb::kRuledLaneParams;
        constexpr std::uint64_t b0 = 1000;
        constexpr std::uint8_t kTag = 0x4d;
        const std::uint64_t n_pos = 1100;
        KatMoneroRows m = monero_chain(kTag, 1115, 1000000000ull, [](std::uint64_t) {
            return std::optional<pb::RowWeights>(rw(kTailAgc, 300000, 300000));
        });
        const pb::FollowerBranchView view(m);
        pb::BinStore s(P, 64, idn(0xC1, 0), b0);
        auto h_of = [&](std::uint64_t pos) { return b0 + pos / 10; };
        for (std::uint64_t pos = 1; pos <= n_pos; ++pos) {
            const std::uint64_t h = h_of(pos);
            std::vector<pb::Placement> pls{rcpt(idn(0xD1, pos), h, pos, idn(0xA1, pos), 20000),
                                           rcpt(idn(0xD2, pos), h, pos, idn(0xA2, pos), 20000)};
            extend(s, idn(0xC1, pos), idn(0xC1, pos - 1), h, pls, true);
        }
        auto p_t = [&](std::uint64_t pos) { return block_id(kTag, h_of(pos) - 1); };
        for (const std::uint64_t pos : {std::uint64_t{1100}, std::uint64_t{1090}, std::uint64_t{1080}, std::uint64_t{1000}})
            for (const std::uint8_t v : {std::uint8_t{16}, std::uint8_t{17}})
                rec.tip("xmr_window_kat/iv-eval-" + std::to_string(pos) + "-" + std::to_string(v),
                        pb::evaluate_window_at(s, idn(0xC1, pos), p_t(pos), view, v, author), R);
        KatMoneroRows m2 = m;
        const pb::Hash32 a_t = block_id(kTag, h_of(n_pos) - 1 - 60);
        m2.w.erase(a_t);
        const pb::FollowerBranchView view2(m2);
        rec.tip("xmr_window_kat/iv-defer-weights",
                pb::evaluate_window_at(s, idn(0xC1, n_pos), p_t(n_pos), view2, 16, author), R);
    }
    {   // (v) D_net u128
        std::vector<pb::WinBin> bins;
        for (std::uint64_t k = 0; k < 3; ++k)
            bins.push_back({3 - k, {wk_entry(static_cast<std::uint8_t>(0x30 + k), 100, 30 - k)}});
        list3(rec, "xmr_window_kat/v-dnet-2^64", bins, pb::DNet{1} << 64, kB, 1, 3747, pb::Hash32{}, R);
    }
    {   // winflags
        const std::uint64_t f = f16();
        {
            pb::WinEntry a = wk_flagged(0x1A, 31), b = wk_flagged(0x1B, 30), c = wk_flagged(0x1C, 10);
            a.give_author_bp = 10;
            const std::vector<pb::WinBin> bins{{2, {a, b}}, {1, {c}}};
            list3(rec, "xmr_window_kat/winflags-n-drop", bins, kHugeDnet, kB, f, 3, id_of(0xAA), R);
        }
        {
            std::vector<pb::WinEntry> es;
            for (std::uint64_t i = 0; i < 5; ++i) es.push_back(wk_flagged(0x30 + i, 50 - i));
            const std::vector<pb::WinBin> bins{{5, es}};
            list3(rec, "xmr_window_kat/winflags-n-cut", bins, kHugeDnet, kB, f, 3, pb::Hash32{}, R);
        }
        {
            pb::WinEntry x = wk_flagged(0x40, 20);
            x.owner = id_of(0x41);
            x.p = 1;
            x.give_author_bp = 10;
            pb::WinEntry heavy = wk_flagged(0x42, 19);
            heavy.work = 900000000;
            const std::vector<pb::WinBin> bins{{7, {x, heavy}}};
            list3(rec, "xmr_window_kat/winflags-merge", bins, kHugeDnet, kB, f, 3747, id_of(0xAA), R);
        }
        {
            const std::vector<pb::WinBin> bins{{9, {wk_flagged(0x50, 40)}}, {8, {wk_flagged(0x51, 39)}}};
            list3(rec, "xmr_window_kat/winflags-none", bins, kHugeDnet, kB, 1, 3747, pb::Hash32{}, R);
        }
    }
}

// ---- xmr_window_split_kat (split over hand-built windows) ----
inline pb::Window split_mk_window(std::uint64_t n, std::uint64_t base_w, std::uint64_t jitter) {
    pb::Window w;
    Rng rng(0x5157 + n);
    for (std::uint64_t i = 0; i < n; ++i) {
        const std::uint64_t wt = base_w + (jitter ? rng.below(jitter) : 0);
        w.weight[id_of(i + 1)] = pb::Work(wt);
        w.W += pb::Work(wt);
    }
    return w;
}

inline void kat_xmr_window_split(Recorder& rec) {
    const std::uint64_t R = 734123456789ull;
    for (std::uint64_t n : {std::uint64_t{1}, std::uint64_t{2}, std::uint64_t{3747}, std::uint64_t{10000}})
        rec.win("xmr_window_split_kat/sum-" + std::to_string(n), split_mk_window(n, 1000, 500), R);
    {
        pb::Window w;
        for (std::uint64_t i = 0; i < 3; ++i) w.weight[id_of(i + 1)] = pb::Work(1);
        w.W = pb::Work(3);
        rec.win("xmr_window_split_kat/tie-3", w, 10);
    }
    {
        pb::Window w;
        for (std::uint64_t i = 0; i < 3747; ++i) w.weight[id_of(i + 1)] = pb::Work(1);
        w.W = pb::Work(3747);
        rec.win("xmr_window_split_kat/tie-3747", w, 3747ull * 5 + 100);
    }
    {
        pb::Window w;
        w.weight[id_of(1)] = pb::Work(1);
        w.weight[id_of(2)] = pb::Work(2);
        w.W = pb::Work(3);
        rec.win("xmr_window_split_kat/unequal-1-2", w, 10);
    }
    {
        pb::Window w;
        w.weight[id_of(1)] = pb::Work(1);
        w.weight[id_of(2)] = pb::Work(1);
        w.weight[id_of(3)] = pb::Work(5);
        w.W = pb::Work(7);
        rec.win("xmr_window_split_kat/unequal-1-1-5", w, 100);
    }
    {
        Rng rng(0x4C52);
        for (int trial = 0; trial < 40; ++trial) {
            const std::uint64_t n = 2 + rng.below(600);
            const std::uint64_t Rt = 1 + rng.below(std::uint64_t{1} << 62);
            pb::Window w;
            unsigned __int128 W = 0;
            for (std::uint64_t i = 0; i < n; ++i) {
                const std::uint64_t wt = 1 + rng.below(std::uint64_t{1} << 40);
                w.weight[id_of(i + 1)] = pb::Work(wt);
                W += wt;
            }
            w.W = pb::Work(static_cast<std::uint64_t>(W));
            rec.win("xmr_window_split_kat/random-" + std::to_string(trial), w, Rt);
        }
    }
    {
        const pb::Window w = split_mk_window(50, 2000, 1000);
        rec.win("xmr_window_split_kat/fees-a", w, 100000000ull);
        rec.win("xmr_window_split_kat/fees-b", w, 120000000ull);
    }
    {
        const std::uint64_t B = 600000000000ull, f = 12530000ull, dmin = 20000;
        const std::uint64_t W = static_cast<std::uint64_t>(static_cast<unsigned __int128>(B) * dmin / f);
        pb::Window w;
        w.weight[id_of(1)] = pb::Work(dmin);
        w.weight[id_of(2)] = pb::Work(W - dmin);
        w.W = pb::Work(W);
        rec.win("xmr_window_split_kat/smallest-ge-f", w, B);
    }
}

// ---- xmr_window_spend_floor_kat ----
inline pb::WinEntry sf_e(std::uint8_t miner, std::uint64_t work, std::uint64_t pos) {
    pb::WinEntry x;
    x.miner = rep(miner);
    x.work = work;
    x.position = pos;
    x.id = rep(miner);
    return x;
}

inline void kat_xmr_window_spend_floor(Recorder& rec) {
    using namespace pathb_kat;
    const std::uint64_t B = kB;
    const std::uint64_t kHuge15 = 1000000000000000ull;
    const std::uint64_t f = f16();
    {   // F6
        std::vector<pb::WinBin> bins;
        std::uint64_t pos = 2000000;
        for (int k = 0; k < 1500; ++k) {
            pb::WinBin b;
            b.bin = 2000000 - k;
            for (int j = 0; j < 12; ++j) b.entries.push_back(sf_e(static_cast<std::uint8_t>(0x60 + j), 80000, pos--));
            bins.push_back(b);
        }
        for (int k = 0; k < 20; ++k) {
            pb::WinBin b;
            b.bin = 1000000 - k;
            for (int j = 0; j < 12; ++j) b.entries.push_back(sf_e(static_cast<std::uint8_t>(0x60 + j), 20000, pos--));
            bins.push_back(b);
        }
        list3(rec, "xmr_window_spend_floor_kat/f6", bins, kHuge15, B, f, 3747, pb::Hash32{}, B);
    }
    {   // 47,886 entries at one d
        const std::uint64_t n = 47886;
        std::vector<pb::WinBin> bins;
        bins.reserve(n);
        for (std::uint64_t k = 0; k < n; ++k) {
            pb::WinBin b;
            b.bin = 5000000 - k;
            pb::WinEntry x;
            x.miner = id_of(k + 1);
            x.work = 80000;
            x.position = 9000000 - k;
            x.id = x.miner;
            b.entries.push_back(x);
            bins.push_back(b);
        }
        list3(rec, "xmr_window_spend_floor_kat/47885", bins, kHuge15, B, f, pb::n_rule(3830978, 16, B), pb::Hash32{}, B);
    }
    {   // the cap stops at <=
        std::vector<pb::WinBin> eq{{11, {sf_e(0x51, 12530, 21)}}, {10, {sf_e(0x52, 599987470, 20)}}};
        std::vector<pb::WinBin> over{{11, {sf_e(0x51, 12530, 21)}}, {10, {sf_e(0x52, 599987471, 20)}}};
        list3(rec, "xmr_window_spend_floor_kat/cap-eq", eq, kHuge15, B, f, 3747, pb::Hash32{}, B);
        list3(rec, "xmr_window_spend_floor_kat/cap-over", over, kHuge15, B, f, 3747, pb::Hash32{}, B);
    }
    {   // d_min over receipt entries
        std::vector<pb::WinBin> bins;
        bins.push_back({3, {sf_e(0x70, 3000000, 30)}});
        bins.push_back({2, {sf_e(0x71, 3000000, 20)}});
        bins.push_back({1, {sf_e(0x72, 3000000, 10), sf_e(0x73, 100, 35)}});
        list3(rec, "xmr_window_spend_floor_kat/dmin-receipts", bins, kHuge15, B, f, 3747, pb::Hash32{}, B);
        std::vector<pb::WinBin> carriers_only = bins;
        carriers_only[2].entries.pop_back();
        list3(rec, "xmr_window_spend_floor_kat/dmin-carriers-only", carriers_only, kHuge15, B, f, 3747, pb::Hash32{}, B);
    }
    {   // build orders
        struct Pl {
            std::uint64_t origin_bin;
            std::uint8_t miner;
            std::uint64_t work;
            std::uint64_t carrier_pos;
            bool carried;
        };
        const std::vector<Pl> chain{
                {50, 1, 1000, 100, false}, {50, 2, 1100, 101, false}, {51, 3, 1200, 102, false},
                {50, 4, 900, 102, true},   {51, 1, 1000, 103, false}, {51, 5, 950, 103, true},
                {52, 2, 1300, 104, false}, {50, 6, 800, 104, true},   {51, 7, 850, 104, true},
                {52, 8, 700, 105, false},  {52, 9, 600, 105, true},   {52, 10, 650, 105, true},
        };
        auto build = [](const std::vector<Pl>& ps) {
            std::map<std::uint64_t, pb::WinBin> by;
            for (const Pl& p : ps) {
                pb::WinEntry x;
                x.miner = rep(p.miner);
                x.work = p.work;
                x.position = p.carrier_pos;
                x.id = id_of(1000 * p.carrier_pos + p.miner);
                by[p.origin_bin].bin = p.origin_bin;
                by[p.origin_bin].entries.push_back(x);
            }
            std::vector<pb::WinBin> out;
            for (auto it = by.rbegin(); it != by.rend(); ++it) out.push_back(it->second);
            return out;
        };
        std::vector<Pl> carried_first;
        for (const Pl& p : chain)
            if (p.carried) carried_first.push_back(p);
        for (const Pl& p : chain)
            if (!p.carried) carried_first.push_back(p);
        const std::vector<Pl> reverse(chain.rbegin(), chain.rend());
        const auto a = build(chain), b = build(carried_first), c = build(reverse);
        const std::uint64_t R = B + 3000000000ull;
        for (const std::uint64_t N : {std::uint64_t{3747}, std::uint64_t{3}}) {
            const std::string t = "-N" + std::to_string(N);
            list3(rec, "xmr_window_spend_floor_kat/orders-a" + t, a, kHuge15, B, f, N, pb::Hash32{}, R);
            list3(rec, "xmr_window_spend_floor_kat/orders-b" + t, b, kHuge15, B, f, N, pb::Hash32{}, R);
            list3(rec, "xmr_window_spend_floor_kat/orders-c" + t, c, kHuge15, B, f, N, pb::Hash32{}, R);
        }
    }
    const std::uint64_t R = B + 5000000000ull;
    {   // build orders through the store
        const pb::LaneParams P = pb::kRuledLaneParams;
        constexpr std::uint64_t b0 = 5000;
        struct C {
            std::uint64_t pos, h;
            std::vector<pb::Placement> own, carried;
        };
        const std::vector<C> chain{
                {1, b0, {rcpt(idn(0xD5, 1), b0, 1, idn(0xA5, 1), 30000)}, {}},
                {2, b0, {rcpt(idn(0xD5, 2), b0, 2, idn(0xA5, 2), 31000)}, {}},
                {3, b0, {rcpt(idn(0xD5, 3), b0, 3, idn(0xA5, 3), 32000)}, {}},
                {4, b0 + 1, {rcpt(idn(0xD5, 4), b0 + 1, 4, idn(0xA5, 4), 33000)},
                 {rcpt(idn(0xD6, 5), b0, 3, idn(0xA5, 5), 34000), rcpt(idn(0xD6, 6), b0 + 1, 3, idn(0xA5, 6), 35000)}},
                {5, b0 + 1, {rcpt(idn(0xD5, 7), b0 + 1, 5, idn(0xA5, 7), 36000)},
                 {rcpt(idn(0xD6, 8), b0 + 1, 4, idn(0xA5, 8), 37000), rcpt(idn(0xD6, 9), b0 + 1, 4, idn(0xA5, 9), 38000)}},
        };
        for (int order = 0; order < 3; ++order) {
            pb::BinStore s(P, 64, idn(0xC5, 0), b0);
            for (const C& c : chain) {
                std::vector<pb::Placement> pls;
                std::vector<pb::Placement> carried = c.carried;
                if (order == 2) std::reverse(carried.begin(), carried.end());
                if (order == 1) pls.insert(pls.end(), c.own.begin(), c.own.end());
                pls.insert(pls.end(), carried.begin(), carried.end());
                if (order != 1) pls.insert(pls.end(), c.own.begin(), c.own.end());
                extend(s, idn(0xC5, c.pos), idn(0xC5, c.pos - 1), c.h, pls, true);
            }
            for (const std::uint64_t N : {std::uint64_t{3747}, std::uint64_t{6}, std::uint64_t{2}})
                rec.tip("xmr_window_spend_floor_kat/store-order" + std::to_string(order) + "-N" + std::to_string(N),
                        pb::tip_window(s, idn(0xC5, 5), wparams(pb::DNet{1} << 100, kB, f16(), N), 16), R);
        }
    }
    {   // d_min over LIVE receipt entries through the store
        const pb::LaneParams P = pb::kRuledLaneParams;
        constexpr std::uint64_t b0 = 6000;
        pb::BinStore s(P, 64, idn(0xC6, 0), b0);
        for (std::uint64_t pos = 1; pos <= 6; ++pos) {
            const std::uint64_t h = pos <= 3 ? b0 : b0 + 5;
            std::vector<pb::Placement> pls{rcpt(idn(0xD7, pos), h, pos, idn(0xA7, pos), 3000000)};
            if (pos == 6) pls.insert(pls.begin(), rcpt(idn(0xD8, 6), b0 + 1, 6, idn(0xA8, 6), 100));
            extend(s, idn(0xC6, pos), idn(0xC6, pos - 1), h, pls, true);
        }
        rec.tip("xmr_window_spend_floor_kat/store-dead-dmin",
                pb::tip_window(s, idn(0xC6, 6), wparams(pb::DNet{1} << 100, kB, f16(), 3747), 16), R);
    }
    {   // M(A_t) doubles; P-38 / P-37 retention
        const pb::LaneParams P = pb::kRuledLaneParams;
        constexpr std::uint64_t b0 = 1000;
        constexpr std::uint8_t kTag = 0x4d;
        constexpr std::uint64_t kJ = 64;
        constexpr std::uint64_t kSmallPos = 180;
        constexpr std::uint64_t kL = 20000000;
        const std::uint64_t t2 = 300;
        KatMoneroRows m = monero_chain(kTag, 1305, 2000000000ull, [](std::uint64_t h) {
            return std::optional<pb::RowWeights>(h == 1239 ? rw(kTailAgc, 600000, 600000) : rw(kTailAgc, 300000, 300000));
        });
        const pb::FollowerBranchView view(m);
        pb::BinStore full(P, kJ, idn(0xC7, 0), b0), pruned(P, kJ, idn(0xC7, 0), b0), ent(P, kJ, idn(0xC7, 0), b0);
        for (std::uint64_t pos = 1; pos <= t2; ++pos) {
            const std::vector<pb::Placement> pls{
                    rcpt(idn(0xD9, pos), b0 + pos, pos, idn(0xA9, pos % 8), pos == kSmallPos ? 18180 : kL)};
            for (pb::BinStore* st : {&full, &pruned, &ent})
                extend(*st, idn(0xC7, pos), idn(0xC7, pos - 1), b0 + pos, pls, true);
        }
        const pb::Hash32 author{};
        auto eval = [&](const pb::BinStore& st, std::uint64_t pos) {
            return pb::evaluate_window_at(st, idn(0xC7, pos), block_id(kTag, b0 + pos - 1), view, 16, author);
        };
        std::uint64_t min_read = std::numeric_limits<std::uint64_t>::max();
        for (std::uint64_t pos = t2 - kJ; pos <= t2; ++pos) {
            const pb::TipWindow w = eval(full, pos);
            if (pos < t2 && w.ok()) min_read = std::min(min_read, b0 + pos + P.fresh_max + 1 - w.bins_read);
            rec.tip("xmr_window_spend_floor_kat/m-doubles-full-" + std::to_string(pos), w, R);
        }
        pruned.prune_buckets(min_read);
        for (std::uint64_t pos = t2 - kJ; pos < t2; ++pos)
            rec.tip("xmr_window_spend_floor_kat/m-doubles-pruned-" + std::to_string(pos), eval(pruned, pos), R);
        pb::TipWindow w2p = eval(pruned, t2);
        for (std::uint64_t k = 0; k < 1000; ++k) {
            rec.tip("xmr_window_spend_floor_kat/m-doubles-fetch-" + std::to_string(k), w2p, R);
            if (w2p.ok() || w2p.defer != pb::WindowDefer::MissingBucket) break;
            const pb::SealedBin* sb = full.view_at(full.best_tip()).bucket(w2p.missing_bin);
            if (sb == nullptr) break;
            pruned.restore_bucket(sb->bucket, sb->refs);
            w2p = eval(pruned, t2);
        }
        ent.prune_entries(std::numeric_limits<std::uint64_t>::max());
        for (std::uint64_t pos = t2 - kJ; pos <= t2; ++pos)
            rec.tip("xmr_window_spend_floor_kat/m-doubles-ent-" + std::to_string(pos), eval(ent, pos), R);
        rec.tip("xmr_window_spend_floor_kat/m-doubles-full-150", eval(full, 150), R);
        rec.tip("xmr_window_spend_floor_kat/m-doubles-ent-150", eval(ent, 150), R);
    }
}

// ---- xmr_window_merge_back_kat ----
inline pb::WinEntry mb_mk(std::uint8_t miner, std::uint8_t owner, std::uint64_t work, std::uint16_t p, std::uint64_t pos) {
    pb::WinEntry x;
    x.miner = rep(miner);
    if (owner) x.owner = rep(owner);
    x.work = work;
    x.p = p;
    x.position = pos;
    x.id = rep(miner);
    return x;
}

inline void mb_same_window_sealed(Recorder& rec, const std::string& name, const std::vector<pb::WinEntry>& E,
                                  std::uint64_t B, std::uint64_t f, std::uint64_t N, const pb::Hash32& author) {
    std::vector<pb::WinBin> one(1);
    one[0].bin = 4;
    one[0].entries = E;
    std::vector<pb::WinBin> open(4);
    for (std::size_t k = 0; k < 4; ++k) open[k].bin = 4 - k;
    for (std::size_t i = 0; i < E.size(); ++i) open[i % 4].entries.push_back(E[i]);
    std::vector<pb::L1Bucket> buckets(4);
    for (std::size_t k = 0; k < 4; ++k) buckets[k] = pb::seal_from_entries(open[k].bin, open[k].entries);
    std::vector<pb::WinBin> sealed(4), mixed(4);
    for (std::size_t k = 0; k < 4; ++k) {
        sealed[k].bin = open[k].bin;
        sealed[k].sealed = &buckets[k];
        mixed[k] = k == 0 ? open[k] : sealed[k];
    }
    const std::uint64_t R = B + 5000000000ull;
    list3(rec, "xmr_window_merge_back_kat/sealed-" + name + "/one", one, kHugeDnet, B, f, N, author, R);
    list3(rec, "xmr_window_merge_back_kat/sealed-" + name + "/open", open, kHugeDnet, B, f, N, author, R);
    list3(rec, "xmr_window_merge_back_kat/sealed-" + name + "/sealed", sealed, kHugeDnet, B, f, N, author, R);
    list3(rec, "xmr_window_merge_back_kat/sealed-" + name + "/mixed", mixed, kHugeDnet, B, f, N, author, R);
}

inline void kat_xmr_window_merge_back(Recorder& rec) {
    const pb::Hash32 author{};
    const std::uint64_t B = kB, f = f16(), N = 3747, R = kB + 5000000000ull;
    auto one_bin = [&](const std::string& name, const pb::WinBin& bin, std::uint64_t Bx, const pb::Hash32& au) {
        list3(rec, "xmr_window_merge_back_kat/" + name, std::vector<pb::WinBin>{bin}, 1, Bx, f, N, au, R);
    };
    {
        pb::WinBin bin;
        bin.bin = 1;
        bin.entries.push_back(mb_mk(0x01, 0x00, 1000000000ull, 0, 100));
        for (int i = 0; i < 100; ++i) bin.entries.push_back(mb_mk(0x02, 0x0C, 200000, 10, 99 - i));
        one_bin("owner-below", bin, B, author);
    }
    {
        pb::WinBin bin;
        bin.bin = 1;
        bin.entries.push_back(mb_mk(0x01, 0x00, 1000000000ull, 0, 100));
        for (int i = 0; i < 100; ++i) bin.entries.push_back(mb_mk(0x02, 0x0C, 200000, 100, 99 - i));
        one_bin("owner-above", bin, B, author);
        one_bin("owner-small-B", bin, 1000000ull, author);
    }
    {
        pb::WinBin bin;
        bin.bin = 1;
        bin.entries.push_back(mb_mk(0x01, 0x00, 1000000000ull, 0, 100));
        bin.entries.push_back(mb_mk(0x0C, 0x00, 500000, 0, 95));
        for (int i = 0; i < 100; ++i) bin.entries.push_back(mb_mk(0x02, 0x0C, 200000, 10, 90 - i));
        one_bin("owner-raw-entry", bin, B, author);
    }
    {
        pb::WinBin bin;
        bin.bin = 1;
        bin.entries.push_back(mb_mk(0x01, 0x00, 1000000000ull, 0, 100));
        bin.entries.push_back(mb_mk(0x0D, 0x00, 500000, 0, 95));
        for (int i = 0; i < 100; ++i) bin.entries.push_back(mb_mk(0x02, 0x0C, 200000, 10, 90 - i));
        one_bin("pure-owner", bin, B, author);
    }
    {
        const pb::Hash32 au = rep(0xEE);
        for (const bool author_mines : {true, false}) {
            pb::WinBin bin;
            bin.bin = 1;
            bin.entries.push_back(mb_mk(0x01, 0x00, 1000000000ull, 0, 100));
            bin.entries.push_back(mb_mk(author_mines ? 0xEE : 0x0D, 0x00, 500000, 0, 95));
            for (int i = 0; i < 100; ++i) {
                pb::WinEntry x = mb_mk(0x02, 0x00, 200000, 0, 90 - i);
                x.give_author_bp = 10;
                bin.entries.push_back(x);
            }
            one_bin(author_mines ? "author-mines" : "author-pure", bin, B, au);
        }
    }
    {
        const pb::Hash32 au = rep(0xEE);
        for (const auto& [big, each] : {std::pair<std::uint64_t, std::uint64_t>{990000000ull, 100000},
                                        std::pair<std::uint64_t, std::uint64_t>{979000000ull, 210000}}) {
            pb::WinBin bin;
            bin.bin = 1;
            bin.entries.push_back(mb_mk(0x01, 0x00, big, 0, 100));
            for (int i = 0; i < 100; ++i) {
                pb::WinEntry x = mb_mk(0x02, 0x00, each, 0, 99 - i);
                x.give_author_bp = 10;
                bin.entries.push_back(x);
            }
            one_bin("fleet-" + std::to_string(each), bin, B, au);
        }
    }
    for (const bool x_first : {true, false}) {
        const std::uint8_t X = x_first ? 0x0A : 0x0B, Y = x_first ? 0x0B : 0x0A, Z = 0x0C;
        pb::WinBin bin;
        bin.bin = 1;
        bin.entries.push_back(mb_mk(0x01, 0x00, 1000000000ull, 0, 100));
        bin.entries.push_back(mb_mk(Y, X, 30000, 5000, 99));
        bin.entries.push_back(mb_mk(Z, Y, 1000000, 1, 98));
        one_bin(x_first ? "lift-x-first" : "lift-y-first", bin, B, author);
    }
    {
        pb::WinBin a;
        a.bin = 1;
        a.entries = {mb_mk(0x01, 0x00, 300000, 0, 10), mb_mk(0x02, 0x0C, 400000, 50, 9), mb_mk(0x03, 0x0D, 500000, 200, 8)};
        pb::WinBin b = a;
        std::reverse(b.entries.begin(), b.entries.end());
        one_bin("order-a", a, B, author);
        one_bin("order-b", b, B, author);
    }
    {
        std::vector<pb::WinEntry> e;
        e.push_back(mb_mk(0x01, 0x00, 1000000000ull, 0, 100));
        for (int i = 0; i < 100; ++i) e.push_back(mb_mk(0x02, 0x0C, 200000, 10, 99 - i));
        mb_same_window_sealed(rec, "owner-10bp", e, B, f, N, author);
        for (pb::WinEntry& x : e)
            if (x.p == 10) x.p = 100;
        mb_same_window_sealed(rec, "owner-100bp", e, B, f, N, author);
    }
    {
        std::vector<pb::WinEntry> e;
        e.push_back(mb_mk(0x01, 0x00, 1000000000ull, 0, 100));
        for (int i = 0; i < 100; ++i) e.push_back(mb_mk(0x02, 0x0C, 200000, 1, 99 - i));
        mb_same_window_sealed(rec, "owner-1bp", e, B, f, N, author);
    }
    {
        std::vector<pb::WinEntry> e;
        e.push_back(mb_mk(0x01, 0x00, 1000000000ull, 0, 100));
        e.push_back(mb_mk(0x0C, 0x00, 500000, 0, 95));
        for (int i = 0; i < 100; ++i) e.push_back(mb_mk(0x02, 0x0C, 200000, 10, 90 - i));
        mb_same_window_sealed(rec, "owner-raw", e, B, f, N, author);
        e[1].miner = rep(0x0D);
        mb_same_window_sealed(rec, "owner-pure", e, B, f, N, author);
    }
    for (const bool author_mines : {true, false}) {
        const pb::Hash32 au = rep(0xEE);
        std::vector<pb::WinEntry> e;
        e.push_back(mb_mk(0x01, 0x00, 1000000000ull, 0, 100));
        e.push_back(mb_mk(author_mines ? 0xEE : 0x0D, 0x00, 500000, 0, 95));
        for (int i = 0; i < 100; ++i) {
            pb::WinEntry x = mb_mk(0x02, 0x00, 200000, 0, 90 - i);
            x.give_author_bp = 10;
            e.push_back(x);
        }
        mb_same_window_sealed(rec, author_mines ? "author-raw" : "author-pure", e, B, f, N, au);
    }
    for (const std::uint64_t each : {std::uint64_t{100000}, std::uint64_t{210000}}) {
        const pb::Hash32 au = rep(0xEE);
        std::vector<pb::WinEntry> e;
        e.push_back(mb_mk(0x01, 0x00, 1000000000ull - 100 * each, 0, 100));
        for (int i = 0; i < 100; ++i) {
            pb::WinEntry x = mb_mk(0x02, 0x00, each, 0, 99 - i);
            x.give_author_bp = 10;
            e.push_back(x);
        }
        mb_same_window_sealed(rec, "fleet-" + std::to_string(each), e, B, f, N, au);
    }
    for (const bool x_first : {true, false}) {
        const std::uint8_t X = x_first ? 0x0A : 0x0B, Y = x_first ? 0x0B : 0x0A, Z = 0x0C;
        std::vector<pb::WinEntry> e{mb_mk(0x01, 0x00, 1000000000ull, 0, 100), mb_mk(Y, X, 30000, 5000, 99),
                                    mb_mk(Z, Y, 1000000, 1, 98)};
        mb_same_window_sealed(rec, x_first ? "lift-x" : "lift-y", e, B, f, N, author);
    }
    {
        pb::WinEntry c = mb_mk(0xC1, 0x0F, 300000, 100, 20);
        const std::vector<pb::WinEntry> b3{mb_mk(0xA1, 0x00, 300000, 0, 31), mb_mk(0xB1, 0x00, 300000, 0, 30)};
        const std::vector<pb::WinEntry> b2{c};
        const std::vector<pb::WinEntry> b1{mb_mk(0xD1, 0x00, 300000, 0, 10)};
        const pb::L1Bucket s2 = pb::seal_from_entries(2, b2), s1 = pb::seal_from_entries(1, b1);
        std::vector<pb::WinBin> sealed(3);
        sealed[0].bin = 3;
        sealed[0].entries = b3;
        sealed[1].bin = 2;
        sealed[1].sealed = &s2;
        sealed[2].bin = 1;
        sealed[2].sealed = &s1;
        const std::vector<pb::WinBin> open{{3, b3}, {2, b2}, {1, b1}};
        list3(rec, "xmr_window_merge_back_kat/n-c-minus-1-sealed", sealed, kHugeDnet, B, f, 4, author, R);
        list3(rec, "xmr_window_merge_back_kat/n-c-minus-1-open", open, kHugeDnet, B, f, 4, author, R);
    }
}

// ---- v37_xmr_window_branch_kat ----
inline pathb_kat::KatBranchView branch_main_chain(std::uint64_t top) {
    pathb_kat::KatBranchView v;
    pb::Hash32 parent{};
    for (std::uint64_t h = 0; h <= top; ++h)
        parent = v.add(0x4d, h, parent, 1600000000ull + 120 * h, 1000 + h, h * 10000000000000ull, 300000, 300000);
    return v;
}

inline void kat_v37_xmr_window_branch(Recorder& rec) {
    using namespace pathb_kat;
    {   // s3b_race
        constexpr std::uint8_t kC = 0x4d, kA = 0x41, kBt = 0x42;
        constexpr std::uint64_t hr = 140;
        auto ts = [](std::uint64_t h) { return 1600000000ull + 120 * h; };
        const pb::RowWeights tail = rw(kTailAgc, 300000, 300000);
        KatMoneroRows x = monero_chain(kC, hr - 1, 10000000ull, [&](std::uint64_t) { return std::optional<pb::RowWeights>(tail); });
        KatMoneroRows y = x;
        const pb::Hash32 c = block_id(kC, hr - 1);
        const pb::Hash32 a1 = x.add(kA, hr, c, ts(hr) + 5, 1000000000ull, tail, true);
        const pb::Hash32 a2 = x.add(kA, hr + 1, a1, ts(hr + 1) + 5, 1000000000ull, tail, true);
        const pb::Hash32 b1 = x.add(kBt, hr, c, ts(hr) + 9, 500000000ull, std::nullopt, false);
        const pb::Hash32 b2 = x.add(kBt, hr + 1, b1, ts(hr + 1) + 9, 500000000ull, std::nullopt, false);
        y.add(kBt, hr, c, ts(hr) + 9, 500000000ull, tail, true);
        y.add(kBt, hr + 1, b1, ts(hr + 1) + 9, 500000000ull, tail, true);
        y.add(kA, hr, c, ts(hr) + 5, 1000000000ull, std::nullopt, false);
        y.add(kA, hr + 1, a1, ts(hr + 1) + 5, 1000000000ull, std::nullopt, false);
        const pb::FollowerBranchView vx(x), vy(y);
        RefBook book;
        std::vector<pb::Hash32> payees;
        for (std::uint64_t k = 0; k < 8; ++k) payees.push_back(book.add(ref_from_secrets(1000 + k, 2000 + k)));
        constexpr std::uint64_t b0 = 100;
        pb::BinStore sx(pb::kRuledLaneParams, 64, idn(0xC8, 0), b0), sy(pb::kRuledLaneParams, 64, idn(0xC8, 0), b0);
        for (pb::BinStore* st : {&sx, &sy}) {
            for (std::uint64_t pos = 1; pos <= 40; ++pos)
                extend(*st, idn(0xC8, pos), idn(0xC8, pos - 1), b0 + pos,
                       {rcpt(idn(0xD8, pos), b0 + pos, pos, payees[pos % 8], 1000000)}, true);
            extend(*st, idn(0xCA, 41), idn(0xC8, 40), hr + 2, {rcpt(idn(0xDA, 41), hr + 2, 41, payees[1], 1000000)}, true);
            extend(*st, idn(0xCB, 41), idn(0xC8, 40), hr + 2, {rcpt(idn(0xDB, 41), hr + 2, 41, payees[2], 1000000)}, false);
        }
        const pb::XmrKeyRef author = kat_author();
        const pb::Hash32 author_id = pb::key_ref_identity(author);
        const pb::Hash32 t = idn(0xC8, 40);
        const pb::TipWindow wx = pb::evaluate_window_at(sx, t, c, vx, 16, author_id);
        const pb::TipWindow wy = pb::evaluate_window_at(sy, t, c, vy, 16, author_id);
        const std::uint64_t R = 600000000000ull + 1500000000ull;
        rec.tip("v37_xmr_window_branch_kat/race-x", wx, R);
        rec.tip("v37_xmr_window_branch_kat/race-y", wy, R);
        {
            pb::ReceiptBodyV3 r;
            r.blob.major = 16;
            r.blob.minor = 16;
            r.blob.prev_id = a2;
            r.extra_nonce = {9, 8, 7, 6};
            r.branch = {seq32(0x81), seq32(0x91)};
            r.side.pool_id = seq32(0x01);
            r.side.payee = payees[3];
            r.side.t_origin = 1000000;
            r.side.tip = t;
            r.side.receipts_root = seq32(0xA0);
            r.payee = book.refs.at(payees[3]);
            r.reward_total = R;
            const std::uint64_t h_r = hr + 2;
            for (const auto* tw : {&wx, &wy}) {
                pb::WindowAt at;
                at.window = tw->window.get();
                at.tip = tw->tip;
                at.v = tw->v;
                at.window_root = tw->window_root;
                at.mmr_root = tw->mmr_root;
                pb::KeyCache k;
                rec.tx(std::string("v37_xmr_window_branch_kat/race-tx-") + (tw == &wx ? "x" : "y"),
                       pb::canonical_miner_tx(r, at, t, a2, h_r, 16, k, book.lookup(), author));
            }
        }
        rec.tip("v37_xmr_window_branch_kat/race-own-main",
                pb::evaluate_window_at(sx, t, vx.main_tip(), vx, 16, author_id), R);
        for (const auto& [tip, p] : {std::pair<pb::Hash32, pb::Hash32>{idn(0xCA, 41), a2},
                                     std::pair<pb::Hash32, pb::Hash32>{idn(0xCB, 41), b2}}) {
            const std::string tag = p == a2 ? "A2" : "B2";
            rec.tip("v37_xmr_window_branch_kat/race-" + tag + "-x", pb::evaluate_window_at(sx, tip, p, vx, 16, author_id), R);
            rec.tip("v37_xmr_window_branch_kat/race-" + tag + "-y", pb::evaluate_window_at(sy, tip, p, vy, 16, author_id), R);
        }
    }
    const std::uint64_t B = kB, f = 1, R = kB + 5000000000ull;
    const pb::Hash32 author{};
    {
        std::vector<pb::WinBin> bins;
        for (int i = 0; i < 10; ++i) {
            pb::WinEntry x;
            x.miner = rep(static_cast<std::uint8_t>(0x80 + i));
            x.work = 100;
            x.position = 100 - i;
            x.id = x.miner;
            bins.push_back({static_cast<std::uint64_t>(10 - i), {x}});
        }
        list3(rec, "v37_xmr_window_branch_kat/tip-t-150", bins, 150, B, f, 3747, author, R);
        list3(rec, "v37_xmr_window_branch_kat/tip-u-450", bins, 450, B, f, 3747, author, R);
    }
    {
        const KatBranchView x = branch_main_chain(102);
        const KatBranchView y = branch_main_chain(100);
        std::vector<pb::WinBin> unit;
        for (std::uint64_t k = 0; k < 3000; ++k) {
            pb::WinEntry e;
            e.miner = rep(static_cast<std::uint8_t>(0x10 + k % 8));
            e.work = 1;
            e.position = 900000 - k;
            e.id = e.miner;
            unit.push_back({100000 - k, {e}});
        }
        auto window_on = [&](const KatBranchView& v, const pb::Hash32& p_t, const std::string& name) {
            pb::WindowInputs in;
            const bool ok = pb::select_window_inputs(v, p_t, 16, in).selected() && in.d_net.hi == 0;
            if (!ok) return;
            const std::uint64_t Bx = in.weights.base_reward;
            list3(rec, name, unit, in.d_net.lo, Bx, pb::f_spend(Bx, in.weights.fee_median, 16),
                  pb::n_rule(in.weights.zone, 16, Bx), pb::Hash32{}, Bx + 7000000000ull);
        };
        window_on(x, block_id(0x4d, 100), "v37_xmr_window_branch_kat/main102-p100");
        window_on(y, block_id(0x4d, 100), "v37_xmr_window_branch_kat/main100-p100");
        window_on(x, block_id(0x4d, 102), "v37_xmr_window_branch_kat/main102-p102");
    }
}

// ---- v37_xmr_window_fork_height_kat ----
inline void kat_v37_xmr_window_fork_height(Recorder& rec) {
    using namespace pathb_kat;
    RefBook book;
    const pb::XmrKeyRef author = kat_author();
    const pb::Window w = window_of({{book.add(key_ref(0xA1)), 100}});
    pb::ReceiptBodyV3 r = make_body(3, false, 0x30);
    r.reward_total = 700000000000ull;
    const pb::Hash32 tip = r.side.tip, p_r = r.blob.prev_id;
    pb::KeyCache cache;
    for (const std::uint8_t hf : {std::uint8_t{16}, std::uint8_t{17}, std::uint8_t{18}})
        rec.tx("v37_xmr_window_fork_height_kat/hf" + std::to_string(hf),
               pb::canonical_miner_tx(r, at_of(&w, tip, hf), tip, p_r, kKatHeight, hf, cache, book.lookup(), author));
}

// ---- v37_xmr_pathb_coinbase_kat ----
inline void kat_v37_xmr_pathb_coinbase(Recorder& rec) {
    using namespace pathb_kat;
    const pb::XmrKeyRef author = kat_author();
    RefBook book;
    const pb::RefLookup refs = book.lookup();
    pb::KeyCache cache;
    auto mtx = [&](const std::string& name, const pb::ReceiptBodyV3& r, const pb::Window& w, std::uint8_t hf) {
        rec.tx("v37_xmr_pathb_coinbase_kat/" + name,
               pb::canonical_miner_tx(r, at_of(&w, r.side.tip, hf), r.side.tip, r.blob.prev_id, kKatHeight, hf, cache,
                                      refs, author));
    };
    {   // case 4: mainnet block 3,755,897 and regtest
        const m2::Block& B = m2::kBlocks[0];
        std::vector<std::pair<pb::Hash32, std::uint64_t>> wts;
        for (std::size_t i = 0; i < B.n_payees; ++i) {
            pb::XmrKeyRef ref;
            ref.spend = h32(B.payees[i].spend);
            ref.view = h32(B.payees[i].view);
            wts.push_back({book.add(ref), 1000003u + 7919u * i});
        }
        const pb::Window w = window_of(wts);
        pb::ReceiptBodyV3 r = make_body(3, false, 0x24);
        r.reward_total = B.reward;
        rec.win("v37_xmr_pathb_coinbase_kat/case4-mainnet-window", w, B.reward);
        mtx("case4-mainnet", r, w, 16);
        const std::uint64_t R = pb::base_reward_at(17592186044415ull, 16);
        std::vector<std::pair<pb::Hash32, std::uint64_t>> wr;
        for (std::uint8_t i = 0; i < 3; ++i) wr.push_back({book.add(key_ref(static_cast<std::uint8_t>(0xA0 + i))), 1u << i});
        const pb::Window w_reg = window_of(wr);
        pb::ReceiptBodyV3 q = make_body(3, false, 0x25);
        q.reward_total = R;
        rec.win("v37_xmr_pathb_coinbase_kat/case4-regtest-window", w_reg, R);
        mtx("case4-regtest", q, w_reg, 16);
    }
    const std::uint64_t base = 600000000000ull, fees = 5000000000ull, R = base + fees;
    {   // the window through window()
        const pb::Hash32 cb_owner = id_of(0x1000), cb_author = id_of(0x2000);
        std::vector<pb::WinBin> cb_bins;
        for (std::uint64_t k = 0; k < 3; ++k) {
            pb::WinBin b;
            b.bin = 2000 - k;
            for (std::uint64_t i = 1; i <= 32; ++i) {
                pb::WinEntry x;
                x.miner = id_of(i);
                x.work = 500 * i;
                x.position = 900 - 40 * k - i;
                x.id = id_of(100000 + x.position);
                if (i == 32) {
                    x.owner = cb_owner;
                    x.p = 100;
                }
                if (i == 31) x.give_author_bp = 10;
                b.entries.push_back(x);
            }
            cb_bins.push_back(b);
        }
        list3(rec, "v37_xmr_pathb_coinbase_kat/cb-bins", cb_bins, 200000, base, pb::f_spend(base, 300000, 16),
              pb::n_rule(300000, 16, base), cb_author, R);
    }
    std::vector<std::pair<pb::Hash32, std::uint64_t>> wts;
    for (std::uint64_t i = 1; i <= 32; ++i) wts.push_back({book.add(key_ref(static_cast<std::uint8_t>(i))), 1000 * i});
    const pb::Window wk = window_of(wts);
    {
        pb::ReceiptBodyV3 r = make_body(3, false, 0x20);
        r.reward_total = R;
        mtx("wk-split", r, wk, 16);
        pb::ReceiptBodyV3 bad = r;
        bad.reward_total = R + 1;
        mtx("wk-r-plus-1", bad, wk, 16);
        pb::ReceiptBodyV3 o = make_body(3, true, 0x21);
        o.reward_total = R;
        mtx("wk-owner", o, wk, 16);
        pb::ReceiptBodyV3 ne = make_body(3, false, 0x22);
        ne.reward_total = R;
        ne.side.owner = seq32(0x21);
        mtx("wk-no-encode", ne, wk, 16);
    }
    {
        const pb::Window wf = finder_only_window();
        pb::ReceiptBodyV3 f = make_body(3, true, 0x23);
        f.reward_total = R;
        mtx("finder-only", f, wf, 16);
        pb::ReceiptBodyV3 bad = f;
        bad.side.fee_rate_bp = 0;
        mtx("finder-only-no-encode", bad, wf, 16);
    }
    {
        const pb::Hash32 au = pb::key_ref_identity(author);
        auto entry_of = [&](const pb::ReceiptBodyV3& b, std::uint64_t work, std::uint64_t pos) {
            book.add(b.payee);
            if (b.owner) book.add(*b.owner);
            pb::WinEntry e;
            e.miner = b.side.payee;
            e.owner = b.side.owner;
            e.work = work;
            e.p = b.side.fee_rate_bp;
            e.give_author_bp = b.side.give_author_bp;
            e.position = pos;
            e.id = id_of(pos);
            return e;
        };
        const pb::ReceiptBodyV3 honest = make_body(3, false, 0x30);
        pb::WinBin ok_bin;
        ok_bin.bin = 7;
        ok_bin.entries.push_back(entry_of(honest, 1000000, 2));
        ok_bin.entries.push_back(entry_of(make_body(3, true, 0x50), 2000000, 3));
        const std::vector<pb::WinBin> okv{ok_bin};
        list3(rec, "v37_xmr_pathb_coinbase_kat/ok-bin", okv, 1000000000ull, base, 1, 3747, au, R);
        const pb::Window w_ok = pb::window(okv, 1000000000ull, base, 1, 3747, au);
        const pb::Window wf = finder_only_window();
        struct Case {
            std::uint16_t p, ga;
        };
        for (const Case c : {Case{9990, 10}, Case{10000, 0}}) {
            for (const pb::Window* win : {&w_ok, &wf}) {
                pb::ReceiptBodyV3 x = make_body(3, true, 0x40);
                x.side.fee_rate_bp = c.p;
                x.side.give_author_bp = c.ga;
                mtx("cases-" + std::to_string(c.p) + "-" + std::to_string(c.ga) + (win == &wf ? "-finder" : "-window"), x,
                    *win, 16);
            }
        }
        for (const Case c : {Case{9990, 10}, Case{10000, 0}}) {
            pb::ReceiptBodyV3 x = make_body(3, true, 0x40);
            x.side.fee_rate_bp = c.p;
            x.side.give_author_bp = c.ga;
            pb::WinBin bin;
            bin.bin = 7;
            bin.entries.push_back(entry_of(honest, 1000000, 2));
            bin.entries.push_back(entry_of(x, 1000000, 1));
            const std::vector<pb::WinBin> v{bin};
            list3(rec, "v37_xmr_pathb_coinbase_kat/own-entry-" + std::to_string(c.p) + "-" + std::to_string(c.ga), v,
                  1000000000ull, base, 1, 3747, au, x.reward_total);
            mtx("own-entry-tx-" + std::to_string(c.p) + "-" + std::to_string(c.ga), x,
                pb::window(v, 1000000000ull, base, 1, 3747, au), 16);
        }
        {
            pb::ReceiptBodyV3 y = make_body(3, true, 0x40);
            mtx("hf17", y, w_ok, 17);
        }
        {
            pb::ReceiptBodyV3 u = make_body(3, true, 0x60);
            u.side.fee_rate_bp = 10000;
            u.side.give_author_bp = 10;
            pb::WinBin bin;
            bin.bin = 7;
            bin.entries.push_back(entry_of(honest, 1000000, 2));
            bin.entries.push_back(entry_of(u, 1000000, 1));
            const std::vector<pb::WinBin> v{bin};
            list3(rec, "v37_xmr_pathb_coinbase_kat/undefined-entry", v, 1000000000ull, base, 1, 3747, au, R);
            pb::ReceiptBodyV3 h = make_body(3, false, 0x70);
            mtx("undefined-window", h, pb::window(v, 1000000000ull, base, 1, 3747, au), 16);
        }
    }
}

// ===========================================================================
// (b) corner vectors at depth 0 and the SealedCut vectors (M-1)
// ===========================================================================
inline pb::WinEntry cx_entry(std::uint64_t miner, std::uint64_t work, std::uint64_t pos, std::uint64_t id) {
    pb::WinEntry e;
    e.miner = id_of(miner);
    e.work = work;
    e.position = pos;
    e.id = id_of(id);
    return e;
}

// A store of test lane params: F open bins, Fresh 2, T 3600 s (J_0 = 3).
inline pb::LaneParams small_params(std::uint64_t F) {
    pb::LaneParams P = pb::kRuledLaneParams;
    P.carrier_interval_s = 3600;
    P.open_bins = F;
    return P;
}

inline void corner_vectors(Recorder& rec) {
    using namespace pathb_kat;
    const std::uint64_t f = f16(), R = kB;
    // (1) the lazy read over listed bins: COV equal to the newest bin's work: one bin read.
    {
        const std::vector<pb::WinBin> bins{{20, {cx_entry(1, 500000, 40, 1), cx_entry(2, 500000, 39, 2)}},
                                           {19, {cx_entry(3, 18180, 38, 3)}}};
        list3(rec, "corner/lazy-read-listed", bins, 500000, kB, f, 3747, pb::Hash32{}, R);
    }
    // (1') the lazy read through the store: the newest bin H(t) + Fresh holds work 2 D_net; the older
    // bins' buckets are absent: a verdict from one bin, never a deferral.
    {
        const pb::LaneParams P = small_params(1);
        constexpr std::uint64_t b0 = 7000;
        pb::BinStore s(P, 4, idn(0xF0, 0), b0);
        for (std::uint64_t pos = 1; pos <= 12; ++pos) {
            std::vector<pb::Placement> pls{rcpt(idn(0xF1, pos), b0 + pos, pos, idn(0xF2, pos), 300000)};
            if (pos == 12) pls.push_back(rcpt(idn(0xF3, pos), b0 + pos + 2, pos, idn(0xF4, pos), 1000000));
            extend(s, idn(0xF0, pos), idn(0xF0, pos - 1), b0 + pos, pls, true);
        }
        s.prune_buckets(b0 + 1000);
        rec.tip("corner/lazy-read-store", pb::tip_window(s, idn(0xF0, 12), wparams(500000, kB, f, 3747), 16), R);
        rec.tip("corner/lazy-read-store-deeper",
                pb::tip_window(s, idn(0xF0, 12), wparams(1000000, kB, f, 3747), 16), R);
    }
    // (2) entries in the Fresh bins above H(pos(t)).
    {
        const pb::LaneParams P = pb::kRuledLaneParams;
        constexpr std::uint64_t b0 = 8000;
        pb::BinStore s(P, 64, idn(0xF5, 0), b0);
        for (std::uint64_t pos = 1; pos <= 8; ++pos) {
            const std::uint64_t h = b0 + pos;
            std::vector<pb::Placement> pls{rcpt(idn(0xF6, pos), h, pos, idn(0xF7, pos % 5), 40000 + pos)};
            if (pos % 2 == 0) pls.push_back(rcpt(idn(0xF8, pos), h + 1, pos, idn(0xF7, 7), 50000));
            if (pos % 3 == 0) pls.push_back(rcpt(idn(0xF9, pos), h + 2, pos, idn(0xF7, 8), 60000));
            extend(s, idn(0xF5, pos), idn(0xF5, pos - 1), h, pls, true);
        }
        for (const std::uint64_t pos : {std::uint64_t{6}, std::uint64_t{8}}) {
            rec.tip("corner/fresh-bins-" + std::to_string(pos),
                    pb::tip_window(s, idn(0xF5, pos), wparams(kHugeDnet, kB, f, 3747), 16), R);
            rec.tip("corner/fresh-bins-cov-" + std::to_string(pos),
                    pb::tip_window(s, idn(0xF5, pos), wparams(60000, kB, f, 3747), 16), R);
            rec.tip("corner/fresh-bins-n2-" + std::to_string(pos),
                    pb::tip_window(s, idn(0xF5, pos), wparams(kHugeDnet, kB, f, 2), 16), R);
        }
    }
    // (3) V2: the newest bin holds 47,886 receipts of equal work d: v1's cut keeps the 47,885 newest.
    {
        std::vector<pb::WinBin> bins(1);
        bins[0].bin = 900;
        for (std::uint64_t k = 0; k < 47886; ++k) bins[0].entries.push_back(cx_entry(k + 1, 80000, 5000000 + k, 9000000 + k));
        list3(rec, "corner/v2", bins, kHugeDnet, kB, f, 100000, pb::Hash32{}, R);
    }
    // (4) a sealed bin taken whole weighs raw_sum.
    {
        std::vector<pb::WinEntry> es;
        for (std::uint64_t k = 0; k < 6; ++k) {
            pb::WinEntry e = cx_entry(10 + k, 100000 + 17 * k, 60 - k, 70 + k);
            if (k % 2 == 0) {
                e.owner = id_of(50);
                e.p = 250;
            }
            if (k % 3 == 0) e.give_author_bp = 40;
            es.push_back(e);
        }
        const pb::L1Bucket bk = pb::seal_from_entries(30, es);
        std::vector<pb::WinBin> bins(2);
        bins[0].bin = 31;
        bins[0].entries = {cx_entry(1, 200000, 70, 1)};
        bins[1].bin = 30;
        bins[1].sealed = &bk;
        list3(rec, "corner/sealed-whole-raw-sum", bins, kHugeDnet, kB, f, 3747, id_of(0xAA), R);
        list3(rec, "corner/sealed-whole-raw-sum-loose", bins, kHugeDnet, kB, 1, 3747, pb::Hash32{}, R);
    }
}

inline void sealed_cut_vectors(Recorder& rec) {
    using namespace pathb_kat;
    const std::uint64_t f = f16(), R = kB;
    // (i) a sealed FIRST bin failing W_max alone (empty open bins before it).
    std::vector<pb::WinEntry> wmax_es{cx_entry(1, 1000000000000ull, 30, 1), cx_entry(2, 20000, 29, 2)};
    const pb::L1Bucket wmax_bk = pb::seal_from_entries(40, wmax_es);
    {
        std::vector<pb::WinBin> bins(4);
        bins[0].bin = 43;
        bins[1].bin = 42;
        bins[2].bin = 40;
        bins[2].sealed = &wmax_bk;
        bins[3].bin = 39;
        bins[3].entries = {cx_entry(3, 50000, 20, 3)};
        list3(rec, "sealedcut/i-wmax-first", bins, kHugeDnet, kB, f, 3747, pb::Hash32{}, R);
        std::vector<pb::WinBin> alone{bins[2]};
        list3(rec, "sealedcut/i-wmax-alone", alone, kHugeDnet, kB, f, 3747, pb::Hash32{}, R);
        // the same bin open: the R-12 cut (a verdict)
        std::vector<pb::WinBin> open{{40, wmax_es}};
        list3(rec, "sealedcut/i-wmax-open-control", open, kHugeDnet, kB, f, 3747, pb::Hash32{}, R);
    }
    // (ii) one sealed bin whose payees exceed N.
    std::vector<pb::WinEntry> n_es{cx_entry(11, 30000, 30, 11), cx_entry(12, 30000, 29, 12), cx_entry(13, 30000, 28, 13)};
    n_es[1].owner = id_of(14);
    n_es[1].p = 100;
    const pb::L1Bucket n_bk = pb::seal_from_entries(50, n_es);
    {
        std::vector<pb::WinBin> one(1);
        one[0].bin = 50;
        one[0].sealed = &n_bk;
        for (const std::uint64_t N : {std::uint64_t{1}, std::uint64_t{3}})
            list3(rec, "sealedcut/ii-n-alone-N" + std::to_string(N), one, kHugeDnet, kB, 1, N, pb::Hash32{}, R);
        std::vector<pb::WinBin> more(3);
        more[0].bin = 52;
        more[1].bin = 50;
        more[1].sealed = &n_bk;
        more[2].bin = 49;
        more[2].entries = {cx_entry(20, 40000, 10, 20)};
        for (const std::uint64_t N : {std::uint64_t{2}, std::uint64_t{4}, std::uint64_t{5}})
            list3(rec, "sealedcut/ii-n-first-N" + std::to_string(N), more, kHugeDnet, kB, 1, N, pb::Hash32{}, R);
        std::vector<pb::WinBin> open{{50, n_es}};
        list3(rec, "sealedcut/ii-n-open-control", open, kHugeDnet, kB, 1, 2, pb::Hash32{}, R);
    }
    // (iii) window() on (i) and (ii) is recorded by list3 above (".../window").
    // (iv) / (v) the store forms through tip_window: t's own receipt missing (an empty run of carriers after the
    // last placement), the newest non-empty bin sealed at t.
    for (int variant = 0; variant < 3; ++variant) {
        for (const std::uint64_t F : {std::uint64_t{2}, std::uint64_t{96}}) {
            const pb::LaneParams P = F == 96 ? pb::kRuledLaneParams : small_params(F);
            constexpr std::uint64_t b0 = 9000;
            pb::BinStore s(P, 64, idn(0xE5, 0), b0);
            std::uint64_t pos = 0;
            for (; pos < 4; ++pos) {
                const std::uint64_t q = pos + 1, h = b0 + q;
                std::vector<pb::Placement> pls{rcpt(idn(0xE6, q), h, q, idn(0xE7, q), 300000)};
                if (q == 4) {
                    if (variant == 0) {  // W_max alone fails
                        pls.push_back(rcpt(idn(0xE8, q), h, q, idn(0xE9, 1), 1000000000000ull));
                        pls.push_back(rcpt(idn(0xE8, q + 100), h, q, idn(0xE9, 2), 20000));
                    } else {  // two more payees (N rule) / both tests pass
                        pls.push_back(rcpt(idn(0xE8, q), h, q, idn(0xE9, 1), 300000));
                        pls.push_back(rcpt(idn(0xE8, q + 100), h, q, idn(0xE9, 2), 300000, 100, 0, idn(0xEA, 1)));
                    }
                }
                extend(s, idn(0xE5, q), idn(0xE5, q - 1), h, pls, true);
            }
            const std::uint64_t run = F + 2 + 1;
            for (std::uint64_t k = 0; k < run; ++k, ++pos)
                extend(s, idn(0xE5, pos + 1), idn(0xE5, pos), b0 + pos + 1, {}, true);
            const pb::Hash32 t = idn(0xE5, pos);
            const std::string tag = "sealedcut/store-" + std::string(variant == 0 ? "wmax" : variant == 1 ? "n" : "pass") +
                                    "-F" + std::to_string(F);
            if (variant == 0) rec.tip(tag, pb::tip_window(s, t, wparams(kHugeDnet, kB, f, 3747), 16), R);
            if (variant == 1)
                for (const std::uint64_t N : {std::uint64_t{1}, std::uint64_t{2}, std::uint64_t{3}})
                    rec.tip(tag + "-N" + std::to_string(N), pb::tip_window(s, t, wparams(kHugeDnet, kB, 1, N), 16), R);
            if (variant == 2) {
                rec.tip(tag, pb::tip_window(s, t, wparams(kHugeDnet, kB, f, 3747), 16), R);
                rec.tip(tag + "-cov", pb::tip_window(s, t, wparams(300000, kB, f, 3747), 16), R);
            }
        }
    }
}

// ===========================================================================
// (c) the seeded generator of K = 1 stores with generated payees
// ===========================================================================
struct GenPool {
    pathb_kat::RefBook book;
    std::vector<pb::Hash32> miners;  // identities 0 .. 39
    std::vector<pb::Hash32> owners;  // identities 40 .. 55
    pb::XmrKeyRef author_ref;
    pb::Hash32 author{};
    GenPool() {
        for (std::uint64_t k = 0; k < 56; ++k) {
            std::vector<std::uint8_t> pre(kTestTag, kTestTag + std::char_traits<char>::length(kTestTag));
            for (int i = 0; i < 8; ++i) pre.push_back(static_cast<std::uint8_t>(k >> (8 * i)));
            const pb::Hash32 hs = ::v37::sha256d(pre);
            std::uint64_t a = 0, b = 0;
            for (int i = 0; i < 8; ++i) {
                a |= std::uint64_t{hs[i]} << (8 * i);
                b |= std::uint64_t{hs[8 + i]} << (8 * i);
            }
            a = (a >> 2) | 1;
            b = (b >> 2) | 1;
            const pb::Hash32 id = book.add(pathb_kat::ref_from_secrets(a, b));
            (k < 40 ? miners : owners).push_back(id);
        }
        author_ref = pathb_kat::kat_author();
        author = pb::key_ref_identity(author_ref);
    }
};

// A generated receipt id under the test tag.
inline pb::Hash32 gen_id(std::uint64_t n) {
    std::vector<std::uint8_t> pre(kTestTag, kTestTag + std::char_traits<char>::length(kTestTag));
    pre.push_back(0x49);
    for (int i = 0; i < 8; ++i) pre.push_back(static_cast<std::uint8_t>(n >> (8 * i)));
    return ::v37::sha256d(pre);
}

// log-uniform work in [lo, lo x 2^bits)
inline std::uint64_t gen_work(Rng& rng, std::uint64_t lo, unsigned bits) {
    const unsigned e = static_cast<unsigned>(rng.below(bits + 1));
    const std::uint64_t span = e == 0 ? lo : lo << (e - 1);
    return lo + (e == 0 ? rng.below(lo) : span + rng.below(span));
}

struct ListCase {
    std::vector<pb::WinBin> bins;
    std::deque<pb::L1Bucket> buckets;
    pb::DNet d_net = 0;
    std::uint64_t B = kB, f = 1, N = 3747, R = kB;
    pb::Hash32 author{};
};

// The regime of one listed case, read from its inputs and outputs.
inline void count_list_regimes(Recorder& rec, const ListCase& c, const pb::WinEval& e,
                               const std::vector<pb::WinBin>& sel) {
    if (e.status == pb::WinStatus::SealedCut) ++rec.regime[RgSealedCut];
    if (e.status != pb::WinStatus::Ok) return;
    if (e.n_dropped_bins && !e.n_cut_position) ++rec.regime[RgNDrop];
    if (e.n_cut_position) ++rec.regime[RgNCut];
    if (e.window.weight.empty()) ++rec.regime[RgEmpty];
    // R-12: the first non-empty input bin is open and step 1 kept fewer of its entries
    const pb::WinBin* first = nullptr;
    std::size_t first_i = 0;
    for (std::size_t i = 0; i < c.bins.size(); ++i) {
        const pb::WinBin& b = c.bins[i];
        const bool empty = b.sealed ? b.sealed->rows.empty() : b.entries.empty();
        if (!empty) {
            first = &b;
            first_i = i;
            break;
        }
    }
    bool r12 = false;
    if (first && !first->sealed) r12 = sel.empty() || sel[0].entries.size() < first->entries.size();
    if (r12) ++rec.regime[RgR12Cut];
    // W_max-bound: step 1 stopped below coverage with a later non-empty bin left unread
    if (!r12 && !sel.empty() && first) {
        pb::Work raw;
        for (const pb::WinBin& b : sel) {
            if (b.sealed) raw += b.sealed->raw_sum;
            for (const pb::WinEntry& x : b.entries) raw += pb::Work(x.work);
        }
        pb::Work cov;
        for (int i = 0; i < 2; ++i) cov += pb::Work::from_u128(c.d_net);
        std::size_t last = first_i;
        for (std::size_t i = first_i; i < c.bins.size(); ++i)
            if (c.bins[i].bin == sel.back().bin) last = i;
        bool later = false;
        for (std::size_t i = last + 1; i < c.bins.size(); ++i) {
            const pb::WinBin& b = c.bins[i];
            later = later || !(b.sealed ? b.sealed->rows.empty() : b.entries.empty());
        }
        if (raw < cov && later) ++rec.regime[RgWmaxBound];
    }
    // merge-back by owners / the author (owners, miners and the author are disjoint identities here)
    std::map<pb::Hash32, pb::Work> owner_w;
    pb::Work author_w;
    for (const pb::BucketRow& r : e.window.rows) {
        if (!(r.owner == pb::Hash32{}) && !r.w_owner.is_zero()) owner_w[r.owner] += r.w_owner;
        author_w += r.w_author;
    }
    bool owner_merged = false;
    for (const auto& [o, w] : owner_w) owner_merged = owner_merged || e.window.weight.count(o) == 0;
    if (owner_merged) ++rec.regime[RgOwnerMerge];
    if (!(c.author == pb::Hash32{}) && !author_w.is_zero() && e.window.weight.count(c.author) == 0)
        ++rec.regime[RgAuthorMerge];
}

inline void gen_list_case(Rng& rng, const GenPool& pool, std::size_t i, ListCase& c, std::uint64_t& id_ctr) {
    const std::size_t shape = i % 10;
    std::uint64_t pos = 1000000;
    std::uint64_t bin = 500000 + 64 * i;
    auto entry = [&](std::size_t miner, std::uint64_t work, std::uint16_t p, std::uint16_t ga, std::size_t owner) {
        pb::WinEntry e;
        e.miner = pool.miners[miner % pool.miners.size()];
        if (p > 0) e.owner = pool.owners[owner % pool.owners.size()];
        e.work = work;
        e.p = p;
        e.give_author_bp = ga;
        e.position = pos - rng.below(40);
        e.id = gen_id(id_ctr++);
        return e;
    };
    auto push_bin = [&](std::vector<pb::WinEntry> es, bool sealed) {
        pb::WinBin b;
        b.bin = bin--;
        pos -= 50;
        if (sealed) {
            c.buckets.push_back(pb::seal_from_entries(b.bin, es));
            b.sealed = &c.buckets.back();
        } else {
            b.entries = std::move(es);
        }
        c.bins.push_back(std::move(b));
    };
    auto rand_entries = [&](std::size_t n, std::uint64_t lo, unsigned bits, bool shares) {
        std::vector<pb::WinEntry> es;
        for (std::size_t k = 0; k < n; ++k) {
            std::uint16_t p = 0, ga = 0;
            if (shares && rng.below(3) == 0) p = static_cast<std::uint16_t>(rng.below(3) == 0 ? rng.below(10001) : rng.below(300));
            if (shares && rng.below(3) == 0) ga = static_cast<std::uint16_t>(std::min<std::uint64_t>(10000 - p, rng.below(200)));
            es.push_back(entry(rng.below(40), gen_work(rng, lo, bits), p, ga, rng.below(16)));
        }
        return es;
    };
    c.B = rng.below(4) == 0 ? 1000000000ull + rng.below(20000000000000ull) : kB;
    c.f = f16();
    c.N = 3747;
    c.author = rng.below(2) == 0 ? pool.author : pb::Hash32{};
    c.d_net = kHugeDnet;
    switch (shape) {
        case 0: {  // free: coverage-bound or end-bound
            const std::size_t nb = rng.below(7);
            for (std::size_t k = 0; k < nb; ++k) push_bin(rand_entries(rng.below(9), 18180, 20, true), rng.below(10) < 3);
            c.f = rng.below(3) == 0 ? 1 : (rng.below(2) == 0 ? f16() : 1 + rng.below(50000000));
            c.N = rng.below(3) == 0 ? 1 + rng.below(20) : 3747;
            pb::Work tot;
            for (const pb::WinBin& b : c.bins) {
                if (b.sealed) tot += b.sealed->raw_sum;
                for (const pb::WinEntry& x : b.entries) tot += pb::Work(x.work);
            }
            const std::uint64_t t64 = tot.v[0];
            c.d_net = t64 == 0 ? 1 + rng.below(1000) : 1 + rng.below(t64);
            break;
        }
        case 1: {  // W_max-bound: a later bin's small entry stops step 1
            const std::size_t nb = 3 + rng.below(4);
            const std::size_t small_at = 1 + rng.below(nb - 1);
            for (std::size_t k = 0; k < nb; ++k) {
                std::vector<pb::WinEntry> es = rand_entries(1 + rng.below(4), 100000000ull, 3, false);
                if (k == small_at) es.push_back(entry(rng.below(40), 18180 + rng.below(30000), 0, 0, 0));
                push_bin(std::move(es), rng.below(10) < 3);
            }
            break;
        }
        case 2: {  // R-12: the first bin open, failing W_max alone
            std::vector<pb::WinEntry> es = rand_entries(2 + rng.below(6), 100000000ull, 4, true);
            const std::size_t smalls = 1 + rng.below(2);
            for (std::size_t k = 0; k < smalls; ++k) es.push_back(entry(rng.below(40), 18180 + rng.below(20000), 0, 0, 0));
            if (rng.below(3) == 0) push_bin({}, false);
            push_bin(std::move(es), false);
            for (std::size_t k = rng.below(3); k > 0; --k) push_bin(rand_entries(1 + rng.below(3), 18180, 10, true), rng.below(2) == 0);
            break;
        }
        case 3: {  // the N rule drops k >= 1 bins
            const std::size_t nb = 2 + rng.below(5);
            std::size_t next_miner = rng.below(10);
            std::vector<std::uint64_t> cum;
            std::uint64_t count = 0;
            for (std::size_t k = 0; k < nb; ++k) {
                const std::size_t n = 1 + rng.below(4);
                std::vector<pb::WinEntry> es;
                for (std::size_t j = 0; j < n; ++j) es.push_back(entry(next_miner++, gen_work(rng, 18180, 8), 0, 0, 0));
                count += n;
                cum.push_back(count);
                push_bin(std::move(es), rng.below(10) < 4);
            }
            c.f = 1;
            c.author = pb::Hash32{};
            c.N = cum[rng.below(nb - 1)];
            break;
        }
        case 4: {  // the N cut of the first bin
            const std::size_t n = 3 + rng.below(8);
            std::vector<pb::WinEntry> es = rand_entries(n, 18180, 12, true);
            push_bin(std::move(es), false);
            for (std::size_t k = rng.below(3); k > 0; --k) push_bin(rand_entries(1 + rng.below(3), 18180, 10, true), rng.below(2) == 0);
            c.f = 1;
            c.N = 1 + rng.below(2);
            break;
        }
        case 5: {  // owner merge-back
            const std::size_t nb = 1 + rng.below(3);
            for (std::size_t k = 0; k < nb; ++k) {
                std::vector<pb::WinEntry> es;
                es.push_back(entry(rng.below(40), 1000000000ull + rng.below(1000000000ull), 0, 0, 0));
                const std::size_t n = 1 + rng.below(40);
                const std::size_t owner = rng.below(16);
                for (std::size_t j = 0; j < n; ++j)
                    es.push_back(entry(rng.below(40), 100000 + rng.below(200000), static_cast<std::uint16_t>(1 + rng.below(30)), 0, owner));
                push_bin(std::move(es), rng.below(10) < 4);
            }
            c.B = kB;
            c.author = rng.below(2) == 0 ? pool.author : pb::Hash32{};
            break;
        }
        case 6: {  // author merge-back
            const std::size_t nb = 1 + rng.below(3);
            for (std::size_t k = 0; k < nb; ++k) {
                std::vector<pb::WinEntry> es;
                es.push_back(entry(rng.below(40), 1000000000ull + rng.below(1000000000ull), 0, 0, 0));
                const std::size_t n = 1 + rng.below(40);
                for (std::size_t j = 0; j < n; ++j)
                    es.push_back(entry(rng.below(40), 100000 + rng.below(200000), 0, static_cast<std::uint16_t>(1 + rng.below(30)), 0));
                push_bin(std::move(es), rng.below(10) < 4);
            }
            c.B = kB;
            c.author = pool.author;
            break;
        }
        case 7: {  // the empty window
            const std::size_t v = rng.below(4);
            if (v == 1)
                for (std::size_t k = 1 + rng.below(4); k > 0; --k) push_bin({}, rng.below(2) == 0);
            if (v == 2) {  // f above B: one entry alone fails W_max: nothing kept
                push_bin(rand_entries(1 + rng.below(4), 18180, 10, false), false);
                c.f = c.B + 1 + rng.below(1000);
            }
            if (v == 3) {  // N 1 and an entry with an owner: two identities, nothing kept
                std::vector<pb::WinEntry> es;
                es.push_back(entry(rng.below(40), gen_work(rng, 18180, 8), static_cast<std::uint16_t>(100 + rng.below(100)), 0, rng.below(16)));
                for (std::size_t k = rng.below(3); k > 0; --k) es.push_back(entry(rng.below(40), gen_work(rng, 18180, 8), 0, 0, 0));
                for (pb::WinEntry& x : es) x.position = 1000000 + 100;  // the owner entry first: ids decide
                es[0].position = 1000000 + 200;
                push_bin(std::move(es), false);
                c.f = 1;
                c.N = 1;
            }
            break;
        }
        case 8: {  // SealedCut at depth 0
            for (std::size_t k = rng.below(3); k > 0; --k) push_bin({}, rng.below(2) == 0);
            if (rng.below(2) == 0) {  // W_max alone fails
                std::vector<pb::WinEntry> es = rand_entries(1 + rng.below(4), 100000000000ull, 4, true);
                es.push_back(entry(rng.below(40), 18180 + rng.below(20000), 0, 0, 0));
                push_bin(std::move(es), true);
            } else {  // the N rule leaves one sealed bin over N
                std::vector<pb::WinEntry> es;
                const std::size_t n = 2 + rng.below(6);
                const std::size_t m0 = rng.below(40);
                for (std::size_t j = 0; j < n; ++j) es.push_back(entry(m0 + j, gen_work(rng, 18180, 8), 0, 0, 0));
                push_bin(std::move(es), true);
                c.N = 1 + rng.below(n - 1);
                c.f = 1;
            }
            for (std::size_t k = rng.below(3); k > 0; --k) push_bin(rand_entries(1 + rng.below(3), 18180, 10, true), rng.below(2) == 0);
            break;
        }
        default: {  // sealed-heavy mix with shares
            const std::size_t nb = 1 + rng.below(6);
            for (std::size_t k = 0; k < nb; ++k) push_bin(rand_entries(rng.below(10), 18180, 24, true), rng.below(10) < 7);
            c.f = rng.below(2) == 0 ? f16() : 1;
            c.N = rng.below(2) == 0 ? 1 + rng.below(30) : 3747;
            break;
        }
    }
    c.R = c.B + rng.below(10000000000ull);
}

// A generated store case: a chain built through BinStore with generated payees.
struct StoreCase {
    pb::LaneParams P;
    std::unique_ptr<pb::BinStore> s;
    std::vector<std::uint64_t> H;  // records by position (best chain)
    std::uint64_t b0 = 0;
    std::uint8_t tag = 0;
};

inline void store_extend(StoreCase& sc, Rng& rng, const GenPool& pool, std::uint64_t q, std::uint64_t h,
                         std::size_t n_pl, std::uint64_t& id_ctr, bool fresh_above, std::uint64_t work_lo,
                         unsigned work_bits, bool shares) {
    using namespace pathb_kat;
    const std::uint64_t Hp = sc.H[q - 1];
    const std::uint64_t Hq = std::max(Hp, h);
    std::vector<pb::Placement> pls;
    for (std::size_t k = 0; k < n_pl; ++k) {
        // an open bin at the parent: b > H(q - 1) - F; at most H(q) (+ Fresh when fresh_above)
        const std::uint64_t lo = Hp >= sc.P.open_bins ? std::max(sc.b0, Hp - sc.P.open_bins + 1) : sc.b0;
        const std::uint64_t hi = Hq + (fresh_above ? sc.P.fresh_max : 0);
        const std::uint64_t b = lo + rng.below(hi - lo + 1);
        std::uint64_t p_own = q;  // live iff b >= H(min(q - 1, p_own))
        if (b < Hp && rng.below(10) != 0) {
            p_own = 0;
            for (std::uint64_t x = q; x > 0; --x)
                if (sc.H[x - 1] <= b) {
                    p_own = x - 1;
                    break;
                }
        }
        std::uint16_t p = 0, ga = 0;
        pb::Hash32 owner{};
        if (shares && rng.below(3) == 0) {
            p = static_cast<std::uint16_t>(1 + rng.below(rng.below(4) == 0 ? 10000 : 200));
            owner = pool.owners[rng.below(pool.owners.size())];
        }
        if (shares && rng.below(3) == 0) ga = static_cast<std::uint16_t>(std::min<std::uint64_t>(10000 - p, rng.below(100)));
        pls.push_back(rcpt(gen_id(id_ctr++), b, p_own, pool.miners[rng.below(pool.miners.size())],
                           gen_work(rng, work_lo, work_bits), p, ga, owner));
    }
    extend(*sc.s, idn(sc.tag, q), idn(sc.tag, q - 1), h, pls, true);
    sc.H.push_back(Hq);
}

inline void gen_store_case(Recorder& rec, Rng& rng, const GenPool& pool, std::size_t i, std::uint64_t& id_ctr) {
    using namespace pathb_kat;
    StoreCase sc;
    const std::size_t kind = i % 4;
    sc.P = small_params(1 + rng.below(4));
    sc.b0 = 20000 + 1000 * i;
    sc.tag = static_cast<std::uint8_t>(0x10 + (i % 0xE0));
    const std::uint64_t J = 4;
    sc.s = std::make_unique<pb::BinStore>(sc.P, J, idn(sc.tag, 0), sc.b0);
    sc.H.push_back(sc.b0);
    const std::string name = "seeded/store-" + std::to_string(i) + "-k" + std::to_string(kind);
    const pathb_kat::RefBook* book = &pool.book;
    TxCtx ctx;
    ctx.book = book;
    ctx.author = pool.author_ref;
    ctx.body_seed = static_cast<std::uint8_t>(0x20 + (i % 32));
    const std::uint64_t R = kB + rng.below(10000000000ull);
    auto advance = [&]() { return sc.H.back() + (rng.below(5) == 0 ? 0 : 1); };
    switch (kind) {
        case 0: {  // MissingBucket: bodies pruned below a bin the window reads
            const std::uint64_t L = 15 + rng.below(20);
            for (std::uint64_t q = 1; q <= L; ++q)
                store_extend(sc, rng, pool, q, advance(), rng.below(4), id_ctr, rng.below(3) == 0, 18180, 16, true);
            const std::uint64_t top_sealed = sc.H.back() >= sc.P.open_bins ? sc.H.back() - sc.P.open_bins : sc.b0;
            const std::uint64_t keep = sc.b0 + 1 + rng.below(top_sealed > sc.b0 ? top_sealed - sc.b0 + 1 : 1);
            sc.s->prune_buckets(keep);
            rec.tip(name, pb::tip_window(*sc.s, idn(sc.tag, L), wparams(kHugeDnet, kB, 1, 3747, pool.author), 16), R, &ctx);
            break;
        }
        case 1: {  // MissingEntries: an old tip whose open bins lie below the P-37 floor
            const std::uint64_t L = 30 + rng.below(16);
            for (std::uint64_t q = 1; q <= L; ++q)
                store_extend(sc, rng, pool, q, sc.H.back() + 1, rng.below(4), id_ctr, rng.below(3) == 0, 18180, 16, true);
            const std::uint64_t floor = sc.s->prune_entries(std::numeric_limits<std::uint64_t>::max());
            std::uint64_t q_max = 0;
            for (std::uint64_t q = 1; q <= L; ++q)
                if (sc.H[q] + sc.P.fresh_max < floor) q_max = q;
            const std::uint64_t q_t = q_max == 0 ? L : 1 + rng.below(q_max);
            rec.tip(name, pb::tip_window(*sc.s, idn(sc.tag, q_t), wparams(kHugeDnet, kB, 1, 3747, pool.author), 16), R, &ctx);
            break;
        }
        case 2: {  // SealedCut / a verdict: t's own receipt missing, the newest non-empty bin sealed at t
            const std::uint64_t L1 = 3 + rng.below(8);
            for (std::uint64_t q = 1; q < L1; ++q)
                store_extend(sc, rng, pool, q, sc.H.back() + 1, rng.below(3), id_ctr, false, 18180, 12, true);
            const std::size_t variant = rng.below(3);
            {   // the last placing carrier: its own bin H(L1)
                using namespace pathb_kat;
                const std::uint64_t h = sc.H.back() + 1;
                std::vector<pb::Placement> pls;
                const std::size_t n = 2 + rng.below(4);
                const std::size_t m0 = rng.below(pool.miners.size());
                for (std::size_t k = 0; k < n; ++k)
                    pls.push_back(rcpt(gen_id(id_ctr++), h, L1, pool.miners[(m0 + k) % pool.miners.size()],
                                       variant == 0 && k == 0 ? 100000000000ull + rng.below(100000000000ull)
                                                              : 18180 + rng.below(500000)));
                extend(*sc.s, idn(sc.tag, L1), idn(sc.tag, L1 - 1), h, pls, true);
                sc.H.push_back(h);
            }
            const std::uint64_t run = sc.P.open_bins + sc.P.fresh_max + 1 + rng.below(3);
            std::uint64_t q = L1;
            for (std::uint64_t k = 0; k < run; ++k) {
                ++q;
                store_extend(sc, rng, pool, q, sc.H.back() + 1, 0, id_ctr, false, 18180, 12, false);
            }
            pb::WindowParams wp = wparams(kHugeDnet, kB, f16(), 3747, pool.author);
            if (variant == 1) {
                wp.f_spend = 1;
                wp.N = 1;
            }
            if (variant == 2) wp.f_spend = 1;
            rec.tip(name, pb::tip_window(*sc.s, idn(sc.tag, q), wp, 16), R, &ctx);
            break;
        }
        default: {  // mixed: a side branch, random params, a random tip
            const std::uint64_t L = 6 + rng.below(25);
            for (std::uint64_t q = 1; q <= L; ++q)
                store_extend(sc, rng, pool, q, advance(), rng.below(5), id_ctr, rng.below(2) == 0, 18180, 20, true);
            // a side branch of two carriers on position L - 2
            const std::uint64_t fq = L >= 3 ? L - 2 : 0;
            {
                using namespace pathb_kat;
                pb::Hash32 parent = idn(sc.tag, fq);
                std::uint64_t Hs = sc.H[fq];
                for (std::uint64_t k = 1; k <= 2; ++k) {
                    const std::uint64_t h = Hs + 1;
                    const std::uint64_t lo = Hs >= sc.P.open_bins ? std::max(sc.b0, Hs - sc.P.open_bins + 1) : sc.b0;
                    std::vector<pb::Placement> pls{rcpt(gen_id(id_ctr++), lo + rng.below(h - lo + 1), fq + k,
                                                        pool.miners[rng.below(pool.miners.size())],
                                                        gen_work(rng, 18180, 20))};
                    const pb::Hash32 id = idn(static_cast<std::uint8_t>(sc.tag ^ 0x80), k);
                    extend(*sc.s, id, parent, h, pls, false);
                    parent = id;
                    Hs = h;
                }
            }
            const std::size_t which = rng.below(3);
            const pb::Hash32 t = which == 0 ? idn(sc.tag, L)
                                 : which == 1 ? idn(static_cast<std::uint8_t>(sc.tag ^ 0x80), 2)
                                              : idn(sc.tag, 1 + rng.below(L));
            pb::Work tot;
            for (std::uint64_t k = 0; k < 4; ++k) tot += pb::Work(gen_work(rng, 18180, 20));
            const pb::DNet d = rng.below(2) == 0 ? kHugeDnet : pb::DNet{1 + tot.v[0]};
            const std::uint64_t f = rng.below(3) == 0 ? 1 : f16();
            const std::uint64_t N = rng.below(3) == 0 ? 1 + rng.below(6) : 3747;
            if (rng.below(4) == 0) sc.s->prune_buckets(sc.b0 + rng.below(8));
            rec.tip(name, pb::tip_window(*sc.s, t, wparams(d, kB, f, N, rng.below(2) == 0 ? pool.author : pb::Hash32{}), 16),
                    R, &ctx);
            break;
        }
    }
}

inline void seeded_vectors(Recorder& rec) {
    const GenPool pool;
    Rng rng(kSeed);
    std::uint64_t id_ctr = 1;
    TxCtx ctx;
    ctx.book = &pool.book;
    ctx.author = pool.author_ref;
    for (std::size_t i = 0; i < kListCases; ++i) {
        ListCase c;
        gen_list_case(rng, pool, i, c, id_ctr);
        const std::string name = "seeded/list-" + std::to_string(i) + "-s" + std::to_string(i % 10);
        const pb::WinEval e = pb::window_from(pb::ListedBins{c.bins}, c.d_net, c.B, c.f, c.N, c.author);
        const std::vector<pb::WinBin> sel = pb::select_window_bins(c.bins, c.d_net, c.B, c.f);
        ctx.body_seed = static_cast<std::uint8_t>(0x20 + (i % 32));
        rec.eval(name + "/window_from", e, c.R, i % 5 == 0 ? &ctx : nullptr);
        rec.win(name + "/window", pb::window(c.bins, c.d_net, c.B, c.f, c.N, c.author), c.R);
        rec.sel(name + "/select", sel);
        count_list_regimes(rec, c, e, sel);
    }
    Rng srng(kSeed ^ 0x53544F5245ull);
    for (std::size_t i = 0; i < kStoreCases; ++i) {
        const std::size_t before = rec.recs.size();
        gen_store_case(rec, srng, pool, i, id_ctr);
        for (std::size_t k = before; k < rec.recs.size(); ++k) {
            const std::vector<std::uint8_t>& b = rec.recs[k].bytes;
            if (b.size() < 2 || b[0] != 0x04) continue;
            const auto d = static_cast<pb::WindowDefer>(b[1]);
            if (d == pb::WindowDefer::MissingBucket) ++rec.regime[RgMissingBucket];
            if (d == pb::WindowDefer::MissingEntries) ++rec.regime[RgMissingEntries];
            if (d == pb::WindowDefer::SealedCut) ++rec.regime[RgSealedCut];
        }
    }
}

// ---------------------------------------------------------------------------
// The golden text: a header, then one line per record: name, length, and
// sha256d of the record bytes. The raw stream holds every record in full.
// ---------------------------------------------------------------------------
inline std::string golden_text(const std::vector<std::string>& header, const Recorder& rec) {
    std::string out;
    for (const std::string& h : header) out += "# " + h + "\n";
    std::uint64_t total = 0;
    for (const Recorder::Rec& r : rec.recs) total += r.bytes.size();
    out += "# records " + std::to_string(rec.recs.size()) + " bytes " + std::to_string(total) + "\n";
    for (const Recorder::Rec& r : rec.recs) {
        const pb::Hash32 d = ::v37::sha256d(r.bytes);
        out += r.name + "\t" + std::to_string(r.bytes.size()) + "\t" + pathb_kat::hex(d.data(), d.size()) + "\n";
    }
    return out;
}

inline std::vector<std::uint8_t> golden_raw(const Recorder& rec) {
    Bytes o;
    for (const Recorder::Rec& r : rec.recs) {
        o.raw(std::vector<std::uint8_t>(r.name.begin(), r.name.end()));
        o.raw(r.bytes);
    }
    return std::move(o.b);
}

// Every vector, in a fixed order.
inline void all_vectors(Recorder& rec) {
    kat_xmr_window(rec);
    kat_xmr_window_split(rec);
    kat_xmr_window_spend_floor(rec);
    kat_xmr_window_merge_back(rec);
    kat_v37_xmr_window_branch(rec);
    kat_v37_xmr_window_fork_height(rec);
    kat_v37_xmr_pathb_coinbase(rec);
    corner_vectors(rec);
    sealed_cut_vectors(rec);
    seeded_vectors(rec);
}

}  // namespace ring_c1
