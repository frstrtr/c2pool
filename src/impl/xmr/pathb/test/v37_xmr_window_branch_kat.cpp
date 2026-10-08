// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_window_branch_kat (pathb_window.hpp / pathb_branch.hpp /
// pathb_emission.hpp, C41): the window of the block's OWN tip. Two tips with
// different D_net compute different windows for the same receipts; two nodes
// with different Monero main tips (main 102 / main 100) compute one window and
// one split for receipts on P_t = main 100, from select_window_inputs; D_net
// read at the node's own main tip gives another window; B(A_t) is the weight
// input at the anchor of the tip's own branch (main 40 / side 40); chain start
// h(P_t) <= K_A -> A_t = genesis, B(A_t) at agc 0.
// S3b-1b (pathb_branch_follower.hpp, pathb_window_chain.hpp,
// pathb_window_cache.hpp; C41): a race at h 140 with a depth-2 reorg; node X
// follows A1, A2, node Y follows B1, B2, each holding the other side as alt rows
// without RowWeights. For a tip t whose P_t is the common ancestor (Monero 139)
// both nodes read one WindowInputs and compute one window(t, 16), one
// window_root and mmr_root, and one canonical coinbase (the same tx hash, Match
// on both); D_net for a child of each node's own main tip differs and gives
// another window; tips on A2 and on B2 (alt without RowWeights on one node)
// resolve on both nodes to the same windows.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_branch.hpp"
#include "impl/xmr/pathb/pathb_branch_follower.hpp"
#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "impl/xmr/pathb/pathb_window_cache.hpp"
#include "pathb_kat_branch_view.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_kat_lane.hpp"
#include "pathb_kat_miner.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

constexpr std::uint8_t kMain = 0x4d;
constexpr std::uint8_t kSide = 0x53;

pb::Hash32 rep(std::uint8_t b) { pb::Hash32 h{}; h.fill(b); return h; }
pb::WinEntry e(std::uint8_t m, std::uint64_t w, std::uint64_t pos) {
    pb::WinEntry x; x.miner = rep(m); x.work = w; x.position = pos; x.id = rep(m); return x;
}

// main 0..top: difficulty 1000 + h, 120 s apart, agc after h = h x 10^13.
KatBranchView main_chain(std::uint64_t top) {
    KatBranchView v;
    pb::Hash32 parent{};
    for (std::uint64_t h = 0; h <= top; ++h)
        parent = v.add(kMain, h, parent, 1600000000ull + 120 * h, 1000 + h, h * 10000000000000ull, 300000, 300000);
    return v;
}

// The window of a tip whose Monero parent is p_t, every input from the branch.
pb::Window window_on(const KatBranchView& v, const pb::Hash32& p_t, const std::vector<pb::WinBin>& bins,
                     pb::WindowInputs& in, bool& ok) {
    ok = pb::select_window_inputs(v, p_t, 16, in).selected() && in.d_net.hi == 0;
    const std::uint64_t B = in.weights.base_reward;
    return pb::window(bins, in.d_net.lo, B, pb::f_spend(B, in.weights.fee_median, 16),
                      pb::n_rule(in.weights.zone, 16, B), pb::Hash32{});
}

// ---- S3b-1b: the race through the follower view, the store and the cache ----
void s3b_race() {
    constexpr std::uint8_t kC = 0x4d, kA = 0x41, kB = 0x42;
    constexpr std::uint64_t hr = 140;  // the race height
    auto ts = [](std::uint64_t h) { return 1600000000ull + 120 * h; };
    const pb::RowWeights tail = rw(kTailAgc, 300000, 300000);
    KatMoneroRows x = monero_chain(kC, hr - 1, 10000000ull,
                                   [&](std::uint64_t) { return std::optional<pb::RowWeights>(tail); });
    KatMoneroRows y = x;
    const pb::Hash32 c = block_id(kC, hr - 1);
    // node X: main A1, A2 (difficulty 1e9) with RowWeights; alt B1, B2 without.
    const pb::Hash32 a1 = x.add(kA, hr, c, ts(hr) + 5, 1000000000ull, tail, true);
    const pb::Hash32 a2 = x.add(kA, hr + 1, a1, ts(hr + 1) + 5, 1000000000ull, tail, true);
    const pb::Hash32 b1 = x.add(kB, hr, c, ts(hr) + 9, 500000000ull, std::nullopt, false);
    const pb::Hash32 b2 = x.add(kB, hr + 1, b1, ts(hr + 1) + 9, 500000000ull, std::nullopt, false);
    // node Y: main B1, B2 with RowWeights; alt A1, A2 without.
    y.add(kB, hr, c, ts(hr) + 9, 500000000ull, tail, true);
    y.add(kB, hr + 1, b1, ts(hr + 1) + 9, 500000000ull, tail, true);
    y.add(kA, hr, c, ts(hr) + 5, 1000000000ull, std::nullopt, false);
    y.add(kA, hr + 1, a1, ts(hr + 1) + 5, 1000000000ull, std::nullopt, false);
    check(x.main_tip() == a2 && y.main_tip() == b2 && !x.weights(b2) && !y.weights(a2),
          "race: X follows A2, Y follows B2; each holds the other side without RowWeights");
    const pb::FollowerBranchView vx(x), vy(y);

    // the lane: carriers 1..40 at h = 100 + pos (P = Monero 99 + pos), then two
    // carriers at 41: on A2 (h 142, best) and on B2 (h 142, side). Both nodes
    // hold the same lane.
    RefBook book;
    std::vector<pb::Hash32> payees;
    for (std::uint64_t k = 0; k < 8; ++k) payees.push_back(book.add(ref_from_secrets(1000 + k, 2000 + k)));
    constexpr std::uint64_t b0 = 100;
    pb::BinStore sx(pb::kRuledLaneParams, 64, idn(0xC8, 0), b0), sy(pb::kRuledLaneParams, 64, idn(0xC8, 0), b0);
    bool ok = true;
    for (pb::BinStore* st : {&sx, &sy}) {
        for (std::uint64_t pos = 1; pos <= 40; ++pos)
            ok = ok && extend(*st, idn(0xC8, pos), idn(0xC8, pos - 1), b0 + pos,
                              {rcpt(idn(0xD8, pos), b0 + pos, pos, payees[pos % 8], 1000000)}, true);
        ok = ok && extend(*st, idn(0xCA, 41), idn(0xC8, 40), hr + 2,
                          {rcpt(idn(0xDA, 41), hr + 2, 41, payees[1], 1000000)}, true);
        ok = ok && extend(*st, idn(0xCB, 41), idn(0xC8, 40), hr + 2,
                          {rcpt(idn(0xDB, 41), hr + 2, 41, payees[2], 1000000)}, false);
    }
    check(ok, "race: both nodes hold the lane (40 carriers, two siblings at 41)");
    const pb::XmrKeyRef author = kat_author();
    const pb::Hash32 author_id = pb::key_ref_identity(author);
    const pb::Hash32 t = idn(0xC8, 40);

    pb::WindowCache cx, cy;
    const pb::TipWindow wx = cx.get(t, 16, [&] { return pb::evaluate_window_at(sx, t, c, vx, 16, author_id); });
    const pb::TipWindow wy = cy.get(t, 16, [&] { return pb::evaluate_window_at(sy, t, c, vy, 16, author_id); });
    check(wx.ok() && wy.ok(), "race: P_t = Monero 139 (common): window(t, 16) evaluated on both nodes");
    check(wx.ok() && wy.ok() && wx.inputs.d_net == wy.inputs.d_net && wx.inputs.a_t == wy.inputs.a_t
                  && wx.inputs.weights == wy.inputs.weights && wx.inputs.d_net.lo == 10000000ull,
          "race: one WindowInputs on both nodes (D_net 10,000,000 for a child of Monero 139)");
    check(wx.ok() && wy.ok() && wx.window->weight == wy.window->weight && wx.window->W == wy.window->W
                  && wx.window->W == pb::Work(20000000ull),
          "race: one window on both nodes (20 newest bins, W 20,000,000)");
    check(wx.ok() && wy.ok() && wx.window_root == wy.window_root && wx.mmr_root == wy.mmr_root,
          "race: one window_root and one mmr_root on both nodes");

    // one canonical coinbase on both sides: a receipt on t whose own P_r is A2.
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
        r.reward_total = 600000000000ull + 1500000000ull;
        const std::uint64_t h_r = hr + 2;  // height(A2) + 1
        check(wx.ok() && commit_miner_tx(r, *wx.window, t, a2, h_r, book, author), "race: the miner commits its coinbase");
        pb::KeyCache kx, ky;
        const pb::CoinbaseCheck ox =
                pb::canonical_coinbase_check(r, pb::window_at(wx), t, a2, h_r, 16, kx, book.lookup(), author);
        const pb::CoinbaseCheck oy =
                pb::canonical_coinbase_check(r, pb::window_at(wy), t, a2, h_r, 16, ky, book.lookup(), author);
        check(ox == pb::CoinbaseCheck::Match && oy == pb::CoinbaseCheck::Match, "race: the coinbase check Matches on both nodes");
        const pb::CanonicalTx tx = pb::canonical_miner_tx(r, pb::window_at(wx), t, a2, h_r, 16, kx, book.lookup(), author);
        const pb::CanonicalTx ty = pb::canonical_miner_tx(r, pb::window_at(wy), t, a2, h_r, 16, ky, book.lookup(), author);
        check(tx.tx && ty.tx && tx.tx->tx_hash == ty.tx->tx_hash && tx.tx->outs.size() == 8,
              "race: one canonical miner tx (the same tx hash, 8 outputs) on both nodes");
    }

    // the node's own main tip is another read point (the control).
    {
        pb::U128 dx{}, dy{};
        check(pb::dnet_for_child(vx, vx.main_tip(), 16, dx).selected()
                      && pb::dnet_for_child(vy, vy.main_tip(), 16, dy).selected() && !(dx == dy)
                      && !(dx == wx.inputs.d_net),
              "race: D_net for a child of each node's own main tip differs");
        const pb::TipWindow own = pb::evaluate_window_at(sx, t, vx.main_tip(), vx, 16, author_id);
        check(own.ok() && wx.ok() && !(own.window_root == wx.window_root),
              "race: a window read at X's own main tip differs");
    }

    // tips on A2 and on B2: the alt side without RowWeights still resolves.
    for (const auto& [tip, p] : {std::pair<pb::Hash32, pb::Hash32>{idn(0xCA, 41), a2},
                                 std::pair<pb::Hash32, pb::Hash32>{idn(0xCB, 41), b2}}) {
        const pb::TipWindow ox = pb::evaluate_window_at(sx, tip, p, vx, 16, author_id);
        const pb::TipWindow oy = pb::evaluate_window_at(sy, tip, p, vy, 16, author_id);
        const std::string tag = p == a2 ? "A2" : "B2";
        check(ox.ok() && oy.ok() && ox.inputs.a_t == block_id(kC, 81) && oy.inputs.a_t == block_id(kC, 81)
                      && ox.inputs.d_net == oy.inputs.d_net,
              "race: P_t = " + tag + ": A_t = Monero 81 on both nodes, one D_net");
        check(ox.ok() && oy.ok() && ox.window_root == oy.window_root && ox.mmr_root == oy.mmr_root,
              "race: P_t = " + tag + ": one window_root on both nodes");
    }
}

}  // namespace

int main() {
    s3b_race();

    const std::uint64_t B = 600000000000ull;
    const std::uint64_t f = 1;  // loose
    const pb::Hash32 author{};

    // the same bins, read at two tips with different D_net, give two windows.
    std::vector<pb::WinBin> bins;
    for (int i = 0; i < 10; ++i) bins.push_back({static_cast<std::uint64_t>(10 - i), {e(static_cast<std::uint8_t>(0x80 + i), 100, 100 - i)}});
    const std::uint64_t d_net_tip_t = 150;  // own tip t
    const std::uint64_t d_net_tip_u = 450;  // neighbouring tip u
    const auto sel_t = pb::select_window_bins(bins, d_net_tip_t, B, f);
    const auto sel_u = pb::select_window_bins(bins, d_net_tip_u, B, f);
    check(sel_t.size() == 3 && sel_u.size() == 9, "each tip resolves its OWN window (D_net at the tip)");
    const pb::Window wt = pb::window(bins, d_net_tip_t, B, f, 3747, author);
    const pb::Window wu = pb::window(bins, d_net_tip_u, B, f, 3747, author);
    check(!(pb::window_root(wt) == pb::window_root(wu)), "different tips -> different window_root");

    // a receipt naming a neighbouring tip gets THAT tip's window (here: u's D_net).
    check(pb::window_root(pb::window(bins, d_net_tip_u, B, f, 3747, author)) == pb::window_root(wu),
          "a receipt on tip u gets tip u's window");

    // ---- a race: node X follows main to 102, node Y holds main to 100 ----
    {
        const KatBranchView x = main_chain(102);
        const KatBranchView y = main_chain(100);
        std::vector<pb::WinBin> unit;  // 3,000 bins of one entry of work 1, newest first
        for (std::uint64_t k = 0; k < 3000; ++k)
            unit.push_back({100000 - k, {e(static_cast<std::uint8_t>(0x10 + k % 8), 1, 900000 - k)}});
        pb::WindowInputs ix, iy, iown;
        bool okx = false, oky = false, okown = false;
        const pb::Window wx = window_on(x, block_id(kMain, 100), unit, ix, okx);
        const pb::Window wy = window_on(y, block_id(kMain, 100), unit, iy, oky);
        check(okx && oky, "P_t = main 100: window inputs selected on both nodes");
        check(ix.d_net == iy.d_net && ix.a_t == iy.a_t && ix.weights == iy.weights,
              "both nodes read the same D_net, A_t and weight inputs for P_t = main 100");
        check(pb::window_root(wx) == pb::window_root(wy) && !wx.weight.empty(), "both nodes: one window_root");
        const std::uint64_t R = ix.weights.base_reward + 7000000000ull;
        const auto sx = pb::split(R, wx), sy = pb::split(R, wy);
        bool same = sx.size() == sy.size() && !sx.empty();
        for (std::size_t i = 0; same && i < sx.size(); ++i)
            same = sx[i].payee == sy[i].payee && sx[i].amount == sy[i].amount;
        check(same, "both nodes: one split");
        // D_net read at node X's own main tip (main 102) is another value and another window.
        const pb::Window wown = window_on(x, block_id(kMain, 102), unit, iown, okown);
        check(okown && !(iown.d_net == ix.d_net), "D_net for a child of main 102 differs from P_t = main 100");
        check(!(pb::window_root(wown) == pb::window_root(wx)), "a window from the node's own main tip differs");
    }

    // ---- B(A_t) at the anchor of the tip's own branch ----
    {
        KatBranchView v = main_chain(100);
        pb::Hash32 parent = block_id(kMain, 30);
        for (std::uint64_t h = 31; h <= 100; ++h)  // side branch on main 30, agc after h = h x 2 x 10^13
            parent = v.add(kSide, h, parent, 1600000000ull + 120 * h + 7, 1001 + h, h * 20000000000000ull, 300000,
                           300000);
        pb::WindowInputs im, is;
        check(pb::select_window_inputs(v, block_id(kMain, 100), 16, im).selected() && im.a_t == block_id(kMain, 40)
                      && im.weights.base_reward == 35183609149378ull,
              "P_t = main 100: A_t = main 40, B(A_t) == 35,183,609,149,378");
        check(pb::select_window_inputs(v, block_id(kSide, 100), 16, is).selected() && is.a_t == block_id(kSide, 40)
                      && is.weights.base_reward == 35182846209925ull,
              "P_t = side 100: A_t = side 40, B(A_t) == 35,182,846,209,925 (the side branch's supply)");
    }

    // ---- chain start: h(P_t) <= K_A (60) -> A_t = genesis (agc 0) ----
    {
        const std::uint64_t K_A = pb::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
        check(K_A == 60, "K_A == CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW (60)");
        const KatBranchView v = main_chain(100);
        for (const std::uint64_t h : {std::uint64_t{1}, std::uint64_t{30}, std::uint64_t{60}}) {
            pb::WindowInputs w;
            check(pb::select_window_inputs(v, block_id(kMain, h), 16, w).selected() && w.a_t == block_id(kMain, 0)
                          && w.a_t_height == 0 && w.weights.base_reward == 35184372088831ull,
                  "chain start: P_t = main " + std::to_string(h) + " -> A_t = genesis, B(A_t) == 35,184,372,088,831");
        }
        pb::WindowInputs w;
        check(pb::select_window_inputs(v, block_id(kMain, 61), 16, w).selected() && w.a_t == block_id(kMain, 1)
                      && w.weights.base_reward == 35184353015345ull,
              "P_t = main 61 -> A_t = main 1, B(A_t) == 35,184,353,015,345");
    }

    return finish("v37_xmr_window_branch_kat");
}
