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
// ---------------------------------------------------------------------------
#include <cstdint>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_branch.hpp"
#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_branch_view.hpp"
#include "pathb_kat_check.hpp"

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

}  // namespace

int main() {
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
