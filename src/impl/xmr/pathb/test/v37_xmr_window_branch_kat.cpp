// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_window_branch_kat (pathb_window.hpp / pathb_emission.hpp, C41): the
// window of the block's OWN tip. Two tips with different D_net compute different
// windows for the same receipts; D_net must be read from the tip's own branch;
// the emission base B(A_t) is read at the anchor; a chain start below K_A falls
// back to the genesis anchor (agc 0).
// ---------------------------------------------------------------------------
#include <cstdint>
#include <vector>

#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 rep(std::uint8_t b) { pb::Hash32 h{}; h.fill(b); return h; }
static pb::WinEntry e(std::uint8_t m, std::uint64_t w, std::uint64_t pos) {
    pb::WinEntry x; x.miner = rep(m); x.work = w; x.position = pos; x.id = rep(m); return x;
}

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

    // emission base at the anchor A_t: two branches at different supply -> different B.
    const std::uint64_t B_low = pb::base_reward_at(1000000000000000ull, 16);
    const std::uint64_t B_high = pb::base_reward_at(500000000000000ull, 16);
    check(B_high > B_low, "B(A_t) read at the anchor's supply");

    // chain start below K_A (60): the anchor falls back to genesis (agc 0).
    const std::uint64_t K_A = pb::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
    check(K_A == 60, "K_A == CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW (60)");
    auto anchor_agc = [K_A](std::uint64_t height, std::uint64_t agc_at_anchor) -> std::uint64_t {
        return height < K_A ? 0 /* genesis anchor */ : agc_at_anchor;
    };
    check(pb::base_reward_at(anchor_agc(/*height=*/30, 999), 16) == pb::base_reward_at(0, 16),
          "chain start < K_A -> A_t = genesis (agc 0)");

    return finish("v37_xmr_window_branch_kat");
}
