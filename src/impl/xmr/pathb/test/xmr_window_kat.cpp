// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// xmr_window_kat (pathb_window.hpp, C38, K09): whole bins back to COVERAGE x
// D_net, NO DECAY (an old entry weighs as much as a new one), the window of the
// block's OWN tip, the N rule with N(B) window slots (no reserved slot), the
// Merkle-SUM window_root recomputed and non-zero (the golden node), the empty
// window -> finder-only.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <vector>

#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 rep(std::uint8_t b) { pb::Hash32 h{}; h.fill(b); return h; }
static std::string hx(const pb::Hash32& h) { return hex(h.data(), h.size()); }

static pb::WinEntry entry(std::uint8_t miner, std::uint64_t work, std::uint64_t pos) {
    pb::WinEntry e;
    e.miner = rep(miner);
    e.work = work;
    e.position = pos;
    e.id = rep(miner);
    return e;
}

int main() {
    const pb::Hash32 author{};          // zero author: donation merges back
    const std::uint64_t B = 600000000000ull;  // 6e11
    const std::uint64_t f_spend = 1;    // loose: W_max never binds here
    const std::uint64_t N = 3747;       // N(B) at Z 300000, hf 16

    // ---- the golden Merkle-SUM window node (S3.2) ----
    {
        pb::Window w;
        w.weight[rep(0xAA)] = pb::Work(119880);
        w.weight[rep(0xBB)] = pb::Work(89900);
        w.W = pb::Work(209780);
        pb::Work sum;
        const pb::Hash32 wr = pb::window_root(w, &sum);
        check(hx(pb::window_sum_leaf(rep(0xAA), pb::Work(119880))) ==
                      "ab0fc9f834c3bb0776e629fcbad11c1746da0289ae89c698f58c781666669591",
              "golden window leaf (0xAA, 119880)");
        check(hx(wr) == "b97ea1ebcd7303e4d9b87012c962f5ac8ceaf21c243dbeff032e0003f3ea234b",
              "golden window node");
        check(sum == pb::Work(209780), "window_root sum == W (209780)");
        check(!(wr == pb::Hash32{}), "window_root non-zero (lifts the S1/S2 stub)");
    }

    // ---- NO DECAY: an entry 3 bins old weighs as much as a fresh one ----
    {
        std::vector<pb::WinBin> bins;
        bins.push_back({3, {entry(0x01, 100, 30)}});   // newest
        bins.push_back({2, {entry(0x02, 100, 20)}});
        bins.push_back({1, {entry(0x03, 100, 10)}});   // oldest
        const pb::Window w = pb::window(bins, /*D_net=*/1000, B, f_spend, N, author);
        check(w.weight.at(rep(0x01)) == w.weight.at(rep(0x03)), "no decay: old entry weighs same as new");
        check(w.W == pb::Work(300), "W == total raw work");
    }

    // ---- COVERAGE: whole bins back until raw work reaches COVERAGE x D_net ----
    {
        std::vector<pb::WinBin> bins;
        for (int i = 0; i < 6; ++i) bins.push_back({static_cast<std::uint64_t>(6 - i), {entry(static_cast<std::uint8_t>(0x40 + i), 100, 60 - i)}});
        // D_net = 75 -> COVERAGE x D_net = 150; two 100-work bins cross it.
        const auto sel = pb::select_window_bins(bins, /*D_net=*/75, B, f_spend);
        check(sel.size() == 2, "coverage 2 x D_net selects the 2 newest bins");
    }

    // ---- the window is read at the block's OWN tip (different D_net -> different window) ----
    {
        std::vector<pb::WinBin> bins;
        for (int i = 0; i < 10; ++i) bins.push_back({static_cast<std::uint64_t>(10 - i), {entry(static_cast<std::uint8_t>(0x50 + i), 100, 100 - i)}});
        check(pb::select_window_bins(bins, 150, B, f_spend).size() == 3, "own tip D_net 150 -> 3 bins");
        check(pb::select_window_bins(bins, 450, B, f_spend).size() == 9, "own tip D_net 450 -> 9 bins");
    }

    // ---- empty window -> finder-only (D2.7 step 6) ----
    {
        std::vector<pb::WinBin> none;
        const pb::Window w = pb::window(none, 1000, B, f_spend, N, author);
        check(w.empty_finder_only, "empty window -> one output of R to the finder");
        check(pb::window_root(w) == pb::Hash32{}, "empty window_root == 32 zero bytes");
    }

    return finish("xmr_window_kat");
}
