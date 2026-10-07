// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_pathb_branch_kat.cpp
// Window inputs from the branch of prev_id(tip), over synthetic branches:
//   main chain 0..802; side branch S2 at heights 799..800 on main 798 (fork
//   2 deep); side branch S100 at heights 701..800 on main 700 (fork 100 deep).
//   (1) P_t = main 800 while the node's main tip is 802: D_net equals the
//       native rolling window over main 66..800, not the value for a child of
//       main 802; A_t = main 740; weights read at main 740;
//   (2) P_t = S2 800: D_net equals next_difficulty over main 66..798 + S2
//       799..800 (the newest DIFFICULTY_LAG rows do not enter the retarget, so
//       it also equals the main 800 value); A_t = main 740;
//   (3) P_t = S100 800: D_net over main 66..700 + S100 701..800, different
//       from the main-chain value at the same height; A_t = S100 740, weights
//       of S100 740, not main 740;
//   (4) chain start: P_t at 30 -> A_t = genesis, 30 rows; P_t = genesis ->
//       empty window;
//   (5) missing P_t, a missing block inside the window, missing weights at
//       A_t, heights that do not follow parent links: Defer naming the id;
//       no other outcome.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_branch.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;
namespace nat = ::c2pool::xmr::native;

namespace {

constexpr std::uint8_t kMain = 0x4d;
constexpr std::uint8_t kS2 = 0x32;
constexpr std::uint8_t kS100 = 0x64;
constexpr std::uint8_t kHf = 16;

pb::Hash32 bid(std::uint8_t tag, std::uint64_t h) {
    pb::Hash32 id{};
    id[0] = tag;
    for (int i = 0; i < 8; ++i) id[1 + i] = static_cast<std::uint8_t>(h >> (8 * i));
    id[31] = 0x99;
    return id;
}

class MapView final : public pb::IBranchView {
public:
    std::map<pb::Hash32, pb::BranchBlock> blocks;
    std::map<pb::Hash32, pb::WeightInputs> weights;

    std::optional<pb::BranchBlock> block(const pb::Hash32& id) const override {
        auto it = blocks.find(id);
        if (it == blocks.end()) return std::nullopt;
        return it->second;
    }
    std::optional<pb::WeightInputs> weights_at(const pb::Hash32& id) const override {
        auto it = weights.find(id);
        if (it == weights.end()) return std::nullopt;
        return it->second;
    }

    void add(std::uint8_t tag, std::uint64_t h, const pb::Hash32& parent, std::uint64_t ts, std::uint64_t diff,
             std::uint64_t wseed) {
        pb::BranchBlock b;
        b.id = bid(tag, h);
        b.prev_id = parent;
        b.height = h;
        b.timestamp = ts;
        nat::U128 prev_cum{};
        if (h > 0) prev_cum = blocks.at(parent).cumulative_difficulty;
        b.cumulative_difficulty = nat::u128_add(prev_cum, nat::U128{diff, 0});
        blocks[b.id] = b;
        weights[b.id] = pb::WeightInputs{600000000000ull, 300000 + wseed, 300000 + 2 * wseed, 100000 + 3 * wseed};
    }
};

std::uint64_t ts_main(std::uint64_t h) { return 1600000000ull + 120 * h + (h * 7919) % 37; }
std::uint64_t diff_main(std::uint64_t h) { return 300000000000ull + (h % 11) * 1000000ull; }

MapView build() {
    MapView v;
    for (std::uint64_t h = 0; h <= 802; ++h) v.add(kMain, h, h ? bid(kMain, h - 1) : pb::Hash32{}, ts_main(h), diff_main(h), h);
    // S2: faster timestamps, higher difficulty
    v.add(kS2, 799, bid(kMain, 798), ts_main(798) + 20, diff_main(799) * 3, 5000 + 799);
    v.add(kS2, 800, bid(kS2, 799), ts_main(798) + 40, diff_main(800) * 3, 5000 + 800);
    // S100
    for (std::uint64_t h = 701; h <= 800; ++h)
        v.add(kS100, h, h == 701 ? bid(kMain, 700) : bid(kS100, h - 1), ts_main(h) + 7, diff_main(h) + 5000000,
              9000 + h);
    return v;
}

nat::U128 dnet_over(const MapView& v, const std::vector<pb::Hash32>& ids) {
    std::vector<std::uint64_t> ts;
    std::vector<nat::U128> cd;
    for (const pb::Hash32& id : ids) {
        ts.push_back(v.blocks.at(id).timestamp);
        cd.push_back(v.blocks.at(id).cumulative_difficulty);
    }
    return nat::next_difficulty_from_window(ts, cd, nat::DIFFICULTY_TARGET_V2);
}

std::vector<pb::Hash32> main_ids(std::uint64_t lo, std::uint64_t hi) {
    std::vector<pb::Hash32> ids;
    for (std::uint64_t h = lo; h <= hi; ++h) ids.push_back(bid(kMain, h));
    return ids;
}

}  // namespace

int main() {
    std::printf("v37_xmr_pathb_branch_kat\n");
    const MapView v = build();

    // (1) main chain
    {
        pb::WindowInputs w;
        const pb::BranchStatus s = pb::select_window_inputs(v, bid(kMain, 800), kHf, w);
        check(s.selected(), "main 800 selected");
        check(w.tip_height == 801 && w.p_t_height == 800, "h(t) = height(P_t) + 1 = 801");
        nat::DifficultyWindow dw;
        for (std::uint64_t h = 1; h <= 800; ++h) dw.push(ts_main(h), v.blocks.at(bid(kMain, h)).cumulative_difficulty);
        check(dw.size() == 735, "native rolling window holds 735 rows");
        check(w.d_net == dw.next_difficulty(kHf), "D_net equals the native rolling window over main 66..800");
        check(w.d_net == dnet_over(v, main_ids(66, 800)), "D_net equals next_difficulty over main 66..800");
        check(!(w.d_net == dnet_over(v, main_ids(65, 800))), "a 736-row window gives a different value");
        check(!(w.d_net == dnet_over(v, main_ids(68, 802))), "the node's own main tip (802) gives a different value");
        check(w.a_t == bid(kMain, 740) && w.a_t_height == 740, "A_t = main 740 (60 below P_t)");
        check(w.weights == v.weights.at(bid(kMain, 740)), "weights read at main 740");
        pb::DifficultyWindowRows rows;
        check(pb::difficulty_window_for_child(v, bid(kMain, 800), rows).selected() && rows.timestamps.size() == 735
                      && rows.timestamps.front() == ts_main(66) && rows.timestamps.back() == ts_main(800),
              "window rows: 735, oldest first, heights 66..800");
    }

    // (2) fork 2 deep
    {
        pb::WindowInputs w;
        const pb::BranchStatus s = pb::select_window_inputs(v, bid(kS2, 800), kHf, w);
        check(s.selected(), "S2 800 selected");
        std::vector<pb::Hash32> ids = main_ids(66, 798);
        ids.push_back(bid(kS2, 799));
        ids.push_back(bid(kS2, 800));
        const nat::U128 branch_dnet = dnet_over(v, ids);
        const nat::U128 by_height = dnet_over(v, main_ids(66, 800));
        check(w.d_net == branch_dnet, "fork 2 deep: D_net over main 66..798 + S2 799..800");
        check(branch_dnet == by_height, "fork 2 deep: the newest DIFFICULTY_LAG rows do not enter the retarget");
        check(w.a_t == bid(kMain, 740), "fork 2 deep: A_t = main 740");
        check(w.weights == v.weights.at(bid(kMain, 740)), "fork 2 deep: weights of main 740");
        pb::U128 d799;
        check(pb::dnet_for_child(v, bid(kS2, 799), kHf, d799).selected(), "D_net for a child of S2 799");
        std::vector<pb::Hash32> ids799 = main_ids(65, 798);
        ids799.push_back(bid(kS2, 799));
        check(d799 == dnet_over(v, ids799), "D_net for a child of S2 799 over main 65..798 + S2 799");
    }

    // (3) fork 100 deep
    {
        pb::WindowInputs w;
        const pb::BranchStatus s = pb::select_window_inputs(v, bid(kS100, 800), kHf, w);
        check(s.selected(), "S100 800 selected");
        check(w.a_t == bid(kS100, 740) && w.a_t_height == 740, "fork 100 deep: A_t = S100 740");
        check(w.weights == v.weights.at(bid(kS100, 740)), "fork 100 deep: weights of S100 740");
        check(!(w.weights == v.weights.at(bid(kMain, 740))), "fork 100 deep: not the weights of main 740");
        std::vector<pb::Hash32> ids = main_ids(66, 700);
        for (std::uint64_t h = 701; h <= 800; ++h) ids.push_back(bid(kS100, h));
        check(w.d_net == dnet_over(v, ids), "fork 100 deep: D_net over main 66..700 + S100 701..800");
        check(!(w.d_net == dnet_over(v, main_ids(66, 800))), "fork 100 deep: the by-height main-chain value differs");
        pb::BranchBlock a;
        check(pb::ancestor_on_branch(v, bid(kS100, 800), 100, a).selected() && a.id == bid(kMain, 700),
              "100 parent links from S100 800 reach main 700");
    }

    // (4) chain start
    {
        pb::WindowInputs w;
        check(pb::select_window_inputs(v, bid(kMain, 30), kHf, w).selected(), "main 30 selected");
        check(w.a_t == bid(kMain, 0) && w.a_t_height == 0, "chain start: A_t = genesis");
        check(w.d_net == dnet_over(v, main_ids(1, 30)), "chain start: 30 rows, genesis skipped");
        check(w.weights == v.weights.at(bid(kMain, 0)), "chain start: weights of genesis");
        pb::WindowInputs g;
        check(pb::select_window_inputs(v, bid(kMain, 0), kHf, g).selected(), "genesis selected");
        check(g.d_net == nat::U128{1, 0} && g.a_t == bid(kMain, 0), "genesis: empty window gives 1, A_t = genesis");
        pb::WindowInputs w60;
        check(pb::select_window_inputs(v, bid(kMain, 60), kHf, w60).selected() && w60.a_t == bid(kMain, 0),
              "P_t at 60: A_t = genesis");
        pb::WindowInputs w61;
        check(pb::select_window_inputs(v, bid(kMain, 61), kHf, w61).selected() && w61.a_t == bid(kMain, 1),
              "P_t at 61: A_t = main 1");
    }

    // (5) defer
    {
        pb::WindowInputs w;
        const pb::Hash32 unknown = bid(0x77, 5);
        pb::BranchStatus s = pb::select_window_inputs(v, unknown, kHf, w);
        check(s.verdict == pb::BranchVerdict::Defer && s.reason == pb::DeferReason::MissingBlock && s.missing == unknown,
              "unknown P_t: Defer naming P_t");

        MapView gap = v;
        gap.blocks.erase(bid(kS2, 799));
        s = pb::select_window_inputs(gap, bid(kS2, 800), kHf, w);
        check(s.verdict == pb::BranchVerdict::Defer && s.reason == pb::DeferReason::MissingBlock
                      && s.missing == bid(kS2, 799),
              "missing S2 799: Defer naming S2 799");

        MapView deep = v;
        deep.blocks.erase(bid(kMain, 100));
        s = pb::select_window_inputs(deep, bid(kMain, 800), kHf, w);
        check(s.verdict == pb::BranchVerdict::Defer && s.missing == bid(kMain, 100),
              "missing main 100 inside the 735-row window: Defer naming main 100");
        s = pb::select_window_inputs(deep, bid(kMain, 50), kHf, w);
        check(s.selected(), "P_t at 50 (window 1..50) does not need main 100");

        MapView now = v;
        now.weights.erase(bid(kS100, 740));
        s = pb::select_window_inputs(now, bid(kS100, 800), kHf, w);
        check(s.verdict == pb::BranchVerdict::Defer && s.reason == pb::DeferReason::MissingWeights
                      && s.missing == bid(kS100, 740),
              "missing weights at S100 740: Defer naming S100 740");

        MapView bad = v;
        bad.blocks[bid(kS2, 799)].height = 805;
        s = pb::select_window_inputs(bad, bid(kS2, 800), kHf, w);
        check(s.verdict == pb::BranchVerdict::Defer && s.reason == pb::DeferReason::Inconsistent,
              "parent height not one below its child: Defer (inconsistent)");
    }

    return finish("v37_xmr_pathb_branch_kat");
}
