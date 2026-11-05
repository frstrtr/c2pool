// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// xmr_epoch_accounting_kat (C24; pathb_window.hpp across an activation):
//   across an epoch that keeps weight semantics, every receipt placed before
//   H_act keeps its weight and is counted exactly once in every window that
//   covers it, on every node, under the old and the new rules; a synthetic
//   epoch that adds raindrop entries from H_act on leaves every
//   pre-activation weight unchanged.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <map>
#include <vector>

#include "impl/xmr/pathb/pathb_ratchet_activation.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

pb::Hash32 id_of(std::uint8_t a, std::uint8_t b) {
    pb::Hash32 h{};
    h[0] = a;
    h[1] = b;
    return h;
}

struct Built {
    std::vector<pb::WinBin> bins;  // newest first
    std::uint64_t h_act = 0;
};

// 40 bins of 3 receipts each, one bin per 12 positions; H_act at the 20th bin.
Built chain(bool raindrops) {
    Built b;
    b.h_act = 20 * 12;
    std::vector<pb::WinBin> asc;
    for (std::uint64_t i = 0; i < 40; ++i) {
        pb::WinBin bin;
        bin.bin = 3000000 + i;
        for (std::uint8_t m = 0; m < 3; ++m) {
            pb::WinEntry e;
            e.miner = id_of(0x10 + m, 0);
            e.work = 1000000 + 1000 * i + m;
            e.position = i * 12 + m;
            e.id = id_of(0x80 + static_cast<std::uint8_t>(i), m);
            e.give_author_bp = 10;
            bin.entries.push_back(e);
        }
        if (raindrops && i * 12 >= b.h_act) {  // the synthetic epoch's extra entries from H_act on
            pb::WinEntry r;
            r.miner = id_of(0x40, 0);
            r.work = 500000;
            r.position = i * 12 + 5;
            r.id = id_of(0xc0 + static_cast<std::uint8_t>(i % 0x3f), 9);
            bin.entries.push_back(r);
        }
        asc.push_back(bin);
    }
    b.bins.assign(asc.rbegin(), asc.rend());
    return b;
}

}  // namespace

int main() {
    const pb::Hash32 author = pb::author_identity(pb::LaneNet::Mainnet);
    const std::uint64_t B = 600000000000ull, f_spend = 1, N = 1000;
    // the epoch of each receipt: epoch 0 before H_act, 1 from it (the activation keeps weight semantics)
    const Built old_rules = chain(false), new_rules = chain(false), drops = chain(true);
    bool once = true, same = true, kept = true;
    int windows = 0;
    // every window that covers a pre-activation bin: from tips at bins 20..39 (each window = whole bins back to coverage)
    for (std::size_t newest = 0; newest + 20 <= old_rules.bins.size(); ++newest) {
        const std::vector<pb::WinBin> v_old(old_rules.bins.begin() + newest, old_rules.bins.end());
        const std::vector<pb::WinBin> v_new(new_rules.bins.begin() + newest, new_rules.bins.end());
        const std::vector<pb::WinBin> v_rd(drops.bins.begin() + newest, drops.bins.end());
        std::uint64_t d_net = 0;
        for (const pb::WinBin& b : v_old)
            for (const pb::WinEntry& e : b.entries) d_net += e.work;
        d_net /= 3;  // COVERAGE 2 x D_net covers about two thirds of the bins
        const std::vector<pb::WinBin> sel = pb::select_window_bins(v_old, d_net, B, f_spend);
        const pb::Window w_old = pb::window(v_old, d_net, B, f_spend, N, author);
        const pb::Window w_new = pb::window(v_new, d_net, B, f_spend, N, author);
        // counted exactly once: each miner's weight == the sum of its own shares over the selected bins
        std::map<pb::Hash32, pb::Work> want;
        for (const pb::WinBin& b : sel)
            for (const pb::WinEntry& e : b.entries) {
                const pb::Shares s = pb::shares_of(e.work, e.p, e.give_author_bp);
                want[e.miner] += pb::Work(s.w_miner);
                want[author] += pb::Work(s.w_author);
            }
        for (const auto& [k, wv] : want) once = once && w_old.weight.count(k) == 1 && w_old.weight.at(k) == wv;
        same = same && w_old.weight == w_new.weight && w_old.W == w_new.W && pb::window_root(w_old) == pb::window_root(w_new);
        // the synthetic raindrop epoch: every pre-activation entry keeps its weight (its bucket row shares)
        for (const pb::WinBin& b : v_rd) {
            if (b.entries.front().position >= old_rules.h_act) continue;
            for (const pb::WinEntry& e : b.entries) {
                const pb::Shares s = pb::shares_of(e.work, e.p, e.give_author_bp);
                kept = kept && s.w_miner + s.w_author == e.work && s.w_author == e.work * 10 / 10000;
            }
        }
        // two nodes: the same inputs give the same window
        same = same && pb::window(v_old, d_net, B, f_spend, N, author).weight == w_old.weight;
        ++windows;
    }
    check(windows == 21, "21 windows cover pre-activation bins");
    check(once, "every pre-activation receipt is counted exactly once in every window that covers it");
    check(same, "under the old and the new rules (an epoch that keeps weight semantics) the windows are equal, on every node");
    check(kept, "a synthetic epoch adding raindrop entries from H_act on leaves every pre-activation weight unchanged");
    // the raindrop epoch changes the window amounts (more work) but not a pre-activation entry's weight
    const std::vector<pb::WinBin> rd_all = drops.bins;
    const pb::Window w_rd = pb::window(rd_all, 1ull << 40, B, f_spend, N, author);
    const pb::Window w_ol = pb::window(old_rules.bins, 1ull << 40, B, f_spend, N, author);
    check(w_rd.W != w_ol.W && w_rd.weight.at(pb::Hash32(id_of(0x10, 0))) == w_ol.weight.at(pb::Hash32(id_of(0x10, 0))),
          "with raindrops the window total changes, a pre-activation miner's weight does not");
    return finish("xmr_epoch_accounting_kat");
}
