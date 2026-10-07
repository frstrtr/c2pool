// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// xmr_window_merge_back_kat (pathb_window.hpp, ruling 15 Q5, 20 Q-K, 24 K-1):
//   an owner whose aggregated share x B(A_t) < W x f_spend gets NO output and its
//   weight returns to the contributing receipts' miners (miner paid in full); an
//   owner above the floor keeps its output; the threshold reads B(A_t) not R; the
//   order of identities does not change window_root; an identity with a raw entry
//   of its own is untouched; W is constant across merge-back.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <cstdint>
#include <vector>

#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 rep(std::uint8_t b) { pb::Hash32 h{}; h.fill(b); return h; }
static pb::WinEntry mk(std::uint8_t miner, std::uint8_t owner, std::uint64_t work, std::uint16_t p,
                       std::uint64_t pos) {
    pb::WinEntry x;
    x.miner = rep(miner);
    if (owner) x.owner = rep(owner);
    x.work = work;
    x.p = p;
    x.position = pos;
    x.id = rep(miner);
    return x;
}

int main() {
    const pb::Hash32 author{};                 // zero author: donation merges back
    const std::uint64_t B = 600000000000ull;   // 6e11
    const std::uint64_t f = pb::f_spend(B, 300000, 16);  // 12,530,000
    const std::uint64_t N = 3747;

    // ---- owner below the floor merges back; the miner is paid in full ----
    {
        pb::WinBin bin; bin.bin = 1;
        bin.entries.push_back(mk(0x01, 0x00, 1000000000ull, 0, 100));  // big miner, no owner
        for (int i = 0; i < 100; ++i) bin.entries.push_back(mk(0x02, 0x0C, 200000, /*p=*/10, 99 - i));
        const pb::Window w = pb::window({bin}, /*D_net=*/1, B, f, N, author);
        check(w.weight.find(rep(0x0C)) == w.weight.end(), "owner below floor -> NO owner output");
        check(w.weight.at(rep(0x02)) == pb::Work(20000000ull), "owner share returns to the miner (paid in full)");
        check(w.weight.at(rep(0x01)) == pb::Work(1000000000ull), "the big miner is untouched");
        // W is constant: total weight == total raw work.
        pb::Work tot;
        for (const auto& [id, wt] : w.weight) tot += wt;
        check(tot == pb::Work(1020000000ull) && w.W == tot, "W constant across merge-back");
    }

    // ---- owner above the floor keeps its output ----
    {
        pb::WinBin bin; bin.bin = 1;
        bin.entries.push_back(mk(0x01, 0x00, 1000000000ull, 0, 100));
        for (int i = 0; i < 100; ++i) bin.entries.push_back(mk(0x02, 0x0C, 200000, /*p=*/100, 99 - i));
        const pb::Window w = pb::window({bin}, 1, B, f, N, author);
        check(w.weight.find(rep(0x0C)) != w.weight.end(), "owner above floor -> owner output present");
        check(w.weight.at(rep(0x0C)) == pb::Work(200000ull), "owner output == aggregated owner share");
    }

    // ---- the threshold reads B(A_t): with a smaller B the same owner flips to merged ----
    {
        pb::WinBin bin; bin.bin = 1;
        bin.entries.push_back(mk(0x01, 0x00, 1000000000ull, 0, 100));
        for (int i = 0; i < 100; ++i) bin.entries.push_back(mk(0x02, 0x0C, 200000, /*p=*/100, 99 - i));
        // owner weight 200000; above floor at B 6e11, below floor at a small B.
        const pb::Window hi = pb::window({bin}, 1, B, f, N, author);
        const pb::Window lo = pb::window({bin}, 1, /*B=*/1000000ull, f, N, author);
        check(hi.weight.count(rep(0x0C)) == 1 && lo.weight.count(rep(0x0C)) == 0,
              "merge threshold reads B(A_t): smaller B merges the owner");
    }

    // ---- an identity with a raw entry of its own is untouched ----
    {
        pb::WinBin bin; bin.bin = 1;
        bin.entries.push_back(mk(0x01, 0x00, 1000000000ull, 0, 100));
        bin.entries.push_back(mk(0x0C, 0x00, 500000, 0, 95));  // 0x0C mines its own share
        for (int i = 0; i < 100; ++i) bin.entries.push_back(mk(0x02, 0x0C, 200000, /*p=*/10, 90 - i));
        const pb::Window w = pb::window({bin}, 1, B, f, N, author);
        check(w.weight.at(rep(0x0C)) == pb::Work(500000ull),
              "0x0C's own miner weight untouched (owner share merges to 0x02)");
        check(w.weight.at(rep(0x02)) == pb::Work(20000000ull), "0x02 gets the merged owner share");
    }

    // ---- order of identities does not change window_root ----
    {
        pb::WinBin a; a.bin = 1;
        a.entries = {mk(0x01, 0x00, 300000, 0, 10), mk(0x02, 0x0C, 400000, 50, 9),
                     mk(0x03, 0x0D, 500000, 200, 8)};
        pb::WinBin b = a;
        std::reverse(b.entries.begin(), b.entries.end());
        check(pb::window_root(pb::window({a}, 1, B, f, N, author)) ==
                      pb::window_root(pb::window({b}, 1, B, f, N, author)),
              "identity order does not change window_root");
    }

    return finish("xmr_window_merge_back_kat");
}
