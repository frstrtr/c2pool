// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// xmr_window_merge_back_kat (pathb_window.hpp, ruling 15 Q5, 20 Q-K, 24 K-1):
//   an identity whose TOTAL window weight x B(A_t) < W x f_spend gets NO owner /
//   author share and that weight returns to the contributing receipts' miners
//   (miner paid in full); an owner above the floor keeps its output; the threshold
//   reads B(A_t) not R; the order of identities does not change window_root; an
//   identity with a raw entry of its own is untouched (owner or author, its shares
//   stay); W is constant across merge-back.
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
    // 0x0C mines 500,000 and owns 100 receipts at p 10 bp (owner shares 20,000):
    // w_X = 520,000 is above the floor, so its owner share stays.
    {
        pb::WinBin bin; bin.bin = 1;
        bin.entries.push_back(mk(0x01, 0x00, 1000000000ull, 0, 100));
        bin.entries.push_back(mk(0x0C, 0x00, 500000, 0, 95));  // 0x0C mines its own share
        for (int i = 0; i < 100; ++i) bin.entries.push_back(mk(0x02, 0x0C, 200000, /*p=*/10, 90 - i));
        const pb::Window w = pb::window({bin}, 1, B, f, N, author);
        check(w.weight.at(rep(0x0C)) == pb::Work(520000ull),
              "0x0C (raw entry + owner shares) untouched: w_X = 520,000");
        check(w.weight.at(rep(0x02)) == pb::Work(19980000ull), "0x02 keeps work minus the owner share");
        check(w.W == pb::Work(1020500000ull), "W constant");
    }
    // the same owner shares with no raw entry of 0x0C: below the floor, merged.
    {
        pb::WinBin bin; bin.bin = 1;
        bin.entries.push_back(mk(0x01, 0x00, 1000000000ull, 0, 100));
        bin.entries.push_back(mk(0x0D, 0x00, 500000, 0, 95));
        for (int i = 0; i < 100; ++i) bin.entries.push_back(mk(0x02, 0x0C, 200000, /*p=*/10, 90 - i));
        const pb::Window w = pb::window({bin}, 1, B, f, N, author);
        check(w.weight.count(rep(0x0C)) == 0, "pure owner 0x0C below the floor: no output");
        check(w.weight.at(rep(0x02)) == pb::Work(20000000ull), "0x02 gets the merged owner share");
    }

    // ---- the author identity: the floor reads its TOTAL window weight ----
    // 100 receipts donate 10 bp of 200,000 (author shares 20,000 in all).
    {
        const pb::Hash32 au = rep(0xEE);
        auto donating_bin = [&](bool author_mines) {
            pb::WinBin bin; bin.bin = 1;
            bin.entries.push_back(mk(0x01, 0x00, 1000000000ull, 0, 100));
            bin.entries.push_back(mk(author_mines ? 0xEE : 0x0D, 0x00, 500000, 0, 95));
            for (int i = 0; i < 100; ++i) {
                pb::WinEntry x = mk(0x02, 0x00, 200000, 0, 90 - i);
                x.give_author_bp = 10;
                bin.entries.push_back(x);
            }
            return bin;
        };
        const pb::Window mines = pb::window({donating_bin(true)}, 1, B, f, N, au);
        check(mines.weight.at(au) == pb::Work(520000ull), "author with a raw entry keeps its shares (520,000)");
        check(mines.weight.at(rep(0x02)) == pb::Work(19980000ull), "donors keep work minus the author share");
        const pb::Window pure = pb::window({donating_bin(false)}, 1, B, f, N, au);
        check(pure.weight.count(au) == 0, "author without a raw entry below the floor: no output");
        check(pure.weight.at(rep(0x02)) == pb::Work(20000000ull), "author share returns to the donors");
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
