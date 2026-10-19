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
//   identity whose raw entry lifts its total above the floor is untouched (owner or
//   author, its shares stay); W is constant across merge-back. Author at a 1 % donating fleet (10 bp):
//   no author output; at 2.1 %: an author output. Every floor test reads the
//   totals before merge-back: an identity whose miner weight another identity's
//   merge-back lifts above the floor is tested on its total before that, under
//   either identity order.
// S3b-1b (sealed bins; ruling 20 Q-K, R-13): the same receipts built as open
//   entries in one bin, spread over four open bins, over four SEALED bins
//   (seal_from_entries) and over a mixed window (newest bin open, older bins
//   sealed) give byte-equal weights, W and window_root, for every vector
//   above; the N rule reads owners from sealed rows: N = C - 1 with an owner
//   that is not a miner in a sealed bin drops the oldest bin.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_bin_store.hpp"  // seal_from_entries
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

static constexpr pb::DNet kHugeDnet = pb::DNet{1} << 100;

// The receipts E as one open bin, four open bins, four sealed bins and a mixed
// window (bin 4 open, bins 3..1 sealed): one window.
static void same_window_sealed(const std::string& name, const std::vector<pb::WinEntry>& E, std::uint64_t B,
                               std::uint64_t f, std::uint64_t N, const pb::Hash32& author) {
    std::vector<pb::WinBin> one(1);
    one[0].bin = 4;
    one[0].entries = E;
    std::vector<pb::WinBin> open(4);
    for (std::size_t k = 0; k < 4; ++k) open[k].bin = 4 - k;  // newest first
    for (std::size_t i = 0; i < E.size(); ++i) open[i % 4].entries.push_back(E[i]);
    std::vector<pb::L1Bucket> buckets(4);
    bool consistent = true;
    for (std::size_t k = 0; k < 4; ++k) {
        buckets[k] = pb::seal_from_entries(open[k].bin, open[k].entries);
        consistent = consistent && pb::bucket_consistent(buckets[k]);
    }
    std::vector<pb::WinBin> sealed(4), mixed(4);
    for (std::size_t k = 0; k < 4; ++k) {
        sealed[k].bin = open[k].bin;
        sealed[k].sealed = &buckets[k];
        mixed[k] = k == 0 ? open[k] : sealed[k];
    }
    const pb::Window w1 = pb::window(one, kHugeDnet, B, f, N, author);
    const pb::Window wo = pb::window(open, kHugeDnet, B, f, N, author);
    const pb::Window ws = pb::window(sealed, kHugeDnet, B, f, N, author);
    const pb::Window wm = pb::window(mixed, kHugeDnet, B, f, N, author);
    check(consistent, "sealed == open, " + name + ": the four buckets are consistent");
    check(!w1.weight.empty() && w1.weight == wo.weight && w1.weight == ws.weight && w1.weight == wm.weight,
          "sealed == open, " + name + ": open, sealed and mixed: the same weights");
    check(w1.W == wo.W && w1.W == ws.W && w1.W == wm.W, "sealed == open, " + name + ": the same W");
    check(pb::window_root(w1) == pb::window_root(ws) && pb::window_root(w1) == pb::window_root(wm)
                  && pb::window_root(w1) == pb::window_root(wo),
          "sealed == open, " + name + ": the same window_root");
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

    // ---- the author with no raw entry, a donating fleet at 10 bp: 1 % of W ->
    // no author output (author shares 10,000); 2.1 % of W -> an author output
    // (21,000). W = 1,000,000,000 in both. ----
    {
        const pb::Hash32 au = rep(0xEE);
        auto fleet_bin = [&](std::uint64_t big, std::uint64_t each) {
            pb::WinBin bin; bin.bin = 1;
            bin.entries.push_back(mk(0x01, 0x00, big, 0, 100));
            for (int i = 0; i < 100; ++i) {
                pb::WinEntry x = mk(0x02, 0x00, each, 0, 99 - i);
                x.give_author_bp = 10;
                bin.entries.push_back(x);
            }
            return bin;
        };
        const pb::Window one = pb::window({fleet_bin(990000000ull, 100000)}, 1, B, f, N, au);
        check(one.W == pb::Work(1000000000ull), "1 % fleet: W");
        check(one.weight.count(au) == 0, "1 % donating fleet: no author output");
        check(one.weight.at(rep(0x02)) == pb::Work(10000000ull), "1 % fleet: the author share returns to the donors");
        const pb::Window two = pb::window({fleet_bin(979000000ull, 210000)}, 1, B, f, N, au);
        check(two.W == pb::Work(1000000000ull), "2.1 % fleet: W");
        check(two.weight.count(au) == 1 && two.weight.at(au) == pb::Work(21000ull),
              "2.1 % donating fleet: an author output (21,000)");
        check(two.weight.at(rep(0x02)) == pb::Work(20979000ull), "2.1 % fleet: donors keep work minus the author share");
    }

    // ---- one identity's merge-back lifts another's miner weight above the floor ----
    // X owns Y's receipt (30,000 at p 5000 bp): X total 15,000. Y mines it (15,000)
    // and owns Z's receipt (1,000,000 at p 1 bp): Y total 15,100. W = 1,001,030,000.
    // Both totals are below the floor before merge-back: X's share returns to Y,
    // Y's share returns to Z. Under both identity orders: no X, Y 30,000, Z 1,000,000.
    for (const bool x_first : {true, false}) {
        const std::uint8_t X = x_first ? 0x0A : 0x0B, Y = x_first ? 0x0B : 0x0A, Z = 0x0C;
        pb::WinBin bin; bin.bin = 1;
        bin.entries.push_back(mk(0x01, 0x00, 1000000000ull, 0, 100));
        bin.entries.push_back(mk(Y, X, 30000, /*p=*/5000, 99));
        bin.entries.push_back(mk(Z, Y, 1000000, /*p=*/1, 98));
        const pb::Window w = pb::window({bin}, 1, B, f, N, author);
        const char* tag = x_first ? " (X before Y)" : " (Y before X)";
        check(w.W == pb::Work(1001030000ull), std::string("lift: W") + tag);
        check(w.weight.count(rep(X)) == 0, std::string("lift: X below the floor, no output") + tag);
        check(w.weight.at(rep(Y)) == pb::Work(30000ull),
              std::string("lift: Y tested on its total before merge-back, its owner share merges") + tag);
        check(w.weight.at(rep(Z)) == pb::Work(1000000ull), std::string("lift: Z paid in full") + tag);
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

    // ---- sealed-bin merge-back from the bucket rows == the open-bin result ----
    {
        std::vector<pb::WinEntry> e;
        e.push_back(mk(0x01, 0x00, 1000000000ull, 0, 100));
        for (int i = 0; i < 100; ++i) e.push_back(mk(0x02, 0x0C, 200000, /*p=*/10, 99 - i));
        same_window_sealed("owner p 10 bp below the floor", e, B, f, N, author);
        for (pb::WinEntry& x : e)
            if (x.p == 10) x.p = 100;
        same_window_sealed("owner p 100 bp above the floor", e, B, f, N, author);
    }
    {
        std::vector<pb::WinEntry> e;
        e.push_back(mk(0x01, 0x00, 1000000000ull, 0, 100));
        for (int i = 0; i < 100; ++i) e.push_back(mk(0x02, 0x0C, 200000, /*p=*/1, 99 - i));
        same_window_sealed("owner p 1 bp over 100 receipts", e, B, f, N, author);
    }
    {
        std::vector<pb::WinEntry> e;
        e.push_back(mk(0x01, 0x00, 1000000000ull, 0, 100));
        e.push_back(mk(0x0C, 0x00, 500000, 0, 95));
        for (int i = 0; i < 100; ++i) e.push_back(mk(0x02, 0x0C, 200000, /*p=*/10, 90 - i));
        same_window_sealed("owner with a raw entry", e, B, f, N, author);
        e[1].miner = rep(0x0D);
        same_window_sealed("pure owner below the floor", e, B, f, N, author);
    }
    for (const bool author_mines : {true, false}) {
        const pb::Hash32 au = rep(0xEE);
        std::vector<pb::WinEntry> e;
        e.push_back(mk(0x01, 0x00, 1000000000ull, 0, 100));
        e.push_back(mk(author_mines ? 0xEE : 0x0D, 0x00, 500000, 0, 95));
        for (int i = 0; i < 100; ++i) {
            pb::WinEntry x = mk(0x02, 0x00, 200000, 0, 90 - i);
            x.give_author_bp = 10;
            e.push_back(x);
        }
        same_window_sealed(author_mines ? "author with a raw entry" : "author without a raw entry", e, B, f, N, au);
    }
    for (const std::uint64_t each : {std::uint64_t{100000}, std::uint64_t{210000}}) {
        const pb::Hash32 au = rep(0xEE);
        std::vector<pb::WinEntry> e;
        e.push_back(mk(0x01, 0x00, 1000000000ull - 100 * each, 0, 100));
        for (int i = 0; i < 100; ++i) {
            pb::WinEntry x = mk(0x02, 0x00, each, 0, 99 - i);
            x.give_author_bp = 10;
            e.push_back(x);
        }
        same_window_sealed(each == 100000 ? "1 % donating fleet" : "2.1 % donating fleet", e, B, f, N, au);
    }
    for (const bool x_first : {true, false}) {
        const std::uint8_t X = x_first ? 0x0A : 0x0B, Y = x_first ? 0x0B : 0x0A, Z = 0x0C;
        std::vector<pb::WinEntry> e{mk(0x01, 0x00, 1000000000ull, 0, 100), mk(Y, X, 30000, 5000, 99),
                                    mk(Z, Y, 1000000, 1, 98)};
        same_window_sealed(x_first ? "lift (X before Y)" : "lift (Y before X)", e, B, f, N, author);
    }

    // ---- the N rule reads the owners of sealed rows (R-13): N = C - 1 ----
    // bin 3 open: A, B; bin 2 sealed: C with owner O (p 100 bp; O mines nothing);
    // bin 1 sealed: D. C = 5 identities; N = 4 drops bin 1.
    {
        pb::WinEntry c = mk(0xC1, 0x0F, 300000, 100, 20);
        const std::vector<pb::WinEntry> b3{mk(0xA1, 0x00, 300000, 0, 31), mk(0xB1, 0x00, 300000, 0, 30)};
        const std::vector<pb::WinEntry> b2{c};
        const std::vector<pb::WinEntry> b1{mk(0xD1, 0x00, 300000, 0, 10)};
        const pb::L1Bucket s2 = pb::seal_from_entries(2, b2), s1 = pb::seal_from_entries(1, b1);
        std::vector<pb::WinBin> sealed(3);
        sealed[0].bin = 3;
        sealed[0].entries = b3;
        sealed[1].bin = 2;
        sealed[1].sealed = &s2;
        sealed[2].bin = 1;
        sealed[2].sealed = &s1;
        const std::vector<pb::WinBin> open{{3, b3}, {2, b2}, {1, b1}};
        const pb::Window ws = pb::window(sealed, kHugeDnet, B, f, 4, author);
        const pb::Window wo = pb::window(open, kHugeDnet, B, f, 4, author);
        check(ws.weight.count(rep(0xD1)) == 0 && ws.W == pb::Work(900000) && ws.weight.count(rep(0x0F)) == 1,
              "N = C - 1: the sealed owner O counts, bin 1 (D) leaves the window, W 900,000");
        check(ws.weight == wo.weight && pb::window_root(ws) == pb::window_root(wo),
              "N = C - 1: sealed and open give one window");
    }

    return finish("xmr_window_merge_back_kat");
}
