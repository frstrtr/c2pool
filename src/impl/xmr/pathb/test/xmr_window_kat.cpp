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
// S3b-1b (pathb_window_chain.hpp, pathb_window_cache.hpp; C38, C13, C35):
//   (i)   in-bin cut by the placing position q through the store: N 3, five
//         payees at q 10..14 whose own positions p(r) order them the other way
//         -> kept q 14, 13, 12;
//   (ii)  R-12: the newest bin alone fails W_max (300 entries at 4,300,000 and
//         one at 18,180, B 6e11, f_spend 12,530,000) -> cut by position, the
//         300 kept, W 1,290,000,000 (not finder-only);
//   (iii) R-13: a miner at weight 0 (p 10000) is not a payee for N: N 2 keeps
//         both bins;
//   (iv)  the (tip, v) window cache: three lookups -> one evaluation; (t, 17)
//         != (t, 16) and == a fresh window(t, 17); a one-entry budget and the
//         default give the same answers; a DEFER is not stored; the entry
//         carries mmr_root_at(t), not the best tip's root; WindowAt bound to
//         (t, v);
//   (v)   D_net u128: D_net = 2^64 takes every bin.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <limits>
#include <vector>

#include "impl/xmr/pathb/pathb_window.hpp"
#include "impl/xmr/pathb/pathb_window_cache.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_kat_lane.hpp"

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

// identity with `i` in the last 8 bytes big-endian.
static pb::Hash32 id_of(std::uint64_t i) {
    pb::Hash32 h{};
    for (int b = 0; b < 8; ++b) h[31 - b] = static_cast<std::uint8_t>(i >> (8 * b));
    return h;
}

static constexpr pb::DNet kHugeDnet = pb::DNet{1} << 100;
static constexpr std::uint64_t kB = 600000000000ull;

static pb::WindowParams params(std::uint64_t N, std::uint64_t f) {
    pb::WindowParams wp;
    wp.d_net = kHugeDnet;
    wp.B = kB;
    wp.f_spend = f;
    wp.N = N;
    return wp;
}

// (i) the in-bin cut keys on q, the position of the placing carrier (R-11).
static void s3b_in_bin_cut() {
    const pb::LaneParams P = pb::kRuledLaneParams;
    constexpr std::uint64_t b0 = 3500000;
    pb::BinStore s(P, 64, idn(0xC0, 0), b0);
    bool ok = true;
    for (std::uint64_t q = 1; q <= 14; ++q) {
        std::vector<pb::Placement> pls;
        if (q >= 10) pls.push_back(rcpt(idn(0xD0, q), b0, 19 - q, idn(0xE0, q), 20000));
        ok = ok && extend(s, idn(0xC0, q), idn(0xC0, q - 1), b0, pls, true);
    }
    check(ok, "(i) chain of 14 carriers at h = b0, five carried receipts at q 10..14");
    const pb::TipWindow w = pb::tip_window(s, idn(0xC0, 14), params(3, pb::f_spend(kB, 300000, 16)), 16);
    check(w.ok() && w.window->weight.size() == 3, "(i) N 3: one bin of five payees cut to three");
    check(w.ok() && w.window->weight.count(idn(0xE0, 14)) && w.window->weight.count(idn(0xE0, 13))
                  && w.window->weight.count(idn(0xE0, 12)),
          "(i) kept the newest placing positions q 14, 13, 12 (p(r) 5, 6, 7)");
    check(w.ok() && !w.window->weight.count(idn(0xE0, 10)) && !w.window->weight.count(idn(0xE0, 11)),
          "(i) q 10 and 11 cut although their own positions p(r) 9, 8 are the newest");
}

// (ii) R-12: the newest bin alone fails W_max.
static void s3b_newest_bin_w_max_cut() {
    const std::uint64_t f = pb::f_spend(kB, 300000, 16);
    check(f == 12530000ull, "(ii) f_spend 12,530,000");
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
    const auto sel = pb::select_window_bins(bins, 1000000000ull, kB, f);
    check(sel.size() == 1 && sel[0].entries.size() == 300, "(ii) the newest bin is cut by position: 300 entries kept");
    const pb::Window w = pb::window(bins, 1000000000ull, kB, f, 3747, pb::Hash32{});
    check(!w.empty_finder_only && w.weight.size() == 300 && w.W == pb::Work(1290000000ull)
                  && w.weight.count(id_of(9999)) == 0,
          "(ii) window: 300 payees, W 1,290,000,000, the 18,180 entry out (not finder-only)");
}

// (iii) R-13: the N rule counts identities whose weight after shares is > 0.
static void s3b_n_count_after_shares() {
    pb::WinEntry x;  // p 10000: miner weight 0, owner Y takes the whole work
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
    check(pb::shares_of(20000, 10000, 0).w_miner == 0, "(iii) p 10000: miner weight 0");
    const pb::Window w = pb::window(bins, kHugeDnet, kB, pb::f_spend(kB, 300000, 16), 2, pb::Hash32{});
    check(w.weight.size() == 2 && w.weight.count(id_of(0x0B)) && w.weight.count(id_of(0x0C))
                  && w.W == pb::Work(60000),
          "(iii) N 2: payees {Y, Z}, both bins kept (the weight-0 miner is not counted)");
    check(w.weight.count(id_of(0x0A)) == 0 && w.weight.at(id_of(0x0B)) == pb::Work(40000),
          "(iii) X has no output; Y = 20,000 own + 20,000 owner share");
}

// (iv) the (tip, v) window cache.
static void s3b_window_cache() {
    const pb::LaneParams P = pb::kRuledLaneParams;
    constexpr std::uint64_t b0 = 1000;
    constexpr std::uint8_t kTag = 0x4d;
    const std::uint64_t n_pos = 1100;
    // Monero 0 .. 1115: difficulty 1e9 per block, RowWeights at the tail, Z = M = 300,000.
    KatMoneroRows m = monero_chain(kTag, 1115, 1000000000ull, [](std::uint64_t) {
        return std::optional<pb::RowWeights>(rw(kTailAgc, 300000, 300000));
    });
    const pb::FollowerBranchView view(m);
    pb::BinStore s(P, 64, idn(0xC1, 0), b0);
    auto h_of = [&](std::uint64_t pos) { return b0 + pos / 10; };
    bool ok = true;
    for (std::uint64_t pos = 1; pos <= n_pos; ++pos) {
        const std::uint64_t h = h_of(pos);
        std::vector<pb::Placement> pls{rcpt(idn(0xD1, pos), h, pos, idn(0xA1, pos), 20000),
                                       rcpt(idn(0xD2, pos), h, pos, idn(0xA2, pos), 20000)};
        ok = ok && extend(s, idn(0xC1, pos), idn(0xC1, pos - 1), h, pls, true);
    }
    check(ok, "(iv) chain of 1,100 carriers, two receipts each (2,200 payees)");
    const pb::Hash32 author{};
    auto p_t = [&](std::uint64_t pos) { return block_id(kTag, h_of(pos) - 1); };
    const pb::Hash32 t = idn(0xC1, n_pos);
    auto eval = [&](std::uint64_t pos, std::uint8_t v) {
        return [&, pos, v] { return pb::evaluate_window_at(s, idn(0xC1, pos), p_t(pos), view, v, author); };
    };
    check(pb::n_rule(300000, 16, kB) == 3747 && pb::n_rule(300000, 17, kB) == 1665, "(iv) N(B) 3,747 at hf 16, 1,665 at hf 17");

    pb::WindowCache cache;
    const pb::TipWindow a = cache.get(t, 16, eval(n_pos, 16));
    const pb::TipWindow b = cache.get(t, 16, eval(n_pos, 16));
    const pb::TipWindow c = cache.get(t, 16, eval(n_pos, 16));
    check(a.ok() && b.ok() && c.ok() && cache.computations() == 1 && cache.hits() == 2,
          "(iv) three lookups of (t, 16): one evaluation, two hits");
    check(a.window_root == b.window_root && b.window_root == c.window_root && a.window == c.window,
          "(iv) the hits return the stored window");
    check(a.ok() && a.window->weight.size() == 2200, "(iv) (t, 16): 2,200 payees");
    const pb::TipWindow d17 = cache.get(t, 17, eval(n_pos, 17));
    const pb::TipWindow fresh17 = pb::evaluate_window_at(s, t, p_t(n_pos), view, 17, author);
    check(d17.ok() && fresh17.ok() && cache.computations() == 2, "(iv) (t, 17) is evaluated, not taken from (t, 16)");
    check(d17.ok() && fresh17.ok() && d17.window_root == fresh17.window_root && d17.sum == fresh17.sum
                  && d17.window->weight == fresh17.window->weight && d17.window->weight.size() <= 1665,
          "(iv) (t, 17) == a fresh window(t, 17): N(B) 1,665 cuts the oldest bins");
    check(d17.ok() && a.ok() && !(d17.window_root == a.window_root), "(iv) window(t, 17) != window(t, 16)");
    const pb::WindowAt at17 = pb::window_at(d17);
    check(at17.window == d17.window.get() && at17.tip == t && at17.v == 17 && at17.window_root == d17.window_root
                  && at17.mmr_root == d17.mmr_root,
          "(iv) WindowAt of (t, 17): bound to t and v 17, with its roots");

    // a one-entry budget and the default give the same answers.
    {
        const std::size_t one = pb::WindowCache::entry_bytes(*a.window);
        pb::WindowCache small(one), big;
        const std::uint64_t seq_pos[] = {1100, 1090, 1100, 1080, 1090, 1100, 1100, 1080};
        const std::uint8_t seq_v[] = {16, 16, 17, 16, 17, 16, 17, 16};
        bool same = true;
        for (std::size_t i = 0; i < 8; ++i) {
            const pb::Hash32 ti = idn(0xC1, seq_pos[i]);
            const pb::TipWindow x = small.get(ti, seq_v[i], eval(seq_pos[i], seq_v[i]));
            const pb::TipWindow y = big.get(ti, seq_v[i], eval(seq_pos[i], seq_v[i]));
            same = same && x.ok() && y.ok() && x.window_root == y.window_root && x.sum == y.sum
                   && x.mmr_root == y.mmr_root && x.window->weight == y.window->weight;
        }
        check(same, "(iv) budget of one entry and the default: the same windows and roots");
        check(small.entries() <= 1 && small.computations() > big.computations(),
              "(iv) the small budget recomputes, the default reuses");
    }

    // a DEFER is returned and never stored.
    {
        KatMoneroRows m2 = m;
        const pb::Hash32 a_t = block_id(kTag, h_of(n_pos) - 1 - 60);
        const pb::RowWeights keep = m2.w.at(a_t);
        m2.w.erase(a_t);
        const pb::FollowerBranchView view2(m2);
        pb::WindowCache c2;
        auto eval2 = [&] { return pb::evaluate_window_at(s, t, p_t(n_pos), view2, 16, author); };
        const pb::TipWindow x = c2.get(t, 16, eval2);
        check(!x.ok() && x.defer == pb::WindowDefer::MissingWeights && x.missing_id == a_t && c2.entries() == 0,
              "(iv) A_t without RowWeights: DEFER MissingWeights naming A_t, nothing stored");
        check(pb::window_at(x).window == nullptr, "(iv) a DEFER gives WindowAt without a window");
        m2.w[a_t] = keep;
        const pb::TipWindow y = c2.get(t, 16, eval2);
        check(y.ok() && c2.computations() == 2 && y.window_root == a.window_root,
              "(iv) after the fetch: evaluated again, the same window_root");
    }

    // the entry carries mmr_root_at(t), not the best tip's root.
    {
        const pb::Hash32 t_old = idn(0xC1, 1000);
        const pb::TipWindow o = cache.get(t_old, 16, eval(1000, 16));
        const pb::LaneView vo = s.view_at(t_old);
        const pb::LaneView vb = s.view_at(s.best_tip());
        check(o.ok() && vo.leaf_count() == 5 && vb.leaf_count() == 15, "(iv) t_old seals 5 bins, the best tip 15");
        check(o.ok() && o.mmr_root == vo.mmr_root_at(1000) && !(o.mmr_root == vb.mmr_root()),
              "(iv) the cached mmr_root is mmr_root_at(t_old)");
    }
}

// (v) D_net is u128 and is compared in U256.
static void s3b_dnet_u128() {
    std::vector<pb::WinBin> bins;
    for (std::uint64_t k = 0; k < 3; ++k) bins.push_back({3 - k, {entry(static_cast<std::uint8_t>(0x30 + k), 100, 30 - k)}});
    pb::U128 d{};
    d.lo = 0;
    d.hi = 1;  // 2^64
    const pb::DNet dn = pb::dnet_of(d);
    check(dn == (pb::DNet{1} << 64), "(v) dnet_of(U128 2^64) == 2^64");
    const pb::Window w = pb::window(bins, dn, kB, 1, 3747, pb::Hash32{});
    check(w.W == pb::Work(300) && w.weight.size() == 3, "(v) D_net 2^64: every bin taken (W 300)");
    check(pb::select_window_bins(bins, pb::DNet{1} << 64, kB, 1).size() == 3, "(v) select at D_net 2^64: 3 bins");
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

    s3b_in_bin_cut();
    s3b_newest_bin_w_max_cut();
    s3b_n_count_after_shares();
    s3b_window_cache();
    s3b_dnet_u128();

    return finish("xmr_window_kat");
}
