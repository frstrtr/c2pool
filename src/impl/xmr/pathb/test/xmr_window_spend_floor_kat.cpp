// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// xmr_window_spend_floor_kat (pathb_window.hpp / pathb_emission.hpp, C38, K11a):
//   W_max = B(A_t) x d / f_spend PER ENTRY; the F6 vector stops the window at
//   1,500 bins (W 1,440,000,000, entry value 33,333,333; bin 1,501 would give
//   W 1,440,240,000, entry value 8,331,944); a window of 47,885 entries at one d
//   (B / f_spend at 6e11, hf 16) and no payee output below f_spend, entry 47,886
//   excluded; the cap stops at <= (W x f == B x d_min kept, one unit more cut);
//   f_spend(6e11, 300k, hf16) == 12,530,000; a larger fee median M quarters the
//   fee per byte; B(A_t) on both sides (the window reads B, never R:
//   signature); d_min over receipt entries (a carried entry below every carrier
//   in its bin cuts the bin; a carriers-only reading would keep it); two build
//   orders (carrier entries first / carried entries first, placements in chain
//   order / reverse) give one window_root and one split, the in-bin cut included.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <map>
#include <string>
#include <type_traits>
#include <vector>

#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

pb::Hash32 rep(std::uint8_t b) { pb::Hash32 h{}; h.fill(b); return h; }
pb::WinEntry e(std::uint8_t miner, std::uint64_t work, std::uint64_t pos) {
    pb::WinEntry x; x.miner = rep(miner); x.work = work; x.position = pos; x.id = rep(miner); return x;
}
// identity with `i` in the last 8 bytes big-endian: memcmp order == numeric order.
pb::Hash32 id_of(std::uint64_t i) {
    pb::Hash32 h{};
    for (int b = 0; b < 8; ++b) h[31 - b] = static_cast<std::uint8_t>(i >> (8 * b));
    return h;
}
std::uint64_t raw_work(const std::vector<pb::WinBin>& bins) {
    std::uint64_t w = 0;
    for (const pb::WinBin& b : bins)
        for (const pb::WinEntry& x : b.entries) w += x.work;
    return w;
}
std::uint64_t smallest(const std::vector<pb::SplitOutput>& o) {
    std::uint64_t s = ~std::uint64_t{0};
    for (const auto& x : o) s = x.amount < s ? x.amount : s;
    return s;
}

// The window reads B(A_t) and f_spend; R (base + fees) is not an input.
static_assert(std::is_same_v<decltype(&pb::select_window_bins),
                             std::vector<pb::WinBin> (*)(const std::vector<pb::WinBin>&, std::uint64_t, std::uint64_t,
                                                         std::uint64_t)>,
              "select_window_bins(bins, D_net, B, f_spend)");
static_assert(std::is_same_v<decltype(&pb::window),
                             pb::Window (*)(const std::vector<pb::WinBin>&, std::uint64_t, std::uint64_t, std::uint64_t,
                                            std::uint64_t, const pb::Hash32&)>,
              "window(bins, D_net, B, f_spend, N, author)");

}  // namespace

int main() {
    const std::uint64_t B = 600000000000ull;  // 6e11
    const std::uint64_t kHugeDnet = 1000000000000000ull;  // COVERAGE never binds

    // ---- f_spend values (K11d, ruling 5) ----
    check(pb::f_spend(B, 300000, 16) == 12530000ull, "f_spend(6e11, M 300k, hf16) == 12,530,000");
    // fee per byte scales as 1/M^2: M 600k -> a quarter of the M 300k value.
    check(pb::fee_per_byte(B, 600000, 16) * 4 == pb::fee_per_byte(B, 300000, 16),
          "fee per byte at M 600k == 1/4 of the M 300k value");
    // the floor at max(M, zone): M below the penalty-free zone reads the zone.
    check(pb::f_spend(B, 100000, 16) == pb::f_spend(B, 300000, 16), "f_spend floors M at the zone");

    const std::uint64_t f = pb::f_spend(B, 300000, 16);  // 12,530,000

    // ---- the F6 W_max vector: 1,500 bins at d 80,000 then bins at d 20,000 ----
    {
        std::vector<pb::WinBin> bins;
        std::uint64_t pos = 2000000;
        for (int k = 0; k < 1500; ++k) {           // newest-first, d = 80,000
            pb::WinBin b; b.bin = 2000000 - k;
            for (int j = 0; j < 12; ++j) b.entries.push_back(e(static_cast<std::uint8_t>(0x60 + j), 80000, pos--));
            bins.push_back(b);
        }
        for (int k = 0; k < 20; ++k) {             // then d = 20,000
            pb::WinBin b; b.bin = 1000000 - k;
            for (int j = 0; j < 12; ++j) b.entries.push_back(e(static_cast<std::uint8_t>(0x60 + j), 20000, pos--));
            bins.push_back(b);
        }
        const auto sel = pb::select_window_bins(bins, kHugeDnet, B, f);
        check(sel.size() == 1500, "W_max per entry stops the window at 1,500 bins (F6)");
        const std::uint64_t W = raw_work(sel);
        check(W == 1440000000ull && B * 80000 / W == 33333333ull && B * 80000 / W >= f,
              "F6: W 1,440,000,000, entry value 33,333,333 >= f_spend");
        const std::uint64_t W1501 = W + 12 * 20000;
        check(W1501 == 1440240000ull && B * 20000 / W1501 == 8331944ull && B * 20000 / W1501 < f,
              "F6: bin 1,501 would give W 1,440,240,000, entry value 8,331,944 < f_spend");
        const pb::Window w = pb::window(bins, kHugeDnet, B, f, 3747, pb::Hash32{});
        check(w.W == pb::Work(1440000000ull) && w.weight.size() == 12, "F6: window() W 1,440,000,000, 12 payees");
    }

    // ---- 47,885 entries at one d: B / f_spend = 47,885.03 (6e11, hf 16) ----
    {
        const std::uint64_t n = 47886;  // one entry per bin, distinct payees, newest first
        std::vector<pb::WinBin> bins;
        bins.reserve(n);
        for (std::uint64_t k = 0; k < n; ++k) {
            pb::WinBin b; b.bin = 5000000 - k;
            pb::WinEntry x; x.miner = id_of(k + 1); x.work = 80000; x.position = 9000000 - k; x.id = x.miner;
            b.entries.push_back(x);
            bins.push_back(b);
        }
        const std::uint64_t N = pb::n_rule(3830978, 16, B);
        check(N == 47885, "N(B) at Z 3,830,978 hf16 == 47,885 (the N rule does not bind)");
        const auto sel = pb::select_window_bins(bins, kHugeDnet, B, f);
        check(sel.size() == 47885, "47,885 entries kept, entry 47,886 excluded");
        const pb::Window w = pb::window(bins, kHugeDnet, B, f, N, pb::Hash32{});
        check(w.weight.size() == 47885 && w.W == pb::Work(47885ull * 80000), "window of 47,885 payees");
        const auto outs = pb::split(B, w);
        check(outs.size() == 47885 && smallest(outs) >= f && smallest(outs) == 12530019ull,
              "no payee output below f_spend in a window of 47,885 entries (smallest 12,530,019)");
    }

    // ---- the cap stops at <=: W x f == B x d_min is kept, one unit more is cut ----
    {
        // d_min 12,530: B x d_min = 7.518e15 = 600,000,000 x f.
        std::vector<pb::WinBin> eq{{11, {e(0x51, 12530, 21)}}, {10, {e(0x52, 599987470, 20)}}};
        std::vector<pb::WinBin> over{{11, {e(0x51, 12530, 21)}}, {10, {e(0x52, 599987471, 20)}}};
        check(pb::select_window_bins(eq, kHugeDnet, B, f).size() == 2, "W x f == B x d_min: bin kept");
        check(pb::select_window_bins(over, kHugeDnet, B, f).size() == 1, "W x f == B x d_min + f: bin cut");
    }

    // ---- d_min over RECEIPT entries: a carried entry below every carrier ----
    {
        // bins 3 and 2 hold one carrier each (d 3,000,000); bin 1 holds a carrier
        // (d 3,000,000) and a carried entry (d 100, placed by the carrier at 35).
        std::vector<pb::WinBin> bins;
        bins.push_back({3, {e(0x70, 3000000, 30)}});
        bins.push_back({2, {e(0x71, 3000000, 20)}});
        bins.push_back({1, {e(0x72, 3000000, 10), e(0x73, 100, 35)}});
        const auto sel = pb::select_window_bins(bins, kHugeDnet, B, f);
        check(sel.size() == 2, "d_min over receipt entries: the carried entry's bin is cut by W_max");
        std::vector<pb::WinBin> carriers_only = bins;
        carriers_only[2].entries.pop_back();
        check(pb::select_window_bins(carriers_only, kHugeDnet, B, f).size() == 3,
              "a reading over carriers only would keep that bin");
        const auto outs = pb::split(B, pb::window(bins, kHugeDnet, B, f, 3747, pb::Hash32{}));
        check(outs.size() == 2 && smallest(outs) >= f, "no output below f_spend");
    }

    // ---- two build orders give one window (carrier-first vs carried-first,
    // placements in chain order vs reverse), the in-bin N cut included ----
    {
        struct Placement {
            std::uint64_t origin_bin;
            std::uint8_t miner;
            std::uint64_t work;
            std::uint64_t carrier_pos;  // the position that placed it
            bool carried;
        };
        // chain order: each carrier, then the receipts it carries.
        const std::vector<Placement> chain{
                {50, 1, 1000, 100, false}, {50, 2, 1100, 101, false},
                {51, 3, 1200, 102, false}, {50, 4, 900, 102, true},
                {51, 1, 1000, 103, false}, {51, 5, 950, 103, true},
                {52, 2, 1300, 104, false}, {50, 6, 800, 104, true}, {51, 7, 850, 104, true},
                {52, 8, 700, 105, false},  {52, 9, 600, 105, true}, {52, 10, 650, 105, true},
        };
        auto build = [](const std::vector<Placement>& ps) {
            std::map<std::uint64_t, pb::WinBin> by;
            for (const Placement& p : ps) {
                pb::WinEntry x;
                x.miner = rep(p.miner);
                x.work = p.work;
                x.position = p.carrier_pos;
                x.id = id_of(1000 * p.carrier_pos + p.miner);
                by[p.origin_bin].bin = p.origin_bin;
                by[p.origin_bin].entries.push_back(x);
            }
            std::vector<pb::WinBin> out;
            for (auto it = by.rbegin(); it != by.rend(); ++it) out.push_back(it->second);  // newest first
            return out;
        };
        std::vector<Placement> carried_first;
        for (const Placement& p : chain)
            if (p.carried) carried_first.push_back(p);
        for (const Placement& p : chain)
            if (!p.carried) carried_first.push_back(p);
        const std::vector<Placement> reverse(chain.rbegin(), chain.rend());
        const auto a = build(chain), b = build(carried_first), c = build(reverse);
        check(!(a.front().entries.front().id == b.front().entries.front().id)
                      && !(a.front().entries.front().id == c.front().entries.front().id),
              "three build orders give three entry orders");
        const std::uint64_t R = B + 3000000000ull;
        for (const std::uint64_t N : {std::uint64_t{3747}, std::uint64_t{3}}) {
            const pb::Window wa = pb::window(a, kHugeDnet, B, f, N, pb::Hash32{});
            const pb::Window wb = pb::window(b, kHugeDnet, B, f, N, pb::Hash32{});
            const pb::Window wc = pb::window(c, kHugeDnet, B, f, N, pb::Hash32{});
            const std::string tag = " (N " + std::to_string(N) + ")";
            check(pb::window_root(wa) == pb::window_root(wb) && pb::window_root(wa) == pb::window_root(wc),
                  "build orders give one window_root" + tag);
            const auto sa = pb::split(R, wa), sb = pb::split(R, wb), sc = pb::split(R, wc);
            bool same = sa.size() == sb.size() && sa.size() == sc.size();
            for (std::size_t i = 0; same && i < sa.size(); ++i)
                same = sa[i].payee == sb[i].payee && sa[i].payee == sc[i].payee && sa[i].amount == sb[i].amount
                       && sa[i].amount == sc[i].amount;
            check(same, "build orders give one split" + tag);
            if (N == 3)
                check(wa.weight.size() == 3 && wa.weight.count(rep(8)) && wa.weight.count(rep(9))
                              && wa.weight.count(rep(10)) && wa.W == pb::Work(1950),
                      "N 3: newest bin cut by carrier position: miners 8, 9, 10 (W 1,950)");
            else
                check(wa.weight.size() == 10 && wa.W == pb::Work(11050), "N 3747: 10 payees, W 11,050");
        }
    }

    return finish("xmr_window_spend_floor_kat");
}
