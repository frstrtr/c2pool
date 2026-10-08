// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// xmr_window_split_kat (pathb_window.hpp, C07, C21, K29a): q_i = floor(R w_i / W)
// in U320, largest remainder, ties by payee identity ascending, Sum(vout) == R
// exactly for 1 / 2 / 3,747 / 10,000 payees; the equal-remainder tie goes to the
// lowest identity; with unequal remainders the larger remainder gets the +1
// (R 10, w 1 / 2 -> 3 / 7; R 100, w 1 / 1 / 5 -> 14 / 14 / 72; 40 random
// windows against a u128 reference); fees shared in proportion to work (two R
// values, no key change); the smallest output >= f_spend when N does not bind
// and R >= B.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <cstdint>
#include <vector>

#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

// identity with `i` in the last 8 bytes big-endian: memcmp order == numeric order.
static pb::Hash32 id_of(std::uint64_t i) {
    pb::Hash32 h{};
    for (int b = 0; b < 8; ++b) h[31 - b] = static_cast<std::uint8_t>(i >> (8 * b));
    return h;
}

static pb::Window mk_window(std::uint64_t n, std::uint64_t base_w, std::uint64_t jitter) {
    pb::Window w;
    Rng rng(0x5157 + n);
    for (std::uint64_t i = 0; i < n; ++i) {
        const std::uint64_t wt = base_w + (jitter ? rng.below(jitter) : 0);
        w.weight[id_of(i + 1)] = pb::Work(wt);
        w.W += pb::Work(wt);
    }
    return w;
}

static std::uint64_t sum_amounts(const std::vector<pb::SplitOutput>& o) {
    std::uint64_t s = 0;
    for (const auto& x : o) s += x.amount;
    return s;
}

int main() {
    const std::uint64_t R = 734123456789ull;  // base + fees, a mainnet-shaped reward

    // ---- Sum(vout) == R exactly for 1 / 2 / 3,747 / 10,000 payees ----
    for (std::uint64_t n : {std::uint64_t{1}, std::uint64_t{2}, std::uint64_t{3747}, std::uint64_t{10000}}) {
        const pb::Window w = mk_window(n, 1000, 500);
        const auto outs = pb::split(R, w);
        check(outs.size() == n, "one output per window payee");
        check(sum_amounts(outs) == R, "Sum(vout) == R exactly");
        // outputs in identity-ascending order (hf 16 order).
        bool ordered = true;
        for (std::size_t i = 1; i < outs.size(); ++i)
            if (!(outs[i - 1].payee < outs[i].payee)) ordered = false;
        check(ordered, "outputs ordered by identity ascending");
    }

    // ---- largest-remainder tie goes to the lowest identity ----
    {
        pb::Window w;
        for (std::uint64_t i = 0; i < 3; ++i) w.weight[id_of(i + 1)] = pb::Work(1);
        w.W = pb::Work(3);
        const auto outs = pb::split(10, w);  // floor(10/3)=3 each, rem 1 each; +1 to lowest id
        check(sum_amounts(outs) == 10, "equal-remainder: Sum == R");
        check(outs[0].amount == 4 && outs[1].amount == 3 && outs[2].amount == 3,
              "equal remainder -> +1 to the lowest identity");
    }
    {
        // 3,747 equal remainders: R = 3747*5 + 100, every rem == 100, the 100
        // lowest identities get +1.
        pb::Window w;
        for (std::uint64_t i = 0; i < 3747; ++i) w.weight[id_of(i + 1)] = pb::Work(1);
        w.W = pb::Work(3747);
        const std::uint64_t Rt = 3747ull * 5 + 100;
        const auto outs = pb::split(Rt, w);
        check(sum_amounts(outs) == Rt, "3747 equal remainders: Sum == R");
        std::size_t plus = 0, base = 0;
        for (std::size_t i = 0; i < outs.size(); ++i) {
            if (outs[i].amount == 6) ++plus;
            else if (outs[i].amount == 5) ++base;
        }
        check(plus == 100 && base == 3647, "exactly the 100 lowest identities get +1");
        for (std::size_t i = 0; i < 100; ++i) check(outs[i].amount == 6, "lowest-100 got the +1");
    }

    // ---- largest remainder with UNEQUAL remainders: the larger remainder wins,
    // whatever its identity ----
    {
        pb::Window w;
        w.weight[id_of(1)] = pb::Work(1);
        w.weight[id_of(2)] = pb::Work(2);
        w.W = pb::Work(3);
        const auto outs = pb::split(10, w);  // floors 3 (rem 1) and 6 (rem 2), deficit 1
        check(outs.size() == 2 && outs[0].amount == 3 && outs[1].amount == 7,
              "R 10, w 1 / 2: outputs 3 / 7 (the +1 to the larger remainder, identity 2)");
    }
    {
        pb::Window w;
        w.weight[id_of(1)] = pb::Work(1);
        w.weight[id_of(2)] = pb::Work(1);
        w.weight[id_of(3)] = pb::Work(5);
        w.W = pb::Work(7);
        const auto outs = pb::split(100, w);  // floors 14 / 14 / 71, rems 2 / 2 / 3, deficit 1
        check(outs.size() == 3 && outs[0].amount == 14 && outs[1].amount == 14 && outs[2].amount == 72,
              "R 100, w 1 / 1 / 5: outputs 14 / 14 / 72");
    }
    {
        // many payees, random weights and R, against an independent u128 reference:
        // q_i = floor(R w_i / W), deficit to the largest remainders, ties by identity.
        Rng rng(0x4C52);
        bool all_match = true;
        int with_deficit = 0;
        for (int trial = 0; trial < 40 && all_match; ++trial) {
            const std::uint64_t n = 2 + rng.below(600);
            const std::uint64_t Rt = 1 + rng.below(std::uint64_t{1} << 62);
            pb::Window w;
            std::vector<std::uint64_t> wt(n);
            unsigned __int128 W = 0;
            for (std::uint64_t i = 0; i < n; ++i) {
                wt[i] = 1 + rng.below(std::uint64_t{1} << 40);
                w.weight[id_of(i + 1)] = pb::Work(wt[i]);
                W += wt[i];
            }
            w.W = pb::Work(static_cast<std::uint64_t>(W));
            std::vector<std::uint64_t> q(n);
            std::vector<unsigned __int128> rem(n);
            std::uint64_t assigned = 0;
            for (std::uint64_t i = 0; i < n; ++i) {
                const unsigned __int128 p = static_cast<unsigned __int128>(Rt) * wt[i];
                q[i] = static_cast<std::uint64_t>(p / W);
                rem[i] = p % W;
                assigned += q[i];
            }
            std::vector<std::uint64_t> order(n);
            for (std::uint64_t i = 0; i < n; ++i) order[i] = i;
            std::sort(order.begin(), order.end(), [&](std::uint64_t a, std::uint64_t b) {
                return rem[a] != rem[b] ? rem[a] > rem[b] : a < b;
            });
            const std::uint64_t deficit = Rt - assigned;
            if (deficit > 0) ++with_deficit;
            for (std::uint64_t j = 0; j < deficit; ++j) ++q[order[j]];
            const auto outs = pb::split(Rt, w);
            if (outs.size() != n) all_match = false;
            for (std::uint64_t i = 0; all_match && i < n; ++i)
                if (!(outs[i].payee == id_of(i + 1)) || outs[i].amount != q[i]) all_match = false;
        }
        check(all_match && with_deficit >= 30, "40 random windows (2..601 payees) == the u128 largest-remainder reference");
    }

    // ---- fees shared in proportion to work: more fees -> every amount grows, no key ----
    {
        const pb::Window w = mk_window(50, 2000, 1000);
        const auto a = pb::split(100000000ull, w);
        const auto b = pb::split(120000000ull, w);  // same window, +20% fees
        check(sum_amounts(a) == 100000000ull && sum_amounts(b) == 120000000ull, "each Sum == its R");
        bool same_payees = a.size() == b.size();
        for (std::size_t i = 0; same_payees && i < a.size(); ++i)
            if (!(a[i].payee == b[i].payee)) same_payees = false;
        check(same_payees, "fees change amounts, not the payee set / keys");
        bool grew = true;
        for (std::size_t i = 0; i < a.size(); ++i)
            if (b[i].amount < a[i].amount) grew = false;
        check(grew, "more fees -> every amount grows");
    }

    // ---- smallest output >= f_spend when N does not bind and R >= B ----
    {
        const std::uint64_t B = 600000000000ull;
        const std::uint64_t f = 12530000ull;      // f_spend at M 300k, hf16
        const std::uint64_t dmin = 20000;
        // W at the W_max edge: W * f == B * dmin -> W = B*dmin/f.
        const std::uint64_t W = (static_cast<unsigned __int128>(B) * dmin / f);
        pb::Window w;
        // one payee holding the smallest entry dmin, the rest filling to W.
        w.weight[id_of(1)] = pb::Work(dmin);
        w.weight[id_of(2)] = pb::Work(W - dmin);
        w.W = pb::Work(W);
        const auto outs = pb::split(B, w);  // R == B (the normal case R >= B)
        std::uint64_t smallest = ~std::uint64_t{0};
        for (const auto& o : outs) smallest = o.amount < smallest ? o.amount : smallest;
        check(smallest >= f, "smallest output >= f_spend when N does not bind and R >= B");
    }

    return finish("xmr_window_split_kat");
}
