// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// xmr_wide_int_extreme_kat (pathb_wide.hpp / pathb_window.hpp, C30, C35): the
// wide-integer paths at their extremes. R = 2^64-1 with one payee of weight
// 2^255-1 and W = 2^255-1; 10,000 payees of weight 2^64-1; N(B) at Z = 2^32-1;
// the W_max and merge-back U320 compares at f_spend = 2^63 and d_min = 2^64-1.
// These paths never clamp or wrap: the U320 products are EXACT, as the C35
// width-law review requires of the money path.
// ---------------------------------------------------------------------------
#include <cstdint>

#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_wide.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 id_of(std::uint64_t i) {
    pb::Hash32 h{};
    for (int b = 0; b < 8; ++b) h[31 - b] = static_cast<std::uint8_t>(i >> (8 * b));
    return h;
}
static pb::Work w255() {  // 2^255 - 1
    pb::Work w;
    w.v = {~0ull, ~0ull, ~0ull, 0x7fffffffffffffffull};
    return w;
}

int main() {
    using pb::wide::u128;

    // mul_u256_u64 is EXACT against __int128 for u64 x u64 and small U256 (no wrap).
    {
        const std::uint64_t a = 0xDEADBEEFCAFEBABEull, b = 0x0123456789ABCDEFull;
        const u128 want = static_cast<u128>(a) * b;
        const pb::wide::U320 got = pb::wide::mul_u64_u64(a, b);
        check(got.v[0] == static_cast<std::uint64_t>(want) && got.v[1] == static_cast<std::uint64_t>(want >> 64)
                      && got.v[2] == 0,
              "mul_u64_u64 exact vs __int128");
    }

    // R = 2^64-1, one payee of weight 2^255-1, W = 2^255-1 -> that payee gets all of R.
    {
        pb::Window w;
        w.weight[id_of(1)] = w255();
        w.W = w255();
        const auto outs = pb::split(~std::uint64_t{0}, w);
        check(outs.size() == 1 && outs[0].amount == ~std::uint64_t{0}, "R = 2^64-1 to one payee of weight W");
    }

    // 10,000 payees each of weight 2^64-1: Sum(vout) == R exactly.
    {
        pb::Window w;
        for (std::uint64_t i = 0; i < 10000; ++i) {
            w.weight[id_of(i + 1)] = pb::Work(~std::uint64_t{0});
            w.W += pb::Work(~std::uint64_t{0});
        }
        const std::uint64_t R = 123456789012345ull;
        const auto outs = pb::split(R, w);
        std::uint64_t s = 0;
        for (const auto& o : outs) s += o.amount;
        check(outs.size() == 10000 && s == R, "10000 payees of weight 2^64-1: Sum == R");
    }

    // divmod against __int128 where the product fits (random sweep, w <= W).
    {
        Rng rng(0xE7312345ull);
        for (int i = 0; i < 20000; ++i) {
            const std::uint64_t R = rng.next();
            const std::uint64_t W = (rng.next() % 1000000) + 1;
            const std::uint64_t w = rng.below(W + 1);
            pb::Work rem;
            const std::uint64_t q = pb::wide::divmod_u320_u256(
                    pb::wide::mul_u256_u64(pb::Work(w), R), pb::Work(W), rem);
            const u128 prod = static_cast<u128>(R) * w;
            if (q != static_cast<std::uint64_t>(prod / W) || rem.v[0] != static_cast<std::uint64_t>(prod % W)
                || rem.v[1] || rem.v[2] || rem.v[3]) {
                check(false, "divmod_u320_u256 matches __int128");
                break;
            }
        }
        check(true, "divmod exact over 20000 random (R, w<=W)");
    }

    // N(B) at Z = 2^32-1 computes without overflow.
    {
        const std::uint64_t n = pb::n_rule(0xFFFFFFFFull, 16, 600000000000ull);
        check(n == (0xFFFFFFFFull / 2 - 89) / 40, "N(B) at Z = 2^32-1 (no overflow)");
    }

    // the W_max and merge-back U320 compares at f_spend = 2^63, d_min = 2^64-1.
    {
        const std::uint64_t f = std::uint64_t{1} << 63;
        const std::uint64_t dmin = ~std::uint64_t{0};
        const std::uint64_t B = 600000000000ull;
        pb::Work W; W.v = {0, 1, 0, 0};  // W = 2^64
        // W_max: (W) x f <= B x d_min ?  both U320, exact.
        const pb::wide::U320 lhs = pb::wide::mul_u256_u64(W, f);
        const pb::wide::U320 rhs = pb::wide::mul_u64_u64(B, dmin);
        // W x f = 2^64 x 2^63 = 2^127; B x dmin ~ 6e11 x 1.8e19 ~ 1.1e31 ~ 2^103.
        check(rhs < lhs, "W_max compare exact at f_spend = 2^63, d_min = 2^64-1 (2^127 > ~2^103)");
        // merge-back: w_X x B < W x f ?  exact.
        pb::Work wx; wx.v = {1000, 0, 0, 0};
        check(pb::wide::mul_u256_u64(wx, B) < pb::wide::mul_u256_u64(W, f), "merge-back compare exact");
    }

    return finish("xmr_wide_int_extreme_kat");
}
