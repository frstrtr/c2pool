// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See <https://www.gnu.org/licenses/>.
//
// v37_xmr_drops_count_kat -- DROPS on the XMR lane credits every hash below the
// drops floor at the floor's own work (SubthresholdGate mode 2, Count), the
// work its TARGET expected (paper §5), in the design's integer unit.
//
//   CT1 the XMR default lane selects Count (mode 2, floor shift 6).
//   CT2 integer exactness on the 288-bit normalised geometry (lz = 32):
//       att(floor) = floor(2^256 / 2^230) = 2^26 = 1/64 of a share's 2^32;
//       Hhat = (S + J) * 2^26; REPLACE delta = (S + J) * 2^26 - S * 2^32.
//   CT3 the floor is the EXACT one, N < 2^230 <=> H * share_diff < 2^262, for
//       any share_diff (10000 is not a multiple of 64): a hash one below it is
//       counted, the one at it is not.
//   CT4 no K and no J < K rule: one raindrop alone is credited.
//   CT5 unbiased and split-neutral in mean AND variance on the censored XMR
//       stream, through the shipped interval_work(); the K-min (Combined)
//       estimator on the same stream is biased and moves with the split.
//   CT6 the whole seam (subthreshold_credit): S = 1, J = 63 -> delta 0;
//       S = 0, J = 64 -> exactly one share's entitlement; not enrolled -> none.
//
// Research: docs/research/drops-split/.

#include <cmath>
#include <cstdio>
#include <map>
#include <random>
#include <string>
#include <vector>

#include <c2pool/v37/v37_subthreshold_estimator.hpp>
#include <c2pool/v37/v37_drop_harvest.hpp>
#include <c2pool/v37/v37_drops_enrollment.hpp>
#include <c2pool/v37/w4_settlement.hpp>
#include <c2pool/v37/xmr/xmr_node_config.hpp>
#include <c2pool/v37/xmr/xmr_drops_wiring.hpp>

namespace st = ::c2pool::v37::subthreshold;
namespace settle = ::c2pool::v37n::settle;
namespace dx = ::c2pool::v37n::xmr::drops;

static int g_pass = 0, g_fail = 0;
static void check(bool ok, const std::string& what) {
    (ok ? g_pass : g_fail)++;
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
}

// 2^b as a u256 (b < 256).
static st::u256 pow2(unsigned b) { st::u256 x; x.w[b >> 6] = 1ull << (b & 63); return x; }
static st::u256 minus1(st::u256 x) {
    for (auto& w : x.w) { if (w-- != 0) break; }
    return x;
}
static bool u320_eq_pow2(const st::u320& a, unsigned b) {
    for (std::size_t i = 0; i < a.w.size(); ++i)
        if (a.w[i] != ((i == (b >> 6)) ? (1ull << (b & 63)) : 0ull)) return false;
    return true;
}
static double u320_d(const st::u320& a) {
    double r = 0;
    for (int i = 4; i >= 0; --i) r = r * 18446744073709551616.0 + (double)a.w[static_cast<std::size_t>(i)];
    return r;
}
// A floor-normalised u in [0, 1) as the normalised hash u * 2^230 (lz = 32).
static st::u256 hash_of(double u) {
    const unsigned long long m = (unsigned long long)std::ldexp(u, 63);
    st::u256 h;
    // value = m << 167
    const unsigned sh = 167;
    h.w[sh >> 6] |= m << (sh & 63);
    if (sh & 63) h.w[(sh >> 6) + 1] |= m >> (64 - (sh & 63));
    return h;
}

int main() {
    std::printf("== v37_xmr_drops_count_kat\n");
    const st::u256 hT = ::c2pool::v37n::drops_detail::h_t_of_lz(dx::kXmrDropsLz);   // 2^224 - 1
    const std::uint32_t SH = ::c2pool::v37n::xmr::kXmrDropsFloorShift;

    std::printf("-- CT1 the XMR default lane selects Count\n");
    {
        const ::v37::LaneParams p = ::c2pool::v37n::xmr::xmr_lane_params_default();
        check(p.subthreshold.enabled, "CT1 DROPS is on in the XMR build");
        check(p.subthreshold.mode == 2 && p.subthreshold.count_floor_shift == 6,
              "CT1 mode 2 (Count), floor shift 6 (share_diff / 64)");
        const auto sp = settle::to_subthreshold_params(p);
        check(sp.mode == st::CreditMode::Count && sp.count_floor_shift == 6,
              "CT1 the W4 seam maps it to CreditMode::Count");
        check(dx::kDropsFloorDiv == (1ull << SH), "CT1 the relay floor divisor is 2^shift");
    }

    std::printf("-- CT2 integer exactness (lz = 32 geometry)\n");
    {
        check(u320_eq_pow2(st::att_of_floor(hT, SH), 26), "CT2 att(floor) == 2^26");
        check(u320_eq_pow2(st::share_covered_work_att(1, hT), 32) && u320_eq_pow2(st::share_covered_work(1, hT), 32),
              "CT2 one share's work == 2^32 (att form and the K-min form agree on this geometry)");
        check(u320_eq_pow2(st::estimate_count(1, 63, hT, SH), 32), "CT2 S=1, J=63 -> 64 * 2^26 == 2^32 (one share)");
        const st::u320 e = st::estimate_count(3, 5, hT, SH);
        check(e.w[0] == 8ull << 26 && e.w[1] == 0, "CT2 S=3, J=5 -> exactly 8 * 2^26");
    }

    std::printf("-- CT3 the exact floor, any share_diff\n");
    {
        st::ReceiptCollector rc(4, hT);
        rc.observe(minus1(pow2(230)));   // N = 2^230 - 1: below the floor
        rc.observe(pow2(230));           // N = 2^230: at the floor, not below
        rc.observe(pow2(229));
        check(rc.near_miss_below(SH) == 2, "CT3 N < 2^230 counted, N == 2^230 not");
        // share_diff = 10000 (not a multiple of 64): H * 10000 < 2^262 exactly.
        const std::uint64_t sd = 10000;
        // H_max = floor((2^262 - 1) / 10000); build it as bytes via long division.
        std::array<std::uint64_t, 5> num{0, 0, 0, 0, 1ull << 6};   // 2^262
        for (auto& w : num) { if (w-- != 0) break; }                  // 2^262 - 1
        std::array<std::uint64_t, 5> q{};
        unsigned __int128 rem = 0;
        for (int i = 4; i >= 0; --i) {
            const unsigned __int128 cur = (rem << 64) | num[static_cast<std::size_t>(i)];
            q[static_cast<std::size_t>(i)] = (std::uint64_t)(cur / sd);
            rem = cur % sd;
        }
        auto le_bytes = [](const std::array<std::uint64_t, 5>& v) {
            ::v37::bytes32 b{};
            for (int i = 0; i < 32; ++i) b[static_cast<std::size_t>(i)] = (std::uint8_t)(v[static_cast<std::size_t>(i / 8)] >> (8 * (i % 8)));
            return b;
        };
        const auto in  = dx::normalized_hash(le_bytes(q), sd);
        std::array<std::uint64_t, 5> q1 = q; for (auto& w : q1) { if (++w != 0) break; }
        const auto out = dx::normalized_hash(le_bytes(q1), sd);
        st::ReceiptCollector r2(4, hT);
        r2.observe(::c2pool::v37n::drops_detail::u256_of(in));
        r2.observe(::c2pool::v37n::drops_detail::u256_of(out));
        check(r2.near_miss_below(SH) == 1,
              "CT3 share_diff 10000: the largest H with H*sd < 2^262 is counted, H+1 is not");
    }

    std::printf("-- CT4 no K, no J < K rule\n");
    {
        st::SubthresholdParams sp; sp.enabled = true; sp.mode = st::CreditMode::Count; sp.count_floor_shift = SH;
        st::ReceiptCollector rc(4, hT);
        rc.observe(pow2(229));
        std::map<st::DedupKey, bool> seen;
        const auto w = st::interval_work(sp, st::DedupKey{}, rc, seen, true);
        check(w.credited && u320_eq_pow2(w.est, 26) && w.covered.is_zero(), "CT4 one raindrop alone: credited 2^26");
        std::map<st::DedupKey, bool> seen2;
        st::ReceiptCollector empty(4, hT);
        check(!st::interval_work(sp, st::DedupKey{}, empty, seen2, true).credited, "CT4 nothing seen: no row");
    }

    std::printf("-- CT5 unbiased and split-neutral (the censored XMR stream)\n");
    {
        std::mt19937_64 rng(20260930);
        const long IV = 40000;
        auto run = [&](st::CreditMode mode, double lam, int N, double& mean, double& cv) {
            st::SubthresholdParams sp; sp.enabled = true; sp.mode = mode; sp.K = 4; sp.count_floor_shift = SH;
            double s = 0, q = 0;
            for (long it = 0; it < IV; ++it) {
                double tot = 0;
                for (int k = 0; k < N; ++k) {
                    st::ReceiptCollector rc(4, hT);
                    std::uint64_t S = 0;
                    const int n = std::poisson_distribution<int>(lam / N)(rng);
                    for (int j = 0; j < n; ++j) {
                        const double u = std::uniform_real_distribution<double>(0, 1)(rng);
                        if (u < 1.0 / 64) ++S; else rc.observe(hash_of(u));
                    }
                    rc.set_shares(S);
                    std::map<st::DedupKey, bool> seen;
                    const auto w = st::interval_work(sp, st::DedupKey{}, rc, seen, true);
                    // credit in floor units: E_b's S*64 plus the REPLACE delta
                    double c = 64.0 * (double)S;
                    if (w.credited) c += (u320_d(w.est) - u320_d(w.covered)) / 67108864.0;   // / 2^26
                    tot += c;
                }
                s += tot / lam; q += (tot / lam) * (tot / lam);
            }
            mean = s / IV; cv = std::sqrt(q / IV - mean * mean) / mean;
        };
        for (double lam : {16.0, 64.0}) {
            double m1, c1, m16, c16, k1, kc1, k16, kc16;
            run(st::CreditMode::Count, lam, 1, m1, c1);
            run(st::CreditMode::Count, lam, 16, m16, c16);
            run(st::CreditMode::Combined, lam, 1, k1, kc1);
            run(st::CreditMode::Combined, lam, 16, k16, kc16);
            char b[256];
            std::snprintf(b, sizeof b, "CT5 lambda %.0f: Count N=1 %.3f (cv %.3f), N=16 %.3f (cv %.3f); K-min N=1 %.3f, N=16 %.3f",
                          lam, m1, c1, m16, c16, k1, k16);
            std::printf("     %s\n", b);
            check(std::fabs(m1 - 1) < 0.02 && std::fabs(m16 - 1) < 0.02, std::string("CT5 Count unbiased on 1 and 16 identities, lambda ") + std::to_string((int)lam));
            check(std::fabs(c1 - c16) < 0.04 * c1, std::string("CT5 Count variance unchanged by the split, lambda ") + std::to_string((int)lam));
            if (lam == 64.0)
                check(k16 - k1 > 0.1, "CT5 control: K-min pays the 16-way split > 10% more (the reason for Count)");
        }
    }

    std::printf("-- CT6 the whole seam\n");
    {
        ::v37::LaneParams p = ::c2pool::v37n::xmr::xmr_lane_params_default();
        settle::DropsCompose ctx;
        ctx.price.reward = 64ull * 1000000;     // 64 shares worth 1e6 each
        ctx.price.sum_weight.v[1] = 16;         // 64 shares of weight in Q62: 64 << 62 = 2^68
        ctx.price.valid = true;
        // Price one share of work (2^32 estimator units) as the lane prices a share:
        // sum' = SUM weight << lz (receipt weight 1), so one share == reward / 64.
        ctx.price = dx::rescale_price(ctx.price, 1);
        ::c2pool::v37n::EnrollmentBook book;
        ::v37::bytes32 A{}, B{}, C{}; A[0] = 1; B[0] = 2; C[0] = 3;
        book.commit(A, 0, 1); book.commit(B, 0, 1);   // C never enrols
        ctx.enrollment = &book;
        auto rec = [&](const ::v37::bytes32& who, std::uint64_t S, int J) {
            settle::HarvestedReceipt hr{who, 5, st::ReceiptCollector(4, hT)};
            for (int j = 0; j < J; ++j) hr.collector.observe(pow2(228));
            hr.collector.set_shares(S);
            return hr;
        };
        std::vector<settle::HarvestedReceipt> h{rec(A, 1, 63), rec(B, 0, 64), rec(C, 0, 64)};
        const auto d = settle::subthreshold_credit(p, h, ctx);
        const long long one_share = settle::entitlement_of_work(ctx.price, st::share_covered_work(1, hT));
        check(one_share == 1000000, "CT6 the priced share is worth reward / 64 (" + std::to_string(one_share) + ")");
        check(d.count(A) == 0, "CT6 S=1, J=63: delta 0 (a share and its 63 raindrops are one share of work)");
        check(d.count(B) && d.at(B) == one_share, "CT6 S=0, J=64: exactly one share's entitlement");
        check(d.count(C) == 0, "CT6 a payee that never enrolled gets no row");
    }

    std::printf("== v37_xmr_drops_count_kat: %d passed, %d failed -> %s\n", g_pass, g_fail, g_fail ? "FAIL" : "OK");
    return g_fail ? 1 : 0;
}
