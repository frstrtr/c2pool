// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/xmr_share_retarget_kat.cpp
// Carrier retarget (pathb_retarget.hpp) at T 10, d_min 18,180, N_rt 2,160,
// g* 101/100:
//   (1)  parameters: m_rt 9; g* 13/12 -> m 1; g* 505/504 -> m 42;
//   (2)  formula: N_rt carriers of d 1,000,000, dh 179 -> 1,005,586; a
//        window one carrier wider is cut to N_rt;
//   (3)  chain start: empty window -> d_min; one carrier of d_min with dh 0
//        -> d_min at m 1, 9 and 42 (raw 1,515 / 168 / 36);
//   (4)  dh 0: dh_eff = m (20,000,000 at m 9, 180,000,000 at m 1);
//   (5)  wide values: raw at 107/108 x (2^64 - 1) exact; raw >= 2^64 ->
//        2^64 - 1, never a wrap; W x T above 2^128 (T 2^56) exact;
//   (6)  no per-step bound: one step up x56.8 and one step down x0.0176
//        are taken as computed;
//   (7)  steady state: 10 spans at 600,000 H/s from a full window; m 1 and
//        m 9 give the same d at every carrier; d within 1 % of H x T;
//   (8)  lane start at 6,000,000 H/s: within 20 % of H x T at carrier 968
//        (m 9) and 111 (m 1);
//   (9)  hashrate falls x1/16 after 2 spans: d is within 20 % of the new
//        H x T 2,046 carriers later, before 4 spans, and stays there; m 1
//        and m 9 give the same d at every carrier;
//   (10) one Monero height for every carrier from a full window: once the
//        window holds one height, d grows by at most 109/108 per carrier
//        (m 9; 13/12 at m 1); d at checkpoints;
//   (11) seeded two-chain vector at m 9 (400 runs, seed 20261006, 7 days
//        from lane start): chain B at 2/5 of 600,000 H/s, every carrier at
//        one record height; chain A at 3/5 with carriers of d 6,000,000; B's
//        cumulative work does not exceed A's at any point where A holds
//        >= 120 or >= J = 1,152 carriers;
//   (12) one value per tip: carriers on one tip at h(tip), +1, +2 get the
//        same d; d is a function of the record heights only;
//   (13) a lane that starts from a predecessor's carriers takes the window
//        of its newest N_rt carriers; without one it starts at d_min.
// Vectors: the:K03.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>
#include <tuple>
#include <vector>

#include "impl/xmr/pathb/pathb_caps.hpp"
#include "impl/xmr/pathb/pathb_fork_choice.hpp"
#include "impl/xmr/pathb/pathb_retarget.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;
namespace nat = ::c2pool::xmr::native;

namespace {

constexpr std::uint64_t kUs = 1000000;              // time unit of the scenarios: microseconds
constexpr std::uint64_t kU64 = pb::kU64Max;

pb::LaneParams with_growth(std::uint64_t num, std::uint64_t den) {
    pb::LaneParams p = pb::kRuledLaneParams;
    p.retarget_growth_num = num;
    p.retarget_growth_den = den;
    return p;
}

std::vector<pb::RetargetEntry> repeat(std::uint64_t n, std::uint64_t d, std::uint64_t H) {
    return std::vector<pb::RetargetEntry>(n, pb::RetargetEntry{d, H});
}

// N_rt carriers of d0, one every T s, record heights h0 + floor(t / 120).
std::vector<pb::RetargetEntry> steady_window(const pb::LaneParams& p, std::uint64_t d0, std::uint64_t h0) {
    std::vector<pb::RetargetEntry> w;
    for (std::uint64_t i = 0; i < p.retarget_span; ++i)
        w.push_back(pb::RetargetEntry{d0, h0 + (i * p.carrier_interval_s) / pb::DIFFICULTY_TARGET_V2});
    return w;
}

struct Seg {
    std::uint64_t t_us;
    std::uint64_t hashrate;
};
struct Find {
    std::uint64_t t_us;
    std::uint64_t d;
    std::uint64_t h;
};

// Deterministic chain: a carrier of difficulty d takes ceil(d / H) s at hashrate H,
// Monero heights every 120 s: h = h0 + floor(t / 120).
std::vector<Find> run_chain(const pb::LaneParams& p, const std::vector<pb::RetargetEntry>& start, std::uint64_t t_us,
                            std::uint64_t h0, const std::vector<Seg>& segs, std::uint64_t t_end_us) {
    pb::RetargetWindow w(p, start);
    std::vector<Find> out;
    std::size_t i = 0;
    for (;;) {
        const std::uint64_t d = w.next_difficulty();
        while (i + 1 < segs.size() && segs[i + 1].t_us <= t_us) ++i;
        t_us += pb::ceil_div(d * kUs, segs[i].hashrate);
        if (t_us >= t_end_us) break;
        const std::uint64_t h = h0 + t_us / (pb::DIFFICULTY_TARGET_V2 * kUs);
        if (w.extend(h) != d) {
            check(false, "extend returns next_difficulty");
            break;
        }
        out.push_back(Find{t_us, d, h});
    }
    return out;
}

bool within_20pct(std::uint64_t d, std::uint64_t target) {
    return 5 * d <= 6 * target && 6 * d >= 5 * target;
}

std::vector<std::uint64_t> ds_of(const std::vector<Find>& f) {
    std::vector<std::uint64_t> v;
    for (const Find& x : f) v.push_back(x.d);
    return v;
}

// (11) seeded two-chain run: exponential waiting times from Rng.
double exp1(Rng& r) {
    const double u = static_cast<double>((r.next() >> 11) + 1) * 0x1p-53;
    return -std::log(u);
}

// Runs in which B's work exceeds A's while A holds >= 120 / >= depth_j carriers.
struct DepthPasses {
    int at_120 = 0;
    int at_j = 0;
};

DepthPasses two_chain(const pb::LaneParams& p, int trials, std::uint64_t seed, std::uint64_t depth_j) {
    constexpr std::uint64_t kH0 = 600000;
    constexpr std::uint64_t kShareNum = 2, kShareDen = 5;
    constexpr std::uint64_t kHorizonS = 7 * 86400;
    constexpr std::uint64_t kDepthShort = 120;
    constexpr std::uint64_t kOneHeight = 500;
    const std::uint64_t d0 = kH0 * p.carrier_interval_s;
    const double h_b = static_cast<double>(kH0 * kShareNum) / static_cast<double>(kShareDen);
    const double h_a = static_cast<double>(kH0 * (kShareDen - kShareNum)) / static_cast<double>(kShareDen);
    const std::uint64_t mix = 0x9E3779B97F4A7C15ull;
    DepthPasses passes;
    for (int tr = 0; tr < trials; ++tr) {
        Rng rb(seed * mix + 2 * static_cast<std::uint64_t>(tr) + 1);
        Rng ra(seed * mix + 2 * static_cast<std::uint64_t>(tr) + 2);
        pb::RetargetWindow w(p);
        double t = 0.0;
        nat::U128 work_b{};
        std::uint64_t n_a = 0;
        double t_a = exp1(ra) * static_cast<double>(d0) / h_a;
        bool past_120 = false, past_j = false;
        for (;;) {
            const std::uint64_t d = w.next_difficulty();
            t += exp1(rb) * static_cast<double>(d) / h_b;
            if (t > static_cast<double>(kHorizonS)) break;
            while (t_a <= t) {
                ++n_a;
                t_a += exp1(ra) * static_cast<double>(d0) / h_a;
            }
            work_b = nat::u128_add(work_b, nat::U128{d, 0});
            w.push(pb::RetargetEntry{d, kOneHeight});
            if (nat::u128_greater(work_b, nat::U128{d0 * n_a, 0})) {
                if (n_a >= kDepthShort) past_120 = true;
                if (n_a >= depth_j) past_j = true;
                if (past_120 && past_j) break;
            }
        }
        passes.at_120 += past_120 ? 1 : 0;
        passes.at_j += past_j ? 1 : 0;
    }
    return passes;
}

// A carrier on a held tip, with the receipts_root it commits there.
pb::CarrierAnnounce on_tip(const pb::CarrierTree& t, const pb::Hash32& id, const pb::Hash32& tip, std::uint64_t h) {
    return pb::CarrierAnnounce{id, tip, h, t.next_receipts_root(tip, {}).value_or(pb::Hash32{}), 0};
}

}  // namespace

int main() {
    std::printf("xmr_share_retarget_kat\n");
    const pb::LaneParams P = pb::kRuledLaneParams;
    const pb::LaneParams P1 = with_growth(13, 12);    // m 1
    const pb::LaneParams P42 = with_growth(505, 504); // m 42
    const std::uint64_t N = P.retarget_span;

    // (1)
    check(pb::retarget_params_valid(P) && pb::retarget_params_valid(P1) && pb::retarget_params_valid(P42),
          "parameters valid");
    check(pb::retarget_min_span(P) == 9, "m_rt = 9 at T 10, g* 101/100");
    check(pb::retarget_min_span(P1) == 1 && pb::retarget_min_span(P42) == 42, "m 1 at g* 13/12, m 42 at g* 505/504");
    check(P.d_min == 18180 && N == 2160 && P.carrier_interval_s == 10, "K01 10, K02 18,180, K03 2,160");
    check(!pb::retarget_params_valid(with_growth(100, 100)) && !pb::retarget_params_valid(with_growth(1, 0)),
          "g* <= 1 refused");

    // (2)
    {
        std::vector<pb::RetargetEntry> w;
        for (std::uint64_t i = 0; i < N; ++i) w.push_back(pb::RetargetEntry{1000000, 5000 + (i * 179) / (N - 1)});
        check(w.back().H - w.front().H == 179, "window dh 179");
        check(pb::retarget(P, w) == 1005586, "W 2,160,000,000, dh 179, T 10 -> 1,005,586");
        check(pb::retarget(P1, w) == 1005586, "same at m 1");
        // N_rt + 1 carriers spanning 180 heights; the newest N_rt span 179
        std::vector<pb::RetargetEntry> wider{pb::RetargetEntry{1000000, 5000}};
        for (std::uint64_t i = 0; i < N; ++i) wider.push_back(pb::RetargetEntry{1000000, 5001 + (i * 179) / (N - 1)});
        check(wider.back().H - wider.front().H == 180, "N_rt + 1 carriers span 180 heights");
        check(pb::retarget(P, wider) == 1005586 && pb::retarget(P, std::span(wider).subspan(1)) == 1005586,
              "window = the newest N_rt carriers: 1,005,586");
        pb::RetargetWindow rw(P, wider);
        check(rw.size() == N && rw.work() == nat::U128{N * 1000000, 0} && rw.height_span() == 179,
              "rolling window keeps N_rt, W 2,160,000,000, dh 179");
        check(rw.next_difficulty() == pb::retarget(P, wider), "rolling window = span form");
    }

    // (3)
    check(pb::retarget(P, std::vector<pb::RetargetEntry>{}) == P.d_min, "k = 1: empty window -> d_min");
    for (const pb::LaneParams& q : {P1, P, P42}) {
        check(pb::retarget(q, repeat(1, P.d_min, 77)) == P.d_min, "k = 2: one carrier of d_min -> d_min");
    }
    {
        // raw below the floor: 18,180 x 10 / (120 m)
        const nat::U128 W{P.d_min, 0};
        check(pb::rt_wide::div_u256_u128(pb::rt_wide::mul_u128_u64(W, 10), pb::rt_wide::mul_64x64(120, 1)).w[0] == 1515
                      && pb::rt_wide::div_u256_u128(pb::rt_wide::mul_u128_u64(W, 10), pb::rt_wide::mul_64x64(120, 9)).w[0] == 168
                      && pb::rt_wide::div_u256_u128(pb::rt_wide::mul_u128_u64(W, 10), pb::rt_wide::mul_64x64(120, 42)).w[0] == 36,
              "raw 1,515 / 168 / 36");
    }

    // (4)
    check(pb::retarget(P, repeat(N, 1000000, 777)) == 20000000, "dh 0, m 9: 20,000,000");
    check(pb::retarget(P1, repeat(N, 1000000, 777)) == 180000000, "dh 0, m 1: 180,000,000");

    // (5)
    {
        check(pb::retarget(P, repeat(107, kU64, 5)) == 18275940887841870581ull, "raw 107/108 x (2^64 - 1) exact");
        check(pb::retarget(P, repeat(108, kU64, 5)) == kU64, "raw = 2^64 - 1");
        check(pb::retarget(P, repeat(109, kU64, 5)) == kU64, "raw >= 2^64 -> 2^64 - 1");
        check(pb::retarget(P, repeat(N, kU64, 5)) == kU64, "full window of 2^64 - 1 at dh 0 -> 2^64 - 1");
        std::vector<pb::RetargetEntry> wide = repeat(N, kU64, kU64);
        wide.front().H = 0;
        check(pb::retarget(P, wide) == P.d_min, "dh 2^64 - 1 -> floor d_min");
        pb::LaneParams pw = with_growth(2, 1);
        pw.carrier_interval_s = std::uint64_t{1} << 56;
        check(pb::retarget_params_valid(pw) && pb::retarget_min_span(pw) == 600479950316067ull, "T 2^56: m");
        check(pb::retarget(pw, wide) == 18 * (std::uint64_t{1} << 56), "W x T above 2^128: exact quotient");
        const pb::rt_wide::U256 prod = pb::rt_wide::mul_u128_u64(nat::U128{kU64, kU64}, kU64);
        check(prod.w[0] == 1 && prod.w[1] == kU64 && prod.w[2] == kU64 - 1 && prod.w[3] == 0,
              "(2^128 - 1)(2^64 - 1) in 256 bits");
        check(pb::rt_wide::div_u256_u128(prod, nat::U128{kU64, 0}) == pb::rt_wide::U256{{kU64, kU64, 0, 0}},
              "256 / 128 division");
        check(pb::rt_wide::div_u256_u128(prod, nat::U128{kU64, kU64}) == pb::rt_wide::U256{{kU64, 0, 0, 0}},
              "division by 2^128 - 1");
    }

    // (6)
    {
        std::vector<pb::RetargetEntry> w{pb::RetargetEntry{1000000000, 0}};
        for (std::uint64_t i = 1; i < N; ++i) w.push_back(pb::RetargetEntry{1000000000, 10000 + ((i - 1) * 179) / (N - 2)});
        pb::RetargetWindow up(P, w);
        const std::uint64_t d_prev = up.next_difficulty();
        up.push(pb::RetargetEntry{d_prev, w.back().H});
        const std::uint64_t d_next = up.next_difficulty();
        check(d_prev == 17683465 && d_next == 1005129275, "up step: 17,683,465 -> 1,005,129,275");
        check(d_next > 4 * d_prev, "up step above 4x taken as computed");
        std::vector<pb::RetargetEntry> w2;
        for (std::uint64_t i = 0; i < N; ++i) w2.push_back(pb::RetargetEntry{1000000000, 5000 + (i * 179) / (N - 1)});
        pb::RetargetWindow down(P, w2);
        const std::uint64_t d2_prev = down.next_difficulty();
        down.push(pb::RetargetEntry{d2_prev, w2.back().H + 10000});
        const std::uint64_t d2_next = down.next_difficulty();
        check(d2_prev == 1005586592 && d2_next == 17683511, "down step: 1,005,586,592 -> 17,683,511");
        check(4 * d2_next < d2_prev, "down step below 1/4 taken as computed");
    }

    const std::uint64_t span_us = N * P.carrier_interval_s * kUs;

    // (7)
    {
        const std::uint64_t H = 600000, d0 = H * P.carrier_interval_s;
        const std::vector<pb::RetargetEntry> w = steady_window(P, d0, 1000);
        const std::uint64_t t0 = span_us;
        const std::vector<Find> a = run_chain(P1, w, t0, 1000, {{0, H}}, t0 + 10 * span_us);
        const std::vector<Find> b = run_chain(P, w, t0, 1000, {{0, H}}, t0 + 10 * span_us);
        check(ds_of(a) == ds_of(b), "steady: m 1 and m 9 give the same d at every carrier");
        check(b.size() == 21590, "steady: 21,590 carriers in 10 spans");
        check(b[0].d == 6033519 && b[1].d == 6000015 && b.back().d == 6002839, "steady: first and last d");
        bool in1 = true;
        std::uint64_t lo = kU64, hi = 0;
        for (const Find& f : b) {
            if (f.t_us < t0 + 2 * span_us) continue;
            lo = std::min(lo, f.d);
            hi = std::max(hi, f.d);
            in1 = in1 && 100 * f.d >= 99 * d0 && 100 * f.d <= 101 * d0;
        }
        check(in1 && lo == 5969630 && hi == 6036293, "steady: d within 1 % of H x T after 2 spans");
    }

    // (8)
    {
        const std::uint64_t H = 6000000, dstar = H * P.carrier_interval_s;
        const std::uint64_t t_end = 2 * 3600 * kUs;
        for (const auto& [q, k_in, d_in] : {std::tuple{P, std::size_t{968}, std::uint64_t{50343172}},
                                             std::tuple{P1, std::size_t{111}, std::uint64_t{50238134}}}) {
            const std::vector<Find> f = run_chain(q, {}, 0, 1000, {{0, H}}, t_end);
            std::size_t k = 0;
            while (k < f.size() && !within_20pct(f[k].d, dstar)) ++k;
            check(k == k_in && k < f.size() && f[k].d == d_in && f[0].d == P.d_min,
                  "lane start: within 20 % at carrier " + std::to_string(k_in));
        }
    }

    // (9)
    {
        constexpr std::uint64_t kFall = 16;
        const std::uint64_t H1 = 600000, H0 = H1 * kFall, d0 = H0 * P.carrier_interval_s, dstar = H1 * P.carrier_interval_s;
        const std::vector<pb::RetargetEntry> w = steady_window(P, d0, 1000);
        const std::uint64_t t0 = span_us, tf = t0 + 2 * span_us;
        const std::vector<Find> a = run_chain(P, w, t0, 1000, {{0, H0}, {tf, H1}}, tf + 8 * span_us);
        const std::vector<Find> b = run_chain(P1, w, t0, 1000, {{0, H0}, {tf, H1}}, tf + 8 * span_us);
        check(ds_of(a) == ds_of(b), "fall: m 1 and m 9 give the same d at every carrier");
        std::size_t pre = 0;
        while (pre < a.size() && a[pre].t_us < tf) ++pre;
        std::size_t k = pre;
        while (k < a.size() && !within_20pct(a[k].d, dstar)) ++k;
        check(pre == 4318 && k == 6364 && a[k].d == 7195504, "fall: within 20 % after 2,046 carriers");
        check(a[k].t_us - tf < 4 * span_us && a[k].t_us - tf > 3 * span_us, "fall: recovered before 4 spans");
        bool stays = true;
        for (std::size_t i = k; i < a.size(); ++i) stays = stays && within_20pct(a[i].d, dstar);
        check(stays && a.back().d == 6002729, "fall: stays within 20 % after recovery");

        // (12) the d of a chain is a function of its record heights only
        pb::RetargetWindow replay(P, w);
        bool same = true;
        for (const Find& f : a) same = same && replay.extend(f.h) == f.d;
        check(same, "heights alone reproduce every d");
    }

    // (10)
    {
        const std::vector<pb::RetargetEntry> w = steady_window(P, 1000000, 1000);
        for (const auto& [q, d_n1, d_n, d_2n, d_end] :
             {std::tuple{P, std::uint64_t{564488520}, std::uint64_t{569706006}, std::uint64_t{251630456989191879ull}, kU64},
              std::tuple{P1, std::uint64_t{65186364073ull}, std::uint64_t{70618477746ull}, kU64, kU64}}) {
            pb::RetargetWindow rw(q, w);
            const std::uint64_t hf = rw.newest_record();
            const std::uint64_t m = pb::retarget_min_span(q);
            std::vector<std::uint64_t> ds;
            bool bounded = true;
            for (std::uint64_t k = 0; k < 3 * N; ++k) {
                const bool one_height = rw.height_span() == 0;
                const std::uint64_t d = rw.extend(hf);
                if (one_height && !ds.empty() && ds.back() < kU64 && d < kU64) {
                    // d_k <= d_{k-1} x (120 m + T) / (120 m), compared in 128 bits
                    const nat::U128 lhs = pb::rt_wide::mul_64x64(d, 120 * m);
                    const nat::U128 rhs = pb::rt_wide::mul_64x64(ds.back(), 120 * m + q.carrier_interval_s);
                    bounded = bounded && !nat::u128_greater(lhs, rhs);
                }
                ds.push_back(d);
            }
            check(ds[0] == 1005586 && ds[N - 1] == d_n1 && ds[N] == d_n && ds[2 * N] == d_2n && ds.back() == d_end,
                  "one height, m " + std::to_string(m) + ": d at 0, N_rt - 1, N_rt, 2 N_rt, 3 N_rt - 1");
            check(bounded, "one height, m " + std::to_string(m) + ": growth <= 1 + T / (120 m) per carrier");
        }
    }

    // (11)
    {
        const std::uint64_t J = pb::journal_depth(P);
        check(J == 1152, "J = 1,152");
        const DepthPasses at_m9 = two_chain(P, 400, 20261006, J);
        check(at_m9.at_j == 0 && at_m9.at_120 == 0, "two chains, m 9: B's work never above A's at depth >= 120 or >= J");
    }

    // (12) one value per tip
    {
        pb::CarrierTree t(P, seq32(0x01), 1000, pb::EpochTable{});
        pb::Hash32 tip = seq32(0x01);
        for (std::uint64_t i = 1; i <= 40; ++i) {
            pb::Hash32 id = seq32(0x40);
            id[0] = static_cast<std::uint8_t>(i);
            t.place(on_tip(t, id, tip, 1000 + i / 12), {});
            tip = id;
        }
        const std::uint64_t h_tip = t.find(tip)->h;
        const std::uint64_t d = *t.next_difficulty(tip);
        bool same = true;
        for (std::uint64_t dh = 0; dh <= 2; ++dh) {
            pb::Hash32 id = seq32(0x90);
            id[0] = static_cast<std::uint8_t>(0x90 + dh);
            same = same && t.place(on_tip(t, id, tip, h_tip + dh), {}).verdict == pb::PlaceVerdict::Placed
                   && t.find(id)->d == d;
        }
        check(same, "h(tip), +1, +2 on one tip: one d");
        static_assert(sizeof(pb::RetargetEntry) == 2 * sizeof(std::uint64_t), "window entry = d and record height");
    }

    // (13)
    {
        const std::uint64_t H = 600000, d0 = H * P.carrier_interval_s;
        const std::vector<pb::RetargetEntry> w = steady_window(P, d0, 1000);
        const std::vector<Find> run = run_chain(P, w, span_us, 1000, {{0, H}}, span_us + 1000 * P.carrier_interval_s * kUs);
        std::vector<pb::RetargetEntry> pred = w;
        for (std::size_t i = 0; i < 100; ++i) pred.push_back(pb::RetargetEntry{run[i].d, std::max(pred.back().H, run[i].h)});
        check(pred.size() == N + 100 && pb::retarget(P, pred) == 6000016, "predecessor: next d 6,000,016");
        pb::RetargetWindow inherited(P, pred);
        check(inherited.size() == N && inherited.next_difficulty() == 6000016, "window keeps the newest N_rt");

        pb::CarrierTree lane(P, seq32(0x02), pred.back().H, pb::EpochTable{}, pred);
        pb::CarrierTree fresh(P, seq32(0x02), pred.back().H, pb::EpochTable{});
        check(*lane.next_difficulty(seq32(0x02)) == 6000016, "inherited lane: position 1 at 6,000,016");
        check(*fresh.next_difficulty(seq32(0x02)) == P.d_min, "lane without a predecessor: position 1 at d_min");
        // positions 1..k on the new lane continue the window
        std::vector<pb::RetargetEntry> joined = pred;
        pb::Hash32 tip = seq32(0x02);
        bool cont = true;
        for (std::uint64_t i = 1; i <= 30; ++i) {
            pb::Hash32 id = seq32(0x60);
            id[0] = static_cast<std::uint8_t>(i);
            const std::uint64_t h = pred.back().H + i / 12;
            cont = cont && lane.place(on_tip(lane, id, tip, h), {}).verdict == pb::PlaceVerdict::Placed
                   && lane.find(id)->d == pb::retarget(P, joined);
            joined.push_back(pb::RetargetEntry{lane.find(id)->d, lane.find(id)->H});
            tip = id;
        }
        check(cont, "inherited lane: d over predecessor + lane carriers");
        check(lane.genesis().H == pred.back().H, "inherited lane: genesis record height");
    }

    return finish("xmr_share_retarget_kat");
}
