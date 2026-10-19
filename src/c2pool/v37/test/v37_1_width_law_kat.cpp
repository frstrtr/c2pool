// SPDX-License-Identifier: AGPL-3.0-or-later
// v37_1_width_law_kat.cpp -- the V37.1 width law settles at its fixed point.
//
// The law (winlaw, v37_lane.hpp) aims the window at C * D_net / rate bins,
// where rate is the pool's raw work per bin. The rate is raw / span, and the
// span is the number of bins the raw work was measured over:
//
//   WL-1  retarget_width(d, W, raw) == retarget_width_over(d, W, raw, W)
//         (the positional-window form is unchanged, bit for bit);
//   WL-2  the pure law, fed one R_b-bin period at a constant rate, settles at
//         C * D / rate from both sides and stays there;
//   WL-3  the REAL native-ridge lane (LTC, the ruled gate, d_net != 0) settles
//         at the same fixed point. Before the 2026-09-30 fix it divided
//         C * D * W_cur by ONE period's raw work and ran to W_MAX (4608).
//
// Research note: docs/research/window-pulse/README.md.

#include <cstdio>
#include <cstdint>

#include "sharechain/v37/v37_lane.hpp"

using namespace v37;

static long g_checks = 0, g_fail = 0;
static void check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) { ++g_fail; std::printf("  FAIL: %s\n", what); }
}

static bytes32 key_of(MinerId m) {
    std::uint8_t b[4] = {std::uint8_t(m), std::uint8_t(m >> 8), std::uint8_t(m >> 16), std::uint8_t(m >> 24)};
    return ::v37::sha256d(b, 4);
}

// Drive the real lane with the ridge flipped at 4096 and a constant pool:
// `per_bin` pushes of `w` raw work per bin, D_net = d. Returns the final W.
static u64 drive_nr(u64 per_bin, u64 w, u64 d, u64 periods, u64* retargets) {
    LaneParams p = LaneParams::for_version(1, LaneKind::LTC);
    p.mrr.activation_pos   = 4096;
    p.nr.nr_activation_pos = 4096;
    ::v37::Lane lane(p);
    const u64 n = 4096 + per_bin * p.nr.retarget_bins * periods;
    for (u64 i = 0; i < n; ++i) {
        ::v37::WorkAtom a{};
        a.miner       = MinerId(1 + (i % 7));
        a.w_raw       = w;
        a.origin_bin  = i / per_bin;
        a.carrier_bin = a.origin_bin;
        a.version     = ::v37::PROV_V37;
        a.d_net       = U256{d};
        lane.push(a, key_of);
    }
    if (retargets) *retargets = lane.nr_retargets();
    return lane.nr_W_bins();
}

int main() {
    std::printf("== v37_1_width_law_kat\n");
    const WinGate g = winlaw::for_version(1, LaneKind::LTC);   // 528 / 576 / 4608, C = 576 [OWED]
    const u64 C = g.coverage_blocks;

    std::printf("-- WL-1 positional form unchanged --\n");
    {
        long same = 0, n = 0;
        for (u64 d : {1ull, 16ull, 1000ull, 123456789ull})
            for (u64 W : {8ull, 528ull, 576ull, 1000ull, 4608ull})
                for (u64 raw : {1ull, 7ull, 4096ull, 999983ull, 1ull << 40}) {
                    ++n;
                    same += winlaw::retarget_width(U256{d}, W, raw, g) ==
                            winlaw::retarget_width_over(U256{d}, W, raw, W, g);
                }
        std::printf("   %ld / %ld identical\n", same, n);
        check(same == n, "retarget_width == retarget_width_over(span = W_cur)");
        check(winlaw::retarget_width_over(U256{16}, 576, 0, 8, g) == 576, "no work -> W_default");
        check(winlaw::retarget_width_over(U256{16}, 576, 64, 0, g) == 576, "empty span -> W_default");
    }

    std::printf("-- WL-2 pure law, one-period divisor, fixed point --\n");
    {
        // rate 8 per bin, D 16: W* = C * D / rate = 576 * 16 / 8 = 1152
        const u64 d = 16, rate = 8, R = g.retarget_bins, want = C * d / rate;
        for (u64 W0 : {g.w_min_bins, g.w_default_bins, g.w_max_bins}) {
            u64 W = W0;
            for (int k = 0; k < 10; ++k) W = winlaw::retarget_width_over(U256{d}, W, (u128)rate * R, R, g);
            std::printf("   from %llu -> %llu (want %llu)\n", (unsigned long long)W0, (unsigned long long)W,
                        (unsigned long long)want);
            check(W == want, "the period law settles at C * D / rate");
        }
        u64 W = g.w_default_bins;
        for (int k = 0; k < 10; ++k) W = winlaw::retarget_width(U256{d}, W, (u128)rate * R, g);
        std::printf("   the old one-period divisor through retarget_width -> %llu\n", (unsigned long long)W);
        check(W == g.w_max_bins, "control: dividing C*D*W_cur by one period's work runs to W_MAX");
    }

    std::printf("-- WL-3 real native-ridge lane (LTC) --\n");
    {
        struct Case { u64 per_bin, w, d, want; };
        const Case cases[] = {
            {8, 1, 16, 1152},   // C * 16 / 8
            {8, 2, 16, 576},    // C * 16 / 16
            {8, 4, 16, 528},    // C * 16 / 32 = 288, clamped to W_MIN
            {8, 1, 64, 4608},   // C * 64 / 8 = 4608 = W_MAX
        };
        for (const auto& c : cases) {
            u64 rt = 0;
            const u64 W = drive_nr(c.per_bin, c.w, c.d, 40, &rt);
            std::printf("   rate %llu/bin D %llu: W %llu after %llu retargets (want %llu)\n",
                        (unsigned long long)(c.per_bin * c.w), (unsigned long long)c.d, (unsigned long long)W,
                        (unsigned long long)rt, (unsigned long long)c.want);
            check(rt > 10, "the width law ran");
            check(W == c.want, "the ridge settles at the law's fixed point");
        }
    }

    std::printf("\n%ld checks, %ld failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
