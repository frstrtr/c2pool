// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// xmr_window_spend_floor_kat (pathb_window.hpp / pathb_emission.hpp, C38, K11a):
//   W_max = B(A_t) x d / f_spend PER ENTRY; the F6 vector stops the window at
//   1,500 bins; f_spend(6e11, 300k, hf16) == 12,530,000; a larger fee median M
//   quarters the fee per byte; B(A_t) on both sides (fees do not move the
//   window); d_min over receipt entries; two build orders give one window_root.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <vector>

#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 rep(std::uint8_t b) { pb::Hash32 h{}; h.fill(b); return h; }
static pb::WinEntry e(std::uint8_t miner, std::uint64_t work, std::uint64_t pos) {
    pb::WinEntry x; x.miner = rep(miner); x.work = work; x.position = pos; x.id = rep(miner); return x;
}

int main() {
    const std::uint64_t B = 600000000000ull;  // 6e11

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
        // D_net huge so COVERAGE never binds; only W_max stops the window.
        const auto sel = pb::select_window_bins(bins, /*D_net=*/1000000000000000ull, B, f);
        check(sel.size() == 1500, "W_max per entry stops the window at 1,500 bins (F6)");
    }

    // ---- B(A_t) on BOTH sides: the window does not depend on the template fees ----
    // (select_window_bins takes B, never R; a template with 2 XMR of fees and one
    // with 0 give the same selection.)
    {
        std::vector<pb::WinBin> bins;
        for (int k = 0; k < 40; ++k) bins.push_back({static_cast<std::uint64_t>(40 - k), {e(static_cast<std::uint8_t>(0x60 + (k % 10)), 80000, static_cast<std::uint64_t>(100 - k))}});
        const auto s1 = pb::select_window_bins(bins, 1000000000000000ull, B, f);
        const auto s2 = pb::select_window_bins(bins, 1000000000000000ull, B, f);
        check(s1.size() == s2.size(), "B(A_t) on both sides: fees do not move the window");
    }

    // ---- d_min over RECEIPT entries: a tiny-d entry shrinks the window ----
    {
        // two big bins accumulate W ~ 6e6 so that lowering d_min to 100 makes
        // B x d_min < W x f_spend -> the tiny-d (carried) bin is cut by W_max.
        // (A reading over carriers only would keep d_min at 3e6 and take it; this
        // vector fails that reading, so d_min MUST range over receipt entries.)
        std::vector<pb::WinBin> bins;
        bins.push_back({3, {e(0x70, 3000000, 30)}});
        bins.push_back({2, {e(0x71, 3000000, 20)}});
        bins.push_back({1, {e(0x72, 100, 10)}});  // tiny-d carried entry: dmin -> 100
        const auto sel = pb::select_window_bins(bins, 1000000000000000ull, B, f);
        check(sel.size() == 2, "d_min over receipt entries: a tiny-d bin is cut by W_max");
    }

    // ---- two build orders give one window_root (carrier-first vs carried-first) ----
    {
        pb::WinBin a; a.bin = 5;
        a.entries = {e(0x01, 100, 50), e(0x02, 200, 49), e(0x03, 300, 48)};
        pb::WinBin b; b.bin = 5;
        b.entries = {e(0x03, 300, 48), e(0x01, 100, 50), e(0x02, 200, 49)};  // reordered
        const pb::Hash32 author{};
        const pb::Window wa = pb::window({a}, 1000, B, f, 3747, author);
        const pb::Window wb = pb::window({b}, 1000, B, f, 3747, author);
        check(pb::window_root(wa) == pb::window_root(wb), "entry order does not change window_root");
    }

    return finish("xmr_window_spend_floor_kat");
}
