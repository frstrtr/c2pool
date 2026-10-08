// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_fairness_schedules_kat (pathb_window.hpp, C39): under the no-decay,
// proportional window rule a miner's share of R equals its share of the
// schedule's work (summed from the bins, every bin inside the window), within
// 0.003, for steady / pulser / hopper / part-time schedules. (The
// window pays floor(R w_i / W) + largest remainder, so the deviation is below
// one atomic unit per payee -- far inside the 0.003 fairness band.)
// ---------------------------------------------------------------------------
#include <cmath>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 id_of(std::uint64_t i) {
    pb::Hash32 h{};
    for (int b = 0; b < 8; ++b) h[31 - b] = static_cast<std::uint8_t>(i >> (8 * b));
    return h;
}

// a schedule assigns work to miner `m` in a subset of the window's bins.
static void check_fairness(const std::vector<pb::WinBin>& bins, const char* tag) {
    const std::uint64_t B = 600000000000ull;
    const std::uint64_t R = 600000000000ull;
    const pb::Hash32 author{};
    const pb::Window w = pb::window(bins, /*D_net=*/1000000000000ull, B, /*f_spend=*/1, /*N=*/3747, author);
    const auto outs = pb::split(R, w);
    // the schedule's own work per miner over every bin (COVERAGE does not bind),
    // summed here, not read from the window.
    std::map<pb::Hash32, double> work;
    double total = 0;
    for (const pb::WinBin& b : bins)
        for (const pb::WinEntry& x : b.entries) {
            work[x.miner] += static_cast<double>(x.work);
            total += static_cast<double>(x.work);
        }
    bool ok = outs.size() == work.size();
    for (const auto& o : outs) {
        const double share_paid = static_cast<double>(o.amount) / static_cast<double>(R);
        const auto it = work.find(o.payee);
        if (it == work.end() || std::fabs(share_paid - it->second / total) > 0.003) ok = false;
    }
    check(ok, std::string("payout share == the schedule's work share within 0.003: ") + tag);
}

int main() {
    auto e = [](std::uint64_t m, std::uint64_t work, std::uint64_t pos) {
        pb::WinEntry x; x.miner = id_of(m); x.work = work; x.position = pos; x.id = x.miner; return x;
    };

    // STEADY: two miners present in every bin at a fixed rate.
    {
        std::vector<pb::WinBin> bins;
        for (int k = 0; k < 10; ++k) bins.push_back({static_cast<std::uint64_t>(10 - k),
                                                     {e(1, 70000, 100 - 2 * k), e(2, 30000, 99 - 2 * k)}});
        check_fairness(bins, "steady 70/30");
    }
    // PULSER: a miner that mines in bursts (only some bins) still gets its work share.
    {
        std::vector<pb::WinBin> bins;
        for (int k = 0; k < 10; ++k) {
            pb::WinBin b; b.bin = 10 - k;
            b.entries.push_back(e(1, 50000, 200 - 2 * k));            // steady
            if (k % 3 == 0) b.entries.push_back(e(2, 90000, 199 - 2 * k));  // pulses every 3rd bin
            bins.push_back(b);
        }
        check_fairness(bins, "pulser");
    }
    // HOPPER before/after: a miner present only in the newest half, then the oldest.
    {
        std::vector<pb::WinBin> bins;
        for (int k = 0; k < 10; ++k) {
            pb::WinBin b; b.bin = 10 - k;
            b.entries.push_back(e(1, 40000, 300 - 2 * k));
            b.entries.push_back(e(k < 5 ? 2 : 3, 60000, 299 - 2 * k));  // hops miner 2 -> 3
            bins.push_back(b);
        }
        check_fairness(bins, "hopper");
    }
    // PART-TIME: a small miner present in a single bin.
    {
        std::vector<pb::WinBin> bins;
        for (int k = 0; k < 10; ++k) {
            pb::WinBin b; b.bin = 10 - k;
            b.entries.push_back(e(1, 80000, 400 - 2 * k));
            if (k == 4) b.entries.push_back(e(2, 20000, 399 - 2 * k));  // part-time, one bin
            bins.push_back(b);
        }
        check_fairness(bins, "part-time");
    }

    return finish("v37_xmr_fairness_schedules_kat");
}
