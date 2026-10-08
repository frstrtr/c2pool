// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// xmr_coinbase_output_gate_kat (pathb_window.hpp / pathb_emission.hpp, C13): the
// N rule caps the outputs at N(B); whole oldest bins leave while the payees
// exceed N(B); one output per surviving window payee (K = 1); N(B) across the
// Carrot height and the hf 17 cap 10,000.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <vector>

#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 id_of(std::uint64_t i) {
    pb::Hash32 h{};
    for (int b = 0; b < 8; ++b) h[31 - b] = static_cast<std::uint8_t>(i >> (8 * b));
    return h;
}

int main() {
    const std::uint64_t B = 600000000000ull;
    const std::uint64_t f = 1;  // loose: W_max never binds
    const pb::Hash32 author{};

    // 20 bins, 50 distinct payees each (1000 total), N = 100: the oldest bins
    // leave until the window payees <= N; one output per payee.
    std::vector<pb::WinBin> bins;
    std::uint64_t uid = 1, pos = 100000;
    for (int k = 0; k < 20; ++k) {
        pb::WinBin b; b.bin = 20 - k;
        for (int j = 0; j < 50; ++j) {
            pb::WinEntry e; e.miner = id_of(uid++); e.work = 100000; e.position = pos--; e.id = e.miner;
            b.entries.push_back(e);
        }
        bins.push_back(b);
    }
    const std::uint64_t N = 100;
    const pb::Window w = pb::window(bins, /*D_net=*/1000000000ull, B, f, N, author);
    check(w.weight.size() <= N, "N rule: outputs <= N(B)");
    check(w.weight.size() == N, "whole oldest bins leave until payees == N (50 per bin, 2 newest bins)");
    for (const auto& [id, wt] : w.weight) check(!wt.is_zero(), "one output per window payee, all > 0");

    // in-bin cut (one bin, 300 payees, N = 100 forced by a test hook): cut to N.
    {
        pb::WinBin one; one.bin = 1;
        for (std::uint64_t j = 0; j < 300; ++j) {
            pb::WinEntry e; e.miner = id_of(10000 + j); e.work = 100000; e.position = 300 - j; e.id = e.miner;
            one.entries.push_back(e);
        }
        const pb::Window wc = pb::window({one}, 1000000000ull, B, f, 100, author);
        check(wc.weight.size() == 100, "in-bin cut by position: one bin of 300 payees cut to N = 100");
    }

    // N(B) across the Carrot height and the hf 17 cap.
    check(pb::n_rule(300000, 16, B) == 3747, "N(B) hf16 = 3747");
    check(pb::n_rule(300000, 17, B) == 1665, "N(B) hf17 = 1665 (across Carrot)");
    check(pb::n_rule(5000000, 17, B) == 10000, "hf17 cap binds at 10,000");

    return finish("xmr_coinbase_output_gate_kat");
}
