// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_fairness_cap_kat (pathb_window.hpp, C39): one 20 % miner + 40,000
// small payees at 0.6 XMR -> every surviving window payee is paid, Sum(vout) ==
// R, outputs <= N(B), today (hf16) and with the hf 17 format N(B).
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

static void run(std::uint64_t N, const char* tag) {
    const std::uint64_t B = 600000000000ull;
    const std::uint64_t R = 600000000000ull;  // 0.6 XMR
    const pb::Hash32 author{};
    pb::WinBin bin; bin.bin = 1;
    // one 20 % miner (newest position so it survives the cut) ...
    { pb::WinEntry e; e.miner = id_of(1); e.work = 20000000; e.position = 100000000; e.id = e.miner; bin.entries.push_back(e); }
    // ... + 40,000 small payees at 0.002 % each.
    for (std::uint64_t j = 0; j < 40000; ++j) {
        pb::WinEntry e; e.miner = id_of(100 + j); e.work = 2000; e.position = 40000 - j; e.id = e.miner;
        bin.entries.push_back(e);
    }
    const pb::Window w = pb::window({bin}, /*D_net=*/1000000000000ull, B, /*f_spend=*/1, N, author);
    check(w.weight.size() <= N, std::string("outputs <= N(B) ") + tag);
    const auto outs = pb::split(R, w);
    std::uint64_t s = 0;
    bool all_paid = true;
    for (const auto& o : outs) { s += o.amount; if (o.amount == 0) all_paid = false; }
    check(s == R, std::string("Sum(vout) == R ") + tag);
    check(all_paid, std::string("every surviving window payee is paid (> 0) ") + tag);
}

int main() {
    run(pb::n_rule(300000, 16, 600000000000ull), "hf16 N=3747");  // 3747
    run(pb::n_rule(300000, 17, 600000000000ull), "hf17 N=1665");  // 1665 (format)
    return finish("v37_xmr_fairness_cap_kat");
}
