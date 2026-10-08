// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_coinbase_output_order_kat (pathb_window.hpp / pathb_coinbase_split.hpp,
// A-9, ruling 20 H-1 replaced): hf 16 window outputs are ordered by payee
// identity ascending; there is NO fee output in any case (ruling 20 H-1
// replaced, v37_xmr_fee_output_kat RETIRED); fees change amounts, never the
// order or the keys; at hf 17 the amount FORK-FUSEs (order by Ko is format only).
// ---------------------------------------------------------------------------
#include <cstdint>
#include <vector>

#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
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
    // a window of 64 payees, out of identity order in the map insertion.
    pb::Window w;
    Rng rng(0x0A9);
    for (std::uint64_t i = 0; i < 64; ++i) {
        const std::uint64_t id = 1 + rng.below(1000000);
        w.weight[id_of(id)] = pb::Work(1000 + rng.below(5000));
    }
    for (const auto& [k, v] : w.weight) w.W += v;

    const std::uint64_t base = 600000000000ull, fees = 123456789ull;
    const auto a = pb::split(base, w);
    const auto b = pb::split(base + fees, w);  // more fees

    // hf 16 outputs by identity ascending.
    bool ordered = true;
    for (std::size_t i = 1; i < a.size(); ++i)
        if (!(a[i - 1].payee < a[i].payee)) ordered = false;
    check(ordered, "hf16 outputs ordered by payee identity ascending");

    // NO fee output: outputs == window payees, no extra slot.
    check(a.size() == w.weight.size(), "no fee output: one output per window payee");

    // fees change amounts, not the order or the payee set (no key change).
    bool same = a.size() == b.size();
    for (std::size_t i = 0; same && i < a.size(); ++i)
        if (!(a[i].payee == b[i].payee)) same = false;
    check(same, "fees do not change the output order or the payee / key set");

    // the 0x04 additional-pubkeys order equals the vout order (hf 17 format): the
    // keys are emitted in output order; FORK-FUSE means no hf 17 amounts are built.
    check(pb::amount_fork_fused(17), "hf17 amounts FORK-FUSE (order-by-Ko is format only)");

    return finish("v37_xmr_coinbase_output_order_kat");
}
