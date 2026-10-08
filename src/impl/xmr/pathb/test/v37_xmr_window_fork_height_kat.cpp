// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_window_fork_height_kat (pathb_emission.hpp / pathb_coinbase_split.hpp,
// C41): a tip one height below the hf 17 fork gives two windows -- hf 16 (OUT 40,
// OVH 89) and hf 17 (OUT 90, OVH 61) -- each exact as a FORMAT; N(B) differs; at
// hf 17 NO amount is produced until O-01 exists (the lane FORK-FUSEs).
// ---------------------------------------------------------------------------
#include <cstdint>

#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 rep(std::uint8_t b) { pb::Hash32 h{}; h.fill(b); return h; }

int main() {
    const std::uint64_t s = 600000000000ull;  // S_A = 6e11

    // FORMAT differs across the fork (K24a / K24b).
    check(pb::ovh(16) == 89 && pb::ovh(17) == 61, "OVH 89 (hf16) / 61 (hf17)");
    check(pb::out_size(16, s) == 40 && pb::out_size(17, s) == 90, "OUT 40 (hf16) / 90 (hf17)");

    // N(B) differs across the fork at the same Z.
    check(pb::n_rule(300000, 16, s) == 3747 && pb::n_rule(300000, 17, s) == 1665,
          "N(B) differs: 3747 (hf16) vs 1665 (hf17)");

    // hf 16 produces amounts; hf 17 FORK-FUSEs (no amount until O-01).
    check(!pb::amount_fork_fused(16), "hf16 amounts produced");
    check(pb::amount_fork_fused(17) && pb::amount_fork_fused(18), "hf >= 17 FORK-FUSEs the amount");

    // the canonical coinbase at hf 17 builds NOTHING (fork_fused), at hf 16 it does.
    pb::ReceiptBodyV3 r;
    r.reward_total = 700000000000ull;
    pb::Window w;
    w.weight[rep(0xA1)] = pb::Work(100);
    w.W = pb::Work(100);
    const pb::Hash32 tip = rep(0x01), p_r = rep(0x02), mm = rep(0x03);
    const pb::CanonLeaf at16 = pb::canonical_coinbase_leaf(r, w, tip, p_r, 16, mm);
    const pb::CanonLeaf at17 = pb::canonical_coinbase_leaf(r, w, tip, p_r, 17, mm);
    check(!at16.fork_fused, "hf16 canonical coinbase leaf built");
    check(at17.fork_fused, "hf17 canonical coinbase FORK-FUSED (no amount invented)");
    // at hf 17 admission admits nothing (builds nothing).
    check(!pb::canonical_coinbase_ok_split(r, w, tip, p_r, 17, mm), "hf17: admit nothing (O-01 owed)");

    return finish("v37_xmr_window_fork_height_kat");
}
