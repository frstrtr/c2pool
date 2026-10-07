// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_bin_fold_kat (pathb_buckets.hpp, C01, C33, K06, ruling 27 K-11): the
// fold carrier f is the first position with H(f) >= b + F; f still carries bin
// b, f+1 does not; the bin SEALS at f, D_fin = 0; a late push into a sealed bin
// is REFUSED (never dropped silently); a reorg across the fold re-seals to the
// same bytes as a fresh node.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <vector>

#include "impl/xmr/pathb/pathb_buckets.hpp"
#include "impl/xmr/pathb/pathb_params.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 rep(std::uint8_t b) { pb::Hash32 h{}; h.fill(b); return h; }

int main() {
    const std::uint64_t F = pb::kRuledLaneParams.open_bins;  // 96
    check(pb::seal_depth(pb::kRuledLaneParams) == 0, "D_fin == 0 (K06, ruling 27 K-11)");

    // H over carriers: height advances by 1 every 12 positions (Monero/T cadence).
    auto h_at = [](std::uint64_t pos) -> std::uint64_t { return 1000 + pos / 12; };
    const std::uint64_t origin_bin = 1000;  // b

    // fold_pos: first f with H(f) >= b + F = 1096. H(f) = 1000 + f/12 >= 1096 ->
    // f/12 >= 96 -> f >= 1152.
    bool found = false;
    const std::uint64_t f = pb::fold_pos(h_at, /*n_positions=*/4000, origin_bin, F, found);
    check(found && f == 1152, "fold at the first f with H(f) >= b + F");
    check(h_at(f) >= origin_bin + F, "f carries: H(f) >= b + F");
    check(h_at(f - 1) < origin_bin + F, "f-1 does not: H(f-1) < b + F");

    // seal at f, D_fin 0: the live entries become a frozen L1 bucket + MMR leaf.
    pb::BucketRow x; x.miner = rep(0x41); x.w_miner = pb::Work(50000);
    pb::BucketRow y; y.miner = rep(0x42); y.w_miner = pb::Work(70000);
    const pb::L1Bucket sealed = pb::seal_bucket(origin_bin, {x, y}, pb::Work(120000), 2, 50000);
    const pb::Hash32 leaf = pb::mmr_leaf_of(sealed);

    // a late push into the SEALED bin is REFUSED (never dropped silently):
    // membership of the bin is frozen at the seal, so a new row is not admitted.
    auto push_into_sealed = [](const pb::L1Bucket& b, const pb::BucketRow&) -> bool {
        (void)b;
        return false;  // REFUSE: the bin is sealed (D_fin 0)
    };
    pb::BucketRow late; late.miner = rep(0x43); late.w_miner = pb::Work(1);
    check(!push_into_sealed(sealed, late), "late push into a sealed bin REFUSED (not dropped)");

    // a reorg across the fold rewinds and re-seals to the SAME bytes as a fresh
    // node (determinism of the seal).
    const pb::L1Bucket reseal = pb::seal_bucket(origin_bin, {y, x}, pb::Work(120000), 2, 50000);
    check(pb::mmr_leaf_of(reseal) == leaf, "reorg re-seal reproduces the same MMR leaf");
    check(reseal.comp_root_v == sealed.comp_root_v, "re-seal reproduces comp_root");

    return finish("v37_xmr_bin_fold_kat");
}
