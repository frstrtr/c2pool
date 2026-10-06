// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_relay_horizons_kat.cpp
// Derived horizons and caps:
//   (1) (F, T, D_fin, R_MAX, Fresh, P_heal) = (96, 10, 12, 16, 2, 3 h):
//       index_horizon 99, backfill 1,164, ctx_window 100, ctx_max_depth 3,
//       index_retention 2,112, pending_cap 18,432; J = 1,164;
//   (2) (48, 10, 12, 16, 2, 3 h): 51 / 1,080 / 93 / 3 / 2,112 / 9,216; J = 1,080;
//   (3) blob_cap: Z 300,000 at OVH 89 / OUT 40 = 313,166; Z 625,000 at
//       OVH 61 / OUT 90 = 652,368; n_tx bound 411 / 856;
//   (4) w_min = 1,459 (prefix 126 + rct base 82 + prunable 1,251);
//       D_max(16) = 14 -> RECEIPT_CAP 945; D_max(17) = 12 -> 881; D_max moves
//       with Z_lt; zone / surge / extra leaves per hf;
//   (5) formulas follow the parameters (a changed T or F moves every value);
//       out-of-domain inputs give no value.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <string>

#include "impl/xmr/pathb/pathb_caps.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

int main() {
    std::printf("v37_xmr_relay_horizons_kat\n");

    // (1) ruled parameters
    {
        const pb::LaneParams p = pb::kRuledLaneParams;
        check(p.carrier_interval_s == 10 && p.open_bins == 96 && p.fresh_max == 2 && p.r_max == 16
                      && p.heal_period_h == 3,
              "ruled lane parameters (T 10, F 96, Fresh 2, R_MAX 16, P_heal 3 h)");
        check(pb::seal_depth(p) == 12, "D_fin = ceil(120 / 10) = 12");
        check(pb::fold_crossing_depth(p) == 1164, "F x 120 / T + D_fin = 1,164");
        check(pb::journal_depth(p) == 1164, "J = max(1,080, 1,164) = 1,164");
        const pb::RelayHorizons h = pb::relay_horizons(p);
        check(h.index_horizon == 99, "index_horizon 99");
        check(h.backfill == 1164, "backfill 1,164");
        check(h.ctx_window == 100, "ctx_window 100");
        check(h.ctx_max_depth == 3, "ctx_max_depth 3");
        check(h.index_retention == 2112, "index_retention 2,112");
        check(h.pending_cap == 18432, "pending_cap 18,432");
    }

    // (2) F = 48
    {
        pb::LaneParams p = pb::kRuledLaneParams;
        p.open_bins = 48;
        check(pb::fold_crossing_depth(p) == 588, "F 48: F x 120 / T + D_fin = 588");
        check(pb::journal_depth(p) == 1080, "F 48: J = 1,080");
        const pb::RelayHorizons h = pb::relay_horizons(p);
        const pb::RelayHorizons want{51, 1080, 93, 3, 2112, 9216};
        check(h == want, "F 48: 51 / 1,080 / 93 / 3 / 2,112 / 9,216");
    }

    // (3) blob_cap
    {
        check(pb::kHashingHeaderMaxBytes == 43, "HDR_max = 1 + 1 + 5 + 32 + 4");
        check(pb::max_tx_count(300000) == 411, "floor(2 x 300,000 / 1,459) = 411");
        check(pb::max_tx_count(625000) == 856, "floor(2 x 625,000 / 1,459) = 856");
        const std::optional<std::uint64_t> c16 = pb::blob_cap(pb::CoinbaseLayout{89, 40}, 300000);
        const std::optional<std::uint64_t> c17 = pb::blob_cap(pb::CoinbaseLayout{61, 90}, 625000);
        check(c16 && *c16 == 313166, "blob_cap(Z 300,000; OVH 89, OUT 40) = 313,166");
        check(c17 && *c17 == 652368, "blob_cap(Z 625,000; OVH 61, OUT 90) = 652,368");
        const std::optional<std::uint64_t> c_small = pb::blob_cap(pb::CoinbaseLayout{89, 40}, 50);
        check(c_small && *c_small == 43 + 89 + 0 + 0 + 1, "Z below OVH: no outputs, no transactions");
        check(!pb::blob_cap(pb::CoinbaseLayout{89, 0}, 300000).has_value(), "OUT 0 gives no value");
        check(!pb::blob_cap(pb::CoinbaseLayout{89, 40}, UINT64_MAX).has_value(), "Z outside the u64 domain gives no value");
        const std::uint64_t z2 = 300000 * 2;
        const std::optional<std::uint64_t> c_big = pb::blob_cap(pb::CoinbaseLayout{89, 40}, z2);
        check(c_big && *c_big > *c16, "blob_cap grows with Z");
    }

    // (4) receipt cap
    {
        check(pb::min_tx::kPrefixBytes == 126, "minimal tx prefix 126 B");
        check(pb::min_tx::kRctBaseBytes == 82, "minimal tx rct base 82 B");
        check(pb::min_tx::kPrunableBytes == 1251, "minimal tx prunable 1,251 B");
        check(pb::kMinTxWeight == 1459, "w_min = 1,459");
        check(pb::min_tx::kBpPlusRounds == 7, "BP+ rounds at two outputs = 7");
        check(pb::zone(16) == 300000 && pb::zone(17) == 625000, "zone 300,000 / 625,000");
        check(pb::surge_factor(16) == 50 && pb::surge_factor(17) == 8, "surge factor 50 / 8");
        check(pb::tree_extra_leaves(16) == 0 && pb::tree_extra_leaves(17) == 2, "X(16) = 0, X(17) = 2");
        check(pb::d_max(16, 0) == std::optional<std::uint64_t>(14), "D_max(16, Z_lt <= zone) = 14");
        check(pb::d_max(17, 0) == std::optional<std::uint64_t>(12), "D_max(17, Z_lt <= zone) = 12");
        check(pb::receipt_cap(16, 0) == std::optional<std::uint64_t>(945), "RECEIPT_CAP(16) = 945");
        check(pb::receipt_cap(17, 0) == std::optional<std::uint64_t>(881), "RECEIPT_CAP(17) = 881");
        check(pb::d_max(16, 300000) == pb::d_max(16, 0), "Z_lt at the zone: D_max unchanged");
        // 1 + floor(2 x 50 x Z / 1,459) reaches 2^15 at Z = 478,071
        check(pb::d_max(16, 478070) == std::optional<std::uint64_t>(14), "D_max(16, Z_lt 478,070) = 14");
        check(pb::d_max(16, 478071) == std::optional<std::uint64_t>(15), "D_max(16, Z_lt 478,071) = 15");
        check(pb::receipt_cap(16, 478071) == std::optional<std::uint64_t>(977), "RECEIPT_CAP rises to 977");
        check(!pb::d_max(16, UINT64_MAX).has_value(), "Z_lt outside the u64 domain gives no value");
    }

    // (5) the formulas follow the parameters
    {
        pb::LaneParams p = pb::kRuledLaneParams;
        p.carrier_interval_s = 20;
        check(pb::seal_depth(p) == 6, "T 20: D_fin = 6");
        check(pb::fold_crossing_depth(p) == 96 * 6 + 6, "T 20: F x 120 / T + D_fin = 582");
        check(pb::journal_depth(p) == 582, "T 20: J = max(540, 582) = 582");
        p.carrier_interval_s = 7;
        check(pb::seal_depth(p) == 18, "T 7: D_fin = ceil(120 / 7) = 18");
        check(pb::fold_crossing_depth(p) == 1646 + 18, "T 7: ceil(96 x 120 / 7) + 18 = 1,664");
        p = pb::kRuledLaneParams;
        p.heal_period_h = 4;
        check(pb::journal_depth(p) == 1440, "P_heal 4 h: J = max(1,440, 1,164) = 1,440");
        check(pb::relay_horizons(p).ctx_window == 120 + 3, "P_heal 4 h: ctx_window = 123");
        p = pb::kRuledLaneParams;
        p.open_bins = 170;
        check(pb::relay_horizons(p).index_horizon == 173, "F 170: index_horizon 173");
        check(pb::relay_horizons(p).pending_cap == 170 * 12 * 16, "F 170: pending_cap 32,640");
    }

    return finish("v37_xmr_relay_horizons_kat");
}
