// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_relay_horizons_kat.cpp
// Derived horizons and caps:
//   (1) (F, T, D_fin, R_MAX, Fresh, P_heal) = (96, 10, 0, 16, 2, 3 h):
//       index_horizon 99, backfill 1,152, ctx_window 99, ctx_max_depth 3,
//       index_retention (Monero rows kept) 1,455, pending_cap 18,432;
//       J = 1,152; the fold crossing 1,152;
//   (2) (48, 10, 0, 16, 2, 3 h): 51 / 1,080 / 93 / 3 / 1,455 / 9,216; J = 1,080;
//   (3) blob caps: own found block, Z 300,000 at OVH 89 / OUT 40 = 313,166;
//       Z 625,000 at OVH 61 / OUT 90 (hf 17, trailer 33) = 652,401; outputs
//       from Z_A, transactions from Z_P; at most 10,000 outputs from hf 17;
//       one output below OVH; context block 2 Z + 50 + 1 (+ 33 from hf 17):
//       600,051 / 1,250,084; a context block with a 500,000 B miner tx at
//       Z 300,000 fits the context cap and not the own cap; n_tx bound 411 / 856;
//   (4) w_min = 1,459 (prefix 126 + rct base 82 + prunable 1,251);
//       D_max(16) = 14 -> RECEIPT_CAP 913; D_max(17) = 12 -> 849; D_max moves
//       with Z_lt; zone / surge / extra leaves per hf;
//   (5) formulas follow the parameters (a changed T or F moves every value;
//       D_fin stays 0: T 20 -> J 576, T 7 -> ceil(96 x 120 / 7) = 1,646);
//       out-of-domain inputs give no value;
//   (6) Monero rows kept: delta_win 734; k_alt 720 + 735 = 1,455 by default;
//       rows_window above it (a carrier record far below the Monero tip)
//       raises it; heights near genesis clamp.
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
        check(pb::seal_depth(p) == 0 && pb::kSealDepth == 0, "D_fin = 0 (K06)");
        check(pb::fold_crossing_depth(p) == 1152, "F x 120 / T + D_fin = 1,152");
        check(pb::journal_depth(p) == 1152, "J = max(1,080, 1,152) = 1,152");
        const pb::RelayHorizons h = pb::relay_horizons(p);
        check(h.index_horizon == 99, "index_horizon 99");
        check(h.backfill == 1152, "backfill 1,152");
        check(h.ctx_window == 99, "ctx_window = ceil(1,152 x 10 / 120) + 3 = 99");
        check(h.ctx_max_depth == 3, "ctx_max_depth 3");
        check(h.index_retention == 1455, "Monero rows kept 1,455");
        check(h.pending_cap == 18432, "pending_cap 18,432");
    }

    // (2) F = 48
    {
        pb::LaneParams p = pb::kRuledLaneParams;
        p.open_bins = 48;
        check(pb::fold_crossing_depth(p) == 576, "F 48: F x 120 / T + D_fin = 576");
        check(pb::journal_depth(p) == 1080, "F 48: J = 1,080");
        const pb::RelayHorizons h = pb::relay_horizons(p);
        const pb::RelayHorizons want{51, 1080, 93, 3, 1455, 9216};
        check(h == want, "F 48: 51 / 1,080 / 93 / 3 / 1,455 / 9,216");
    }

    // (3) blob caps
    {
        check(pb::kHashingHeaderMaxBytes == 43, "HDR_max = 1 + 1 + 5 + 32 + 4");
        check(pb::kMoneroHeaderMaxBytes == 50, "HDR_ctx = 2 + 2 + 10 + 32 + 4");
        check(pb::block_trailer_bytes(16) == 0 && pb::block_trailer_bytes(17) == 33, "trailer 0 / 33 (hf 16 / 17)");
        check(pb::max_tx_count(300000) == 411, "floor(2 x 300,000 / 1,459) = 411");
        check(pb::max_tx_count(625000) == 856, "floor(2 x 625,000 / 1,459) = 856");
        const pb::CoinbaseLayout l16{89, 40};
        const pb::CoinbaseLayout l17{61, 90};

        // own found block
        const std::optional<std::uint64_t> c16 = pb::blob_cap_own(16, l16, 300000, 300000);
        const std::optional<std::uint64_t> c17 = pb::blob_cap_own(17, l17, 625000, 625000);
        check(c16 && *c16 == 313166, "own: Z 300,000, OVH 89, OUT 40 -> 313,166");
        check(c17 && *c17 == 652401, "own: hf 17, Z 625,000, OVH 61, OUT 90 -> 652,368 + 33 = 652,401");
        check(pb::blob_cap_own(16, l16, 400000, 300000) == std::optional<std::uint64_t>(413166),
              "own: outputs from Z_A 400,000, transactions from Z_P 300,000 -> 413,166");
        check(pb::blob_cap_own(16, l16, 300000, 400000) == std::optional<std::uint64_t>(317550),
              "own: outputs from Z_A 300,000, transactions from Z_P 400,000 -> 317,550");
        check(pb::blob_cap_own(17, l17, 2000000, 625000) == std::optional<std::uint64_t>(927531),
              "own: hf 17, Z_A 2,000,000 -> 10,000 outputs, 927,531");
        check(pb::blob_cap_own(16, l16, 2000000, 625000) == std::optional<std::uint64_t>(43 + 89 + 49997 * 40 + 27392 + 2),
              "own: hf 16, Z_A 2,000,000 -> 49,997 outputs");
        check(pb::blob_cap_own(16, l16, 50, 50) == std::optional<std::uint64_t>(43 + 89 + 40 + 0 + 1),
              "own: Z below OVH -> one output, no transactions");
        check(!pb::blob_cap_own(16, pb::CoinbaseLayout{89, 0}, 300000, 300000).has_value(), "own: OUT 0 gives no value");
        check(!pb::blob_cap_own(16, l16, UINT64_MAX, 300000).has_value(), "own: Z_A outside the domain gives no value");
        check(!pb::blob_cap_own(16, l16, 300000, UINT64_MAX).has_value(), "own: Z_P outside the domain gives no value");
        check(!pb::blob_cap_own(16, pb::CoinbaseLayout{UINT64_MAX, 40}, 300000, 300000).has_value(),
              "own: OVH outside the domain gives no value");
        const std::optional<std::uint64_t> c_big = pb::blob_cap_own(16, l16, 600000, 600000);
        check(c_big && *c_big > *c16, "own: grows with Z");

        // context block
        const std::optional<std::uint64_t> x16 = pb::blob_cap_ctx(16, 300000);
        const std::optional<std::uint64_t> x17 = pb::blob_cap_ctx(17, 625000);
        check(x16 && *x16 == 600051, "ctx: Z 300,000 -> 50 + 600,000 + 1 = 600,051");
        check(x17 && *x17 == 1250084, "ctx: hf 17, Z 625,000 -> 50 + 1,250,000 + 1 + 33 = 1,250,084");
        const std::uint64_t foreign = pb::kMoneroHeaderMaxBytes + 500000 + pb::varint_len(0);
        check(foreign <= *x16 && foreign > *c16, "a 500,000 B miner tx at Z 300,000: inside the ctx cap, above the own cap");
        check(*x16 >= *c16 && *x17 >= *c17, "ctx cap >= own cap at the same Z");
        check(!pb::blob_cap_ctx(16, UINT64_MAX).has_value(), "ctx: Z outside the domain gives no value");
        check(pb::blob_cap_ctx(16, (UINT64_MAX - 51) / 2).has_value(), "ctx: largest Z in the domain");
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
        check(pb::receipt_cap(16, 0) == std::optional<std::uint64_t>(913), "RECEIPT_CAP(16) = 913");
        check(pb::receipt_cap(17, 0) == std::optional<std::uint64_t>(849), "RECEIPT_CAP(17) = 849");
        check(pb::d_max(16, 300000) == pb::d_max(16, 0), "Z_lt at the zone: D_max unchanged");
        // 1 + floor(2 x 50 x Z / 1,459) reaches 2^15 at Z = 478,071
        check(pb::d_max(16, 478070) == std::optional<std::uint64_t>(14), "D_max(16, Z_lt 478,070) = 14");
        check(pb::d_max(16, 478071) == std::optional<std::uint64_t>(15), "D_max(16, Z_lt 478,071) = 15");
        check(pb::receipt_cap(16, 478071) == std::optional<std::uint64_t>(945), "RECEIPT_CAP rises to 945");
        check(!pb::d_max(16, UINT64_MAX).has_value(), "Z_lt outside the u64 domain gives no value");
    }

    // (5) the formulas follow the parameters
    {
        pb::LaneParams p = pb::kRuledLaneParams;
        p.carrier_interval_s = 20;
        check(pb::seal_depth(p) == 0, "T 20: D_fin = 0");
        check(pb::fold_crossing_depth(p) == 96 * 6, "T 20: F x 120 / T + D_fin = 576");
        check(pb::journal_depth(p) == 576, "T 20: J = max(540, 576) = 576");
        check(pb::relay_horizons(p).backfill == 576 && pb::relay_horizons(p).ctx_window == 96 + 3,
              "T 20: backfill 576, ctx_window 99");
        p.carrier_interval_s = 7;
        check(pb::seal_depth(p) == 0, "T 7: D_fin = 0");
        check(pb::fold_crossing_depth(p) == 1646, "T 7: ceil(96 x 120 / 7) + 0 = 1,646");
        check(pb::journal_depth(p) == 1646, "T 7: J = max(1,543, 1,646) = 1,646");
        check(pb::relay_horizons(p).ctx_window == 97 + 3, "T 7: ctx_window = ceil(1,646 x 7 / 120) + 3 = 100");
        p = pb::kRuledLaneParams;
        p.heal_period_h = 4;
        check(pb::journal_depth(p) == 1440, "P_heal 4 h: J = max(1,440, 1,152) = 1,440");
        check(pb::relay_horizons(p).ctx_window == 120 + 3, "P_heal 4 h: ctx_window = 123");
        p = pb::kRuledLaneParams;
        p.open_bins = 170;
        check(pb::relay_horizons(p).index_horizon == 173, "F 170: index_horizon 173");
        check(pb::relay_horizons(p).pending_cap == 170 * 12 * 16, "F 170: pending_cap 32,640");
    }

    // (6) Monero rows kept
    {
        const pb::LaneParams p = pb::kRuledLaneParams;
        check(pb::DIFFICULTY_BLOCKS_COUNT == 735 && pb::kAltDepth == 720, "DIFFICULTY_BLOCKS_COUNT 735, k_alt 720");
        check(pb::kRowsWindowDelta == 734, "delta_win = max(735, 60 + 100, 60) - 1 = 734");
        check(pb::monero_rows_default(pb::kAltDepth) == 1455, "default 720 + 735 = 1,455");
        // carriers in step with Monero: H(L - J) 9,904, H(L - D_fin) 10,000, M 10,000
        check(pb::rows_window(p, 10000, 9904, 10000) == 833, "rows_window = 10,000 - (9,903 - 1 - 734) + 1 = 833");
        check(pb::monero_rows_keep(p, pb::kAltDepth, 10000, 9904, 10000) == 1455, "833 below the default: 1,455");
        // carrier records far below the Monero tip
        check(pb::rows_window(p, 10000, 9000, 9500) == 1736, "rows_window = 10,000 - (9,000 - 1 - 734) + 1 = 1,736");
        check(pb::monero_rows_keep(p, pb::kAltDepth, 10000, 9000, 9500) == 1736, "rows_window above the default raises it");
        check(pb::rows_window(p, 500, 400, 500) == 501, "near genesis: h_floor clamps to 0, rows = M + 1");
        check(pb::monero_rows_keep(p, 2000, 10000, 9904, 10000) == 2735, "k_alt raised to 2,000: 2,735");
    }

    return finish("v37_xmr_relay_horizons_kat");
}
