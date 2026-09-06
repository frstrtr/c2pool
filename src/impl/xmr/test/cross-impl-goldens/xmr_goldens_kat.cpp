// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/test/cross-impl-goldens/xmr_goldens_kat.cpp
//   LOAD-BEARING golden regression KAT for the XMR/RandomX v37 lane (Family B) —
//   the analogue of the Bitcoin-family proto/ decay-table golden gate.
//
//   It recomputes every captured XMR-lane deterministic output LIVE through the
//   merged consensus primitives (xmr_goldens_compute.hpp -> xmr_coin) and
//   byte-compares each to the FROZEN golden header (xmr_lane_goldens_golden.hpp,
//   emitted by gen_xmr_goldens.cpp). Any later code change that shifts an XMR-
//   lane output makes the live recompute diverge from the frozen constant and
//   this KAT exits nonzero — that is the regression gate.
//
//   The gate is NEGATIVE-CONTROLLED: a final section deliberately corrupts one
//   byte of the expected value and asserts the SAME comparator then reports a
//   MISMATCH, proving the comparison is real (not vacuously passing).
//
//   Coverage:
//     G1  difficulty check_hash accept/reject bitmask (11 overflow boundaries)
//     G2  CryptoNote stealth derivation D / P0 / view-tag over OFFICIAL vectors
//     G3  deterministic coinbase r, R=r*G, mm-commitment root, coinbase out key
//     G4  receipt cheap dedup-id, wire_size, info digest
//     G5  wire carrier codec bytes (full frame) + its keccak digest + length
//
//   LIGHT: keccak/cn_fast_hash + ed25519 ge_*/sc_* + boost-free check_hash only.
//   No RandomX, no libsodium, no boost.
// ---------------------------------------------------------------------------
#include <cstdio>
#include <string>

#include "xmr_goldens_compute.hpp"
#include "xmr_lane_goldens_golden.hpp"

namespace g = xmr_goldens::golden;

static int g_fail = 0;

static void check_str(const char* name, const std::string& got, const std::string& want) {
    bool ok = (got == want);
    std::printf("  [%s] %-22s got=%s%s\n", ok ? "PASS" : "FAIL", name,
                got.c_str(), ok ? "" : (std::string(" want=") + want).c_str());
    if (!ok) ++g_fail;
}
static void check_u(const char* name, unsigned long long got, unsigned long long want) {
    bool ok = (got == want);
    std::printf("  [%s] %-22s got=%llu%s\n", ok ? "PASS" : "FAIL", name, got,
                ok ? "" : (std::string(" want=") + std::to_string(want)).c_str());
    if (!ok) ++g_fail;
}

int main() {
    std::printf("=== xmr_goldens_kat (Family B load-bearing golden regression gate) ===\n");
    xmr_goldens::XmrGoldens live = xmr_goldens::compute_xmr_goldens();

    std::printf("-- G1 difficulty boundaries --\n");
    check_str("g1_difficulty_bits", live.g1_bits, g::G1_DIFFICULTY_BITS);

    std::printf("-- G2 stealth derivation (official monero vectors) --\n");
    check_str("g2_derivation_D", live.g2_D, g::G2_D);
    check_str("g2_one_time_P0",  live.g2_P0, g::G2_P0);
    check_u  ("g2_view_tag0",    live.g2_vt0, g::G2_VT0);

    std::printf("-- G3 deterministic coinbase --\n");
    check_str("g3_tx_secret_r",  live.g3_r,       g::G3_R);
    check_str("g3_tx_pubkey_R",  live.g3_R,       g::G3_R_PUB);
    check_str("g3_mm_root",      live.g3_mm_root, g::G3_MM_ROOT);
    check_str("g3_coinbase_Pcb", live.g3_Pcb,     g::G3_PCB0);

    std::printf("-- G4 receipt / admission digest --\n");
    check_str("g4_cheap_id",     live.g4_cheap_id,    g::G4_CHEAP_ID);
    check_u  ("g4_wire_size",    live.g4_wire_size,   g::G4_WIRE_SIZE);
    check_str("g4_info_digest",  live.g4_info_digest, g::G4_INFO_DIGEST);

    std::printf("-- G5 wire carrier codec --\n");
    check_u  ("g5_carrier_len",    live.g5_len,    g::G5_LEN);
    check_str("g5_carrier_digest", live.g5_digest, g::G5_DIGEST);
    check_str("g5_carrier_bytes",  live.g5_bytes,  std::string(g::G5_BYTES));

    // -----------------------------------------------------------------------
    // NEGATIVE CONTROL: prove the comparator actually catches a corruption.
    // Flip one nibble of the expected carrier byte string and assert the same
    // equality test the gate uses now reports a MISMATCH against the live value.
    // -----------------------------------------------------------------------
    std::printf("-- negative control (deliberate 1-byte corruption) --\n");
    {
        std::string corrupt = g::G5_BYTES;
        corrupt[10] = (corrupt[10] == '0') ? '1' : '0';   // flip one hex nibble
        bool live_matches_golden  = (live.g5_bytes == std::string(g::G5_BYTES));
        bool live_matches_corrupt = (live.g5_bytes == corrupt);
        bool control_ok = live_matches_golden && !live_matches_corrupt;
        std::printf("  [%s] gate catches corruption   (golden=%d corrupt=%d)\n",
                    control_ok ? "PASS" : "FAIL", live_matches_golden, live_matches_corrupt);
        if (!control_ok) ++g_fail;
    }

    std::printf("%s (%d failure%s)\n", g_fail ? "KAT FAILED" : "KAT OK",
                g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
