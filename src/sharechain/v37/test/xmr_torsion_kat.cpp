/*
 * xmr_torsion_kat.cpp — Known-Answer Test for the XMR descriptor torsion /
 * prime-order point check (v37::xmr::is_valid_point via the ref10 backend).
 *
 * This file is part of c2pool (frstrtr/c2pool).
 * Copyright (c) 2026 The c2pool developers. AGPL-3.0-or-later.
 * See <https://www.gnu.org/licenses/>.
 *
 * WHAT IT PROVES
 *   The finalized backend (v37_descriptor_xmr_point_check_ref10.cpp, compiled
 *   into this TU under -DV37_XMR_HAVE_MONERO_CRYPTO) performs a REAL ed25519
 *   prime-order subgroup check on the vendored Monero crypto-ops:
 *     - ACCEPTS prime-order points: the ed25519 basepoint and real Monero
 *       spend/view pubkeys (clamped-scalar * basepoint).
 *     - REJECTS every small-order point (order 1/2/4/8) — the ed25519 torsion
 *       subgroup — AND a runtime-constructed MIXED point (basepoint + order-2)
 *       that is on-curve, canonical, non-identity, yet carries a torsion
 *       component. The mixed case is the descriptor attack the canon guards:
 *       it decodes fine and passes a naive "is it on the curve" test, and is
 *       caught ONLY by the [L]P == 𝒪 subgroup test.
 *   It then checks the descriptor-level valid() path: xmr_ref_valid rejects a
 *   ScriptRef whose spend half is a torsion point and accepts one built from
 *   real pubkeys.
 *
 * BUILD (single TU, links vendored crypto-ops; no RandomX, no cmake):
 *   g++ -std=c++20 -DV37_XMR_HAVE_MONERO_CRYPTO \
 *       -I<mydir> -I<tree>/src/sharechain/v37 \
 *       -I<tree>/src/impl/xmr/coin/vendor -I<tree>/src/impl/xmr/coin/compat \
 *       xmr_torsion_kat.cpp ../v37_descriptor_xmr_point_check_ref10.cpp \
 *       <tree>/src/impl/xmr/coin/vendor/crypto-ops.c \
 *       <tree>/src/impl/xmr/coin/vendor/crypto-ops-data.c -o /tmp/xmr_torsion_kat
 */

#include <array>
#include <cstdint>
#include <cstdio>

#include "v37_descriptor_xmr.hpp"

extern "C" {
#include "crypto-ops.h"   // ge_* for the runtime mixed-point construction
}

using namespace v37;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

using Pt = std::array<std::uint8_t, 32>;

// ---- ACCEPT vectors: prime-order points -----------------------------------
// ed25519 basepoint B, little-endian compressed.
static const Pt BASEPOINT = {
    0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66};

// ---- REJECT vectors: the ed25519 small-order (torsion) subgroup ------------
// (libsodium's has_small_order blacklist; all canonical, on-curve.)
static const Pt ORDER1_IDENTITY = { // 𝒪 = (0,1)
    0x01,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
static const Pt ORDER2_NEG1 = {     // (0,-1), y = p-1
    0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f};
static const Pt ORDER4_YZERO = {    // (sqrt(-1),0), y = 0
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
static const Pt ORDER8_A = {
    0x26,0xe8,0x95,0x8f,0xc2,0xb2,0x27,0xb0,0x45,0xc3,0xf4,0x89,0xf2,0xef,0x98,0xf0,
    0xd5,0xdf,0xac,0x05,0xd3,0xc6,0x33,0x39,0xb1,0x38,0x02,0x88,0x6d,0x53,0xfc,0x05};
static const Pt ORDER8_B = {
    0xc7,0x17,0x6a,0x70,0x3d,0x4d,0xd8,0x4f,0xba,0x3c,0x0b,0x76,0x0d,0x10,0x67,0x0f,
    0x2a,0x20,0x53,0xfa,0x2c,0x39,0xcc,0xc6,0x4e,0xc7,0xfd,0x77,0x92,0xac,0x03,0x7a};

// Build a MIXED point P = B + T2 (prime-order basepoint plus the order-2 point).
// Order(P) = 2L: on-curve, canonical, NOT identity, NOT small-order — yet it
// carries torsion, so [L]P = T2 != 𝒪. Only the subgroup test rejects it.
static bool make_mixed_point(Pt& out) {
    ge_p3 B, T2;
    if (ge_frombytes_vartime(&B, BASEPOINT.data()) != 0) return false;
    if (ge_frombytes_vartime(&T2, ORDER2_NEG1.data()) != 0) return false;
    ge_cached cT2;
    ge_p3_to_cached(&cT2, &T2);
    ge_p1p1 sum;
    ge_add(&sum, &B, &cT2);
    ge_p3 P;
    ge_p1p1_to_p3(&P, &sum);
    ge_p3_tobytes(out.data(), &P);
    return true;
}

int main() {
    // The backend installs itself at static-init (BackendInstaller). Confirm it
    // is live — with no backend the check is fail-closed (all false), which
    // would make the ACCEPT assertions fail loudly rather than silently pass.
    CHECK(xmr::point_check_backend() != nullptr);

    // ---- ACCEPT: prime-order points -------------------------------------
    CHECK(xmr::is_valid_point(BASEPOINT.data()));
    CHECK(xmr::is_valid_point(xmr::kat::STD_KAT.p0.data()));   // real spend pub B
    CHECK(xmr::is_valid_point(xmr::kat::STD_KAT.p1.data()));   // real view  pub A
    CHECK(xmr::is_valid_point(xmr::kat::SUB_KAT.p0.data()));   // real sub-spend D_i

    // ---- REJECT: the full small-order subgroup --------------------------
    CHECK(!xmr::is_valid_point(ORDER1_IDENTITY.data()));       // order 1 (identity)
    CHECK(!xmr::is_valid_point(ORDER2_NEG1.data()));           // order 2
    CHECK(!xmr::is_valid_point(ORDER4_YZERO.data()));          // order 4
    CHECK(!xmr::is_valid_point(ORDER8_A.data()));              // order 8
    CHECK(!xmr::is_valid_point(ORDER8_B.data()));              // order 8

    // ---- REJECT: mixed prime+torsion point (the descriptor attack) ------
    Pt mixed{};
    CHECK(make_mixed_point(mixed));
    CHECK(!xmr::is_valid_point(mixed.data()));                 // caught by [L]P

    // ---- spec-vector wrapper from the header ----------------------------
    CHECK(xmr::kat::check_torsion_kats());  // basepoint pass + identity fail

    // ---- descriptor-level valid() ---------------------------------------
    {   // both halves prime-order -> valid
        ScriptRef ok = xmr::make_xmr_std(xmr::kat::STD_KAT.p0, xmr::kat::STD_KAT.p1);
        CHECK(xmr::xmr_ref_valid(ok));
        PayoutDescriptor d; d.pay = ok;
        CHECK(xmr::xmr_descriptor_valid(d));
    }
    {   // spend half is a torsion point -> INVALID (even though structurally ok)
        Pt view = xmr::kat::STD_KAT.p1;
        ScriptRef bad = xmr::make_xmr_std(ORDER8_A, view);
        CHECK(xmr::xmr_ref_well_formed(bad));   // structural: 64 bytes, xmr kind
        CHECK(!xmr::xmr_ref_valid(bad));        // torsion: rejected
    }
    {   // view half is the identity -> INVALID
        Pt spend = xmr::kat::STD_KAT.p0;
        ScriptRef bad = xmr::make_xmr_std(spend, ORDER1_IDENTITY);
        CHECK(!xmr::xmr_ref_valid(bad));
    }

    if (g_fail == 0) std::printf("ALL XMR TORSION KATS GREEN\n");
    else             std::printf("%d TORSION CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
