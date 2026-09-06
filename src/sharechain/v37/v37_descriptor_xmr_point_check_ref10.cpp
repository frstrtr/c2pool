/*
 * v37_descriptor_xmr_point_check_ref10.cpp — reference backend for
 * v37::xmr::xmr_point_check_fn (the descriptor torsion / prime-order check).
 *
 * This file is part of c2pool (frstrtr/c2pool).
 * Copyright (c) 2026 The c2pool developers.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version. Distributed WITHOUT ANY WARRANTY. See
 * <https://www.gnu.org/licenses/> for the full AGPL-3.0 text.
 *
 * ---------------------------------------------------------------------------
 * PROVENANCE
 *   Fresh c2pool glue (AGPL-3.0). It CALLS — it does not copy — one upstream
 *   crypto surface:
 *
 *     - Monero  src/crypto/crypto-ops.{h,c} + crypto-ops-data.c
 *               `ge_frombytes_vartime`, `ge_scalarmult`, `ge_tobytes`,
 *               `ge_p3_is_point_at_infinity_vartime`, the ge_* types.
 *               License: BSD-3-Clause (monero-project/monero; derived from the
 *               SUPERCOP ref10 ed25519 implementation). Vendored by X1 under
 *               src/impl/xmr/coin/vendor/ — reused here, NOT re-vendored.
 *
 *   The validation SEQUENCE (decode -> reject identity -> require prime-order
 *   subgroup membership via [L]P == 𝒪) is the textbook cofactor / torsion test
 *   and matches, in intent, SChernykh/p2pool src/wallet.cpp
 *   `Wallet::torsion_check()` (GPL-3.0, combinable into this AGPL-3.0 program
 *   under AGPLv3 §13). No p2pool source text is reproduced here.
 *
 *   WHY [L]P == 𝒪 (not fcmp_pp): the ed25519 group is Z_L × Z_8. A point lies
 *   in the prime-order subgroup IFF its Z_8 component is trivial IFF [L]P = 𝒪
 *   (multiplying by L kills the Z_L part and, since gcd(L, 8) = gcd(5, 8) = 1,
 *   acts as a bijection on the Z_8 part, so [L]P = 𝒪 ⟺ Z_8-part = 𝒪). This is
 *   exact and needs ONLY the ge_* primitives X1 already vendored — it does NOT
 *   depend on monero/fcmp_pp (which is not in-tree; it is X6 territory and is
 *   FCMP-fenced out of this wave). An earlier draft called
 *   fcmp_pp::mul8_is_identity + torsion_check_vartime; finalized to crypto-ops
 *   only so the check is buildable in the CI-gated lane today.
 *
 *   BUILD: compiled ONLY in a lane build that links the vendored Monero-core
 *   crypto (crypto-ops.c + crypto-ops-data.c, BSD-3). NOT part of the
 *   header-only descriptor surface and NOT compiled in the header-only
 *   descriptor unit test (which exercises the SHA-256 identity_key KATs only).
 *   Guarded by V37_XMR_HAVE_MONERO_CRYPTO.
 * ---------------------------------------------------------------------------
 */

#include "v37_descriptor_xmr.hpp"

#if defined(V37_XMR_HAVE_MONERO_CRYPTO)

extern "C" {
#include "crypto-ops.h"   // ge_p3, ge_p2, ge_frombytes_vartime, ge_scalarmult,
                          // ge_tobytes, ge_p3_is_point_at_infinity_vartime (BSD-3)
}

namespace v37 {
namespace xmr {

// The order L of the ed25519 prime-order subgroup, 32-byte little-endian:
//   L = 2^252 + 27742317777372353535851937790883648493
// (RFC 8032 / the constant used throughout ref10 sc_reduce).
static const unsigned char kEd25519GroupOrderL[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

// Canonical encoding of the group identity 𝒪 = (x=0, y=1): 0x01 00 .. 00.
static const unsigned char kIdentityEncoding[32] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Contract (see v37_descriptor_xmr.hpp): true IFF `pt` (32-byte little-endian
// ed25519 encoding) decodes canonically, is on-curve, is NOT the identity /
// a small-order point, and IS in the prime-order (torsion-free) subgroup.
//
//   Step 1  ge_frombytes_vartime(&P, pt) != 0  -> non-canonical or off-curve.
//   Step 2  ge_p3_is_point_at_infinity_vartime(&P) -> identity (order 1): reject.
//   Step 3  [L]P == 𝒪  -> P has no torsion component (prime-order subgroup).
//           Any small-order (order 2/4/8) or mixed (prime+torsion) point has
//           [L]P != 𝒪 and is rejected here — that is the whole point of the
//           check (a curve point that is NOT identity but carries torsion still
//           fails).
static bool ref10_point_check(const std::uint8_t* pt) {
    ge_p3 P;
    if (ge_frombytes_vartime(&P, pt) != 0) return false;      // decode / on-curve
    if (ge_p3_is_point_at_infinity_vartime(&P)) return false;  // identity guard
    ge_p2 lp;
    ge_scalarmult(&lp, kEd25519GroupOrderL, &P);               // [L]P
    unsigned char out[32];
    ge_tobytes(out, &lp);
    // Constant-length compare against the identity encoding. (vartime backend;
    // point material here is public, so a plain compare is acceptable.)
    for (int i = 0; i < 32; ++i)
        if (out[i] != kIdentityEncoding[i]) return false;
    return true;                                                // prime-order
}

// Install the backend at static-init so is_valid_point() is live once this TU
// is linked. A lane may instead call set_point_check_backend(&ref10_point_check)
// explicitly during startup.
namespace {
struct BackendInstaller {
    BackendInstaller() {
        set_point_check_backend(&ref10_point_check);
        // P-1 canon activation: register the whole-descriptor XMR validator
        // with the ratified PayoutDescriptor canon so PayoutDescriptor::valid()
        // RECOGNIZES the reserved XMR kinds (0x10/0x11) wherever this torsion
        // backend is linked. Co-located by design: XMR validity is meaningless
        // without the point-check backend, so both come online in the same TU
        // (the canon is fail-closed — XMR rejected — until this runs).
        ::v37::set_xmr_descriptor_validator(&xmr_descriptor_valid);
    }
};
const BackendInstaller g_install_xmr_point_check_backend;
} // namespace

} // namespace xmr
} // namespace v37

#endif // V37_XMR_HAVE_MONERO_CRYPTO
