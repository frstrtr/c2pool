/*
 * xmr_point_check_ref10.cpp — reference backend for v37::xmr::xmr_point_check_fn.
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
 *   Fresh c2pool glue (AGPL-3.0). It CALLS — it does not copy — two upstream
 *   crypto surfaces:
 *
 *     - Monero  src/crypto/crypto-ops.{h,c}  `ge_frombytes_vartime`, `ge_p3`
 *               License: BSD-3-Clause (monero-project/monero;
 *               derived from the SUPERCOP ref10 ed25519 implementation).
 *
 *     - Monero  src/fcmp_pp/fcmp_pp_crypto.h  `fcmp_pp::mul8_is_identity`,
 *               `fcmp_pp::torsion_check_vartime`  (BSD-3-Clause).
 *
 *   The validation SEQUENCE (decode -> reject cofactor-identity -> require
 *   prime-order) is re-expressed from, and matches, SChernykh/p2pool
 *   src/wallet.cpp `Wallet::torsion_check()` (GPL-3.0). GPL-3.0 code is
 *   combinable into this AGPL-3.0 program under AGPLv3 §13; no p2pool source
 *   text is reproduced here — only the well-known 4-step check is mirrored.
 *
 *   BUILD: this TU is compiled ONLY in a lane build that links Monero-core
 *   crypto (BSD-3, ports trivially into c2pool). It is NOT part of the
 *   header-only descriptor surface and is NOT compiled in the descriptor unit
 *   test (which exercises the SHA-256 identity_key KATs only). Guarded by
 *   V37_XMR_HAVE_MONERO_CRYPTO so the tree builds without Monero crypto until
 *   the lane is wired.
 * ---------------------------------------------------------------------------
 */

#include "v37_descriptor_xmr.hpp"

#if defined(V37_XMR_HAVE_MONERO_CRYPTO)

extern "C" {
#include "crypto-ops.h"          // ge_p3, ge_frombytes_vartime  (Monero, BSD-3)
}
#include "fcmp_pp_crypto.h"      // fcmp_pp::mul8_is_identity / torsion_check_vartime

namespace v37 {
namespace xmr {

// Contract (see v37_descriptor_xmr.hpp): true iff `pt` (32-byte little-endian
// ed25519 encoding) decodes canonically, is on-curve, is NOT a small-order
// point, and IS in the prime-order (torsion-free) subgroup.
//
// Step 1  ge_frombytes_vartime != 0  -> not a valid/canonical on-curve point.
// Step 2  mul8_is_identity(P)        -> P is small-order (8·P == 𝒪): reject.
// Step 3  torsion_check_vartime(P)   -> P is in the prime-order subgroup.
static bool ref10_point_check(const std::uint8_t* pt) {
    ge_p3 P;
    if (ge_frombytes_vartime(&P, pt) != 0) return false;   // decode / on-curve
    if (fcmp_pp::mul8_is_identity(P))      return false;    // small-order guard
    return fcmp_pp::torsion_check_vartime(P);               // prime-order subgroup
}

// Install the backend at static-init so is_valid_point() is live once this TU
// is linked. (A lane may instead call set_point_check_backend(&ref10_point_check)
// explicitly during startup.)
namespace {
struct BackendInstaller {
    BackendInstaller() { set_point_check_backend(&ref10_point_check); }
};
const BackendInstaller g_install_xmr_point_check_backend;
} // namespace

} // namespace xmr
} // namespace v37

#endif // V37_XMR_HAVE_MONERO_CRYPTO
