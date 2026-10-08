// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// Derived from monero-project/monero src/ringct/rctSigs.cpp
// (verRctCLSAGSimple, get_pre_mlsag_hash), src/ringct/rctOps.cpp
// (addKeys_aGbBcC, addKeys_aAbBcC, precomp, scalarmult8) and
// src/device/device_default.cpp (mlsag_prehash = cn_fast_hash(hashes)),
// BSD-3-Clause. See PROVENANCE.md in this directory.
//
// Transcribed step for step from verRctCLSAGSimple, with upstream's notation
// and comments where they explain a step; every throwing
// CHECK_AND_ASSERT_MES becomes a typed status return, because the ring, the
// signature and the commitment offset are all bytes an unauthenticated peer
// chose.
// ---------------------------------------------------------------------------
#include "xmr_clsag_verify.hpp"

#include <cstring>

extern "C" {
#include "vendor/crypto-ops.h"
}

namespace c2pool::xmr::native::rct {
namespace {

// Domain separators (monero src/cryptonote_config.h HASH_KEY_CLSAG_AGG_0 /
// _AGG_1 / _ROUND): the ASCII string left-aligned in a 32-byte key, the rest
// zero -- exactly what upstream's `sc_0` + `memcpy(..., sizeof(lit)-1)` builds.
Key domain(const char* lit) noexcept {
    Key k{};
    const std::size_t n = std::strlen(lit);
    std::memcpy(k.data(), lit, n);
    return k;
}
const Key& agg0()  noexcept { static const Key k = domain("CLSAG_agg_0"); return k; }
const Key& agg1()  noexcept { static const Key k = domain("CLSAG_agg_1"); return k; }
const Key& round() noexcept { static const Key k = domain("CLSAG_round"); return k; }

// 8*P, encoded (upstream scalarmult8(key)). false when P is not a point.
bool scalarmult8_encode(Key& out, const Key& P) noexcept {
    ge_p3 p3;
    if (ge_frombytes_vartime(&p3, P.data()) != 0) return false;
    ge_p2 p2;
    ge_p3_to_p2(&p2, &p3);
    ge_p1p1 p1;
    ge_mul8(&p1, &p2);
    ge_p1p1_to_p2(&p2, &p1);
    ge_tobytes(out.data(), &p2);
    return true;
}

// dsm precompute of an already-decoded point (upstream precomp(rv, key), but
// taking the decoded p3 so the caller keeps the decode-failure branch).
inline void precomp_p3(ge_dsmp rv, const ge_p3& p) noexcept {
    ge_dsm_precomp(rv, &p);
}

} // namespace

const char* to_string(ClsagStatus s) noexcept {
    switch (s) {
        case ClsagStatus::Ok:             return "Ok";
        case ClsagStatus::ShapeMismatch:  return "ShapeMismatch";
        case ClsagStatus::BadScalar:      return "BadScalar";
        case ClsagStatus::BadKeyImage:    return "BadKeyImage";
        case ClsagStatus::BadAuxKeyImage: return "BadAuxKeyImage";
        case ClsagStatus::BadPoint:       return "BadPoint";
        case ClsagStatus::BadCommitment:  return "BadCommitment";
        case ClsagStatus::BadHash:        return "BadHash";
        case ClsagStatus::SigMismatch:    return "SigMismatch";
    }
    return "?";
}

Key clsag_message(const Key& prefix_hash, const Key& rct_base_hash,
                  const BulletproofPlus& bpp) noexcept {
    // cn_fast_hash(kv) over A,A1,B,r1,s1,d1,L[],R[] -- V omitted (expanded from
    // outPk, already in the rct base hash).
    KeyV kv;
    kv.reserve(6 + bpp.L.size() + bpp.R.size());
    kv.push_back(bpp.A);
    kv.push_back(bpp.A1);
    kv.push_back(bpp.B);
    kv.push_back(bpp.r1);
    kv.push_back(bpp.s1);
    kv.push_back(bpp.d1);
    for (const Key& l : bpp.L) kv.push_back(l);
    for (const Key& r : bpp.R) kv.push_back(r);
    const Key h_kv = cn_fast_hash(kv.data(), kv.size() * sizeof(Key));

    // prehash = cn_fast_hash(hashes) with hashes = { H(prefix), H(base), H(kv) }.
    std::uint8_t hashes[96];
    std::memcpy(hashes,      prefix_hash.data(),   32);
    std::memcpy(hashes + 32, rct_base_hash.data(), 32);
    std::memcpy(hashes + 64, h_kv.data(),          32);
    return cn_fast_hash(hashes, sizeof(hashes));
}

ClsagStatus verify_clsag(const Key& message, const Clsag& sig,
                         const std::vector<CtKey>& ring, const Key& C_offset) noexcept {
    const std::size_t n = ring.size();
    if (n < 1)              return ClsagStatus::ShapeMismatch;
    if (n != sig.s.size())  return ClsagStatus::ShapeMismatch;

    for (const Key& s : sig.s)
        if (sc_check(s.data()) != 0) return ClsagStatus::BadScalar;
    if (sc_check(sig.c1.data()) != 0) return ClsagStatus::BadScalar;
    if (sig.I == identity())          return ClsagStatus::BadKeyImage;

    // Cache the commitment offset for the per-member subtraction.
    ge_p3 C_offset_p3;
    if (ge_frombytes_vartime(&C_offset_p3, C_offset.data()) != 0) return ClsagStatus::BadPoint;
    ge_cached C_offset_cached;
    ge_p3_to_cached(&C_offset_cached, &C_offset_p3);

    // Key images: I from the input, D rescaled into the subgroup (8*D).
    Key c = sig.c1;
    Key D_8{};
    if (!scalarmult8_encode(D_8, sig.D))      return ClsagStatus::BadPoint;
    if (D_8 == identity())                    return ClsagStatus::BadAuxKeyImage;

    ge_p3   I_p3, D_p3;
    ge_dsmp I_precomp, D_precomp;
    if (ge_frombytes_vartime(&I_p3, sig.I.data()) != 0) return ClsagStatus::BadPoint;
    if (ge_frombytes_vartime(&D_p3, D_8.data())   != 0) return ClsagStatus::BadPoint;
    precomp_p3(I_precomp, I_p3);
    precomp_p3(D_precomp, D_p3);

    // Aggregation hashes mu_P, mu_C over: domain, dest[], mask[], I, D, C_offset.
    KeyV mu_P_to_hash(2 * n + 4), mu_C_to_hash(2 * n + 4);
    mu_P_to_hash[0] = agg0();
    mu_C_to_hash[0] = agg1();
    for (std::size_t i = 1; i < n + 1; ++i) {
        mu_P_to_hash[i] = ring[i - 1].dest;
        mu_C_to_hash[i] = ring[i - 1].dest;
    }
    for (std::size_t i = n + 1; i < 2 * n + 1; ++i) {
        mu_P_to_hash[i] = ring[i - n - 1].mask;
        mu_C_to_hash[i] = ring[i - n - 1].mask;
    }
    mu_P_to_hash[2 * n + 1] = sig.I;
    mu_P_to_hash[2 * n + 2] = sig.D;
    mu_P_to_hash[2 * n + 3] = C_offset;
    mu_C_to_hash[2 * n + 1] = sig.I;
    mu_C_to_hash[2 * n + 2] = sig.D;
    mu_C_to_hash[2 * n + 3] = C_offset;
    const Key mu_P = hash_to_scalar(mu_P_to_hash);
    const Key mu_C = hash_to_scalar(mu_C_to_hash);

    // Round hash pre-image: domain, dest[], mask[], C_offset, message, L, R.
    KeyV c_to_hash(2 * n + 5);
    c_to_hash[0] = round();
    for (std::size_t i = 1; i < n + 1; ++i) {
        c_to_hash[i]     = ring[i - 1].dest;
        c_to_hash[i + n] = ring[i - 1].mask;
    }
    c_to_hash[2 * n + 1] = C_offset;
    c_to_hash[2 * n + 2] = message;

    for (std::size_t i = 0; i < n; ++i) {
        const Key c_p = sc_mul_k(mu_P, c);
        const Key c_c = sc_mul_k(mu_C, c);

        // P_precomp for dest[i].
        ge_p3 P_p3;
        if (ge_frombytes_vartime(&P_p3, ring[i].dest.data()) != 0) return ClsagStatus::BadPoint;
        ge_dsmp P_precomp;
        precomp_p3(P_precomp, P_p3);

        // C_precomp for (mask[i] - C_offset).
        ge_p3 C_p3;
        if (ge_frombytes_vartime(&C_p3, ring[i].mask.data()) != 0) return ClsagStatus::BadCommitment;
        ge_p1p1 sub_p1;
        ge_sub(&sub_p1, &C_p3, &C_offset_cached);
        ge_p3 Cd_p3;
        ge_p1p1_to_p3(&Cd_p3, &sub_p1);
        ge_dsmp C_precomp;
        precomp_p3(C_precomp, Cd_p3);

        // L = s[i]*G + c_p*P + c_c*(C - C_offset).
        Key L{};
        {
            ge_p2 rv;
            ge_triple_scalarmult_base_vartime(&rv, sig.s[i].data(), c_p.data(), P_precomp,
                                              c_c.data(), C_precomp);
            ge_tobytes(L.data(), &rv);
        }

        // R = s[i]*Hp(dest) + c_p*I + c_c*D.
        ge_p3 hash8_p3;
        hash_to_p3(hash8_p3, ring[i].dest);
        ge_dsmp hash_precomp;
        precomp_p3(hash_precomp, hash8_p3);
        Key R{};
        {
            ge_p2 rv;
            ge_triple_scalarmult_precomp_vartime(&rv, sig.s[i].data(), hash_precomp,
                                                 c_p.data(), I_precomp, c_c.data(), D_precomp);
            ge_tobytes(R.data(), &rv);
        }

        c_to_hash[2 * n + 3] = L;
        c_to_hash[2 * n + 4] = R;
        const Key c_new = hash_to_scalar(c_to_hash);
        if (scalar_is_zero(c_new)) return ClsagStatus::BadHash;
        c = c_new;
    }

    const Key diff = sc_sub_k(c, sig.c1);
    return sc_isnonzero(diff.data()) == 0 ? ClsagStatus::Ok : ClsagStatus::SigMismatch;
}

} // namespace c2pool::xmr::native::rct
