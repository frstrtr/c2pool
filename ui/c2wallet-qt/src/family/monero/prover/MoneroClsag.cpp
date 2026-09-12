// Copyright (c) 2014-2026, The Monero Project  (BSD-3-Clause)
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED. Full BSD-3 text: xmr_derivation.cpp.
//
// Port of monero-project/monero src/ringct/rctSigs.cpp (CLSAG_Gen,
// proveRctCLSAGSimple, verRctCLSAGSimple), src/device/device_default.cpp
// (clsag_prepare/clsag_hash/clsag_sign) and src/ringct/rctOps.cpp
// (commit, addKeys_aGbBcC, addKeys_aAbBcC), re-expressed over Bytes32 and the
// vendored ed25519 engine. See MoneroClsag.hpp for full provenance.

#include "family/monero/prover/MoneroClsag.hpp"

#include <cstring>

#include "secure/SecureString.hpp"          // c2w::secure::secure_wipe
#include "xmr_rct_ops.hpp"                   // c2pool::xmr::native::rct helpers

extern "C" {
#include "vendor/crypto-ops.h"
}

namespace xr = c2pool::xmr::native::rct;

namespace c2wallet::monero::prover {

namespace {

// A domain-separation scalar seed: the ASCII tag in the low bytes, zero-padded,
// exactly as monerod builds config::HASH_KEY_CLSAG_* (sc_0 then memcpy tag).
Bytes32 domain_key(const char* tag) {
    Bytes32 k{};
    std::memcpy(k.data(), tag, std::strlen(tag));
    return k;
}

// aG = a*G (the fixed basepoint).
void scalarmult_base(Bytes32& out, const Bytes32& a) {
    ge_p3 point;
    ge_scalarmult_base(&point, a.data());
    ge_p3_tobytes(out.data(), &point);
}

// A double-scalar-mult precomputation table for a point given by bytes.
struct GeDsmp { ge_cached k[8]; };
bool precomp(GeDsmp& out, const Bytes32& P) {
    ge_p3 p3;
    if (ge_frombytes_vartime(&p3, P.data()) != 0) return false;
    ge_dsm_precomp(out.k, &p3);
    return true;
}
void precomp(GeDsmp& out, const ge_p3& p3) { ge_dsm_precomp(out.k, &p3); }

// L = a*G + b*B + c*C  (rctOps addKeys_aGbBcC; B, C precomputed).
void addKeys_aGbBcC(Bytes32& out, const Bytes32& a, const Bytes32& b,
                    const GeDsmp& B, const Bytes32& c, const GeDsmp& C) {
    ge_p2 rv;
    ge_triple_scalarmult_base_vartime(&rv, a.data(), b.data(), B.k, c.data(), C.k);
    ge_tobytes(out.data(), &rv);
}

// R = a*A + b*B + c*C  (rctOps addKeys_aAbBcC; A, B, C precomputed).
void addKeys_aAbBcC(Bytes32& out, const Bytes32& a, const GeDsmp& A,
                    const Bytes32& b, const GeDsmp& B, const Bytes32& c, const GeDsmp& C) {
    ge_p2 rv;
    ge_triple_scalarmult_precomp_vartime(&rv, a.data(), A.k, b.data(), B.k, c.data(), C.k);
    ge_tobytes(out.data(), &rv);
}

bool is_identity(const Bytes32& k) { return k == xr::identity(); }

} // namespace

// C = mask*G + amount*H  (rct::commit).
Bytes32 commit(std::uint64_t amount, const Bytes32& mask) {
    Bytes32 mG{};
    scalarmult_base(mG, mask);
    const Bytes32 aH = xr::scalarmult_H(xr::amount_to_scalar(amount));
    Bytes32 out{};
    // mG + aH via the vendored group add.
    ge_p3 a3, b3; ge_cached bc; ge_p1p1 sum; ge_p3 res;
    if (ge_frombytes_vartime(&a3, mG.data()) != 0) return out;
    if (ge_frombytes_vartime(&b3, aH.data()) != 0) return out;
    ge_p3_to_cached(&bc, &b3);
    ge_add(&sum, &a3, &bc);
    ge_p1p1_to_p3(&res, &sum);
    ge_p3_tobytes(out.data(), &res);
    return out;
}

bool clsag_gen(const Bytes32& message,
               const std::vector<Bytes32>& P,
               const Bytes32& p,
               const std::vector<Bytes32>& C,
               const Bytes32& z,
               const std::vector<Bytes32>& C_nonzero,
               const Bytes32& C_offset,
               std::size_t l,
               Clsag& sig) {
    const std::size_t n = P.size();
    if (n == 0 || n != C.size() || n != C_nonzero.size() || l >= n) return false;

    // Key images. H = H_p(P[l]).
    ge_p3 H_p3;
    xr::hash_to_p3(H_p3, P[l]);
    Bytes32 H{};
    ge_p3_tobytes(H.data(), &H_p3);

    // clsag_prepare (device_default): a random nonce, and the two images.
    Bytes32 a = xr::random_scalar_nonzero();
    Bytes32 aG{}; scalarmult_base(aG, a);
    Bytes32 aH{}; xr::scalarmult_key(aH, H, a);   // aH = a*H
    xr::scalarmult_key(sig.I, H, p);              // I  = p*H
    Bytes32 D{}; xr::scalarmult_key(D, H, z);     // D  = z*H

    GeDsmp I_precomp, D_precomp;
    if (!precomp(I_precomp, sig.I)) { c2w::secure::secure_wipe(a.data(), a.size()); return false; }
    if (!precomp(D_precomp, D))    { c2w::secure::secure_wipe(a.data(), a.size()); return false; }

    // Offset (published) key image D/8.
    xr::scalarmult_key(sig.D, D, xr::inv_eight());

    // Aggregation hashes mu_P, mu_C: domain, P[..], C_nonzero[..], I, D, C_offset.
    xr::KeyV mu_P_to_hash(2 * n + 4), mu_C_to_hash(2 * n + 4);
    mu_P_to_hash[0] = domain_key("CLSAG_agg_0");
    mu_C_to_hash[0] = domain_key("CLSAG_agg_1");
    for (std::size_t i = 1; i < n + 1; ++i) { mu_P_to_hash[i] = P[i - 1]; mu_C_to_hash[i] = P[i - 1]; }
    for (std::size_t i = n + 1; i < 2 * n + 1; ++i) {
        mu_P_to_hash[i] = C_nonzero[i - n - 1];
        mu_C_to_hash[i] = C_nonzero[i - n - 1];
    }
    mu_P_to_hash[2 * n + 1] = sig.I; mu_P_to_hash[2 * n + 2] = sig.D; mu_P_to_hash[2 * n + 3] = C_offset;
    mu_C_to_hash[2 * n + 1] = sig.I; mu_C_to_hash[2 * n + 2] = sig.D; mu_C_to_hash[2 * n + 3] = C_offset;
    const Bytes32 mu_P = xr::hash_to_scalar(mu_P_to_hash);
    const Bytes32 mu_C = xr::hash_to_scalar(mu_C_to_hash);

    // Round hash: domain, P[..], C_nonzero[..], C_offset, message, aG, aH.
    xr::KeyV c_to_hash(2 * n + 5);
    c_to_hash[0] = domain_key("CLSAG_round");
    for (std::size_t i = 1; i < n + 1; ++i) { c_to_hash[i] = P[i - 1]; c_to_hash[i + n] = C_nonzero[i - 1]; }
    c_to_hash[2 * n + 1] = C_offset;
    c_to_hash[2 * n + 2] = message;
    c_to_hash[2 * n + 3] = aG;
    c_to_hash[2 * n + 4] = aH;
    Bytes32 c = xr::hash_to_scalar(c_to_hash);

    std::size_t i = (l + 1) % n;
    if (i == 0) sig.c1 = c;

    sig.s.assign(n, Bytes32{});
    Bytes32 c_p{}, c_c{}, L{}, R{};
    GeDsmp P_precomp, C_precomp, H_precomp;
    ge_p3 Hi_p3;

    while (i != l) {
        sig.s[i] = xr::random_scalar_nonzero();
        sc_mul(c_p.data(), mu_P.data(), c.data());
        sc_mul(c_c.data(), mu_C.data(), c.data());

        if (!precomp(P_precomp, P[i]) || !precomp(C_precomp, C[i])) {
            c2w::secure::secure_wipe(a.data(), a.size());
            return false;
        }
        addKeys_aGbBcC(L, sig.s[i], c_p, P_precomp, c_c, C_precomp);

        xr::hash_to_p3(Hi_p3, P[i]);
        precomp(H_precomp, Hi_p3);
        addKeys_aAbBcC(R, sig.s[i], H_precomp, c_p, I_precomp, c_c, D_precomp);

        c_to_hash[2 * n + 3] = L;
        c_to_hash[2 * n + 4] = R;
        c = xr::hash_to_scalar(c_to_hash);

        i = (i + 1) % n;
        if (i == 0) sig.c1 = c;
    }

    // Final scalar: s[l] = a - c*(mu_P*p + mu_C*z)  (clsag_sign).
    Bytes32 s0_p_mu_P{}, s0_add_z_mu_C{};
    sc_mul(s0_p_mu_P.data(), mu_P.data(), p.data());
    sc_muladd(s0_add_z_mu_C.data(), mu_C.data(), z.data(), s0_p_mu_P.data());
    sc_mulsub(sig.s[l].data(), c.data(), s0_add_z_mu_C.data(), a.data());

    c2w::secure::secure_wipe(a.data(), a.size());
    c2w::secure::secure_wipe(s0_p_mu_P.data(), s0_p_mu_P.size());
    c2w::secure::secure_wipe(s0_add_z_mu_C.data(), s0_add_z_mu_C.size());
    return true;
}

bool clsag_prove_simple(const Bytes32& message,
                        const std::vector<CtKey>& ring,
                        const Bytes32& p,
                        const Bytes32& c_a,
                        const Bytes32& c_out,
                        const Bytes32& Cout,
                        std::size_t index,
                        Clsag& out) {
    if (ring.empty() || index >= ring.size()) return false;

    std::vector<Bytes32> P, C, C_nonzero;
    P.reserve(ring.size());
    C.reserve(ring.size());
    C_nonzero.reserve(ring.size());
    for (const CtKey& k : ring) {
        P.push_back(k.dest);
        C_nonzero.push_back(k.mask);
        // C_i = C_nonzero_i - Cout  (subKeys).
        ge_p3 a3, b3; ge_cached bc; ge_p1p1 diff; ge_p3 res;
        Bytes32 tmp{};
        if (ge_frombytes_vartime(&a3, k.mask.data()) != 0) return false;
        if (ge_frombytes_vartime(&b3, Cout.data()) != 0) return false;
        ge_p3_to_cached(&bc, &b3);
        ge_sub(&diff, &a3, &bc);
        ge_p1p1_to_p3(&res, &diff);
        ge_p3_tobytes(tmp.data(), &res);
        C.push_back(tmp);
    }

    // z = c_a - c_out  (blinding factor of the commitment-to-zero C[index]).
    Bytes32 z{};
    sc_sub(z.data(), c_a.data(), c_out.data());

    const bool ok = clsag_gen(message, P, p, C, z, C_nonzero, Cout, index, out);
    c2w::secure::secure_wipe(z.data(), z.size());
    return ok;
}

bool clsag_verify(const Bytes32& message,
                  const Clsag& sig,
                  const std::vector<CtKey>& ring,
                  const Bytes32& C_offset) {
    const std::size_t n = ring.size();
    if (n < 1 || n != sig.s.size()) return false;
    for (std::size_t i = 0; i < n; ++i)
        if (sc_check(sig.s[i].data()) != 0) return false;
    if (sc_check(sig.c1.data()) != 0) return false;
    if (is_identity(sig.I)) return false;

    ge_p3 C_offset_p3;
    if (ge_frombytes_vartime(&C_offset_p3, C_offset.data()) != 0) return false;
    ge_cached C_offset_cached;
    ge_p3_to_cached(&C_offset_cached, &C_offset_p3);

    Bytes32 c = sig.c1;

    // D_8 = 8 * sig.D  (undo the /8 published form).
    ge_p3 D8_p3;
    if (!xr::scalarmult8(D8_p3, sig.D)) return false;
    Bytes32 D_8{};
    ge_p3_tobytes(D_8.data(), &D8_p3);
    if (is_identity(D_8)) return false;

    GeDsmp I_precomp, D_precomp;
    if (!precomp(I_precomp, sig.I)) return false;
    precomp(D_precomp, D8_p3);

    xr::KeyV mu_P_to_hash(2 * n + 4), mu_C_to_hash(2 * n + 4);
    mu_P_to_hash[0] = domain_key("CLSAG_agg_0");
    mu_C_to_hash[0] = domain_key("CLSAG_agg_1");
    for (std::size_t i = 1; i < n + 1; ++i) { mu_P_to_hash[i] = ring[i - 1].dest; mu_C_to_hash[i] = ring[i - 1].dest; }
    for (std::size_t i = n + 1; i < 2 * n + 1; ++i) {
        mu_P_to_hash[i] = ring[i - n - 1].mask;
        mu_C_to_hash[i] = ring[i - n - 1].mask;
    }
    mu_P_to_hash[2 * n + 1] = sig.I; mu_P_to_hash[2 * n + 2] = sig.D; mu_P_to_hash[2 * n + 3] = C_offset;
    mu_C_to_hash[2 * n + 1] = sig.I; mu_C_to_hash[2 * n + 2] = sig.D; mu_C_to_hash[2 * n + 3] = C_offset;
    const Bytes32 mu_P = xr::hash_to_scalar(mu_P_to_hash);
    const Bytes32 mu_C = xr::hash_to_scalar(mu_C_to_hash);

    xr::KeyV c_to_hash(2 * n + 5);
    c_to_hash[0] = domain_key("CLSAG_round");
    for (std::size_t i = 1; i < n + 1; ++i) { c_to_hash[i] = ring[i - 1].dest; c_to_hash[i + n] = ring[i - 1].mask; }
    c_to_hash[2 * n + 1] = C_offset;
    c_to_hash[2 * n + 2] = message;

    Bytes32 c_p{}, c_c{}, c_new{}, L{}, R{};
    GeDsmp P_precomp, C_precomp, hash_precomp;
    ge_p3 hash8_p3, temp_p3; ge_p1p1 temp_p1;

    for (std::size_t i = 0; i < n; ++i) {
        sc_mul(c_p.data(), mu_P.data(), c.data());
        sc_mul(c_c.data(), mu_C.data(), c.data());

        if (!precomp(P_precomp, ring[i].dest)) return false;

        // C_i = ring[i].mask - C_offset, precomputed.
        if (ge_frombytes_vartime(&temp_p3, ring[i].mask.data()) != 0) return false;
        ge_sub(&temp_p1, &temp_p3, &C_offset_cached);
        ge_p1p1_to_p3(&temp_p3, &temp_p1);
        precomp(C_precomp, temp_p3);

        addKeys_aGbBcC(L, sig.s[i], c_p, P_precomp, c_c, C_precomp);

        xr::hash_to_p3(hash8_p3, ring[i].dest);
        precomp(hash_precomp, hash8_p3);
        addKeys_aAbBcC(R, sig.s[i], hash_precomp, c_p, I_precomp, c_c, D_precomp);

        c_to_hash[2 * n + 3] = L;
        c_to_hash[2 * n + 4] = R;
        c_new = xr::hash_to_scalar(c_to_hash);
        if (xr::scalar_is_zero(c_new)) return false;
        c = c_new;
    }

    Bytes32 diff{};
    sc_sub(diff.data(), c.data(), sig.c1.data());
    return sc_isnonzero(diff.data()) == 0;
}

} // namespace c2wallet::monero::prover
