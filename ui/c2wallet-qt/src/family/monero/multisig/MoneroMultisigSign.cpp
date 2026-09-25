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
// Cooperative (multi-party) CLSAG signer. The ring hash loop mirrors
// monero-project rctSigs.cpp CLSAG_Gen (and MoneroClsag.cpp) exactly so the
// combined signature verifies under the unchanged in-tree verifier. See
// MoneroMultisigSign.hpp for the multi-party algebra and money-safety notes.

#include "family/monero/multisig/MoneroMultisigSign.hpp"

#include <algorithm>
#include <cstring>

#include "secure/SecureString.hpp"                    // secure_wipe
#include "xmr_rct_ops.hpp"                            // c2pool::xmr::native::rct helpers
#include "family/monero/prover/MoneroProverRng.hpp"   // csprng_scalar_nonzero (money-safe)

extern "C" {
#include "vendor/crypto-ops.h"
}

namespace xr = c2pool::xmr::native::rct;
using c2w::secure::secure_wipe;

namespace c2wallet::monero::multisig {

namespace {

// Domain-separation scalar seed: ASCII tag zero-padded, matching monerod's
// config::HASH_KEY_CLSAG_* (identical to MoneroClsag.cpp domain_key).
Bytes32 domain_key(const char* tag) {
    Bytes32 k{};
    std::memcpy(k.data(), tag, std::strlen(tag));
    return k;
}

void scalarmult_base(Bytes32& out, const Bytes32& a) {
    ge_p3 point;
    ge_scalarmult_base(&point, a.data());
    ge_p3_tobytes(out.data(), &point);
}

struct GeDsmp { ge_cached k[8]; };
bool precomp(GeDsmp& out, const Bytes32& P) {
    ge_p3 p3;
    if (ge_frombytes_vartime(&p3, P.data()) != 0) return false;
    ge_dsm_precomp(out.k, &p3);
    return true;
}
void precomp(GeDsmp& out, const ge_p3& p3) { ge_dsm_precomp(out.k, &p3); }

// L = a*G + b*B + c*C  (rctOps addKeys_aGbBcC).
void addKeys_aGbBcC(Bytes32& out, const Bytes32& a, const Bytes32& b,
                    const GeDsmp& B, const Bytes32& c, const GeDsmp& C) {
    ge_p2 rv;
    ge_triple_scalarmult_base_vartime(&rv, a.data(), b.data(), B.k, c.data(), C.k);
    ge_tobytes(out.data(), &rv);
}
// R = a*A + b*B + c*C  (rctOps addKeys_aAbBcC).
void addKeys_aAbBcC(Bytes32& out, const Bytes32& a, const GeDsmp& A,
                    const Bytes32& b, const GeDsmp& B, const Bytes32& c, const GeDsmp& C) {
    ge_p2 rv;
    ge_triple_scalarmult_precomp_vartime(&rv, a.data(), A.k, b.data(), B.k, c.data(), C.k);
    ge_tobytes(out.data(), &rv);
}

// R = P - Q for compressed points (subKeys). False on decode failure.
bool sub_points(const Bytes32& P, const Bytes32& Q, Bytes32& R) {
    ge_p3 a3, b3; ge_cached bc; ge_p1p1 diff; ge_p3 res;
    if (ge_frombytes_vartime(&a3, P.data()) != 0) return false;
    if (ge_frombytes_vartime(&b3, Q.data()) != 0) return false;
    ge_p3_to_cached(&bc, &b3);
    ge_sub(&diff, &a3, &bc);
    ge_p1p1_to_p3(&res, &diff);
    ge_p3_tobytes(R.data(), &res);
    return true;
}

// Sum a list of compressed points into `out`. False on decode failure.
bool sum_points(const std::vector<Bytes32>& pts, Bytes32& out) {
    if (pts.empty()) return false;
    ge_p3 acc;
    if (ge_frombytes_vartime(&acc, pts[0].data()) != 0) return false;
    for (std::size_t i = 1; i < pts.size(); ++i) {
        ge_p3 p; ge_cached c; ge_p1p1 s;
        if (ge_frombytes_vartime(&p, pts[i].data()) != 0) return false;
        ge_p3_to_cached(&c, &p);
        ge_add(&s, &acc, &c);
        ge_p1p1_to_p3(&acc, &s);
    }
    ge_p3_tobytes(out.data(), &acc);
    return true;
}

// pp = Sum of `assigned` scalars (+ *known if non-null). Caller wipes.
Bytes32 fold_secret(const std::vector<Bytes32>& assigned, const Bytes32* known) {
    Bytes32 pp{};
    for (const Bytes32& sh : assigned) sc_add(pp.data(), pp.data(), sh.data());
    if (known) sc_add(pp.data(), pp.data(), known->data());
    return pp;
}

} // namespace

CosignerNonce::~CosignerNonce() {
    if (live) { secure_wipe(alpha.data(), alpha.size()); live = false; }
}

bool make_signing_session(const Bytes32& message,
                          const std::vector<CtKey>& ring,
                          std::size_t real_index,
                          const Bytes32& Cout,
                          SigningSession& out) {
    if (ring.empty() || real_index >= ring.size()) return false;
    out.message = message;
    out.ring = ring;
    out.real_index = real_index;
    out.Cout = Cout;
    ge_p3 H_p3;
    xr::hash_to_p3(H_p3, ring[real_index].dest);
    ge_p3_tobytes(out.H.data(), &H_p3);
    return true;
}

std::vector<Bytes32> assigned_shares(const SignerShares& shares,
                                     const std::vector<std::uint32_t>& quorum) {
    std::vector<Bytes32> out;
    for (std::size_t k = 0; k < shares.spend_key_shares.size(); ++k) {
        const std::vector<std::uint32_t>& subset = shares.shares_subset[k];
        // Lowest-index member of the subset that is in the quorum owns this share.
        bool have_min = false;
        std::uint32_t owner = 0;
        for (std::uint32_t m : subset) {
            if (std::find(quorum.begin(), quorum.end(), m) == quorum.end()) continue;
            if (!have_min || m < owner) { owner = m; have_min = true; }
        }
        if (have_min && owner == shares.signer_index)
            out.push_back(shares.spend_key_shares[k]);
    }
    return out;
}

bool cosigner_round1(const SigningSession& s,
                     std::uint32_t signer_index,
                     const std::vector<Bytes32>& assigned,
                     const Bytes32* known_part,
                     PartialNonce& out,
                     CosignerNonce& nonce_out) {
    out.signer_index = signer_index;
    // Fresh CSPRNG nonce (money-safety). Kept secret in nonce_out.
    nonce_out.alpha = prover::csprng_scalar_nonzero();
    nonce_out.live = true;

    scalarmult_base(out.alpha_G, nonce_out.alpha);
    if (!xr::scalarmult_key(out.alpha_H, s.H, nonce_out.alpha)) return false;

    Bytes32 pp = fold_secret(assigned, known_part);
    bool ok = xr::scalarmult_key(out.partial_ki, s.H, pp);   // pp * H
    secure_wipe(pp.data(), pp.size());
    return ok;
}

bool coordinator_combine_round1(const SigningSession& s,
                                const std::vector<PartialNonce>& nonces,
                                const Bytes32& z,
                                Round1Combined& out) {
    const std::size_t n = s.ring.size();
    const std::size_t l = s.real_index;
    if (nonces.empty() || l >= n) return false;

    std::vector<Bytes32> aGs, aHs, kis;
    for (const PartialNonce& p : nonces) { aGs.push_back(p.alpha_G); aHs.push_back(p.alpha_H); kis.push_back(p.partial_ki); }

    Bytes32 aG{}, aH{};
    if (!sum_points(aGs, aG)) return false;
    if (!sum_points(aHs, aH)) return false;
    if (!sum_points(kis, out.I)) return false;              // I = x * H

    // Auxiliary image D = z*H (full); published as D/8.
    Bytes32 D_full{};
    if (!xr::scalarmult_key(D_full, s.H, z)) return false;
    if (!xr::scalarmult_key(out.D, D_full, xr::inv_eight())) return false;

    GeDsmp I_precomp, D_precomp;
    if (!precomp(I_precomp, out.I)) return false;
    if (!precomp(D_precomp, D_full)) return false;

    // Aggregation hashes mu_P, mu_C.
    xr::KeyV mu_P_to_hash(2 * n + 4), mu_C_to_hash(2 * n + 4);
    mu_P_to_hash[0] = domain_key("CLSAG_agg_0");
    mu_C_to_hash[0] = domain_key("CLSAG_agg_1");
    for (std::size_t i = 1; i < n + 1; ++i) { mu_P_to_hash[i] = s.ring[i - 1].dest; mu_C_to_hash[i] = s.ring[i - 1].dest; }
    for (std::size_t i = n + 1; i < 2 * n + 1; ++i) {
        mu_P_to_hash[i] = s.ring[i - n - 1].mask;
        mu_C_to_hash[i] = s.ring[i - n - 1].mask;
    }
    mu_P_to_hash[2 * n + 1] = out.I; mu_P_to_hash[2 * n + 2] = out.D; mu_P_to_hash[2 * n + 3] = s.Cout;
    mu_C_to_hash[2 * n + 1] = out.I; mu_C_to_hash[2 * n + 2] = out.D; mu_C_to_hash[2 * n + 3] = s.Cout;
    out.mu_P = xr::hash_to_scalar(mu_P_to_hash);
    out.mu_C = xr::hash_to_scalar(mu_C_to_hash);

    // Round hash chain, seeded with the aggregated nonce commitments.
    xr::KeyV c_to_hash(2 * n + 5);
    c_to_hash[0] = domain_key("CLSAG_round");
    for (std::size_t i = 1; i < n + 1; ++i) { c_to_hash[i] = s.ring[i - 1].dest; c_to_hash[i + n] = s.ring[i - 1].mask; }
    c_to_hash[2 * n + 1] = s.Cout;
    c_to_hash[2 * n + 2] = s.message;
    c_to_hash[2 * n + 3] = aG;
    c_to_hash[2 * n + 4] = aH;
    Bytes32 c = xr::hash_to_scalar(c_to_hash);

    out.s.assign(n, Bytes32{});
    std::size_t i = (l + 1) % n;
    if (i == 0) out.c1 = c;

    Bytes32 c_p{}, c_c{}, L{}, R{}, Ci{};
    GeDsmp P_precomp, C_precomp, H_precomp;
    ge_p3 Hi_p3;
    while (i != l) {
        // Published decoy scalar -- MUST be CSPRNG (leaks the chain state / key
        // otherwise), exactly as MoneroClsag.cpp CLSAG_Gen.
        out.s[i] = prover::csprng_scalar_nonzero();
        sc_mul(c_p.data(), out.mu_P.data(), c.data());
        sc_mul(c_c.data(), out.mu_C.data(), c.data());

        if (!precomp(P_precomp, s.ring[i].dest)) return false;
        if (!sub_points(s.ring[i].mask, s.Cout, Ci)) return false;   // C_i = C_nonzero_i - Cout
        if (!precomp(C_precomp, Ci)) return false;
        addKeys_aGbBcC(L, out.s[i], c_p, P_precomp, c_c, C_precomp);

        xr::hash_to_p3(Hi_p3, s.ring[i].dest);
        precomp(H_precomp, Hi_p3);
        addKeys_aAbBcC(R, out.s[i], H_precomp, c_p, I_precomp, c_c, D_precomp);

        c_to_hash[2 * n + 3] = L;
        c_to_hash[2 * n + 4] = R;
        c = xr::hash_to_scalar(c_to_hash);

        i = (i + 1) % n;
        if (i == 0) out.c1 = c;
    }
    out.c_at_l = c;   // the challenge each response consumes
    secure_wipe(D_full.data(), D_full.size());
    return true;
}

Bytes32 cosigner_round2(const Bytes32& c_at_l,
                        const Bytes32& mu_P,
                        const Bytes32& mu_C,
                        const std::vector<Bytes32>& assigned,
                        const Bytes32* known_part,
                        const Bytes32* z,
                        CosignerNonce& nonce) {
    // pp = Sum(assigned) (+ known_part for the coordinator).
    Bytes32 pp = fold_secret(assigned, known_part);

    // resp = alpha - (c*mu_P)*pp.
    Bytes32 cp{};
    sc_mul(cp.data(), c_at_l.data(), mu_P.data());
    Bytes32 resp{};
    sc_mulsub(resp.data(), cp.data(), pp.data(), nonce.alpha.data());  // alpha - cp*pp

    // Coordinator also subtracts (c*mu_C)*z (the commitment-to-zero term).
    if (z) {
        Bytes32 cc{};
        sc_mul(cc.data(), c_at_l.data(), mu_C.data());
        sc_mulsub(resp.data(), cc.data(), z->data(), resp.data());     // resp - cc*z
    }

    secure_wipe(pp.data(), pp.size());
    // Consume the nonce: it must never be reused (would leak pp).
    secure_wipe(nonce.alpha.data(), nonce.alpha.size());
    nonce.live = false;
    return resp;
}

bool coordinator_combine_round2(const SigningSession& s,
                                const Round1Combined& r1,
                                const std::vector<Bytes32>& responses,
                                Clsag& out) {
    if (responses.empty()) return false;
    Bytes32 sl{};
    for (const Bytes32& r : responses) sc_add(sl.data(), sl.data(), r.data());  // s[l] = Sum resp_j
    out.s = r1.s;
    out.s[s.real_index] = sl;
    out.c1 = r1.c1;
    out.I = r1.I;
    out.D = r1.D;
    return true;
}

} // namespace c2wallet::monero::multisig
