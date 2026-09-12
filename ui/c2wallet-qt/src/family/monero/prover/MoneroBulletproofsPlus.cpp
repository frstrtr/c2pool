// Copyright (c) 2017-2026, The Monero Project  (BSD-3-Clause)
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
// Port of monero-project/monero src/ringct/bulletproofs_plus.cc
// (bulletproof_plus_PROVE + helpers), re-expressed over the in-tree RingCT ops
// and multiexp. See MoneroBulletproofsPlus.hpp for full provenance.

#include "family/monero/prover/MoneroBulletproofsPlus.hpp"

#include <cstddef>
#include <string>

#include "secure/SecureString.hpp"                     // c2w::secure::secure_wipe
#include "xmr_rct_ops.hpp"                             // scalar/point helpers
#include "xmr_multiexp.hpp"                            // multiexp / MultiexpTerm
#include "family/monero/prover/MoneroProverRng.hpp"    // csprng_scalar_nonzero (money-safe prover RNG)

extern "C" {
#include "vendor/crypto-ops.h"                         // sc_*, ge_*
}

namespace xr = c2pool::xmr::native::rct;

namespace c2wallet::monero::prover {

namespace {

using xr::Key;
using xr::KeyV;

constexpr std::size_t LOG_N = 6;
constexpr std::size_t N     = std::size_t{1} << LOG_N;   // 64 bits per range
constexpr std::size_t MAX_M = xr::BULLETPROOF_PLUS_MAX_OUTPUTS;

constexpr char HASH_KEY_EXPONENT[]   = "bulletproof_plus";
constexpr char HASH_KEY_TRANSCRIPT[] = "bulletproof_plus_transcript";

// --- small scalar/point conveniences over the vendored engine ---------------

Key make_two() {                       // the scalar 2
    Key t = xr::scalar_zero();
    t[0]  = 2;
    return t;
}
const Key& two()             { static const Key t = make_two(); return t; }
const Key& minus_inv_eight() {                 // -(8^-1) mod l
    static const Key t = xr::sc_sub_k(xr::scalar_zero(), xr::inv_eight());
    return t;
}

// P = a*G (fixed basepoint), encoded.
Key scalarmult_base_k(const Key& a) {
    ge_p3 p; ge_scalarmult_base(&p, a.data());
    Key out{}; ge_p3_tobytes(out.data(), &p);
    return out;
}

// out = a + b for two encoded points (rct::addKeys). Assumes valid points.
Key point_add_k(const Key& a, const Key& b) {
    ge_p3 a3, b3; ge_cached bc; ge_p1p1 sum; ge_p3 res;
    ge_frombytes_vartime(&a3, a.data());
    ge_frombytes_vartime(&b3, b.data());
    ge_p3_to_cached(&bc, &b3);
    ge_add(&sum, &a3, &bc);
    ge_p1p1_to_p3(&res, &sum);
    Key out{}; ge_p3_tobytes(out.data(), &res);
    return out;
}

// V = a*G + b*B (rct::addKeys2). B given as an encoded point.
Key add_keys2(const Key& a, const Key& b, const Key& B) {
    Key bB{}; xr::scalarmult_key(bB, B, b);    // b*B
    return point_add_k(scalarmult_base_k(a), bB);
}

// --- Fiat-Shamir transcript (bulletproofs_plus.cc transcript_update) ---------
Key transcript_update(Key& transcript, const Key& u0) {
    Key data[2] = {transcript, u0};
    transcript = xr::hash_to_scalar(data, sizeof(data));
    return transcript;
}
Key transcript_update(Key& transcript, const Key& u0, const Key& u1) {
    Key data[3] = {transcript, u0, u1};
    transcript = xr::hash_to_scalar(data, sizeof(data));
    return transcript;
}

// --- the public generator tables + transcript seed (init_exponents) ----------
// 2*64*16 = 2048 generators, derived once. Byte-identical to the verifier's own
// Exponents (same base H, same "bulletproof_plus" domain, same varint index).
std::string varint_data(std::size_t v) {
    std::string out;
    while (v >= 0x80) { out.push_back(static_cast<char>((v & 0x7f) | 0x80)); v >>= 7; }
    out.push_back(static_cast<char>(v));
    return out;
}

struct Exponents {
    ge_p3 Hi[N * MAX_M];
    ge_p3 Gi[N * MAX_M];
    Key   initial_transcript{};

    static void get_exponent(ge_p3& out, const Key& base, std::size_t idx) {
        std::string hashed(reinterpret_cast<const char*>(base.data()), base.size());
        hashed += HASH_KEY_EXPONENT;
        hashed += varint_data(idx);
        xr::hash_to_p3(out, xr::cn_fast_hash(hashed.data(), hashed.size()));
    }

    Exponents() {
        for (std::size_t i = 0; i < N * MAX_M; ++i) {
            get_exponent(Hi[i], xr::generator_H(), i * 2);
            get_exponent(Gi[i], xr::generator_H(), i * 2 + 1);
        }
        const std::string ds(HASH_KEY_TRANSCRIPT);
        ge_p3 p3;
        xr::hash_to_p3(p3, xr::cn_fast_hash(ds.data(), ds.size()));
        initial_transcript = xr::point_encode(p3);
    }
};

const Exponents& exponents() { static const Exponents e; return e; }

// --- scalar-vector helpers (bulletproofs_plus.cc) ----------------------------
KeyV vector_of_scalar_powers(const Key& x, std::size_t n) {
    KeyV res(n);
    res[0] = xr::scalar_one();
    if (n == 1) return res;
    res[1] = x;
    for (std::size_t i = 2; i < n; ++i) sc_mul(res[i].data(), res[i - 1].data(), x.data());
    return res;
}

KeyV vector_subtract_scalar(const KeyV& a, const Key& b) {
    KeyV res(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) sc_sub(res[i].data(), a[i].data(), b.data());
    return res;
}
KeyV vector_add_scalar(const KeyV& a, const Key& b) {
    KeyV res(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) sc_add(res[i].data(), a[i].data(), b.data());
    return res;
}
KeyV vector_add(const KeyV& a, const KeyV& b) {
    KeyV res(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) sc_add(res[i].data(), a[i].data(), b[i].data());
    return res;
}
// x * a[a0 .. a0+len)
KeyV vector_scalar(const KeyV& a, std::size_t a0, std::size_t len, const Key& x) {
    KeyV res(len);
    for (std::size_t i = 0; i < len; ++i) sc_mul(res[i].data(), a[a0 + i].data(), x.data());
    return res;
}

// a_0*b_0*y + a_1*b_1*y^2 + ... over the sliced ranges (weighted_inner_product).
Key weighted_inner_product(const KeyV& a, std::size_t a0,
                           const KeyV& b, std::size_t b0, std::size_t len, const Key& y) {
    Key res = xr::scalar_zero();
    Key y_power = xr::scalar_one();
    Key temp{};
    for (std::size_t i = 0; i < len; ++i) {
        sc_mul(temp.data(), a[a0 + i].data(), b[b0 + i].data());
        sc_mul(y_power.data(), y_power.data(), y.data());
        sc_muladd(res.data(), temp.data(), y_power.data(), res.data());
    }
    return res;
}

// aL8·Gi + aR8·Hi (vector_exponent).
Key vector_exponent(const KeyV& a, const KeyV& b, const Exponents& ex) {
    std::vector<xr::MultiexpTerm> md;
    md.reserve(a.size() * 2);
    for (std::size_t i = 0; i < a.size(); ++i) {
        md.emplace_back(a[i], ex.Gi[i]);
        md.emplace_back(b[i], ex.Hi[i]);
    }
    return xr::multiexp(md);
}

// compute_LR: sum over the sliced ranges of (a*y*8^-1)*G[G0+i] + (b*8^-1)*H[H0+i],
// plus (c*8^-1)*rct::H + (d*8^-1)*rct::G.
Key compute_LR(std::size_t len, const Key& y,
               const std::vector<ge_p3>& G, std::size_t G0,
               const std::vector<ge_p3>& H, std::size_t H0,
               const KeyV& a, std::size_t a0,
               const KeyV& b, std::size_t b0,
               const Key& c, const Key& d) {
    std::vector<xr::MultiexpTerm> md;
    md.resize(len * 2 + 2);
    Key temp{};
    for (std::size_t i = 0; i < len; ++i) {
        sc_mul(temp.data(), a[a0 + i].data(), y.data());
        sc_mul(md[i * 2].scalar.data(), temp.data(), xr::inv_eight().data());
        md[i * 2].point = G[G0 + i];

        sc_mul(md[i * 2 + 1].scalar.data(), b[b0 + i].data(), xr::inv_eight().data());
        md[i * 2 + 1].point = H[H0 + i];
    }
    sc_mul(md[2 * len].scalar.data(), c.data(), xr::inv_eight().data());
    md[2 * len].point = xr::generator_H_p3();
    sc_mul(md[2 * len + 1].scalar.data(), d.data(), xr::inv_eight().data());
    md[2 * len + 1].point = xr::generator_G_p3();
    return xr::multiexp(md);
}

// Fold a point vector: v[n] = a*v[n] + b*v[sz+n] (hadamard_fold).
void hadamard_fold(std::vector<ge_p3>& v, const Key& a, const Key& b) {
    const std::size_t sz = v.size() / 2;
    for (std::size_t n = 0; n < sz; ++n) {
        ge_dsmp c[2];
        ge_dsm_precomp(c[0], &v[n]);
        ge_dsm_precomp(c[1], &v[sz + n]);
        ge_double_scalarmult_precomp_vartime2_p3(&v[n], a.data(), c[0], b.data(), c[1]);
    }
    v.resize(sz);
}

void wipe(Key& k) { c2w::secure::secure_wipe(k.data(), k.size()); }
void wipe(KeyV& v) { for (Key& k : v) wipe(k); }

} // namespace

bool prove_range(const std::vector<std::uint64_t>& amounts,
                 const std::vector<Bytes32>& masks,
                 BulletproofPlus& out) {
    if (amounts.empty() || amounts.size() != masks.size()) return false;
    if (amounts.size() > MAX_M) return false;
    for (const Bytes32& g : masks)
        if (!xr::scalar_is_reduced(g)) return false;

    const Exponents& ex = exponents();

    std::size_t M = 0, logM = 0;
    for (logM = 0; (M = std::size_t{1} << logM) <= MAX_M && M < amounts.size(); ++logM) {}
    if (M > MAX_M) return false;
    const std::size_t logMN = logM + LOG_N;
    const std::size_t MN    = M * N;

    KeyV V(amounts.size());
    KeyV aL(MN, xr::scalar_zero()), aR(MN, xr::scalar_zero());
    KeyV aL8(MN, xr::scalar_zero()), aR8(MN, xr::scalar_zero());
    Key temp{}, temp2{};

    // Output commitments, offset by 8^-1: V[i] = gamma8*G + sv8*H.
    for (std::size_t i = 0; i < amounts.size(); ++i) {
        const Key sv = xr::amount_to_scalar(amounts[i]);
        Key gamma8{}, sv8{};
        sc_mul(gamma8.data(), masks[i].data(), xr::inv_eight().data());
        sc_mul(sv8.data(), sv.data(), xr::inv_eight().data());
        V[i] = add_keys2(gamma8, sv8, xr::generator_H());
    }

    // Bit-decompose each amount (padded to a power of two by M).
    for (std::size_t j = 0; j < M; ++j) {
        for (std::size_t i = N; i-- > 0;) {
            const bool bit = (j < amounts.size()) &&
                             ((amounts[j] >> i) & std::uint64_t{1});
            if (bit) {
                aL[j * N + i]  = xr::scalar_one();
                aL8[j * N + i] = xr::inv_eight();
                aR[j * N + i]  = xr::scalar_zero();
                aR8[j * N + i] = xr::scalar_zero();
            } else {
                aL[j * N + i]  = xr::scalar_zero();
                aL8[j * N + i] = xr::scalar_zero();
                aR[j * N + i]  = xr::minus_one();
                aR8[j * N + i] = minus_inv_eight();
            }
        }
    }

    // The prover retries on the astronomically unlikely event a challenge is 0.
    for (;;) {
        Key transcript = ex.initial_transcript;
        transcript = transcript_update(transcript, xr::hash_to_scalar(V));

        // A = pre_A + (alpha*8^-1)*G, pre_A = aL8·Gi + aR8·Hi.
        Key alpha = csprng_scalar_nonzero();          // MONEY: CSPRNG, not mt19937
        Key pre_A = vector_exponent(aL8, aR8, ex);
        sc_mul(temp.data(), alpha.data(), xr::inv_eight().data());
        Key A = point_add_k(pre_A, scalarmult_base_k(temp));

        Key y = transcript_update(transcript, A);
        if (xr::scalar_is_zero(y)) { wipe(alpha); continue; }
        Key z = transcript = xr::hash_to_scalar(y.data(), y.size());
        if (xr::scalar_is_zero(z)) { wipe(alpha); continue; }
        Key z_squared{}; sc_mul(z_squared.data(), z.data(), z.data());

        // Windowed vector d[j*N+i] = z^(2*(j+1)) * 2^i.
        KeyV d(MN, xr::scalar_zero());
        d[0] = z_squared;
        for (std::size_t i = 1; i < N; ++i) sc_mul(d[i].data(), d[i - 1].data(), two().data());
        for (std::size_t j = 1; j < M; ++j)
            for (std::size_t i = 0; i < N; ++i)
                sc_mul(d[j * N + i].data(), d[(j - 1) * N + i].data(), z_squared.data());

        KeyV y_powers = vector_of_scalar_powers(y, MN + 2);

        // aL1 = aL - z ; aR1 = aR + z + d_y where d_y[i] = d[i]*y^(MN-i).
        KeyV aL1 = vector_subtract_scalar(aL, z);
        KeyV aR1 = vector_add_scalar(aR, z);
        KeyV d_y(MN);
        for (std::size_t i = 0; i < MN; ++i)
            sc_mul(d_y[i].data(), d[i].data(), y_powers[MN - i].data());
        aR1 = vector_add(aR1, d_y);

        // alpha1 = alpha + sum_j z^(2(j+1)) * y^(MN+1) * gamma[j].
        Key alpha1 = alpha;
        temp = xr::scalar_one();
        for (std::size_t j = 0; j < amounts.size(); ++j) {
            sc_mul(temp.data(), temp.data(), z_squared.data());
            sc_mul(temp2.data(), y_powers[MN + 1].data(), temp.data());
            sc_muladd(alpha1.data(), temp2.data(), masks[j].data(), alpha1.data());
        }

        // Inner-product setup.
        std::size_t nprime = MN;
        std::vector<ge_p3> Gprime(MN), Hprime(MN);
        KeyV aprime(MN), bprime(MN);
        const Key yinv = xr::scalar_invert(y);
        KeyV yinvpow(MN);
        yinvpow[0] = xr::scalar_one();
        for (std::size_t i = 0; i < MN; ++i) {
            Gprime[i] = ex.Gi[i];
            Hprime[i] = ex.Hi[i];
            if (i > 0) sc_mul(yinvpow[i].data(), yinvpow[i - 1].data(), yinv.data());
            aprime[i] = aL1[i];
            bprime[i] = aR1[i];
        }
        KeyV L(logMN), R(logMN);
        std::size_t round = 0;
        bool restart = false;

        while (nprime > 1) {
            nprime /= 2;

            Key cL = weighted_inner_product(aprime, 0, bprime, nprime, nprime, y);
            KeyV a_hi = vector_scalar(aprime, nprime, nprime, y_powers[nprime]);
            Key cR = weighted_inner_product(a_hi, 0, bprime, 0, nprime, y);

            Key dL = csprng_scalar_nonzero();          // MONEY: CSPRNG
            Key dR = csprng_scalar_nonzero();          // MONEY: CSPRNG

            L[round] = compute_LR(nprime, yinvpow[nprime], Gprime, nprime, Hprime, 0,
                                  aprime, 0, bprime, nprime, cL, dL);
            R[round] = compute_LR(nprime, y_powers[nprime], Gprime, 0, Hprime, nprime,
                                  aprime, nprime, bprime, 0, cR, dR);

            Key challenge = transcript_update(transcript, L[round], R[round]);
            if (xr::scalar_is_zero(challenge)) {
                wipe(alpha); wipe(alpha1); wipe(dL); wipe(dR); wipe(aprime); wipe(bprime);
                restart = true; break;
            }
            const Key challenge_inv = xr::scalar_invert(challenge);

            sc_mul(temp.data(), yinvpow[nprime].data(), challenge.data());
            hadamard_fold(Gprime, challenge_inv, temp);
            hadamard_fold(Hprime, challenge, challenge_inv);

            sc_mul(temp.data(), challenge_inv.data(), y_powers[nprime].data());
            KeyV a_new = vector_add(vector_scalar(aprime, 0, nprime, challenge),
                                    vector_scalar(aprime, nprime, nprime, temp));
            KeyV b_new = vector_add(vector_scalar(bprime, 0, nprime, challenge_inv),
                                    vector_scalar(bprime, nprime, nprime, challenge));
            wipe(aprime); wipe(bprime);
            aprime = a_new;
            bprime = b_new;

            Key challenge_squared{}, challenge_squared_inv{};
            sc_mul(challenge_squared.data(), challenge.data(), challenge.data());
            sc_mul(challenge_squared_inv.data(), challenge_inv.data(), challenge_inv.data());
            sc_muladd(alpha1.data(), dL.data(), challenge_squared.data(), alpha1.data());
            sc_muladd(alpha1.data(), dR.data(), challenge_squared_inv.data(), alpha1.data());
            wipe(dL); wipe(dR);

            ++round;
        }
        if (restart) { wipe(d_y); wipe(aL1); wipe(aR1); continue; }

        // Final round.
        Key r = csprng_scalar_nonzero();               // MONEY: CSPRNG
        Key s = csprng_scalar_nonzero();               // MONEY: CSPRNG
        Key d_ = csprng_scalar_nonzero();              // MONEY: CSPRNG
        Key eta = csprng_scalar_nonzero();             // MONEY: CSPRNG

        // A1 = 8^-1*( r*Gprime[0] + s*Hprime[0] + d_*G + (r*y*bprime0 + s*y*aprime0)*H )
        std::vector<xr::MultiexpTerm> a1d(4);
        sc_mul(a1d[0].scalar.data(), r.data(), xr::inv_eight().data());
        a1d[0].point = Gprime[0];
        sc_mul(a1d[1].scalar.data(), s.data(), xr::inv_eight().data());
        a1d[1].point = Hprime[0];
        sc_mul(a1d[2].scalar.data(), d_.data(), xr::inv_eight().data());
        a1d[2].point = xr::generator_G_p3();
        sc_mul(temp.data(), r.data(), y.data());
        sc_mul(temp.data(), temp.data(), bprime[0].data());
        sc_mul(temp2.data(), s.data(), y.data());
        sc_mul(temp2.data(), temp2.data(), aprime[0].data());
        sc_add(temp.data(), temp.data(), temp2.data());
        sc_mul(a1d[3].scalar.data(), temp.data(), xr::inv_eight().data());
        a1d[3].point = xr::generator_H_p3();
        Key A1 = xr::multiexp(a1d);

        // B = (eta*8^-1)*G + (r*y*s*8^-1)*H.
        sc_mul(temp.data(), r.data(), y.data());
        sc_mul(temp.data(), temp.data(), s.data());
        sc_mul(temp.data(), temp.data(), xr::inv_eight().data());
        sc_mul(temp2.data(), eta.data(), xr::inv_eight().data());
        Key B = add_keys2(temp2, temp, xr::generator_H());

        Key e = transcript_update(transcript, A1, B);
        if (xr::scalar_is_zero(e)) {
            wipe(alpha); wipe(alpha1); wipe(r); wipe(s); wipe(d_); wipe(eta);
            wipe(aprime); wipe(bprime); wipe(d_y); wipe(aL1); wipe(aR1);
            continue;
        }
        Key e_squared{}; sc_mul(e_squared.data(), e.data(), e.data());

        Key r1{}, s1{}, d1{};
        sc_muladd(r1.data(), aprime[0].data(), e.data(), r.data());
        sc_muladd(s1.data(), bprime[0].data(), e.data(), s.data());
        sc_muladd(d1.data(), d_.data(), e.data(), eta.data());
        sc_muladd(d1.data(), alpha1.data(), e_squared.data(), d1.data());

        out.V  = V;
        out.A  = A;
        out.A1 = A1;
        out.B  = B;
        out.r1 = r1;
        out.s1 = s1;
        out.d1 = d1;
        out.L  = L;
        out.R  = R;

        // Wipe every secret nonce / intermediate from the stack.
        wipe(alpha); wipe(alpha1); wipe(r); wipe(s); wipe(d_); wipe(eta);
        wipe(aprime); wipe(bprime); wipe(d_y); wipe(aL1); wipe(aR1);
        return true;
    }
}

} // namespace c2wallet::monero::prover
