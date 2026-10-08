// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// Derived from monero-project/monero src/ringct/bulletproofs_plus.cc
// (BSD-3-Clause) -- the VERIFIER only. See PROVENANCE.md in this directory.
// ---------------------------------------------------------------------------
#include "xmr_bulletproofs_plus.hpp"

#include <algorithm>
#include <string>

#include "xmr_multiexp.hpp"

namespace c2pool::xmr::native::rct {
namespace {

constexpr std::size_t LOG_N = 6;
constexpr std::size_t N     = std::size_t{1} << LOG_N;   // 64 bits per range
constexpr std::size_t MAX_M = BULLETPROOF_PLUS_MAX_OUTPUTS;

// Domain separators, upstream cryptonote_config.h.
constexpr char HASH_KEY_EXPONENT[]   = "bulletproof_plus";
constexpr char HASH_KEY_TRANSCRIPT[] = "bulletproof_plus_transcript";

// CryptoNote LEB128, as tools::get_varint_data writes it for the generator
// index.
std::string varint_data(std::size_t v) {
    std::string out;
    while (v >= 0x80) {
        out.push_back(static_cast<char>((v & 0x7f) | 0x80));
        v >>= 7;
    }
    out.push_back(static_cast<char>(v));
    return out;
}

// The public generators. Deriving one costs a Keccak and a hash-to-point; there
// are 2 * 64 * 16 = 2048 of them, so they are derived once for the process.
struct Exponents {
    ge_p3 Hi[N * MAX_M];
    ge_p3 Gi[N * MAX_M];
    Key   two_pow_64_minus_one{};
    Key   initial_transcript{};

    Exponents() {
        for (std::size_t i = 0; i < N * MAX_M; ++i) {
            get_exponent(Hi[i], generator_H(), i * 2);
            get_exponent(Gi[i], generator_H(), i * 2 + 1);
        }

        // 2**64 - 1, by squaring 2 six times and subtracting one.
        Key t = scalar_zero();
        t[0]  = 2;
        for (std::size_t i = 0; i < 6; ++i) sc_mul(t.data(), t.data(), t.data());
        sc_sub(t.data(), t.data(), scalar_one().data());
        two_pow_64_minus_one = t;

        // The Fiat-Shamir transcript starts from a constant point, so every
        // proof's challenge chain is rooted in the same domain separator.
        const std::string ds(HASH_KEY_TRANSCRIPT);
        ge_p3 p3;
        hash_to_p3(p3, cn_fast_hash(ds.data(), ds.size()));
        initial_transcript = point_encode(p3);
    }

    static void get_exponent(ge_p3& out, const Key& base, std::size_t idx) {
        std::string hashed(reinterpret_cast<const char*>(base.data()), base.size());
        hashed += HASH_KEY_EXPONENT;
        hashed += varint_data(idx);
        hash_to_p3(out, cn_fast_hash(hashed.data(), hashed.size()));
    }
};

const Exponents& exponents() {
    static const Exponents e;
    return e;
}

// --- transcript --------------------------------------------------------------
Key transcript_update(Key& transcript, const Key& update_0) {
    Key data[2] = {transcript, update_0};
    transcript = hash_to_scalar(data, sizeof(data));
    return transcript;
}

Key transcript_update(Key& transcript, const Key& update_0, const Key& update_1) {
    Key data[3] = {transcript, update_0, update_1};
    transcript = hash_to_scalar(data, sizeof(data));
    return transcript;
}

// --- scalar power sums -------------------------------------------------------
// x**2 + x**4 + ... + x**n, for n a power of two.
Key sum_of_even_powers(const Key& x, std::size_t n) {
    Key x1 = x;
    sc_mul(x1.data(), x1.data(), x1.data());

    Key res = x1;
    while (n > 2) {
        sc_muladd(res.data(), x1.data(), res.data(), res.data());
        sc_mul(x1.data(), x1.data(), x1.data());
        n /= 2;
    }
    return res;
}

// x**1 + x**2 + ... + x**n.
Key sum_of_scalar_powers(const Key& x, std::size_t n) {
    Key res = scalar_one();
    if (n == 1) return x;

    n += 1;
    Key x1 = x;

    const bool is_power_of_2 = (n & (n - 1)) == 0;
    if (is_power_of_2) {
        sc_add(res.data(), res.data(), x1.data());
        while (n > 2) {
            sc_mul(x1.data(), x1.data(), x1.data());
            sc_muladd(res.data(), x1.data(), res.data(), res.data());
            n /= 2;
        }
    } else {
        Key prev = x1;
        for (std::size_t i = 1; i < n; ++i) {
            if (i > 1) sc_mul(prev.data(), prev.data(), x1.data());
            sc_add(res.data(), res.data(), prev.data());
        }
    }
    sc_sub(res.data(), res.data(), scalar_one().data());
    return res;
}

struct ProofData {
    Key         y{}, z{}, e{};
    KeyV        challenges;
    std::size_t logM       = 0;
    std::size_t inv_offset = 0;
};

} // namespace

std::size_t bulletproof_plus_max_amounts(const BulletproofPlus& proof) noexcept {
    if (proof.L.size() < LOG_N) return 0;
    const std::size_t shift = proof.L.size() - LOG_N;
    if (shift >= 32) return 0;
    return std::size_t{1} << shift;
}

bool verify_bulletproofs_plus(const std::vector<const BulletproofPlus*>& proofs) {
    if (proofs.empty()) return true;

    const Exponents& ex = exponents();

    std::size_t max_length = 0;   // longest inner-product vector in the batch
    std::size_t nV         = 0;   // commitments across all proofs
    std::size_t inv_offset = 0;
    std::size_t max_logM   = 0;

    std::vector<ProofData> proof_data;
    proof_data.reserve(proofs.size());

    // One batch inversion for the whole call: a scalar inversion is expensive
    // and Montgomery's trick turns n of them into one plus 3n multiplications.
    KeyV to_invert;
    to_invert.reserve(11 * proofs.size());

    for (const BulletproofPlus* p : proofs) {
        const BulletproofPlus& proof = *p;

        if (!scalar_is_reduced(proof.r1)) return false;
        if (!scalar_is_reduced(proof.s1)) return false;
        if (!scalar_is_reduced(proof.d1)) return false;

        if (proof.V.empty())        return false;
        if (proof.V.size() > MAX_M) return false;
        if (proof.L.size() != proof.R.size()) return false;
        if (proof.L.empty())        return false;

        max_length = std::max(max_length, proof.L.size());
        nV += proof.V.size();

        proof_data.emplace_back();
        ProofData& pd = proof_data.back();

        // Reconstruct the challenges from the transcript.
        Key transcript = ex.initial_transcript;
        transcript     = transcript_update(transcript, hash_to_scalar(proof.V));
        pd.y           = transcript_update(transcript, proof.A);
        if (scalar_is_zero(pd.y)) return false;
        pd.z = transcript = hash_to_scalar(pd.y.data(), pd.y.size());
        if (scalar_is_zero(pd.z)) return false;

        // The number of inner-product rounds follows from the proof's size.
        std::size_t M = 0;
        for (pd.logM = 0; (M = std::size_t{1} << pd.logM) <= MAX_M && M < proof.V.size();
             ++pd.logM) {
        }
        if (proof.L.size() != LOG_N + pd.logM) return false;
        max_logM = std::max(pd.logM, max_logM);

        const std::size_t rounds = pd.logM + LOG_N;
        if (rounds == 0) return false;

        pd.challenges.resize(rounds);
        for (std::size_t j = 0; j < rounds; ++j) {
            pd.challenges[j] = transcript_update(transcript, proof.L[j], proof.R[j]);
            if (scalar_is_zero(pd.challenges[j])) return false;
        }

        pd.e = transcript_update(transcript, proof.A1, proof.B);
        if (scalar_is_zero(pd.e)) return false;

        pd.inv_offset = inv_offset;
        for (std::size_t j = 0; j < rounds; ++j) to_invert.push_back(pd.challenges[j]);
        to_invert.push_back(pd.y);
        inv_offset += rounds + 1;
    }

    if (max_length >= 32) return false;
    const std::size_t maxMN = std::size_t{1} << max_length;
    if (maxMN > N * MAX_M) return false;   // no generator for a longer proof

    Key temp{}, temp2{};

    std::vector<MultiexpTerm> multiexp_data;
    multiexp_data.reserve(nV + (2 * (max_logM + LOG_N) + 3) * proofs.size() + 2 * maxMN);
    multiexp_data.resize(2 * maxMN);

    KeyV inverses = to_invert;
    if (!scalar_batch_invert(inverses)) return false;
    to_invert.clear();

    // Each proof's own multi-scalar check is folded into ONE batch check with a
    // random weight, and the group elements common to every proof (G, H and the
    // Gi/Hi generators) appear once with their weighted scalar sums.
    Key  G_scalar = scalar_zero();
    Key  H_scalar = scalar_zero();
    KeyV Gi_scalars(maxMN, scalar_zero());
    KeyV Hi_scalars(maxMN, scalar_zero());

    std::size_t proof_data_index = 0;
    KeyV challenges_cache;
    std::vector<ge_p3> proof8_V, proof8_L, proof8_R;

    for (const BulletproofPlus* p : proofs) {
        const BulletproofPlus& proof = *p;
        const ProofData&       pd    = proof_data[proof_data_index++];

        if (proof.L.size() != LOG_N + pd.logM) return false;
        const std::size_t M  = std::size_t{1} << pd.logM;
        const std::size_t MN = M * N;

        const Key weight = random_scalar_nonzero();

        // Rescale the offset proof elements by the cofactor, which is what puts
        // every one of them in the prime-order subgroup. A proof element that
        // is not a point at all fails here rather than deep in the arithmetic.
        proof8_V.resize(proof.V.size());
        for (std::size_t i = 0; i < proof.V.size(); ++i)
            if (!scalarmult8(proof8_V[i], proof.V[i])) return false;
        proof8_L.resize(proof.L.size());
        for (std::size_t i = 0; i < proof.L.size(); ++i)
            if (!scalarmult8(proof8_L[i], proof.L[i])) return false;
        proof8_R.resize(proof.R.size());
        for (std::size_t i = 0; i < proof.R.size(); ++i)
            if (!scalarmult8(proof8_R[i], proof.R[i])) return false;
        ge_p3 proof8_A1, proof8_B, proof8_A;
        if (!scalarmult8(proof8_A1, proof.A1)) return false;
        if (!scalarmult8(proof8_B, proof.B)) return false;
        if (!scalarmult8(proof8_A, proof.A)) return false;

        // y**MN and y**(MN+1)
        Key y_MN = pd.y;
        Key y_MN_1{};
        {
            std::size_t temp_MN = MN;
            while (temp_MN > 1) {
                sc_mul(y_MN.data(), y_MN.data(), y_MN.data());
                temp_MN /= 2;
            }
        }
        sc_mul(y_MN_1.data(), y_MN.data(), pd.y.data());

        // V_j: -e**2 * z**(2*j+1) * y**(MN+1) * weight
        Key e_squared{};
        sc_mul(e_squared.data(), pd.e.data(), pd.e.data());
        Key z_squared{};
        sc_mul(z_squared.data(), pd.z.data(), pd.z.data());

        sc_sub(temp.data(), scalar_zero().data(), e_squared.data());
        sc_mul(temp.data(), temp.data(), y_MN_1.data());
        sc_mul(temp.data(), temp.data(), weight.data());
        for (std::size_t j = 0; j < proof8_V.size(); ++j) {
            sc_mul(temp.data(), temp.data(), z_squared.data());
            multiexp_data.emplace_back(temp, proof8_V[j]);
        }

        // B: -weight
        sc_mul(temp.data(), minus_one().data(), weight.data());
        multiexp_data.emplace_back(temp, proof8_B);

        // A1: -weight*e
        sc_mul(temp.data(), temp.data(), pd.e.data());
        multiexp_data.emplace_back(temp, proof8_A1);

        // A: -weight*e*e
        Key minus_weight_e_squared{};
        sc_mul(minus_weight_e_squared.data(), temp.data(), pd.e.data());
        multiexp_data.emplace_back(minus_weight_e_squared, proof8_A);

        // G: weight*d1
        sc_muladd(G_scalar.data(), weight.data(), proof.d1.data(), G_scalar.data());

        // The windowed vector d[j*N+i] = z**(2*(j+1)) * 2**i
        KeyV d(MN, scalar_zero());
        d[0] = z_squared;
        for (std::size_t i = 1; i < N; ++i) sc_add(d[i].data(), d[i - 1].data(), d[i - 1].data());
        for (std::size_t j = 1; j < M; ++j)
            for (std::size_t i = 0; i < N; ++i)
                sc_mul(d[j * N + i].data(), d[(j - 1) * N + i].data(), z_squared.data());

        Key sum_d{};
        sc_mul(sum_d.data(), ex.two_pow_64_minus_one.data(),
               sum_of_even_powers(pd.z, 2 * M).data());

        // H: weight*( r1*y*s1 + e**2*( y**(MN+1)*z*sum(d) + (z**2-z)*sum(y) ) )
        const Key sum_y = sum_of_scalar_powers(pd.y, MN);
        sc_sub(temp.data(), z_squared.data(), pd.z.data());
        sc_mul(temp.data(), temp.data(), sum_y.data());
        sc_mul(temp2.data(), y_MN_1.data(), pd.z.data());
        sc_mul(temp2.data(), temp2.data(), sum_d.data());
        sc_add(temp.data(), temp.data(), temp2.data());
        sc_mul(temp.data(), temp.data(), e_squared.data());
        sc_mul(temp2.data(), proof.r1.data(), pd.y.data());
        sc_mul(temp2.data(), temp2.data(), proof.s1.data());
        sc_add(temp.data(), temp.data(), temp2.data());
        sc_muladd(H_scalar.data(), temp.data(), weight.data(), H_scalar.data());

        const std::size_t rounds = pd.logM + LOG_N;
        if (rounds == 0) return false;

        const Key* challenges_inv = &inverses[pd.inv_offset];
        const Key  yinv           = inverses[pd.inv_offset + rounds];

        // Products of the inner-product challenges, indexed by the binary
        // decomposition of the generator index.
        challenges_cache.resize(std::size_t{1} << rounds);
        challenges_cache[0] = challenges_inv[0];
        challenges_cache[1] = pd.challenges[0];
        for (std::size_t j = 1; j < rounds; ++j) {
            const std::size_t slots = std::size_t{1} << (j + 1);
            for (std::size_t s = slots; s-- > 0; --s) {
                sc_mul(challenges_cache[s].data(), challenges_cache[s / 2].data(),
                       pd.challenges[j].data());
                sc_mul(challenges_cache[s - 1].data(), challenges_cache[s / 2].data(),
                       challenges_inv[j].data());
            }
        }

        // Gi and Hi
        Key e_r1_w_y{};
        sc_mul(e_r1_w_y.data(), pd.e.data(), proof.r1.data());
        sc_mul(e_r1_w_y.data(), e_r1_w_y.data(), weight.data());
        Key e_s1_w{};
        sc_mul(e_s1_w.data(), pd.e.data(), proof.s1.data());
        sc_mul(e_s1_w.data(), e_s1_w.data(), weight.data());
        Key e_squared_z_w{};
        sc_mul(e_squared_z_w.data(), e_squared.data(), pd.z.data());
        sc_mul(e_squared_z_w.data(), e_squared_z_w.data(), weight.data());
        Key minus_e_squared_z_w{};
        sc_sub(minus_e_squared_z_w.data(), scalar_zero().data(), e_squared_z_w.data());
        Key minus_e_squared_w_y{};
        sc_sub(minus_e_squared_w_y.data(), scalar_zero().data(), e_squared.data());
        sc_mul(minus_e_squared_w_y.data(), minus_e_squared_w_y.data(), weight.data());
        sc_mul(minus_e_squared_w_y.data(), minus_e_squared_w_y.data(), y_MN.data());

        for (std::size_t i = 0; i < MN; ++i) {
            Key g_scalar = e_r1_w_y;
            Key h_scalar{};

            sc_muladd(g_scalar.data(), g_scalar.data(), challenges_cache[i].data(),
                      e_squared_z_w.data());
            sc_muladd(h_scalar.data(), e_s1_w.data(),
                      challenges_cache[(~i) & (MN - 1)].data(),
                      minus_e_squared_z_w.data());

            sc_add(Gi_scalars[i].data(), Gi_scalars[i].data(), g_scalar.data());
            sc_muladd(h_scalar.data(), minus_e_squared_w_y.data(), d[i].data(),
                      h_scalar.data());
            sc_add(Hi_scalars[i].data(), Hi_scalars[i].data(), h_scalar.data());

            sc_mul(e_r1_w_y.data(), e_r1_w_y.data(), yinv.data());
            sc_mul(minus_e_squared_w_y.data(), minus_e_squared_w_y.data(), yinv.data());
        }

        // L_j: -weight*e*e*challenges[j]**2 ; R_j the same with the inverse
        for (std::size_t j = 0; j < rounds; ++j) {
            sc_mul(temp.data(), pd.challenges[j].data(), pd.challenges[j].data());
            sc_mul(temp.data(), temp.data(), minus_weight_e_squared.data());
            multiexp_data.emplace_back(temp, proof8_L[j]);

            sc_mul(temp.data(), challenges_inv[j].data(), challenges_inv[j].data());
            sc_mul(temp.data(), temp.data(), minus_weight_e_squared.data());
            multiexp_data.emplace_back(temp, proof8_R[j]);
        }
    }

    multiexp_data.emplace_back(G_scalar, generator_G_p3());
    multiexp_data.emplace_back(H_scalar, generator_H_p3());
    for (std::size_t i = 0; i < maxMN; ++i) {
        multiexp_data[i * 2]     = MultiexpTerm(Gi_scalars[i], ex.Gi[i]);
        multiexp_data[i * 2 + 1] = MultiexpTerm(Hi_scalars[i], ex.Hi[i]);
    }

    return multiexp(multiexp_data) == identity();
}

bool verify_bulletproof_plus(const BulletproofPlus& proof) {
    return verify_bulletproofs_plus(std::vector<const BulletproofPlus*>{&proof});
}

} // namespace c2pool::xmr::native::rct
