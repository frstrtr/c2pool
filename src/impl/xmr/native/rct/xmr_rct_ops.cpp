// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// Portions derived from monero-project/monero src/ringct/rctOps.cpp and
// src/ringct/rctTypes.h (BSD-3-Clause). See PROVENANCE.md in this directory.
// ---------------------------------------------------------------------------
#include "xmr_rct_ops.hpp"

#include <cstring>
#include <random>

extern "C" {
#include "vendor/hash-ops.h"
}

namespace c2pool::xmr::native::rct {
namespace {

constexpr Key K_IDENTITY = {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
constexpr Key K_ZERO = {{0}};
constexpr Key K_ONE = {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

// 8^-1 mod l  (upstream rctOps.h INV_EIGHT)
constexpr Key K_INV_EIGHT = {{0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61,
                              0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06}};

// -1 mod l  (upstream bulletproofs_plus.cc MINUS_ONE)
constexpr Key K_MINUS_ONE = {{0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                              0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}};

// l = 2^252 + 27742317777372353535851937790883648493  (upstream curveOrder)
constexpr Key K_CURVE_ORDER = {{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                                0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}};

// The two generators are derived once, not hard-coded: G from the vendored
// scalar-base multiplication of 1, H from the vendored ge_p3_H table. Deriving
// them keeps this file free of a constant that could silently disagree with the
// arithmetic underneath it.
struct Generators {
    ge_p3 G_p3{};
    Key   G{};
    Key   H{};

    Generators() {
        ge_scalarmult_base(&G_p3, K_ONE.data());
        ge_p3_tobytes(G.data(), &G_p3);
        ge_p3_tobytes(H.data(), &ge_p3_H);
    }
};

const Generators& gens() {
    static const Generators g;
    return g;
}

// Upstream's `sm` helper: square `y` n times, then multiply by x.
inline Key sm(Key y, int n, const Key& x) noexcept {
    while (n--) sc_mul(y.data(), y.data(), y.data());
    sc_mul(y.data(), y.data(), x.data());
    return y;
}

} // namespace

const Key& identity()      noexcept { return K_IDENTITY; }
const Key& scalar_zero()   noexcept { return K_ZERO; }
const Key& scalar_one()    noexcept { return K_ONE; }
const Key& inv_eight()     noexcept { return K_INV_EIGHT; }
const Key& minus_one()     noexcept { return K_MINUS_ONE; }
const Key& curve_order()   noexcept { return K_CURVE_ORDER; }

const Key&   generator_G()     noexcept { return gens().G; }
const Key&   generator_H()     noexcept { return gens().H; }
const ge_p3& generator_G_p3()  noexcept { return gens().G_p3; }
const ge_p3& generator_H_p3()  noexcept { return ge_p3_H; }

// --- hashing -----------------------------------------------------------------
Key cn_fast_hash(const void* data, std::size_t len) noexcept {
    Key out{};
    ::cn_fast_hash(data, len, reinterpret_cast<char*>(out.data()));
    return out;
}

Key hash_to_scalar(const void* data, std::size_t len) noexcept {
    Key out = cn_fast_hash(data, len);
    sc_reduce32(out.data());
    return out;
}

Key hash_to_scalar(const KeyV& keys) noexcept {
    if (keys.empty()) return hash_to_scalar("", 0);
    // The vector is contiguous 32-byte elements, which is exactly the buffer
    // upstream hashes (`keys.size() * sizeof(keys[0])`).
    return hash_to_scalar(keys.data(), keys.size() * sizeof(Key));
}

void hash_to_p3(ge_p3& out, const Key& k) noexcept {
    const Key h = cn_fast_hash(k.data(), k.size());
    ge_p2 p2;
    ge_fromfe_frombytes_vartime(&p2, h.data());
    ge_p1p1 p1;
    ge_mul8(&p1, &p2);
    ge_p1p1_to_p3(&out, &p1);
}

// --- scalars -----------------------------------------------------------------
bool scalar_is_reduced(const Key& s) noexcept { return sc_check(s.data()) == 0; }

bool scalar_is_zero(const Key& s) noexcept {
    std::uint8_t acc = 0;
    for (std::uint8_t b : s) acc = static_cast<std::uint8_t>(acc | b);
    return acc == 0;
}

Key sc_mul_k(const Key& a, const Key& b) noexcept {
    Key r{};
    sc_mul(r.data(), a.data(), b.data());
    return r;
}
Key sc_add_k(const Key& a, const Key& b) noexcept {
    Key r{};
    sc_add(r.data(), a.data(), b.data());
    return r;
}
Key sc_sub_k(const Key& a, const Key& b) noexcept {
    Key r{};
    sc_sub(r.data(), a.data(), b.data());
    return r;
}
Key sc_muladd_k(const Key& a, const Key& b, const Key& c) noexcept {
    Key r{};
    sc_muladd(r.data(), a.data(), b.data(), c.data());
    return r;
}

// Upstream's addition chain for x^(l-2) mod l. Transcribed unchanged: the
// chain is the algorithm, and re-deriving it would be a gratuitous divergence.
Key scalar_invert(const Key& x) noexcept {
    Key _1{}, _10{}, _100{}, _11{}, _101{}, _111{}, _1001{}, _1011{}, _1111{};

    _1 = x;
    sc_mul(_10.data(), _1.data(), _1.data());
    sc_mul(_100.data(), _10.data(), _10.data());
    sc_mul(_11.data(), _10.data(), _1.data());
    sc_mul(_101.data(), _10.data(), _11.data());
    sc_mul(_111.data(), _10.data(), _101.data());
    sc_mul(_1001.data(), _10.data(), _111.data());
    sc_mul(_1011.data(), _10.data(), _1001.data());
    sc_mul(_1111.data(), _100.data(), _1011.data());

    Key inv{};
    sc_mul(inv.data(), _1111.data(), _1.data());

    inv = sm(inv, 123 + 3, _101);
    inv = sm(inv, 2 + 2, _11);
    inv = sm(inv, 1 + 4, _1111);
    inv = sm(inv, 1 + 4, _1111);
    inv = sm(inv, 4, _1001);
    inv = sm(inv, 2, _11);
    inv = sm(inv, 1 + 4, _1111);
    inv = sm(inv, 1 + 3, _101);
    inv = sm(inv, 3 + 3, _101);
    inv = sm(inv, 3, _111);
    inv = sm(inv, 1 + 4, _1111);
    inv = sm(inv, 2 + 3, _111);
    inv = sm(inv, 2 + 2, _11);
    inv = sm(inv, 1 + 4, _1011);
    inv = sm(inv, 2 + 4, _1011);
    inv = sm(inv, 6 + 4, _1001);
    inv = sm(inv, 2 + 2, _11);
    inv = sm(inv, 3 + 2, _11);
    inv = sm(inv, 3 + 2, _11);
    inv = sm(inv, 1 + 4, _1001);
    inv = sm(inv, 1 + 3, _111);
    inv = sm(inv, 2 + 4, _1111);
    inv = sm(inv, 1 + 4, _1011);
    inv = sm(inv, 3, _101);
    inv = sm(inv, 2 + 4, _1111);
    inv = sm(inv, 3, _101);
    inv = sm(inv, 1 + 2, _11);

    return inv;
}

bool scalar_batch_invert(KeyV& x) noexcept {
    if (x.empty()) return true;

    KeyV scratch;
    scratch.reserve(x.size());

    Key acc = K_IDENTITY;   // upstream seeds with identity(), i.e. the scalar 1
    for (std::size_t n = 0; n < x.size(); ++n) {
        if (scalar_is_zero(x[n])) return false;
        scratch.push_back(acc);
        if (n == 0) acc = x[0];
        else        sc_mul(acc.data(), acc.data(), x[n].data());
    }

    acc = scalar_invert(acc);

    Key tmp{};
    for (std::size_t i = x.size(); i-- > 0;) {
        sc_mul(tmp.data(), acc.data(), x[i].data());
        sc_mul(x[i].data(), acc.data(), scratch[i].data());
        acc = tmp;
    }
    return true;
}

// --- points ------------------------------------------------------------------
bool point_decode(ge_p3& out, const Key& k) noexcept {
    return ge_frombytes_vartime(&out, k.data()) == 0;
}

Key point_encode(const ge_p3& p) noexcept {
    Key out{};
    ge_p3_tobytes(out.data(), &p);
    return out;
}

bool scalarmult8(ge_p3& out, const Key& P) noexcept {
    ge_p3 p3;
    if (!point_decode(p3, P)) return false;
    ge_p2 p2;
    ge_p3_to_p2(&p2, &p3);
    ge_p1p1 p1;
    ge_mul8(&p1, &p2);
    ge_p1p1_to_p3(&out, &p1);
    return true;
}

Key scalarmult_H(const Key& a) noexcept {
    ge_p2 R;
    ge_scalarmult(&R, a.data(), &ge_p3_H);
    Key out{};
    ge_tobytes(out.data(), &R);
    return out;
}

bool scalarmult_key(Key& out, const Key& P, const Key& a) noexcept {
    ge_p3 p3;
    if (!point_decode(p3, P)) return false;
    ge_p2 R;
    ge_scalarmult(&R, a.data(), &p3);
    ge_tobytes(out.data(), &R);
    return true;
}

bool add_keys(const KeyV& points, Key& out) noexcept {
    if (points.empty()) { out = K_IDENTITY; return true; }

    ge_p3 acc;
    if (!point_decode(acc, points[0])) return false;
    for (std::size_t i = 1; i < points.size(); ++i) {
        ge_p3 tmp;
        if (!point_decode(tmp, points[i])) return false;
        ge_cached c;
        ge_p3_to_cached(&c, &tmp);
        ge_p1p1 sum;
        ge_add(&sum, &acc, &c);
        ge_p1p1_to_p3(&acc, &sum);
    }
    out = point_encode(acc);
    return true;
}

bool in_main_subgroup(const Key& P) noexcept {
    ge_p3 p3;
    if (!point_decode(p3, P)) return false;
    ge_p2 R;
    ge_scalarmult(&R, K_CURVE_ORDER.data(), &p3);
    Key tmp{};
    ge_tobytes(tmp.data(), &R);
    return tmp == K_IDENTITY;
}

// --- amounts -----------------------------------------------------------------
Key amount_to_scalar(std::uint64_t amount) noexcept {
    Key out{};
    for (std::size_t i = 0; i < 8; ++i)
        out[i] = static_cast<std::uint8_t>((amount >> (8 * i)) & 0xff);
    return out;
}

// --- randomness --------------------------------------------------------------
Key random_scalar_nonzero() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    Key k{};
    for (;;) {
        for (std::size_t i = 0; i < 32; i += 8) {
            const std::uint64_t v = rng();
            for (std::size_t j = 0; j < 8; ++j)
                k[i + j] = static_cast<std::uint8_t>((v >> (8 * j)) & 0xff);
        }
        sc_reduce32(k.data());
        if (!scalar_is_zero(k)) return k;
    }
}

} // namespace c2pool::xmr::native::rct
