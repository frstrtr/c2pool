// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_wide.hpp
// Path B, slice S3: the wide-integer paths of the payout window (D2.13; C30,
// C35). Weights / raw bin sums / the window total W are ::v37::U256 (< 2^84 in
// practice, asserted < 2^255); the products the split and the W_max / merge-back
// tests form reach 320 bits, so a 5-limb U320 holds them EXACTLY (no clamping
// on a money path; the products are exact and never wrap).
//
//   split      : q_i = floor(R x w_i / W), R u64, w_i / W U256 -> R x w_i in
//                U320, quotient <= R (fits u64), remainder < W (fits U256).
//   W_max      : (W + w_b) x f_spend  <=  B x min(d_min, d_min(b)), both U320.
//   merge-back : w_X x B  <  W x f_spend, both U320.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "sharechain/v37/v37_fixed.hpp"  // ::v37::U256 (4 x u64 limbs, little-endian)

#include "pathb_params.hpp"

namespace c2pool::xmr::pathb {

// The weight / sum type of the window (D2.13): U256, little-endian 4 x u64.
using Work = ::v37::U256;

namespace wide {

using u128 = unsigned __int128;

// 320-bit unsigned, 5 x u64 limbs, little-endian. Exact for every product the
// window forms: U256 (< 2^256) x u64 (< 2^64) < 2^320.
struct U320 {
    std::array<std::uint64_t, 5> v{0, 0, 0, 0, 0};

    bool is_zero() const noexcept { return !(v[0] | v[1] | v[2] | v[3] | v[4]); }

    U320& operator+=(const U320& o) noexcept {
        u128 c = 0;
        for (int i = 0; i < 5; ++i) {
            const u128 s = static_cast<u128>(v[i]) + o.v[i] + c;
            v[i] = static_cast<std::uint64_t>(s);
            c = s >> 64;
        }
        return *this;  // callers keep every term < 2^320 (asserted by the width law)
    }
    friend U320 operator+(U320 a, const U320& b) noexcept { a += b; return a; }
    friend bool operator==(const U320& a, const U320& b) noexcept { return a.v == b.v; }
    friend bool operator<(const U320& a, const U320& b) noexcept {
        for (int i = 4; i >= 0; --i)
            if (a.v[i] != b.v[i]) return a.v[i] < b.v[i];
        return false;
    }
    friend bool operator<=(const U320& a, const U320& b) noexcept { return !(b < a); }
};

// a x m, exact (U256 x u64 -> U320). The product always fits; never wraps.
inline U320 mul_u256_u64(const Work& a, std::uint64_t m) noexcept {
    U320 out;
    u128 carry = 0;
    for (int i = 0; i < 4; ++i) {
        const u128 p = static_cast<u128>(a.v[i]) * m + carry;
        out.v[i] = static_cast<std::uint64_t>(p);
        carry = p >> 64;
    }
    out.v[4] = static_cast<std::uint64_t>(carry);
    return out;
}

// a x b, exact (u64 x u64 -> U320, top three limbs zero). For the W_max / merge-
// back right-hand sides (B x d, W-side products reuse mul_u256_u64).
inline U320 mul_u64_u64(std::uint64_t a, std::uint64_t b) noexcept {
    const u128 p = static_cast<u128>(a) * b;
    U320 out;
    out.v[0] = static_cast<std::uint64_t>(p);
    out.v[1] = static_cast<std::uint64_t>(p >> 64);
    return out;
}

// floor(num / den) returned as u64, with the remainder (< den, so a Work), for
// the exact split. Precondition (asserted by the caller's width law): the true
// quotient fits u64 (num = R x w_i, w_i <= W = den, so quotient <= R <= 2^64-1).
// Schoolbook binary long division; the running remainder stays < den < 2^256 and
// is carried in a 6th limb head so (rem << 1) never loses a bit. den != 0.
inline std::uint64_t divmod_u320_u256(const U320& num, const Work& den, Work& rem_out) noexcept {
    // remainder held as 5 limbs (< 2^256, but (rem<<1) can touch bit 256).
    std::array<std::uint64_t, 5> rem{0, 0, 0, 0, 0};
    std::array<std::uint64_t, 5> d{den.v[0], den.v[1], den.v[2], den.v[3], 0};
    std::uint64_t q = 0;
    bool hi = false;  // set iff a quotient bit at index >= 64 is 1 (a width-law bug)
    auto rem_ge_d = [&]() noexcept {
        for (int i = 4; i >= 0; --i)
            if (rem[i] != d[i]) return rem[i] > d[i];
        return true;  // equal
    };
    auto rem_sub_d = [&]() noexcept {
        u128 borrow = 0;
        for (int i = 0; i < 5; ++i) {
            const u128 x = static_cast<u128>(rem[i]) - d[i] - borrow;
            rem[i] = static_cast<std::uint64_t>(x);
            borrow = (x >> 64) ? 1 : 0;
        }
    };
    for (int i = 319; i >= 0; --i) {
        // rem <<= 1 across the five limbs.
        for (int k = 4; k >= 1; --k) rem[k] = (rem[k] << 1) | (rem[k - 1] >> 63);
        rem[0] = (rem[0] << 1) | ((num.v[i >> 6] >> (i & 63)) & 1u);
        if (rem_ge_d()) {
            rem_sub_d();
            if (i < 64) q |= (std::uint64_t{1} << i);
            else hi = true;
        }
    }
    Work r;
    r.v[0] = rem[0]; r.v[1] = rem[1]; r.v[2] = rem[2]; r.v[3] = rem[3];
    rem_out = r;
    return hi ? ~std::uint64_t{0} : q;  // hi can only fire on a width-law violation
}

}  // namespace wide

// ---------------------------------------------------------------------------
// Work <-> bytes / u64 helpers (LE256 as encode_ratchet_state's limb order).
// ---------------------------------------------------------------------------
inline Work work_from_u64(std::uint64_t x) noexcept { return Work(x); }

// floor(x * bp / 10000) in u128 -> u64 (x u64, bp <= 10000); the owner / author
// share of a receipt's raw work. x * bp can exceed u64, so the multiply is u128.
inline std::uint64_t share_floor(std::uint64_t x, std::uint64_t bp) noexcept {
    return static_cast<std::uint64_t>((static_cast<wide::u128>(x) * bp) / kBasisPointsScale);
}

// 32-byte little-endian encoding of a Work (U256), limbs low-first (== the
// side_data / ratchet-state convention and the golden vectors' LE256(w)).
inline std::array<std::uint8_t, 32> le256(const Work& w) noexcept {
    std::array<std::uint8_t, 32> out{};
    std::size_t o = 0;
    for (std::uint64_t limb : w.v)
        for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i)
            out[o++] = static_cast<std::uint8_t>(limb >> (8 * i));
    return out;
}

}  // namespace c2pool::xmr::pathb
