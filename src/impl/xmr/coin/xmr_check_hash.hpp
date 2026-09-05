// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/coin/xmr_check_hash.hpp  --  Monero 128-bit difficulty test
//
// AUTHORED for c2pool (not ported). A boost-FREE, header-only reimplementation
// of monero-project's difficulty check so the XMR-lane receipt verifier can run
// the R-1 target test without pulling boost::multiprecision + crypto/hash.h.
//
// Rule (scoping S6 / S8-item-6): a PoW hash passes difficulty d iff
//     hashVal * d  <=  2^256 - 1
// where hashVal is the 32-byte RandomX output read as a 256-bit LITTLE-ENDIAN
// integer (four u64 limbs, limb 0 = least significant). Equivalent statement:
// the 320/384-bit product has all bits >= 256 clear.
//
// This MUST stay byte-equivalent to monero-project
//   src/cryptonote_basic/difficulty.cpp @ 3d3920d7
// (check_hash_64 / check_hash_128 / check_hash). The vendored difficulty.cpp is
// kept alongside as the reference oracle; an X0/X1 KAT cross-checks the two on
// the RandomX test vectors + recent mainnet blocks before consensus trust.
//
// v37 note: Monero network difficulty is a 128-bit type, but p2pool-class share
// targets (1e5..1e9) and current network difficulty (~1e11..1e12) fit u64, so
// the u64 path is the hot path. `work(T)` (w_raw) is defined by the LANE layer,
// not here; this file only answers "does this hash meet this difficulty".
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <cstring>

#include "xmr_crypto_types.hpp"

namespace xmr::coin {

namespace detail {

// (low,high) = a*b, 64x64->128.
inline void mul64(std::uint64_t a, std::uint64_t b,
                  std::uint64_t& low, std::uint64_t& high) {
#if defined(__SIZEOF_INT128__)
    unsigned __int128 r = static_cast<unsigned __int128>(a) * b;
    low  = static_cast<std::uint64_t>(r);
    high = static_cast<std::uint64_t>(r >> 64);
#else
    // Portable schoolbook (latexi95), identical to difficulty.cpp's fallback.
    std::uint64_t aL = a & 0xFFFFFFFF, aH = a >> 32;
    std::uint64_t bL = b & 0xFFFFFFFF, bH = b >> 32;
    std::uint64_t t = aL * bL;
    std::uint64_t l0 = t & 0xFFFFFFFF, c = t >> 32;
    t = aH * bL + c;      std::uint64_t hH1 = t >> 32, hL1 = t & 0xFFFFFFFF;
    t = aL * bH;          std::uint64_t l2 = t & 0xFFFFFFFF; c = t >> 32;
    t = aH * bH + c;      std::uint64_t hH2 = t >> 32, hL2 = t & 0xFFFFFFFF;
    std::uint64_t r = hL1 + l2; c = r >> 32;
    low = (r << 32) | l0;
    r = hH1 + hL2 + c; std::uint64_t d3 = r & 0xFFFFFFFF; c = r >> 32;
    r = hH2 + c;
    high = d3 | (r << 32);
#endif
}

inline bool cadd(std::uint64_t a, std::uint64_t b) { return a + b < a; }
inline bool cadc(std::uint64_t a, std::uint64_t b, bool c) {
    return a + b < a || (c && a + b == static_cast<std::uint64_t>(-1));
}

// hash as four little-endian u64 limbs (limb 0 = LSB).
inline std::uint64_t limb(const unsigned char* h, int i) {
    std::uint64_t w;
    std::memcpy(&w, h + i * 8, 8);
    // Source encoding is little-endian; on a big-endian host this must byteswap.
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    w = __builtin_bswap64(w);
#endif
    return w;
}

} // namespace detail

// 64-bit-difficulty path. Verbatim algorithm of difficulty.cpp check_hash_64.
inline bool check_hash(const unsigned char (&hash)[32], std::uint64_t difficulty) {
    using detail::mul64; using detail::cadd; using detail::cadc; using detail::limb;
    const unsigned char* h = hash;
    std::uint64_t low, high, top, cur;
    mul64(limb(h, 3), difficulty, top, high);   // highest word first: usually fails
    if (high != 0) return false;
    mul64(limb(h, 0), difficulty, low, cur);
    mul64(limb(h, 1), difficulty, low, high);
    bool carry = cadd(cur, low);
    cur = high;
    mul64(limb(h, 2), difficulty, low, high);
    carry = cadc(cur, low, carry);
    carry = cadc(high, top, carry);
    return !carry;
}

// 128-bit-difficulty path (difficulty = dhi:dlo). Requires the full 4x2-limb
// product to have both limbs above bit 255 clear, i.e. product <= 2^256 - 1.
inline bool check_hash(const unsigned char (&hash)[32],
                       std::uint64_t dlo, std::uint64_t dhi) {
    if (dhi == 0) return check_hash(hash, dlo);
    using detail::mul64; using detail::limb;
    const unsigned char* h = hash;
    std::uint64_t H[4] = { limb(h, 0), limb(h, 1), limb(h, 2), limb(h, 3) };
    std::uint64_t D[2] = { dlo, dhi };
    // product p[0..5], schoolbook with carry.
    std::uint64_t p[6] = {0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        std::uint64_t carry = 0;
        for (int j = 0; j < 2; ++j) {
            std::uint64_t lo, hi;
            mul64(H[i], D[j], lo, hi);
            // p[i+j] += lo + carry ; propagate to hi
            std::uint64_t s = p[i + j] + lo;
            std::uint64_t c1 = s < p[i + j] ? 1 : 0;
            std::uint64_t s2 = s + carry;
            std::uint64_t c2 = s2 < s ? 1 : 0;
            p[i + j] = s2;
            carry = hi + c1 + c2;
        }
        p[i + 2] += carry; // no further overflow: p[i+2] was 0 before this i
    }
    // <= 2^256 - 1  iff  limbs 4 and 5 are both zero.
    return p[4] == 0 && p[5] == 0;
}

// Convenience overloads on the lane hash type.
inline bool check_hash(const Hash256& hash, std::uint64_t difficulty) {
    return check_hash(*reinterpret_cast<const unsigned char(*)[32]>(hash.data()), difficulty);
}
inline bool check_hash(const Hash256& hash, std::uint64_t dlo, std::uint64_t dhi) {
    return check_hash(*reinterpret_cast<const unsigned char(*)[32]>(hash.data()), dlo, dhi);
}

} // namespace xmr::coin
