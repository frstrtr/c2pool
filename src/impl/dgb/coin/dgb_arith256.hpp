// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// DGB DigiShield retarget arithmetic at TRUE 256-bit width  (M3 §7b).
//
// The DigiShield/MultiShield damped multiply in coin/header_chain.hpp pins
// DigiByte Core CalculateNextWorkRequired:
//
//     bnNew  = avg_target          (arith_uint256)
//     bnNew *= damped_timespan      <-- 256-bit multiply, OVERFLOW TRUNCATES
//     bnNew /= nominal_timespan
//
// Earlier §7b slices used an unsigned __int128 proxy: correct ONLY while the
// expanded target fits 64 bits. A real DigiByte Scrypt target is a full
// arith_uint256 (pow_limit ~2^224); near it, avg_target * damped exceeds
// 2^256 and arith_uint256 DROPS the overflow limb. That truncation is
// CONSENSUS behaviour — a wider (overflow-safe) intermediate would compute a
// DIFFERENT next target and diverge from DigiByte Core / p2pool-merged-v36.
//
// This header is the minimal 256-bit unsigned that reproduces that exact
// truncation, isolated + separately guarded like dgb_digishield.hpp. It is
// header-only and depends ONLY on <cstdint>, so it links into the standalone
// GTest guard (no dgb OBJECT lib, no bitcoin arith_uint256 link) — the same
// constraint algo_select / header_chain tests run under. When the embedded
// DigiByte Core port lands, real arith_uint256 drops in with this same
// multiply-then-divide ordering and the boundary vectors carry over.
// ---------------------------------------------------------------------------

#include <cstdint>

#ifdef _MSC_VER
#include <intrin.h>   // _umul128 / _udiv128 -- MSVC has no __int128 keyword
#endif

namespace dgb::coin {

// ---------------------------------------------------------------------------
// Portable 128-bit primitives. GCC/Clang express the 64x64->128 multiply,
// 128/64 divide and 64+64 add through unsigned __int128; MSVC has no such
// type, so it uses the x64 intrinsics (_umul128 / _udiv128) that lower to the
// SAME mul/div/add-with-carry instructions. Both branches are bit-identical,
// so the DigiShield boundary vectors are unchanged. Mirrors the portable
// mul128_shift precedent in dgb/share_tracker.hpp.
// ---------------------------------------------------------------------------
namespace detail {

// low 64 of (a*b + add); high 64 written to hi. a*b+add always fits 128 bits.
inline uint64_t mul_add_u128(uint64_t a, uint64_t b, uint64_t add, uint64_t& hi) {
#ifdef _MSC_VER
    uint64_t lo = _umul128(a, b, &hi);
    lo += add;
    hi += (lo < add) ? 1u : 0u;     // carry out of the low limb
    return lo;
#else
    unsigned __int128 p = (unsigned __int128)a * b + add;
    hi = (uint64_t)(p >> 64);
    return (uint64_t)p;
#endif
}

// quotient of (hi:lo)/d; remainder written to rem. Requires hi < d (holds for
// schoolbook long division where hi is the running remainder), so the 64-bit
// quotient never overflows.
inline uint64_t div_u128(uint64_t hi, uint64_t lo, uint64_t d, uint64_t& rem) {
#ifdef _MSC_VER
    return _udiv128(hi, lo, d, &rem);
#else
    unsigned __int128 cur = ((unsigned __int128)hi << 64) | lo;
    rem = (uint64_t)(cur % d);
    return (uint64_t)(cur / d);
#endif
}

// low 64 of (a + b + carry_in); carry out (0/1) written to carry_out.
inline uint64_t add_u128(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t& carry_out) {
#ifdef _MSC_VER
    uint64_t s = a + b;
    uint64_t c = (s < a) ? 1u : 0u;
    s += carry_in;
    c += (s < carry_in) ? 1u : 0u;
    carry_out = c;
    return s;
#else
    unsigned __int128 s = (unsigned __int128)a + b + carry_in;
    carry_out = (uint64_t)(s >> 64);
    return (uint64_t)s;
#endif
}


// ---------------------------------------------------------------------------
// PORTABLE-FORCED reference primitives (the #690 native==portable KAT oracle).
//
// The MSVC branches above route through _umul128 / _udiv128 -- x64 hardware
// instructions that CANNOT be compiled or run on the Linux/macOS CI, so the
// "both branches bit-identical" claim can't be diffed directly there. These
// twins reproduce the SAME two operations (64x64->128 multiply, 128/64 divide)
// in pure 32-bit-limb software -- NO __int128, NO intrinsic -- a genuinely
// INDEPENDENT computation. If the software path equals the native __int128
// path across the DigiShield operand domain on Linux, and the x64
// _umul128/_udiv128 are (by ISA definition) exactly the 64x64->128 product and
// 128/64 quotient this software reproduces, then the MSVC path we cannot run
// here is equal too. Compiled unconditionally on every platform; NEVER
// referenced by the shipping u256 / mul_div_u256 (those stay byte-identical).
// ---------------------------------------------------------------------------

// software 64x64 -> 128 multiply (what _umul128 does in hardware).
inline uint64_t umul128_soft(uint64_t a, uint64_t b, uint64_t& hi) {
    const uint64_t a_lo = (uint32_t)a, a_hi = a >> 32;
    const uint64_t b_lo = (uint32_t)b, b_hi = b >> 32;
    const uint64_t p0 = a_lo * b_lo;
    const uint64_t p1 = a_lo * b_hi;
    const uint64_t p2 = a_hi * b_lo;
    const uint64_t p3 = a_hi * b_hi;
    const uint64_t mid = (p0 >> 32) + (uint32_t)p1 + (uint32_t)p2;
    hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
    return (p0 & 0xffffffffULL) | (mid << 32);
}

// software 128/64 -> 64 divide (what _udiv128 does in hardware). Requires
// hi < d so the 64-bit quotient never overflows -- the SAME precondition the
// _udiv128 intrinsic imposes. Binary long division from the top bit down; the
// running remainder r is kept < d, and (top:r) is the conceptual 65-bit value
// so d up to 2^64-1 is handled without a wider type.
inline uint64_t udiv128_soft(uint64_t hi, uint64_t lo, uint64_t d, uint64_t& rem) {
    uint64_t q = 0, r = hi;                 // r < d on entry (precondition)
    for (int i = 63; i >= 0; --i) {
        const uint64_t top = r >> 63;       // bit shifted out of the 64-bit r
        r = (r << 1) | ((lo >> i) & 1ULL);  // conceptual 65-bit value == (top:r)
        if (top || r >= d) {                // (top:r) >= d -> subtract, set bit
            r -= d;                         // uint64 wrap yields the true low64
            q |= 1ULL << i;
        }
    }
    rem = r;
    return q;
}

// Portable-forced twins of the three primitives the shipping u256 uses; each
// mirrors the corresponding MSVC branch above with the intrinsic swapped for
// the software op (add_u128's MSVC branch is already intrinsic-free).
inline uint64_t mul_add_u128_portable(uint64_t a, uint64_t b, uint64_t add, uint64_t& hi) {
    uint64_t lo = umul128_soft(a, b, hi);
    lo += add;
    hi += (lo < add) ? 1u : 0u;
    return lo;
}
inline uint64_t div_u128_portable(uint64_t hi, uint64_t lo, uint64_t d, uint64_t& rem) {
    return udiv128_soft(hi, lo, d, rem);
}
inline uint64_t add_u128_portable(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t& carry_out) {
    uint64_t s = a + b;
    uint64_t c = (s < a) ? 1u : 0u;
    s += carry_in;
    c += (s < carry_in) ? 1u : 0u;
    carry_out = c;
    return s;
}

} // namespace detail

// 256-bit unsigned, little-endian limbs (limb[0] least significant). Only the
// operations the DigiShield damped multiply needs: scale-by-u64 (truncating at
// 256 bits exactly as arith_uint256::operator*=), divide-by-u64, and compare.
struct u256 {
    uint64_t limb[4] = {0, 0, 0, 0};

    // Default-zero, plus an IMPLICIT widening from uint64_t so the field-shape
    // swap (M3 7b) leaves every existing uint64-range brace-init / literal
    // comparison byte-identical: `target = 4096`, `h.target == expected`,
    // `pow_limit != 0` all keep compiling and computing the same value, while
    // the embedded-daemon port drops full-width digests through this SAME field.
    u256() = default;
    u256(uint64_t v) { limb[0] = v; }

    static u256 from_u64(uint64_t v) { u256 r; r.limb[0] = v; return r; }

    // Construct from a 32-byte little-endian digest (the scrypt_1024_1_1_256
    // PoW output): limb[0] holds the least-significant 8 bytes. Mirrors bitcoin
    // UintToArith256 -- the Scrypt PoW hash is read little-endian for the
    // hash <= target comparison, so the digest the embedded DigiByte Core port
    // produces drops straight into HeaderSample::pow_hash at the ingest boundary
    // in the SAME byte order the 256-bit satisfaction gate already compares.
    // Depends only on <cstdint> / builtin unsigned char, so the standalone
    // header guard keeps linking with NO btclibs scrypt dependency; the scrypt
    // CALL itself lands at the ingest boundary in a following slice.
    static u256 from_le_bytes(const unsigned char b[32]) {
        u256 r;
        for (int i = 0; i < 4; ++i) {
            uint64_t v = 0;
            for (int j = 0; j < 8; ++j)
                v |= (uint64_t)b[i * 8 + j] << (8 * j);
            r.limb[i] = v;
        }
        return r;
    }

    bool     fits_u64() const { return limb[1] == 0 && limb[2] == 0 && limb[3] == 0; }
    bool     is_zero()  const { return limb[0] == 0 && limb[1] == 0 && limb[2] == 0 && limb[3] == 0; }
    uint64_t low64()    const { return limb[0]; }

    // Multiply by a 64-bit scalar. Carry past the top limb is DISCARDED, i.e.
    // the result is truncated to 256 bits — byte-for-byte what arith_uint256
    // does. This is the divergence point vs a 128/wider proxy.
    u256 mul_u64(uint64_t m) const {
        u256 r;
        uint64_t carry = 0;
        for (int i = 0; i < 4; ++i) {
            uint64_t hi;
            r.limb[i] = detail::mul_add_u128(limb[i], m, carry, hi);
            carry     = hi;
        }
        // carry beyond limb[3] dropped -> 256-bit truncation (consensus).
        return r;
    }

    // Divide by a 64-bit scalar (d must be non-zero), truncating toward zero.
    // Schoolbook long division from the most-significant limb down.
    u256 div_u64(uint64_t d) const {
        u256 r;
        uint64_t rem = 0;
        for (int i = 3; i >= 0; --i) {
            r.limb[i] = detail::div_u128(rem, limb[i], d, rem);
        }
        return r;
    }

    // Add another 256-bit value, truncating carry past limb[3] (256-bit wrap,
    // same width discipline as mul_u64). Accumulates the retarget window's
    // target sum before the divide-by-count average.
    u256& operator+=(const u256& o) {
        uint64_t carry = 0;
        for (int i = 0; i < 4; ++i) {
            limb[i] = detail::add_u128(limb[i], o.limb[i], carry, carry);
        }
        return *this;
    }

    friend bool operator<(const u256& a, const u256& b) {
        for (int i = 3; i >= 0; --i)
            if (a.limb[i] != b.limb[i]) return a.limb[i] < b.limb[i];
        return false;
    }
    friend bool operator>(const u256& a, const u256& b)  { return b < a; }
    friend bool operator==(const u256& a, const u256& b) {
        return a.limb[0] == b.limb[0] && a.limb[1] == b.limb[1]
            && a.limb[2] == b.limb[2] && a.limb[3] == b.limb[3];
    }
};

// avg * mul / div at full 256-bit width, in DigiByte Core ordering: MULTIPLY
// FIRST (overflow truncates at 256 bits), THEN divide. Reordering to divide
// first would lose low-order precision and is NOT what consensus computes.
inline u256 mul_div_u256(const u256& avg, uint64_t mul, uint64_t div) {
    return avg.mul_u64(mul).div_u64(div);
}


// ---------------------------------------------------------------------------
// PORTABLE-FORCED twin of u256 -- the #690 KAT oracle. Same little-endian limb
// layout and 256-bit truncation discipline, but mul_u64 / div_u64 / operator+=
// route through the software detail::*_portable primitives instead of the
// native __int128 (or MSVC intrinsic) ones. The native==portable guard diffs
// this against u256 on Linux. NOT used by any shipping code path.
// ---------------------------------------------------------------------------
struct u256_portable {
    uint64_t limb[4] = {0, 0, 0, 0};

    u256_portable() = default;
    explicit u256_portable(const u256& s) { for (int i = 0; i < 4; ++i) limb[i] = s.limb[i]; }

    u256_portable mul_u64(uint64_t m) const {
        u256_portable r;
        uint64_t carry = 0;
        for (int i = 0; i < 4; ++i) {
            uint64_t hi;
            r.limb[i] = detail::mul_add_u128_portable(limb[i], m, carry, hi);
            carry     = hi;
        }
        return r;
    }
    u256_portable div_u64(uint64_t d) const {
        u256_portable r;
        uint64_t rem = 0;
        for (int i = 3; i >= 0; --i)
            r.limb[i] = detail::div_u128_portable(rem, limb[i], d, rem);
        return r;
    }
    u256_portable& operator+=(const u256_portable& o) {
        uint64_t carry = 0;
        for (int i = 0; i < 4; ++i)
            limb[i] = detail::add_u128_portable(limb[i], o.limb[i], carry, carry);
        return *this;
    }
    // BIT-IDENTICAL check against a native u256 (all four limbs).
    bool equals(const u256& s) const {
        return limb[0] == s.limb[0] && limb[1] == s.limb[1]
            && limb[2] == s.limb[2] && limb[3] == s.limb[3];
    }
};

inline u256_portable mul_div_u256_portable(const u256_portable& avg, uint64_t mul, uint64_t div) {
    return avg.mul_u64(mul).div_u64(div);
}

} // namespace dgb::coin