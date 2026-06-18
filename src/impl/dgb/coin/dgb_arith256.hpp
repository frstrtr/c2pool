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

namespace dgb::coin {

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

    bool     fits_u64() const { return limb[1] == 0 && limb[2] == 0 && limb[3] == 0; }
    bool     is_zero()  const { return limb[0] == 0 && limb[1] == 0 && limb[2] == 0 && limb[3] == 0; }
    uint64_t low64()    const { return limb[0]; }

    // Multiply by a 64-bit scalar. Carry past the top limb is DISCARDED, i.e.
    // the result is truncated to 256 bits — byte-for-byte what arith_uint256
    // does. This is the divergence point vs a 128/wider proxy.
    u256 mul_u64(uint64_t m) const {
        u256 r;
        unsigned __int128 carry = 0;
        for (int i = 0; i < 4; ++i) {
            unsigned __int128 prod = (unsigned __int128)limb[i] * m + carry;
            r.limb[i] = (uint64_t)prod;
            carry     = prod >> 64;
        }
        // carry beyond limb[3] dropped -> 256-bit truncation (consensus).
        return r;
    }

    // Divide by a 64-bit scalar (d must be non-zero), truncating toward zero.
    // Schoolbook long division from the most-significant limb down.
    u256 div_u64(uint64_t d) const {
        u256 r;
        unsigned __int128 rem = 0;
        for (int i = 3; i >= 0; --i) {
            unsigned __int128 cur = (rem << 64) | limb[i];
            r.limb[i] = (uint64_t)(cur / d);
            rem       = cur % d;
        }
        return r;
    }

    // Add another 256-bit value, truncating carry past limb[3] (256-bit wrap,
    // same width discipline as mul_u64). Accumulates the retarget window's
    // target sum before the divide-by-count average.
    u256& operator+=(const u256& o) {
        unsigned __int128 carry = 0;
        for (int i = 0; i < 4; ++i) {
            unsigned __int128 s = (unsigned __int128)limb[i] + o.limb[i] + carry;
            limb[i] = (uint64_t)s;
            carry   = s >> 64;
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

} // namespace dgb::coin
