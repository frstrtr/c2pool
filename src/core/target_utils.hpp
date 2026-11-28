#pragma once

#include <core/uint256.hpp>

#include <cmath>
#include <cstdint>
#include <optional>
#include <string>

namespace chain
{

// Convert nBits compact format to expanded uint256 target
// This matches the Bitcoin/Litecoin compact format used in block headers
inline uint256 bits_to_target(uint32_t bits)
{
    int nSize = bits >> 24;
    uint32_t nWord = bits & 0x00ffffff;

    uint256 target;
    if (nSize <= 3)
    {
        nWord >>= 8 * (3 - nSize);
        target = nWord;
    }
    else
    {
        target = nWord;
        target <<= 8 * (nSize - 3);
    }
    return target;
}

// 2^256 / (target + 1)
// Returns the expected number of hash attempts to find a value <= target
inline uint288 target_to_average_attempts(const uint256& target)
{
    uint288 targ;
    targ.SetHex(target.GetHex());

    uint288 two_256;
    two_256.SetHex("10000000000000000000000000000000000000000000000000000000000000000");

    two_256 /= (targ + 1);
    return two_256;
}

// Convert uint256 target to compact nBits format (upper bound: smallest nBits
// whose decoded target is >= the input target).
// Inverse of bits_to_target(). Matches p2pool FloatingInteger.from_target_upper_bound().
//
// p2pool reference (bitcoin/data.py FloatingInteger.from_target_upper_bound):
//   1. Encode target as compact bits (truncating lower bytes)
//   2. If decoded bits.target < input target, increment bits by 1
//   3. Assert: decoded target >= input target (true upper bound)
inline uint32_t target_to_bits_upper_bound(const uint256& target)
{
    // data() is little-endian: data()[0] is least significant byte
    const unsigned char* d = target.data();

    // Find the most significant non-zero byte (big-endian size)
    int nSize = 32;
    while (nSize > 0 && d[nSize - 1] == 0)
        --nSize;

    if (nSize == 0)
        return 0;

    uint32_t nWord;
    if (nSize <= 3) {
        nWord = 0;
        for (int i = nSize - 1; i >= 0; --i)
            nWord = (nWord << 8) | d[i];
        nWord <<= 8 * (3 - nSize);
    } else {
        // Extract top 3 bytes (big-endian: d[nSize-1], d[nSize-2], d[nSize-3])
        nWord = (static_cast<uint32_t>(d[nSize - 1]) << 16) |
                (static_cast<uint32_t>(d[nSize - 2]) << 8) |
                (static_cast<uint32_t>(d[nSize - 3]));
        // Handle overflow of 3-byte mantissa
        if (nWord > 0x7fffff) {
            nWord >>= 8;
            ++nSize;
        }
    }

    // High bit of mantissa must be 0 for positive encoding
    if (nWord & 0x00800000) {
        nWord >>= 8;
        ++nSize;
    }

    return (static_cast<uint32_t>(nSize) << 24) | (nWord & 0x00ffffff);
}

// Convert target to mining difficulty (relative to max_target for display)
inline double target_to_difficulty(const uint256& target)
{
    if (target.IsNull())
        return 0.0;

    uint256 max_target;
    max_target.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
    return max_target.getdouble() / target.getdouble();
}

inline double target_to_difficulty(const uint288& target)
{
    uint288 max_target;
    max_target.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
    return max_target.getdouble() / target.getdouble();
}

// p2pool bitcoin/data.py difficulty_to_target for a float difficulty > 0:
//   min(int((0xffff0000 * 2**(256-64) + 1)/difficulty - 1 + 0.5), 2**256-1)
// evaluated as python does it: the numerator rounds to the double
// 0xffff * 2**208, then one IEEE division, "- 1", "+ 0.5", and int()
// truncates the double exactly. Difficulty 1 is 0x00000000ffff0000...
// (the same unit as target_to_difficulty). None where python's int() raises
// (the quotient overflows a double: difficulty below ~1e-241, or not a finite
// number > 0); p2pool's get_user_details catches that and sets no target.
inline std::optional<uint256> difficulty_to_target(double difficulty)
{
    if (!(difficulty > 0.0) || !std::isfinite(difficulty))
        return std::nullopt;
    const double q = std::ldexp(65535.0, 208) / difficulty - 1.0 + 0.5;
    if (!std::isfinite(q))
        return std::nullopt;
    uint256 max_t;
    max_t.SetHex(std::string(64, 'f'));
    if (q >= std::ldexp(1.0, 256))
        return max_t;
    if (!(q >= 1.0))
        return uint256();   // int() of a value in (-1, 1)
    int exp = 0;
    const double m = std::frexp(q, &exp);   // q = m * 2**exp, 0.5 <= m < 1
    if (exp <= 64)
        return uint256(static_cast<uint64_t>(q));
    // q >= 2**64 is an integer: its 53 significant bits, shifted into place.
    uint256 t(static_cast<uint64_t>(std::ldexp(m, 64)));
    t <<= static_cast<unsigned int>(exp - 64);
    return t;
}

} // namespace chain
