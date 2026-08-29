#pragma once

#include <core/uint256.hpp>

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

} // namespace chain
