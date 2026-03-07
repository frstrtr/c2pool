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
