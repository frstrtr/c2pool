// src/core/author_fee.hpp
//
// Single source of truth for the built-in author/dev donation policy shared by
// every coin lane. The in-code default is HARD-PINNED at 0.1% (see the
// operator money rule: author-fee default = 0.1%, NEVER 0). The percent → u16
// conversion is the p2pool oracle math perfect_round(65535 * pct / 100),
// hoisted here so DASH / LTC / BTC / DGB / BCH / BIP110 all share ONE formula
// and one constant instead of scattered hardcoded literals.
#ifndef C2POOL_CORE_AUTHOR_FEE_HPP
#define C2POOL_CORE_AUTHOR_FEE_HPP

#include <cstdint>

namespace core {

// Built-in author/dev donation default, in percent. 0.1% → u16 66.
constexpr double kAuthorFeeDefaultPct = 0.1;

// round(65535 * pct / 100), clamped to the u16 field — the oracle's
// math.perfect_round(65535*donation_percentage/100) (p2pool work.py).
inline uint16_t donation_percent_to_u16(double pct)
{
    if (pct <= 0.0)   return 0;
    if (pct >= 100.0) return 65535;
    const double v = 65535.0 * pct / 100.0;
    const uint64_t r = static_cast<uint64_t>(v + 0.5);
    return r > 65535 ? 65535 : static_cast<uint16_t>(r);
}

} // namespace core

#endif // C2POOL_CORE_AUTHOR_FEE_HPP
