#ifndef C2POOL_DASH_PAYOUT_MULDIV_HPP
#define C2POOL_DASH_PAYOUT_MULDIV_HPP

// ---------------------------------------------------------------------------
// dash::payout -- MSVC-portable 128-bit intermediate for the PPLNS coinbase
// payout proportion (coinbase_builder.hpp step 3-4).
//
// The per-script amount is a muldiv evaluated in a 128-bit intermediate:
//
//     v36     : amount = worker_payout * weight / total_weight
//     pre-v36 : amount = worker_payout * 49 * weight / (total_weight * 50)
//
// The numerator worker_payout*weight*49 reaches ~2^120 (weight < 2^64,
// worker_payout < 2^50, 49 < 2^6) and the pre-v36 denominator total_weight*50
// exceeds 2^64, so a true 128-bit intermediate is REQUIRED.
//
// GCC/Clang provide native unsigned __int128 -- that path is kept BYTE-EXACT
// for the shipping Linux/macOS c2pool-dash packages. MSVC has no __int128
// (error C2065: '__uint128_t': undeclared identifier), which broke the
// c2pool-dash Windows v0.2.1 build; on any compiler without __int128 we fall
// back to boost::multiprecision::uint128_t, a fixed 128-bit unsigned type that
// yields BIT-IDENTICAL results. This is CONSENSUS PAYOUT math -- a one-satoshi
// divergence forks payouts -- so test_dash_coinbase_muldiv pins native ==
// portable across the full DASH payout domain (the required guard). Mirrors the
// BCH abla (#688) and DGB arith256 (#690) MSVC-portability rework.
// ---------------------------------------------------------------------------

#include <cassert>
#include <cstdint>
#include <limits>

// Portable 128-bit intermediate on compilers without __int128 (MSVC).
// Header-only; boost is already a c2pool dependency (conan + system libboost).
#include <boost/multiprecision/cpp_int.hpp>

#include <core/uint256.hpp>   // uint288 (v36 consensus entry below)

#include <stdexcept>

namespace dash {
namespace payout {

// Portable path (MSVC and any non-__int128 compiler). Fixed 128-bit unsigned
// boost intermediate -> BIT-IDENTICAL to the native __int128 result.
inline uint64_t payout_share_portable(uint64_t weight, uint64_t worker_payout,
                                      uint64_t total_weight, bool v36) {
    assert(total_weight > 0);
    using u128 = boost::multiprecision::uint128_t;
    u128 num = u128(weight) * u128(worker_payout);
    if (!v36) num *= 49u;
    const u128 den = v36 ? u128(total_weight) : u128(total_weight) * 50u;
    const u128 q = num / den;
    assert(q <= u128(std::numeric_limits<uint64_t>::max()));
    return static_cast<uint64_t>(q);
}

#if defined(__SIZEOF_INT128__)
// Native path (GCC/Clang) -- BYTE-EXACT reproduction of the original
// coinbase_builder.hpp:131-138 block; this is what the merged Linux/macOS
// packages ship. Exposed by name so the KAT can diff it against the portable
// path on the trusted platform.
inline uint64_t payout_share_native(uint64_t weight, uint64_t worker_payout,
                                    uint64_t total_weight, bool v36) {
    assert(total_weight > 0);
    const __uint128_t den = v36
        ? static_cast<__uint128_t>(total_weight)
        : static_cast<__uint128_t>(total_weight) * 50;
    __uint128_t num = static_cast<__uint128_t>(weight)
                    * static_cast<__uint128_t>(worker_payout);
    if (!v36) num *= 49;
    const __uint128_t q = num / den;
    assert(q <= static_cast<__uint128_t>(std::numeric_limits<uint64_t>::max()));
    return static_cast<uint64_t>(q);
}
inline uint64_t payout_share(uint64_t weight, uint64_t worker_payout,
                             uint64_t total_weight, bool v36) {
    return payout_share_native(weight, worker_payout, total_weight, v36);
}
#else
inline uint64_t payout_share(uint64_t weight, uint64_t worker_payout,
                             uint64_t total_weight, bool v36) {
    return payout_share_portable(weight, worker_payout, total_weight, v36);
}
#endif


// ---------------------------------------------------------------------------
// v36 consensus entry (private/isolated DASH v36 sharechain; dormant until the
// v36 share type is live). THE one exact payout muldiv the v36 verifier
// (share_check.hpp build_v36_gentx), the v36 producer (share_producer.hpp
// build_share_v36, via the same builder) and the stratum coinbase builder's
// v36 arm (coinbase_builder.hpp compute_dash_payouts, via compute_v36_amounts)
// all use, so the three cannot drift:
//
//     amount = floor(weight * worker_payout / total_weight)   (full weight)
//
// Wide inputs: the tracker's v36 decayed weights are uint288 values
// (att * decay * 65535, att up to ~2^59 at DASH mainnet difficulty), so they
// do not fit the uint64 payout_share() above. The product is taken in a
// 512-bit boost intermediate (288 + 64 < 512): exact by construction and
// MSVC-portable (no __int128). test_dash_v36_gentx pins it equal to
// payout_share(..., v36=true) over the whole uint64 domain sweep and against
// hand-computed answers above 2^64. total_weight == 0 throws (callers guard).
// The quotient never exceeds worker_payout because weight <= total_weight for
// every caller; a caller violating that gets a throw, never a truncated value.
// ---------------------------------------------------------------------------
inline uint64_t v36_worker_amount(const uint288& weight, uint64_t worker_payout,
                                  const uint288& total_weight) {
    using u512 = boost::multiprecision::uint512_t;
    auto widen = [](const uint288& v) {
        u512 out = 0;
        for (int i = uint288::WIDTH - 1; i >= 0; --i) {
            out <<= 32;
            out |= v.pn[i];
        }
        return out;
    };
    const u512 den = widen(total_weight);
    if (den == 0)
        throw std::invalid_argument("v36_worker_amount: total_weight is zero");
    const u512 q = (widen(weight) * u512(worker_payout)) / den;
    if (q > u512(std::numeric_limits<uint64_t>::max()))
        throw std::overflow_error("v36_worker_amount: amount exceeds 64 bits");
    return static_cast<uint64_t>(q);
}

} // namespace payout
} // namespace dash

#endif // C2POOL_DASH_PAYOUT_MULDIV_HPP
