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

} // namespace payout
} // namespace dash

#endif // C2POOL_DASH_PAYOUT_MULDIV_HPP
