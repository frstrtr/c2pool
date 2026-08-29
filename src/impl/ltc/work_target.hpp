#pragma once

#include <limits>
#include <core/uint256.hpp>

// LTC producer-target modulation helpers.
//
// This is the LTC sibling of src/impl/dash/stratum/work_target.hpp. The mint
// path in main_ltc.cpp (ref_hash_fn) applies the same two oracle caps DASH
// does -- Cap 1 (1.67% pool-share) and Cap 2 (dust ease) -- and both convert a
// double "average attempts" figure into a target via the inverse below. The
// arithmetic used to be inlined twice; it is factored here so it is unit
// testable and shared with the KAT (test_ltc_work_target.cpp). Behaviour is
// byte-identical to the previous inline for every avg_attempts < 2**64.
//
// Bucket-2 (v36-native shared structure): this converges the LTC shape toward
// the DASH one for a clean v37 fold; it is NOT an isolation primitive.
namespace ltc::stratum {

// average_attempts_to_target(n) -- inverse of target_to_average_attempts.
//   p2pool data.average_attempts_to_target: 2**256 // n - 1, clamped to
//   [1, 2**256-1]. avg_attempts is a double (hashrate*time arithmetic);
//   values <= 1.0 mean "no meaningful cap" and yield the maximum target.
//
// SATURATION (#859, mirrors DASH #858): the uint64 narrowing below is
// UNDEFINED BEHAVIOUR once avg_attempts >= 2**64, and on x86-64 it yields 0 ->
// two_256 / 0 THROWS "Division by zero" out of the caller. Cap 1 multiplies the
// miner rate by SHARE_PERIOD/0.0167 (~1198x), putting that boundary at only
// ~1.5e16 H/s of measured local rate -- reachable by a large aggregator. A
// throw on the producer-job path is caught by work_source and degrades to the
// non-producer coinbase, i.e. minting SILENTLY STOPS on LTC production. Clamp
// the divisor at UINT64_MAX -> 2**256//2**64 - 1: a target far harder than any
// chain band, which the subsequent band clip pins to the hard edge -- the same
// answer the unbounded oracle integer would clip to. The oracle's exact value
// is only ever observable INSIDE the band, where no saturation occurs.
inline uint256 average_attempts_to_target(double avg_attempts)
{
    uint256 max_t;
    max_t.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    if (!(avg_attempts > 1.0))
        return max_t;

    // 2**64 exactly, as a double: any avg_attempts at or above it cannot be
    // narrowed to uint64. (NaN falls out through the !(>1.0) guard above.)
    constexpr double kTwo64 = 18446744073709551616.0;
    const uint64_t avg_u64 = (avg_attempts >= kTwo64)
        ? std::numeric_limits<uint64_t>::max()
        : static_cast<uint64_t>(avg_attempts);

    uint288 two_256;
    two_256.SetHex("10000000000000000000000000000000000000000000000000000000000000000");
    uint288 avg_288(avg_u64);
    uint288 t_288 = two_256 / avg_288;
    if (t_288 > uint288(1))
        t_288 = t_288 - uint288(1);

    uint256 out;
    out.SetHex(t_288.GetHex());
    return out;
}

} // namespace ltc::stratum
