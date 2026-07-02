#pragma once

// dash::stratum::* — per-miner work-target MODULATION accessor (S8).
//
// This is the c2pool-dash equivalent of the desired_share_target logic in
// the DASH oracle frstrtr/p2pool-dash @9a0a609 work.py:266-426 (the
// `get_work()` modulation block, specifically lines 308-326). When a miner
// asks for work, p2pool does NOT hand out the raw sharechain target — it
// modulates a per-miner target down by two independent caps so that:
//
//   Cap 1 (pool-share cap, work.py:309-312) — a single fast miner is limited
//          to ~1.67% of all pool shares, by tightening its share difficulty
//          in proportion to its measured hashrate. Without this, one big
//          aggregator dominates the PPLNS window and starves small miners.
//
//   Cap 2 (dust-threshold ease, work.py:317-326) — if a miner's expected
//          payout per block would fall below PARENT.DUST_THRESHOLD, EASE its
//          target so it still lands meaningful (non-dust) shares. This is the
//          opposite direction — it makes the target easier — so small miners
//          keep getting paid instead of having every output dropped as dust.
//
// CLASSIFICATION (operator v36_standardization_goal 2026-06-17, Bucket-2):
//   The modulation ALGORITHM (the 0.0167 pool-share fraction, the *SPREAD
//   dust ease, the average_attempts_to_target conversion) is the
//   protocol-UNIVERSAL shape — identical across btc/ltc/dgb/dash — and folds
//   cleanly to a single v37 unified work-source. It is therefore authored
//   here as a pure, reusable accessor (NOT re-inlined into a future
//   DASHWorkSource the way the legacy LTC path inlines it inside the
//   ref_hash_fn lambda at c2pool_refactored.cpp:4449-4500).
//   The INPUTS it reads — SHARE_PERIOD / SPREAD / DUST_THRESHOLD / subsidy /
//   block target — stay per-coin config SSOT (dash::SharechainConfig,
//   config_pool.hpp). They are tuning inputs, not isolation primitives, so
//   no cross-coin entanglement is introduced.
//
// PURITY: header-only, socket-free, node-free. Every function is a pure
// transform of its arguments — no template/chain/daemon state is touched.
// This is what makes the modulation KAT (test_dash_work_target) able to pin
// oracle-exact arithmetic with no VM200/201 node and no live sharechain.
//
// The eventual DASHWorkSource::get_work() (S8 follow-on) calls these with the
// frozen per-job inputs; the modulation result becomes the job's nbits.

#include <algorithm>
#include <cstdint>

#include <core/target_utils.hpp>   // chain::bits_to_target / target_to_average_attempts
#include <core/uint256.hpp>        // uint256 / uint288

namespace dash::stratum {

// average_attempts_to_target(n) — inverse of target_to_average_attempts.
//   p2pool dash_data.average_attempts_to_target: 2**256 // n - 1, clamped to
//   [1, 2**256-1]. Mirrors c2pool_refactored.cpp:4453-4458 (LTC reference).
// `avg_attempts` is a double (hashrate*time arithmetic). Values <= 1.0 mean
// "no meaningful cap" and yield the maximum target (2**256-1).
inline uint256 average_attempts_to_target(double avg_attempts)
{
    uint256 max_t;
    max_t.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    if (!(avg_attempts > 1.0))
        return max_t;

    uint288 two_256;
    two_256.SetHex("10000000000000000000000000000000000000000000000000000000000000000");
    uint288 avg_288(static_cast<uint64_t>(avg_attempts));
    uint288 t_288 = two_256 / avg_288;
    if (t_288 > uint288(1))
        t_288 = t_288 - uint288(1);

    uint256 out;
    out.SetHex(t_288.GetHex());
    return out;
}

// ── Cap 1: pool-share cap (work.py:309-312) ───────────────────────────────
// desired = min(desired,
//   average_attempts_to_target(local_hash_rate * SHARE_PERIOD / 0.0167))
// 0.0167 == the 1.67% pool-share fraction (oracle literal). A miner with no
// measured hashrate (local_hash_rate <= 0) is left untouched.
inline uint256 cap_pool_share(uint256 desired_target,
                              double local_hash_rate,
                              uint32_t share_period)
{
    if (!(local_hash_rate > 0.0))
        return desired_target;

    const double pool_share_fraction = 0.0167;  // oracle work.py literal
    double avg_attempts =
        local_hash_rate * static_cast<double>(share_period) / pool_share_fraction;

    uint256 cap = average_attempts_to_target(avg_attempts);
    return (cap < desired_target) ? cap : desired_target;
}

// ── Cap 2: dust-threshold ease (work.py:317-326) ──────────────────────────
// Only applies once the sharechain is deep enough that a pool-hashrate
// estimate exists (caller gates on height > 3600/SHARE_PERIOD lookbehind and
// passes pool_attempts_per_second > 0). If the miner's expected payout per
// block is below dust_threshold, ease the target to:
//   average_attempts_to_target(
//     target_to_average_attempts(block_target) * SPREAD * DUST / subsidy)
// Returns desired_target unchanged when not gated / not below dust.
// Mirrors c2pool_refactored.cpp:4468-4500 (LTC reference); double arithmetic
// on the attempts product avoids uint288 overflow.
inline uint256 cap_dust_threshold(uint256 desired_target,
                                  double local_hash_rate,
                                  double pool_attempts_per_second,
                                  uint64_t subsidy,
                                  uint32_t block_bits,
                                  uint32_t spread,
                                  uint64_t dust_threshold,
                                  double donation_percentage)
{
    if (!(local_hash_rate > 0.0) || !(pool_attempts_per_second > 0.0) ||
        subsidy == 0)
        return desired_target;

    double expected_payout = (local_hash_rate / pool_attempts_per_second) *
                             static_cast<double>(subsidy) *
                             (1.0 - donation_percentage / 100.0);
    if (!(expected_payout < static_cast<double>(dust_threshold)))
        return desired_target;

    uint256 block_target = chain::bits_to_target(block_bits);
    uint288 block_aps = chain::target_to_average_attempts(block_target);
    double dust_avg = static_cast<double>(block_aps.GetLow64()) *
                      static_cast<double>(spread) *
                      static_cast<double>(dust_threshold) /
                      static_cast<double>(subsidy);

    uint256 eased = average_attempts_to_target(dust_avg);
    return (eased < desired_target) ? eased : desired_target;
}

// Frozen per-miner inputs for a single get_work() modulation, supplied by the
// (future) DASHWorkSource from template + share-tracker state at job time.
struct WorkTargetInputs {
    double   local_hash_rate         = 0.0;   ///< H/s for this miner's payout addr (0 = unknown)
    uint32_t share_period            = 0;     ///< dash::SharechainConfig::share_period()
    uint32_t spread                  = 0;     ///< dash::SharechainConfig::SPREAD
    uint64_t dust_threshold          = 0;     ///< dash::SharechainConfig::dust_threshold()
    bool     dust_gate               = false; ///< sharechain height > 3600/SHARE_PERIOD lookbehind
    double   pool_attempts_per_second = 0.0;  ///< pool aps over the lookbehind (0 if ungated)
    uint64_t subsidy                 = 0;     ///< block subsidy (coinbasevalue)
    uint32_t block_bits              = 0;     ///< dashd block target bits
    double   donation_percentage     = 0.0;   ///< dev-donation % (Cap-2 payout adjust)
};

// Full modulation: start from the unconstrained target (2**256-1) and apply
// both caps in oracle order. The result is the per-miner desired_share_target
// the job is built with. Faithful to work.py:308-326: desired starts at
// 2**256-1, Cap 1 always considered, Cap 2 only when `dust_gate` is set.
inline uint256 modulate_desired_share_target(const WorkTargetInputs& in)
{
    uint256 desired;
    desired.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    desired = cap_pool_share(desired, in.local_hash_rate, in.share_period);

    if (in.dust_gate)
        desired = cap_dust_threshold(desired, in.local_hash_rate,
                                     in.pool_attempts_per_second, in.subsidy,
                                     in.block_bits, in.spread, in.dust_threshold,
                                     in.donation_percentage);
    return desired;
}

}  // namespace dash::stratum
