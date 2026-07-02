#pragma once

// dash::stratum::* — get_work() JOB-TARGET assembly (S8 get_work() wiring).
//
// This is the S8 follow-on the per-miner modulation accessor (work_target.hpp,
// PR #545) explicitly deferred: where work_target.hpp authors the
// desired_SHARE_target modulation (work.py:308-326), this header authors the
// rest of the get_work() target arithmetic — the desired_PSEUDOSHARE_target
// (vardiff) modulation, the SANE_TARGET_RANGE clip, and the two job-target
// fields the stratum work blob carries. Together they are everything the
// (future) DASHWorkSource::get_work() needs to turn frozen template +
// share-tracker state into a jobs nbits, with no node and no socket.
//
// ORACLE: frstrtr/p2pool-dash @9a0a609 p2pool/work.py:368-426.
//
//   Pseudoshare modulation (work.py:368-374) — when the stratum client supplies
//     no desired_pseudoshare_target, start from 2**256-1 and cap to ~one share
//     response per second: average_attempts_to_target(local_hash_rate * 1).
//
//   SANE clip (work.py:380-393) — math.clip(target, PARENT.SANE_TARGET_RANGE):
//     bound the vardiff target into (min_target/hardest, max_target/easiest).
//
//   Job targets (work.py:411-426, the `ba` dict) —
//     min_share_target = min(share_info[bits].target, SANE_TARGET_RANGE[1])
//                        (the P2Pool share-difficulty floor)
//     share_target     = the clipped pseudoshare/vardiff target.
//
// CLASSIFICATION (operator v36_standardization_goal 2026-06-17, Bucket-2):
//   Same as work_target.hpp — the pseudoshare modulation + clip ALGORITHM is the
//   protocol-universal shape that folds to a v37 unified work-source, so it is a
//   pure reusable accessor. The INPUTS it reads — SANE_TARGET_RANGE — stay
//   per-coin config SSOT (dash::SharechainConfig::sane_target_min/max, config_pool.hpp);
//   tuning bounds, not isolation primitives, so no cross-coin entanglement.
//
// PURITY: header-only, socket-free, node-free — every function is a pure
// transform of its arguments. This is what lets test_dash_work_job_targets pin
// oracle-exact arithmetic with no VM200/201 node and no live sharechain.

#include "work_target.hpp"   // dash::stratum::average_attempts_to_target
#include <core/uint256.hpp>  // uint256

namespace dash::stratum {

// math.clip(x, (lo, hi)) — oracle p2pool util/math.py: return lo if x < lo,
// hi if x > hi, else x. SANE_TARGET_RANGE = (min_target/hardest, max_target/
// easiest), so lo <= hi as targets. Clamps the vardiff target into range.
inline uint256 clip_to_sane(uint256 target,
                            const uint256& sane_min,
                            const uint256& sane_max)
{
    if (target < sane_min) return sane_min;
    if (target > sane_max) return sane_max;
    return target;
}

// Pseudoshare (vardiff) target modulation — work.py:368-374. The None-path:
// start from 2**256-1, cap to one share-response/sec by tightening to
// average_attempts_to_target(local_hash_rate * 1). local_hash_rate <= 0 leaves
// it unconstrained (no measured rate yet). The merged-work aux max
// (work.py:376-377) is omitted: this is the dash-fenced single-chain path; aux
// targets fold in at the merged-mining seam, not here.
inline uint256 modulate_desired_pseudoshare_target(double local_hash_rate)
{
    uint256 target;
    target.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    if (local_hash_rate > 0.0) {
        uint256 cap = average_attempts_to_target(local_hash_rate * 1.0);
        if (cap < target) target = cap;
    }
    return target;
}

// Frozen per-job target inputs, assembled by the (future) DASHWorkSource from
// the modulated desired_share_target (work_target.hpp), the generated share_info
// bits target, and per-miner vardiff state at job time.
struct WorkJobTargetInputs {
    uint256 share_info_bits_target;          ///< share_info[bits].target from generate_transaction
    uint256 sane_target_min;                 ///< SharechainConfig::sane_target_min() (SANE_TARGET_RANGE[0])
    uint256 sane_target_max;                 ///< SharechainConfig::sane_target_max() (SANE_TARGET_RANGE[1])
    bool    have_desired_pseudoshare = false;///< client supplied desired_pseudoshare_target?
    uint256 desired_pseudoshare_target;      ///< client-supplied target (when have_... = true)
    double  local_hash_rate          = 0.0;  ///< for the None-path *1 cap
};

// The two job-target fields of the stratum work blob (work.py:411-426 `ba`).
struct WorkJobTargets {
    uint256 min_share_target;  ///< min(share_info bits target, SANE_TARGET_RANGE[1]) — share floor
    uint256 share_target;      ///< clipped pseudoshare/vardiff target
};

// get_work() job-target assembly. Faithful to work.py:368-426: the share_target
// is the (modulated-or-supplied) pseudoshare target clipped into SANE range; the
// min_share_target is the generated share bits target floored at the easiest sane
// target. Pure transform of `in` — no node/template/daemon state touched.
inline WorkJobTargets assemble_work_job_targets(const WorkJobTargetInputs& in)
{
    uint256 target = in.have_desired_pseudoshare
        ? in.desired_pseudoshare_target
        : modulate_desired_pseudoshare_target(in.local_hash_rate);
    target = clip_to_sane(target, in.sane_target_min, in.sane_target_max);

    uint256 floor = (in.share_info_bits_target < in.sane_target_max)
        ? in.share_info_bits_target
        : in.sane_target_max;

    return WorkJobTargets{ floor, target };
}

}  // namespace dash::stratum
