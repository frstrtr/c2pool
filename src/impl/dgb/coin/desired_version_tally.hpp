#pragma once

// SSOT for the DGB DESIRED-VERSION TALLY -- the pure accumulation core of
// ShareTracker::get_desired_version_weights() (and its flat-count diagnostic
// sibling get_desired_version_counts()). Walking back over a clamped
// [.., CHAIN_LENGTH] window of shares, each share's m_desired_version is
// bucketed and either its work is summed (the consensus map) or its occurrence
// counted (the diagnostic map). The work-weighted map is the CONSENSUS input to
// the V36 60%-by-work switch rule (share_check step 2) and the #288 AutoRatchet
// activation tail guard; the flat-count map is diagnostics/KAT only and is
// NEVER the gate.
//
// Oracle: p2pool-dgb-scrypt data.py:918-922 get_desired_version_counts:
//     def get_desired_version_counts(tracker, best_share_hash, dist):
//         res = {}
//         for share in tracker.get_chain(best_share_hash, dist):
//             res[share.desired_version] = res.get(share.desired_version, 0) \
//                 + bitcoin_data.target_to_average_attempts(share.target)
//         return res
//
// NOTE the oracle's get_desired_version_counts is ALREADY work-weighted -- each
// share contributes target_to_average_attempts(share.target), NOT 1. c2pool
// splits this into two accessors: get_desired_version_weights (the true oracle
// match -- weight = ShareIndex::work = chain::target_to_average_attempts(
// chain::bits_to_target(m_bits)), the CONSENSUS gate input) and
// get_desired_version_counts (a flat occurrence count, diagnostics-only, never
// the gate -- see the share_tracker.hpp comment, #406 and #288). This header
// captures ONLY the per-version accumulation over already-resolved
// (desired_version, work) pairs as free functions; the chain-walk and the
// lookbehind clamp stay inside ShareTracker (the clamp is the separate
// chain_walk_window SSOT). share_tracker.hpp is NOT rewired this slice
// (byte-identity delegation is the follow-on).
//
// Per-coin isolation: dgb/ only. Header-only, additive, consensus-neutral (pure
// std::map accumulation, no value semantics changed). MUST appear in BOTH this
// dir CMakeLists.txt AND the build.yml --target allowlist, or it becomes a #143
// NOT_BUILT sentinel.

#include <core/uint256.hpp>  // uint288

#include <cstdint>
#include <map>
#include <vector>

namespace dgb {

// One share's contribution to the tally: its desired_version and its work
// (= chain::target_to_average_attempts(chain::bits_to_target(m_bits)), the same
// value ShareIndex::work caches). Mirrors the (dv, idx->work) pair the inline
// loop reads per share in get_desired_version_weights.
struct VersionWork {
    uint64_t desired_version;
    uint288  work;
};

// Work-weighted version tally -- the CONSENSUS gate input. Mirrors verbatim the
// inline body:
//     for (share in window) weights[dv] = weights[dv] + idx->work;
// std::map value-initializes uint288(0) on first touch of a version key, exactly
// matching the inline weights[dv] + idx->work (and the oracle
// res.get(dv, 0) + attempts).
inline std::map<uint64_t, uint288>
accumulate_version_weights(const std::vector<VersionWork>& window)
{
    std::map<uint64_t, uint288> weights;
    for (const auto& s : window)
        weights[s.desired_version] = weights[s.desired_version] + s.work;
    return weights;
}

// Flat occurrence count -- DIAGNOSTICS/KAT ONLY, never the consensus gate. Each
// share counts as 1 regardless of its work. Mirrors verbatim the inline body:
//     for (share in window) counts[dv]++;
inline std::map<uint64_t, int32_t>
accumulate_version_counts(const std::vector<uint64_t>& window)
{
    std::map<uint64_t, int32_t> counts;
    for (uint64_t dv : window)
        counts[dv]++;
    return counts;
}

}  // namespace dgb
