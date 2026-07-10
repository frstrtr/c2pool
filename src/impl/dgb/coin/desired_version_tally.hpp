// SPDX-License-Identifier: AGPL-3.0-or-later
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

// Runtime P2P accept-floor RATCHET -- SSOT for the oracle update_min_protocol_version
// (p2pool-dgb-scrypt data.py:857-863), the runtime sibling of the 60% version-switch
// gate (share_check.hpp step 2). Both read the SAME work-weighted desired-version map
// over the SAME window [CHAIN_LENGTH*9//10, CHAIN_LENGTH//10] behind the best share's
// parent (main.py:216 / data.py:562 call-site); this one lifts the inbound handshake
// floor instead of rejecting a share.
//
// Oracle (data.py:857):
//     def update_min_protocol_version(counts, share):
//         minpver    = getattr(share.net, 'MINIMUM_PROTOCOL_VERSION', 1400)
//         newminpver = share.MINIMUM_PROTOCOL_VERSION
//         if (counts is not None) and (minpver < newminpver):
//             if counts.get(share.VERSION, 0) >= sum(counts.itervalues())*95//100:
//                 share.net.MINIMUM_PROTOCOL_VERSION = newminpver
//
// `counts` here is get_desired_version_counts -- WORK-WEIGHTED by
// target_to_average_attempts(share.target), keyed by desired_version, looked up by the
// best share's VERSION. c2pool's get_desired_version_weights is the byte-faithful
// match (see accumulate_version_weights above), so this function consumes that map
// directly. Pure: no I/O, inputs unmutated; returns the (possibly lifted) floor.
//
// Integer math is the oracle's exactly: ratchet iff
//     best_weight >= floor(total_weight * 95 / 100).
// We floor-divide (total*95)/100 and NOT the cross-multiplied best*100 >= total*95
// idiom -- the two differ at the boundary when (total*95) % 100 != 0 (then floor-div
// accepts best == floor(...), cross-mult rejects it), and the oracle floor-divides.
inline uint32_t ratchet_min_protocol_version(
    const std::map<uint64_t, uint288>& version_weights,
    int64_t  best_version,
    uint32_t current_floor,
    uint32_t target_floor)
{
    if (current_floor >= target_floor)          // oracle: minpver < newminpver guard
        return current_floor;

    uint288 best_weight;
    uint288 total_weight;
    for (const auto& [ver, w] : version_weights) {
        total_weight = total_weight + w;
        if (static_cast<int64_t>(ver) == best_version)
            best_weight = best_weight + w;
    }
    // oracle: counts.get(share.VERSION, 0) >= sum(counts.itervalues())*95//100
    if (best_weight >= (total_weight * uint32_t(95)) / uint32_t(100))
        return target_floor;
    return current_floor;
}

// Runtime WIRING decision -- the call-site guard the pure ratchet above deliberately
// omits. ratchet_min_protocol_version mirrors ONLY the oracle dict-branch
// (data.py:861): over an empty/partial window it ratchets (0 >= 0), because the
// oracle's None / full-window guard lives at the CALL SITE (main.py:212):
//     if len(shares) > CHAIN_LENGTH:
//         counts = get_desired_version_counts(tracker,
//             get_nth_parent_hash(previous_share.hash, CHAIN_LENGTH*9//10), CHAIN_LENGTH//10)
//         update_min_protocol_version(counts, best_share)
// Without this guard a fresh node (parent_height < CHAIN_LENGTH -> empty window) would
// spuriously lift the floor to 3500 and reject every legitimate peer. This function is
// that guard: no lift until a FULL window exists behind the best share's parent, then
// delegate to the pure ratchet over the [CHAIN_LENGTH*9/10, CHAIN_LENGTH] window the
// caller sampled (the SAME window as the 60% version-switch gate, share_check step 2).
inline uint32_t apply_min_protocol_ratchet_decision(
    int32_t  parent_height,
    int32_t  chain_length,
    const std::map<uint64_t, uint288>& window_weights,
    int64_t  best_version,
    uint32_t current_floor,
    uint32_t target_floor)
{
    if (current_floor >= target_floor)      // oracle guard: minpver < newminpver
        return current_floor;
    if (parent_height < chain_length)       // oracle main.py:212: len(shares) > CHAIN_LENGTH
        return current_floor;               // no full window yet -> never lift
    return ratchet_min_protocol_version(
        window_weights, best_version, current_floor, target_floor);
}

}  // namespace dgb