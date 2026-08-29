// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH v36-native MINT-side auto-ratchet of the P2P accept floor.
//
// FENCED / ADDITIVE / UNWIRED. This header carries NO src/ call site — the live
// consumer (node.cpp, analogous to dgb::NodeImpl min-proto-ratchet) rides the S8
// pool-node wire-up and is consensus-bearing, so it is surfaced separately for an
// integrator merge tap. Landing the skeleton here de-risks that wire-up and closes
// the single gap the #357 AutoRatchet mint-gate weighting audit found: DASH already
// defines the WEIGHTED desired-version tally (version_negotiation.hpp
// get_desired_version_weights) and the 60%/95% accept gates consume it, but there
// was NO mint-side consumer that lifts MINIMUM_PROTOCOL_VERSION off the same window.
//
// v36-STANDARDIZATION (operator 3-bucket rule, bucket 2 = v36-NATIVE SHARED
// STRUCTURE): the auto-ratchet is standardized cross-coin toward the v37 shape. It
// mirrors dgb::apply_min_protocol_ratchet_decision byte-for-byte in decision logic;
// only the floor constants differ per coin (the ISOLATION invariant stays per-coin).
//
// ORACLE NOTE (honest, surfaced to integrator): the DASH oracle frstrtr/p2pool-dash
// (older-than-v35) has NO update_min_protocol_version and NO NEW_MINIMUM_PROTOCOL_VERSION
// — MINIMUM_PROTOCOL_VERSION is the static 1700 net constant (dash.py:23). The
// dgb-scrypt oracle DOES ratchet (data.py:715 newminpver = NEW_MINIMUM_PROTOCOL_VERSION,
// 1400 -> 3500). So the DASH ratchet TARGET floor is a c2pool v36-native choice, not
// an oracle-derived number. The decision MATH below is oracle-faithful to the
// dgb-scrypt update_min_protocol_version (floor-divided 95% work-weighted gate); the
// concrete target value is a wire-up-time decision and is intentionally NOT baked in
// here — every function takes current_floor / target_floor as parameters.

#include <core/uint256.hpp>  // uint288

#include <cstdint>
#include <map>
#include <vector>

namespace dash {

// A single share's contribution to a desired-version tally: the version it desires
// and its work weight (target_to_average_attempts of its target, == ShareIndex::work,
// the same metric get_desired_version_weights caches -- version_negotiation.hpp D5).
struct VersionWork {
    int64_t desired_version;
    uint288 work;
};

// WORK-WEIGHTED accumulation: sum each version's work over the window. This is the
// map get_desired_version_weights produces from a real chain window; exposed here so
// the KAT can exercise the exact weighting divergence without a live ShareChain.
inline std::map<uint64_t, uint288>
accumulate_version_weights(const std::vector<VersionWork>& window)
{
    std::map<uint64_t, uint288> res;
    for (const auto& vw : window)
        res[static_cast<uint64_t>(vw.desired_version)] += vw.work;
    return res;
}

// FLAT (plain-count) accumulation: one vote per share, work ignored. This is the
// count map the ratchet must NOT consume -- it exists only to PROVE, in the KAT,
// that the weighted decision diverges from the plain-count decision on a crafted
// window (matching the btc/dgb work-weighted-not-flat-count divergence assert).
inline std::map<uint64_t, uint288>
accumulate_version_counts(const std::vector<VersionWork>& window)
{
    std::map<uint64_t, uint288> res;
    for (const auto& vw : window)
        res[static_cast<uint64_t>(vw.desired_version)] += uint288(1);
    return res;
}

// Pure ratchet -- mirrors the dgb-scrypt oracle update_min_protocol_version dict
// branch (data.py:715-719):
//     minpver    = getattr(share.net, 'MINIMUM_PROTOCOL_VERSION', 1700)
//     newminpver = getattr(share.net, 'NEW_MINIMUM_PROTOCOL_VERSION', minpver)
//     if (counts is not None) and (minpver < newminpver):
//         if counts.get(share.VERSION, 0) >= sum(counts.itervalues())*95//100:
//             share.net.MINIMUM_PROTOCOL_VERSION = newminpver
//
// counts is the WORK-WEIGHTED map (get_desired_version_weights), keyed by
// desired_version and looked up by the best share's VERSION. Pure: no I/O, inputs
// unmutated; returns the (possibly lifted) floor.
//
// Integer math is the oracle's exactly: ratchet iff
//     best_weight >= floor(total_weight * 95 / 100).
// We floor-divide (total*95)/100 rather than the cross-multiplied
// best*100 >= total*95 idiom -- the two differ at the boundary when
// (total*95) % 100 != 0 (floor-div accepts best == floor(...), cross-mult rejects),
// and the oracle floor-divides. uint288 throughout: no IEEE-double, no overflow at
// consensus (2^256-scale) weights.
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

// Runtime WIRING decision -- the call-site guard the pure ratchet deliberately omits.
// ratchet_min_protocol_version mirrors ONLY the oracle dict-branch: over an empty or
// partial window it ratchets (0 >= 0), because the oracle's full-window guard lives
// at the CALL SITE (main.py: only update when len(shares) > CHAIN_LENGTH, sampling
// get_desired_version over [nth_parent(prev, CHAIN_LENGTH*9/10), CHAIN_LENGTH/10] --
// the SAME window the 60% version-switch gate reads, version_negotiation.hpp). Without
// this guard a fresh node (parent_height < CHAIN_LENGTH -> partial window) would
// spuriously lift the floor and reject every legitimate peer. This function is that
// guard: no lift until a FULL window exists behind the best share's parent, then
// delegate to the pure ratchet over the window the caller sampled.
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
    if (parent_height < chain_length)       // oracle: len(shares) > CHAIN_LENGTH
        return current_floor;               // no full window yet -> never lift
    return ratchet_min_protocol_version(
        window_weights, best_version, current_floor, target_floor);
}

}  // namespace dash