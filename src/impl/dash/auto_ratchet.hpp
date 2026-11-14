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

#include <core/netaddress.hpp>  // NetService (share peer_addr = reception origin)
#include <core/uint256.hpp>  // uint288

#include <cstdint>
#include <map>
#include <set>
#include <vector>

namespace dash {

// Distinct-origin precondition (#920; DASH port of the LTC guard, #930 + #1362).
// A 95% supermajority is necessary but NOT sufficient to lift the floor: the YES-
// votes in the ratchet window must trace to at least MIN_DISTINCT_ORIGINS distinct
// origins. An "origin" is the self node (every locally minted YES-vote collapses to
// ONE origin) plus each distinct non-self peer_addr among the received YES-votes.
//
// Without it, any node alone on its sharechain -- a fresh chain, a testnet, a
// partitioned segment, a node whose peers all dropped -- is trivially 100% of its
// own window and ratchets itself 1700 -> 3600, partitioning from every legacy 1700
// peer: the #774 outcome (absence read as assent) reached by the opposite route
// (a real but SELF-AUTHORED supermajority). Counting self as one origin and
// requiring >= 2 also closes the relayed shape: a supermajority authored by one
// entity and injected through ONE peer connection.
//
// LEGITIMATE SMALL POOLS: a 2-operator crossing still fires -- each node sees its
// own YES-votes (self) plus the other's relayed YES-votes (one non-self origin)
// = 2. A pool that is genuinely ONE node never auto-ratchets; the floor stays at
// the legacy 1700, which admits every peer, so the guard can only DELAY our own
// floor lift, never change any share's validity or work (peer_addr is transient
// reception metadata, never serialized into the share hash).
//
// LIMITATION (same as LTC): origins are counted by reception address, so one
// operator holding N addresses can still simulate N origins. This raises the floor
// from 1 to 2; it is not a sybil-proof identity check.
inline constexpr int MIN_DISTINCT_ORIGINS = 2;

// A single share's vote and reception origin, as read off the ratchet window.
struct VoteOrigin {
    int64_t    desired_version;
    NetService peer_addr;
};

// Canonical "locally minted" test, identical to LTC's: a local share carries the
// default NetService{} or 0.0.0.0:0; a network share carries the relaying peer.
// Shares restored from LevelDB also load with NetService{} and so count as self --
// conservative (it can only reduce the distinct count, i.e. delay, never lift).
inline bool is_self_origin(const NetService& peer_addr)
{
    return peer_addr == NetService{} || peer_addr == NetService{"0.0.0.0", 0};
}

// Distinct origins among the shares voting desired_version >= yes_version. Pure.
inline int count_distinct_yes_origins(const std::vector<VoteOrigin>& window,
                                      int64_t yes_version)
{
    bool self_yes = false;
    std::set<NetService> nonself;
    for (const auto& v : window) {
        if (v.desired_version < yes_version)
            continue;
        if (is_self_origin(v.peer_addr))
            self_yes = true;
        else
            nonself.insert(v.peer_addr);
    }
    return static_cast<int>(nonself.size()) + (self_yes ? 1 : 0);
}

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
//
// distinct_origins is count_distinct_yes_origins over that SAME window. It is a
// required argument (no default) so no call site can skip the #920 precondition.
// c2pool-native: the oracle has no origin rule (it ratchets on weight alone).
inline uint32_t apply_min_protocol_ratchet_decision(
    int32_t  parent_height,
    int32_t  chain_length,
    const std::map<uint64_t, uint288>& window_weights,
    int64_t  best_version,
    uint32_t current_floor,
    uint32_t target_floor,
    int      distinct_origins)
{
    if (current_floor >= target_floor)      // oracle guard: minpver < newminpver
        return current_floor;
    if (parent_height < chain_length)       // oracle: len(shares) > CHAIN_LENGTH
        return current_floor;               // no full window yet -> never lift
    if (distinct_origins < MIN_DISTINCT_ORIGINS)  // #920: single origin -> never lift
        return current_floor;
    return ratchet_min_protocol_version(
        window_weights, best_version, current_floor, target_floor);
}

}  // namespace dash