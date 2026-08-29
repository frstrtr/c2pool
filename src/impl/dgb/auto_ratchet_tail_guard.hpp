// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// AutoRatchet tail-guard SSOT (DGB Phase-B conformance pillar).
//
// Single source of truth for the WORK-WEIGHTED 60% tail guard that
// AutoRatchet::get_share_version evaluates over the oldest 10% of the
// activation window [9/10*CHAIN_LENGTH, CHAIN_LENGTH] before it may transition
// VOTING -> ACTIVATED. This is the mint<->accept coupling that stops a
// 95%-by-COUNT activation from outrunning the 60%-by-WORK accept gate
// (share_check step 2 / p2pool check() data.py:1399): without it a node mints
// a V36 boundary share every mature peer rejects and the crossing wedges.
//
// Oracle: frstrtr/p2pool-dgb-scrypt data.py get_desired_version_counts weights
// each share by target_to_average_attempts(target) = WORK (data.py:2651), and
// the canonical switch rule (data.py:1399) reads:
//
//     if counts.get(VERSION, 0) < sum(counts.itervalues()) * 60 // 100:
//         <stay on old format>            # i.e. NOT switched
//
// i.e.  SWITCHED  iff  target_weight >= floor(total_weight * 60 / 100).
//
// CONFORMANCE NOTE (divergence flagged to integrator/decisions 2026-06-24):
// the live inline in auto_ratchet.hpp computes the negation as
//     tail_target * 100 < tail_total * 60
// which is the EXACT-RATIONAL test target < total*60/100, NOT the canonical
// FLOOR test target < floor(total*60/100). The two differ in exactly one case
// -- target == floor(total*60/100) AND (total*60) % 100 != 0 -- where the
// inline waits one extra work-quantum (negligibly STRICTER; never observed
// with real uint288 work weights, but a formal divergence from the oracle).
// This SSOT implements the EXACT canonical floor expression so a future
// delegation makes the inline byte-faithful to the oracle. auto_ratchet.hpp is
// NOT rewired here (delegation is the byte-identity follow-on); this header is
// additive + FENCED (dgb-tree-local, consensus path untouched).

#include <core/uint256.hpp>   // uint288 work-weight accumulator
#include <cstdint>
#include <utility>

namespace dgb::auto_ratchet
{

inline constexpr int SWITCH_THRESHOLD = 60;  // % work required to switch format

// Reduce a desired-version -> work-weight map into
//   {weight voting version >= target, total weight}.
// Mirrors the inline accumulation in AutoRatchet::get_share_version verbatim
// (uint288 default-initialises to 0; map iteration order is version-ascending
// but the sum is order-independent).
template <typename WeightMap>
inline std::pair<typename WeightMap::mapped_type, typename WeightMap::mapped_type>
reduce_target_total(const WeightMap& weights, int64_t target_version)
{
    using W = typename WeightMap::mapped_type;
    W target{}, total{};
    for (const auto& kv : weights) {
        total = total + kv.second;
        if (static_cast<int64_t>(kv.first) >= target_version)
            target = target + kv.second;
    }
    return {target, total};
}

// Canonical p2pool switch predicate (data.py:1399) with EXACT floor semantics:
//   SWITCHED  iff  target_weight >= floor(total_weight * threshold / 100).
// Returns true when the work-weighted V>=target support meets the gate
// (== tail guard PASSES, AutoRatchet may proceed VOTING -> ACTIVATED).
template <typename W>
inline bool switched(const W& target_weight, const W& total_weight,
                     int switch_threshold = SWITCH_THRESHOLD)
{
    // floor(total * thr / 100) on the unsigned work accumulator. base_uint
    // multiply takes uint32_t; divide takes the same width, so wrap 100 in W.
    W floor_gate = (total_weight * static_cast<uint32_t>(switch_threshold))
                   / W(static_cast<uint64_t>(100));
    return !(target_weight < floor_gate);
}

// Convenience: reduce a weight map and apply the canonical switch gate.
template <typename WeightMap>
inline bool tail_guard_passes(const WeightMap& weights, int64_t target_version,
                              int switch_threshold = SWITCH_THRESHOLD)
{
    auto tt = reduce_target_total(weights, target_version);
    return switched(tt.first, tt.second, switch_threshold);
}

} // namespace dgb::auto_ratchet