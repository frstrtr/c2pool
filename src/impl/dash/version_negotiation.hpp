#pragma once

// Dash share-version transition negotiation (older-than-v35 -> v36).
//
// Conforms to frstrtr/p2pool-dash (OLDER oracle) — Option A, not a c2pool
// reinterpretation. Two distinct tallies, deliberately kept apart (the F10
// version-gate trap):
//
//   * get_desired_version_counts() — a PLAIN tally (one vote per share) over a
//     chain window. Reference: p2pool-dash data.py get_desired_version_counts
//     as consumed by Share.check()'s confirmed-state guard and by the
//     AutoRatchet desired-version selection. It is NOT weighted in place.
//
//   * get_desired_version_weights() — the SEPARATE WEIGHTED variant
//     (weight = target_to_average_attempts(target), i.e. expected hashes) the
//     v36 activation gate consumes. Reference: p2pool-merged-v36 work.py
//     v36_active = weight[36] / Sum(weight) >= 0.95.
//
// The confirmed-state guard (Share.check): a SUCCESSOR-version share may follow
// its predecessor only if the new version already holds >= 60% of the PLAIN
// votes in the [9/10 .. 10/10] tail of the CHAIN_LENGTH window; a switch with
// fewer than CHAIN_LENGTH ancestors is rejected ("without enough history").

#include "share_chain.hpp"   // dash::ShareChain, dash::DashShare

#include <core/target_utils.hpp>  // chain::target_to_average_attempts, bits_to_target
#include <core/uint256.hpp>       // uint256, uint288

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>

namespace dash::version_negotiation
{

// PLAIN desired-version tally over the `dist` shares ending at `start_hash`
// (inclusive, walking back via prev_hash). One vote per share. Mirrors the
// older p2pool-dash get_desired_version_counts as used by the SUCCESSOR
// tail-guard / AutoRatchet — do NOT add work weighting here (F10 trap).
inline std::map<uint64_t, uint64_t>
get_desired_version_counts(ShareChain& chain, const uint256& start_hash, uint64_t dist)
{
    std::map<uint64_t, uint64_t> res;
    if (!chain.contains(start_hash)) return res;
    const uint64_t n = std::min<uint64_t>(dist,
        static_cast<uint64_t>(chain.get_height(start_hash)));
    for (auto&& [h, data] : chain.get_chain(start_hash, n)) {
        (void)h;
        data.share.invoke([&](auto* obj) {
            using S = std::remove_pointer_t<decltype(obj)>;
            if constexpr (std::is_same_v<S, dash::DashShare>)
                res[obj->m_desired_version] += 1;
        });
    }
    return res;
}

// WEIGHTED desired-version tally: each share contributes its expected hash
// count (target_to_average_attempts of its target), matching ShareIndex::work.
// This is the variant the v36 activation gate consumes — kept separate from the
// plain count above.
inline std::map<uint64_t, uint288>
get_desired_version_weights(ShareChain& chain, const uint256& start_hash, uint64_t dist)
{
    std::map<uint64_t, uint288> res;
    if (!chain.contains(start_hash)) return res;
    const uint64_t n = std::min<uint64_t>(dist,
        static_cast<uint64_t>(chain.get_height(start_hash)));
    for (auto&& [h, data] : chain.get_chain(start_hash, n)) {
        (void)h;
        data.share.invoke([&](auto* obj) {
            using S = std::remove_pointer_t<decltype(obj)>;
            if constexpr (std::is_same_v<S, dash::DashShare>) {
                uint288 w = chain::target_to_average_attempts(
                    chain::bits_to_target(obj->m_bits));
                res[obj->m_desired_version] += w;
            }
        });
    }
    return res;
}

// 60% confirmed-state guard (p2pool-dash data.py Share.check). A SUCCESSOR
// share is accepted only when its PLAIN vote count reaches floor(total*60/100).
// The floor matches the oracle's integer `sum*60//100` exactly (e.g. 4/7 votes
// clears thr=4, 3/7 does not).
inline bool
successor_switch_allowed(const std::map<uint64_t, uint64_t>& plain_counts,
                         uint64_t successor_version)
{
    uint64_t total = 0;
    for (const auto& [v, c] : plain_counts) total += c;
    if (total == 0) return false;
    const uint64_t threshold = (total * 60) / 100;  // floor, as in the oracle
    auto it = plain_counts.find(successor_version);
    const uint64_t have = (it == plain_counts.end()) ? 0 : it->second;
    return have >= threshold;
}

// v36 activation gate (p2pool-merged-v36 work.py): v36 is active once its
// WEIGHTED signaling reaches >= 95% of total work. Evaluated as the exact
// rational w36*100 >= total*95 — integer uint288, no IEEE-double fragility.
inline bool
v36_active(const std::map<uint64_t, uint288>& weights, uint64_t v36_version = 36)
{
    uint288 total(0);
    for (const auto& [v, w] : weights) total += w;
    if (total == uint288(0)) return false;
    auto it = weights.find(v36_version);
    uint288 w36 = (it == weights.end()) ? uint288(0) : it->second;
    return w36 * uint288(100) >= total * uint288(95);
}

// Window helper mirroring Share.check: negotiation looks at the [9/10 .. 10/10]
// tail of the CHAIN_LENGTH ancestry behind `prev_hash`. Returns nullopt when
// fewer than `chain_length` ancestors exist ("switch without enough history").
struct Window { uint256 start_hash; uint64_t dist; };
inline std::optional<Window>
negotiation_window(ShareChain& chain, const uint256& prev_hash, uint64_t chain_length)
{
    if (chain.get_height(prev_hash) < static_cast<int64_t>(chain_length))
        return std::nullopt;
    const uint64_t back = (chain_length * 9) / 10;
    const uint64_t dist = chain_length / 10;
    uint256 start = chain.get_nth_parent_key(prev_hash, static_cast<int32_t>(back));
    return Window{start, dist};
}

} // namespace dash::version_negotiation
