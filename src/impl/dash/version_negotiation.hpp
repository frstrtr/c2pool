#pragma once

// Dash share-version transition negotiation (older-than-v35 -> v36).
//
// Conforms to frstrtr/p2pool-dash (OLDER oracle) — Option A, not a c2pool
// reinterpretation. Two distinct tallies, deliberately kept apart (the F10
// version-gate trap):
//
//   * get_desired_version_counts() — a PLAIN tally (one vote per share) over a
//     chain window. Reference: p2pool-dash data.py get_desired_version_counts
//     as consumed by the AutoRatchet desired-version selection and the VOTING
//     tail guard (F10 keeps these count-based). It is NOT weighted in place.
//
//   * get_desired_version_weights() — the SEPARATE WEIGHTED variant
//     (weight = target_to_average_attempts(target), i.e. expected hashes) that
//     BOTH consensus gates consume: the 60% SUCCESSOR switch gate (D1) and the
//     95% v36 activation gate. Reference: p2pool data.py:1396-1414 (60% switch,
//     PPLNS-weighted) + p2pool-merged-v36 work.py v36_active = weight[36] /
//     Sum(weight) >= 0.95.
//
// The confirmed-state guard (Share.check): a SUCCESSOR-version share may follow
// its predecessor only if the new version already holds >= 60% of the WEIGHTED
// desired-version tally in the [9/10 .. 10/10] tail of the CHAIN_LENGTH window; a switch with
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

// 60% switch gate (canonical v36-native -- F10 685669e9 share_check.hpp step 2;
// p2pool data.py:1396-1414). A SUCCESSOR-version share is accepted only when the
// new version holds >= 60% of the PPLNS-WEIGHTED desired-version tally (weight =
// target_to_average_attempts per share), via the exact rational
// new_ver_weight*100 >= total_weight*60 -- integer uint288, no IEEE-double and no
// floor. D1 standardization: the weighted tally (get_desired_version_weights)
// feeds this consensus gate; the PLAIN count (get_desired_version_counts) is
// retained for AutoRatchet + the VOTING tail guard only (D4). F10 deleted the
// old flat-count validate_version_switch precisely because flat-count diverges.
inline bool
successor_switch_allowed(const std::map<uint64_t, uint288>& weights,
                         uint64_t successor_version)
{
    uint288 total(0);
    for (const auto& [v, w] : weights) total += w;
    if (total == uint288(0)) return false;
    auto it = weights.find(successor_version);
    const uint288 have = (it == weights.end()) ? uint288(0) : it->second;
    return have * uint288(100) >= total * uint288(60);
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

// ── D2: unified 5-case version-switch classifier (F10 share_check.hpp step 2) ─
// successor_switch_allowed() answers ONLY the 60% upgrade threshold. The
// canonical v36-native shape (F10 share_check step 2; p2pool-dash data.py
// Share.check) classifies a proposed predecessor->desired version transition
// into five cases -- the threshold gate is just the body of ONE of them:
//
//   Same                desired == prev          -> always allowed (continuation)
//   SuccessorGated      desired == prev + 1      -> allowed IFF the 60% weighted
//                                                   gate (successor_switch_allowed)
//                                                   clears over the window
//   PredecessorAllowed  desired == prev - 1      -> always allowed (downgrade-by-one
//                                                   rollback; needs no support window)
//   InvalidJump         |desired - prev| > 1     -> rejected (no version skipping)
//   NoHistory           a +1 switch is proposed  -> rejected ("switch without enough
//                       with < CHAIN_LENGTH         history"): the support window
//                       ancestors                   cannot be evaluated
//
// no-history applies ONLY to the +1 successor case -- it is the one transition
// that needs the support window; Same/Predecessor need no window, an InvalidJump
// is rejected on structure regardless of history. DASH previously expressed only
// negotiation_window() + the threshold; this folds them into the canonical shape.
// Pure + scaffolding-only (no live share_check caller) -- zero consensus risk.
enum class SwitchClass : uint8_t {
    Same               = 0,  // desired == prev               -- allow
    SuccessorGated     = 1,  // desired == prev + 1           -- allow iff 60% gate clears
    PredecessorAllowed = 2,  // desired == prev - 1           -- allow (rollback)
    InvalidJump        = 3,  // |desired - prev| > 1          -- reject
    NoHistory          = 4,  // +1 switch, < CHAIN_LENGTH anc -- reject (no support window)
};

// Classify the predecessor->desired transition. `has_history` is whether the
// support window exists (>= CHAIN_LENGTH ancestors), i.e. negotiation_window()
// returned a value; it only changes the verdict for the +1 successor case.
inline SwitchClass
classify_switch(uint64_t prev_version, uint64_t desired_version, bool has_history)
{
    if (desired_version == prev_version)     return SwitchClass::Same;
    if (desired_version == prev_version - 1) return SwitchClass::PredecessorAllowed;
    if (desired_version == prev_version + 1)
        return has_history ? SwitchClass::SuccessorGated : SwitchClass::NoHistory;
    return SwitchClass::InvalidJump;  // |delta| > 1
}

// Final accept decision for a classified transition. SuccessorGated defers to the
// 60% weighted gate result (`gate_cleared` = successor_switch_allowed over the
// window); every other case is decided structurally. Mirrors F10 step 2 exactly.
inline bool
switch_accepted(SwitchClass cls, bool gate_cleared)
{
    switch (cls) {
        case SwitchClass::Same:
        case SwitchClass::PredecessorAllowed: return true;
        case SwitchClass::SuccessorGated:     return gate_cleared;
        case SwitchClass::InvalidJump:
        case SwitchClass::NoHistory:          return false;
    }
    return false;
}

} // namespace dash::version_negotiation
