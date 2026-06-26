#pragma once

// SSOT for the DGB LOOKBEHIND chain-walk WINDOW clamp -- the pure integer guard
// every backward sharechain scan applies before calling forest.get_chain(). The
// same three-line pattern is open-coded in four share_tracker.hpp accessors:
//
//     auto height = chain.get_height(share_hash);
//     auto actual = std::min(static_cast<int32_t>(lookbehind), height);   // clamp
//     if (actual <= 0) return <empty>;                                    // guard
//     auto view = chain.get_chain(share_hash, actual);                    // walk
//
//   get_average_stale_prop      (share_tracker.hpp:2050)
//   get_stale_counts            (share_tracker.hpp:2072)
//   get_desired_version_counts  (share_tracker.hpp:2114)
//   get_desired_version_weights (share_tracker.hpp:2149)
//
// The clamp is the canonical p2pool windowing idiom: the caller asks for a
// `lookbehind` of N shares, but a head only `height` shares deep can yield at
// most `height` ancestors, so the realized window is min(lookbehind, height).
// A window of zero (genesis / shallower-than-1) must short-circuit to the empty
// result BEFORE the walk, exactly as the oracle does -- forest.get_chain over a
// zero count yields nothing and the per-share denominators (stale_count + actual)
// / weight maps degenerate.
//
// Oracle: p2pool-dgb-scrypt main.py status loop, which clamps every diagnostic
// lookbehind at the call site --
//     get_average_stale_prop(tracker, best, min(720, tracker.get_height(best)))
//     get_desired_version_counts(tracker, best, min(self.tracker.get_height(best), ...))
// -- and util/forest.py Tracker.get_chain(item_hash, n), which walks at most
// `n` parents and stops at the chain end. The clamp + (actual<=0) guard are the
// c2pool restatement of that min() and the implicit empty-walk.
//
// Two consensus-bearing consumers ride this window:
//   * get_desired_version_weights feeds the check()-phase 60% work-weighted v36
//     switch gate (share_check step 2) -- a drifted window would re-scope the
//     accept gate and break the p2pool-dgb-scrypt crossing-soak invariant.
//   * get_average_stale_prop / get_stale_counts feed efficiency diagnostics
//     (pool_efficiency.hpp) -- diagnostic, but pinned so a silent floor drift is
//     caught at compile-test time.
//
// Per-coin isolation: dgb/ only. Header-only, additive, free functions over the
// already-resolved (height, lookbehind) pair -- the get_chain skip-list walk
// stays in the forest. Delegation follow-on (mirrors #414 redistribute rewire):
// the two desired_version accessors -- get_desired_version_counts AND the
// consensus get_desired_version_weights (60%-by-work switch-gate input) -- now
// route their clamp through these helpers; get_average_stale_prop /
// get_stale_counts keep their inline std::min/(actual<=0) guards pending their
// own follow-on. The lifted body is a verbatim copy of the inline clamp (same
// int32_t height, same std::min, same <=0 comparison), proven value-identical by
// DgbChainWalkWindow.DelegationMatchesPreDelegationInline over a dense matrix.
// Consensus-neutral: pure arithmetic, no value semantics changed.

#include <algorithm>
#include <cstdint>

namespace dgb {

// Realized lookbehind window: the number of ancestors a backward get_chain walk
// from a head `height` shares deep will yield when asked for `lookbehind`.
//   p2pool/c2pool: actual = min(lookbehind, height)
// `lookbehind` is taken as int32_t here; the two uint64_t call sites
// (get_average_stale_prop / get_stale_counts) apply static_cast<int32_t> at the
// call exactly as today -- the cast stays at the call, so delegation is byte-id.
inline int32_t chain_walk_window_count(int32_t height, int32_t lookbehind)
{
    return std::min(lookbehind, height);
}

// Walk activation: the four accessors short-circuit to the empty result when the
// realized window is non-positive (genesis / shallower-than-one). Returns true
// when the get_chain walk should actually run.
//   c2pool: if (actual <= 0) return <empty>;  -> runs iff actual > 0
inline bool chain_walk_window_active(int32_t actual)
{
    return actual > 0;
}

} // namespace dgb
