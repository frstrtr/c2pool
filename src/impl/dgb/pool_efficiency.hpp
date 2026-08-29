// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SSOT for the DGB pool EFFICIENCY / REAL-HASHRATE diagnostics — the two pure
// arithmetic steps the status loop applies when reporting pool performance:
//   (a) the stale proportion over a recent share window, and
//   (b) the efficiency-adjusted "real" pool hashrate that scales the raw
//       attempts/s up to compensate for stale (orphan + DOA) work.
//
// These are currently OPEN-CODED inline in node.cpp's diagnostics loop (the
// `stale_prop = (orphan + doa) / total_recent` reduction and the
// `real_pool_hs = pool_hs / (1 - stale_prop)` guarded division feeding the
// "Pool: <hashrate>  Expected time to block:" line). A silent drift — a flipped
// guard, a wrong denominator, or dropping the div-by-~0 floor — would misreport
// a node's effective hashrate and expected-time-to-block with NO compile error,
// which is operator-facing behavior the V36 master-compat invariant pins to the
// p2pool reference. Lifting the arithmetic to a single header-only SSOT lets a
// KAT pin it exactly against the oracle.
//
// Oracle: p2pool-dgb-scrypt main.py status loop:
//     real_att_s = p2pool_data.get_pool_attempts_per_second(...) / (1 - stale_prop)
//   with stale_prop derived from the recent orphan/DOA counts over the window,
//   and the (1 - stale_prop) division guarded against the empty / ~all-stale
//   case so it never divides by ~zero.
//
// Per-coin isolation: dgb/ only. Header-only, additive; this slice does NOT yet
// rewire node.cpp (that is the byte-identity-fenced delegation follow-on) — it
// pins the math as free functions so the KAT exercises them with no NodeImpl /
// ShareTracker standup. Consensus-neutral: pure arithmetic, no value semantics
// changed.

#include <cstdint>

namespace dgb {

// Stale proportion over a recent share window.
//   stale_prop = (orphan_count + doa_count) / total_recent
// An empty window (total_recent == 0) reports 0.0 rather than NaN, matching the
// inline reduction in node.cpp's diagnostics loop.
inline double compute_stale_prop(uint64_t orphan_count, uint64_t doa_count,
                                 uint64_t total_recent) {
    if (total_recent == 0)
        return 0.0;
    return static_cast<double>(orphan_count + doa_count) /
           static_cast<double>(total_recent);
}

// Efficiency-adjusted "real" pool hashrate.
//   real = pool_hs / (1 - stale_prop)   when stale_prop < 0.999 AND pool_hs > 0
//   real = pool_hs                      otherwise
// The guard mirrors the oracle: when stale_prop approaches 1 (≥ 0.999) the
// (1 - stale_prop) denominator approaches zero and the adjustment is suppressed
// to avoid a blow-up; with no measured hashrate (pool_hs <= 0) there is nothing
// to scale.
inline double compute_real_pool_hashrate(double pool_hs, double stale_prop) {
    if (stale_prop < 0.999 && pool_hs > 0)
        return pool_hs / (1.0 - stale_prop);
    return pool_hs;
}

} // namespace dgb