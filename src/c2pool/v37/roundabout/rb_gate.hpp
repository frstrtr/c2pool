#pragma once
// S5 — RoundaboutGate: the ADD-ONLY roundabout-split parameter set, default OFF.
//
// Pattern: ::v37::SubthresholdGate (src/sharechain/v37/v37_lane.hpp:55-95) —
// a plain struct with a for_version(v) factory that is the single source of
// truth for version -> gate config. DEFAULT OFF: k = 1 (one roundabout), which
// is the pre-split pool on every schedule.
//
// Why standalone and not a LaneParams field: LaneParams lives in the consensus
// canon (v37_lane.hpp), which this lane may not edit. The wiring seam is one
// field + one factory line (see README.md "S5 seam"); because LaneParams'
// build_leaves header leaf (v37_lane.hpp:2869-2879) appends only the explicit
// geometry fields and geometry_is_ratified (w4_settlement.hpp:427-471) reads
// only window/c0/rollup/half_life/level_caps + nr + win, a RoundaboutGate
// member appends NOTHING to any digest while OFF. The gate-off KAT
// (v37_rb_gate_off_kat) re-derives the pinned lane digest golden with this
// header in the same TU to hold that line.
//
// Units (integer only — no floats in any consensus path):
//   H_ref_per_s   reference hashrate of ONE roundabout, in the SAME raw-work
//                 units per second as the finalized raw work fed to the map
//                 derivation (D3: a PARAM per coin; BTC candidate 86 PH/s).
//   bin_seconds   nominal seconds per bin (BTC 600, XMR 120); the map period
//                 is E_map_bins * bin_seconds seconds.
//   S             stripes per unit of reference work: u = H_ref / S (D2/D5).
//   eps           bounded-load slack: cap = ceil((1+eps) * mean load) (D5).
//   delta         split/merge hysteresis (D2 trigger; D5 = 1/8).
//   E_map_bins    map period in bins (D4: ~1 day = 144 BTC / 720 XMR).
//   ckpt_bins     summary/checkpoint cadence in bins (D4: ~64).
//   k_max         maximum roundabouts (power of two, <= S).
//   miss_grace    G: a roundabout whose summary is missing for G consecutive
//                 periods contributes W = 0 (decayed before that); a missing
//                 summary never vetoes the map.

#include <cstdint>

#include "rb_params.hpp"

namespace c2pool::v37n::rb {

struct RoundaboutGate {
    std::uint32_t version = 0;       // 0 = OFF (base). Nonzero = split rules live.
    u64           H_ref_per_s = 0;   // D3 per-coin PARAM (0 while OFF)
    u64           bin_seconds = 0;   // seconds per bin (0 while OFF)
    std::uint32_t S = 256;           // D5
    std::uint32_t eps_num = 1;       // D5 eps = 1/4 (heuristic; measured by churn KAT)
    std::uint32_t eps_den = 4;
    std::uint32_t delta_num = 1;     // D5 delta = 1/8
    std::uint32_t delta_den = 8;
    u64           E_map_bins = 0;    // D4 map period (0 while OFF)
    u64           ckpt_bins = 0;     // D4 summary cadence (0 while OFF)
    std::uint32_t k_max = 1;         // ★ DEFAULT 1 => one roundabout => OFF
    std::uint32_t miss_grace = 4;    // G

    bool enabled() const { return version != 0 && k_max > 1; }
    bool is_off() const { return !enabled(); }

    // Structural validity of an ENABLED gate. An OFF gate is always valid (it
    // is never consulted). Checked by the map derivation; an ill-formed gate
    // derives the k = 1 map (fail-safe: never guesses a partition).
    bool well_formed() const {
        if (is_off()) return true;
        if (!is_pow2_u64(S) || S > 65536u) return false;          // stripe is u16
        if (!is_pow2_u64(k_max) || k_max > S) return false;
        if (eps_den == 0 || delta_den == 0) return false;
        if (eps_den > 65536u || eps_num > 65536u || delta_den > 65536u) return false;
        if (delta_num >= delta_den) return false;                 // delta < 1
        if (H_ref_per_s == 0 || bin_seconds == 0) return false;
        if (bin_seconds > (1u << 20)) return false;               // u128 headroom
        if (E_map_bins == 0 || E_map_bins > (1u << 24)) return false;
        if (ckpt_bins == 0 || ckpt_bins > E_map_bins) return false;
        if (miss_grace == 0 || miss_grace > 63) return false;
        return true;
    }

    // Map period length in seconds (u128: never overflows for sane params).
    u128 period_seconds() const { return u128(E_map_bins) * bin_seconds; }

    // ── CANONICAL version -> gate map (ADD-ONLY). EVERY version, known or
    // not, returns the OFF gate today: the roundabout split is not activated by
    // any shipped consensus version. Activation = adding a `v == N` arm here
    // that returns a candidate() profile — a consensus change, operator's hand.
    static RoundaboutGate for_version(std::uint32_t /*v*/) {
        return RoundaboutGate{};   // OFF: version 0, k_max 1
    }

    // Design-of-record candidate profiles (NOT selected by for_version; they
    // exist so KATs and the operator can exercise the ON path). H_ref stays a
    // parameter (D3).
    static RoundaboutGate candidate(u64 H_ref_per_s, u64 bin_seconds,
                                    u64 E_map_bins, std::uint32_t k_max = 64) {
        RoundaboutGate g{};
        g.version = 1;
        g.H_ref_per_s = H_ref_per_s;
        g.bin_seconds = bin_seconds;
        g.E_map_bins = E_map_bins;
        g.ckpt_bins = 64;
        g.k_max = k_max;
        return g;
    }
    // BTC: 86 PH/s candidate (D3), 600 s bins, 144-bin (~1 day) map period.
    static RoundaboutGate btc_candidate(u64 H_ref_per_s = 86000000000000000ull) {
        return candidate(H_ref_per_s, 600, 144);
    }
    // XMR: H_ref is an operator PARAM (no ruled number yet), 120 s bins,
    // 720-bin (~1 day) map period.
    static RoundaboutGate xmr_candidate(u64 H_ref_per_s) {
        return candidate(H_ref_per_s, 120, 720);
    }

    bool operator==(const RoundaboutGate&) const = default;
};

}  // namespace c2pool::v37n::rb
