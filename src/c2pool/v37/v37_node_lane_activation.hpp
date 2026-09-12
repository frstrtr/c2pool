#pragma once
// ============================================================================
// V37 consumer seam T1 — the NODE LANE FACTORY, and the one place a live node's
// consensus version is chosen.
//
// WHAT THIS IS FOR
//   Every live v37 node builds its lane from `::v37::LaneParams{}` — the V37.0
//   base, with EVERY gate OFF. So a shipped node runs neither the V37.1 native
//   ridge nor DROPS, no matter what the canon declares. Before this header the
//   V37.0 default was written out THREE times, in three files, and flipping the
//   fleet meant editing all three consistently. Here it is written ONCE.
//
//   This header CHANGES NOTHING BY DEFAULT. node_lane_params() returns exactly
//   `::v37::LaneParams{}` unless V37_ACTIVATE_CONSENSUS_V1 is defined non-zero
//   at build time, so every owed_digest, lane digest and receipt/share digest on
//   a default build is byte-identical to master. It is the SEAM, not the flip.
//
// ★★ THE FLIP IS A CONSENSUS ACTIVATION AND IT IS THE OPERATOR'S HAND
//   Defining V37_ACTIVATE_CONSENSUS_V1=1 is a FLEET FLAG DAY. Nodes that have
//   it and nodes that do not will not agree on owed_digest once either of the
//   two gates it opens actually moves a value. It must be taken deliberately,
//   fleet-wide, at a ruled height — never as a build-config accident.
//
// ★★ AND IT IS COUPLED: ONE SWITCH, TWO ACTIVATIONS
//   `::v37::LaneParams::for_version(1, LaneKind)` folds
//   `nr::for_version(1, lane)` into the lane, which bakes
//   `mrr.activation_pos = nr.nr_activation_pos = 4096`. So the two-argument
//   factory turns on the V37.1 NATIVE RIDGE (Shape A, position 4096) AT THE SAME
//   TIME as it turns on DROPS. They are not separable through this factory:
//     - for_version(1, lane)  => DROPS ON  *and*  V37.1 ridge ON   (P = 4096)
//     - for_version(1)        => DROPS ON  *and*  V37.1 ridge OFF
//       (the 1-argument factory names no parent LaneKind, so it carries no ridge
//        dimensions; v37_lane.hpp states it stays byte-identical to
//        for_version(0) on the lane digest)
//   An operator who wants only one of the two must therefore choose the ARITY,
//   and that choice is recorded below as kActivationArity.
//
//   ★★ RULED: DECOUPLE. kActivationArity is 1 — the flip activates DROPS AND
//   NOTHING ELSE. The earlier default was 2, on the reasoning that one flag day
//   beats two; the operator ruling reverses it, and the reason belongs next to
//   the constant. DROPS and the V37.1 ridge answer to DIFFERENT evidence: DROPS
//   is a payout-composition change whose live behaviour depends on an enrolment
//   set that exists on no fleet yet, while the ridge is a lane-geometry change
//   already minted at golden 87c5249a and wholly independent of who is enrolled.
//   Binding them means a fleet that has to roll one back rolls back both. At
//   arity 1 the ridge flip stays available as its own, separately ruled flag day.
//
//   WHAT THIS COSTS, STATED PLAINLY. The DROPS activation mint 984c7753 was
//   composed over `for_version(1, LaneKind)`, i.e. with the ridge ON. At arity 1
//   a live node's geometry is `for_version(1)` — DROPS on, ridge OFF — so the
//   fleet's owed_digest over that same schedule is NOT 984c7753. That golden
//   pins the CANON ACTIVATION SCHEDULE and the composition rule, which is what
//   it exists for; it is not the arity-1 fleet value, and this header does not
//   pretend it is. Whichever arity is taken, every node must take the SAME one —
//   that is what makes it a flag day.
//
// ★★ XMR HAS NO RATIFIED LaneKind
//   nr_ladder.hpp declares `enum class LaneKind { BTC, LTC, DASH, DOGE }`. There
//   is no XMR row, so the XMR lane CANNOT take the two-argument factory and
//   node_lane_params_no_kind() is what it must use: DROPS ON, native ridge
//   declared OFF. Adding an XMR ridge row is a canon edit to
//   src/sharechain/v37/nr_ladder.hpp whose constants are not derivable from
//   anything in this tree — an operator ruling (ND-R6), not a port. This is the
//   one place where "ALL lanes" is not expressible today, and it is stated here
//   rather than papered over.
// ============================================================================
#include <sharechain/v37/v37_lane.hpp>       // ::v37::LaneParams, LaneKind,
                                             // SHIPPED_CONSENSUS_VERSION

namespace c2pool::v37n {

// The build-time consensus-activation switch. 0 == V37.0 base (the shipped
// default, byte-identical to master). 1 == V37.1: DROPS + (by arity) the native
// ridge. Set it ONLY through the build system, fleet-wide, at a ruled flag day.
#ifndef V37_ACTIVATE_CONSENSUS_V1
#define V37_ACTIVATE_CONSENSUS_V1 0
#endif

inline constexpr bool kActivateConsensusV1 = (V37_ACTIVATE_CONSENSUS_V1 != 0);

// Which factory arity the flip uses when it is taken. 2 == for_version(v, lane):
// DROPS ON and the V37.1 native ridge ON (P = 4096). 1 == for_version(v): DROPS
// ON, ridge OFF. ★ RULED 1 (DECOUPLE) — see the coupling note above; changing
// it is a second, equally deliberate ruling and a second flag day.
inline constexpr int kActivationArity = 1;

// The lane geometry a live node on a RATIFIED LaneKind builds.
//   OFF (default) => ::v37::LaneParams{}, the OQ-5 ratified V37.0 default and
//                    the only geometry W4's geometry_is_ratified() admits today
//                    without the ridge dimensions.
//   ON            => the SHIPPED consensus version for this lane.
inline ::v37::LaneParams node_lane_params(::v37::LaneKind lane) {
    if constexpr (!kActivateConsensusV1) {
        (void)lane;
        return ::v37::LaneParams{};
    } else if constexpr (kActivationArity == 2) {
        return ::v37::LaneParams::for_version(::v37::SHIPPED_CONSENSUS_VERSION,
                                              lane);
    } else {
        (void)lane;
        return ::v37::LaneParams::for_version(::v37::SHIPPED_CONSENSUS_VERSION);
    }
}

// The lane geometry for a lane with NO ratified LaneKind row (XMR). Carries the
// consensus version WITHOUT ridge dimensions, because there are none to carry.
inline ::v37::LaneParams node_lane_params_no_kind() {
    if constexpr (!kActivateConsensusV1) return ::v37::LaneParams{};
    else return ::v37::LaneParams::for_version(::v37::SHIPPED_CONSENSUS_VERSION);
}

} // namespace c2pool::v37n
