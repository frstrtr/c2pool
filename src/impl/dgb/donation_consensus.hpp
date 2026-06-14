#pragma once

/// PILLAR 4 (donation gate) — Phase B scaffolding STUB, GATED.
///
/// GATE: donation reconcile (ltc-doge + operator). DGB pre-v36 donation is
/// farsider350 2-of-3 P2MS (105 bytes), NOT LTC 67B P2PK — verified ground
/// truth (see [[dgb-canonical-base-and-donation]]). The version-gate itself
/// already LANDED in config_pool.hpp::get_donation_script (PR #82, 46fbdd18):
/// farsider350-2of3 for version < 36, COMBINED_DONATION_SCRIPT for >= 36.
///
/// This module ports ltc::donation_consensus (per-share donation accounting /
/// consensus enforcement) on TOP of that already-landed script selection.
/// It stays a STUB until integrator routes the farsider350-vs-LTC reconcile
/// with ltc-doge + operator at Phase B start (per integrator 06-11 18:29).
///
/// COMPAT: donation consensus math is shared base — must match
/// p2pool-merged-v36. Divergence => [decision-needed].

#include "config_pool.hpp"

namespace dgb
{

// TODO(Phase B, reconcile-gated): port ltc/donation_consensus.hpp.
// config_pool::get_donation_script(version) is ALREADY version-gated; this
// module enforces the per-share donation against that selection. Folds the
// landed pillar-4 gate, no re-port (integrator confirmed #82 stays).

} // namespace dgb
