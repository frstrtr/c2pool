#pragma once

/// PILLAR 4 (donation gate) — Phase B scaffolding STUB.
///
/// RESOLVED (integrator 06-16, independently verified against merged-v36 @ 42ccca53):
/// DGB donation is the GLOBAL p2pool script, NOT a per-network value. DGB's
/// networks/digibyte.py defines no donation, so DGB inherits data.py:118 (pre-V36
/// P2PK, forrestv) / data.py:131 (V36+ COMBINED P2SH 1-of-2) identically to LTC/DOGE.
/// The legacy farsider350 p2pool-dgb-scrypt-350 2-of-3 P2MS is the standalone-network
/// donation and is SUPERSEDED for the v36 compat target (using it would break gentx
/// parity). config_pool.hpp::get_donation_script + params.hpp::make_coin_params now
/// both carry the global bytes with the same >=36 gate.
///
/// COMPAT: donation consensus math is shared base — must match p2pool-merged-v36.
/// Divergence => [decision-needed].

#include "config_pool.hpp"

namespace dgb
{

// TODO(Phase B): port ltc/donation_consensus.hpp per-share donation accounting /
// consensus enforcement on top of the (now resolved) global script selection.

} // namespace dgb
