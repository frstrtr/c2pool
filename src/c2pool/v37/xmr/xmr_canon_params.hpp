// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// src/c2pool/v37/xmr/xmr_canon_params.hpp -- lane constants of the canonical
// coinbase rule (LaneParams::canon, xmr_canonical_coinbase.hpp).
#pragma once

#include <cstdint>
#include <string>

namespace c2pool::v37n::xmr {

// Total-outputs cap C of a canonical lane coinbase. Under the canon gate the cap
// is a LANE CONSTANT, not the weight-aware value the assembler derives from the
// transaction set: a peer that recomputes the coinbase does not know the
// builder's mempool, so a tx-dependent cap would make the canonical payee set
// unverifiable. 256 outputs are ~10 kB, far below the 300 kB penalty-free zone,
// so the constant never costs reward; a ledger with more owed keys than this is
// paid oldest-first over successive blocks (K_fair), as before.
inline constexpr std::uint32_t kCanonOutputCap = 256;

// The start-up rules of the canon gate. Pure, so the daemon refuses on the very
// function the KAT pins. Empty = accepted.
//   * an enabled gate must be a known version;
//   * canon shapes the v37 settlement coinbase and is meaningful only with the
//     mandatory donation output (fee model v1: the residual sink IS that output,
//     so the canonical output set has no node-local absorber) and the lane-constant
//     cap (--settle-output-cap would override it);
//   * MAINNET runs both gates from genesis: a mainnet lane that admits a
//     non-canonical coinbase or a per-node residual sink has no rule to verify.
inline std::string canon_refusal(bool mainnet, bool coinbase_v37, bool fee_on, bool canon_on,
                                 std::uint32_t canon_version, std::uint32_t settle_output_cap) {
    if (canon_on && canon_version != 1)
        return "unknown --canonical-coinbase version " + std::to_string(canon_version);
    if (mainnet && coinbase_v37 && !fee_on)
        return "mainnet runs the fee model v1 from genesis (the donation output is the one protocol residual sink "
               "the canonical coinbase can verify): pass --fee-model v1";
    if (mainnet && coinbase_v37 && !canon_on)
        return "mainnet runs the canonical-coinbase rule from genesis (a peer recomputes the payout before it "
               "credits a block): pass --canonical-coinbase v1";
    if (canon_on && !coinbase_v37)
        return "--canonical-coinbase v1 shapes the v37 settlement coinbase; it needs --coinbase v37";
    if (canon_on && !fee_on)
        return "--canonical-coinbase v1 needs --fee-model v1 (the donation output is the canonical residual sink)";
    if (canon_on && settle_output_cap != 0)
        return "--canonical-coinbase v1 fixes the coinbase output cap at " + std::to_string(kCanonOutputCap) +
               " (a lane constant); --settle-output-cap must not override it";
    return {};
}

} // namespace c2pool::v37n::xmr
