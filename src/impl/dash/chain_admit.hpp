// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Dash chain-relative share admission seam.
//
// THE PROBLEM THIS CLOSES: dash::verify_version_transition (share_check.hpp) is
// the mint<->accept version-coupling gate, fully KAT-proven in isolation — but
// before this header it had ZERO src/ consumers (the only callers lived in
// test/test_dash_conformance.cpp). btc/dgb carry this coupling LIVE: dgb's
// src/impl/dgb/node.cpp runs share_init_verify() in a parallel phase and then
// applies the chain-relative gates serially as each share is admitted to the
// tracker. Dash had no accept orchestrator at all, so the gate was dead in
// prod. This header is the FIRST src/ consumer: the single, named seam the S8
// dash node run-loop / launcher --run share-receive path calls per incoming
// share. The behavioural thresholds (60% weighted successor / 95% weighted v36
// obsolescence) are pinned by the version_negotiation isolation KATs and the
// DashConformanceVersionWiring wired-path KATs; this seam locks the WIRING
// boundary the node accept path consumes, not the thresholds.
//
// Oracle: ref/p2pool-dash/p2pool/data.py — Share.__init__() (step 1, structural
// + PoW) followed by tracker admission running Share.check() (step 2, the
// chain-relative version guard). Mirrors the cross-coin standard so the v37
// unification is a clean migration, not a per-coin v36 dialect.

#include "share.hpp"
#include "share_check.hpp"   // share_init_verify (step 1) + verify_version_transition (step 2)

#include <core/coin_params.hpp>
#include <core/uint256.hpp>

namespace dash
{

// admit_chain_relative — STEP 2 ONLY: the chain-relative version-transition
// gate, decoupled from the CPU-bound structural verify. This is the seam the
// node accept path runs AFTER share_init_verify has been computed (typically in
// a parallel scrypt/X11 phase off the io_context — the dgb node.cpp pattern),
// so the chain admission never re-runs PoW. Throws std::invalid_argument on a
// disallowed version switch; returns normally when the share is admissible.
//
// Extension point: additional chain-relative admission gates (timestamp
// monotonicity, abswork progression, far_share_hash anchoring) compose HERE as
// they are conformance-proven, keeping the node accept path a single call.
template <typename ChainT>
inline void admit_chain_relative(const DashShare& share, ChainT& chain,
                                 uint64_t chain_length)
{
    verify_version_transition(share, chain, chain_length);
}

// admit_share — the canonical per-incoming-share admission a Dash node runs in
// its accept path, composing BOTH steps in oracle order:
//   step 1  share_init_verify(...)        structural + X11 PoW, coin-param-relative
//   step 2  admit_chain_relative(...)      version mint<->accept coupling, chain-relative
// Returns the verified share hash (the value share_init_verify computes); throws
// std::invalid_argument on any rejected share. Use this single-call form on the
// serial accept path; use share_init_verify + admit_chain_relative separately
// when the structural verify is hoisted into a parallel phase.
template <typename ChainT>
inline uint256 admit_share(const DashShare& share, ChainT& chain,
                           const core::CoinParams& params, uint64_t chain_length,
                           bool check_pow = true)
{
    uint256 hash = share_init_verify(share, params, check_pow);
    admit_chain_relative(share, chain, chain_length);
    return hash;
}

} // namespace dash