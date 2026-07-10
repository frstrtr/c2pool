// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining (D0.5) -- per-coin consensus-isolation guard.
//
// The -DAUX_DOGE=ON DGB-as-parent build links ltc_coin (substrate path (a),
// integrator-ratified) for Bitcoin-wire-generic value/serialization types ONLY
// (BlockType, MutableTransaction, compute_merkle_root, ...). The LTC CONSENSUS
// surface -- ltc::coin::HeaderChain, make_ltc_chain_params_mainnet/testnet, the
// scrypt pow binding, Art-Forz retarget -- is present-but-dead at link and must
// NEVER reach a live DGB-parent call path. "DGB-parent never instantiates
// ltc::coin::HeaderChain nor calls make_ltc_chain_params_*" is today a discipline
// invariant; this header converts the most regression-prone half into a
// COMPILE-TIME invariant so one future edit cannot silently re-route the
// DGB-parent path through foreign (LTC) consensus serialization.
//
// Two-part guard (per the isolation-invariant hardening):
//   * compile-time (this header): assert the DGB-parent aux seam binds DGB's OWN
//     consensus serialization (dgb::coin::TX_NO_WITNESS), not bitcoin_family's
//     default that LTC/DASH inherit, and that the DGB parent coinbase type is
//     distinct from ltc::coin's.
//   * link-time (fast-follow, src/impl/dgb/CMakeLists.txt POST_BUILD): an
//     `nm -C` negative-symbol check on the c2pool-dgb binary that FAILS the
//     build if `make_ltc_chain_params` or `ltc::coin::HeaderChain` is ODR-used.
//     (Staged separately -- it needs an AUX_DOGE build slot to validate the
//     demangled-symbol grep.)
// ---------------------------------------------------------------------------

#ifdef AUX_DOGE

#include <type_traits>

#include <impl/doge/coin/auxpow.hpp>                 // CAuxPow<>, parent_coinbase_no_witness<>
#include <impl/dgb/coin/transaction.hpp>             // dgb::coin::MutableTransaction, TX_NO_WITNESS
#include <impl/dgb/coin/aux_doge_parent_traits.hpp>  // doge::coin::parent_coinbase_no_witness<dgb::coin::MutableTransaction>
#include <impl/ltc/coin/transaction.hpp>             // ltc::coin::MutableTransaction (wire-generic, ALLOWED on link)

namespace dgb::coin::aux_doge_guard {

// (1) The DGB-parent witness-strip trait in effect MUST resolve to DGB's own
//     consensus serialization. The shared aux module defaults this trait to
//     bitcoin_family::coin::TX_NO_WITNESS (the LTC/DASH path); the dgb
//     specialization in aux_doge_parent_traits.hpp overrides it to
//     dgb::coin::TX_NO_WITNESS. If a refactor ever dropped that specialization,
//     the DGB-parent coinbase would silently serialize through bitcoin_family's
//     (foreign) params -- caught here at compile time.
static_assert(
    std::is_same_v<
        std::decay_t<decltype(
            ::doge::coin::parent_coinbase_no_witness<dgb::coin::MutableTransaction>::value)>,
        dgb::coin::TxParams>,
    "AUX_DOGE isolation: DGB-parent coinbase must serialize through dgb::coin::TxParams "
    "(its OWN consensus params), never bitcoin_family's default (the LTC/DASH path). "
    "A failure here means the dgb specialization in aux_doge_parent_traits.hpp was dropped.");

// (2) The DGB parent coinbase type is DGB-owned, distinct from ltc::coin's. The
//     shared aux module's DEFAULT parent is ltc::coin::MutableTransaction; the
//     DGB seam pins the parser to dgb::coin::MutableTransaction instead. This
//     records that the two parent types are genuinely distinct, so a regression
//     that left the ltc default in place is a type change, not a silent alias.
static_assert(
    !std::is_same_v<dgb::coin::MutableTransaction, ::ltc::coin::MutableTransaction>,
    "AUX_DOGE isolation: DGB parent coinbase type must be distinct from ltc::coin's; "
    "the DGB seam pins the parser to dgb::coin::MutableTransaction, not the shared "
    "module's ltc default.");

} // namespace dgb::coin::aux_doge_guard

#endif // AUX_DOGE