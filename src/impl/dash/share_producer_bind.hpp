// share_producer_bind.hpp -- slice 2/3 of the DASH mint campaign.
//
// Adapter that binds the producer-side share construction in
// share_producer.hpp (build_share) to the node work-source found-share
// seam DASHWorkSource::MintShareFn (work_source.hpp). This is the wire-in
// half of the campaign: it turns a stratum-found solution (MintShareInputs)
// into a fully-built, self-verified DashShare and returns its X11 share
// hash for the run-loop to add to the ShareTracker + broadcast.
//
// SCOPE / SAFETY (mirrors #734 skeleton posture, integrator-approved):
//   - header-only, lives entirely inside src/impl/dash/ (single-coin smoke
//     gate preserved -- touches nothing shared);
//   - KAT-gated: exercised only by test/impl/dash (see
//     share_producer_bind_kat.cpp); NOT wired into --run here. The run-loop
//     set_mint_share_fn(...) call is slice 3/3 (main_dash);
//   - dashd RPC fallback path is untouched and stays.
//
// Mapping MintShareInputs -> ProducerJobInputs (build order):
//   header_bytes(80)   -> SmallBlockHeaderType min_header   [deserialize]
//   coinbase_bytes     -> coinbase_scriptSig + DIP4 payload [parse; reuse
//                         the CbTx decode already in share_check.hpp]
//   payout_script      -> pubkey_hash (uint160)             [extract P2PKH]
//   subsidy            -> subsidy
//   prev_share_hash    -> prev_share_hash
//   pow_hash           -> cross-check vs build_share self-verify (X11)
//   (payments/desired_tx set + desired_target come from the frozen job
//    context the run-loop threads in slice 3/3; here they arrive via the
//    ProducerJobInputs the KAT constructs.)
//
// STATUS: WIP skeleton -- signature + mapping doc landed; parse helpers +
// build_share call + KAT are the next commit (build-verified before push).

#pragma once

#include <impl/dash/share_producer.hpp>
#include <impl/dash/stratum/work_source.hpp>

namespace dash::stratum {

// TODO(slice 2/3): implement -- deserialize min_header, parse coinbase into
// scriptSig+payload, derive pubkey_hash from payout_script, assemble
// ProducerJobInputs, call dash::coin::build_share, cross-check pow_hash, and
// return BuiltShare.share.m_hash. Bound via set_mint_share_fn in slice 3/3.
//
// template <typename ChainT>
// DASHWorkSource::MintShareFn make_producer_mint_fn(
//     ChainT& chain, const core::CoinParams& params);

}  // namespace dash::stratum
