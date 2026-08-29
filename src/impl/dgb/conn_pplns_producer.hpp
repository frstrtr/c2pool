// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ============================================================================
// conn_pplns_producer.hpp — per-connection PPLNS-inputs producer-assembly SSOT.
//
// The per-connection Stratum coinbase a miner hashes commits, in its OP_RETURN,
// to a p2pool ref_hash for the prospective NEXT share. That ref_hash MUST be
// computed by the EXACT primitive the share verifier uses
// (dgb::compute_ref_hash_for_work — share_check.hpp), or a Stratum-emitted
// share can never match the share it commits to. This is precisely the latent
// no-segwit-v36 gap fixed in compute_ref_hash_for_work (the ref preimage always
// carries the segwit field for ver >= SEGWIT_ACTIVATION_VERSION); the
// per-connection coinbase producer is that primitive's FIRST live caller.
//
// make_conn_pplns_inputs() is the single seam that binds the verifier ref-hash
// primitive onto the per-connection PPLNS inputs. The caller (main_dgb) does
// the lock-safe tracker walk and resolves the two oracle-pinned design points:
//
//   subsidy        == DGBWorkSource::coinbase_value(height, fees, gbt)
//                     i.e. the SAME block-template value the miner solves
//                     (oracle work.py get_work: subsidy=current_work['subsidy']).
//   use_v36_pplns  == is_v36_active(ratchet-selected mint version)
//                     i.e. the formula the NEXT share will be minted under
//                     (oracle work.py: share_type via AutoRatchet switchover),
//                     NOT a separate runtime flag.
//
// This header adds NO payout or ref arithmetic of its own: it forwards the
// already-walked PPLNS weights into ConnCoinbasePplnsInputs (which delegates the
// amount split to compute_pplns_payout_split — the verifier's SSOT) and fills
// ref_hash/last_txout_nonce from compute_ref_hash_for_work. Emission and
// verification therefore share ONE ref-hash implementation and ONE payout
// implementation, by construction — not two kept in agreement.
//
// Pure / tracker-free: weights + RefHashParams are caller-supplied inputs, so
// the assembled output is directly KAT-able against the verifier primitive
// (see test/conn_pplns_producer_test.cpp).
// ============================================================================

#include "share_check.hpp"                       // dgb::compute_ref_hash_for_work, dgb::RefHashParams
#include <impl/dgb/coin/connection_coinbase.hpp> // dgb::coin::ConnCoinbasePplnsInputs

#include <core/coin_params.hpp>
#include <core/uint256.hpp>

#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace dgb
{

// Caller-resolved inputs for one connection's prospective-next-share coinbase.
// weights/total_weight come from a lock-safe compute_pplns_weight_walk() over
// the live ShareTracker (done upstream, off the work-gen thread under the
// tracker read lock). ref_params carries the prospective share's fields that
// feed the ref preimage.
struct ConnPplnsAssemblyInputs
{
    // PPLNS weight map + total, exactly as compute_pplns_weight_walk() produced.
    std::map<std::vector<unsigned char>, uint288> weights;
    uint288  total_weight;

    uint64_t subsidy{0};                          // == coinbase_value(height,fees,gbt)
    bool     use_v36_pplns{true};                 // == is_v36_active(mint version)

    std::vector<unsigned char> coinbase_script;   // scriptSig (BIP34 height + tag)
    std::optional<std::vector<unsigned char>> segwit_commitment_script;
    std::vector<unsigned char> finder_script;     // pre-V36 0.5% finder-fee target
    std::vector<unsigned char> donation_script;

    RefHashParams ref_params;                     // feeds compute_ref_hash_for_work
};

// Assemble a complete ConnCoinbasePplnsInputs for one connection. ref_hash and
// last_txout_nonce are computed HERE via the verifier's
// compute_ref_hash_for_work primitive, so the emitted OP_RETURN commits to a
// ref the verifier reproduces bit-for-bit (no second ref-hash implementation).
inline dgb::coin::ConnCoinbasePplnsInputs make_conn_pplns_inputs(
    const ConnPplnsAssemblyInputs& in, const core::CoinParams& params)
{
    const auto [ref_hash, last_txout_nonce] =
        compute_ref_hash_for_work(in.ref_params, params);

    dgb::coin::ConnCoinbasePplnsInputs out;
    out.coinbase_script          = in.coinbase_script;
    out.segwit_commitment_script = in.segwit_commitment_script;
    out.weights                  = in.weights;
    out.total_weight             = in.total_weight;
    out.subsidy                  = in.subsidy;
    out.use_v36_pplns            = in.use_v36_pplns;
    out.finder_script            = in.finder_script;
    out.donation_script          = in.donation_script;
    out.ref_hash                 = ref_hash;
    out.last_txout_nonce         = last_txout_nonce;
    return out;
}

} // namespace dgb