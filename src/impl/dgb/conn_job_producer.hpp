// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// The DGB per-connection job producer: the PPLNS inputs of one stratum job's
// coinbase at a prev share, with the share fields it commits to FROZEN on it.
//
// Lifted verbatim from main_dgb's set_pplns_inputs_fn lambda so the KATs run
// the real producer (producer -> coinbase -> submit -> mint round trip); the
// lambda keeps only the tracker guard and the AutoRatchet ask. Every field is
// derived exactly as create_local_share derives it (timestamp clip,
// compute_share_target, absheight/abswork/far_share_hash, merged_payout_hash),
// and those values are now also returned (ConnCoinbasePplnsInputs::frozen_*):
// the job carries them (JobSnapshot::frozen_ref) and the mint stamps them
// (has_frozen), as the BTC lane does. Before, the mint recomputed them at
// submit time (timestamp = now), so the share's ref differed from the
// OP_RETURN ref the miner hashed.
//
// Caller holds the tracker guard (shared) for the whole call.
// ---------------------------------------------------------------------------

#include <impl/dgb/conn_pplns_producer.hpp>        // ConnPplnsAssemblyInputs, make_conn_pplns_inputs
#include <impl/dgb/coin/coinbase_scriptsig.hpp>    // build_coinbase_scriptsig (BIP34 + tag, #902)
#include <impl/dgb/coin/connection_coinbase.hpp>   // ConnCoinbasePplnsInputs
#include <impl/dgb/coin/pplns_weight_walk.hpp>     // compute_pplns_weight_walk (PPLNS step-1 SSOT)
#include <impl/dgb/coin/work_ref_hash.hpp>         // WorkRefHashInputs, make_work_ref_hash_params

#include <core/coin_params.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <core/version_gate.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace dgb {

struct ConnJobRequest {
    uint256 prev_share_hash;
    std::vector<unsigned char> payout_script;   // the job's (effective) payout script
    std::vector<std::pair<uint32_t, std::vector<unsigned char>>> merged_addrs;
    uint32_t next_block_height = 0;             // the job template's height (BIP34)
    uint32_t block_bits = 0;                    // the job template's bits (the share's header bits)
    uint64_t block_value = 0;                   // the value the job's coinbase claims
    uint32_t now = 0;                           // wall clock (seconds)
    uint16_t donation = 0;                      // share donation (u16, --give-author)
    // The tagged DOGE merged-mining commitment ([0x2c][44 B], empty when merged
    // mining is off): part of the coinbase scriptSig, so of the ref preimage.
    std::vector<unsigned char> aux_mm_scriptsig;
};

/// {mint version, vote version} for the job, asked once (the AutoRatchet in
/// production). Called at the point the lambda asked it before the lift.
using ConnJobVersionsFn = std::function<std::pair<int64_t, uint64_t>()>;

template <typename TrackerT>
std::optional<coin::ConnCoinbasePplnsInputs> build_conn_job_inputs(
    TrackerT& tracker, const core::CoinParams& params, const ConnJobRequest& req,
    const ConnJobVersionsFn& versions)
{
    const uint256& prev_share_hash = req.prev_share_hash;

    // No tip / parent not in chain -> no job (the caller holds it).
    if (prev_share_hash.IsNull() || !tracker.chain.contains(prev_share_hash))
        return std::nullopt;

    // Prospective block bits: the tip share's block target (the value
    // create_local_share reads from the found block header) feeds the pre-V36
    // max_weight cap. Read under the held tracker lock.
    // The block the job is for (the job template): its bits are the share's
    // header bits, so the PPLNS walk's block target, as the verifier reads them
    // from the share's own header (share_check) and p2pool generate_transaction
    // takes block_target; never the previous share's header.
    const uint32_t block_bits = req.block_bits;
    if (block_bits == 0)
        return std::nullopt;  // no template: no job.
    uint32_t prev_ts    = 0;
    uint128  prev_abswork;
    uint32_t prev_absheight = 0;
    tracker.chain.get(prev_share_hash).share.invoke([&](auto* prev) {
        prev_ts         = prev->m_timestamp;
        prev_abswork    = prev->m_abswork;
        prev_absheight  = prev->m_absheight;
    });

    // #884: the {mint, vote} pair, asked ONCE for this template.
    const auto [mint_version, vote_version] = versions();
    const bool use_v36_pplns = core::version_gate::is_v36_active(mint_version);

    // PAYOUT half -- PPLNS weight walk SSOT (the verifier's step 1).
    decltype(coin::compute_pplns_weight_walk(tracker, prev_share_hash, block_bits, params,
                                             use_v36_pplns)) walk;
    try {
        walk = coin::compute_pplns_weight_walk(tracker, prev_share_hash, block_bits, params,
                                               use_v36_pplns);
    } catch (const std::invalid_argument&) {
        // Insufficient depth (the SAME boundary the verifier refuses).
        return std::nullopt;
    }
    if (walk.weights.empty())
        return std::nullopt;  // no payout recipients yet.

    // -- FROZEN template-time fields (mirror create_local_share) --
    // timestamp: clip to >= prev.timestamp + 1.
    uint32_t timestamp = req.now;
    if (timestamp <= prev_ts)
        timestamp = prev_ts + 1;

    // share target AFTER timestamp clip (== create_local_share order).
    const auto desired_target = chain::bits_to_target(block_bits);
    const auto st = tracker.compute_share_target(prev_share_hash, timestamp, desired_target, mint_version);
    const uint32_t max_bits = st.max_bits;
    const uint32_t bits     = st.bits;

    // absheight / abswork / far_share_hash from the parent.
    const uint32_t absheight = prev_absheight + 1;
    const auto cur_attempts = chain::target_to_average_attempts(chain::bits_to_target(bits));
    const uint128 abswork = prev_abswork + uint128(cur_attempts.GetLow64());

    uint256 far_share_hash;
    {
        auto [prev_height, last] = tracker.chain.get_height_and_last(prev_share_hash);
        if (last.IsNull() && prev_height < 99)
            far_share_hash = uint256();  // chain complete & < 99 deep
        else
            far_share_hash = tracker.chain.get_nth_parent_key(prev_share_hash, 99);
    }

    // merged_payout_hash (V36) over the same block target.
    const uint256 merged_payout_hash =
        tracker.compute_merged_payout_hash(prev_share_hash, desired_target);

    // Merged-mining addresses forwarded from the session.
    std::vector<MergedAddressEntry> merged_addresses;
    merged_addresses.reserve(req.merged_addrs.size());
    for (const auto& entry : req.merged_addrs) {
        MergedAddressEntry e;
        e.m_chain_id = entry.first;
        e.m_script.m_data = entry.second;
        merged_addresses.push_back(std::move(e));
    }

    // subsidy for the prospective NEXT block (== create_local_share subsidy arg).
    // The block's value (the job template's: subsidy at the block height),
    // never a subsidy of the share-chain height.
    const uint64_t subsidy = req.block_value;

    // #902 -- coinbase scriptSig: [BIP34 height push][/c2pool-dgb/ tag], then
    // the DOGE merged-mining commitment when merged mining is on. The SAME bytes
    // feed the ref preimage and the emitted coinbase, so the share minted from
    // this coinbase commits to the scriptSig its OP_RETURN ref commits to.
    std::vector<unsigned char> coinbase_scriptsig =
        coin::build_coinbase_scriptsig(req.next_block_height);
    coinbase_scriptsig.insert(coinbase_scriptsig.end(), req.aux_mm_scriptsig.begin(),
                              req.aux_mm_scriptsig.end());

    // REF half -- the ref preimage via the SSOT.
    coin::WorkRefHashInputs rin;
    rin.share_version      = mint_version;   // #884: ratchet-selected
    rin.desired_version    = vote_version;
    rin.prev_share         = prev_share_hash;
    rin.coinbase_scriptSig = coinbase_scriptsig;
    rin.share_nonce        = 0;               // share commitment nonce (not block)
    rin.payout_script      = req.payout_script;
    rin.subsidy            = subsidy;
    rin.donation           = req.donation;
    rin.stale_info         = 0;
    rin.has_segwit         = false;           // non-segwit coinbase
    rin.merged_addresses   = merged_addresses;
    rin.merged_payout_hash = merged_payout_hash;
    rin.far_share_hash     = far_share_hash;
    rin.max_bits           = max_bits;
    rin.bits               = bits;
    rin.timestamp          = timestamp;
    rin.absheight          = absheight;
    rin.abswork            = abswork;

    // Final PPLNS inputs via the make_conn_pplns_inputs() SSOT.
    ConnPplnsAssemblyInputs ain;
    ain.weights         = std::move(walk.weights);
    ain.total_weight    = walk.total_weight;
    ain.subsidy         = subsidy;
    ain.coinbase_script = coinbase_scriptsig;
    apply_conn_mint_version(ain, mint_version, req.payout_script);
    ain.ref_params      = coin::make_work_ref_hash_params(rin, params);
    auto out = make_conn_pplns_inputs(ain, params);

    // The share fields the ref commits to, for the job and the mint.
    out.frozen_absheight          = absheight;
    out.frozen_abswork            = abswork;
    out.frozen_far_share_hash     = far_share_hash;
    out.frozen_max_bits           = max_bits;
    out.frozen_bits               = bits;
    out.frozen_timestamp          = timestamp;
    out.frozen_merged_payout_hash = merged_payout_hash;
    return out;
}

} // namespace dgb
