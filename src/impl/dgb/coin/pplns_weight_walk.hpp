// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// SSOT: PPLNS weight walk — step 1 of generate_share_transaction(), lifted so the
// share-VERIFICATION path (share_check.hpp generate_share_transaction) and the
// per-connection Stratum coinbase EMISSION path (work_source.cpp
// build_connection_coinbase producer seam, bound in main_dgb.cpp) draw ONE
// tracker-walk implementation — no second copy to drift a payout satoshi.
//
// Counterpart of the steps 2-3 lift in pplns_payout_split.hpp (#328): together
// compute_pplns_weight_walk() + compute_pplns_payout_split() are the full
// former-inline body of generate_share_transaction()'s PPLNS computation.
// Verbatim lift — exact V36 (exponential depth-decay) vs pre-V36 (flat
// cumulative, grandparent start) branch, the data.py:762-764 insufficient-depth
// guard, the block-target / spread / 65535 max_weight cap, and the
// unlimited-weight V36 sentinel.
// Reference: frstrtr/p2pool-merged-v36 data.py:879/884-885, work.py:759.
//
// NOTE: the result type is DEDUCED from the tracker (dgb::CumulativeWeights) via
// decltype rather than named/included directly — share_tracker.hpp includes
// share_check.hpp, which includes this header, so naming the type here (or
// including share_tracker.hpp) would form a parse-time include cycle when
// share_tracker.hpp is the outer include. The dependent return type resolves
// only at instantiation, where TrackerT is complete.
// ─────────────────────────────────────────────────────────────────────────────

#include <core/coin_params.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>

namespace dgb::coin {

// Walk the sharechain from `prev_hash` (the new share's parent / the current
// tip when emitting work) backward and accumulate the PPLNS weight map exactly
// as the verifier does. `block_bits` is the block-header nBits feeding the
// pre-V36 max_weight cap (share.m_min_header.m_bits on the verify path).
//
//  * prev_hash null or absent from the chain  -> empty weights (caller treats
//    as a safe coinbase-only / empty job — the pre-wire behavior).
//  * chain shorter than real_chain_length     -> throws std::invalid_argument,
//    the SAME boundary generate_share_transaction() rejects, so emission and
//    verification refuse identical insufficient-depth states.
template <typename TrackerT>
inline auto compute_pplns_weight_walk(
    TrackerT& tracker,
    const uint256& prev_hash,
    uint32_t block_bits,
    const core::CoinParams& params,
    bool use_v36_pplns)
    -> decltype(tracker.get_v36_decayed_cumulative_weights(
           prev_hash, std::int32_t{0}, std::declval<const uint288&>()))
{
    using Result = decltype(tracker.get_v36_decayed_cumulative_weights(
        prev_hash, std::int32_t{0}, std::declval<const uint288&>()));
    Result out{};

    if (prev_hash.IsNull() || !tracker.chain.contains(prev_hash))
        return out;  // no parent in chain -> empty (safe coinbase-only job).

    // p2pool data.py:762-764 — refuse to compute PPLNS with insufficient depth.
    // Without this guard, attempt_verify() (which allows CHAIN_LENGTH+1) can
    // trigger a PPLNS walk that terminates early, producing wrong coinbase
    // amounts and causing persistent GENTX-MISMATCH during bootstrap.
    auto chain_len = static_cast<int32_t>(params.real_chain_length);
    {
        auto pplns_height = tracker.chain.get_height(prev_hash);
        auto pplns_last = tracker.chain.get_last(prev_hash);
        if (!(pplns_height >= chain_len || pplns_last.IsNull()))
            throw std::invalid_argument(
                "share chain not long enough for PPLNS verification (height="
                + std::to_string(pplns_height) + " need="
                + std::to_string(chain_len) + ")");
    }

    // block_target from block header bits (matches Python: self.header['bits'].target)
    auto block_target = chain::bits_to_target(block_bits);
    auto max_weight = chain::target_to_average_attempts(block_target)
                      * params.spread * 65535;

    // PPLNS formula selected by runtime v36_active (AutoRatchet state), not
    // compile-time share version. Ref: p2pool data.py:879, work.py:759.
    if (use_v36_pplns) {
        // V36 PPLNS: exponential depth-decay, walk from parent.
        uint288 unlimited_weight;
        unlimited_weight.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        out = tracker.get_v36_decayed_cumulative_weights(prev_hash, chain_len, unlimited_weight);
    } else {
        // Pre-V36 PPLNS: flat cumulative weights (no decay). CRITICAL: walk from
        // GRANDPARENT for HEIGHT-1 shares. p2pool data.py:884-885:
        //   _pplns_start = previous_share.share_data['previous_share_hash']
        //   _pplns_max_shares = max(0, min(height, REAL_CHAIN_LENGTH) - 1)
        uint256 pplns_start;
        tracker.chain.get(prev_hash).share.invoke([&](auto* s) {
            pplns_start = s->m_prev_hash;  // grandparent
        });
        auto available = tracker.chain.get_height(prev_hash);
        auto walk_count = static_cast<int32_t>(
            std::max(0, std::min(chain_len, available) - 1));

        if (!pplns_start.IsNull() && tracker.chain.contains(pplns_start) && walk_count > 0) {
            out = tracker.get_cumulative_weights(pplns_start, walk_count, max_weight);
        }
    }
    return out;
}

} // namespace dgb::coin