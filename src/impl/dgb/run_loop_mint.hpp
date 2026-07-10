// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// run_loop_mint.hpp — DGB Phase B: worker->mint adapter SSOT.
//
// This is the consumer adapter that DGBWorkSource::MintShareFn binds to in
// main_dgb.cpp (work_source.hpp:197 "binds this to mint_local_share_with_ratchet
// (run_loop_mint.hpp) -> create_local_share"). When mining_submit classifies a
// submission as ShareAccept (Scrypt PoW meets the SHARE target but NOT the full
// block target), try_mint_share() invokes this with the assembled MintShareInputs.
// It:
//   1. parses the 80-byte reconstructed block header into a SmallBlockHeaderType,
//   2. asks the live AutoRatchet for the {mint, vote} version pair via
//      dgb_select_mint_versions (anchored at the current sharechain tip = the
//      new share's parent), and
//   3. inserts the share into the tracker via create_local_share, returning the
//      minted share hash (NULL uint256 on a malformed header / fail-closed).
//
// History: this helper was authored under #294 and lost from master in the
// #292/#293/#294 stacked squash-merge (no #294 merge commit reaches master; the
// underlying primitives dgb_select_mint_versions + create_local_share survive).
// Re-landed here to its documented contract against master's create_local_share
// signature, which is authoritative.
//
// PURE adapter: the helper takes references and performs ONE tracker insertion.
// Thread-safety of that insertion is the CALLER's concern — main_dgb binds this
// on the Stratum-submission thread and is responsible for the tracker lock.
//
// Duck-typed on the inputs (InputsT) so this header does NOT pull the stratum
// work_source TU in: any struct exposing { header_bytes, coinbase_bytes, subsidy,
// prev_share, merkle_branches, payout_script, segwit_active } binds — in
// production that is DGBWorkSource::MintShareInputs.

#include <optional>
#include <vector>

#include <core/pack.hpp>                  // PackStream, operator>>
#include <core/pack_types.hpp>            // BaseScript
#include <core/uint256.hpp>

#include <impl/dgb/coin/block.hpp>        // SmallBlockHeaderType, BlockHeaderType
#include <impl/dgb/share_check.hpp>       // create_local_share, MergedAddressEntry, StaleInfo, uint128
#include <impl/dgb/auto_ratchet_wire.hpp> // dgb_select_mint_versions, AutoRatchet

namespace dgb {

// Parse a canonical 80-byte block header (fixed 4-byte version + merkle_root)
// into the SmallBlockHeaderType (version|prev|time|bits|nonce) create_local_share
// consumes. Returns nullopt on a short/malformed buffer (fail-closed). Pure.
inline std::optional<coin::SmallBlockHeaderType>
parse_min_header_80(const std::vector<unsigned char>& header_bytes)
{
    if (header_bytes.size() < 80)
        return std::nullopt;
    try {
        PackStream ps(header_bytes);
        coin::BlockHeaderType full;
        ps >> full;
        // SmallBlockHeaderType is the base subobject of BlockHeaderType; slicing
        // off m_merkle_root yields exactly the small-header fields.
        return static_cast<coin::SmallBlockHeaderType&>(full);
    } catch (const std::exception&) {
        return std::nullopt;  // truncated / unserialize failure -> fail-closed
    }
}

// The worker->mint adapter. Returns the minted share hash, or NULL uint256 if
// the header is malformed (fail-closed; the caller logs a no-record outcome).
template <typename TrackerT, typename InputsT>
inline uint256 mint_local_share_with_ratchet(
    const InputsT&          in,
    TrackerT&               tracker,
    const core::CoinParams& params,
    AutoRatchet&            ratchet,
    uint16_t                donation = 50)
{
    auto min_header = parse_min_header_80(in.header_bytes);
    if (!min_header)
        return uint256();  // fail-closed: malformed 80-byte header

    BaseScript coinbase(in.coinbase_bytes);

    // The new share's parent is the current sharechain tip carried by the
    // submission; the ratchet decides which {mint, vote} version pair to stamp.
    const uint256 best_share = in.prev_share;
    auto [mint_version, vote_version] =
        dgb_select_mint_versions(ratchet, tracker, best_share);

    return create_local_share(
        tracker, params, *min_header, coinbase, in.subsidy, in.prev_share,
        in.merkle_branches, in.payout_script,
        donation,
        std::vector<MergedAddressEntry>{},   // merged_addrs (DOGE aux: none in Scrypt-only)
        StaleInfo::none,                      // stale_info
        in.segwit_active,                     // segwit_active
        std::string{},                       // witness_commitment_hex
        std::vector<unsigned char>{},        // message_data
        std::vector<unsigned char>{},        // actual_coinbase_bytes
        uint256(),                           // witness_root
        0u,                                  // override_max_bits
        0u,                                  // override_bits
        0u,                                  // frozen_absheight
        uint128(),                           // frozen_abswork
        uint256(),                           // frozen_far_share_hash
        0u,                                  // frozen_timestamp
        uint256(),                           // frozen_merged_payout_hash
        false,                               // has_frozen
        std::vector<uint256>{},              // frozen_merkle_branches
        uint256(),                           // frozen_witness_root
        std::vector<unsigned char>{},        // frozen_merged_coinbase_info
        static_cast<int64_t>(mint_version),  // share_version (ratchet-selected)
        static_cast<uint64_t>(vote_version)); // desired_version (always target)
}

} // namespace dgb