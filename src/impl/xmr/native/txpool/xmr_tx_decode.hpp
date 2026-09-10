// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/txpool/xmr_tx_decode.hpp
//
// The relay-side transaction decoder: from the exact bytes a peer sent, to
// {id, weight, fee, key images} plus everything the non-input consensus checks
// need (output commitments, pseudo-outputs, the Bulletproof+ proof).
//
// It does NOT re-implement the consensus transaction weight. That function is
// Wave-0 property at ../consensus/xmr_tx_weight.hpp, is pinned against real
// monerod block weights by xmr_native_tx_weight_kat, and is the single source
// of truth for both the pruned chain-sync path and this one. This file calls
// it and then extracts the two things it deliberately skips over: the output
// commitments (the last 32*n_out bytes of the rct base) and the structure of
// the prunable part.
//
// Transaction identity is monerod's v2 triple hash
//   id = H( H(prefix) || H(rct base) || H(prunable) )
// which is why the byte spans matter and why the decoder measures them rather
// than trusting any length the sender supplied.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <vector>

#include "impl/xmr/native/consensus/xmr_tx_weight.hpp"
#include "impl/xmr/native/contracts/types.hpp"
#include "impl/xmr/native/rct/xmr_rct_verify.hpp"

namespace c2pool::xmr::native {

enum class TxDecodeStatus : std::uint8_t {
    Ok = 0,
    ParseFail,           // the prefix or rct base did not decode (see .parse)
    Coinbase,            // a generation transaction cannot arrive over tx relay
    UnsupportedRctType,  // not RCTTypeBulletproofPlus: fail-closed
    PrunableMalformed,   // the prunable part does not have the shape the base implies
    PrunableTrailing,    // bytes left over after the prunable part
    ProofShape,          // proof count or L/R vector sizes are impossible
};

const char* to_string(TxDecodeStatus s) noexcept;

struct DecodedTx {
    TxWeightInfo   w;              // version, sizes, weight, fee, ring, key images
    TxParseStatus  parse = TxParseStatus::Ok;
    Hash           id{};           // the v2 triple hash

    rct::RctNonInput rct;          // what verify_non_input_consensus consumes

    // Byte spans within the blob, all measured.
    std::size_t prefix_size   = 0;
    std::size_t base_size     = 0;
    std::size_t prunable_size = 0;
};

// Decode a COMPLETE transaction blob (the only kind that arrives on
// NOTIFY_NEW_TRANSACTIONS). Every failure is a verdict, never a throw.
TxDecodeStatus decode_relayed_tx(const std::uint8_t* data, std::size_t size, DecodedTx& out);

inline TxDecodeStatus decode_relayed_tx(const std::vector<std::uint8_t>& blob, DecodedTx& out) {
    return decode_relayed_tx(blob.data(), blob.size(), out);
}

} // namespace c2pool::xmr::native
