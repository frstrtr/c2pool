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
#include "impl/xmr/native/rct/xmr_clsag_verify.hpp"
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

    // Input-consensus raw material -- everything verify_clsag and the ring
    // resolver need, decoded from the same bytes. Filled for every
    // BulletproofPlus transaction that decodes; the txpool's input-consensus
    // step consumes it (and the ring MEMBERS it resolves from the chain).
    std::vector<rct::Clsag>                 clsags;       // one per input
    std::vector<std::vector<std::uint64_t>> key_offsets;  // relative, per input
    std::vector<rct::Key>                   out_pubkeys;  // one per output
    rct::Key h_prefix{};   // Keccak of the prefix span (monerod rv.message)
    rct::Key h_base{};     // Keccak of the rct base span

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

// ---------------------------------------------------------------------------
// UNKNOWN-FORK TRANSACTION (not understood, not invalid).
//
// Asked ONLY about a blob that decode_relayed_tx() already refused. True when
// the transaction declares a format above what this build implements, so the
// refusal says nothing about the sender's honesty:
//
//   * a transaction version above CURRENT_TRANSACTION_VERSION (2); or
//   * a well-formed version-2 prefix whose rct type is above
//     RCTTypeBulletproofPlus (6). FCMP++ is type 7 (fcmp++-stage rctTypes.h).
//     To reach the rct type of a real FCMP++ transaction, the prefix walk also
//     accepts the output tag the same fork defines, txout_to_carrot_v1 (0x01:
//     key[32], view_tag[3], encrypted_janus_anchor[16]), and an input with an
//     empty ring (an FCMP++ input keeps its key image and drops key_offsets).
//
// Everything else stays what decode_relayed_tx() said it was: a tx version 0,
// a truncated prefix, an unknown input or output tag, or a Carrot output in a
// transaction of a KNOWN rct type is malformed, exactly as before.
// ---------------------------------------------------------------------------
inline constexpr std::uint64_t TX_MAX_IMPLEMENTED_VERSION = 2;      // CURRENT_TRANSACTION_VERSION
inline constexpr std::uint8_t  TX_OUT_TO_CARROT_V1        = 0x01;   // v17 (fcmp++-stage cryptonote_basic.h)
inline constexpr std::size_t   TX_OUT_CARROT_V1_BYTES     = 32 + 3 + 16;

inline bool tx_format_above_implemented(const std::uint8_t* data, std::size_t size) {
    if (!data || !size) return false;
    BlobReader r(data, size);
    std::uint64_t version = 0;
    if (!r.read_varint(version)) return false;
    if (version > TX_MAX_IMPLEMENTED_VERSION) return true;
    if (version != 2) return false;            // 0 is malformed; 1 has no rct type
    std::uint64_t unlock = 0;
    if (!r.read_varint(unlock)) return false;

    std::uint64_t n_in = 0;
    if (!r.read_count(n_in, TX_MAX_INPUTS) || n_in == 0) return false;
    for (std::uint64_t i = 0; i < n_in; ++i) {
        std::uint8_t tag = 0;
        if (!r.read_byte(tag) || tag != TX_IN_TO_KEY) return false;
        std::uint64_t amount = 0, n_off = 0;
        if (!r.read_varint(amount)) return false;
        if (!r.read_count(n_off, TX_MAX_RING)) return false;
        for (std::uint64_t k = 0; k < n_off; ++k) {
            std::uint64_t off = 0;
            if (!r.read_varint(off)) return false;
        }
        if (!r.skip(32)) return false;         // key image
    }

    std::uint64_t n_out = 0;
    if (!r.read_count(n_out, TX_MAX_OUTPUTS) || n_out == 0) return false;
    for (std::uint64_t i = 0; i < n_out; ++i) {
        std::uint64_t amount = 0;
        std::uint8_t  tag    = 0;
        if (!r.read_varint(amount) || !r.read_byte(tag)) return false;
        std::size_t body = 0;
        if (tag == TX_OUT_TO_KEY)             body = 32;
        else if (tag == TX_OUT_TO_TAGGED_KEY) body = 33;
        else if (tag == TX_OUT_TO_CARROT_V1)  body = TX_OUT_CARROT_V1_BYTES;
        else return false;
        if (!r.skip(body)) return false;
    }

    std::uint64_t extra_len = 0;
    if (!r.read_count(extra_len, TX_MAX_EXTRA_BYTES)) return false;
    if (!r.skip(static_cast<std::size_t>(extra_len))) return false;

    std::uint8_t rct_type = 0;
    if (!r.read_byte(rct_type)) return false;
    return rct_type > RCT_TYPE_BULLETPROOF_PLUS;
}

inline bool tx_format_above_implemented(const std::vector<std::uint8_t>& blob) {
    return tx_format_above_implemented(blob.data(), blob.size());
}

} // namespace c2pool::xmr::native
