// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// The prunable layout transcribed here is monero-project/monero
// src/ringct/rctTypes.h serialize_rctsig_prunable (BSD-3-Clause).
// ---------------------------------------------------------------------------
#include "xmr_tx_decode.hpp"

#include <cstring>

namespace c2pool::xmr::native {
namespace {

// The longest inner-product vector a legal Bulletproof+ carries is 6 + log2(16)
// = 10 entries; the cap is generous and only there to bound an allocation.
constexpr std::uint64_t MAX_LR_ENTRIES = 32;

Hash keccak_of(const std::uint8_t* p, std::size_t n) noexcept {
    return rct::cn_fast_hash(p, n);
}

} // namespace

const char* to_string(TxDecodeStatus s) noexcept {
    switch (s) {
        case TxDecodeStatus::Ok:                 return "Ok";
        case TxDecodeStatus::ParseFail:          return "ParseFail";
        case TxDecodeStatus::Coinbase:           return "Coinbase";
        case TxDecodeStatus::UnsupportedRctType: return "UnsupportedRctType";
        case TxDecodeStatus::PrunableMalformed:  return "PrunableMalformed";
        case TxDecodeStatus::PrunableTrailing:   return "PrunableTrailing";
        case TxDecodeStatus::ProofShape:         return "ProofShape";
    }
    return "?";
}

TxDecodeStatus decode_relayed_tx(const std::uint8_t* data, std::size_t size, DecodedTx& out) {
    out = DecodedTx{};

    // 1) Weight, sizes, ring sizes, key images and fee: the shared Wave-0
    //    consensus parser, not a second opinion.
    out.parse = parse_tx_full(data, size, out.w);
    if (out.parse != TxParseStatus::Ok) {
        return out.parse == TxParseStatus::UnsupportedRctType
                       ? TxDecodeStatus::UnsupportedRctType
                       : TxDecodeStatus::ParseFail;
    }
    if (out.w.is_coinbase) return TxDecodeStatus::Coinbase;

    out.prefix_size   = out.w.prefix_size;
    out.base_size     = out.w.rct_base_size;
    out.prunable_size = out.w.prunable_size;

    if (out.w.rct_type != rct::RCT_TYPE_BULLETPROOF_PLUS)
        return TxDecodeStatus::UnsupportedRctType;

    // 2) The output commitments. The rct base ends with one 32-byte commitment
    //    per output, so their offset follows from the measured span without
    //    re-walking the varint-encoded fee.
    const std::size_t n_out = out.w.n_outputs;
    const std::size_t n_in  = out.w.n_inputs;
    const std::size_t commitments_bytes = 32 * n_out;
    if (out.w.pruned_size < commitments_bytes) return TxDecodeStatus::PrunableMalformed;
    const std::size_t outpk_off = out.w.pruned_size - commitments_bytes;

    out.rct.rct_type   = out.w.rct_type;
    out.rct.fee        = out.w.fee;
    out.rct.ecdh_count = n_out;
    out.rct.outPk.resize(n_out);
    for (std::size_t i = 0; i < n_out; ++i)
        std::memcpy(out.rct.outPk[i].data(), data + outpk_off + 32 * i, 32);

    out.rct.key_images.assign(out.w.key_images.begin(), out.w.key_images.end());

    // 3) The prunable part: one Bulletproof+ proof, then one CLSAG per input,
    //    then one pseudo-output per input. Sizes that are implied by the base
    //    (the CLSAG s vector length, the pseudo-output count) carry no length
    //    prefix on the wire, which is why this cannot be decoded without the
    //    prefix having been parsed first.
    BlobReader r(data + out.w.pruned_size, out.w.prunable_size);

    std::uint64_t nbp = 0;
    if (!r.read_varint(nbp)) return TxDecodeStatus::PrunableMalformed;
    if (nbp != 1) return TxDecodeStatus::ProofShape;   // consensus shape for BP+

    out.rct.bpp.resize(1);
    rct::BulletproofPlus& proof = out.rct.bpp[0];

    if (!r.read_key(proof.A))  return TxDecodeStatus::PrunableMalformed;
    if (!r.read_key(proof.A1)) return TxDecodeStatus::PrunableMalformed;
    if (!r.read_key(proof.B))  return TxDecodeStatus::PrunableMalformed;
    if (!r.read_key(proof.r1)) return TxDecodeStatus::PrunableMalformed;
    if (!r.read_key(proof.s1)) return TxDecodeStatus::PrunableMalformed;
    if (!r.read_key(proof.d1)) return TxDecodeStatus::PrunableMalformed;

    std::uint64_t n_l = 0;
    if (!r.read_count(n_l, MAX_LR_ENTRIES, 32)) return TxDecodeStatus::PrunableMalformed;
    proof.L.resize(static_cast<std::size_t>(n_l));
    for (auto& k : proof.L)
        if (!r.read_key(k)) return TxDecodeStatus::PrunableMalformed;

    std::uint64_t n_r = 0;
    if (!r.read_count(n_r, MAX_LR_ENTRIES, 32)) return TxDecodeStatus::PrunableMalformed;
    proof.R.resize(static_cast<std::size_t>(n_r));
    for (auto& k : proof.R)
        if (!r.read_key(k)) return TxDecodeStatus::PrunableMalformed;

    if (n_l != n_r || n_l < 6) return TxDecodeStatus::ProofShape;

    // CLSAG per input: s[ring], c1, D. The signatures themselves are INPUT
    // consensus (they are checked against the ring members, which need the
    // chain) so they are walked over, not decoded -- but they must be exactly
    // as long as the ring sizes in the prefix say, or the pseudo-outputs that
    // follow are not where we think they are.
    if (out.w.ring_sizes.size() != n_in) return TxDecodeStatus::PrunableMalformed;
    for (std::size_t i = 0; i < n_in; ++i) {
        const std::uint64_t ring = out.w.ring_sizes[i];
        if (ring == 0 || ring > TX_MAX_RING) return TxDecodeStatus::PrunableMalformed;
        if (!r.skip(static_cast<std::size_t>(32 * ring))) return TxDecodeStatus::PrunableMalformed;
        if (!r.skip(64)) return TxDecodeStatus::PrunableMalformed;   // c1 and D
    }

    out.rct.pseudoOuts.resize(n_in);
    for (auto& k : out.rct.pseudoOuts)
        if (!r.read_key(k)) return TxDecodeStatus::PrunableMalformed;

    if (r.remaining() != 0) return TxDecodeStatus::PrunableTrailing;

    // 4) Identity. Three Keccaks over the three measured spans, then one more
    //    over their concatenation.
    const Hash h_prefix   = keccak_of(data, out.w.prefix_size);
    const Hash h_base     = keccak_of(data + out.w.prefix_size, out.w.rct_base_size);
    const Hash h_prunable = keccak_of(data + out.w.pruned_size, out.w.prunable_size);

    std::uint8_t triple[96];
    std::memcpy(triple, h_prefix.data(), 32);
    std::memcpy(triple + 32, h_base.data(), 32);
    std::memcpy(triple + 64, h_prunable.data(), 32);
    out.id = keccak_of(triple, sizeof(triple));

    return TxDecodeStatus::Ok;
}

} // namespace c2pool::xmr::native
