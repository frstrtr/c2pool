// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/consensus/xmr_tx_weight.hpp
//
// CONSENSUS TRANSACTION WEIGHT -- the single most consensus-fatal function in
// the native node, and therefore Wave 0 property rather than any one wave-1
// component's.
//
// Weight, not size, is what Monero's block weight limit, the block-reward
// penalty and the fee policy are all denominated in. Two components need it
// from two different starting points:
//
//   * the txpool sees FULL transaction blobs off the relay and must reproduce
//     monerod's `{id, weight, fee, blob_size}` exactly, or our templates get
//     the penalty knee wrong and our blocks are rejected;
//   * the chain-state index syncs with prune=true (pinned decision D-4), so it
//     sees the prefix and the rct BASE and never the prunable bytes at all --
//     it must RECONSTRUCT the prunable length from structure to know the weight
//     of a block it just verified.
//
// So this header exposes both paths over one parser, and the golden proves both
// against real chain data.
//
// The formulas mirror monero-project src/cryptonote_basic/cryptonote_format_utils.cpp
// (get_transaction_weight / get_transaction_weight_clawback) and the prunable
// serialization in src/ringct/rctTypes.h (serialize_rctsig_prunable):
//
//   weight = blob_size                                     for version < 2, and
//                                                          for rct types that
//                                                          carry no bulletproof
//   weight = blob_size + clawback(n_padded_outputs)        for bulletproof and
//                                                          bulletproof-plus
//
//   clawback: with M = n_padded_outputs (the next power of two at or above the
//   output count) and nlr = 6 + log2(M),
//     bp_base = 32 * ((plus ? 6 : 9) + 14) / 2
//     bp_size = 32 * ((plus ? 6 : 9) + 2 * nlr)
//     clawback = (bp_base * M - bp_size) * 4 / 5,  and 0 when M <= 2
//
//   predicted prunable size, bulletproof-plus (rct type 6):
//     varint(1 proof) + 6*32 (A,A1,B,r1,s1,d1) + varint(|L|) + 32*|L|
//                                              + varint(|R|) + 32*|R|
//     + per input: 32*ring (CLSAG s) + 32 (c1) + 32 (D)
//     + per input: 32 (pseudoOut)
//   and for bulletproof / bulletproof2 / CLSAG (types 3,4,5) the proof body is
//     9*32 (A,S,T1,T2,taux,mu,a,b,t) instead of 6*32.
//
// PINNED SCOPE (fail-closed): BOTH entry points implement rct types 0
// (coinbase), 5 (CLSAG) and 6 (BulletproofPlus) -- everything a node syncing
// from a modern anchor can meet -- and return UnsupportedRctType for types 1, 2,
// 3 and 4 rather than a guess.
//
// The full-blob path MEASURES the prunable bytes rather than predicting them, so
// it is tempting to let it accept every type, and the first cut of this header
// said it did. It must not, and the reason is the clawback rather than the
// measurement: monerod derives the clawback from n_bulletproof_max_amounts(), a
// sum over the proof VECTOR, while the formula here derives it from
// n_padded_outputs_for(n_outputs), which is the same number only when the
// transaction carries exactly ONE aggregate proof. Type 3 (RCTTypeBulletproof,
// v8-v10) may legally carry several. Accepting it would return a WRONG weight
// with status Ok and no signal at all -- a silent wrong answer in the most
// consensus-fatal function in the tree.
//
// The case is unreachable today (a scan of the whole v8-v10 stagenet band found
// no multi-bulletproof transaction), which is why this is a fence and not a bug
// fix. Widening the scope means implementing the proof-vector sum, not relaxing
// the check.
//
// Depends only on xmr_blob_reader.hpp and the STL.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "xmr_blob_reader.hpp"

namespace c2pool::xmr::native {

// --- CryptoNote tags (mirrors xmr_blob.hpp's writer-side constants) ----------
inline constexpr std::uint8_t TX_IN_GEN             = 0xFF;
inline constexpr std::uint8_t TX_IN_TO_KEY          = 0x02;
inline constexpr std::uint8_t TX_OUT_TO_KEY         = 0x02;
inline constexpr std::uint8_t TX_OUT_TO_TAGGED_KEY  = 0x03;

// --- rct types (monero-project src/ringct/rctTypes.h) ------------------------
inline constexpr std::uint8_t RCT_TYPE_NULL              = 0;
inline constexpr std::uint8_t RCT_TYPE_FULL              = 1;
inline constexpr std::uint8_t RCT_TYPE_SIMPLE            = 2;
inline constexpr std::uint8_t RCT_TYPE_BULLETPROOF       = 3;
inline constexpr std::uint8_t RCT_TYPE_BULLETPROOF2      = 4;
inline constexpr std::uint8_t RCT_TYPE_CLSAG             = 5;
inline constexpr std::uint8_t RCT_TYPE_BULLETPROOF_PLUS  = 6;

inline constexpr bool rct_is_bulletproof(std::uint8_t t) noexcept {
    return t == RCT_TYPE_BULLETPROOF || t == RCT_TYPE_BULLETPROOF2 || t == RCT_TYPE_CLSAG;
}
inline constexpr bool rct_is_bulletproof_plus(std::uint8_t t) noexcept {
    return t == RCT_TYPE_BULLETPROOF_PLUS;
}

// --- structural bounds -------------------------------------------------------
// Deliberately generous: this parser decides shape, not policy. The admission
// check table in the txpool applies the tighter consensus limits.
inline constexpr std::uint64_t TX_MAX_INPUTS      = 4096;
inline constexpr std::uint64_t TX_MAX_OUTPUTS     = 4096;
inline constexpr std::uint64_t TX_MAX_RING        = 512;
inline constexpr std::uint64_t TX_MAX_EXTRA_BYTES = 1u << 20;

enum class TxParseStatus : std::uint8_t {
    Ok = 0,
    Truncated,
    Malformed,
    UnsupportedVersion,
    UnsupportedRctType,
    TrailingBytes,       // full-blob path: prunable ended before the blob did
    Overflow,
};

inline const char* to_string(TxParseStatus s) noexcept {
    switch (s) {
        case TxParseStatus::Ok:                 return "Ok";
        case TxParseStatus::Truncated:          return "Truncated";
        case TxParseStatus::Malformed:          return "Malformed";
        case TxParseStatus::UnsupportedVersion: return "UnsupportedVersion";
        case TxParseStatus::UnsupportedRctType: return "UnsupportedRctType";
        case TxParseStatus::TrailingBytes:      return "TrailingBytes";
        case TxParseStatus::Overflow:           return "Overflow";
    }
    return "?";
}

using KeyImage = std::array<std::uint8_t, 32>;

struct TxWeightInfo {
    std::uint64_t version     = 0;
    std::uint64_t unlock_time = 0;
    bool          is_coinbase = false;

    std::size_t n_inputs  = 0;
    std::size_t n_outputs = 0;
    // Ring size (key-offset count) per input; empty for a coinbase.
    std::vector<std::uint64_t> ring_sizes;
    std::vector<KeyImage>      key_images;

    std::size_t   extra_size = 0;
    std::uint8_t  rct_type   = RCT_TYPE_NULL;
    std::uint64_t fee        = 0;

    // Byte spans, all measured by the parser.
    std::size_t prefix_size   = 0;   // version .. tx_extra inclusive
    std::size_t rct_base_size = 0;   // type byte .. outPk inclusive
    std::size_t pruned_size   = 0;   // prefix_size + rct_base_size

    std::size_t prunable_size = 0;   // measured (full path) or predicted (pruned path)
    bool        prunable_predicted = false;

    std::size_t blob_size = 0;       // pruned_size + prunable_size

    std::size_t   n_padded_outputs = 0;
    std::uint64_t clawback         = 0;
    std::uint64_t weight           = 0;
};

// --- padded output count -----------------------------------------------------
// The bulletproof prover pads the aggregate to the next power of two, so for a
// single proof the padded count is a function of the output count alone. A
// zero-output transaction is not representable on chain; the clamp keeps the
// function total.
inline constexpr std::size_t n_padded_outputs_for(std::size_t n_outputs) noexcept {
    std::size_t m = 1;
    while (m < n_outputs) m <<= 1;
    return m;
}

// log2 of the padded count, plus the fixed 6 rounds, giving |L| == |R|.
inline constexpr std::size_t bp_nlr_for(std::size_t n_padded_outputs) noexcept {
    std::size_t nlr = 0;
    while ((std::size_t{1} << nlr) < n_padded_outputs) ++nlr;
    return nlr + 6;
}

// --- clawback ----------------------------------------------------------------
// Returns 0 for every type that carries no bulletproof, and for one or two
// outputs (where the aggregate is not cheaper than the per-output baseline).
inline constexpr std::uint64_t bulletproof_clawback(std::uint8_t rct_type,
                                                    std::size_t  n_outputs) noexcept {
    const bool plus = rct_is_bulletproof_plus(rct_type);
    if (!plus && !rct_is_bulletproof(rct_type)) return 0;

    const std::size_t m = n_padded_outputs_for(n_outputs);
    if (m <= 2) return 0;

    const std::uint64_t fields  = plus ? 6u : 9u;
    const std::uint64_t bp_base = (32u * (fields + 7u * 2u)) / 2u;
    const std::uint64_t nlr     = bp_nlr_for(m);
    const std::uint64_t bp_size = 32u * (fields + 2u * nlr);

    const std::uint64_t total = bp_base * static_cast<std::uint64_t>(m);
    if (total < bp_size) return 0;   // cannot happen for a well-formed proof
    return (total - bp_size) * 4u / 5u;
}

// --- weight ------------------------------------------------------------------
inline constexpr std::uint64_t transaction_weight(std::size_t  blob_size,
                                                  std::uint64_t version,
                                                  std::uint8_t  rct_type,
                                                  std::size_t   n_outputs) noexcept {
    if (version < 2) return blob_size;
    if (!rct_is_bulletproof(rct_type) && !rct_is_bulletproof_plus(rct_type))
        return blob_size;
    return static_cast<std::uint64_t>(blob_size)
         + bulletproof_clawback(rct_type, n_outputs);
}

// --- predicted prunable size (the pruned-sync path) --------------------------
// `ring_size` is the key-offset count, which consensus fixes for a given hard
// fork and which every input of a valid transaction shares.
inline TxParseStatus predicted_prunable_size(std::uint8_t rct_type,
                                             std::size_t  n_inputs,
                                             std::size_t  ring_size,
                                             std::size_t  n_outputs,
                                             std::size_t& out) noexcept {
    out = 0;
    if (rct_type == RCT_TYPE_NULL) return TxParseStatus::Ok;   // coinbase
    if (rct_type != RCT_TYPE_CLSAG && rct_type != RCT_TYPE_BULLETPROOF_PLUS)
        return TxParseStatus::UnsupportedRctType;
    if (n_inputs == 0 || n_outputs == 0 || ring_size == 0)
        return TxParseStatus::Malformed;

    const bool        plus = rct_is_bulletproof_plus(rct_type);
    const std::size_t nlr  = bp_nlr_for(n_padded_outputs_for(n_outputs));

    // varint(number of proofs). One proof is the only shape consensus accepts
    // for these two types, and one encodes in a single byte.
    std::size_t sz = 1;
    // A,A1,B,r1,s1,d1 for plus; A,S,T1,T2,taux,mu,a,b,t for CLSAG's bulletproof.
    sz += 32 * (plus ? 6u : 9u);
    // L and R, each a length-prefixed vector of `nlr` keys. nlr <= 6 + 12 here,
    // so both length varints are one byte.
    sz += 2 * (1 + 32 * nlr);
    // CLSAG per input: s[ring] + c1 + D. The s vector length is implied by the
    // ring size, so it carries no varint of its own.
    sz += n_inputs * (32 * ring_size + 64);
    // pseudoOuts, one per input, also length-implied.
    sz += n_inputs * 32;

    out = sz;
    return TxParseStatus::Ok;
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------
namespace detail {

// version, unlock_time, vin[], vout[], tx_extra. Leaves the reader positioned
// at the rct base (or at the end, for a version-1 transaction).
inline TxParseStatus parse_tx_prefix(BlobReader& r, TxWeightInfo& info) {
    BlobReader::DepthGuard g(r);
    if (!g.entered()) return TxParseStatus::Malformed;

    const std::size_t begin = r.offset();

    if (!r.read_varint(info.version)) return TxParseStatus::Truncated;
    if (info.version == 0 || info.version > 2) return TxParseStatus::UnsupportedVersion;
    if (!r.read_varint(info.unlock_time)) return TxParseStatus::Truncated;

    // --- inputs --------------------------------------------------------------
    std::uint64_t n_in = 0;
    if (!r.read_count(n_in, TX_MAX_INPUTS)) return TxParseStatus::Truncated;
    if (n_in == 0) return TxParseStatus::Malformed;
    info.n_inputs = static_cast<std::size_t>(n_in);

    for (std::uint64_t i = 0; i < n_in; ++i) {
        BlobReader::DepthGuard gi(r);
        if (!gi.entered()) return TxParseStatus::Malformed;

        std::uint8_t tag = 0;
        if (!r.read_byte(tag)) return TxParseStatus::Truncated;

        if (tag == TX_IN_GEN) {
            // A coinbase input carries the height and nothing else, and it may
            // only appear as the single input of a coinbase transaction.
            if (i != 0 || n_in != 1) return TxParseStatus::Malformed;
            std::uint64_t height = 0;
            if (!r.read_varint(height)) return TxParseStatus::Truncated;
            info.is_coinbase = true;
        } else if (tag == TX_IN_TO_KEY) {
            if (info.is_coinbase) return TxParseStatus::Malformed;
            std::uint64_t amount = 0;
            if (!r.read_varint(amount)) return TxParseStatus::Truncated;
            std::uint64_t n_off = 0;
            if (!r.read_count(n_off, TX_MAX_RING)) return TxParseStatus::Truncated;
            if (n_off == 0) return TxParseStatus::Malformed;
            for (std::uint64_t k = 0; k < n_off; ++k) {
                std::uint64_t off = 0;
                if (!r.read_varint(off)) return TxParseStatus::Truncated;
            }
            KeyImage ki{};
            if (!r.read_key(ki)) return TxParseStatus::Truncated;
            info.ring_sizes.push_back(n_off);
            info.key_images.push_back(ki);
        } else {
            return TxParseStatus::Malformed;
        }
    }

    // --- outputs -------------------------------------------------------------
    std::uint64_t n_out = 0;
    if (!r.read_count(n_out, TX_MAX_OUTPUTS)) return TxParseStatus::Truncated;
    if (n_out == 0) return TxParseStatus::Malformed;
    info.n_outputs = static_cast<std::size_t>(n_out);

    for (std::uint64_t i = 0; i < n_out; ++i) {
        BlobReader::DepthGuard go(r);
        if (!go.entered()) return TxParseStatus::Malformed;

        std::uint64_t amount = 0;
        if (!r.read_varint(amount)) return TxParseStatus::Truncated;
        std::uint8_t tag = 0;
        if (!r.read_byte(tag)) return TxParseStatus::Truncated;
        if (tag == TX_OUT_TO_KEY) {
            if (!r.skip(32)) return TxParseStatus::Truncated;
        } else if (tag == TX_OUT_TO_TAGGED_KEY) {
            if (!r.skip(33)) return TxParseStatus::Truncated;   // key + view tag
        } else {
            return TxParseStatus::Malformed;
        }
    }

    // --- tx_extra ------------------------------------------------------------
    std::uint64_t extra_len = 0;
    if (!r.read_count(extra_len, TX_MAX_EXTRA_BYTES)) return TxParseStatus::Truncated;
    if (!r.skip(static_cast<std::size_t>(extra_len))) return TxParseStatus::Truncated;
    info.extra_size = static_cast<std::size_t>(extra_len);

    info.prefix_size = r.offset() - begin;
    return TxParseStatus::Ok;
}

// type, txnFee, [pseudoOuts for RCTTypeSimple], ecdhInfo[], outPk[].
inline TxParseStatus parse_rct_base(BlobReader& r, TxWeightInfo& info) {
    BlobReader::DepthGuard g(r);
    if (!g.entered()) return TxParseStatus::Malformed;

    const std::size_t begin = r.offset();

    if (!r.read_byte(info.rct_type)) return TxParseStatus::Truncated;
    if (info.rct_type == RCT_TYPE_NULL) {
        info.rct_base_size = r.offset() - begin;
        return TxParseStatus::Ok;
    }
    if (info.rct_type > RCT_TYPE_BULLETPROOF_PLUS) return TxParseStatus::UnsupportedRctType;

    if (!r.read_varint(info.fee)) return TxParseStatus::Truncated;

    // Pre-bulletproof simple signatures keep pseudoOuts in the base.
    if (info.rct_type == RCT_TYPE_SIMPLE) {
        if (!r.skip(32 * info.n_inputs)) return TxParseStatus::Truncated;
    }

    // ecdhInfo: 8 bytes per output from Bulletproof2 onwards (amount only),
    // 64 bytes before that (mask + amount).
    const std::size_t ecdh =
            (info.rct_type == RCT_TYPE_BULLETPROOF2 || info.rct_type == RCT_TYPE_CLSAG
             || info.rct_type == RCT_TYPE_BULLETPROOF_PLUS) ? 8u : 64u;
    if (!r.skip(ecdh * info.n_outputs)) return TxParseStatus::Truncated;

    // outPk: one commitment mask per output.
    if (!r.skip(32 * info.n_outputs)) return TxParseStatus::Truncated;

    info.rct_base_size = r.offset() - begin;
    return TxParseStatus::Ok;
}

inline void finish(TxWeightInfo& info) {
    info.pruned_size = info.prefix_size + info.rct_base_size;
    info.blob_size   = info.pruned_size + info.prunable_size;
    info.n_padded_outputs = rct_is_bulletproof(info.rct_type) || rct_is_bulletproof_plus(info.rct_type)
                          ? n_padded_outputs_for(info.n_outputs) : 0;
    info.clawback = bulletproof_clawback(info.rct_type, info.n_outputs);
    info.weight   = transaction_weight(info.blob_size, info.version, info.rct_type, info.n_outputs);
}

} // namespace detail

// Parse a PRUNED transaction blob (prefix + rct base, as delivered by
// GET_OBJECTS with prune=true) and RECONSTRUCT the prunable length, so the
// weight is known without ever seeing the ring signatures.
inline TxParseStatus parse_tx_pruned(const std::uint8_t* data, std::size_t size,
                                     TxWeightInfo& info) {
    info = TxWeightInfo{};
    BlobReader r(data, size);

    TxParseStatus st = detail::parse_tx_prefix(r, info);
    if (st != TxParseStatus::Ok) return st;

    if (info.version >= 2) {
        st = detail::parse_rct_base(r, info);
        if (st != TxParseStatus::Ok) return st;
    }

    // The pruned blob must be consumed exactly: anything left over means we
    // disagree with the sender about the shape, which is a reject, not a warning.
    if (r.remaining() != 0) return TxParseStatus::TrailingBytes;

    const std::size_t ring = info.ring_sizes.empty() ? 0 : info.ring_sizes.front();
    for (std::uint64_t rs : info.ring_sizes) {
        if (rs != ring) return TxParseStatus::Malformed;   // mixed rings are invalid
    }

    std::size_t prunable = 0;
    st = predicted_prunable_size(info.rct_type, info.n_inputs, ring, info.n_outputs, prunable);
    if (st != TxParseStatus::Ok) return st;

    info.prunable_size      = prunable;
    info.prunable_predicted = true;
    detail::finish(info);
    return TxParseStatus::Ok;
}

inline TxParseStatus parse_tx_pruned(const std::vector<std::uint8_t>& blob,
                                     TxWeightInfo& info) {
    return parse_tx_pruned(blob.data(), blob.size(), info);
}

// Parse a FULL transaction blob. The prunable part is MEASURED (everything the
// prefix and rct base did not consume) rather than predicted -- but the CLAWBACK
// is still computed from the output count, so the pinned scope is the same one
// the prediction path enforces. See PINNED SCOPE at the top of this file: types
// 1-4 are refused here too, because a type-3 transaction carrying more than one
// bulletproof would otherwise get a wrong weight with status Ok.
inline TxParseStatus parse_tx_full(const std::uint8_t* data, std::size_t size,
                                   TxWeightInfo& info) {
    info = TxWeightInfo{};
    BlobReader r(data, size);

    TxParseStatus st = detail::parse_tx_prefix(r, info);
    if (st != TxParseStatus::Ok) return st;

    if (info.version >= 2) {
        st = detail::parse_rct_base(r, info);
        if (st != TxParseStatus::Ok) return st;

        if (info.rct_type != RCT_TYPE_NULL
            && info.rct_type != RCT_TYPE_CLSAG
            && info.rct_type != RCT_TYPE_BULLETPROOF_PLUS)
            return TxParseStatus::UnsupportedRctType;
    }

    info.prunable_size      = r.remaining();
    info.prunable_predicted = false;
    detail::finish(info);

    if (info.blob_size != size) return TxParseStatus::Malformed;   // invariant
    return TxParseStatus::Ok;
}

inline TxParseStatus parse_tx_full(const std::vector<std::uint8_t>& blob,
                                   TxWeightInfo& info) {
    return parse_tx_full(blob.data(), blob.size(), info);
}

} // namespace c2pool::xmr::native
