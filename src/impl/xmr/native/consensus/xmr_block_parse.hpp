// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/consensus/xmr_block_parse.hpp
//
// Wave 1 / C2a: the BLOCK BLOB parser. Wave 0 shipped the bounds-checked cursor
// (xmr_blob_reader.hpp) and the transaction parser (xmr_tx_weight.hpp); this is
// the block on top of them.
//
// A Monero block blob, as it arrives inside block_complete_entry.block, is
// (cryptonote_basic.h, BEGIN_SERIALIZE_OBJECT on block):
//
//     block_header : varint major_version
//                    varint minor_version
//                    varint timestamp
//                    prev_id[32]
//                    nonce[4]          <- RAW 4 bytes little-endian, NOT a varint
//     miner_tx     : one full transaction (version 1 pre-v12, version 2 +
//                    RCTTypeNull from HF_VERSION_MIN_V2_COINBASE_TX = 12)
//     tx_hashes    : varint count, then count * 32 bytes
//
// Two properties this parser is built for, both because the bytes come from an
// unauthenticated peer:
//
//   1. It NEVER re-serializes the header to hash it. The hashing blob's header
//      part is the ORIGINAL bytes, taken as a span of the input (`header_span`).
//      A parser that re-serialized would have to be byte-exact with monerod's
//      writer for every field, and any drift would silently change the block id.
//      Slicing cannot drift.
//   2. It is STL-only. No keccak, no tree hash, no coin tree: identity lives in
//      the sibling header xmr_block_id.hpp, which is the only file in C2a that
//      needs a hash function linked. Everything that only needs FIELDS -- the
//      hard-fork check, the timestamp window, weights, rewards -- can include
//      this header alone and stay dependency-free.
//
// The one thing this header does WRITE is a single varint (the transaction
// count that terminates the hashing blob). It carries its own encoder rather
// than pulling in the coin tree's BlobWriter for six lines, exactly as Wave 0's
// BlobReader carries its own decoder rather than pulling in tools::read_varint.
// The KAT pins blob_write_varint() against xmr::coin::BlobWriter::put_varint
// over a value sweep, so the duplication cannot drift silently.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "xmr_blob_reader.hpp"
#include "xmr_tx_weight.hpp"

namespace c2pool::xmr::native {

using BlockHash = std::array<std::uint8_t, 32>;

// A block may not carry more transactions than the weight limit could ever pay
// for; the bound here is structural (a 32-byte hash each against the bytes
// actually present is the tighter check read_count already applies).
inline constexpr std::uint64_t BLOCK_MAX_TX_HASHES = 1u << 16;

enum class BlockParseStatus : std::uint8_t {
    Ok = 0,
    Truncated,          // ran out of blob
    Malformed,          // structural violation
    BadMinerTx,         // the coinbase did not parse, or is not a coinbase
    TrailingBytes,      // bytes left after tx_hashes
    TxCountMismatch,    // tx_hashes.size() != the number of bodies supplied
};

inline const char* to_string(BlockParseStatus s) noexcept {
    switch (s) {
        case BlockParseStatus::Ok:              return "Ok";
        case BlockParseStatus::Truncated:       return "Truncated";
        case BlockParseStatus::Malformed:       return "Malformed";
        case BlockParseStatus::BadMinerTx:      return "BadMinerTx";
        case BlockParseStatus::TrailingBytes:   return "TrailingBytes";
        case BlockParseStatus::TxCountMismatch: return "TxCountMismatch";
    }
    return "?";
}

struct BlockHeaderFields {
    std::uint64_t major_version = 0;   // varint on the wire, uint8 in consensus
    std::uint64_t minor_version = 0;
    std::uint64_t timestamp     = 0;
    BlockHash     prev_id{};
    std::uint32_t nonce         = 0;
};

struct ParsedBlock {
    BlockHeaderFields header{};

    // Byte spans into the CALLER's buffer. Valid only while that buffer is.
    std::size_t header_offset   = 0;   // always 0
    std::size_t header_size     = 0;   // through the nonce, inclusive
    std::size_t miner_tx_offset = 0;
    std::size_t miner_tx_size   = 0;

    TxWeightInfo           miner_tx{};   // weight == blob size for a coinbase
    std::vector<BlockHash> tx_hashes;    // excludes the coinbase, wire order

    // n_tx as the hashing blob spells it: tx_hashes.size() + 1 for the coinbase.
    std::uint64_t total_tx_count() const noexcept {
        return static_cast<std::uint64_t>(tx_hashes.size()) + 1u;
    }
};

// ---------------------------------------------------------------------------
// CryptoNote LEB128 varint, WRITE side. Byte-identical to monerod's
// tools::write_varint (and to xmr::coin::BlobWriter::put_varint, which wraps
// the vendored copy of it); the KAT sweeps both against each other.
// ---------------------------------------------------------------------------
inline void blob_write_varint(std::vector<std::uint8_t>& out, std::uint64_t v) {
    while (v >= 0x80) {
        out.push_back(static_cast<std::uint8_t>((v & 0x7f) | 0x80));
        v >>= 7;
    }
    out.push_back(static_cast<std::uint8_t>(v));
}

// ---------------------------------------------------------------------------
// The parse itself.
// ---------------------------------------------------------------------------
inline BlockParseStatus parse_block(const std::uint8_t* data, std::size_t size,
                                    ParsedBlock& out) {
    out = ParsedBlock{};
    if (!data && size) return BlockParseStatus::Malformed;

    BlobReader r(data, size);

    // --- header ---------------------------------------------------------------
    if (!r.read_varint(out.header.major_version)) return BlockParseStatus::Truncated;
    if (!r.read_varint(out.header.minor_version)) return BlockParseStatus::Truncated;
    if (!r.read_varint(out.header.timestamp))     return BlockParseStatus::Truncated;
    if (!r.read_bytes(out.header.prev_id.data(), 32)) return BlockParseStatus::Truncated;
    if (!r.read_u32_le(out.header.nonce))         return BlockParseStatus::Truncated;

    // A version above 255 cannot be a Monero major_version; it is a malformed
    // varint dressed as one, and letting it through would make the hard-fork
    // check compare a truncated byte.
    if (out.header.major_version == 0 || out.header.major_version > 0xff)
        return BlockParseStatus::Malformed;
    if (out.header.minor_version > 0xff) return BlockParseStatus::Malformed;

    out.header_offset = 0;
    out.header_size   = r.offset();

    // --- miner_tx -------------------------------------------------------------
    // Parsed in place: the coinbase sits in the middle of the blob, so its end
    // is not known until it is parsed. Wave 0's two stages are used directly
    // rather than parse_tx_full(), which requires a buffer that ends exactly at
    // the end of the transaction.
    out.miner_tx_offset = r.offset();
    {
        TxParseStatus ts = detail::parse_tx_prefix(r, out.miner_tx);
        if (ts != TxParseStatus::Ok) return BlockParseStatus::BadMinerTx;
        if (!out.miner_tx.is_coinbase) return BlockParseStatus::BadMinerTx;

        if (out.miner_tx.version >= 2) {
            // From HF_VERSION_MIN_V2_COINBASE_TX = 12 the coinbase is version 2
            // with an rct signature of type NULL: one 0x00 byte, no prunable
            // part at all. Any other type in a coinbase is a reject.
            ts = detail::parse_rct_base(r, out.miner_tx);
            if (ts != TxParseStatus::Ok) return BlockParseStatus::BadMinerTx;
            if (out.miner_tx.rct_type != RCT_TYPE_NULL) return BlockParseStatus::BadMinerTx;
        }
        out.miner_tx.prunable_size      = 0;
        out.miner_tx.prunable_predicted = false;
        detail::finish(out.miner_tx);
    }
    out.miner_tx_size = r.offset() - out.miner_tx_offset;
    if (out.miner_tx.blob_size != out.miner_tx_size) return BlockParseStatus::BadMinerTx;

    // --- tx_hashes ------------------------------------------------------------
    std::uint64_t n = 0;
    if (!r.read_count(n, BLOCK_MAX_TX_HASHES, 32)) return BlockParseStatus::Truncated;
    out.tx_hashes.resize(static_cast<std::size_t>(n));
    for (std::uint64_t i = 0; i < n; ++i)
        if (!r.read_bytes(out.tx_hashes[static_cast<std::size_t>(i)].data(), 32))
            return BlockParseStatus::Truncated;

    if (r.remaining() != 0) return BlockParseStatus::TrailingBytes;
    return BlockParseStatus::Ok;
}

inline BlockParseStatus parse_block(const std::vector<std::uint8_t>& blob, ParsedBlock& out) {
    return parse_block(blob.data(), blob.size(), out);
}

// ---------------------------------------------------------------------------
// COINBASE FIELDS the weight parser deliberately discards.
//
// consensus/xmr_tx_weight.hpp reads the coinbase's structure to SIZE it, and
// throws away the two numbers it does not need: the height in the txin_gen
// input and the output amounts. Both are consensus-relevant here -- the height
// must equal the block's own height, and the amount sum is what the reward rule
// judges -- so this re-reads the coinbase prefix for them.
//
// It is a second pass over ~100 bytes, not a second parser: the structure has
// already been validated by parse_block(), so this walk is a straight-line
// read whose only failure mode is a truncation the first pass would have
// caught. The alternative -- adding two fields to the frozen Wave 0 struct --
// would be a contracts amendment, which the tree's own rule says costs a
// dedicated commit, and this is not worth one.
// ---------------------------------------------------------------------------
struct CoinbaseFields {
    std::uint64_t height      = 0;   // the height in txin_gen
    std::uint64_t output_sum  = 0;   // sum of vout amounts == money_in_use
    std::size_t   n_outputs   = 0;
};

inline bool parse_coinbase_fields(const std::uint8_t* block_blob, const ParsedBlock& pb,
                                  CoinbaseFields& out) {
    out = CoinbaseFields{};
    BlobReader r(block_blob + pb.miner_tx_offset, pb.miner_tx_size);

    std::uint64_t version = 0, unlock_time = 0;
    if (!r.read_varint(version)) return false;
    if (!r.read_varint(unlock_time)) return false;

    std::uint64_t n_in = 0;
    if (!r.read_varint(n_in) || n_in != 1) return false;
    std::uint8_t tag = 0;
    if (!r.read_byte(tag) || tag != TX_IN_GEN) return false;
    if (!r.read_varint(out.height)) return false;

    std::uint64_t n_out = 0;
    if (!r.read_varint(n_out)) return false;
    out.n_outputs = static_cast<std::size_t>(n_out);
    for (std::uint64_t i = 0; i < n_out; ++i) {
        std::uint64_t amount = 0;
        if (!r.read_varint(amount)) return false;
        if (out.output_sum > UINT64_MAX - amount) return false;   // never wrap
        out.output_sum += amount;
        std::uint8_t otag = 0;
        if (!r.read_byte(otag)) return false;
        if (otag == TX_OUT_TO_KEY)             { if (!r.skip(32)) return false; }
        else if (otag == TX_OUT_TO_TAGGED_KEY) { if (!r.skip(33)) return false; }
        else                                   { return false; }
    }
    return true;
}

// ---------------------------------------------------------------------------
// The hashing blob, minus the tree root the caller must supply:
//
//     hashing_blob = header_bytes || tree_root[32] || varint(n_tx + 1)
//
// (get_block_hashing_blob). The header bytes are the ORIGINAL span, never a
// re-serialization -- see property 1 at the top of this file.
// ---------------------------------------------------------------------------
inline std::vector<std::uint8_t> assemble_hashing_blob(const std::uint8_t* block_blob,
                                                       const ParsedBlock&   pb,
                                                       const BlockHash&     tree_root) {
    std::vector<std::uint8_t> out;
    out.reserve(pb.header_size + 32 + 10);
    out.insert(out.end(), block_blob + pb.header_offset,
                          block_blob + pb.header_offset + pb.header_size);
    out.insert(out.end(), tree_root.begin(), tree_root.end());
    blob_write_varint(out, pb.total_tx_count());
    return out;
}

} // namespace c2pool::xmr::native
