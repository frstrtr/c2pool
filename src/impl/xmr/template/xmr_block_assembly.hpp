// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/template/xmr_block_assembly.hpp  --  the Path B block assembly
//
// A Path B block is the Path B miner tx and the selected transactions:
//   block blob    header (the hashing blob through its 4-byte nonce)
//                 || miner tx prefix || 0x00 (rct_signatures.type = RCTTypeNull)
//                 || varint(n_tx) || n_tx x 32-byte transaction id
//   hashing blob  header || tree_root([miner tx hash] ++ ids) || varint(n_tx + 1)
//                 (the Path B receipt's HashingBlob, encode_hashing_blob)
// Also: the Monero block id of a hashing blob, and the tx_extra field walk.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "impl/xmr/template/xmr_block_template.hpp"   // NONCE_SIZE, TX_EXTRA_* tags, HASH_SIZE
#include "impl/xmr/coin/xmr_blob.hpp"                 // BlobWriter
#include "impl/xmr/coin/xmr_keccak_midstate.hpp"      // keccak256

namespace c2pool::xmr::assembly {

// The block blob of a Path B block (above). `hashing_blob` holds the header through its nonce at `nonce_offset`;
// `miner_tx_prefix` is the miner tx without its RCTTypeNull byte.
inline std::vector<std::uint8_t> pathb_block_blob(std::span<const std::uint8_t> hashing_blob, std::size_t nonce_offset,
                                                  std::span<const std::uint8_t> miner_tx_prefix,
                                                  std::span<const std::array<std::uint8_t, HASH_SIZE>> tx_ids) {
    std::vector<std::uint8_t> out(hashing_blob.begin(),
                                  hashing_blob.begin() + static_cast<std::ptrdiff_t>(nonce_offset + NONCE_SIZE));
    out.insert(out.end(), miner_tx_prefix.begin(), miner_tx_prefix.end());
    out.push_back(0x00);
    std::uint64_t n = tx_ids.size();
    do {
        std::uint8_t b = static_cast<std::uint8_t>(n & 0x7f);
        n >>= 7;
        if (n != 0) b |= 0x80;
        out.push_back(b);
    } while (n != 0);
    for (const std::array<std::uint8_t, HASH_SIZE>& id : tx_ids) out.insert(out.end(), id.begin(), id.end());
    return out;
}

// Monero block id = keccak256( varint(len(hashing_blob)) || hashing_blob ), with
// the nonce already patched into the blob (get_block_hash over the hashing blob).
inline ::xmr::coin::Hash256 block_id_of(const std::vector<std::uint8_t>& hashing_blob_with_nonce) {
    ::xmr::coin::BlobWriter w;
    w.put_varint(hashing_blob_with_nonce.size());
    w.put_bytes(hashing_blob_with_nonce.data(), hashing_blob_with_nonce.size());
    return ::xmr::coin::keccak256(w.bytes());
}

// ---------------------------------------------------------------------------
// walk_tx_extra -- the tx_extra TLV walk, field by field IN ANY ORDER, with the
// field grammar monerod's parse_tx_extra (cryptonote_basic/tx_extra.h) reads:
//   0x00 padding           zero bytes to the END of tx_extra, <= 255 bytes incl. the tag
//   0x01 tx pubkey         32 bytes
//   0x02 extra nonce       varint(len <= 255) + len bytes
//   0x03 merge-mining tag  varint(len) + len bytes, which hold varint(depth) + root[32]
//   0x04 additional keys   varint(count) + 32 * count bytes
//   0xDE minergate         varint(len) + len bytes
// Anything else (an unknown tag, a truncated or malformed field) STOPS the walk
// there: monerod's parse_tx_extra fails at the same byte and keeps the fields
// read before it. The walk never throws and never rejects the transaction --
// Monero consensus does not require a coinbase tx_extra to parse, so a valid
// block can carry any bytes here (merge-mined blocks put 0x03 FIRST; see block
// 3765869). A pure function of the bytes: every node walks it identically.
// ---------------------------------------------------------------------------
struct TxExtraField {
    std::uint8_t tag = 0;
    std::size_t  offset = 0;        // of the tag byte
    std::size_t  size = 0;          // whole field incl. the tag
    std::size_t  data_offset = 0;   // first payload byte (after the tag and any length varint)
    std::size_t  data_size = 0;
};
struct TxExtraWalk {
    std::vector<TxExtraField> fields;   // in the order found
    bool        complete = false;       // true: every byte belongs to a well-formed field
    std::size_t stop_offset = 0;        // == size when complete; else where the walk stopped
    const char* stop_why = "";          // why it stopped early ("" when complete)
    [[nodiscard]] const TxExtraField* first(std::uint8_t tag) const {
        for (const TxExtraField& f : fields) if (f.tag == tag) return &f;
        return nullptr;
    }
};
inline TxExtraWalk walk_tx_extra(const std::uint8_t* x, std::size_t n) {
    TxExtraWalk w;
    std::size_t i = 0;
    auto varint_at = [&](std::size_t& pos, std::uint64_t& v) -> bool {
        const std::uint8_t* it = x + pos;
        const std::uint8_t* end = x + n;
        if (tools::read_varint(it, end, v) <= 0) return false;
        pos = static_cast<std::size_t>(it - x);
        return true;
    };
    auto stop = [&](const char* why) { w.stop_offset = i; w.stop_why = why; return w; };
    while (i < n) {
        TxExtraField f; f.tag = x[i]; f.offset = i;
        std::size_t pos = i + 1;
        switch (f.tag) {
            case 0x00: {   // padding: zeros to the end, <= 255 bytes incl. the tag
                if (n - i > 255) return stop("padding longer than 255 bytes");
                for (std::size_t k = pos; k < n; ++k) if (x[k] != 0) return stop("non-zero byte inside padding");
                f.data_offset = pos; f.data_size = n - pos; pos = n;
                break;
            }
            case 0x01: {   // tx pubkey
                if (n - pos < 32) return stop("truncated 0x01 pubkey");
                f.data_offset = pos; f.data_size = 32; pos += 32;
                break;
            }
            case 0x04: {   // additional pubkeys: varint count + 32 * count
                std::uint64_t cnt = 0;
                if (!varint_at(pos, cnt)) return stop("bad 0x04 count varint");
                if (cnt > (n - pos) / 32) return stop("truncated 0x04 additional pubkeys");
                f.data_offset = pos; f.data_size = static_cast<std::size_t>(cnt) * 32; pos += f.data_size;
                break;
            }
            case 0x02: case 0x03: case 0xDE: {   // length-prefixed blobs
                std::uint64_t len = 0;
                if (!varint_at(pos, len)) return stop("bad length varint");
                if (len > n - pos) return stop("truncated length-prefixed field");
                if (f.tag == 0x02 && len > 255) return stop("0x02 nonce longer than 255 bytes");
                if (f.tag == 0x03) {   // the blob must hold varint(depth) + root[32]
                    std::size_t in = pos; std::uint64_t depth = 0;
                    const std::size_t lim = pos + static_cast<std::size_t>(len);
                    const std::uint8_t* it = x + in; const std::uint8_t* end = x + lim;
                    if (tools::read_varint(it, end, depth) <= 0) return stop("bad 0x03 depth varint");
                    in = static_cast<std::size_t>(it - x);
                    if (lim - in < 32) return stop("truncated 0x03 merkle root");
                }
                f.data_offset = pos; f.data_size = static_cast<std::size_t>(len); pos += f.data_size;
                break;
            }
            default:
                return stop("unknown tx_extra tag");
        }
        f.size = pos - i;
        w.fields.push_back(f);
        i = pos;
    }
    w.complete = true; w.stop_offset = n;
    return w;
}

}  // namespace c2pool::xmr::assembly
