// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/coin/xmr_blob.hpp  --  CryptoNote varint + blob serialization
//
// AUTHORED for c2pool (not ported). v37 builds the Monero miner_tx itself
// (monerod's get_block_template gives a one-output coinbase we cannot use, as
// p2pool notes), so the lane needs its own CryptoNote serializer rather than a
// port of monerod's heavyweight serialization/ framework. Byte formats follow
// the CryptoNote wire spec and monero-project cryptonote_format_utils.cpp; the
// LEB128 varint itself is the VENDORED tools::write_varint (vendor/varint.h,
// BSD-3), so our varints are byte-identical to Monero's.
//
// Covers exactly the XMR-lane surface (scoping S2.5 / S5 / S16):
//   * BlobWriter               -- append varints / raw bytes / 32-byte keys
//   * block hashing-blob header -- varint(major) varint(minor) varint(ts)
//                                  prev_id[32] nonce[4 LE]         (~43-49 B)
//   * assemble_hashing_blob     -- header || tree_root[32] || varint(n_tx)
//                                  (== get_block_hashing_blob, the RandomX input)
//   * coinbase tx-prefix scaffold (txin_gen, txout_to_tagged_key, tx_extra)
//   * v2 RCTTypeNull coinbase tx hash (leaf 0 of the tree)
//   * tree_root / tree_branch / branch-verify over the vendored tree-hash.c
//
// The tx-prefix serialization order (CryptoNote): version, unlock_time,
// vin[] (1x txin_gen = tag 0xFF + varint height), vout[] (varint count +
// per-output: varint amount + tag + key[32] + view_tag[1]), tx_extra
// (varint length + bytes). tx_extra's LAST position is why the Keccak midstate
// opening (xmr_keccak_midstate.hpp) splits there.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "xmr_crypto_types.hpp"
#include "vendor/varint.h"   // tools::write_varint / read_varint (BSD-3, vendored)

namespace xmr::coin {

// CryptoNote constants (monero-project cryptonote_config.h / txout tags).
inline constexpr std::uint8_t TXIN_GEN            = 0xFF; // coinbase input tag
inline constexpr std::uint8_t TXOUT_TO_TAGGED_KEY = 0x03; // since HF15
inline constexpr std::uint8_t TXOUT_TO_KEY        = 0x02; // pre-HF15 (not used by lane)
inline constexpr std::uint64_t TX_VERSION_2       = 2;
inline constexpr std::uint64_t MINER_REWARD_UNLOCK_TIME = 60; // unlock = h + 60
// tx_extra tags
inline constexpr std::uint8_t TX_EXTRA_TAG_PADDING       = 0x00;
inline constexpr std::uint8_t TX_EXTRA_TAG_PUBKEY        = 0x01;
inline constexpr std::uint8_t TX_EXTRA_TAG_NONCE         = 0x02;
inline constexpr std::uint8_t TX_EXTRA_TAG_MERGE_MINING  = 0x03;
inline constexpr std::uint8_t TX_EXTRA_TAG_ADDITIONAL_PUBKEYS = 0x04;

// Append-only byte buffer with CryptoNote LEB128 varints (vendored codec).
class BlobWriter {
public:
    void put_byte(std::uint8_t b) { buf_.push_back(b); }
    void put_bytes(const void* p, std::size_t n) {
        const auto* c = static_cast<const unsigned char*>(p);
        buf_.insert(buf_.end(), c, c + n);
    }
    void put_key(const Bytes32& k) { put_bytes(k.data(), 32); }

    // LEB128 varint, byte-identical to monerod (tools::write_varint).
    void put_varint(std::uint64_t v) {
        char tmp[(sizeof(std::uint64_t) * 8 + 6) / 7]; // max 10 bytes
        char* end = tmp;
        tools::write_varint(end, v);
        put_bytes(tmp, static_cast<std::size_t>(end - tmp));
    }

    // 4-byte little-endian nonce (Monero header nonce field).
    void put_u32_le(std::uint32_t v) {
        for (int i = 0; i < 4; ++i) put_byte(static_cast<std::uint8_t>(v >> (8 * i)));
    }

    const std::vector<unsigned char>& bytes() const { return buf_; }
    std::vector<unsigned char>&& take() { return std::move(buf_); }
    std::size_t size() const { return buf_.size(); }
    void clear() { buf_.clear(); }

private:
    std::vector<unsigned char> buf_;
};

// Minimal Monero block-header hashing-blob fields (NO tree root / n_tx yet).
//   varint(major) varint(minor) varint(timestamp) prev_id[32] nonce[4 LE]
inline std::vector<unsigned char> write_block_header_prefix(
        std::uint8_t major, std::uint8_t minor, std::uint64_t timestamp,
        const Hash256& prev_id, std::uint32_t nonce) {
    BlobWriter w;
    w.put_varint(major);
    w.put_varint(minor);
    w.put_varint(timestamp);
    w.put_key(prev_id);
    w.put_u32_le(nonce);
    return std::vector<unsigned char>(w.bytes());
}

// get_block_hashing_blob: header || tree_root[32] || varint(tx_count incl. miner_tx).
// This is the exact byte string RandomX hashes (scoping S2.5).
inline std::vector<unsigned char> assemble_hashing_blob(
        const std::vector<unsigned char>& header_prefix,
        const Hash256& tree_root, std::uint64_t tx_count) {
    BlobWriter w;
    w.put_bytes(header_prefix.data(), header_prefix.size());
    w.put_key(tree_root);
    w.put_varint(tx_count);
    return std::vector<unsigned char>(w.bytes());
}

// One coinbase payee, serialized as varint(amount) || TXOUT_TO_TAGGED_KEY ||
// one_time_key[32] || view_tag[1]. ~39-42 B.
inline void write_tagged_key_output(BlobWriter& w, std::uint64_t amount,
                                    const PublicKey& one_time_key, ViewTag vt) {
    w.put_varint(amount);
    w.put_byte(TXOUT_TO_TAGGED_KEY);
    w.put_key(one_time_key);
    w.put_byte(vt.tag);
}

// Serialize the coinbase tx-prefix UP TO (but not including) the tx_extra
// section, i.e. version, unlock_time, the single txin_gen, and all outputs +
// the extra-length varint boundary handled by the caller. Splitting here lets
// the caller take the Keccak midstate before absorbing tx_extra.
//   outputs: parallel arrays of (amount, one_time_key, view_tag), n entries.
std::vector<unsigned char> write_coinbase_prefix_head(
        std::uint64_t height,
        const std::uint64_t* amounts, const PublicKey* keys, const ViewTag* vtags,
        std::size_t n_outputs);

// --- consensus hashes (defined in xmr_blob.cpp over vendored keccak/tree-hash) ---

// keccak256(prefix_bytes) == monerod get_transaction_prefix_hash.
Hash256 tx_prefix_hash(const std::vector<unsigned char>& prefix_bytes);

// v2 RCTTypeNull coinbase tx hash:
//   keccak256( prefix_hash || keccak256(0x00) || null_hash )
// (monerod calculate_transaction_hash: hashes[1]=H(rct base=type byte),
//  hashes[2]=null for RCTTypeNull). This is tree leaf 0.
Hash256 coinbase_tx_hash(const Hash256& prefix_hash);

// tree_root over the ordered tx-hash list (miner_tx at index 0). Vendored tree_hash.
Hash256 tree_root(const std::vector<Hash256>& tx_hashes);

// Coinbase-opening branch: proof that leaf 0 (the coinbase) is under `root`.
// depth/path/branch produced by vendored tree_branch; verified by tree_branch_hash.
struct TreeBranch {
    std::vector<Hash256> branch; // sibling hashes, root-ward
    std::uint32_t        path = 0;
    std::size_t          depth = 0;
};
bool make_coinbase_branch(const std::vector<Hash256>& tx_hashes, TreeBranch& out);
bool verify_branch(const Hash256& leaf, const TreeBranch& b, const Hash256& root);

} // namespace xmr::coin
