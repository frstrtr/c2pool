// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/consensus/xmr_block_id.hpp
//
// BLOCK IDENTITY: the coinbase hash, the transaction tree root, the hashing
// blob and the block id, over a block blob that arrived from a peer.
//
// This is the ONE file in C2a that needs a hash function linked; everything
// else in the component is header-only STL over the parse in
// xmr_block_parse.hpp. That split is deliberate: the fields (versions, weights,
// rewards, timestamps, difficulty) are usable on a host with no crypto at all,
// and only identity pulls in keccak.
//
// It links the KECCAK AND TREE-HASH THAT ARE ALREADY IN THIS REPOSITORY
// (`xmr_coin` -- the vendored Monero keccak.c and tree-hash.c behind
// impl/xmr/coin/xmr_blob.hpp), rather than vendoring a second copy. A second
// keccak in the same binary is a divergence waiting to happen, and the coin
// tree's copy is the one the settlement lane's coinbase KATs already pin.
//
// The four values, in monerod's terms (cryptonote_format_utils.cpp,
// cryptonote_basic_impl.cpp):
//
//   miner_tx_hash  v1 coinbase: cn_fast_hash(whole tx blob).
//                  v2 coinbase (RCTTypeNull): cn_fast_hash of the three-hash
//                  triple { prefix_hash, cn_fast_hash(0x00), null_hash }.
//                  Both spellings live in xmr::coin (xmr_blob.cpp), pinned by
//                  the lane's coinbase KAT.
//   tree_root      tree_hash over [miner_tx_hash, tx_hashes...] -- the coinbase
//                  is leaf 0, wire order for the rest.
//   hashing_blob   header bytes (verbatim, sliced) || tree_root || varint(n_tx)
//   id             cn_fast_hash( varint(len(hashing_blob)) || hashing_blob )
//                  -- note the length prefix; see block_id_from_hashing_blob
//
// THE ONE HISTORICAL EXCEPTION, and why it is not implemented: monerod's
// get_block_hash() special-cases mainnet block 202612, whose blob is malformed
// in a way that made two different serializations hash differently, and returns
// the hardcoded id bbd604d2ba11ba27935e006ed39c9bfdd99b76bf4a50654bc1e1e61217962698.
// That height is nine hundred thousand blocks below any anchor this node will
// ever start from (the anchor bundle is a modern height, D-9), so implementing
// the exception would add an untestable branch to consensus code for a block we
// cannot reach. If a future anchor ever moves below 202612 on mainnet, this is
// the note that says what must be added.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "xmr_block_parse.hpp"
#include "impl/xmr/coin/xmr_blob.hpp"            // tree_root, coinbase_tx_hash, tx_prefix_hash
#include "impl/xmr/coin/xmr_keccak_midstate.hpp" // keccak256

namespace c2pool::xmr::native {

// The identity of one block, all four values together so a caller cannot
// accidentally recompute one of them with a different input than another.
struct BlockIdentity {
    BlockHash                 id{};
    BlockHash                 miner_tx_hash{};
    BlockHash                 tree_root{};
    std::vector<std::uint8_t> hashing_blob;
};

namespace detail {

inline BlockHash from_coin_hash(const ::xmr::coin::Hash256& h) noexcept {
    BlockHash out{};
    std::memcpy(out.data(), h.data(), 32);
    return out;
}

inline ::xmr::coin::Hash256 to_coin_hash(const BlockHash& h) noexcept {
    ::xmr::coin::Hash256 out{};
    std::memcpy(out.bytes.data(), h.data(), 32);
    return out;
}

} // namespace detail

// --- the coinbase hash -------------------------------------------------------
// `block_blob` must be the buffer the ParsedBlock was parsed from: the spans
// inside it index into that buffer.
inline BlockHash miner_tx_hash(const std::uint8_t* block_blob, const ParsedBlock& pb) {
    if (pb.miner_tx.version < 2) {
        // v1: the hash is over the whole transaction blob.
        return detail::from_coin_hash(
            ::xmr::coin::keccak256(block_blob + pb.miner_tx_offset, pb.miner_tx_size));
    }
    // v2 with RCTTypeNull, which parse_block() has already required of a
    // coinbase: prefix hash, then the fixed three-hash triple.
    const std::vector<unsigned char> prefix(
        block_blob + pb.miner_tx_offset,
        block_blob + pb.miner_tx_offset + pb.miner_tx.prefix_size);
    const ::xmr::coin::Hash256 ph = ::xmr::coin::tx_prefix_hash(prefix);
    return detail::from_coin_hash(::xmr::coin::coinbase_tx_hash(ph));
}

// --- the tree root -----------------------------------------------------------
// Leaf 0 is the coinbase; the rest are the block's tx_hashes in wire order.
inline BlockHash block_tree_root(const BlockHash& miner_hash,
                                 const std::vector<BlockHash>& tx_hashes) {
    std::vector<::xmr::coin::Hash256> leaves;
    leaves.reserve(tx_hashes.size() + 1);
    leaves.push_back(detail::to_coin_hash(miner_hash));
    for (const BlockHash& h : tx_hashes) leaves.push_back(detail::to_coin_hash(h));
    return detail::from_coin_hash(::xmr::coin::tree_root(leaves));
}

// --- the id ------------------------------------------------------------------
//
// THE LENGTH PREFIX, which is the trap in this whole file. The block id is
//
//     keccak256( varint(len(hashing_blob)) || hashing_blob )
//
// and NOT keccak256(hashing_blob). monerod's get_block_hash() passes the
// hashing blob through get_object_hash(const blobdata&), and serializing a
// blobdata writes its length as a varint first -- so the length is inside the
// hash. The PoW input is the OTHER one: rx_slow_hash is fed the bare hashing
// blob, with no prefix. Two different hashes over almost the same bytes, and
// swapping them produces ids that look perfectly well-formed and match nothing.
//
// This was caught by the golden rather than by reading: the first cut of this
// file hashed the bare blob, every other value in the KAT agreed with monerod,
// and all ten block ids were wrong. The in-tree spelling that already had it
// right is xmr::block_id_of() in impl/xmr/template/xmr_block_assembly.hpp.
inline BlockHash block_id_from_hashing_blob(const std::vector<std::uint8_t>& hashing_blob) {
    std::vector<std::uint8_t> prefixed;
    prefixed.reserve(hashing_blob.size() + 10);
    blob_write_varint(prefixed, static_cast<std::uint64_t>(hashing_blob.size()));
    prefixed.insert(prefixed.end(), hashing_blob.begin(), hashing_blob.end());
    return detail::from_coin_hash(::xmr::coin::keccak256(prefixed.data(), prefixed.size()));
}

// Everything at once, from a parsed block and the buffer it was parsed from.
inline BlockIdentity block_identity(const std::uint8_t* block_blob, const ParsedBlock& pb) {
    BlockIdentity out;
    out.miner_tx_hash = miner_tx_hash(block_blob, pb);
    out.tree_root     = block_tree_root(out.miner_tx_hash, pb.tx_hashes);
    out.hashing_blob  = assemble_hashing_blob(block_blob, pb, out.tree_root);
    out.id            = block_id_from_hashing_blob(out.hashing_blob);
    return out;
}

// Parse and identify in one call, for the common case.
inline BlockParseStatus parse_and_identify(const std::vector<std::uint8_t>& blob,
                                           ParsedBlock& pb, BlockIdentity& id) {
    const BlockParseStatus st = parse_block(blob, pb);
    if (st != BlockParseStatus::Ok) return st;
    id = block_identity(blob.data(), pb);
    return st;
}

// --- transaction-id authentication -------------------------------------------
// The tree root binds the block's tx_hashes into the PoW-signed blob, so a peer
// cannot swap a transaction for another without breaking the id. What it does
// NOT do by itself is tie the BODIES the peer sent to those ids -- that is this
// check, and it is why a pruned sync is safe: the pruned blob plus the prunable
// hash reproduce the id.
//
//   v1 tx  : id == cn_fast_hash(full blob)                (no pruned form)
//   v2 tx  : id == cn_fast_hash( prefix_hash
//                              || cn_fast_hash(rct base bytes)
//                              || prunable_hash )
//            where a pruned body supplies prunable_hash from the wire and an
//            RCTTypeNull body (a coinbase) uses the null hash for it.
//
// `prunable_hash` is ignored for a v1 transaction and for RCTTypeNull.
inline BlockHash tx_hash_from_parts(const std::uint8_t* blob, std::size_t size,
                                    const TxWeightInfo& info,
                                    const BlockHash& prunable_hash) {
    if (info.version < 2)
        return detail::from_coin_hash(::xmr::coin::keccak256(blob, size));

    unsigned char triple[96];
    const std::vector<unsigned char> prefix(blob, blob + info.prefix_size);
    const ::xmr::coin::Hash256 ph = ::xmr::coin::tx_prefix_hash(prefix);
    std::memcpy(triple + 0, ph.data(), 32);

    if (info.rct_type == RCT_TYPE_NULL) {
        // monerod hashes the one-byte RCTTypeNull base and uses the null hash
        // for the prunable part; xmr::coin::coinbase_tx_hash is exactly that.
        return detail::from_coin_hash(::xmr::coin::coinbase_tx_hash(ph));
    }

    const ::xmr::coin::Hash256 base =
        ::xmr::coin::keccak256(blob + info.prefix_size, info.rct_base_size);
    std::memcpy(triple + 32, base.data(), 32);
    std::memcpy(triple + 64, prunable_hash.data(), 32);
    return detail::from_coin_hash(::xmr::coin::keccak256(triple, sizeof(triple)));
}

// The same identity for a body we hold in FULL: the prunable hash is not taken
// from the wire, it is computed from the bytes that are there. `info` must have
// come from parse_tx_full() (prunable_size measured, not predicted).
inline BlockHash tx_hash_full(const std::uint8_t* blob, std::size_t size,
                              const TxWeightInfo& info) {
    if (info.version < 2 || info.rct_type == RCT_TYPE_NULL || info.prunable_size == 0)
        return tx_hash_from_parts(blob, size, info, BlockHash{});
    const ::xmr::coin::Hash256 pr =
        ::xmr::coin::keccak256(blob + info.pruned_size, info.prunable_size);
    return tx_hash_from_parts(blob, size, info, detail::from_coin_hash(pr));
}

} // namespace c2pool::xmr::native
