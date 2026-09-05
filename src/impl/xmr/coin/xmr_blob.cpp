// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// src/impl/xmr/coin/xmr_blob.cpp -- AUTHORED. Consensus hash assembly for the
// XMR-lane coinbase, layered over the vendored monero-project keccak/tree-hash
// (BSD-3). See xmr_blob.hpp for the byte formats and provenance.

#include "xmr_blob.hpp"
#include "xmr_keccak_midstate.hpp"   // keccak256()

#include <cstring>
#include <stdexcept>

extern "C" {
#include "vendor/hash-ops.h"   // cn_fast_hash, tree_hash, tree_branch, tree_branch_hash (BSD-3)
}

namespace xmr::coin {

std::vector<unsigned char> write_coinbase_prefix_head(
        std::uint64_t height,
        const std::uint64_t* amounts, const PublicKey* keys, const ViewTag* vtags,
        std::size_t n_outputs) {
    BlobWriter w;
    w.put_varint(TX_VERSION_2);                     // version
    w.put_varint(height + MINER_REWARD_UNLOCK_TIME); // unlock_time = h + 60
    // vin: exactly one txin_gen
    w.put_varint(1);                                // vin count
    w.put_byte(TXIN_GEN);                           // 0xFF
    w.put_varint(height);                           // gen height
    // vout
    w.put_varint(n_outputs);
    for (std::size_t i = 0; i < n_outputs; ++i)
        write_tagged_key_output(w, amounts[i], keys[i], vtags[i]);
    // NOTE: tx_extra (varint length + bytes) is appended by the caller AFTER
    // the Keccak midstate is snapshotted here.
    return std::vector<unsigned char>(w.bytes());
}

Hash256 tx_prefix_hash(const std::vector<unsigned char>& prefix_bytes) {
    return keccak256(prefix_bytes);   // == cn_fast_hash(prefix)
}

Hash256 coinbase_tx_hash(const Hash256& prefix_hash) {
    // hashes[1] = keccak256 of the RCTTypeNull base blob = the single type byte 0x00.
    const unsigned char rct_base_null = 0x00;
    Hash256 h_rct = keccak256(&rct_base_null, 1);
    // hashes[2] = null_hash (32 zero bytes) for RCTTypeNull.
    unsigned char triple[96];
    std::memcpy(triple + 0,  prefix_hash.data(), 32);
    std::memcpy(triple + 32, h_rct.data(),       32);
    std::memset(triple + 64, 0,                  32);   // null_hash
    return keccak256(triple, sizeof(triple));
}

Hash256 tree_root(const std::vector<Hash256>& tx_hashes) {
    if (tx_hashes.empty()) throw std::runtime_error("tree_root: empty");
    Hash256 root;
    tree_hash(reinterpret_cast<const char(*)[HASH_SIZE]>(tx_hashes.data()),
              tx_hashes.size(),
              reinterpret_cast<char*>(root.data()));
    return root;
}

bool make_coinbase_branch(const std::vector<Hash256>& tx_hashes, TreeBranch& out) {
    const std::size_t n = tx_hashes.size();
    if (n == 0) return false;
    // depth is at most ceil(log2(n)); size generously.
    std::size_t maxdepth = 0;
    for (std::size_t p = 1; p < n; p <<= 1) ++maxdepth;
    out.branch.assign(maxdepth + 1, Hash256{});
    std::size_t depth = 0;
    std::uint32_t path = 0;
    const bool ok = tree_branch(
        reinterpret_cast<const char(*)[HASH_SIZE]>(tx_hashes.data()), n,
        reinterpret_cast<const char*>(tx_hashes[0].data()),   // leaf 0 = coinbase
        reinterpret_cast<char(*)[HASH_SIZE]>(out.branch.data()),
        &depth, &path);
    if (!ok) return false;
    out.branch.resize(depth);
    out.depth = depth;
    out.path  = path;
    return true;
}

bool verify_branch(const Hash256& leaf, const TreeBranch& b, const Hash256& root) {
    return is_branch_in_tree(
        reinterpret_cast<const char*>(leaf.data()),
        reinterpret_cast<const char*>(root.data()),
        reinterpret_cast<const char(*)[HASH_SIZE]>(b.branch.data()),
        b.depth, b.path) != 0;
}

} // namespace xmr::coin
