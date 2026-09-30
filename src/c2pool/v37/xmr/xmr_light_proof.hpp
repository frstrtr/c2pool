// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_light_proof.hpp
//
// VERIFYING PAYMENT WITHOUT THE SHARE CHAIN (Purple Paper §13). A device that
// holds only Monero block headers proves one worker's owed balance:
//
//   block header (hashing blob) --tree branch--> the miner tx (leaf 0)
//   miner tx prefix (Keccak midstate + tail + tx_extra) --> tx_extra's 0x03 root
//   0x03 root == keccak(domain || chain || owed_digest)          (depth 0)
//   owed_digest == sha256d("V37Y" || rows || merkle_root || rest) (merkle_rows)
//   merkle_root <--path of log2(rows) hashes-- sha256d("V37L" || key || balance || age)
//
// The proof is a few hundred bytes: the block's hashing blob, the coinbase
// opening (200-byte midstate, a tail < 136 bytes, tx_extra), the tx-tree
// branch (32 bytes per level) and the balance path (32 bytes per level). The
// device checks the block id against its own header chain and Monero's PoW;
// this file checks everything below the header, with no share-chain data.
//
// The balance proved is the FINALIZED balance of the ledger state the block
// commits (the booking point of that block: every lane block at least D_conf
// below it is settled into it). Pending blocks are not in it.
// ===========================================================================
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>                 // OwedLedger, OwedProof
#include "impl/xmr/coin/xmr_blob.hpp"                    // tree_root, make_coinbase_branch, ...
#include "impl/xmr/coin/xmr_keccak_midstate.hpp"         // keccak256
#include "impl/xmr/receipt/xmr_receipt_verify.hpp"       // verify_crypto_opening, build_coinbase_opening
#include "impl/xmr/settle/xmr_coinbase.hpp"              // mm_commitment_root

namespace c2pool::v37n::xmr::light {

using ::v37::bytes32;
using OwedLedger = ::c2pool::v37n::settle::OwedLedger;

struct LightBalanceProof {
    ::v37::xmr::MoneroReceipt block;     // hashing blob + coinbase opening + tree branch
    std::uint32_t             chain_id = 0;
    OwedLedger::OwedProof     owed;      // the balance and its path to owed_digest
};

// What the prover needs about ONE Monero block: its header fields, the miner
// tx prefix split at tx_extra, and the other transactions' hashes.
struct LightBlockInputs {
    std::uint8_t          major = 16, minor = 16;
    std::uint64_t         timestamp = 0;
    bytes32               prev_id{};
    std::uint32_t         nonce = 0;
    std::vector<std::uint8_t> miner_tx_prefix;   // the serialized prefix, tx_extra last
    std::size_t           extra_start = 0;       // where the tx_extra bytes begin
    std::vector<bytes32>  other_tx_hashes;       // leaves 1..n-1 of the tx tree
};

struct LightVerdict {
    bool          ok = false;
    std::string   why;
    long long     balance = 0;          // the finalized owed balance, piconero
    std::uint64_t first_eligible = 0;   // its age in the queue (0 = none)
    bytes32       block_id{};           // check it against the header chain
    bytes32       prev_id{};
};

namespace detail {
inline void put_varint(std::vector<std::uint8_t>& b, std::uint64_t v) {
    while (v >= 0x80) { b.push_back(static_cast<std::uint8_t>((v & 0x7f) | 0x80)); v >>= 7; }
    b.push_back(static_cast<std::uint8_t>(v));
}
inline bytes32 to_b32(const ::xmr::coin::Hash256& h) { bytes32 b; std::memcpy(b.data(), h.data(), 32); return b; }
inline ::xmr::coin::Hash256 to_h(const bytes32& b) { ::xmr::coin::Hash256 h; std::memcpy(h.data(), b.data(), 32); return h; }
// The last 0x03 field of tx_extra: the merge-mining root (depth 0).
inline std::optional<bytes32> mm_root_of_extra(const std::vector<std::uint8_t>& x) {
    if (x.size() < 35) return std::nullopt;
    const std::uint8_t* t = x.data() + x.size() - 35;
    if (t[0] != 0x03 || t[1] != 0x21 || t[2] != 0x00) return std::nullopt;
    bytes32 r; std::memcpy(r.data(), t + 3, 32);
    return r;
}
}  // namespace detail

// Monero block id: keccak(varint(len(blob)) || hashing blob).
inline bytes32 block_id_of(const std::vector<std::uint8_t>& hashing_blob) {
    std::vector<std::uint8_t> b;
    detail::put_varint(b, hashing_blob.size());
    b.insert(b.end(), hashing_blob.begin(), hashing_blob.end());
    return detail::to_b32(::xmr::coin::keccak256(b.data(), b.size()));
}

// Build the proof for `key` from one lane block and the ledger state its 0x03
// root commits (merkle_rows on). False: the key has no balance there, the
// ledger does not run merkle_rows, or the block does not commit this state.
inline bool make_light_proof(const LightBlockInputs& in, std::uint32_t chain_id, const OwedLedger& ledger,
                             const bytes32& key, LightBalanceProof& out, std::string* why = nullptr) {
    auto fail = [&](const char* w) { if (why) *why = w; return false; };
    const auto owed = ledger.prove_owed(key);
    if (!owed) return fail("no merkle-rows balance for this key in this ledger state");
    auto& r = out.block;
    if (!::v37::xmr::verify::build_coinbase_opening(in.miner_tx_prefix, in.extra_start, r.coinbase_opening))
        return fail("extra_start out of range");
    bytes32 hp{};
    if (!::v37::xmr::verify::resume_prefix_hash(r.coinbase_opening, hp)) return fail("bad prefix tail");
    std::vector<::xmr::coin::Hash256> leaves;
    leaves.push_back(::xmr::coin::coinbase_tx_hash(detail::to_h(hp)));
    for (const auto& h : in.other_tx_hashes) leaves.push_back(detail::to_h(h));
    ::xmr::coin::TreeBranch cb;
    if (!::xmr::coin::make_coinbase_branch(leaves, cb)) return fail("tree branch");
    r.tree_branch.path.clear();
    for (const auto& s : cb.branch) r.tree_branch.path.push_back(detail::to_b32(s));
    r.tree_branch.depth = static_cast<std::uint8_t>(cb.depth);
    r.tree_branch.path_bits = cb.path;
    const auto header = ::xmr::coin::write_block_header_prefix(in.major, in.minor, in.timestamp,
                                                               detail::to_h(in.prev_id), in.nonce);
    const auto blob = ::xmr::coin::assemble_hashing_blob(header, ::xmr::coin::tree_root(leaves), leaves.size());
    r.hashing_blob.bytes.assign(blob.begin(), blob.end());
    const auto root = detail::mm_root_of_extra(r.coinbase_opening.tx_extra);
    if (!root) return fail("the miner tx carries no 0x03 root");
    const auto commit = ::v37::xmr::settle::mm_commitment_root(chain_id, ledger.owed_digest());
    if (std::memcmp(commit.data(), root->data(), 32) != 0) return fail("this block does not commit this ledger state");
    out.chain_id = chain_id;
    out.owed = *owed;
    return true;
}

// Check everything below the header: the tree branch, the coinbase, the 0x03
// root, the owed_digest and the balance path. The caller then checks
// verdict.block_id in its header chain (and Monero's PoW on it).
inline LightVerdict verify_light_balance(const LightBalanceProof& p) {
    LightVerdict v;
    ::v37::xmr::OpenedCommitment oc;
    std::string w;
    if (!::v37::xmr::verify::verify_crypto_opening(p.block, oc, &w)) { v.why = "block: " + w; return v; }
    const auto root = detail::mm_root_of_extra(p.block.coinbase_opening.tx_extra);
    if (!root) { v.why = "the miner tx carries no 0x03 root"; return v; }
    const auto digest = OwedLedger::owed_digest_from_proof(p.owed);
    if (!digest) { v.why = "malformed balance path"; return v; }
    const auto commit = ::v37::xmr::settle::mm_commitment_root(p.chain_id, *digest);
    if (std::memcmp(commit.data(), root->data(), 32) != 0) { v.why = "the balance path does not reach the block's 0x03 root"; return v; }
    ::v37::xmr::verify::ParsedBlob pb;
    if (!::v37::xmr::verify::parse_hashing_blob(p.block.hashing_blob, pb)) { v.why = "hashing blob"; return v; }
    v.ok = true;
    v.balance = p.owed.finalW;
    v.first_eligible = p.owed.first_eligible;
    v.block_id = block_id_of(p.block.hashing_blob.bytes);
    v.prev_id = pb.prev_id;
    return v;
}

}  // namespace c2pool::v37n::xmr::light
