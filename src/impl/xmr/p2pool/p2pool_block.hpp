// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/p2pool_block.hpp
//
// THE SIDECHAIN BLOCK: a Monero block template with P2Pool's own record welded
// onto the end of it.
//
//     +---------------------------------------------+------------------------+
//     |            Monero block template            |     side-chain data    |
//     | ... NONCE ... EXTRA_NONCE ... MM_ROOT ...    | parent, uncles, height,|
//     |                                             | difficulty, proof, ... |
//     +---------------------------------------------+------------------------+
//
// Two things make that picture load-bearing rather than decorative.
//
// FIRST, the Monero half is a COMPLETE, VALID Monero block blob -- header,
// coinbase, transaction id list -- in exactly the layout monerod serialises.
// So this parser does not re-implement Monero: it finds the boundary and hands
// bytes [0, sidechain_offset) to the native lane's own parser
// (native/consensus/xmr_block_parse.hpp) and identity (xmr_block_id.hpp), which
// are the same routines M3's embedded node runs against monerod. That is the
// reuse this component was stacked on M3 for, and it is what lets the observer
// report a real Monero block id, hashing blob and PoW target for a block it
// learned about from a pool it does not participate in.
//
// SECOND, the sidechain id is a hash of the WHOLE picture:
//
//     sidechain_id = keccak256( block_bytes with NONCE, EXTRA_NONCE and the
//                               merge-mining ROOT zeroed  ||  consensus_id )
//
// The three zeroed windows are the fields a miner is allowed to grind, so the
// id is stable while a template is being mined, and the consensus id at the end
// binds the block to one sidechain. Recomputing it is therefore both an
// integrity check on the parse (every offset must be right or the hash is
// wrong) and an authentication of the chain the peer claims to be on. The KAT
// leans on exactly that: it recomputes the id of a block captured off the live
// network and compares it with the id the network itself uses.
//
// ---------------------------------------------------------------------------
// THREE BLOB SHAPES, and what each can honestly be asked
// ---------------------------------------------------------------------------
// Upstream serialises a block three ways, and which one arrives depends on how
// it was asked for:
//
//   Full     -- answer to BLOCK_REQUEST. Every output and every transaction id
//               is present, so the id can be RECOMPUTED and verified.
//   Pruned   -- a broadcast to an old peer. The coinbase outputs are replaced
//               by (total_reward, outputs_blob_size, sidechain_id), because a
//               peer with the PPLNS window can rebuild them. We do not hold
//               that window, so the id is READ from the wire and marked
//               unverified.
//   Compact  -- a broadcast to a current peer. Pruned, and additionally the
//               transaction ids are back-references into the PARENT block's
//               list. Without the parent those references cannot be resolved;
//               they are recorded as unresolved and the id again comes from the
//               wire.
//
// A strictly pulling observer (see p2pool_wire.hpp on why it never sends
// LISTEN_PORT) receives Full blobs and nothing else. The other two are
// implemented anyway, because a peer may send a broadcast unprompted and a
// parser that CANNOT read a legal message would have to guess whether silence
// meant "nothing happened" or "we could not read it".
//
// EVERY read goes through Wave 0's bounds-checked BlobReader
// (native/consensus/xmr_blob_reader.hpp): poisoned-on-first-failure, cursor
// never past the end, varints decoded exactly as monerod's tools::read_varint
// including the non-canonical rejection. These bytes come from an
// unauthenticated peer on a public network, so nothing here is read with a raw
// pointer.
//
// Header-only. STL plus xmr_coin (keccak) plus the native lane's consensus
// headers.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/p2pool/p2pool_consensus.hpp"
#include "impl/xmr/native/consensus/xmr_blob_reader.hpp"
#include "impl/xmr/coin/xmr_keccak_midstate.hpp"

namespace c2pool::xmr::p2pool {

using Hash = std::array<std::uint8_t, 32>;

// P2Pool difficulty is 128-bit (two varints, low then high). Sidechain
// difficulties are small today -- ~2.5e8 on mini, ~4.4e9 on main -- but the
// cumulative difficulty is not, and truncating it to 64 bits would silently
// break the fork-choice comparison the read model makes.
struct Difficulty {
    std::uint64_t lo = 0;
    std::uint64_t hi = 0;

    bool operator<(const Difficulty& o) const noexcept {
        return (hi != o.hi) ? (hi < o.hi) : (lo < o.lo);
    }
    bool operator==(const Difficulty& o) const noexcept { return hi == o.hi && lo == o.lo; }
    bool empty() const noexcept { return hi == 0 && lo == 0; }

    // Decimal, exact, without a bignum library: repeated division of the
    // 128-bit value by 10^19 is overkill here, so the common case (hi == 0) is
    // printed directly and the rare one falls back to a schoolbook divide.
    std::string to_string() const {
        if (hi == 0) return std::to_string(lo);
        unsigned __int128 v = (static_cast<unsigned __int128>(hi) << 64) | lo;
        std::string s;
        while (v) { s.insert(s.begin(), static_cast<char>('0' + static_cast<int>(v % 10))); v /= 10; }
        return s.empty() ? std::string("0") : s;
    }
    long double as_double() const noexcept {
        return static_cast<long double>(hi) * 18446744073709551616.0L
             + static_cast<long double>(lo);
    }
};

enum class BlobShape : std::uint8_t { Full = 0, Pruned = 1, Compact = 2 };

inline const char* to_string(BlobShape s) noexcept {
    switch (s) {
        case BlobShape::Full:    return "full";
        case BlobShape::Pruned:  return "pruned";
        case BlobShape::Compact: return "compact";
    }
    return "?";
}

enum class BlockStatus : std::uint8_t {
    Ok = 0,
    Truncated,
    BadHeader,          // version / minor-version rules
    BadCoinbase,        // tx version, txin_gen, unlock height, outputs
    BadTxExtra,         // pubkey / nonce / merge-mining tag structure
    BadSidechain,       // uncles, height, difficulty bounds
    TrailingBytes,
    IdMismatch,         // recomputed sidechain id != the one on the wire
    PrunedNotAllowed,   // outputs elided but the caller asked for a full parse
};

inline const char* to_string(BlockStatus s) noexcept {
    switch (s) {
        case BlockStatus::Ok:               return "Ok";
        case BlockStatus::Truncated:        return "Truncated";
        case BlockStatus::BadHeader:        return "BadHeader";
        case BlockStatus::BadCoinbase:      return "BadCoinbase";
        case BlockStatus::BadTxExtra:       return "BadTxExtra";
        case BlockStatus::BadSidechain:     return "BadSidechain";
        case BlockStatus::TrailingBytes:    return "TrailingBytes";
        case BlockStatus::IdMismatch:       return "IdMismatch";
        case BlockStatus::PrunedNotAllowed: return "PrunedNotAllowed";
    }
    return "?";
}

// One PPLNS payout line in the coinbase: who gets paid and how much. This is
// the share set -- the thing the whole sidechain exists to agree on.
struct ShareOutput {
    std::uint64_t reward   = 0;
    Hash          eph_key{};        // one-time output key
    std::uint8_t  view_tag = 0;
};

struct MergeMiningEntry {
    Hash                      chain_id{};
    std::vector<std::uint8_t> data;
};

struct PoolBlock {
    // --- Monero block template ------------------------------------------------
    std::uint8_t  major_version = 0;
    std::uint8_t  minor_version = 0;
    std::uint64_t timestamp     = 0;
    Hash          prev_id{};          // Monero parent block id
    std::uint32_t nonce          = 0;
    std::uint64_t txin_gen_height = 0;   // Monero height this template builds on

    std::vector<ShareOutput> outputs;    // empty when the blob was pruned
    std::uint64_t            total_reward = 0;
    std::size_t              outputs_blob_size = 0;

    Hash          txkey_pub{};
    std::uint64_t extra_nonce_size = 0;
    std::uint32_t extra_nonce      = 0;

    std::uint64_t merkle_tree_data  = 0;
    std::uint32_t mm_n_aux_chains   = 0;
    std::uint32_t mm_nonce          = 0;
    Hash          merkle_root{};

    std::vector<Hash>          tx_hashes;        // excludes the coinbase
    std::vector<std::uint64_t> tx_parent_index;  // compact blobs only; 0 = inline

    // --- side-chain record ----------------------------------------------------
    Hash          miner_spend_key{};
    Hash          miner_view_key{};
    Hash          txkey_sec_seed{};
    Hash          parent{};              // previous SIDECHAIN block
    std::vector<Hash> uncles;
    std::uint64_t sidechain_height = 0;
    Difficulty    difficulty{};
    Difficulty    cumulative_difficulty{};
    std::vector<Hash>            merkle_proof;
    std::vector<MergeMiningEntry> merge_mining_extra;
    std::array<std::uint32_t, 4> sidechain_extra{};

    // --- derived --------------------------------------------------------------
    Hash        sidechain_id{};
    bool        sidechain_id_verified = false;   // true only for a Full blob
    BlobShape   shape = BlobShape::Full;
    std::size_t sidechain_offset = 0;            // end of the Monero block blob
    std::size_t blob_size = 0;

    // The embedded Monero block blob is a contiguous prefix ONLY when nothing
    // was elided; a pruned or compact blob has holes where the outputs and
    // transaction ids should be.
    bool monero_blob_contiguous() const noexcept { return shape == BlobShape::Full; }

    std::uint64_t uncle_count() const noexcept { return uncles.size(); }
};

// ---------------------------------------------------------------------------
// P2POOL'S HASH ORDER, which is NOT byte order.
//
// Upstream's `struct hash` (src/common.h) defines operator< over the 32 bytes
// read as FOUR little-endian uint64 words compared MOST-SIGNIFICANT WORD FIRST:
// bytes 24..31 first, then 16..23, then 8..15, then 0..7. Lexicographic byte
// comparison -- what std::array gives for free -- is a different order, and the
// two disagree on roughly half of all pairs.
//
// That matters in exactly one place on the wire, and it is load-bearing: the
// merge-mining extra list is emitted from a std::map<hash, ...>, so it arrives
// in THIS order, and the parser's duplicate check ("ids must increase") has to
// use the same comparator or it rejects perfectly legal blocks.
//
// THIS WAS FOUND BY RUNNING, not by reading. The first live mini-sidechain
// session parsed most blocks and rejected a steady trickle of them with a
// structural error; the rejected blob, kept by the observer's --dump-failed
// path, was mini block f11e43b57722af45ea9f415360753471f852bc07ec661cdd9d8f27e81cea31fb
// at sidechain height 14757139, whose two merge-mining chain ids are
//
//     40b2...b96a  then  01f0...5990
//
// -- descending lexicographically, ascending in P2Pool's word order. That blob
// is golden B in the KAT, so this comparator cannot regress silently.
// ---------------------------------------------------------------------------
inline bool p2pool_hash_less(const Hash& a, const Hash& b) noexcept {
    auto word = [](const Hash& h, int i) -> std::uint64_t {
        std::uint64_t v = 0;
        for (int k = 7; k >= 0; --k) v = (v << 8) | h[static_cast<std::size_t>(i * 8 + k)];
        return v;
    };
    for (int i = 3; i >= 0; --i) {
        const std::uint64_t x = word(a, i), y = word(b, i);
        if (x != y) return x < y;
    }
    return false;
}

namespace detail {

using native::BlobReader;

inline bool read_hash(BlobReader& r, Hash& h) noexcept { return r.read_bytes(h.data(), 32); }

// p2pool src/pool_block.h :: decode_merkle_tree_data
inline void decode_merkle_tree_data(std::uint64_t mtd,
                                    std::uint32_t& n_aux_chains,
                                    std::uint32_t& nonce) noexcept {
    const std::uint32_t k = static_cast<std::uint32_t>(mtd);
    const std::uint32_t n = 1u + (k & 7u);
    n_aux_chains = 1u + ((k >> 3u) & ((1u << n) - 1u));
    nonce = static_cast<std::uint32_t>(mtd >> (3u + n));
}

} // namespace detail

// ---------------------------------------------------------------------------
// The parse.
//
// `shape` says which serialisation to expect; it is NOT inferred, because the
// message id the blob arrived under already determines it and guessing would
// let a crafted blob pick its own rules.
// ---------------------------------------------------------------------------
inline BlockStatus deserialize(const std::uint8_t* data, std::size_t size,
                               const ConsensusId& consensus, BlobShape shape,
                               PoolBlock& out) {
    out = PoolBlock{};
    out.shape     = shape;
    out.blob_size = size;
    if (!data || size == 0 || size > kMaxBlockSize) return BlockStatus::Truncated;

    native::BlobReader r(data, size);

    // --- Monero block header --------------------------------------------------
    // major/minor are single BYTES here, not varints: upstream writes them that
    // way and refuses minor_version > 127 precisely so the result is still a
    // legal one-byte Monero varint. Reading them as bytes and re-checking the
    // bound is what keeps the embedded blob handable to the native parser.
    if (!r.read_byte(out.major_version)) return BlockStatus::Truncated;
    if (!r.read_byte(out.minor_version)) return BlockStatus::Truncated;
    if (out.minor_version < out.major_version) return BlockStatus::BadHeader;
    if (out.minor_version > 127) return BlockStatus::BadHeader;
    if (!r.read_varint(out.timestamp)) return BlockStatus::Truncated;
    if (!detail::read_hash(r, out.prev_id)) return BlockStatus::Truncated;

    const std::size_t nonce_offset = r.offset();
    if (!r.read_u32_le(out.nonce)) return BlockStatus::Truncated;

    // --- coinbase -------------------------------------------------------------
    std::uint8_t b = 0;
    if (!r.read_byte(b)) return BlockStatus::Truncated;
    if (b != 2) return BlockStatus::BadCoinbase;            // TX_VERSION

    std::uint64_t unlock_height = 0;
    if (!r.read_varint(unlock_height)) return BlockStatus::Truncated;
    if (!r.read_byte(b) || b != 1) return BlockStatus::BadCoinbase;       // one input
    if (!r.read_byte(b) || b != 0xFF) return BlockStatus::BadCoinbase;    // TXIN_GEN
    if (!r.read_varint(out.txin_gen_height)) return BlockStatus::Truncated;
    if (unlock_height != out.txin_gen_height + 60) return BlockStatus::BadCoinbase;

    const std::size_t outputs_offset = r.offset();
    std::uint64_t num_outputs = 0;
    if (!r.read_count(num_outputs, kMaxBlockSize / 35, 35)) return BlockStatus::Truncated;

    if (num_outputs > 0) {
        out.outputs.reserve(static_cast<std::size_t>(num_outputs));
        for (std::uint64_t i = 0; i < num_outputs; ++i) {
            ShareOutput o{};
            if (!r.read_varint(o.reward)) return BlockStatus::Truncated;
            if (o.reward > kMaxOutputValue) return BlockStatus::BadCoinbase;
            if (out.total_reward + o.reward < out.total_reward) return BlockStatus::BadCoinbase;
            out.total_reward += o.reward;
            if (!r.read_byte(b) || b != 3) return BlockStatus::BadCoinbase;   // TAGGED_KEY
            if (!detail::read_hash(r, o.eph_key)) return BlockStatus::Truncated;
            if (!r.read_byte(o.view_tag)) return BlockStatus::Truncated;
            out.outputs.push_back(o);
        }
        out.outputs_blob_size = r.offset() - outputs_offset;
    } else {
        // Pruned form: the outputs are replaced by their sum, their length and
        // the id the sender computed while it still had them.
        if (shape == BlobShape::Full) return BlockStatus::PrunedNotAllowed;
        if (!r.read_varint(out.total_reward)) return BlockStatus::Truncated;
        std::uint64_t obs = 0;
        if (!r.read_varint(obs)) return BlockStatus::Truncated;
        if (obs == 0 || obs > kMaxBlockSize) return BlockStatus::BadCoinbase;
        out.outputs_blob_size = static_cast<std::size_t>(obs);
        if (!detail::read_hash(r, out.sidechain_id)) return BlockStatus::Truncated;
    }
    if (out.total_reward < kBaseBlockReward) return BlockStatus::BadCoinbase;

    // --- tx_extra -------------------------------------------------------------
    std::uint64_t tx_extra_size = 0;
    if (!r.read_varint(tx_extra_size)) return BlockStatus::Truncated;
    const std::size_t extra_begin = r.offset();

    if (!r.read_byte(b) || b != 1) return BlockStatus::BadTxExtra;       // TAG_PUBKEY
    if (!detail::read_hash(r, out.txkey_pub)) return BlockStatus::Truncated;

    if (!r.read_byte(b) || b != 2) return BlockStatus::BadTxExtra;       // EXTRA_NONCE
    if (!r.read_varint(out.extra_nonce_size)) return BlockStatus::Truncated;
    if (out.extra_nonce_size < 4 || out.extra_nonce_size > 14) return BlockStatus::BadTxExtra;
    const std::size_t extra_nonce_offset = r.offset();
    if (!r.read_u32_le(out.extra_nonce)) return BlockStatus::Truncated;
    for (std::uint64_t i = 4; i < out.extra_nonce_size; ++i) {
        if (!r.read_byte(b)) return BlockStatus::Truncated;
        if (b != 0) return BlockStatus::BadTxExtra;   // padding must be zero
    }

    if (!r.read_byte(b) || b != 3) return BlockStatus::BadTxExtra;       // MERGE_MINING_TAG
    std::uint64_t mm_field_size = 0;
    if (!r.read_varint(mm_field_size)) return BlockStatus::Truncated;
    const std::size_t mm_begin = r.offset();
    if (!r.read_varint(out.merkle_tree_data)) return BlockStatus::Truncated;
    detail::decode_merkle_tree_data(out.merkle_tree_data, out.mm_n_aux_chains, out.mm_nonce);
    const std::size_t mm_root_offset = r.offset();
    if (!detail::read_hash(r, out.merkle_root)) return BlockStatus::Truncated;
    if (r.offset() - mm_begin != mm_field_size) return BlockStatus::BadTxExtra;
    if (r.offset() - extra_begin != tx_extra_size) return BlockStatus::BadTxExtra;

    // RCTTypeNull: the coinbase's whole signature section is one zero byte.
    if (!r.read_byte(b) || b != 0) return BlockStatus::BadCoinbase;

    // --- transaction ids ------------------------------------------------------
    std::uint64_t num_transactions = 0;
    if (!r.read_count(num_transactions, kMaxBlockSize / 32,
                      shape == BlobShape::Compact ? 1u : 32u))
        return BlockStatus::Truncated;

    out.tx_hashes.reserve(static_cast<std::size_t>(num_transactions));
    if (shape == BlobShape::Compact) {
        out.tx_parent_index.reserve(static_cast<std::size_t>(num_transactions));
        for (std::uint64_t i = 0; i < num_transactions; ++i) {
            std::uint64_t pi = 0;
            if (!r.read_varint(pi)) return BlockStatus::Truncated;
            Hash h{};
            if (pi == 0 && !detail::read_hash(r, h)) return BlockStatus::Truncated;
            out.tx_parent_index.push_back(pi);
            out.tx_hashes.push_back(h);     // all-zero when it is a back-reference
        }
    } else {
        for (std::uint64_t i = 0; i < num_transactions; ++i) {
            Hash h{};
            if (!detail::read_hash(r, h)) return BlockStatus::Truncated;
            out.tx_hashes.push_back(h);
        }
    }

    out.sidechain_offset = r.offset();

    // --- side-chain record ----------------------------------------------------
    if (!detail::read_hash(r, out.miner_spend_key)) return BlockStatus::Truncated;
    if (!detail::read_hash(r, out.miner_view_key))  return BlockStatus::Truncated;
    if (!detail::read_hash(r, out.txkey_sec_seed))  return BlockStatus::Truncated;
    if (!detail::read_hash(r, out.parent))          return BlockStatus::Truncated;

    std::uint64_t num_uncles = 0;
    if (!r.read_count(num_uncles, kMaxUnclesPerBlock, 32)) return BlockStatus::BadSidechain;
    out.uncles.reserve(static_cast<std::size_t>(num_uncles));
    for (std::uint64_t i = 0; i < num_uncles; ++i) {
        Hash h{};
        if (!detail::read_hash(r, h)) return BlockStatus::Truncated;
        out.uncles.push_back(h);
    }

    if (!r.read_varint(out.sidechain_height)) return BlockStatus::Truncated;
    if (out.sidechain_height > kMaxSidechainHeight) return BlockStatus::BadSidechain;

    if (!r.read_varint(out.difficulty.lo)) return BlockStatus::Truncated;
    if (!r.read_varint(out.difficulty.hi)) return BlockStatus::Truncated;
    if (!r.read_varint(out.cumulative_difficulty.lo)) return BlockStatus::Truncated;
    if (!r.read_varint(out.cumulative_difficulty.hi)) return BlockStatus::Truncated;
    // A block's own difficulty is one summand of the running total, so it can
    // never exceed it. Upstream rejects the inverse too and so do we.
    if (out.cumulative_difficulty < out.difficulty) return BlockStatus::BadSidechain;

    std::uint8_t proof_size = 0;
    if (!r.read_byte(proof_size)) return BlockStatus::Truncated;
    if (proof_size > kLog2MergeMiningMaxChains) return BlockStatus::BadSidechain;
    out.merkle_proof.reserve(proof_size);
    for (std::uint8_t i = 0; i < proof_size; ++i) {
        Hash h{};
        if (!detail::read_hash(r, h)) return BlockStatus::Truncated;
        out.merkle_proof.push_back(h);
    }

    std::uint64_t mm_extra_count = 0;
    if (!r.read_count(mm_extra_count, kMergeMiningMaxChains, 33)) return BlockStatus::BadSidechain;
    Hash prev_chain_id{};
    for (std::uint64_t i = 0; i < mm_extra_count; ++i) {
        MergeMiningEntry e{};
        if (!detail::read_hash(r, e.chain_id)) return BlockStatus::Truncated;
        // Strictly increasing in P2POOL'S hash order -- see p2pool_hash_less
        // above. This is how upstream forbids duplicates, and using byte order
        // here rejects real blocks.
        if (i && !p2pool_hash_less(prev_chain_id, e.chain_id)) return BlockStatus::BadSidechain;
        prev_chain_id = e.chain_id;
        std::uint64_t n = 0;
        if (!r.read_count(n, kMaxBlockSize, 1)) return BlockStatus::Truncated;
        e.data.resize(static_cast<std::size_t>(n));
        if (n && !r.read_bytes(e.data.data(), e.data.size())) return BlockStatus::Truncated;
        out.merge_mining_extra.push_back(std::move(e));
    }

    for (std::size_t i = 0; i < 4; ++i)
        if (!r.read_u32_le(out.sidechain_extra[i])) return BlockStatus::Truncated;

    if (!r.ok()) return BlockStatus::Truncated;
    if (r.remaining() != 0) return BlockStatus::TrailingBytes;

    // --- identity -------------------------------------------------------------
    // Only a Full blob can be re-hashed: the pruned forms have holes exactly
    // where the outputs and (for compact) the transaction ids belong, and
    // filling them needs the PPLNS window this observer deliberately does not
    // keep. For those, the id on the wire is recorded and flagged unverified.
    if (shape == BlobShape::Full) {
        std::vector<std::uint8_t> buf;
        buf.reserve(size + 32);
        buf.assign(data, data + size);
        std::memset(buf.data() + nonce_offset, 0, 4);
        std::memset(buf.data() + extra_nonce_offset, 0, 4);
        std::memset(buf.data() + mm_root_offset, 0, 32);
        buf.insert(buf.end(), consensus.begin(), consensus.end());

        const ::xmr::coin::Hash256 h = ::xmr::coin::keccak256(buf.data(), buf.size());
        Hash computed{};
        std::memcpy(computed.data(), h.data(), 32);
        out.sidechain_id = computed;
        out.sidechain_id_verified = true;
    }

    return BlockStatus::Ok;
}

inline BlockStatus deserialize(const std::vector<std::uint8_t>& blob,
                               const ConsensusId& consensus, BlobShape shape,
                               PoolBlock& out) {
    return deserialize(blob.data(), blob.size(), consensus, shape, out);
}

// The embedded Monero block blob, ready for the native lane's parser. Empty
// unless the sidechain blob was Full.
inline std::vector<std::uint8_t> monero_block_blob(const std::uint8_t* data,
                                                   const PoolBlock& pb) {
    if (!pb.monero_blob_contiguous() || pb.sidechain_offset == 0) return {};
    return std::vector<std::uint8_t>(data, data + pb.sidechain_offset);
}

inline std::string hex(const Hash& h) {
    static const char* d = "0123456789abcdef";
    std::string s(64, '0');
    for (std::size_t i = 0; i < 32; ++i) { s[2 * i] = d[h[i] >> 4]; s[2 * i + 1] = d[h[i] & 15]; }
    return s;
}

} // namespace c2pool::xmr::p2pool
