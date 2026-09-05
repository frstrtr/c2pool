// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// src/impl/xmr/receipt/xmr_receipt_verify.cpp -- real bodies over X1 primitives.
// See xmr_receipt_verify.hpp. No src/sharechain/v37 dependency (scoping §B fence).

#include "xmr_receipt_verify.hpp"

#include <algorithm>
#include <cstring>

// X1 already-vendored primitives (do NOT re-vendor). Compiled with
//   -I <c2pool>/src/impl/xmr/coin  so "vendor/..." resolves.
#include "xmr_keccak_midstate.hpp"   // ::xmr::coin::KeccakMidstate, keccak256
#include "xmr_blob.hpp"              // ::xmr::coin::coinbase_tx_hash, tree_root,
                                     //   make_coinbase_branch, verify_branch,
                                     //   write_block_header_prefix, assemble_hashing_blob

namespace v37 {
namespace xmr {
namespace verify {

namespace {

// ---- byte-string bridges between v37::xmr::bytes32 and ::xmr::coin::Hash256 ----
// Both are bare 32-byte PODs (static_assert in xmr_crypto_types.hpp); the copy is
// exact and endianness-neutral (opaque byte strings).
inline ::xmr::coin::Hash256 to_h(const bytes32& b) {
    ::xmr::coin::Hash256 h;
    std::memcpy(h.data(), b.data(), 32);
    return h;
}
inline bytes32 from_h(const ::xmr::coin::Hash256& h) {
    bytes32 b;
    std::memcpy(b.data(), h.data(), 32);
    return b;
}

// LEB128 varint decode (CryptoNote / tools::read_varint semantics). Advances pos.
bool read_varint(const std::vector<u8>& b, std::size_t& pos, u64& out) {
    u64 v = 0; int shift = 0;
    while (pos < b.size()) {
        const u8 byte = b[pos++];
        if (shift > 63) return false;                 // overflow guard
        v |= static_cast<u64>(byte & 0x7f) << shift;
        if (!(byte & 0x80)) { out = v; return true; }
        shift += 7;
    }
    return false;                                      // truncated
}

inline void put_le64(std::vector<u8>& b, u64 v) {
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<u8>(v >> (8 * i)));
}
inline void put_le32(std::vector<u8>& b, u32 v) {
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<u8>(v >> (8 * i)));
}
inline void set_why(std::string* why, const char* m) { if (why) *why = m; }

} // namespace

// ---------------------------------------------------------------------------
bool parse_hashing_blob(const HashingBlob& blob, ParsedBlob& out) {
    const auto& b = blob.bytes;
    std::size_t pos = 0;
    if (!read_varint(b, pos, out.major))     return false;
    if (!read_varint(b, pos, out.minor))     return false;
    if (!read_varint(b, pos, out.timestamp)) return false;
    if (pos + 32 + 4 > b.size())             return false;
    std::memcpy(out.prev_id.data(), b.data() + pos, 32);
    pos += 32;                    // prev_id
    pos += 4;                     // nonce (4 LE)
    out.header_len = pos;
    if (pos + 32 > b.size())                 return false;
    std::memcpy(out.tree_root.data(), b.data() + pos, 32);
    pos += 32;                    // tree_root
    if (!read_varint(b, pos, out.n_tx))      return false;
    return true;
}

// ---------------------------------------------------------------------------
// NOTE on the 0x02 nonce length: the v37 settle leg (assemble_tx_extra) emits the
// extra-nonce length as a VARINT (put_varint), and the receipt binding path only
// ever opens coinbases the settle/template leg minted, so we decode it as a
// varint here. (monerod's own tx_extra_nonce uses a 1-byte count; the two agree
// for len < 128, e.g. mainnet block 3000000's 17-byte nonce. The crypto-only
// opening path (verify_crypto_opening) never parses tx_extra, so raw mainnet
// coinbases with a >=128-byte nonce still verify -- their bytes are absorbed
// wholesale into the sponge, unparsed.)
bool parse_tx_extra(const std::vector<u8>& e, ParsedTxExtra& out) {
    std::size_t pos = 0;
    while (pos < e.size()) {
        const u8 tag = e[pos++];
        if (tag == 0x00) {                       // padding: must run zero to end
            while (pos < e.size()) { if (e[pos] != 0x00) return false; ++pos; }
            break;
        } else if (tag == 0x01) {                // tx pubkey (32)
            if (pos + 32 > e.size()) return false;
            out.has_pubkey = true;
            std::memcpy(out.pubkey.data(), &e[pos], 32);
            pos += 32;
        } else if (tag == 0x02) {                // extra-nonce: varint(len) || bytes
            u64 len;
            if (!read_varint(e, pos, len)) return false;
            if (pos + len > e.size()) return false;
            out.has_nonce = true;
            out.nonce.assign(e.begin() + pos, e.begin() + pos + len);
            pos += static_cast<std::size_t>(len);
        } else if (tag == 0x03) {                // MM: varint(flen) || varint(depth) || root[32]
            u64 flen;
            if (!read_varint(e, pos, flen)) return false;
            const std::size_t fend = pos + static_cast<std::size_t>(flen);
            if (fend > e.size()) return false;
            u64 depth;
            if (!read_varint(e, pos, depth)) return false;
            if (pos + 32 > fend) return false;
            out.has_mm = true;
            out.mm_depth = depth;
            std::memcpy(out.mm_root.data(), &e[pos], 32);
            pos += 32;
            if (pos != fend) return false;       // exact field consumption
        } else if (tag == 0x04) {                // additional pubkeys: varint(cnt) || cnt*32
            u64 cnt;
            if (!read_varint(e, pos, cnt)) return false;
            if (pos + cnt * 32 > e.size()) return false;
            pos += static_cast<std::size_t>(cnt * 32);
        } else {
            return false;                        // unknown tag => not parseable
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
bytes32 side_data_digest(const ReceiptSideData& sd) {
    std::vector<u8> buf;
    buf.reserve(8 + 8 + 32 + 4 + 32);
    put_le64(buf, sd.t_origin.lo);
    put_le64(buf, sd.t_origin.hi);
    buf.insert(buf.end(), sd.payout_identity.begin(), sd.payout_identity.end());
    put_le32(buf, sd.chain_id);
    buf.insert(buf.end(), sd.prev_own_share.begin(), sd.prev_own_share.end());
    return from_h(::xmr::coin::keccak256(buf));
}

// mm_leaf = keccak256(MM_LEAF_DOMAIN || chain_id(LE4) || commitment[32]).
// Byte-identical to the settle leg's mm_commitment_root (xmr_coinbase.cpp).
bytes32 mm_commitment_leaf(u32 chain_id, const bytes32& commitment) {
    ::xmr::coin::KeccakMidstate m;
    m.absorb(MM_LEAF_DOMAIN, MM_LEAF_DOMAIN_LEN);
    unsigned char cid[4] = {
        static_cast<unsigned char>(chain_id & 0xff),
        static_cast<unsigned char>((chain_id >> 8) & 0xff),
        static_cast<unsigned char>((chain_id >> 16) & 0xff),
        static_cast<unsigned char>((chain_id >> 24) & 0xff),
    };
    m.absorb(cid, 4);
    m.absorb(commitment.data(), 32);
    return from_h(m.finalize_copy());
}

// ---------------------------------------------------------------------------
bool build_coinbase_opening(const std::vector<u8>& prefix_bytes,
                            std::size_t extra_start, CoinbaseOpening& out) {
    if (extra_start > prefix_bytes.size()) return false;
    ::xmr::coin::KeccakMidstate m;
    m.absorb(prefix_bytes.data(), extra_start);         // absorb the head
    const std::vector<unsigned char> wire = m.serialize(); // rest(1)||partial||H(200)
    const std::size_t rest = wire[0];
    if (1 + rest + 200 != wire.size()) return false;
    out.prefix_tail.assign(wire.begin() + 1, wire.begin() + 1 + rest);
    std::copy(wire.begin() + 1 + rest, wire.begin() + 1 + rest + 200, out.midstate.begin());
    out.tx_extra.assign(prefix_bytes.begin() + extra_start, prefix_bytes.end());
    return true;
}

bool resume_prefix_hash(const CoinbaseOpening& o, bytes32& h_prefix_out) {
    if (o.prefix_tail.size() >= CoinbaseOpening::KECCAK_RATE_BYTES) return false;
    // Rebuild X1's KeccakMidstate wire form: rest(1) || prefix_tail || midstate(200)
    std::vector<unsigned char> wire;
    wire.reserve(1 + o.prefix_tail.size() + 200);
    wire.push_back(static_cast<unsigned char>(o.prefix_tail.size()));
    wire.insert(wire.end(), o.prefix_tail.begin(), o.prefix_tail.end());
    wire.insert(wire.end(), o.midstate.begin(), o.midstate.end());
    ::xmr::coin::KeccakMidstate m = ::xmr::coin::KeccakMidstate::deserialize(wire);
    m.absorb(o.tx_extra.data(), o.tx_extra.size());     // absorb the opened extra
    h_prefix_out = from_h(m.finalize_copy());           // pad + squeeze => H(prefix)
    return true;
}

// ---------------------------------------------------------------------------
bool verify_crypto_opening(const MoneroReceipt& r, OpenedCommitment& out,
                           std::string* why) {
    ParsedBlob pb;
    if (!parse_hashing_blob(r.hashing_blob, pb)) {
        set_why(why, "hashing_blob malformed / truncated"); return false;
    }
    // (1) resume the Keccak midstate over prefix_tail || tx_extra -> H(prefix)
    bytes32 h_prefix;
    if (!resume_prefix_hash(r.coinbase_opening, h_prefix)) {
        set_why(why, "coinbase opening: bad midstate tail length"); return false;
    }
    // (2) RCTTypeNull coinbase tx hash = leaf 0 of the tree
    const bytes32 leaf0 = from_h(::xmr::coin::coinbase_tx_hash(to_h(h_prefix)));
    // (3) walk the tree branch; require the recomputed root == the blob's tree_root
    if (r.tree_branch.path.size() != r.tree_branch.depth) {
        set_why(why, "tree branch depth != #siblings"); return false;
    }
    ::xmr::coin::TreeBranch cb;
    cb.branch.reserve(r.tree_branch.path.size());
    for (const auto& s : r.tree_branch.path) cb.branch.push_back(to_h(s));
    cb.depth = r.tree_branch.depth;
    cb.path  = r.tree_branch.path_bits;
    if (!::xmr::coin::verify_branch(to_h(leaf0), cb, to_h(pb.tree_root))) {
        set_why(why, "tree branch does not reproduce the blob's tree_root"); return false;
    }
    out.tree_root     = pb.tree_root;
    out.miner_tx_hash = leaf0;
    return true;
}

// ---------------------------------------------------------------------------
bool open_and_bind_impl(const MoneroReceipt& r, const bytes32& carrier_identity,
                        u32 lane_chain_id, OpenedCommitment& out, std::string* why) {
    // structural crypto core first (fills tree_root + miner_tx_hash)
    if (!verify_crypto_opening(r, out, why)) return false;

    // v37 side-data binding
    if (!r.side_data) {
        set_why(why, "v37 receipt missing side_data preimage"); return false;
    }
    const ReceiptSideData& sd = *r.side_data;

    // (a) info_digest self-consistency: info_digest == keccak256(side_data)
    if (side_data_digest(sd) != r.info_digest) {
        set_why(why, "info_digest != keccak256(side_data)"); return false;
    }
    // (b) the tx_extra 0x03 MM leaf must commit our info_digest
    ParsedTxExtra pe;
    if (!parse_tx_extra(r.coinbase_opening.tx_extra, pe)) {
        set_why(why, "tx_extra unparseable"); return false;
    }
    if (!pe.has_mm) {
        set_why(why, "tx_extra carries no 0x03 merge-mining commitment"); return false;
    }
    if (mm_commitment_leaf(sd.chain_id, r.info_digest) != pe.mm_root) {
        set_why(why, "0x03 MM leaf != keccak(domain||chain_id||info_digest)"); return false;
    }
    // (c) chain + self-carriage bindings
    if (sd.chain_id != lane_chain_id) {
        set_why(why, "receipt chain_id != lane chain_id"); return false;
    }
    if (sd.payout_identity != carrier_identity) {
        set_why(why, "receipt payout identity != carrier (self-carriage)"); return false;
    }
    out.t_origin        = sd.t_origin;
    out.payout_identity = sd.payout_identity;
    out.chain_id        = sd.chain_id;
    return true;
}

// ---------------------------------------------------------------------------
bool build_v37_receipt(const BuildInputs& in, MoneroReceipt& out, std::string* why) {
    if (!build_coinbase_opening(in.prefix_bytes, in.extra_start, out.coinbase_opening)) {
        set_why(why, "build: extra_start out of range"); return false;
    }
    bytes32 h_prefix;
    if (!resume_prefix_hash(out.coinbase_opening, h_prefix)) {
        set_why(why, "build: bad prefix tail"); return false;
    }
    const bytes32 leaf0 = from_h(::xmr::coin::coinbase_tx_hash(to_h(h_prefix)));

    std::vector<::xmr::coin::Hash256> leaves;
    leaves.reserve(1 + in.other_leaves.size());
    leaves.push_back(to_h(leaf0));
    for (const auto& l : in.other_leaves) leaves.push_back(to_h(l));

    const ::xmr::coin::Hash256 root = ::xmr::coin::tree_root(leaves);

    ::xmr::coin::TreeBranch cb;
    if (!::xmr::coin::make_coinbase_branch(leaves, cb)) {
        set_why(why, "build: tree branch construction failed"); return false;
    }
    out.tree_branch.path.clear();
    out.tree_branch.path.reserve(cb.branch.size());
    for (const auto& s : cb.branch) out.tree_branch.path.push_back(from_h(s));
    out.tree_branch.depth     = static_cast<u8>(cb.depth);
    out.tree_branch.path_bits = cb.path;

    const std::vector<unsigned char> header =
        ::xmr::coin::write_block_header_prefix(in.major, in.minor, in.timestamp,
                                               to_h(in.prev_id), in.nonce);
    const std::vector<unsigned char> blob =
        ::xmr::coin::assemble_hashing_blob(header, root, leaves.size());
    out.hashing_blob.bytes.assign(blob.begin(), blob.end());

    out.seed_ref.policy = in.seed_policy;
    out.side_data       = in.side_data;
    out.info_digest     = side_data_digest(in.side_data);
    return true;
}

// ---------------------------------------------------------------------------
bytes32 cheap_receipt_id(const HashingBlob& blob) {
    return from_h(::xmr::coin::keccak256(blob.bytes));
}

AdmitOutcome verify_receipt(const MoneroReceipt& r,
                            const bytes32& carrier_identity,
                            u64 carrier_bin,
                            u32 lane_chain_id,
                            const LaneKeyedHeavy& lp,
                            const VerifyConfig& cfg,
                            OpenedCommitment& opened) {
    AdmissionHooks h;
    h.cheap_digest = [](const HashingBlob& b) { return cheap_receipt_id(b); };
    h.seen = cfg.seen ? cfg.seen
                      : std::function<bool(const bytes32&)>([](const bytes32&) { return false; });
    h.bin_of = cfg.bin_of
             ? cfg.bin_of
             : std::function<bool(const HashingBlob&, u64&)>(
                   [](const HashingBlob&, u64&) { return false; });  // no index by default
    h.open_and_bind =
        [&opened, lane_chain_id](const MoneroReceipt& rr, const bytes32& cid, u32 lc,
                                 OpenedCommitment& o) {
            (void)lane_chain_id;
            const bool ok = open_and_bind_impl(rr, cid, lc, o, nullptr);
            if (ok) opened = o;
            return ok;
        };
    h.consensus_difficulty = cfg.consensus_difficulty
        ? cfg.consensus_difficulty
        : std::function<bool(u64, Difficulty&)>([](u64, Difficulty&) { return false; });
    h.seed_for_bin = cfg.seed_for_bin
        ? cfg.seed_for_bin
        : std::function<bool(u64, const SeedRef&, bytes32&)>(
              [](u64, const SeedRef&, bytes32& s) { s = bytes32{}; return true; });
    h.rx_check = cfg.rx_check;   // null => CI-gated skip inside admit_receipt_keyed_heavy

    return admit_receipt_keyed_heavy(r, carrier_identity, carrier_bin,
                                     lane_chain_id, lp, h);
}

} // namespace verify
} // namespace xmr
} // namespace v37
