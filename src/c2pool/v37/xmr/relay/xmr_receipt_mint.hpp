// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/relay/xmr_receipt_mint.hpp   (GAP-2 stage 1)
//
// MINT: turn one accepted stratum share into a relayable, re-verifiable
// Family-B receipt, and CHECK: the structural (RandomX-free) half of admission.
//
// Mint input = the block the share was mined on, exactly as the template layer
// materialises it for (template_id, extra_nonce) -- submit::BlockCandidate's
// full_blob (header | miner_tx | n | tx hashes) + the served hashing blob with
// the share's nonce patched in. From those bytes alone:
//   * hashing_blob  = the RandomX input the miner hashed (nonce included);
//   * opening       = Keccak midstate over the miner_tx prefix up to tx_extra,
//                     + the unabsorbed tail + tx_extra in the clear
//                     (v37::xmr::verify::build_coinbase_opening);
//   * tree branch   = leaf 0 (the coinbase) -> tree_root over the block's
//                     other tx hashes (xmr::coin::make_coinbase_branch);
//   * info_digest   = side_digest_v2(side).
// The mint re-runs verify_crypto_opening on what it built, so a template bug
// can never put an unverifiable receipt on the wire.
//
// Check order (design §3.2, RandomX LAST; this file is steps 4-5, microseconds):
//   payee kind/point -> identity == xmr_identity_key(payee) -> chain_id ->
//   info_digest == side_digest_v2 -> R-1 (t_origin == share_diff) -> the
//   crypto opening (midstate -> H(prefix) -> coinbase hash -> branch -> the
//   blob's tree_root) -> tx_extra shape (0x02 + 0x03 present = a lane coinbase)
//   -> [BindMode::Rbind] 0x02 payload [4..36) == rbind_v1(chain, side).
// A receipt that fails here costs the sender a structural strike and never
// reaches RandomX.
// ===========================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "xmr_relay_wire.hpp"
#include "impl/xmr/receipt/xmr_receipt_verify.hpp"   // build_coinbase_opening / verify_crypto_opening / parse_*
#include "impl/xmr/coin/xmr_blob.hpp"                // tx_prefix_hash / coinbase_tx_hash / tree_root / make_coinbase_branch

namespace c2pool::v37n::xmr::relay {

// ── a minimal Monero block walker (no dependency on the template layer) ─────
struct BlockLayout {
    std::size_t header_size = 0;          // through the nonce
    std::size_t nonce_offset = 0;
    bytes32     prev_id{};
    std::size_t miner_tx_offset = 0;
    std::size_t prefix_size = 0;          // miner_tx prefix bytes (tx_extra is the last field)
    std::size_t extra_size = 0;           // tx_extra length
    std::size_t miner_tx_size = 0;        // prefix + rct_type byte
    std::uint64_t height = 0;             // txin_gen height
    std::vector<bytes32> tx_hashes;       // non-coinbase, wire order
};

namespace detail {
inline bool rd_varint(const std::vector<u8>& b, std::size_t& p, std::uint64_t& v) {
    v = 0; int shift = 0;
    while (p < b.size()) {
        const u8 c = b[p++];
        if (shift > 63) return false;
        v |= static_cast<std::uint64_t>(c & 0x7f) << shift;
        if (!(c & 0x80)) return true;
        shift += 7;
    }
    return false;
}
} // namespace detail

inline bool parse_block_layout(const std::vector<u8>& b, BlockLayout& L, std::string* why = nullptr) {
    auto bad = [&](const char* m) { if (why) *why = m; return false; };
    std::size_t p = 0; std::uint64_t v = 0;
    if (!detail::rd_varint(b, p, v) || !detail::rd_varint(b, p, v) || !detail::rd_varint(b, p, v))
        return bad("block: header varints");
    if (p + 32 + 4 > b.size()) return bad("block: short header");
    std::memcpy(L.prev_id.data(), b.data() + p, 32); p += 32;
    L.nonce_offset = p; p += 4;
    L.header_size = p;
    L.miner_tx_offset = p;
    std::uint64_t version = 0, unlock = 0, vin = 0, nout = 0, xlen = 0;
    if (!detail::rd_varint(b, p, version) || version != 2) return bad("miner_tx: version != 2");
    if (!detail::rd_varint(b, p, unlock)) return bad("miner_tx: unlock");
    if (!detail::rd_varint(b, p, vin) || vin != 1) return bad("miner_tx: vin != 1");
    if (p >= b.size() || b[p++] != 0xff) return bad("miner_tx: not txin_gen");
    if (!detail::rd_varint(b, p, L.height)) return bad("miner_tx: height");
    if (!detail::rd_varint(b, p, nout) || nout > 100000) return bad("miner_tx: nout");
    for (std::uint64_t i = 0; i < nout; ++i) {
        std::uint64_t amt = 0;
        if (!detail::rd_varint(b, p, amt) || p >= b.size()) return bad("miner_tx: vout amount");
        const u8 t = b[p++];
        const std::size_t k = (t == 0x03) ? 33u : (t == 0x02 ? 32u : 0u);
        if (!k || p + k > b.size()) return bad("miner_tx: vout target");
        p += k;
    }
    if (!detail::rd_varint(b, p, xlen) || p + xlen > b.size()) return bad("miner_tx: extra");
    p += static_cast<std::size_t>(xlen);
    L.extra_size = static_cast<std::size_t>(xlen);
    L.prefix_size = p - L.miner_tx_offset;
    if (p >= b.size() || b[p] != 0x00) return bad("miner_tx: rct_type != RCTTypeNull");
    ++p;
    L.miner_tx_size = p - L.miner_tx_offset;
    std::uint64_t ntx = 0;
    if (!detail::rd_varint(b, p, ntx) || ntx > 65536 || p + ntx * 32 != b.size()) return bad("block: tx hash list");
    L.tx_hashes.resize(static_cast<std::size_t>(ntx));
    for (std::size_t i = 0; i < ntx; ++i) { std::memcpy(L.tx_hashes[i].data(), b.data() + p, 32); p += 32; }
    return true;
}

namespace detail {
inline ::xmr::coin::Hash256 to_h(const bytes32& b) { ::xmr::coin::Hash256 h; std::memcpy(h.data(), b.data(), 32); return h; }
inline bytes32 from_h(const ::xmr::coin::Hash256& h) { bytes32 b; std::memcpy(b.data(), h.data(), 32); return b; }
} // namespace detail

// ── a receipt's Monero CONTEXT from a peer-served block blob (FB_CTX) ───────
// `blob` must be monerod's block_to_blob of the block whose id is `want`
// (header | miner_tx | varint n | n tx hashes). Checked from the bytes alone:
// the miner_tx hash + the tx hashes rebuild tree_root, header | tree_root |
// varint(n+1) is get_block_hashing_blob, and keccak256(varint(len) | that) must
// be `want` -- so a peer cannot hand us a block other than the one asked for,
// nor a coinbase height other than the one that block commits to. The CALLER
// then requires `parent` to be a block it already knows at exactly `height`
// (the chain link) and takes the RandomX seed from its OWN chain.
struct BlockCtx {
    bytes32       id{};
    bytes32       parent{};
    std::uint64_t height = 0;   // the block's own height (txin_gen); receipts on it are bin height + 1
};
inline bool verify_block_ctx(const bytes32& want, const std::vector<u8>& blob, BlockCtx& out, std::string* why = nullptr) {
    auto bad = [&](const std::string& m) { if (why) *why = "ctx: " + m; return false; };
    BlockLayout L; std::string w;
    if (!parse_block_layout(blob, L, &w)) return bad(w);
    const std::vector<u8> prefix(blob.begin() + static_cast<std::ptrdiff_t>(L.miner_tx_offset),
                                 blob.begin() + static_cast<std::ptrdiff_t>(L.miner_tx_offset + L.prefix_size));
    std::vector<::xmr::coin::Hash256> leaves;
    leaves.push_back(::xmr::coin::coinbase_tx_hash(::xmr::coin::tx_prefix_hash(prefix)));
    for (const auto& t : L.tx_hashes) leaves.push_back(detail::to_h(t));
    const ::xmr::coin::Hash256 root = ::xmr::coin::tree_root(leaves);
    std::vector<u8> hb(blob.begin(), blob.begin() + static_cast<std::ptrdiff_t>(L.header_size));
    hb.insert(hb.end(), root.data(), root.data() + 32);
    for (std::uint64_t v = leaves.size(); ; ) { const u8 c = static_cast<u8>(v & 0x7f); v >>= 7; hb.push_back(v ? (c | 0x80) : c); if (!v) break; }
    std::vector<u8> pre;
    for (std::uint64_t v = hb.size(); ; ) { const u8 c = static_cast<u8>(v & 0x7f); v >>= 7; pre.push_back(v ? (c | 0x80) : c); if (!v) break; }
    pre.insert(pre.end(), hb.begin(), hb.end());
    const bytes32 id = keccak_bytes(pre);
    if (id != want) return bad("block id of the served blob != the id asked for");
    out.id = id; out.parent = L.prev_id; out.height = L.height;
    return true;
}

// Build the receipt for one share. `hashing_blob` must be the blob served for
// (template_id, extra_nonce) WITH the share's nonce patched at nonce_offset.
inline bool mint_receipt(const std::vector<u8>& full_blob, const std::vector<u8>& hashing_blob,
                         const SideDataV2& side, const ::v37::ScriptRef& payee,
                         FbReceipt& out, std::string* why = nullptr) {
    auto bad = [&](const std::string& m) { if (why) *why = "mint: " + m; return false; };
    BlockLayout L; std::string w;
    if (!parse_block_layout(full_blob, L, &w)) return bad(w);
    if (hashing_blob.size() < L.nonce_offset + 4 ||
        std::memcmp(hashing_blob.data(), full_blob.data(), L.nonce_offset) != 0)
        return bad("hashing blob header != full blob header");
    const std::vector<u8> prefix(full_blob.begin() + static_cast<std::ptrdiff_t>(L.miner_tx_offset),
                                 full_blob.begin() + static_cast<std::ptrdiff_t>(L.miner_tx_offset + L.prefix_size));
    FbReceipt r;
    if (!::v37::xmr::verify::build_coinbase_opening(prefix, L.prefix_size - L.extra_size, r.receipt.coinbase_opening))
        return bad("coinbase opening");
    std::vector<::xmr::coin::Hash256> leaves;
    leaves.push_back(::xmr::coin::coinbase_tx_hash(::xmr::coin::tx_prefix_hash(prefix)));
    for (const auto& t : L.tx_hashes) leaves.push_back(detail::to_h(t));
    ::xmr::coin::TreeBranch br;
    if (!::xmr::coin::make_coinbase_branch(leaves, br)) return bad("tree branch");
    r.receipt.tree_branch.path.clear();
    for (const auto& s : br.branch) r.receipt.tree_branch.path.push_back(detail::from_h(s));
    r.receipt.tree_branch.depth = static_cast<u8>(br.depth);
    r.receipt.tree_branch.path_bits = br.path;
    if (br.path != 0) return bad("coinbase is not a left-spine leaf (path_bits != 0 is not carried on the wire)");
    r.receipt.hashing_blob.bytes = hashing_blob;
    r.receipt.seed_ref.policy = ::v37::xmr::SeedRefPolicy::DerivedFromBin;
    r.receipt.info_digest = side_digest_v2(side);
    r.side = side;
    r.payee = payee;
    // self-check: the opening we built reproduces the RandomX-signed root
    ::v37::xmr::OpenedCommitment oc;
    std::string vw;
    if (!::v37::xmr::verify::verify_crypto_opening(r.receipt, oc, &vw)) return bad("self-check: " + vw);
    out = std::move(r);
    return true;
}

// ── the structural check ────────────────────────────────────────────────────
enum class CheckStage : u8 {
    Ok = 0, Budget, PayeeKind, PayeePoint, Identity, Chain, Reserved, InfoDigest, R1,
    Opening, ExtraShape, Bind,
};
inline const char* to_string(CheckStage s) {
    switch (s) {
        case CheckStage::Ok: return "ok";
        case CheckStage::Budget: return "budget";
        case CheckStage::PayeeKind: return "payee-kind";
        case CheckStage::PayeePoint: return "payee-point";
        case CheckStage::Identity: return "identity";
        case CheckStage::Chain: return "chain";
        case CheckStage::Reserved: return "reserved";
        case CheckStage::InfoDigest: return "info-digest";
        case CheckStage::R1: return "r1-target";
        case CheckStage::Opening: return "opening";
        case CheckStage::ExtraShape: return "extra-shape";
        case CheckStage::Bind: return "bind";
    }
    return "?";
}

struct CheckCtx {
    u32      lane_chain = 0;
    u64      share_diff = 0;
    BindMode bind = BindMode::None;
    bool     check_payee_point = true;   // ed25519 + torsion via xmr_ref_valid
};

struct CheckResult {
    CheckStage stage = CheckStage::Ok;
    std::string why;
    bytes32 id{};        // receipt_id
    bytes32 prev_id{};   // from the hashing blob: the origin bin key
    bool ok() const { return stage == CheckStage::Ok; }
};

inline CheckResult check_structural(const FbReceipt& r, const CheckCtx& c) {
    CheckResult out;
    auto fail = [&](CheckStage s, std::string m) { out.stage = s; out.why = std::move(m); return out; };
    out.id = receipt_id(r);
    if (r.receipt.wire_size() > kFbReceiptBudget) return fail(CheckStage::Budget, "receipt over the relay budget");
    if (!::v37::xmr::is_xmr_kind(r.payee.kind) || r.payee.payload.size() != 64)
        return fail(CheckStage::PayeeKind, "payee is not an XMR ref");
    if (c.check_payee_point && !::v37::xmr::xmr_ref_valid(r.payee))
        return fail(CheckStage::PayeePoint, "payee keys fail the ed25519/torsion check");
    if (r.side.identity != ::v37::xmr::xmr_identity_key(r.payee))
        return fail(CheckStage::Identity, "side.identity != identity_key(payee)");
    if (r.side.chain_id != c.lane_chain) return fail(CheckStage::Chain, "side.chain_id != lane");
    if (r.side.reserved != 0) return fail(CheckStage::Reserved, "side.reserved != 0");
    if (r.receipt.info_digest != side_digest_v2(r.side))
        return fail(CheckStage::InfoDigest, "info_digest != side_digest_v2(side)");
    if (r.side.t_hi != 0 || r.side.t_lo != c.share_diff)
        return fail(CheckStage::R1, "t_origin " + std::to_string(r.side.t_lo) + " != lane share_diff " + std::to_string(c.share_diff));
    ::v37::xmr::OpenedCommitment oc;
    std::string w;
    if (!::v37::xmr::verify::verify_crypto_opening(r.receipt, oc, &w)) return fail(CheckStage::Opening, w);
    ::v37::xmr::verify::ParsedBlob pb;
    if (!::v37::xmr::verify::parse_hashing_blob(r.receipt.hashing_blob, pb)) return fail(CheckStage::Opening, "hashing blob");
    out.prev_id = pb.prev_id;
    ::v37::xmr::verify::ParsedTxExtra px;
    if (!::v37::xmr::verify::parse_tx_extra(r.receipt.coinbase_opening.tx_extra, px) || !px.has_pubkey ||
        !px.has_nonce || !px.has_mm)
        return fail(CheckStage::ExtraShape, "tx_extra is not a v37 lane coinbase (needs 0x01 + 0x02 + 0x03)");
    if (c.bind == BindMode::Rbind) {
        const bytes32 rb = rbind_v1(c.lane_chain, r.side);
        if (px.nonce.size() < 4 + 32 || std::memcmp(px.nonce.data() + 4, rb.data(), 32) != 0)
            return fail(CheckStage::Bind, "coinbase 0x02[4..36) != rbind_v1(chain, side_data_v2)");
    }
    return out;
}

// Monero's exact PoW rule for a 64-bit difficulty (check_hash_128 with hi = 0):
// hash (256-bit LE) * diff < 2^256.
inline bool meets_share_diff(const bytes32& h, u64 diff) {
    if (diff == 0) return false;
    unsigned __int128 carry = 0;
    for (int w = 0; w < 4; ++w) {
        std::uint64_t word = 0;
        for (int i = 0; i < 8; ++i) word |= static_cast<std::uint64_t>(h[w * 8 + i]) << (8 * i);
        const unsigned __int128 prod = static_cast<unsigned __int128>(word) * diff + carry;
        carry = prod >> 64;
    }
    return carry == 0;
}

} // namespace c2pool::v37n::xmr::relay
