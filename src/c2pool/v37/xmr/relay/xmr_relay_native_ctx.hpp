// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/relay/xmr_relay_native_ctx.hpp
//
// A Monero block served by FB_CTX (FB_GETCTX / FB_CTX, xmr_relay_wire.hpp):
//   parse_block_layout  the block's header, miner tx and tx hashes
//   verify_block_ctx    the id recomputed from the bytes, the height from the coinbase
//   judge_block_ctx     the work behind it, against the node's own chain index
//
// No consensus digest; src/sharechain/v37 untouched.
// ===========================================================================
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "xmr_relay_wire.hpp"                        // u8 / u64 / bytes32, keccak_bytes
#include "impl/xmr/coin/xmr_blob.hpp"                // tx_prefix_hash / coinbase_tx_hash / tree_root
#include "impl/xmr/coin/xmr_check_hash.hpp"          // check_hash (Monero's 128-bit difficulty test)
#include "impl/xmr/coin/xmr_seedheight.hpp"          // rx_seedheight

namespace c2pool::v37n::xmr::relay {

// ── a minimal Monero block walker (no dependency on the template layer) ─────
struct BlockLayout {
    std::uint64_t major_version = 0;      // header varints
    std::uint64_t timestamp = 0;
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

// Peer data (FB_CTX): every bound is "len > size - p" with p <= size
// (rd_varint never moves p past the end), never "p + len > size", which a
// varint length near 2^64 would wrap.
inline bool parse_block_layout(const std::vector<u8>& b, BlockLayout& L, std::string* why = nullptr) {
    auto bad = [&](const char* m) { if (why) *why = m; return false; };
    std::size_t p = 0; std::uint64_t v = 0;
    if (!detail::rd_varint(b, p, L.major_version) || !detail::rd_varint(b, p, v) || !detail::rd_varint(b, p, L.timestamp))
        return bad("block: header varints");
    if (b.size() - p < 32 + 4) return bad("block: short header");
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
        if (!k || b.size() - p < k) return bad("miner_tx: vout target");
        p += k;
    }
    if (!detail::rd_varint(b, p, xlen) || xlen > b.size() - p) return bad("miner_tx: extra");
    p += static_cast<std::size_t>(xlen);
    L.extra_size = static_cast<std::size_t>(xlen);
    L.prefix_size = p - L.miner_tx_offset;
    if (p >= b.size() || b[p] != 0x00) return bad("miner_tx: rct_type != RCTTypeNull");
    ++p;
    L.miner_tx_size = p - L.miner_tx_offset;
    std::uint64_t ntx = 0;
    if (!detail::rd_varint(b, p, ntx) || ntx > 65536 || b.size() - p != ntx * 32) return bad("block: tx hash list");
    L.tx_hashes.resize(static_cast<std::size_t>(ntx));
    for (std::size_t i = 0; i < ntx; ++i) { std::memcpy(L.tx_hashes[i].data(), b.data() + p, 32); p += 32; }
    return true;
}

namespace detail {
inline ::xmr::coin::Hash256 to_h(const bytes32& b) { ::xmr::coin::Hash256 h; std::memcpy(h.data(), b.data(), 32); return h; }
} // namespace detail

// ── a receipt's Monero CONTEXT from a peer-served block blob (FB_CTX) ───────
// `blob` must be monerod's block_to_blob of the block whose id is `want`
// (header | miner_tx | varint n | n tx hashes). Checked from the bytes alone:
// the miner_tx hash + the tx hashes rebuild tree_root, header | tree_root |
// varint(n+1) is get_block_hashing_blob, and keccak256(varint(len) | that) must
// be `want` -- so a peer cannot hand us a block other than the one asked for,
// nor a coinbase height other than the one that block commits to. The CALLER
// then requires `parent` to be a block it already knows at exactly `height`
// (the chain link) and takes the RandomX seed from its OWN chain. The bytes
// alone say nothing about WORK: before the block may influence admission the
// caller also runs judge_block_ctx() below.
struct BlockCtx {
    bytes32       id{};
    bytes32       parent{};
    std::uint64_t height = 0;   // the block's own height (txin_gen); receipts on it are bin height + 1
    std::uint64_t timestamp = 0;
    std::uint64_t major_version = 0;
    std::vector<u8> hashing_blob;   // header | tree_root | varint(n+1): the RandomX input
    std::size_t   blob_bytes = 0;   // the served blob's size
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
    out.timestamp = L.timestamp; out.major_version = L.major_version;
    out.hashing_blob = std::move(hb);
    out.blob_bytes = blob.size();
    return true;
}

// ── the WORK behind a context block (judge_block_ctx) ───────────────────────
// A context block is used only if
//   (a) the node's own verified Monero chain index holds it, or
//   (b) its proof of work meets the difficulty its parent implies in that
//       index -- the parent held by the index, or itself verified this way --
//       at most `max_depth` unknown blocks above the index.
// The bound is the caller's: the tip-freshness rule bounds an unsolicited
// receipt's context (Path B: P-06, Fresh + 1); a carrier under verification
// climbs to P-07 (k_alt); anything deeper waits for the node's own Monero sync.
//
// Verdicts follow the carrier rule (impl/xmr/native/relay/xmr_found_block_
// carrier.hpp): a hash BELOW the difficulty is forged (the sender is banned);
// every "we cannot judge it now" -- an unknown or too-deep parent, a window
// or seed the index cannot supply, a verifier that cannot hash -- defers and
// never bans.
struct CtxStep {                // one block verified by (b): what the next window needs
    std::uint64_t timestamp = 0;
    std::uint64_t diff_lo = 0, diff_hi = 0;
};
struct CtxTarget {              // what the index says the next block must meet
    std::uint64_t diff_lo = 0, diff_hi = 0;
    std::uint64_t height = 0;
    bytes32       seed{};
    std::uint64_t blob_cap = 0;   // P-13: blob_cap_ctx(hf, Z) of the anchor's newest ancestor with known state; 0 = none
};
// The node's own verified chain index, as the relay sees it (main binds it to
// the native node's index; a KAT binds a model).
struct CtxChainSource {
    // the index holds `id` verified (a best-chain row or a verified alternative)
    std::function<bool(const bytes32& id)> verified;
    // difficulty / height / seed of the block after `anchor` (held verified)
    // extended by `above` (oldest first); false + why = cannot judge it now
    std::function<bool(const bytes32& anchor, const std::vector<CtxStep>& above, std::uint64_t major_version,
                       CtxTarget& out, std::string& why)> target;
    explicit operator bool() const noexcept { return static_cast<bool>(verified) && static_cast<bool>(target); }
};
struct CtxPowRec {              // a block this node verified by (b)
    bytes32 parent{};
    CtxStep step{};
};
enum class CtxPow : u8 { Indexed = 0, Accept, Defer, Forged, OverCap };
inline const char* to_string(CtxPow k) {
    switch (k) {
        case CtxPow::Indexed: return "indexed";
        case CtxPow::Accept:  return "pow-verified";
        case CtxPow::Defer:   return "deferred";
        case CtxPow::Forged:  return "forged";
        case CtxPow::OverCap: return "over-cap";
    }
    return "?";
}
struct CtxPowVerdict {
    CtxPow        kind = CtxPow::Defer;
    std::size_t   depth = 0;    // unknown blocks above the index, this one included (0 = indexed)
    CtxStep       step{};       // set on Accept: remember it for a child's window
    std::string   why;
    bool usable() const { return kind == CtxPow::Indexed || kind == CtxPow::Accept; }
    bool ban() const { return kind == CtxPow::Forged; }
};
using CtxHashFn  = std::function<bool(const std::vector<u8>& hashing_blob, const bytes32& seed, bytes32& pow)>;
using CtxRecFn   = std::function<std::optional<CtxPowRec>(const bytes32& id)>;

// policy_cap: a raised P-13 (the node's policy, 0: none); the cap is max(P-13 at the anchor, policy_cap). A blob above
// it is OverCap: dropped before hashing (no verdict on the sender, no token, no ban).
inline CtxPowVerdict judge_block_ctx(const BlockCtx& b, const CtxChainSource& src, const CtxRecFn& rec_of,
                                     std::uint32_t max_depth, const CtxHashFn& rx, std::uint64_t policy_cap = 0) {
    CtxPowVerdict v;
    auto defer = [&](std::string m) { v.kind = CtxPow::Defer; v.why = std::move(m); return v; };
    if (!src) return defer("no chain index to judge it against");
    if (src.verified(b.id)) { v.kind = CtxPow::Indexed; v.why = "held by our own chain index"; return v; }
    // walk down to the index through blocks verified here by (b)
    std::vector<CtxStep> above;
    bytes32 cur = b.parent;
    while (!src.verified(cur)) {
        const auto r = rec_of ? rec_of(cur) : std::nullopt;
        if (!r) return defer("parent is neither in our chain index nor proof-of-work verified here");
        above.push_back(r->step);
        if (above.size() >= max_depth)
            return defer("more than " + std::to_string(max_depth) + " unknown blocks above our chain index (waits for our own Monero sync)");
        cur = r->parent;
    }
    std::reverse(above.begin(), above.end());
    v.depth = above.size() + 1;
    CtxTarget t; std::string why;
    if (!src.target(cur, above, b.major_version, t, why)) return defer("cannot judge it now: " + why);
    if (t.diff_lo == 0 && t.diff_hi == 0) return defer("the index answered no difficulty");
    if (t.blob_cap == 0) return defer("the index answered no context block cap (P-13) at the anchor");
    const std::uint64_t cap = std::max(t.blob_cap, policy_cap);
    if (b.blob_bytes > cap) {   // P-13 at the newest known ancestor: dropped before hashing
        v.kind = CtxPow::OverCap;
        v.why = "block blob of " + std::to_string(b.blob_bytes) + " B over the context block cap " + std::to_string(cap);
        return v;
    }
    if (t.height != b.height) {   // the coinbase commits to its height; the index knows the parent's
        v.kind = CtxPow::Forged;
        v.why = "block claims height " + std::to_string(b.height) + " but its parent implies " + std::to_string(t.height);
        return v;
    }
    if (!rx) return defer("no RandomX verifier");
    bytes32 pow{};
    if (!rx(b.hashing_blob, t.seed, pow)) return defer("RandomX could not hash it now");
    if (!::xmr::coin::check_hash(detail::to_h(pow), t.diff_lo, t.diff_hi)) {
        bytes32 pow2{};   // re-hash before blaming the sender (an unstable verifier must not ban)
        if (!rx(b.hashing_blob, t.seed, pow2) || pow2 != pow) return defer("RandomX gave two different hashes");
        v.kind = CtxPow::Forged;
        v.why = "proof of work below the difficulty our chain index implies for it";
        return v;
    }
    v.kind = CtxPow::Accept;
    v.step = CtxStep{b.timestamp, t.diff_lo, t.diff_hi};
    v.why = "proof of work meets the difficulty our chain index implies (depth " + std::to_string(v.depth) + ")";
    return v;
}

} // namespace c2pool::v37n::xmr::relay
