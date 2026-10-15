// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/relay/xmr_relay_native_ctx.hpp   (RC-CTX)
//
// RECEIPT CONTEXTS FROM THE EMBEDDED NATIVE NODE.
//
// A receipt verifies only against its Monero context: the block its template
// built on (prev_id) -> (bin, RandomX seed), looked up in the relay's
// ChainView. On the daemon arm the daemon feeds that view from monerod
// (get_block_headers_range over the last 128 blocks) and serves FB_GETCTX with
// monerod's get_block. On the P2P-FIRST arm the daemon fed it ONLY the prev_id
// of the template it was serving, answered every FB_GETCTX "unknown" and never
// looked at its own wants -- so:
//   * after a restart every pre-restart context was gone (the ChainView is
//     RAM-only), and a cut whose winner-side order held receipts mined on the
//     blocks around the stop never repaired ("N Monero context(s) unresolved"
//     -> relay_repair_stall_timeout REFUSES an honest cut -> fork / halt);
//   * a node that followed another branch (a partition, a race) could never
//     learn the context of the other branch's blocks, although its own native
//     node held them.
//
// Three narrow pieces, none of which touches a consensus rule or a digest:
//   (1) NativeCtxFeeder::feed -- the native node's BEST CHAIN (its verified
//       chain index) feeds the ChainView exactly like the daemon arm's
//       128-block header range does: block at height h -> bin h+1, seed from
//       our own chain. Incremental (stops at the first already-noted block).
//   (2) NativeCtxFeeder::serve -- the relay's local WANTS and peers' FB_GETCTX
//       are answered from the native node's retained BODIES (the entry cache
//       plus the alternative blocks it holds). A want's blob still goes through
//       offer_ctx() (id recomputed, height from the coinbase, parent-linked);
//       nothing is trusted because it came from our own index. No monerod call.
//   (3) CtxJournal -- the contexts of the templates this node ISSUED are
//       appended to <settle-db>/lane<chain>.ctx and re-noted at start, so the
//       contexts of our own pre-restart templates (including a tip that later
//       lost a race and is held by nobody's best chain) survive a restart.
//
// The context block itself (FB_GETCTX / FB_CTX): parse_block_layout,
// verify_block_ctx (the id recomputed from the bytes) and judge_block_ctx (the
// work behind it, against the node's own chain index).
//
// SCOPE FENCE: consumer tree. No consensus digest; src/sharechain/v37 untouched.
// ===========================================================================
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "xmr_relay_wire.hpp"                        // u8 / u64 / bytes32, keccak_bytes, kCtxMaxBlob
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
enum class CtxPow : u8 { Indexed = 0, Accept, Defer, Forged };
inline const char* to_string(CtxPow k) {
    switch (k) {
        case CtxPow::Indexed: return "indexed";
        case CtxPow::Accept:  return "pow-verified";
        case CtxPow::Defer:   return "deferred";
        case CtxPow::Forged:  return "forged";
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

inline CtxPowVerdict judge_block_ctx(const BlockCtx& b, const CtxChainSource& src, const CtxRecFn& rec_of,
                                     std::uint32_t max_depth, const CtxHashFn& rx) {
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

// What the embedded native node can tell the relay. Bound in main_v37_xmr.cpp
// to the running NativeNode's chain index; faked by the KAT.
struct NativeCtxSource {
    std::function<std::optional<u64>()>                  best_height;   // nullopt = no chain yet
    std::function<std::optional<bytes32>(u64 height)>    id_at;         // best chain, retained rows
    std::function<std::optional<bytes32>(u64 bin)>      seed_for_bin;  // RandomX seed of a template at `bin` (our chain)
    std::function<bool(const bytes32& id, std::vector<u8>& blob)> block_blob;   // retained body (connected or held alternative)
    explicit operator bool() const noexcept { return best_height && id_at; }
};

class NativeCtxFeeder {
public:
    struct Stats {
        u64 rows_noted = 0;      // best-chain contexts noted into the ChainView
        u64 seedless = 0;        // a row skipped for now: no seed known for its bin
        u64 wants_native = 0;    // own wants answered from a native body
        u64 wants_missing = 0;   // own wants the native node holds no body for
        u64 getctx_native = 0;   // peer FB_GETCTX answered from a native body
        u64 getctx_unknown = 0;  // ... answered "unknown here"
        u64 getctx_fallback = 0; // ... answered by the caller's fallback (daemon arm only)
    };

    // (1) Note the best chain's last `window` blocks (block h -> bin h+1).
    // Called every tick; walks only when the native tip changed, and stops at
    // the first block it already noted at that height (an id commits to its
    // whole ancestry, so everything below is unchanged).
    template <class View>
    std::size_t feed(View& cv, const NativeCtxSource& src, u64 window = 128) {
        if (!src) return 0;
        const auto best = src.best_height();
        if (!best) return 0;
        if (*best == m_best && !m_retry) {                        // same height: a same-height tip reorg still walks
            const auto tid = src.id_at(*best);
            const auto it = m_rows.find(*best);
            if (!tid || (it != m_rows.end() && it->second == *tid)) return 0;
        }
        const bool full = m_retry;   // a seedless row below: walk the whole window again
        m_retry = false;
        std::size_t n = 0;
        for (u64 k = 0; k < window && k <= *best; ++k) {
            const u64 h = *best - k;
            const auto id = src.id_at(h);
            if (!id) break;                                       // below the retained rows
            auto it = m_rows.find(h);
            if (it != m_rows.end() && it->second == *id) {
                if (!full) break;                                 // same block, same ancestry: done
                continue;
            }
            const u64 bin = h + 1;
            std::optional<bytes32> seed;
            if (src.seed_for_bin) seed = src.seed_for_bin(bin);
            if (!seed) seed = cv.seed_for(bin);
            if (!seed) { ++m_st.seedless; m_retry = true; continue; }
            cv.note(*id, bin, *seed);
            cv.note_seed(::xmr::coin::rx_seedheight(bin), *seed);
            m_rows[h] = *id;
            ++m_st.rows_noted; ++n;
        }
        while (m_rows.size() > 4096) m_rows.erase(m_rows.begin());
        m_best = *best;
        return n;
    }

    // (2) Answer the relay's own wants and peers' FB_GETCTX from native bodies.
    // `fallback` (may be empty) is the daemon arm's monerod get_block; the
    // P2P-first arm passes none, so a body the native node lacks is "unknown".
    template <class Relay>
    void serve(Relay& rn, const NativeCtxSource& src,
               const std::function<std::vector<u8>(const bytes32&)>& fallback = {}) {
        auto native_blob = [&](const bytes32& id, std::vector<u8>& blob) {
            blob.clear();
            return src.block_blob && src.block_blob(id, blob) && !blob.empty() && blob.size() <= kCtxMaxBlob;
        };
        std::vector<u8> blob;
        for (const auto& id : rn.ctx_wants_local()) {
            if (native_blob(id, blob)) { ++m_st.wants_native; rn.offer_ctx(id, blob, 0); continue; }
            ++m_st.wants_missing;
            if (fallback) { const auto b = fallback(id); if (!b.empty()) rn.offer_ctx(id, b, 0); }
        }
        for (const auto& [pid, ids] : rn.drain_ctx_requests())
            for (const auto& id : ids) {
                if (native_blob(id, blob)) { ++m_st.getctx_native; rn.send_ctx(pid, id, blob); continue; }
                if (fallback) {
                    const auto b = fallback(id);
                    if (!b.empty()) { ++m_st.getctx_fallback; rn.send_ctx(pid, id, b); continue; }
                }
                ++m_st.getctx_unknown;
                rn.send_ctx(pid, id, {});
            }
    }

    const Stats& stats() const noexcept { return m_st; }
    std::string describe() const {
        char b[320];
        std::snprintf(b, sizeof b, "native-ctx: rows_noted=%llu seedless=%llu wants native=%llu missing=%llu | getctx native=%llu fallback=%llu unknown=%llu",
                      (unsigned long long)m_st.rows_noted, (unsigned long long)m_st.seedless,
                      (unsigned long long)m_st.wants_native, (unsigned long long)m_st.wants_missing,
                      (unsigned long long)m_st.getctx_native, (unsigned long long)m_st.getctx_fallback,
                      (unsigned long long)m_st.getctx_unknown);
        return b;
    }

private:
    std::map<u64, bytes32> m_rows;   // height -> the id noted there
    u64  m_best = ~u64{0};
    bool m_retry = false;
    Stats m_st{};
};

// (3) The contexts of the templates this node issued, across a restart.
// Record: prev_id(32) | bin u64 LE | seed(32) | fnv1a64 of those 72 bytes.
// Append-only; a torn tail (crash mid-write) is ignored on load and dropped by
// the next compaction. Bounded: compacted to the newest kKeep records.
class CtxJournal {
public:
    static constexpr std::size_t kRec  = 80;
    static constexpr std::size_t kKeep = 4096;

    explicit CtxJournal(std::string path = {}) : m_path(std::move(path)) {}
    const std::string& path() const noexcept { return m_path; }

    // Re-note every valid record into `cv` (oldest first, so the newest wins).
    template <class View>
    std::size_t load(View& cv) {
        m_recs.clear();
        if (m_path.empty()) return 0;
        std::FILE* f = std::fopen(m_path.c_str(), "rb");
        if (!f) return 0;
        u8 r[kRec];
        while (std::fread(r, 1, kRec, f) == kRec) {
            Rec x;
            if (!decode(r, x)) { ++m_bad; break; }
            m_recs.push_back(x);
        }
        std::fclose(f);
        if (m_recs.size() > kKeep) m_recs.erase(m_recs.begin(), m_recs.end() - static_cast<std::ptrdiff_t>(kKeep));
        for (const auto& x : m_recs) { cv.note(x.prev, x.bin, x.seed); cv.note_seed(::xmr::coin::rx_seedheight(x.bin), x.seed); }
        if (!m_recs.empty()) { m_last_prev = m_recs.back().prev; m_last_bin = m_recs.back().bin; }
        compact();   // drops a torn tail, bounds the file
        return m_recs.size();
    }

    // One issued template's context. Only a CHANGED (prev_id, bin) is written.
    bool note(const bytes32& prev, u64 bin, const bytes32& seed) {
        if (m_path.empty()) return false;
        if (prev == m_last_prev && bin == m_last_bin) return false;
        Rec x{prev, bin, seed};
        u8 r[kRec]; encode(x, r);
        std::FILE* f = std::fopen(m_path.c_str(), "ab");
        if (!f) return false;
        const bool ok = std::fwrite(r, 1, kRec, f) == kRec;
        std::fclose(f);
        if (!ok) return false;
        m_last_prev = prev; m_last_bin = bin;
        m_recs.push_back(x);
        ++m_written;
        if (m_recs.size() > 2 * kKeep) {
            m_recs.erase(m_recs.begin(), m_recs.end() - static_cast<std::ptrdiff_t>(kKeep));
            compact();
        }
        return true;
    }

    std::size_t size() const noexcept { return m_recs.size(); }
    u64 written() const noexcept { return m_written; }
    u64 bad_tail() const noexcept { return m_bad; }

private:
    struct Rec { bytes32 prev{}; u64 bin = 0; bytes32 seed{}; };
    static u64 fnv(const u8* p, std::size_t n) {
        u64 h = 1469598103934665603ull;
        for (std::size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ull; }
        return h;
    }
    static void encode(const Rec& x, u8* r) {
        std::memcpy(r, x.prev.data(), 32);
        for (int i = 0; i < 8; ++i) r[32 + i] = static_cast<u8>(x.bin >> (8 * i));
        std::memcpy(r + 40, x.seed.data(), 32);
        const u64 c = fnv(r, 72);
        for (int i = 0; i < 8; ++i) r[72 + i] = static_cast<u8>(c >> (8 * i));
    }
    static bool decode(const u8* r, Rec& x) {
        u64 c = 0;
        for (int i = 0; i < 8; ++i) c |= static_cast<u64>(r[72 + i]) << (8 * i);
        if (c != fnv(r, 72)) return false;
        std::memcpy(x.prev.data(), r, 32);
        x.bin = 0;
        for (int i = 0; i < 8; ++i) x.bin |= static_cast<u64>(r[32 + i]) << (8 * i);
        std::memcpy(x.seed.data(), r + 40, 32);
        return true;
    }
    void compact() {
        const std::string tmp = m_path + ".tmp";
        std::FILE* f = std::fopen(tmp.c_str(), "wb");
        if (!f) return;
        bool ok = true;
        u8 r[kRec];
        for (const auto& x : m_recs) { encode(x, r); ok = ok && std::fwrite(r, 1, kRec, f) == kRec; }
        ok = (std::fclose(f) == 0) && ok;
        std::error_code ec;
        if (ok) std::filesystem::rename(tmp, m_path, ec);
        else std::filesystem::remove(tmp, ec);
    }

    std::string m_path;
    std::vector<Rec> m_recs;
    bytes32 m_last_prev{};
    u64 m_last_bin = ~u64{0};
    u64 m_written = 0, m_bad = 0;
};

} // namespace c2pool::v37n::xmr::relay
