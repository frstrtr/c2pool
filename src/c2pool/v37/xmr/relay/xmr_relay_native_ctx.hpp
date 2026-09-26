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
// SCOPE FENCE: consumer tree. No consensus digest; src/sharechain/v37 untouched.
// ===========================================================================
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "xmr_relay_node.hpp"

namespace c2pool::v37n::xmr::relay {

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
    std::size_t feed(ChainView& cv, const NativeCtxSource& src, u64 window = 128) {
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
    void serve(XmrRelayNode& rn, const NativeCtxSource& src,
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
    std::size_t load(ChainView& cv) {
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
