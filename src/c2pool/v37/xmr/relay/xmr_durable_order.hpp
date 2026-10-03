// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/relay/xmr_durable_order.hpp   (REPAIR-CHAIN, F2-S)
//
// The DURABLE LANE ORDER: this node's own lane order, position-indexed on disk,
// so a relay repair can be served BELOW the in-memory frame-vault horizon
// (stagenet capstone attempt 4: three holds, every one "DEEP-DIVERGENCE ... no
// connected peer retains the divergent positions", while every position was
// still in the serving node's never-pruned receipts log).
//
//   <base>.order   "V37ORD1\0" + one 52-byte record per RECEIPT, push order:
//                  u64 pos_first | u32 n_pushes | b32 receipt_id | u64 log_off
//                  (log_off = the record's offset in lane<N>.receipts)
//   <base>.digest  "V37DIG1\0" + one 32-byte record per PUSH POSITION: record
//                  i = the lane digest after i+1 pushes (all-zero = unknown:
//                  the inner position of a multi-push receipt)
//
// Both files are DERIVED data: open() truncates them and the boot reload of
// the receipts log (XmrReceiptIngest::reload -> on_pushed) rebuilds them, so
// they can never disagree with the live lane (no torn-tail or stale-sidecar
// case exists). Serving is OWN LINEAGE ONLY (positions [0, n) of this node's
// lane, contiguous, fail-closed on any gap) and O(page): a binary search over
// the fixed records + one sequential read. Frames of ids served from here are
// found again through a bounded id -> log_off map (the ids of recent deep
// pages) and read back from the receipts log, verified against the id.
// Node-local bookkeeping only: nothing here is on the wire or in consensus.
//
// HOLD-ROUND-3 F3 (stagenet attempt 8): two additions, both node-local.
//  RETENTION  set_retain(R): the order serves positions >= next_pos - R only
//             (R = 0: everything, the stagenet default). Below that point the
//             fixed records of both sidecars are HOLE-PUNCHED (disk freed, the
//             offsets kept: every reader is position-indexed), amortised every
//             R/16 (>= 1024) appends, and digest_at / order_page / ids_between
//             answer "unknown / cannot serve" there -- a requester that needs a
//             pruned position hears BELOW_HORIZON and names the retention in
//             its alarm (never a silent hold). The receipts log itself is NOT
//             pruned here: it is the lane's durability (the boot reload replays
//             it from byte 0), so its head needs a lane-state checkpoint first.
//  BUDGET     DeepServeBudget: who may be served a WHOLE order [0, P) from
//             here, and how much. The 30-s "deep walker" mark (a probe below
//             our horizon in the last 30 s) was the only key to a deep [0, P)
//             page; a requester whose probe landed exactly at our vault start
//             never got one (attempt 8, node A). Now the key is the ASK ITSELF:
//             every repair asks [0, P) first and is told BELOW_HORIZON (it
//             re-arms to a suffix, O(horizon) ids, exactly as before); a peer
//             that asks [0, P) a SECOND time for the same P means it (its walk
//             reached q = 0, or its suffix replay found no base) and is served
//             in pages, under a per-peer budget: ids_factor x P + one page ids
//             per (peer, P), cuts_per_hour distinct cuts per peer. No wire
//             byte changes: the same GETORDER, the same BELOW_HORIZON answer.
// ===========================================================================
#pragma once

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <linux/falloc.h>   // FALLOC_FL_PUNCH_HOLE (retention: free the pruned head, keep offsets)
#endif
#include <chrono>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <sharechain/v37/v37_hash.hpp>

namespace c2pool::v37n::xmr::relay {

class DurableLaneOrder {
public:
    using bytes32 = ::v37::bytes32;
    static constexpr std::size_t kHdr = 8;
    static constexpr std::size_t kOrdRec = 52;
    static constexpr std::size_t kDigRec = 32;
    static constexpr std::size_t kFrameLruMax = 65536;   // ids of recent deep pages (~5 MB worst case)
    static constexpr std::uint32_t kMaxFrame = 1u << 20;

    struct Stats {
        std::uint64_t records = 0, positions = 0;            // appended since open (= the lane)
        std::uint64_t pages = 0, ids = 0, bytes = 0;          // deep ORDER pages served (ids x 40 B on the wire)
        std::uint64_t frames = 0, frame_bytes = 0, frame_miss = 0;
        std::uint64_t digests = 0;                            // probe digests answered from disk
        std::uint64_t write_fail = 0, gap = 0;
        // F3 retention: prunes done, positions pruned in all, sidecar bytes freed
        // (hole-punched; 0 when the filesystem cannot punch), punches that failed,
        // and asks refused because they reached below the retained window
        std::uint64_t prunes = 0, pruned_positions = 0, freed_bytes = 0, punch_fail = 0, below_retention = 0;
    };
    // F3 retention: one prune, for the owner's log line
    struct PruneEvent { std::uint64_t from = 0, to = 0, order_bytes = 0, digest_bytes = 0, retain = 0; bool punched = false; };
    // true iff `frame` decodes to a receipt whose id is `id` (the relay's decoder)
    using VerifyFn = std::function<bool(const std::vector<std::uint8_t>& frame, const bytes32& id)>;

    DurableLaneOrder() = default;
    ~DurableLaneOrder() { close(); }
    DurableLaneOrder(const DurableLaneOrder&) = delete;
    DurableLaneOrder& operator=(const DurableLaneOrder&) = delete;

    // Truncate + (re)create both sidecars. `receipts_log` = the ingest's
    // durable log (frames of deep pages are read back from it; may be empty).
    bool open(const std::string& base, const std::string& receipts_log, std::string* why = nullptr) {
        std::lock_guard<std::mutex> lk(m_mtx);
        close_locked();
        m_base = base; m_log = receipts_log;
        m_ofd = ::open((base + ".order").c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        m_dfd = ::open((base + ".digest").c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (m_ofd < 0 || m_dfd < 0 || !put(m_ofd, 0, "V37ORD1\0", kHdr) || !put(m_dfd, 0, "V37DIG1\0", kHdr)) {
            if (why) *why = "cannot create " + base + ".order/.digest: " + std::strerror(errno);
            close_locked();
            return false;
        }
        return true;
    }
    bool is_open() const { std::lock_guard<std::mutex> lk(m_mtx); return m_ofd >= 0 && !m_broken; }
    void set_verify(VerifyFn f) { std::lock_guard<std::mutex> lk(m_mtx); m_verify = std::move(f); }
    Stats stats() const { std::lock_guard<std::mutex> lk(m_mtx); return m_st; }
    std::uint64_t next_pos() const { std::lock_guard<std::mutex> lk(m_mtx); return m_next; }
    // F3 retention: logical disk use = the retained records only (the pruned head is a hole)
    std::uint64_t disk_bytes() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_ofd < 0 ? 0 : 2 * kHdr + (m_nrec - m_low_rec) * kOrdRec + (m_next - m_low) * kDigRec;
    }
    // ── F3 retention ────────────────────────────────────────────────────────
    // Keep the last R positions servable (0 = all). Takes effect at the next
    // append; the boot reload re-applies it deterministically (same files, same
    // lowest retained position after the same pushes).
    // `slab` = appends between prunes (0 = max(1024, R / 16); the KAT lowers it).
    void set_retain(std::uint64_t R, std::uint64_t slab = 0) { std::lock_guard<std::mutex> lk(m_mtx); m_retain = R; m_slab = slab; }
    std::uint64_t retain() const { std::lock_guard<std::mutex> lk(m_mtx); return m_retain; }
    // The lowest position this order still serves (0 = never pruned).
    std::uint64_t lowest_retained() const { std::lock_guard<std::mutex> lk(m_mtx); return m_low; }
    // The last prune, once (the owner logs it).
    std::optional<PruneEvent> take_prune() {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto e = m_prune; m_prune.reset(); return e;
    }
#define C2POOL_XMR_DURABLE_ORDER_RETAIN 1

    // One receipt pushed at [pos_first, pos_first + n) (the ingest's m_after
    // triple, in push order: the boot reload first, then every live push).
    void append(std::uint64_t pos_first, std::uint32_t n, const bytes32& id, std::size_t raw_size,
                std::uint64_t next_after, const bytes32& dig_after) {
        std::lock_guard<std::mutex> lk(m_mtx);
        const std::uint64_t off = m_log_off;
        m_log_off += 4 + raw_size;
        if (m_ofd < 0 || m_broken) return;
        if (n == 0 || pos_first != m_next || next_after != pos_first + n) {   // FAIL-CLOSED: never serve a gapped order
            ++m_st.gap; m_broken = true; return;
        }
        std::uint8_t rec[kOrdRec];
        put64(rec, pos_first); put32(rec + 8, n); std::memcpy(rec + 12, id.data(), 32); put64(rec + 44, off);
        std::vector<std::uint8_t> dig(static_cast<std::size_t>(n) * kDigRec, 0);
        std::memcpy(dig.data() + (n - 1) * kDigRec, dig_after.data(), 32);
        if (!put(m_ofd, kHdr + m_nrec * kOrdRec, rec, kOrdRec) ||
            !put(m_dfd, kHdr + m_next * kDigRec, dig.data(), dig.size())) {
            ++m_st.write_fail; m_broken = true; return;
        }
        ++m_nrec; m_next = next_after;
        ++m_st.records; m_st.positions += n;
        // F3 retention: amortised -- prune once the head exceeds R by a slab
        if (m_retain && m_next > m_low + m_retain + (m_slab ? m_slab : std::max<std::uint64_t>(1024, m_retain / 16))) prune_locked();
    }

    // The lane digest after `pos` pushes, from disk (nullopt = unknown; also
    // below the retained window -- the owner's probe then states no digest).
    std::optional<bytes32> digest_at(std::uint64_t pos) {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_dfd < 0 || m_broken || pos == 0 || pos > m_next) return std::nullopt;
        if (pos < m_low) { ++m_st.below_retention; return std::nullopt; }
        bytes32 d{};
        if (!get(m_dfd, kHdr + (pos - 1) * kDigRec, d.data(), 32)) return std::nullopt;
        bytes32 z{};
        if (d == z) return std::nullopt;
        ++m_st.digests;
        return d;
    }

    // ORDER page [a, p): at most max_ids receipts starting EXACTLY at `a`
    // (a receipt boundary), contiguous. ids = (pos_first, id); p_served = the
    // first position not served (p when complete). false = cannot serve.
    bool order_page(std::uint64_t a, std::uint64_t p, std::size_t max_ids,
                    std::vector<std::pair<std::uint64_t, bytes32>>& ids, std::uint64_t& p_served) {
        std::lock_guard<std::mutex> lk(m_mtx);
        ids.clear(); p_served = a;
        if (m_ofd < 0 || m_broken || a > p || a >= m_next || max_ids == 0) return false;
        if (a < m_low) { ++m_st.below_retention; return false; }   // F3 retention: pruned here (BELOW_HORIZON to the asker)
        std::uint64_t lo = m_low_rec, hi = m_nrec;   // first record with pos_first >= a (the pruned head is a hole)
        while (lo < hi) {
            const std::uint64_t mid = lo + (hi - lo) / 2;
            std::uint8_t r[8];
            if (!get(m_ofd, kHdr + mid * kOrdRec, r, 8)) return false;
            if (get64(r) < a) lo = mid + 1; else hi = mid;
        }
        if (lo >= m_nrec) return false;
        const std::uint64_t want = std::min<std::uint64_t>(m_nrec - lo, max_ids);
        std::vector<std::uint8_t> buf(static_cast<std::size_t>(want) * kOrdRec);
        if (!get(m_ofd, kHdr + lo * kOrdRec, buf.data(), buf.size())) return false;
        if (get64(buf.data()) != a) return false;   // `a` inside a multi-push receipt: not a contiguous start
        p_served = p;
        for (std::uint64_t i = 0; i < want; ++i) {
            const std::uint8_t* r = buf.data() + i * kOrdRec;
            const std::uint64_t pos = get64(r);
            if (pos >= p) break;
            bytes32 id{}; std::memcpy(id.data(), r + 12, 32);
            ids.emplace_back(pos, id);
            remember(id, get64(r + 44));
        }
        if (ids.size() == want && lo + want < m_nrec) {   // page full: the next record starts the next page
            std::uint8_t r[8];
            if (!get(m_ofd, kHdr + (lo + want) * kOrdRec, r, 8)) return false;
            if (get64(r) < p) p_served = get64(r);
        }
        ++m_st.pages; m_st.ids += ids.size(); m_st.bytes += ids.size() * 40;
        return true;
    }

    // ★ DROPS-CARRY-LIVE: our own order over [a, p) (pos_first, id), read-only
    // (no serving stats, no frame LRU). false = not readable (closed, broken,
    // `a` not a receipt start, or a gap).
    bool ids_between(std::uint64_t a, std::uint64_t p, std::vector<std::pair<std::uint64_t, bytes32>>& ids) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        ids.clear();
        if (m_ofd < 0 || m_broken || a > p || p > m_next) return false;
        if (a == p) return true;
        if (a < m_low) { ++m_st.below_retention; return false; }   // F3 retention
        std::uint64_t lo = m_low_rec, hi = m_nrec;
        while (lo < hi) {
            const std::uint64_t mid = lo + (hi - lo) / 2;
            std::uint8_t r[8];
            if (!get(m_ofd, kHdr + mid * kOrdRec, r, 8)) return false;
            if (get64(r) < a) lo = mid + 1; else hi = mid;
        }
        std::uint64_t pos = a;
        for (std::uint64_t i = lo; i < m_nrec && pos < p; ++i) {
            std::uint8_t r[kOrdRec];
            if (!get(m_ofd, kHdr + i * kOrdRec, r, kOrdRec)) return false;
            if (get64(r) != pos) return false;
            bytes32 id{}; std::memcpy(id.data(), r + 12, 32);
            ids.emplace_back(pos, id);
            pos += get32(r + 8);
        }
        return pos >= p;
    }

    // The raw frame of an id this node served in a deep page, read back from
    // the receipts log and verified against the id (false = not servable).
    bool frame(const bytes32& id, std::vector<std::uint8_t>& out) {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_lru.find(id);
        if (it == m_lru.end() || m_log.empty()) { ++m_st.frame_miss; return false; }
        const int fd = ::open(m_log.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) { ++m_st.frame_miss; return false; }
        std::uint8_t l[4];
        bool ok = get(fd, it->second, l, 4);
        const std::uint32_t len = ok ? get32(l) : 0;
        ok = ok && len > 0 && len <= kMaxFrame;
        if (ok) { out.resize(len); ok = get(fd, it->second + 4, out.data(), len); }
        ::close(fd);
        if (!ok || (m_verify && !m_verify(out, id))) { out.clear(); ++m_st.frame_miss; return false; }
        ++m_st.frames; m_st.frame_bytes += out.size();
        return true;
    }

private:
    static void put64(std::uint8_t* p, std::uint64_t v) { for (int i = 0; i < 8; ++i) p[i] = static_cast<std::uint8_t>(v >> (8 * i)); }
    static void put32(std::uint8_t* p, std::uint32_t v) { for (int i = 0; i < 4; ++i) p[i] = static_cast<std::uint8_t>(v >> (8 * i)); }
    static std::uint64_t get64(const std::uint8_t* p) { std::uint64_t v = 0; for (int i = 7; i >= 0; --i) v = (v << 8) | p[i]; return v; }
    static std::uint32_t get32(const std::uint8_t* p) { std::uint32_t v = 0; for (int i = 3; i >= 0; --i) v = (v << 8) | p[i]; return v; }
    static bool put(int fd, std::uint64_t off, const void* p, std::size_t n) {
        const auto* b = static_cast<const std::uint8_t*>(p);
        while (n) {
            const ssize_t w = ::pwrite(fd, b, n, static_cast<off_t>(off));
            if (w <= 0) { if (w < 0 && errno == EINTR) continue; return false; }
            b += w; n -= static_cast<std::size_t>(w); off += static_cast<std::uint64_t>(w);
        }
        return true;
    }
    static bool get(int fd, std::uint64_t off, void* p, std::size_t n) {
        auto* b = static_cast<std::uint8_t*>(p);
        while (n) {
            const ssize_t r = ::pread(fd, b, n, static_cast<off_t>(off));
            if (r <= 0) { if (r < 0 && errno == EINTR) continue; return false; }
            b += r; n -= static_cast<std::size_t>(r); off += static_cast<std::uint64_t>(r);
        }
        return true;
    }
    void remember(const bytes32& id, std::uint64_t off) {
        if (m_lru.emplace(id, off).second) {
            m_lru_order.push_back(id);
            while (m_lru_order.size() > kFrameLruMax) { m_lru.erase(m_lru_order.front()); m_lru_order.pop_front(); }
        }
    }
    // F3 retention (m_mtx held): the new lowest served position is the START of
    // the first record at or above next - R (a page must begin at a receipt
    // boundary); the records below it become a hole in both sidecars. The
    // digest of the position just below stays (a probe at exactly `low` reads
    // record low - 1).
    void prune_locked() {
        if (m_retain == 0 || m_next <= m_retain) return;
        const std::uint64_t want = m_next - m_retain;
        std::uint64_t lo = m_low_rec, hi = m_nrec;   // first record with pos_first >= want
        while (lo < hi) {
            const std::uint64_t mid = lo + (hi - lo) / 2;
            std::uint8_t r[8];
            if (!get(m_ofd, kHdr + mid * kOrdRec, r, 8)) return;
            if (get64(r) < want) lo = mid + 1; else hi = mid;
        }
        if (lo >= m_nrec || lo <= m_low_rec) return;
        std::uint8_t r[8];
        if (!get(m_ofd, kHdr + lo * kOrdRec, r, 8)) return;
        const std::uint64_t low = get64(r);
        if (low <= m_low || low == 0) return;
        PruneEvent e; e.from = m_low; e.to = low; e.retain = m_retain;
        e.order_bytes = (lo - m_low_rec) * kOrdRec;
        const std::uint64_t dig_keep_from = low >= 1 ? low - 1 : 0;   // keep the digest after `low` pushes
        const std::uint64_t dig_lo = m_low >= 1 ? m_low - 1 : 0;
        e.digest_bytes = dig_keep_from > dig_lo ? (dig_keep_from - dig_lo) * kDigRec : 0;
        bool punched = false;
#if defined(FALLOC_FL_PUNCH_HOLE) && defined(FALLOC_FL_KEEP_SIZE)
        const int f1 = ::fallocate(m_ofd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                                   static_cast<off_t>(kHdr + m_low_rec * kOrdRec), static_cast<off_t>(e.order_bytes));
        const int f2 = e.digest_bytes ? ::fallocate(m_dfd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                                                    static_cast<off_t>(kHdr + dig_lo * kDigRec), static_cast<off_t>(e.digest_bytes)) : 0;
        punched = (f1 == 0 && f2 == 0);
#endif
        if (punched) m_st.freed_bytes += e.order_bytes + e.digest_bytes; else ++m_st.punch_fail;
        e.punched = punched;
        m_st.pruned_positions += low - m_low;
        ++m_st.prunes;
        m_low = low; m_low_rec = lo;
        m_prune = e;
    }
    void close() { std::lock_guard<std::mutex> lk(m_mtx); close_locked(); }
    void close_locked() {
        if (m_ofd >= 0) ::close(m_ofd);
        if (m_dfd >= 0) ::close(m_dfd);
        m_ofd = m_dfd = -1;
        m_nrec = m_next = m_log_off = 0; m_broken = false;
        m_low = m_low_rec = 0; m_prune.reset();
        m_lru.clear(); m_lru_order.clear();
    }
    struct H32 { std::size_t operator()(const bytes32& b) const { std::size_t h; std::memcpy(&h, b.data(), sizeof h); return h; } };

    mutable std::mutex m_mtx;
    std::string m_base, m_log;
    int m_ofd = -1, m_dfd = -1;
    std::uint64_t m_nrec = 0, m_next = 0, m_log_off = 0;
    bool m_broken = false;
    std::uint64_t m_retain = 0, m_slab = 0;  // F3 retention: 0 = everything; slab 0 = auto
    std::uint64_t m_low = 0, m_low_rec = 0;  // lowest served position / its record index
    std::optional<PruneEvent> m_prune;
    VerifyFn m_verify;
    std::unordered_map<bytes32, std::uint64_t, H32> m_lru;
    std::deque<bytes32> m_lru_order;
    mutable Stats m_st;   // below_retention is counted from const readers too
};

// ★ HOLD-ROUND-3 F3b: who is served a WHOLE lane order [0, P) from the durable
// order, and how much (see the file header). Keyed by the asking connection
// and the P it asks for; bounded (256 peers x 64 cuts, oldest out). The
// clock is injectable for the KAT. No wire byte: the first [0, P) ask of a
// (peer, P) is refused exactly as the vault refuses it today; the second is
// the deliberate one.
class DeepServeBudget {
public:
    using Clock = std::chrono::steady_clock;
    enum class Verdict { Serve = 0, FirstAsk = 1, OverIds = 2, OverCuts = 3 };
    struct Options {
        std::uint64_t ids_factor = 2;        // ids per (peer, P) <= ids_factor x P + page
        std::uint64_t page_ids = 4096;       // + one page of slack (kCtrlMaxIdsPerOrder)
        std::uint32_t cuts_per_hour = 8;     // distinct P a peer may be served whole per rolling hour
        std::chrono::seconds window{3600};
    };
    struct Stats { std::uint64_t cuts = 0, first_ask = 0, over_ids = 0, over_cuts = 0, served_pages = 0, served_ids = 0; };
    struct Ask { Verdict v = Verdict::Serve; bool first_page = false; std::uint64_t ids_used = 0, ids_max = 0; std::uint32_t cuts_hour = 0; };

    DeepServeBudget() = default;
    explicit DeepServeBudget(const Options& o) : m_o(o) {}
    void set_options(Options o) { std::lock_guard<std::mutex> lk(m_mtx); m_o = o; }
    Options options() const { std::lock_guard<std::mutex> lk(m_mtx); return m_o; }
    Stats stats() const { std::lock_guard<std::mutex> lk(m_mtx); return m_st; }

    // A deep ORDER ask [a, P) of `want` ids by `peer` (a == 0: the whole order).
    Ask ask(std::uint64_t peer, std::uint64_t a, std::uint64_t P, std::uint64_t want, Clock::time_point now = Clock::now()) {
        std::lock_guard<std::mutex> lk(m_mtx);
        Ask r;
        Peer& pe = peer_locked(peer, now);
        auto it = pe.cuts.find(P);
        const bool fresh = it == pe.cuts.end();
        if (fresh) {
            while (pe.cuts.size() >= kCutsPerPeer) pe.cuts.erase(pe.cuts.begin());
            it = pe.cuts.emplace(P, Cut{}).first;
        }
        Cut& c = it->second;
        r.ids_max = m_o.ids_factor * P + m_o.page_ids;
        r.ids_used = c.ids;
        if (P > a && want > P - a) want = P - a;   // a page never carries more than the positions left
        if (a == 0 && !c.asked_once) {   // the routine first ask: BELOW_HORIZON, as before (the asker re-arms to a suffix)
            c.asked_once = true; ++m_st.first_ask; r.v = Verdict::FirstAsk; return r;
        }
        // a rolling-hour count of the cuts this peer was served from here
        while (!pe.starts.empty() && now - pe.starts.front() > m_o.window) pe.starts.pop_front();
        r.cuts_hour = static_cast<std::uint32_t>(pe.starts.size());
        if (!c.counted) {
            if (pe.starts.size() >= m_o.cuts_per_hour) { ++m_st.over_cuts; r.v = Verdict::OverCuts; return r; }
        }
        if (c.ids + want > r.ids_max) { ++m_st.over_ids; r.v = Verdict::OverIds; return r; }
        if (!c.counted) { c.counted = true; pe.starts.push_back(now); ++m_st.cuts; r.cuts_hour = static_cast<std::uint32_t>(pe.starts.size()); }
        r.first_page = !c.served;
        c.served = true;
        r.v = Verdict::Serve;
        return r;
    }
    // The page that was served (ids actually sent).
    void served(std::uint64_t peer, std::uint64_t P, std::uint64_t n_ids) {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto pi = m_peers.find(peer);
        if (pi == m_peers.end()) return;
        auto it = pi->second.cuts.find(P);
        if (it == pi->second.cuts.end()) return;
        it->second.ids += n_ids;
        ++m_st.served_pages; m_st.served_ids += n_ids;
    }
    // A refusal is logged once per (peer, P, verdict): true = first time.
    bool note_logged(std::uint64_t peer, std::uint64_t P, Verdict v) {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto pi = m_peers.find(peer);
        if (pi == m_peers.end()) return false;
        auto it = pi->second.cuts.find(P);
        if (it == pi->second.cuts.end()) return false;
        const std::uint8_t bit = static_cast<std::uint8_t>(1u << static_cast<unsigned>(v));
        if (it->second.logged & bit) return false;
        it->second.logged |= bit;
        return true;
    }
    void forget_peer(std::uint64_t peer) { std::lock_guard<std::mutex> lk(m_mtx); m_peers.erase(peer); }
    static const char* name(Verdict v) {
        switch (v) { case Verdict::Serve: return "serve"; case Verdict::FirstAsk: return "first-ask"; case Verdict::OverIds: return "over-ids-budget"; case Verdict::OverCuts: return "over-cuts-budget"; }
        return "?";
    }

private:
    static constexpr std::size_t kPeers = 256, kCutsPerPeer = 64;
    struct Cut { bool asked_once = false, counted = false, served = false; std::uint8_t logged = 0; std::uint64_t ids = 0; };
    struct Peer { std::map<std::uint64_t, Cut> cuts; std::deque<Clock::time_point> starts; Clock::time_point seen{}; };
    Peer& peer_locked(std::uint64_t peer, Clock::time_point now) {
        auto it = m_peers.find(peer);
        if (it == m_peers.end()) {
            while (m_peers.size() >= kPeers) {   // oldest-seen out
                auto victim = m_peers.begin();
                for (auto vi = m_peers.begin(); vi != m_peers.end(); ++vi) if (vi->second.seen < victim->second.seen) victim = vi;
                m_peers.erase(victim);
            }
            it = m_peers.emplace(peer, Peer{}).first;
        }
        it->second.seen = now;
        return it->second;
    }
    mutable std::mutex m_mtx;
    Options m_o;
    std::map<std::uint64_t, Peer> m_peers;
    Stats m_st;
};
#define C2POOL_XMR_DEEP_SERVE_BUDGET 1

} // namespace c2pool::v37n::xmr::relay
