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
// ===========================================================================
#pragma once

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
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
    };
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
    std::uint64_t disk_bytes() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_ofd < 0 ? 0 : 2 * kHdr + m_nrec * kOrdRec + m_next * kDigRec;
    }

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
    }

    // The lane digest after `pos` pushes, from disk (nullopt = unknown).
    std::optional<bytes32> digest_at(std::uint64_t pos) {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_dfd < 0 || m_broken || pos == 0 || pos > m_next) return std::nullopt;
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
        std::uint64_t lo = 0, hi = m_nrec;   // first record with pos_first >= a
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
        std::uint64_t lo = 0, hi = m_nrec;
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
    void close() { std::lock_guard<std::mutex> lk(m_mtx); close_locked(); }
    void close_locked() {
        if (m_ofd >= 0) ::close(m_ofd);
        if (m_dfd >= 0) ::close(m_dfd);
        m_ofd = m_dfd = -1;
        m_nrec = m_next = m_log_off = 0; m_broken = false;
        m_lru.clear(); m_lru_order.clear();
    }
    struct H32 { std::size_t operator()(const bytes32& b) const { std::size_t h; std::memcpy(&h, b.data(), sizeof h); return h; } };

    mutable std::mutex m_mtx;
    std::string m_base, m_log;
    int m_ofd = -1, m_dfd = -1;
    std::uint64_t m_nrec = 0, m_next = 0, m_log_off = 0;
    bool m_broken = false;
    VerifyFn m_verify;
    std::unordered_map<bytes32, std::uint64_t, H32> m_lru;
    std::deque<bytes32> m_lru_order;
    Stats m_st;
};

} // namespace c2pool::v37n::xmr::relay
