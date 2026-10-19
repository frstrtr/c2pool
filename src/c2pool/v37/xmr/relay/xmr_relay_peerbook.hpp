// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/relay/xmr_relay_peerbook.hpp   (RELAY-DISCOVERY)
//
// The relay's address book: every relay address this node has heard of for
// ITS pool (one book per pool id + network; the daemon keys the file on both),
// what it knows of each (first/last seen, "good" = this node completed a HELLO
// with the right pool id on a link it DIALED to that address, dial failures),
// and the policy that uses it (mirrors v36 got_addr / get_good_peers):
//   learn()          a candidate (from FB_ADDR, an inbound peer's listen port,
//                    the seed list); never good by itself
//   mark_good()      HELLO ok on a link dialed to that address
//   mark_failed()    dial failed / link ended before HELLO -> backoff, and
//                    dropped after max_fails
//   mark_bad()       refused at HELLO (another pool): erased and never
//                    re-learned (bounded memory of such addresses)
//   mark_self()      NODE-NONCE: this node's own address (a HELLO carried our
//                    node nonce, or it is our listen address): erased, never
//                    learned / good / dialed / handed out again (bounded)
//   sample_good()    the FB_ADDR answer: a random sample of good entries
//   dial_candidates() good first (freshest), then candidates, honouring backoff
//   expire()         drops stale candidates / stale good entries
// Bounded: max_entries (evicts the stalest non-good entry first).
//
// Boost-free and core-free, so it links into the stdlib-only relay KATs. The
// on-disk form is core::AddrStore (xmr_relay_peerstore.hpp): records() /
// load() are the seam.
// ===========================================================================
#pragma once

#include <algorithm>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <random>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace c2pool::v37n::xmr::relay {

// One persisted address. `good` and `fails` ride core::AddrValue::m_service.
struct PeerRecord {
    std::string   host;
    std::uint16_t port = 0;
    std::uint64_t first_seen = 0;   // unix s
    std::uint64_t last_seen = 0;    // unix s
    bool          good = false;
    std::uint32_t fails = 0;
    bool operator==(const PeerRecord&) const = default;
};

inline std::string peer_key(const std::string& host, std::uint16_t port) { return host + ":" + std::to_string(port); }

class PeerBook {
public:
    struct Limits {
        std::size_t   max_entries = 1024;
        std::uint64_t candidate_ttl_s = 7 * 86400;    // a never-good address unseen this long is dropped
        std::uint64_t good_ttl_s = 30 * 86400;        // a good address unseen this long is dropped
        std::uint32_t max_fails = 8;                  // consecutive failures before an entry is dropped
        std::uint64_t backoff_base_s = 5;             // retry after base * 2^(fails-1), capped
        std::uint64_t backoff_cap_s = 3600;
        std::size_t   bad_memory = 1024;              // refused addresses remembered (never re-learned)
        std::size_t   self_memory = 64;               // NODE-NONCE: own addresses remembered (never dialed)
    };
    PeerBook() = default;
    explicit PeerBook(Limits l) : m_l(l) {}
    void set_limits(Limits l) { std::lock_guard<std::mutex> lk(m_mtx); m_l = l; }

    // Load persisted records (start-up). Capped; last_seen clamped to now.
    void load(const std::vector<PeerRecord>& v, std::uint64_t now) {
        std::lock_guard<std::mutex> lk(m_mtx);
        for (const auto& r : v) {
            if (r.host.empty() || r.port == 0) continue;
            Ent e; e.r = r; e.r.last_seen = std::min(r.last_seen, now); e.r.first_seen = std::min(r.first_seen, e.r.last_seen);
            put_locked(peer_key(r.host, r.port), e);
        }
    }
    std::vector<PeerRecord> records() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        std::vector<PeerRecord> v; v.reserve(m_e.size());
        for (const auto& [k, e] : m_e) { (void)k; v.push_back(e.r); }
        return v;
    }
    // A candidate address. true = it is new to the book.
    bool learn(const std::string& host, std::uint16_t port, std::uint64_t seen, std::uint64_t now) {
        if (host.empty() || port == 0) return false;
        const std::string k = peer_key(host, port);
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_bad.count(k) || m_self.count(k)) return false;
        seen = std::min(seen, now);
        auto it = m_e.find(k);
        if (it != m_e.end()) {
            if (seen > it->second.r.last_seen) { it->second.r.last_seen = seen; m_dirty = true; }
            return false;
        }
        Ent e; e.r.host = host; e.r.port = port; e.r.first_seen = seen; e.r.last_seen = seen;
        return put_locked(k, e);
    }
    void mark_good(const std::string& host, std::uint16_t port, std::uint64_t now) {
        const std::string k = peer_key(host, port);
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_self.count(k)) return;   // NODE-NONCE: our own address is never good
        m_bad.erase(k);
        auto it = m_e.find(k);
        if (it == m_e.end()) {
            Ent e; e.r.host = host; e.r.port = port; e.r.first_seen = now;
            if (!put_locked(k, e)) return;
            it = m_e.find(k);
        }
        it->second.r.good = true; it->second.r.fails = 0; it->second.r.last_seen = now; it->second.next_try = 0;
        m_dirty = true;
    }
    void mark_failed(const std::string& host, std::uint16_t port, std::uint64_t now) {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_e.find(peer_key(host, port));
        if (it == m_e.end()) return;
        Ent& e = it->second;
        if (++e.r.fails >= m_l.max_fails) { m_e.erase(it); m_dirty = true; return; }
        const std::uint32_t sh = std::min<std::uint32_t>(e.r.fails - 1, 20);
        e.next_try = now + std::min(m_l.backoff_cap_s, m_l.backoff_base_s << sh);
        m_dirty = true;
    }
    void mark_bad(const std::string& host, std::uint16_t port) {
        const std::string k = peer_key(host, port);
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_e.erase(k)) m_dirty = true;
        if (m_bad.insert(k).second) {
            m_bad_order.push_back(k);
            while (m_bad_order.size() > m_l.bad_memory) { m_bad.erase(m_bad_order.front()); m_bad_order.pop_front(); }
        }
    }
    // NODE-NONCE: this node's own address. Sticky (mark_good cannot undo it),
    // bounded (self_memory, oldest forgotten first), not persisted: the daemon
    // re-marks its listen addresses at start and a HELLO nonce re-detects the rest.
    void mark_self(const std::string& host, std::uint16_t port) {
        if (host.empty() || port == 0) return;
        const std::string k = peer_key(host, port);
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_e.erase(k)) m_dirty = true;
        m_bad.erase(k);
        if (m_self.insert(k).second) {
            m_self_order.push_back(k);
            while (m_self_order.size() > m_l.self_memory) { m_self.erase(m_self_order.front()); m_self_order.pop_front(); }
        }
    }
    bool is_self(const std::string& host, std::uint16_t port) const {
        std::lock_guard<std::mutex> lk(m_mtx); return m_self.count(peer_key(host, port)) != 0;
    }
    std::size_t self_size() const { std::lock_guard<std::mutex> lk(m_mtx); return m_self.size(); }
    bool is_bad(const std::string& host, std::uint16_t port) const {
        std::lock_guard<std::mutex> lk(m_mtx); return m_bad.count(peer_key(host, port)) != 0;
    }
    bool is_good(const std::string& host, std::uint16_t port) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_e.find(peer_key(host, port));
        return it != m_e.end() && it->second.r.good;
    }
    bool contains(const std::string& host, std::uint16_t port) const {
        std::lock_guard<std::mutex> lk(m_mtx); return m_e.count(peer_key(host, port)) != 0;
    }
    // FB_ADDR answer: up to n good entries at random; `keep` filters (private /
    // asker exclusion is the caller's policy).
    template <class Keep>
    std::vector<PeerRecord> sample_good(std::size_t n, Keep keep) const {
        std::vector<PeerRecord> v;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            for (const auto& [k, e] : m_e) { (void)k; if (e.r.good && keep(e.r)) v.push_back(e.r); }
        }
        thread_local std::mt19937_64 rng{std::random_device{}()};
        std::shuffle(v.begin(), v.end(), rng);
        if (v.size() > n) v.resize(n);
        return v;
    }
    // Addresses to dial now: good first (freshest first), then candidates
    // (freshest first); entries in backoff or whose key is in `skip` are left out.
    std::vector<PeerRecord> dial_candidates(std::size_t n, std::uint64_t now, const std::set<std::string>& skip) const {
        std::vector<PeerRecord> v;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            for (const auto& [k, e] : m_e) if (!skip.count(k) && e.next_try <= now) v.push_back(e.r);
        }
        std::sort(v.begin(), v.end(), [](const PeerRecord& a, const PeerRecord& b) {
            if (a.good != b.good) return a.good;
            if (a.fails != b.fails) return a.fails < b.fails;
            return a.last_seen > b.last_seen;
        });
        if (v.size() > n) v.resize(n);
        return v;
    }
    // Drop stale entries. Returns how many went.
    std::size_t expire(std::uint64_t now) {
        std::lock_guard<std::mutex> lk(m_mtx);
        std::size_t n = 0;
        for (auto it = m_e.begin(); it != m_e.end();) {
            const auto& r = it->second.r;
            const std::uint64_t ttl = r.good ? m_l.good_ttl_s : m_l.candidate_ttl_s;
            if (now > r.last_seen && now - r.last_seen > ttl) { it = m_e.erase(it); ++n; } else ++it;
        }
        if (n) m_dirty = true;
        return n;
    }
    std::size_t size() const { std::lock_guard<std::mutex> lk(m_mtx); return m_e.size(); }
    std::size_t good() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        std::size_t g = 0; for (const auto& [k, e] : m_e) { (void)k; g += e.r.good ? 1 : 0; } return g;
    }
    std::size_t bad_size() const { std::lock_guard<std::mutex> lk(m_mtx); return m_bad.size(); }
    bool take_dirty() { std::lock_guard<std::mutex> lk(m_mtx); const bool d = m_dirty; m_dirty = false; return d; }

private:
    struct Ent { PeerRecord r; std::uint64_t next_try = 0; };
    // insert under the cap: evict the stalest non-good entry, else refuse
    // (a full book of good peers is never displaced by an unverified one).
    bool put_locked(const std::string& k, const Ent& e) {
        if (m_bad.count(k) || m_self.count(k)) return false;
        if (!m_e.count(k) && m_e.size() >= m_l.max_entries) {
            auto victim = m_e.end();
            for (auto it = m_e.begin(); it != m_e.end(); ++it)
                if (!it->second.r.good && (victim == m_e.end() || it->second.r.last_seen < victim->second.r.last_seen)) victim = it;
            if (victim == m_e.end() || (e.r.good == false && victim->second.r.last_seen > e.r.last_seen)) return false;
            m_e.erase(victim);
        }
        m_e[k] = e;
        m_dirty = true;
        return true;
    }
    Limits m_l{};
    mutable std::mutex m_mtx;
    std::map<std::string, Ent> m_e;
    std::set<std::string> m_bad;
    std::deque<std::string> m_bad_order;
    std::set<std::string> m_self;              // NODE-NONCE
    std::deque<std::string> m_self_order;
    bool m_dirty = false;
};

// NODE-NONCE: which of two HELLO-ok links to the SAME node (equal peer node
// nonce) to close. Both ends evaluate it on their own view and close the SAME
// socket: a link's DIALER nonce is known to both ends (ours if we dialed it,
// the peer's HELLO nonce if it dialed us).
//   different dialers  -> keep the link dialed by the LOWER nonce (both ends agree)
//   same dialer, us    -> we close the newer link `p` (only the dialer decides)
//   same dialer, peer  -> Defer: keep both, the peer closes one (no race where
//                         each end closes a different one and both links die)
// No penalty either way: no DoS strike, no book failure, no ban.
enum class DupPick { DropNew, DropOld, Defer };
inline DupPick dup_link_rule(std::uint64_t ours, std::uint64_t theirs, bool new_outbound, bool old_outbound) {
    const std::uint64_t dn = new_outbound ? ours : theirs;
    const std::uint64_t d0 = old_outbound ? ours : theirs;
    if (dn != d0) return dn > d0 ? DupPick::DropNew : DupPick::DropOld;
    return dn == ours ? DupPick::DropNew : DupPick::Defer;
}

} // namespace c2pool::v37n::xmr::relay
