// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Read-only per-inject ledger mirror (S4) and best-ChainLock mirror — OBSERVE
// ONLY.
//
// WHY THIS EXISTS
// ---------------
// /api/tx-inject-status (core::obs::inject_status(), p2p_message_stats.hpp)
// reports COUNTS: how many injects the pool tracks and how many bytes they
// claim. A wallet that submitted a specific tx needs that tx's own state: is
// it still tracked, until which height (expiry_height), and did the last
// template build carry it (RIDES) or not (HELD, and why). The node already
// owns every one of those facts — the inject pool's entry, the ride log's
// per-build verdict — so this store MIRRORS them for the loopback
// GET /api/tx-inject/ledger endpoint. The same endpoint (and getblockchaininfo
// on the DASH node) shows the best ChainLock the node adopted, so a caller can
// tell how deep a confirmation is final.
//
// THREADING: the only non-atomic obs store. Every member is guarded by one
// mutex; writers (the node io thread: NodeCoinState's admit / reconcile; the
// template build: log_inject_rides; the maintainer: ChainLock adoption) take
// it briefly, and the web thread copies a snapshot out. No node lock is ever
// taken from here and no node call is made.
//
// REWARD SAFETY: nothing here is read by template building, share
// validation, payout or coinbase construction. It holds copies of state the
// node already owns; changing it changes nothing on the wire or in a block.
//
// Depends only on core/uint256.hpp; the DASH constants it mirrors are pinned
// by static_assert in test/test_dash_tx_inject.cpp.

#include <core/uint256.hpp>

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace core::obs {

/// The last template build's verdict on one inject (the ride log's line).
struct InjectLedgerBuild {
    uint32_t    height{0};    // the height of the template that was built
    bool        rides{false}; // true: RIDES (in the body); false: HELD
    std::string cause;        // "ok" on RIDES, else the HELD cause
    uint32_t    vin{0};       // inputs of the tx (RIDES only, else 0)
    uint64_t    fee{0};       // base fee the body carries (RIDES only, else 0)

    bool operator==(const InjectLedgerBuild& o) const {
        return height == o.height && rides == o.rides && cause == o.cause &&
               vin == o.vin && fee == o.fee;
    }
};

/// One tracked inject.
struct InjectLedgerEntry {
    uint256  txid;
    int64_t  submit_time{0};
    int32_t  expiry_height{0};   // 0 = never auto-expires
    uint32_t byte_size{0};
    uint32_t flags{0};
    bool     in_mempool{true};
    std::optional<InjectLedgerBuild> last_build;   // nullopt until a build saw it
};

class InjectLedger {
public:
    /// Bound of the mirror: the DASH inject pool's INJECT_POOL_MAX_ENTRIES
    /// (pinned by static_assert in the DASH KAT). An upsert past it is dropped
    /// and counted, never grown.
    static constexpr size_t kMaxEntries = 1024;

    /// Admit / retrack: insert or replace the entry for e.txid. A replace
    /// keeps the stored last_build unless `e` carries one.
    void upsert(const InjectLedgerEntry& e) {
        std::lock_guard<std::mutex> lk(m_mu);
        auto it = m_entries.find(e.txid);
        if (it != m_entries.end()) {
            std::optional<InjectLedgerBuild> keep = it->second.last_build;
            it->second = e;
            if (!e.last_build) it->second.last_build = std::move(keep);
        } else if (m_entries.size() >= kMaxEntries) {
            ++m_overflow_dropped;
        } else {
            m_entries.emplace(e.txid, e);
        }
        touch();
    }

    /// Release / reap: the inject is no longer tracked.
    void erase(const uint256& txid) {
        std::lock_guard<std::mutex> lk(m_mu);
        m_entries.erase(txid);
        touch();
    }

    /// After a reconcile: erase every entry not in `tracked` (the self-heal
    /// for a missed publisher).
    void retain(const std::vector<uint256>& tracked) {
        std::lock_guard<std::mutex> lk(m_mu);
        const std::set<uint256> keep(tracked.begin(), tracked.end());
        for (auto it = m_entries.begin(); it != m_entries.end();)
            it = keep.count(it->first) ? std::next(it) : m_entries.erase(it);
        touch();
    }

    /// The last build's verdict for a tracked inject. No-op when the txid is
    /// not in the ledger (an untracked inject never creates an entry here).
    void set_last_build(const uint256& txid, const InjectLedgerBuild& b) {
        std::lock_guard<std::mutex> lk(m_mu);
        auto it = m_entries.find(txid);
        if (it == m_entries.end()) return;
        it->second.last_build = b;
        touch();
    }

    /// The tip height the last publish saw.
    void set_tip(uint32_t h) {
        std::lock_guard<std::mutex> lk(m_mu);
        m_tip = h;
        touch();
    }

    /// Web thread: a copy of every entry, txid order.
    std::vector<InjectLedgerEntry> snapshot() const {
        std::lock_guard<std::mutex> lk(m_mu);
        std::vector<InjectLedgerEntry> out;
        out.reserve(m_entries.size());
        for (const auto& [id, e] : m_entries) out.push_back(e);
        return out;
    }

    uint64_t overflow_dropped() const { std::lock_guard<std::mutex> lk(m_mu); return m_overflow_dropped; }
    uint32_t tip() const              { std::lock_guard<std::mutex> lk(m_mu); return m_tip; }
    /// Unix seconds of the last write; 0 = never published (the endpoint then
    /// says "wired": false).
    int64_t  updated_at() const       { std::lock_guard<std::mutex> lk(m_mu); return m_updated_at; }

    /// Test seam: back to the never-published state.
    void reset() {
        std::lock_guard<std::mutex> lk(m_mu);
        m_entries.clear();
        m_overflow_dropped = 0;
        m_tip = 0;
        m_updated_at = 0;
    }

private:
    void touch() { m_updated_at = static_cast<int64_t>(std::time(nullptr)); }

    mutable std::mutex                   m_mu;
    std::map<uint256, InjectLedgerEntry> m_entries;
    uint64_t                             m_overflow_dropped{0};
    uint32_t                             m_tip{0};
    int64_t                              m_updated_at{0};
};

/// Process-wide instance (same pattern as inject_status()).
inline InjectLedger& inject_ledger()
{
    static InjectLedger s;
    return s;
}

/// The best ChainLock the node adopted: its height, the block hash it locks
/// (null = unknown, never fabricated), and how it was justified
/// ("bls-verified" | "chain-committed").
struct BestChainLock {
    int32_t     height{0};
    uint256     blockhash;
    std::string provenance;
    int64_t     updated_at{0};
};

class BestChainLockObs {
public:
    void publish(const BestChainLock& cl) {
        std::lock_guard<std::mutex> lk(m_mu);
        m_cl = cl;
    }
    /// nullopt until the first publish.
    std::optional<BestChainLock> snapshot() const {
        std::lock_guard<std::mutex> lk(m_mu);
        return m_cl;
    }
    /// Test seam: back to the never-published state.
    void reset() {
        std::lock_guard<std::mutex> lk(m_mu);
        m_cl.reset();
    }

private:
    mutable std::mutex           m_mu;
    std::optional<BestChainLock> m_cl;
};

/// Process-wide instance.
inline BestChainLockObs& best_chainlock()
{
    static BestChainLockObs s;
    return s;
}

} // namespace core::obs
