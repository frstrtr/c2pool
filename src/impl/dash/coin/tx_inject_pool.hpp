// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// #157 — miner/user tx-injection: the bounded, opt-in INJECT POOL (M1).
///
/// A small, capped, per-node ledger of the injected transactions this node has
/// accepted into its mempool with priority (--embedded-tx-inject, default OFF).
/// It is NOT the template-inclusion mechanism — that is the mempool: an accepted
/// inject rides Mempool::add_inject (a large mapDeltas priority delta) and the
/// SAME get_sorted_txs_with_fees selector guards as any other body tx. This pool
/// is the DoS-accounting + expiry ledger the design's §4.6 guards need:
///
///   * INJECT_POOL_MAX_ENTRIES — a hard cap on how many injects are tracked;
///   * kMaxInjectTotalBytes     — a cumulative byte cap (the PR-1 stand-in for
///                                the §4.4 INJECT_MAX_BLOCK_FRACTION reservation:
///                                bound how much block space injects can claim,
///                                enforced in the pool rather than as a selector
///                                reservation — the selector already yields the
///                                fee-sorted remainder);
///   * kMaxInjectTxBytes        — a per-tx size cap (mirrors the mempool's own
///                                consensus bad-txns-oversize guard);
///   * expiry_height            — drop an inject a node no longer re-offers.
///
/// RELEASE ON CONFIRM (#2121). An inject that left the mempool (confirmed by a
/// block, or conflict-evicted by one) leaves the ACTIVE set through release():
/// its bytes stop counting against the caps at once. Its metadata moves to a
/// bounded RELEASED ledger that size() / total_bytes() / would_admit() never
/// count, kept as deep as the mempool's confirmed-inject keep: a rewind that
/// puts the tx back into the mempool (Mempool::readmit_disconnected_injects)
/// is re-tracked with its original flags / expiry / size / submit time
/// (retrack(), through the same caps as a fresh admit). still_wanted() is the
/// predicate the rewind asks. An expired inject (reap_expired) never enters
/// the released ledger: it is never wanted back.
///
/// REWARD SAFETY: this structure holds txids + metadata ONLY. It has NO write
/// path to the coinbase, subsidy, PPLNS, donation, payee queue, or give_author —
/// it can only bound how many consensus-valid body txs the mempool prioritises.
///
/// THREADING: io-thread confined, same discipline as NodeCoinState's
/// m_pinned_local_txs. No internal lock; the owner serialises access.

#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace dash {
namespace coin {

/// One accepted inject's bookkeeping. `flags` mirror the design's wire flags
/// (bit0 zero-fee-intent, bit1 non-standard-intent, bit2 priority-request) and
/// are carried for M2/M3 (fan-out / rate-accounting); PR-1 stores them but the
/// priority is uniform (see Mempool::INJECT_FEE_DELTA).
struct InjectEntry {
    uint256  txid;
    uint32_t flags{0};
    int32_t  expiry_height{0};   // 0 = never auto-expires
    uint32_t byte_size{0};
    time_t   submit_time{0};
};

/// An inject that left the active set (release()): its bookkeeping, kept so a
/// rewind that puts the tx back can re-track it. `released_at` is the tip
/// height at release; prune_released() drops it past the undo-keep depth.
struct ReleasedEntry {
    InjectEntry e;
    uint32_t    released_at{0};
};

class TxInjectPool {
public:
    /// Hard cap on tracked injects (§4.6 INJECT_POOL_MAX_ENTRIES).
    static constexpr size_t INJECT_POOL_MAX_ENTRIES = 1024;
    /// Cumulative byte ceiling across ALL tracked injects — the PR-1 stand-in
    /// for the block-fraction reservation. Mirrors Mempool::kMaxPinnedTotalBytes
    /// (well under Dash's 2 MB block limit; injects are never the whole block).
    static constexpr size_t kMaxInjectTotalBytes = 400000;
    /// Per-tx size cap (mirrors Mempool::kMaxInjectTxBytes / bad-txns-oversize).
    static constexpr size_t kMaxInjectTxBytes = 100000;
    /// Bound of the released ledger (release()): the oldest record is dropped
    /// past it. Same count as the active cap.
    static constexpr size_t kMaxReleased = INJECT_POOL_MAX_ENTRIES;

    /// Every admission refusal is NAMED (DEF3 discipline).
    enum class Admit : uint8_t {
        Ok = 0,
        Duplicate,           // txid already tracked
        PoolFull,            // INJECT_POOL_MAX_ENTRIES reached
        TotalBytesExceeded,  // would exceed kMaxInjectTotalBytes
        TooLarge,            // byte_size > kMaxInjectTxBytes
        NotTracked,          // retrack: no released record for the txid
    };
    static const char* admit_name(Admit a) {
        switch (a) {
            case Admit::Ok:                 return "ok";
            case Admit::Duplicate:          return "inject-pool-duplicate";
            case Admit::PoolFull:           return "inject-pool-full";
            case Admit::TotalBytesExceeded: return "inject-pool-total-bytes-exceeded";
            case Admit::TooLarge:           return "inject-pool-oversize";
            case Admit::NotTracked:         return "inject-pool-not-tracked";
        }
        return "inject-pool-unknown";
    }

    bool   contains(const uint256& txid) const { return m_entries.count(txid) != 0; }
    size_t size() const { return m_entries.size(); }
    size_t total_bytes() const { return m_total_bytes; }
    bool   empty() const { return m_entries.empty(); }
    size_t released_size() const { return m_released.size(); }

    /// The active (tracked) txids, in admission order.
    std::vector<uint256> tracked_ids() const {
        std::vector<uint256> out;
        out.reserve(m_entries.size());
        for (const uint256& id : m_order)
            if (m_entries.count(id)) out.push_back(id);
        return out;
    }

    /// The active entry for `txid` (nullopt when it is not tracked).
    std::optional<InjectEntry> entry(const uint256& txid) const {
        auto it = m_entries.find(txid);
        if (it == m_entries.end()) return std::nullopt;
        return it->second;
    }

    /// Would-admit check WITHOUT mutating — the caller runs it before the more
    /// expensive mempool admission so a full/over-cap pool refuses cheaply.
    Admit would_admit(const uint256& txid, uint32_t byte_size) const {
        if (byte_size > kMaxInjectTxBytes) return Admit::TooLarge;
        if (m_entries.count(txid))         return Admit::Duplicate;
        if (m_entries.size() >= INJECT_POOL_MAX_ENTRIES) return Admit::PoolFull;
        if (m_total_bytes + byte_size > kMaxInjectTotalBytes)
            return Admit::TotalBytesExceeded;
        return Admit::Ok;
    }

    /// Record an accepted inject. Returns the named verdict; on Ok the entry is
    /// tracked and its bytes count toward the cumulative cap.
    Admit admit(const uint256& txid, uint32_t flags,
                int32_t expiry_height, uint32_t byte_size) {
        Admit v = would_admit(txid, byte_size);
        if (v != Admit::Ok) return v;
        InjectEntry e;
        e.txid = txid;
        e.flags = flags;
        e.expiry_height = expiry_height;
        e.byte_size = byte_size;
        e.submit_time = std::time(nullptr);
        m_order.push_back(txid);
        m_entries.emplace(txid, e);
        m_total_bytes += byte_size;
        // A fresh admission supersedes any released record of the same txid.
        if (m_released.erase(txid)) erase_released_order(txid);
        return Admit::Ok;
    }

    /// Forget one inject without keeping a released record. No-op if
    /// untracked. Returns true if it was tracked.
    bool forget(const uint256& txid) {
        auto it = m_entries.find(txid);
        if (it == m_entries.end()) return false;
        m_total_bytes -= it->second.byte_size;
        m_entries.erase(it);
        erase_order(txid);
        return true;
    }

    /// An active inject left the mempool (confirmed, or conflict-evicted):
    /// it leaves the active set and its bytes leave the caps; its metadata
    /// moves to the released ledger (oldest dropped past kMaxReleased) so a
    /// rewind can re-track it. Returns true if it was tracked.
    bool release(const uint256& txid, uint32_t at_height) {
        auto it = m_entries.find(txid);
        if (it == m_entries.end()) return false;
        ReleasedEntry r;
        r.e = it->second;
        r.released_at = at_height;
        m_total_bytes -= it->second.byte_size;
        m_entries.erase(it);
        erase_order(txid);
        if (m_released.count(txid)) erase_released_order(txid);
        m_released[txid] = r;
        m_released_order.push_back(txid);
        while (m_released.size() > kMaxReleased && !m_released_order.empty()) {
            m_released.erase(m_released_order.front());
            m_released_order.pop_front();
        }
        return true;
    }

    /// What retrack(txid) would answer, without mutating: NotTracked when
    /// there is no released record, else the active caps' verdict on its size.
    Admit would_retrack(const uint256& txid) const {
        auto it = m_released.find(txid);
        if (it == m_released.end()) return Admit::NotTracked;
        return would_admit(txid, it->second.e.byte_size);
    }

    /// A released inject is back in the mempool (a rewind put it back): move
    /// it to the active set with its ORIGINAL flags / expiry / size / submit
    /// time, through the same caps as a fresh admit. On a refusal the
    /// released record stays.
    Admit retrack(const uint256& txid) {
        const Admit v = would_retrack(txid);
        if (v != Admit::Ok) return v;
        auto it = m_released.find(txid);
        const InjectEntry e = it->second.e;
        m_released.erase(it);
        erase_released_order(txid);
        m_order.push_back(txid);
        m_entries.emplace(txid, e);
        m_total_bytes += e.byte_size;
        return Admit::Ok;
    }

    /// Whether a rewind should put `txid` back into the mempool, with
    /// `next_height` the height of the block the next template builds (0:
    /// unknown, nothing counts as expired). Wanted = still active, or released
    /// with an expiry the next block does not pass (expiry_height != 0 &&
    /// next_height > expiry_height is expired, as reap_expired) and room in
    /// the active caps for its retrack.
    bool still_wanted(const uint256& txid, int32_t next_height) const {
        if (m_entries.count(txid)) return true;
        auto it = m_released.find(txid);
        if (it == m_released.end()) return false;
        const InjectEntry& e = it->second.e;
        if (e.expiry_height != 0 && next_height > e.expiry_height) return false;
        return would_retrack(txid) == Admit::Ok;
    }

    /// Drop the released records older than `depth` blocks below
    /// `tip_height` (released_at + depth < tip_height): a rewind cannot reach
    /// them, and the mempool's confirmed keep prunes on the same depth.
    /// Returns how many were dropped.
    size_t prune_released(uint32_t tip_height, uint32_t depth) {
        size_t dropped = 0;
        std::deque<uint256> keep;
        for (const uint256& id : m_released_order) {
            auto it = m_released.find(id);
            if (it == m_released.end()) continue;
            if (static_cast<uint64_t>(it->second.released_at) + depth < tip_height) {
                m_released.erase(it);
                ++dropped;
            } else {
                keep.push_back(id);
            }
        }
        m_released_order.swap(keep);
        return dropped;
    }

    /// Drop injects whose expiry_height has passed (height > expiry_height, for
    /// entries with expiry_height != 0). Returns the dropped txids so the caller
    /// can evict them from the mempool too. Also compacts the FIFO order deque.
    std::vector<uint256> reap_expired(int32_t height) {
        std::vector<uint256> dropped;
        std::deque<uint256> keep;
        for (const uint256& id : m_order) {
            auto it = m_entries.find(id);
            if (it == m_entries.end()) continue;   // already forgotten
            const InjectEntry& e = it->second;
            if (e.expiry_height != 0 && height > e.expiry_height) {
                m_total_bytes -= e.byte_size;
                m_entries.erase(it);
                dropped.push_back(id);
            } else {
                keep.push_back(id);
            }
        }
        m_order.swap(keep);
        return dropped;
    }

    void clear() {
        m_entries.clear();
        m_order.clear();
        m_total_bytes = 0;
        m_released.clear();
        m_released_order.clear();
    }

private:
    void erase_order(const uint256& txid) {
        auto it = std::find(m_order.begin(), m_order.end(), txid);
        if (it != m_order.end()) m_order.erase(it);
    }
    void erase_released_order(const uint256& txid) {
        auto it = std::find(m_released_order.begin(), m_released_order.end(), txid);
        if (it != m_released_order.end()) m_released_order.erase(it);
    }

    std::map<uint256, InjectEntry>   m_entries;
    std::deque<uint256>              m_order;   // FIFO for compaction / reap
    size_t                           m_total_bytes{0};
    // The released ledger (release / retrack / prune_released). Not counted
    // by size() / total_bytes() / would_admit().
    std::map<uint256, ReleasedEntry> m_released;
    std::deque<uint256>              m_released_order;   // FIFO, oldest first
};

} // namespace coin
} // namespace dash
