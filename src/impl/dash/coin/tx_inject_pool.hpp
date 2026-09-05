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
/// REWARD SAFETY: this structure holds txids + metadata ONLY. It has NO write
/// path to the coinbase, subsidy, PPLNS, donation, payee queue, or give_author —
/// it can only bound how many consensus-valid body txs the mempool prioritises.
///
/// THREADING: io-thread confined, same discipline as NodeCoinState's
/// m_pinned_local_txs. No internal lock; the owner serialises access.

#include <core/uint256.hpp>

#include <cstdint>
#include <ctime>
#include <deque>
#include <map>
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

    /// Every admission refusal is NAMED (DEF3 discipline).
    enum class Admit : uint8_t {
        Ok = 0,
        Duplicate,           // txid already tracked
        PoolFull,            // INJECT_POOL_MAX_ENTRIES reached
        TotalBytesExceeded,  // would exceed kMaxInjectTotalBytes
        TooLarge,            // byte_size > kMaxInjectTxBytes
    };
    static const char* admit_name(Admit a) {
        switch (a) {
            case Admit::Ok:                 return "ok";
            case Admit::Duplicate:          return "inject-pool-duplicate";
            case Admit::PoolFull:           return "inject-pool-full";
            case Admit::TotalBytesExceeded: return "inject-pool-total-bytes-exceeded";
            case Admit::TooLarge:           return "inject-pool-oversize";
        }
        return "inject-pool-unknown";
    }

    bool   contains(const uint256& txid) const { return m_entries.count(txid) != 0; }
    size_t size() const { return m_entries.size(); }
    size_t total_bytes() const { return m_total_bytes; }
    bool   empty() const { return m_entries.empty(); }

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
        return Admit::Ok;
    }

    /// Forget one inject (confirmed, evicted from mempool, or expired). No-op if
    /// untracked. Returns true if it was tracked.
    bool forget(const uint256& txid) {
        auto it = m_entries.find(txid);
        if (it == m_entries.end()) return false;
        m_total_bytes -= it->second.byte_size;
        m_entries.erase(it);
        // m_order keeps the txid until the next reap pops it (cheap FIFO; a
        // stale txid there is harmless — reap skips txids no longer in m_entries).
        return true;
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
    }

private:
    std::map<uint256, InjectEntry> m_entries;
    std::deque<uint256>            m_order;   // FIFO for compaction / reap
    size_t                         m_total_bytes{0};
};

} // namespace coin
} // namespace dash
