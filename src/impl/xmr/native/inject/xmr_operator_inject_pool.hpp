// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/inject/xmr_operator_inject_pool.hpp
//
// OPERATOR TX-INJECTION for the daemonless (native) XMR line, MIRRORING the
// Dash inject subsystem (src/impl/dash/coin/tx_inject_pool.hpp). This is the
// bounded, opt-in INJECT LEDGER: a small, capped, per-node record of the
// transactions the operator asked this node to mine WITH PRIORITY
// (--native-inject, default OFF).
//
// It is NOT the template-inclusion mechanism. Inclusion happens in the C4
// selector (xmr_inject_select.hpp): an accepted inject is offered FIRST, ahead
// of every fee-paying transaction, bounded only by the block-size (weight) cap.
// This pool is the DoS-accounting + expiry + ordering ledger the design's §4.6
// guards need, exactly as the Dash TxInjectPool is:
//
//   * INJECT_POOL_MAX_ENTRIES  -- hard cap on how many injects are tracked;
//   * kMaxInjectTotalBytes      -- cumulative byte cap across all injects (the
//                                  stand-in for a block-fraction reservation:
//                                  the selector already yields the fee-sorted
//                                  remainder, so this bounds how much block
//                                  space injects can claim as a ledger cap);
//   * kMaxInjectTxBytes         -- per-tx size cap, set to the consensus tx-
//                                  weight limit (TxpoolConfig::max_tx_weight),
//                                  the honest per-tx ceiling for XMR;
//   * expiry_height             -- drop an inject a node no longer re-offers.
//
// PRIORITY ORDER lives here, not in a mempool fee delta as it does for Dash:
// XMR has no mapDeltas. ordered() returns the injects that are STILL in the C3
// selectable set, ordered by (priority-request flag desc, submit sequence asc).
// The selector consumes that order and takes them before any fee-paying tx.
//
// MEMBERSHIP BY ID AGAINST C3. This pool holds txids + metadata ONLY. The
// transaction BODY, the key-image-conflict authority, and the includability
// decision all live in the C3 RelayedTxPool -- ordered() intersects this
// ledger with the C3 selectable snapshot the caller passes in, so an inject the
// C3 pool has dropped (mined, conflicted, expired) silently stops being
// offered. There is no coinbase / subsidy / settlement write path anywhere in
// this file: it can only bound and order which consensus-valid body txs the
// selector prioritises (reward-neutral by construction, design §5).
//
// THREADING: internally mutex-guarded, in the shape of RelayedTxPool. The gate
// mutates it from the submit path; the selector reads ordered() from the serve
// path; the block-connect hook forgets mined ids from the pool thread.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "impl/xmr/native/contracts/types.hpp"           // Hash, node::TxBacklogEntry

namespace c2pool::xmr::native {

// Wire flags for an inject, mirroring the Dash design's bit assignment
// (bit0 zero-fee-intent, bit1 non-standard-intent, bit2 priority-request).
// Only bit2 changes ordering here; the others are carried for parity / future
// fan-out accounting.
struct InjectFlags {
    static constexpr std::uint32_t ZeroFeeIntent     = 1u << 0;
    static constexpr std::uint32_t NonStandardIntent = 1u << 1;
    static constexpr std::uint32_t PriorityRequest   = 1u << 2;
};

// One accepted inject's bookkeeping. Body lives in C3; this is metadata only.
struct OperatorInjectEntry {
    Hash          id{};
    std::uint32_t flags        = 0;
    std::uint64_t expiry_height = 0;   // 0 = never auto-expires (see gate: a
                                       // finite default is set at submit time)
    std::uint64_t blob_size    = 0;
    std::uint64_t weight       = 0;
    std::uint64_t fee          = 0;
    std::uint64_t submit_time  = 0;
    std::uint64_t seq          = 0;    // monotone submit order (FIFO tie-break)
};

class OperatorInjectPool {
public:
    // Hard cap on tracked injects (§4.6 INJECT_POOL_MAX_ENTRIES), Dash parity.
    static constexpr std::size_t INJECT_POOL_MAX_ENTRIES = 1024;
    // Cumulative byte ceiling across ALL tracked injects. 4 MiB: injects are
    // never the whole block, and one max-weight XMR tx is ~149 KB, so this
    // clears a generous operator batch while bounding the ledger.
    static constexpr std::uint64_t kMaxInjectTotalBytes = 4ull * 1024 * 1024;
    // Per-tx size cap == the consensus tx-weight limit (TxpoolConfig
    // ::max_tx_weight). A blob above it can never be a valid XMR tx, so refuse
    // it here charged-free, before the limiter is charged.
    static constexpr std::uint64_t kMaxInjectTxBytes = 149400;

    // Every admission refusal is NAMED (DEF3 discipline), Dash-parallel names.
    enum class Admit : std::uint8_t {
        Ok = 0,
        Duplicate,           // id already tracked
        PoolFull,            // INJECT_POOL_MAX_ENTRIES reached
        TotalBytesExceeded,  // would exceed kMaxInjectTotalBytes
        TooLarge,            // blob_size > kMaxInjectTxBytes
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

    // -----------------------------------------------------------------------
    // DAEMON-FIRST NAMED-REFUSAL (2026-09-19).
    //
    // The p2p-first arm is the SUPPORTED home for a 0-fee operator inject: it
    // submits a found block over levin and its own native chain index accepts
    // it, so a 0-fee inject placed first in the template is ALWAYS mined (the
    // proven path). The daemon-first arm instead submits the found block to
    // monerod, whose relay/fee rules reject a 0-fee (or otherwise un-relayable)
    // transaction -- monerod returns "Block not accepted" and the inject would
    // sit PINNED, re-offered into every template and failing every submit until
    // it expired. So under the daemon-first arm such an inject is refused BY
    // NAME at submit time, before it can pin, and the operator is pointed at the
    // p2p-first arm.
    //
    // PURE (no node/pool state): the same predicate the node refuses on and a
    // KAT pins. Returns "" to admit, or the named verdict otherwise.
    //   daemon_first_arm   -- the found block is submitted through monerod (arm
    //                         order is NOT p2p-first: DaemonFirst or Parallel).
    //   monerod_configured -- a monerod RPC endpoint is present to judge it.
    //   fee                -- decoded tx fee in piconero (0 == un-relayable
    //                         under monerod default relay-fee rules).
    static const char* daemon_first_refusal(bool daemon_first_arm,
                                            bool monerod_configured,
                                            std::uint64_t fee) {
        if (!daemon_first_arm || !monerod_configured) return "";  // p2p-first: always mined
        if (fee == 0) return "inject-daemon-first-0fee-unrelayable";
        return "";
    }

    bool   contains(const Hash& id) const {
        std::lock_guard<std::mutex> lk(mu_);
        return by_id_.count(key_(id)) != 0;
    }
    std::size_t   size()        const { std::lock_guard<std::mutex> lk(mu_); return by_id_.size(); }
    std::uint64_t total_bytes() const { std::lock_guard<std::mutex> lk(mu_); return total_bytes_; }
    bool          empty()       const { std::lock_guard<std::mutex> lk(mu_); return by_id_.empty(); }

    // Would-admit check WITHOUT mutating. Cheap gate the caller runs before the
    // more expensive C3 admission so a full/over-cap pool refuses cheaply.
    Admit would_admit(const Hash& id, std::uint64_t blob_size) const {
        std::lock_guard<std::mutex> lk(mu_);
        return would_admit_locked_(id, blob_size);
    }

    // Record an accepted inject. Returns the named verdict; on Ok the entry is
    // tracked and its bytes count toward the cumulative cap.
    Admit admit(const Hash& id, std::uint32_t flags, std::uint64_t expiry_height,
                std::uint64_t blob_size, std::uint64_t weight, std::uint64_t fee,
                std::uint64_t submit_time) {
        std::lock_guard<std::mutex> lk(mu_);
        Admit v = would_admit_locked_(id, blob_size);
        if (v != Admit::Ok) return v;
        OperatorInjectEntry e;
        e.id            = id;
        e.flags         = flags;
        e.expiry_height = expiry_height;
        e.blob_size     = blob_size;
        e.weight        = weight;
        e.fee           = fee;
        e.submit_time   = submit_time;
        e.seq           = next_seq_++;
        order_.push_back(key_(id));
        by_id_.emplace(key_(id), e);
        total_bytes_ += blob_size;
        return Admit::Ok;
    }

    // Forget one inject (confirmed, evicted, expired). Returns true if tracked.
    bool forget(const Hash& id) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = by_id_.find(key_(id));
        if (it == by_id_.end()) return false;
        total_bytes_ -= it->second.blob_size;
        by_id_.erase(it);
        return true;   // order_ compacts on next reap; stale keys are skipped
    }

    // Drop injects whose expiry_height has passed (height > expiry_height, for
    // entries with expiry_height != 0). Returns dropped ids so the caller can
    // unpin them in C3. Compacts the FIFO order deque.
    std::vector<Hash> reap_expired(std::uint64_t height) {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<Hash> dropped;
        std::deque<std::string> keep;
        for (const std::string& k : order_) {
            auto it = by_id_.find(k);
            if (it == by_id_.end()) continue;   // already forgotten
            const OperatorInjectEntry& e = it->second;
            if (e.expiry_height != 0 && height > e.expiry_height) {
                total_bytes_ -= e.blob_size;
                dropped.push_back(e.id);
                by_id_.erase(it);
            } else {
                keep.push_back(k);
            }
        }
        order_.swap(keep);
        return dropped;
    }

    // The ids currently tracked (for re-pinning the reserved C3 pin group).
    std::vector<Hash> live_ids() const {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<Hash> ids;
        ids.reserve(by_id_.size());
        for (const auto& [k, e] : by_id_) { (void)k; ids.push_back(e.id); }
        return ids;
    }

    // The inject-selection view. Given the C3 selectable snapshot (which carries
    // the real weight/fee/blob per tx), return the entries that are BOTH tracked
    // here AND still in that snapshot, ordered by (priority-request flag desc,
    // submit seq asc). The selector takes these first, ahead of any fee-paying
    // tx. An inject C3 no longer offers simply does not appear -- membership is
    // by id against C3, the body/includability authority.
    std::vector<node::TxBacklogEntry> ordered(
            const std::vector<node::TxBacklogEntry>& pool_set) const {
        std::lock_guard<std::mutex> lk(mu_);
        struct Ranked { node::TxBacklogEntry e; std::uint32_t flags; std::uint64_t seq; };
        std::vector<Ranked> picked;
        picked.reserve(by_id_.size());
        for (const node::TxBacklogEntry& t : pool_set) {
            auto it = by_id_.find(key_(t.id));
            if (it == by_id_.end()) continue;
            picked.push_back(Ranked{t, it->second.flags, it->second.seq});
        }
        std::stable_sort(picked.begin(), picked.end(), [](const Ranked& a, const Ranked& b) {
            const bool ap = (a.flags & InjectFlags::PriorityRequest) != 0;
            const bool bp = (b.flags & InjectFlags::PriorityRequest) != 0;
            if (ap != bp) return ap;         // priority-request first
            return a.seq < b.seq;            // then FIFO by submit order
        });
        std::vector<node::TxBacklogEntry> out;
        out.reserve(picked.size());
        for (auto& r : picked) out.push_back(r.e);
        return out;
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        by_id_.clear();
        order_.clear();
        total_bytes_ = 0;
    }

private:
    static std::string key_(const Hash& h) {
        return std::string(reinterpret_cast<const char*>(h.data()), h.size());
    }

    Admit would_admit_locked_(const Hash& id, std::uint64_t blob_size) const {
        if (blob_size > kMaxInjectTxBytes) return Admit::TooLarge;
        if (by_id_.count(key_(id)))        return Admit::Duplicate;
        if (by_id_.size() >= INJECT_POOL_MAX_ENTRIES) return Admit::PoolFull;
        if (total_bytes_ + blob_size > kMaxInjectTotalBytes)
            return Admit::TotalBytesExceeded;
        return Admit::Ok;
    }

    mutable std::mutex                                   mu_;
    std::unordered_map<std::string, OperatorInjectEntry> by_id_;
    std::deque<std::string>                              order_;
    std::uint64_t                                        total_bytes_ = 0;
    std::uint64_t                                        next_seq_    = 0;
};

} // namespace c2pool::xmr::native
