// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded DOGE: the full UTXO set's state shared by main_ltc's DOGE
/// handlers (the io_context, the header pool and the full set's own pool),
/// and the rules they apply:
///   - which bodies the full lane asked for (hash -> height). A body below the
///     header checkpoint has no header, so this record is the only thing that
///     places it; a deep body (not the tip's) goes to the full lane only. The
///     record is kept for every later copy of the body (a stalled height is
///     asked again, and every peer asked answers): a copy that lost its
///     height would reach the accrual path as height 0;
///   - when the node starts with the full set pricing the templates;
///   - when the full lane can run (the hash schedule, or a set past it);
///   - the swap of the pool's view to the full set, on every completion.
/// Thread safety: the atomics and the request map (mutex) are safe from any
/// thread; adopt() runs on the full set's thread.

#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/uint256.hpp>
#include <impl/ltc/coin/mempool.hpp>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace doge {
namespace coin {

struct UtxoFullState {
    /// The pool prices against the full set (it reached the header tip);
    /// the accrual lane is off the block feed.
    std::atomic<bool> live{false};
    /// The full lane can place every height it asks for: the hash schedule
    /// below the header checkpoint is proven, not needed (a header chain
    /// from genesis), or the set's best is already past the checkpoint.
    std::atomic<bool> schedule_ready{false};
    /// The DB the explorer reads DOGE blocks from (the lane writing them).
    std::atomic<core::coin::UTXOViewDB*> explorer_db{nullptr};
    /// How many times the pool was swapped to the full set (adopt()).
    std::atomic<uint64_t> adoptions{0};
    /// Called once when the hash schedule becomes ready during the run (set
    /// at wiring, before any callback fires): the full lane starts then.
    std::function<void()> on_schedule_ready;

    /// A request of the full lane: the best chain's block `hash` at `height`.
    void note_request(const uint256& hash, uint32_t height)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_requested[hash] = height;
        if (m_requested.size() > MAX_REQUESTED) {
            // Drop the lowest half: heights long connected.
            std::vector<std::pair<uint32_t, uint256>> by_height;
            by_height.reserve(m_requested.size());
            for (const auto& [h, ht] : m_requested)
                by_height.emplace_back(ht, h);
            std::sort(by_height.begin(), by_height.end());
            for (size_t i = 0; i < by_height.size() / 2; ++i)
                m_requested.erase(by_height[i].second);
        }
    }

    /// The height the full lane asked `hash` for (kept for every copy).
    std::optional<uint32_t> requested_height(const uint256& hash) const
    {
        std::lock_guard<std::mutex> lock(m_mu);
        auto it = m_requested.find(hash);
        if (it == m_requested.end())
            return std::nullopt;
        return it->second;
    }

    /// Where a body goes. `header_height`: the header chain's height for it
    /// (0 = unknown); `chain_height`: the header chain's tip.
    struct Placement {
        uint32_t height{0};     // 0 = cannot be placed
        bool     full_only{false};  // asked by the full lane and deeper than the accrual
                                    // lane's interest: no accrual pass
        uint256  hash;          // the body's
        bool     tip{false};    // the header chain's tip itself
    };
    /// `tip_hash`: the header chain's tip (null = unknown).
    Placement place(const uint256& hash, uint32_t header_height, uint32_t chain_height,
                    const uint256& tip_hash = uint256(),
                    uint32_t keep = core::coin::DOGE_MIN_BLOCKS_TO_KEEP) const
    {
        Placement p;
        p.hash = hash;
        p.tip = !tip_hash.IsNull() && hash == tip_hash;
        p.height = header_height;
        if (const auto asked = requested_height(hash)) {
            if (p.height == 0)
                p.height = *asked;
            // The accrual lane wants the last `keep` blocks too (its
            // bootstrap, its gap fills): a body both lanes asked for serves
            // both. Only a deeper one is the full lane's alone.
            p.full_only = uint64_t(p.height) + keep < chain_height;
        }
        return p;
    }

    /// The queue to the full set's thread (S-A, VERIFY3 S4), bounded for
    /// every body a peer can send:
    ///   - a body that cannot be placed is not queued while the full set is
    ///     not live (nothing can use it);
    ///   - a body whose hash is already queued is not queued again (a peer
    ///     streaming copies costs one slot);
    ///   - while QUEUE_BYTES_MAX is queued, only the header chain's tip
    ///     itself passes (a requested body that is dropped is asked again
    ///     after the request timeout).
    /// true = post it, and call dequeued(hash, bytes) when the full set's
    /// thread takes it.
    static constexpr uint64_t QUEUE_BYTES_MAX = 256u * 1024 * 1024;
    std::atomic<uint64_t> queued_bytes{0};
    std::atomic<uint64_t> queue_dropped{0};

    bool enqueue(const Placement& p, uint64_t bytes)
    {
        std::lock_guard<std::mutex> lock(m_queue_mu);
        const bool drop = (p.height == 0 && !live.load()) || m_queued.count(p.hash)
                       || (!p.tip && m_queue_bytes + bytes > QUEUE_BYTES_MAX);
        if (drop) {
            queue_dropped.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        m_queued.insert(p.hash);
        m_queue_bytes += bytes;
        queued_bytes.store(m_queue_bytes);
        return true;
    }
    void dequeued(const uint256& hash, uint64_t bytes)
    {
        std::lock_guard<std::mutex> lock(m_queue_mu);
        m_queued.erase(hash);
        m_queue_bytes = m_queue_bytes > bytes ? m_queue_bytes - bytes : 0;
        queued_bytes.store(m_queue_bytes);
    }

    /// Start with the full set pricing the templates: built from genesis,
    /// synced once, and at most `keep` blocks behind the header chain (it
    /// catches up in minutes). Further behind (a long downtime, a rebuild
    /// interrupted by a restart) the accrual set serves while the full set
    /// catches up, as in the first transition.
    static bool start_live(const core::coin::SyncState& s, uint32_t best_height, uint32_t header_height,
                           uint32_t keep = core::coin::DOGE_MIN_BLOCKS_TO_KEEP)
    {
        return s.tracked() && s.anchor_height == 0 && s.synced && best_height + keep >= header_height;
    }

    /// The full lane can place every height it will ask for.
    static bool schedule_ready_for(bool schedule_complete, uint32_t header_root, uint32_t best_height)
    {
        return header_root == 0 || schedule_complete || best_height >= header_root;
    }

    /// The pool prices against the full set from now on: every tx re-priced
    /// (one with an input the set does not hold becomes an orphan, an
    /// invalid one leaves), the explorer reads the full set's blocks. Runs on
    /// every completion: after a rebuild the pool emptied into the orphan
    /// set while the set was incomplete, and is priced again here.
    struct Adoption {
        int    requarantined{0};
        int    priced{0};
        int    evicted{0};
        size_t orphans{0};
        bool   first{false};  // the first swap of this run (the accrual lane leaves the feed)
    };
    Adoption adopt(ltc::coin::Mempool& pool, core::coin::UTXOViewCache* full, core::coin::UTXOViewDB* full_db)
    {
        Adoption a;
        pool.set_utxo(full);
        a.requarantined = pool.requarantine_all();
        a.priced = pool.recompute_unknown_fees(full);
        a.evicted = pool.revalidate_inputs(full);
        a.orphans = pool.orphan_count();
        explorer_db.store(full_db);
        a.first = !live.exchange(true);
        adoptions.fetch_add(1, std::memory_order_relaxed);
        return a;
    }

private:
    static constexpr size_t MAX_REQUESTED = 65536;
    mutable std::mutex m_mu;
    std::mutex         m_queue_mu;
    std::set<uint256>  m_queued;       // hashes posted to the full set's thread, not yet taken
    uint64_t           m_queue_bytes{0};
    std::map<uint256, uint32_t> m_requested;
};

} // namespace coin
} // namespace doge
