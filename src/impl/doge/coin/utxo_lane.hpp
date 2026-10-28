// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded DOGE: the UTXO feed of the DOGE full-block and tip-change
/// handlers in main_ltc.cpp, as one object the KAT can drive
/// (src/impl/ltc/test/doge_utxo_lane_test.cpp).
///
/// Moved out of main_ltc.cpp unchanged:
///   - the cold-start bootstrap pipeline (once, the first block above `keep`);
///   - otherwise a block is connected when its height is above the set's best;
///   - a tip change to a height at or below the old one is a reorg: the old
///     branch is disconnected down to the fork by its undo records.
///
/// Thread: one thread (the io_context the handlers run on), except stats(),
/// which is atomic and read from the HTTP thread.

#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/coin/transaction.hpp>

#include <core/coin/block_bootstrapper.hpp>
#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <utility>

namespace doge {
namespace coin {

/// How a block is asked for.
enum class UtxoAsk {
    Broadcast,  // every peer (the cold-start window, a stalled height)
    Targeted,   // one peer, round robin (reorg / rebuild / recovery fills)
    FromPeer,   // the peer that delivered the block being handled (it has its
                // parents), else Targeted
};

/// What the lane needs from its surroundings. main_ltc.cpp wires it to the
/// DOGE HeaderChain, CoinBroadcaster and Mempool; the KAT to maps.
struct UtxoLaneHost {
    using BlockType = ltc::coin::BlockType;
    using Fill = core::coin::BlockBootstrapState<BlockType>;

    /// The header chain's tip height.
    std::function<uint32_t()> chain_height;
    /// The best chain's block hash at height h (null: no block there).
    std::function<uint256(uint32_t)> chain_hash_at;
    /// A known header's parent (nullopt: the header is unknown).
    std::function<std::optional<uint256>(const uint256&)> prev_of;
    /// Fetch the best chain's block at height h.
    std::function<void(uint32_t, UtxoAsk)> request;
    /// A block was connected to the set. drained: by the ordered pipeline
    /// (the handler's own per-block passes did not run for it).
    std::function<void(const BlockType&, const uint256&, uint32_t, bool drained)> connected;
    /// The set was wiped for a rebuild.
    std::function<void()> wiped;
    /// The ordered pipeline started (arm its stall timer) / stopped.
    std::function<void(Fill&)> fill_started;
    std::function<void(Fill&)> fill_stopped;
};

/// Counters for /local_stats ("doge_utxo"). Atomic: read from the HTTP thread.
struct UtxoLaneStats {
    std::atomic<uint64_t> connected{0};      // blocks connected to the set
    std::atomic<uint64_t> gaps{0};           // a block ahead of the set armed a fill
    std::atomic<uint64_t> reorgs{0};         // tip changes taken as reorgs
    std::atomic<uint64_t> refused{0};        // connect-point refusals
    std::atomic<uint64_t> heals{0};          // walks that disconnected blocks
    std::atomic<uint64_t> disconnected{0};   // blocks those walks disconnected
    std::atomic<uint64_t> rebuilds{0};       // wipes + rebuilds
    std::atomic<uint64_t> heal_failures{0};  // the set could not be brought back (yet)

    nlohmann::json to_json() const
    {
        auto v = [](const std::atomic<uint64_t>& a) { return a.load(std::memory_order_relaxed); };
        return {
            {"connected", v(connected)},       {"gaps", v(gaps)},
            {"reorgs", v(reorgs)},             {"refused", v(refused)},
            {"heals", v(heals)},               {"disconnected", v(disconnected)},
            {"rebuilds", v(rebuilds)},         {"heal_failures", v(heal_failures)},
        };
    }
};

class UtxoLane {
public:
    using BlockType = ltc::coin::BlockType;
    using Fill = UtxoLaneHost::Fill;

    /// What on_block did with the block.
    enum class Fed {
        Pipeline,   // the bootstrap pipeline took it (buffered, maybe drained)
        Connected,  // connected now
        Refused,    // (not produced here)
        Skipped,    // at or below the set's best
    };
    struct FeedResult {
        Fed      fed{Fed::Skipped};
        bool     on_best_chain{false};
        uint32_t connected{0};  // blocks connected by this call
    };

    UtxoLane(core::coin::UTXOViewCache& utxo, core::coin::UTXOViewDB& db, UtxoLaneHost host,
             uint32_t keep = core::coin::DOGE_MIN_BLOCKS_TO_KEEP)
        : m_utxo(utxo), m_db(db), m_host(std::move(host)), m_keep(keep)
    {
    }

    UtxoLane(const UtxoLane&) = delete;
    UtxoLane& operator=(const UtxoLane&) = delete;

    /// The full-block handler: block `hash` at `height` (the header chain's
    /// height for it; 0 = unknown).
    FeedResult on_block(const BlockType& block, const uint256& hash, uint32_t height)
    {
        FeedResult r;
        const uint256 at = height ? m_host.chain_hash_at(height) : uint256();
        r.on_best_chain = !at.IsNull() && at == hash;

        // 1. Bootstrap trigger
        if (!m_bootstrap_done && !m_fill.active && height > m_keep) {
            m_bootstrap_done = true;
            const uint32_t best = m_utxo.get_best_height();
            const uint32_t start = (best > 0 && best >= height - m_keep) ? best + 1 : height - m_keep;
            if (start < height) {
                m_fill.active = true;
                m_fill.next_height = start;
                m_fill.end_height = height;
                m_fill.next_request = start;
                m_fill.total = height - start + 1;
                m_fill.buffer[height] = {block, hash};
                m_fill.last_drain_time = std::chrono::steady_clock::now();
                int requested = 0;
                while (m_fill.next_request <= m_fill.end_height
                       && (m_fill.next_request - m_fill.next_height) < m_fill.WINDOW_SIZE) {
                    if (!m_fill.buffer.count(m_fill.next_request)) {
                        m_host.request(m_fill.next_request, UtxoAsk::Broadcast);
                        ++requested;
                    }
                    ++m_fill.next_request;
                }
                LOG_INFO << "[EMB-DOGE] Bootstrap pipeline: " << m_fill.total << " blocks [" << start
                         << ".." << height << "] window=" << m_fill.WINDOW_SIZE
                         << " requests=" << requested;
                if (m_host.fill_started)
                    m_host.fill_started(m_fill);
                r.fed = Fed::Pipeline;
                return r;
            }
            LOG_INFO << "[EMB-DOGE] UTXO warm restart: best=" << best << " — no bootstrap needed";
        }

        // 2. Bootstrap active: buffer → drain → refill
        if (m_fill.active) {
            if (height >= m_fill.next_height && height <= m_fill.end_height) {
                m_fill.buffer.try_emplace(height, std::make_pair(block, hash));
            } else if (height > m_fill.end_height) {
                m_fill.end_height = height;
                m_fill.total = m_fill.processed + (m_fill.end_height - m_fill.next_height + 1);
                m_fill.buffer.try_emplace(height, std::make_pair(block, hash));
            }

            auto now = std::chrono::steady_clock::now();
            auto stall = std::chrono::duration_cast<std::chrono::seconds>(now - m_fill.last_drain_time).count();
            if (stall >= m_fill.STALL_TIMEOUT_SEC) {
                LOG_WARNING << "[EMB-DOGE] Bootstrap stall h=" << m_fill.next_height << " (" << stall
                            << "s) — broadcast fallback";
                m_host.request(m_fill.next_height, UtxoAsk::Broadcast);
                m_fill.last_drain_time = now;
            }

            // Drain consecutive blocks
            while (m_fill.buffer.count(m_fill.next_height)) {
                auto node = m_fill.buffer.extract(m_fill.next_height);
                auto& [b, bh] = node.mapped();
                const uint32_t h = m_fill.next_height;
                connect(b, bh, h, true);
                ++r.connected;
                ++m_fill.next_height;
                ++m_fill.processed;
                m_fill.last_drain_time = std::chrono::steady_clock::now();
            }

            static int dbs_log = 0;
            if (++dbs_log % 50 == 0 || m_fill.next_height > m_fill.end_height) {
                LOG_INFO << "[EMB-DOGE] Bootstrap: " << m_fill.processed << "/" << m_fill.total
                         << " buf=" << m_fill.buffer.size();
            }

            while (m_fill.next_request <= m_fill.end_height
                   && (m_fill.next_request - m_fill.next_height) < m_fill.WINDOW_SIZE) {
                if (!m_fill.buffer.count(m_fill.next_request))
                    m_host.request(m_fill.next_request, UtxoAsk::Broadcast);
                ++m_fill.next_request;
            }

            if (m_fill.next_height > m_fill.end_height) {
                m_fill.active = false;
                if (m_host.fill_stopped)
                    m_host.fill_stopped(m_fill);
                LOG_INFO << "[EMB-DOGE] Bootstrap complete: " << m_fill.processed << " blocks";
            }
            r.fed = Fed::Pipeline;
            return r;
        }

        // 3. Normal processing
        if (height > m_utxo.get_best_height()) {
            connect(block, hash, height, false);
            r.connected = 1;
            r.fed = Fed::Connected;
            return r;
        }
        r.fed = Fed::Skipped;
        return r;
    }

    /// The tip-change handler: a new tip at or below the old height is a
    /// reorg; the old fork's blocks are disconnected by their undo records.
    /// Returns whether it was a reorg.
    bool on_tip_changed(const uint256& old_tip, uint32_t old_height, const uint256& new_tip,
                        uint32_t new_height)
    {
        const bool is_reorg = (new_height <= old_height);
        LOG_WARNING << "[EMB-DOGE] Chain tip changed: " << old_tip.GetHex().substr(0, 16) << " (h="
                    << old_height << ") → " << new_tip.GetHex().substr(0, 16) << " (h=" << new_height
                    << ")" << (is_reorg ? " [REORG]" : "");

        // Disconnect old fork UTXO during reorg
        if (is_reorg) {
            m_stats.reorgs.fetch_add(1, std::memory_order_relaxed);
            std::set<uint256> new_anc;
            {
                uint256 c = new_tip;
                while (!c.IsNull()) {
                    new_anc.insert(c);
                    auto p = m_host.prev_of(c);
                    if (!p)
                        break;
                    c = *p;
                }
            }
            uint256 fork_h;
            uint32_t fork_ht = 0;
            {
                uint256 c = old_tip;
                uint32_t ch = old_height;
                while (!c.IsNull()) {
                    if (new_anc.count(c)) {
                        fork_h = c;
                        fork_ht = ch;
                        break;
                    }
                    auto p = m_host.prev_of(c);
                    if (!p)
                        break;
                    c = *p;
                    --ch;
                }
            }
            if (!fork_h.IsNull() && fork_ht < old_height) {
                int disc = 0;
                for (uint32_t h = old_height; h > fork_ht; --h) {
                    core::coin::BlockUndo undo;
                    if (m_db.get_block_undo(h, undo)) {
                        // false: a legacy (pre-#2059) record; only the
                        // block's outputs went, its spent coins stay
                        // missing (no rebuild path on this lane, #2070).
                        if (!m_utxo.disconnect_from_undo(undo))
                            LOG_ERROR << "[EMB-DOGE] UTXO reorg: legacy undo record (pre-#2059) at h="
                                      << h << ": spent coins not restored";
                        m_db.remove_block_undo(h);
                        ++disc;
                    }
                }
                m_utxo.flush(fork_h, fork_ht);
                LOG_WARNING << "[EMB-DOGE] UTXO reorg: disconnected " << disc << " blocks";
            }
        }
        return is_reorg;
    }

    /// Startup check: none on this lane.
    void startup() {}

    Fill& fill() { return m_fill; }
    const Fill& fill() const { return m_fill; }
    const UtxoLaneStats& stats() const { return m_stats; }

private:
    static uint256 txid_of(const ltc::coin::MutableTransaction& tx) { return ltc::coin::compute_txid(tx); }

    void connect(const BlockType& b, const uint256& bh, uint32_t h, bool drained)
    {
        auto undo = m_utxo.connect_block(b, h, &UtxoLane::txid_of, bh);
        m_db.put_block_undo(h, undo);
        m_utxo.flush(bh, h);
        m_utxo.prune_undo(h, m_keep);
        m_stats.connected.fetch_add(1, std::memory_order_relaxed);
        if (!drained)
            LOG_INFO << "[EMB-DOGE] UTXO: block " << h << " hash=" << bh.GetHex().substr(0, 16)
                     << " txs=" << b.m_txs.size() << " cache=" << m_utxo.cache_size();
        if (m_host.connected)
            m_host.connected(b, bh, h, drained);
    }

    core::coin::UTXOViewCache& m_utxo;
    core::coin::UTXOViewDB&    m_db;
    UtxoLaneHost               m_host;
    const uint32_t             m_keep;
    Fill                       m_fill;
    bool                       m_bootstrap_done{false};
    UtxoLaneStats              m_stats;
};

} // namespace coin
} // namespace doge
