// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded DOGE: the UTXO set follows the header chain's best chain, one
/// block at a time, in height order (#2070).
///
/// The DOGE full-block and tip-change handlers in main_ltc.cpp feed this
/// object; the KAT (src/impl/ltc/test/doge_utxo_lane_test.cpp) drives the
/// same object. The rules are the LTC lane's (impl/ltc/coin/utxo_order.hpp
/// and main_ltc's EMB-LTC handlers, #2058 / #2077), built from the same
/// helpers:
///   - a block is connected only as the set's best + 1, when it is the best
///     chain's block at its height and its parent is the set's best block
///     (utxo_connect_check);
///   - a block further ahead arms the ordered pipeline: it is buffered, the
///     missing heights are fetched, blocks drain in height order;
///   - a tip change whose new tip does not descend from the old one is a
///     reorg, whatever the heights (tip_change_is_reorg: the header chain
///     picks the tip by chain work, so a reorg may end higher than the old
///     tip). A reorg, a connect-point parent mismatch and the startup check
///     walk the set back by its undo records until its best block is on the
///     best chain (at most `keep` blocks; rewind_to_best_chain), then the
///     best chain is connected from there in order;
///   - when the walk can never get there (undo record missing, legacy, of
///     another block, deeper than `keep`, the set's block unknown) the set is
///     wiped and the best chain's last `keep` blocks are connected into the
///     empty set, as a cold start does.
/// Reference: dogecoind v1.14.9 src/validation.cpp ActivateBestChainStep
/// (:2437-2466): the fork point by ancestry (FindFork), disconnect down to
/// it, then connect every block of the new branch in order; MIN_BLOCKS_TO_KEEP
/// = 1440 (src/validation.h:212).
///
/// Thread: one thread (the io_context the handlers run on), except stats(),
/// which is atomic and read from the HTTP thread.

#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/ltc/coin/utxo_order.hpp>

#include <core/coin/block_bootstrapper.hpp>
#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

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
    std::atomic<uint64_t> reorgs{0};         // tip changes not descending from the old tip
    std::atomic<uint64_t> refused{0};        // connect-point refusals (utxo_connect_check)
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
        Pipeline,   // the ordered pipeline took it (buffered, maybe drained)
        Connected,  // connected now, as the set's next block
        Refused,    // the set's next height, but the connect-point check refused it
        Skipped,    // old, a copy, or not the best chain's block
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
        using namespace ltc::coin;
        FeedResult r;
        const uint256 at = height ? m_host.chain_hash_at(height) : uint256();
        r.on_best_chain = !at.IsNull() && at == hash;

        // 1. Cold start: the first block above `keep` with the set empty or
        //    too far behind fetches the last `keep` blocks in order (a set too
        //    far behind starts its partial view at height - keep, the one
        //    deliberate jump: that first block passes the next-height and
        //    parent checks).
        if (!m_bootstrap_done && !m_fill.active && height > m_keep) {
            m_bootstrap_done = true;
            const uint32_t best = m_utxo.get_best_height();
            const uint32_t start = (best > 0 && best >= height - m_keep) ? best + 1 : height - m_keep;
            if (start < height) {
                ordered_arm(m_fill, start, height);
                m_fill.phase = "Bootstrap";
                m_jump_from = (best > 0 && start > best + 1) ? start : 0;
                if (r.on_best_chain)
                    ordered_buffer(m_fill, height, block, hash);
                const uint32_t asked = refill(UtxoAsk::Broadcast);
                LOG_INFO << "[EMB-DOGE] Bootstrap pipeline: " << m_fill.total << " blocks [" << start
                         << ".." << height << "] window=" << m_fill.WINDOW_SIZE
                         << " requests=" << asked;
                started();
                r.fed = Fed::Pipeline;
                return r;
            }
            LOG_INFO << "[EMB-DOGE] UTXO warm restart: best=" << best << " — no bootstrap needed";
        }

        // 2. A fill is running: buffer the best chain's block, drain in order
        //    (each block through the connect-point check), recover from a
        //    refusal, keep the window full.
        if (m_fill.active) {
            if (r.on_best_chain)
                ordered_buffer(m_fill, height, block, hash);
            const auto now = std::chrono::steady_clock::now();
            const auto stall =
                std::chrono::duration_cast<std::chrono::seconds>(now - m_fill.last_drain_time).count();
            if (stall >= m_fill.STALL_TIMEOUT_SEC) {
                LOG_WARNING << "[EMB-DOGE] " << m_fill.phase << " stall h=" << m_fill.next_height
                            << " (" << stall << "s) — broadcast fallback";
                m_host.request(m_fill.next_height, UtxoAsk::Broadcast);
                m_fill.last_drain_time = now;
            }
            r.connected = drain();
            if (m_fill.active)
                refill(m_fill.phase == "Bootstrap" ? UtxoAsk::Broadcast : UtxoAsk::Targeted);
            if (m_fill.active && ordered_done(m_fill)) {
                m_fill.active = false;
                stopped();
                LOG_INFO << "[EMB-DOGE] " << m_fill.phase << " complete: " << m_fill.processed
                         << " blocks, UTXO at h=" << m_utxo.get_best_height();
            }
            r.fed = Fed::Pipeline;
            return r;
        }

        // 3. Normal: strictly in order. A block further ahead (its parent
        //    still in flight, or never announced to us) is buffered and the
        //    missing heights are fetched; it is never connected over them.
        const uint32_t best = m_utxo.get_best_height();
        const auto act = r.on_best_chain ? utxo_connect_action(best, height) : UtxoConnect::Skip;
        if (act == UtxoConnect::Gap) {
            m_stats.gaps.fetch_add(1, std::memory_order_relaxed);
            LOG_WARNING << "[EMB-DOGE] UTXO gap: block h=" << height << " arrived with the UTXO set at h="
                        << best << " — buffering it and fetching " << best + 1 << ".." << height - 1
                        << " in order";
            ordered_arm(m_fill, best + 1, height);
            m_fill.phase = "UTXO gap fill";
            m_jump_from = 0;
            ordered_buffer(m_fill, height, block, hash);
            refill(UtxoAsk::FromPeer);
            started();
            r.fed = Fed::Pipeline;
            return r;
        }
        if (act != UtxoConnect::Connect) {
            r.fed = Fed::Skipped;
            return r;
        }
        const ConnectCheck c = check(block, hash, height);
        if (c != ConnectCheck::Ok) {
            // NotBestChain here is the benign race between the best-chain
            // look-up and the check (the index moved).
            m_stats.refused.fetch_add(1, std::memory_order_relaxed);
            LOG_WARNING << "[EMB-DOGE] Block h=" << height << " " << hash.GetHex().substr(0, 16)
                        << "... not connected to the UTXO set (" << connect_check_name(c)
                        << "), UTXO at h=" << best << " "
                        << m_utxo.get_best_block().GetHex().substr(0, 16) << "...";
            // Keep this block for the refill: the drain uses it without
            // waiting for the heal's own request.
            if (c == ConnectCheck::ParentMismatch && heal(Heal::ParentMismatch, m_host.chain_height())
                && m_fill.active)
                ordered_buffer(m_fill, height, block, hash);
            r.fed = Fed::Refused;
            return r;
        }
        connect(block, hash, height, false);
        r.connected = 1;
        r.fed = Fed::Connected;
        return r;
    }

    /// The tip-change handler. A reorg is any switch to a tip that does not
    /// descend from the old one: a sibling, a shorter heavier branch, and a
    /// heavier branch that ends higher than the old tip. The ancestor is found
    /// by walking back from THIS new tip (the live height index may already
    /// show a later tip). On a reorg the set is walked back to the best chain
    /// and the new branch is connected from there in order. Returns whether
    /// it was a reorg.
    bool on_tip_changed(const uint256& old_tip, uint32_t old_height, const uint256& new_tip,
                        uint32_t new_height)
    {
        const bool is_reorg = ltc::coin::tip_change_is_reorg(
            old_tip, old_height, new_height, [&](uint32_t h) {
                if (h > new_height)
                    return uint256();
                uint256 cur = new_tip;
                for (uint32_t at = new_height; at > h; --at) {
                    const auto p = m_host.prev_of(cur);
                    if (!p)
                        return uint256();
                    cur = *p;
                }
                return cur;
            });
        LOG_WARNING << "[EMB-DOGE] Chain tip changed: " << old_tip.GetHex().substr(0, 16) << " (h="
                    << old_height << ") → " << new_tip.GetHex().substr(0, 16) << " (h=" << new_height
                    << ")" << (is_reorg ? " [REORG]" : "");
        if (is_reorg) {
            m_stats.reorgs.fetch_add(1, std::memory_order_relaxed);
            heal(Heal::Reorg, new_height);
        }
        return is_reorg;
    }

    /// Once at startup: a reorg whose tip was persisted but whose UTXO
    /// disconnect never ran (a crash in between) fires no tip change.
    void startup()
    {
        if (m_host.chain_height() > 0)
            heal(Heal::Startup, m_host.chain_height());
    }

    Fill& fill() { return m_fill; }
    const Fill& fill() const { return m_fill; }
    const UtxoLaneStats& stats() const { return m_stats; }

private:
    enum class Heal { Startup, Reorg, ParentMismatch };

    static uint256 txid_of(const ltc::coin::MutableTransaction& tx) { return ltc::coin::compute_txid(tx); }

    void started()
    {
        if (m_host.fill_started)
            m_host.fill_started(m_fill);
    }
    void stopped()
    {
        if (m_host.fill_stopped)
            m_host.fill_stopped(m_fill);
    }

    uint32_t refill(UtxoAsk how)
    {
        return ltc::coin::ordered_refill(m_fill, [&](uint32_t h) { m_host.request(h, how); });
    }

    /// The check at every connect point; the cold start's deliberate jump
    /// passes the next-height and parent checks once.
    ltc::coin::ConnectCheck check(const BlockType& b, const uint256& bh, uint32_t h)
    {
        using ltc::coin::ConnectCheck;
        auto c = ltc::coin::utxo_connect_check(m_utxo.get_best_height(), m_utxo.get_best_block(), h, bh,
                                               b.m_previous_block, m_host.chain_hash_at(h));
        if (m_jump_from != 0 && h == m_jump_from
            && (c == ConnectCheck::NotNext || c == ConnectCheck::ParentMismatch))
            c = ConnectCheck::Ok;
        return c;
    }

    void connect(const BlockType& b, const uint256& bh, uint32_t h, bool drained)
    {
        if (h == m_jump_from)
            m_jump_from = 0;
        auto undo = m_utxo.connect_block(b, h, &UtxoLane::txid_of, bh);
        m_db.put_block_undo(h, undo);
        m_utxo.flush(bh, h);
        m_utxo.prune_undo(h, m_keep);
        m_stats.connected.fetch_add(1, std::memory_order_relaxed);
        LOG_INFO << "[EMB-DOGE] UTXO: block " << h << " hash=" << bh.GetHex().substr(0, 16)
                 << " txs=" << b.m_txs.size() << " cache=" << m_utxo.cache_size()
                 << (drained ? " (" + m_fill.phase + ")" : std::string());
        if (m_host.connected)
            m_host.connected(b, bh, h, drained);
    }

    /// Drain the buffer in order; on a refused block restart the fill at the
    /// set's real next height, or heal a set that is on another branch.
    uint32_t drain()
    {
        using ltc::coin::ConnectCheck;
        const auto drained = ltc::coin::ordered_drain(
            m_fill, [&](const BlockType& b, const uint256& bh, uint32_t h) { return check(b, bh, h); },
            [&](const BlockType& b, const uint256& bh, uint32_t h) { connect(b, bh, h, true); });
        if (drained.refused == ConnectCheck::Ok)
            return drained.connected;
        m_stats.refused.fetch_add(1, std::memory_order_relaxed);
        LOG_WARNING << "[EMB-DOGE] " << m_fill.phase << ": block h=" << drained.refused_height
                    << " not connected (" << ltc::coin::connect_check_name(drained.refused)
                    << "), UTXO at h=" << m_utxo.get_best_height();
        // Restart at the set's next height, or at the pipeline's own start
        // while the set is empty / before the cold start's deliberate jump.
        const bool from_pipeline = m_utxo.get_best_block().IsNull() || m_jump_from != 0;
        const uint32_t base = from_pipeline ? (m_fill.next_height > 0 ? m_fill.next_height - 1 : 0)
                                            : m_utxo.get_best_height();
        if (drained.refused == ConnectCheck::ParentMismatch) {
            // The set itself is on another branch: walk it back to the best
            // chain and refill from there.
            if (!heal(Heal::ParentMismatch, m_host.chain_height())) {
                m_fill.active = false;
                m_fill.buffer.clear();
                stopped();
                m_jump_from = 0;
            }
        } else if (ltc::coin::ordered_recover(m_fill, drained.refused, base, m_host.chain_height())) {
            refill(UtxoAsk::Targeted);
        } else {
            stopped();
            m_jump_from = 0;
            LOG_ERROR << "[EMB-DOGE] " << m_fill.phase << " stopped at h=" << m_utxo.get_best_height()
                      << " (" << ltc::coin::connect_check_name(drained.refused) << ")";
        }
        return drained.connected;
    }

    /// Bring the set back onto the best chain (main_ltc's EMB-LTC utxo_heal,
    /// same rules): walk its best back by its undo records, at most `keep`
    /// blocks, until its block is the best chain's at that height; flush;
    /// then connect the best chain in order from there to target_height.
    /// Undo records go only after the flush (a crash mid-walk leaves the DB at
    /// its old best with its undo intact). When the walk can never get there
    /// the set is wiped and rebuilt from the best chain (returns true). Returns
    /// false when it cannot be brought back now (a height the header chain
    /// cannot judge), or, for a parent mismatch, when the set's best is
    /// already on the best chain (refilling would hit the same mismatch).
    bool heal(Heal kind, uint32_t target_height)
    {
        using namespace ltc::coin;
        const char* reason =
            kind == Heal::Startup ? "startup" : kind == Heal::Reorg ? "reorg" : "parent mismatch";
        const uint32_t before = m_utxo.get_best_height();
        std::vector<uint32_t> undone;
        const auto rw = rewind_to_best_chain(
            m_keep, m_host.chain_height(), before, m_utxo.get_best_block(), m_host.chain_hash_at,
            m_host.prev_of, [&](uint32_t h, const uint256& hh) {
                const auto w = disconnect_with_undo(m_db, m_utxo, h, hh);
                if (w == RewindResult::Why::None)
                    undone.push_back(h);
                return w;
            });
        if (rw.disconnected > 0) {
            if (!m_utxo.flush(rw.hash, rw.height)) {
                m_stats.heal_failures.fetch_add(1, std::memory_order_relaxed);
                LOG_ERROR << "[EMB-DOGE] UTXO flush failed after disconnecting " << rw.disconnected
                          << " blocks (" << reason << "); undo data kept, UTXO DB still at h=" << before;
                return false;
            }
            for (uint32_t h : undone)
                m_db.remove_block_undo(h);
            m_stats.heals.fetch_add(1, std::memory_order_relaxed);
            m_stats.disconnected.fetch_add(rw.disconnected, std::memory_order_relaxed);
            LOG_WARNING << "[EMB-DOGE] UTXO rewound to the best chain (" << reason << "): disconnected "
                        << rw.disconnected << " blocks (h=" << before << "→" << rw.height
                        << ") best=" << rw.hash.GetHex().substr(0, 16);
        }
        if (rw.permanent()) {
            // The walk can never get further: wipe the set and connect the
            // best chain's last `keep` blocks into it, as a cold start does
            // (the mining gate closes until DOGE_MINING_GATE_DEPTH reconnect).
            const uint32_t tip = m_host.chain_height();
            const uint32_t from = utxo_rebuild_from(tip, m_keep);
            const uint32_t to = std::max(target_height, tip);
            LOG_ERROR << "[EMB-DOGE] UTXO set cannot be brought back to the best chain (" << reason
                      << ": " << rewind_why_name(rw.why) << " at h=" << rw.height
                      << "); re-anchoring: wiping the UTXO set and rebuilding " << from << ".." << to
                      << " from the best chain";
            if (!m_utxo.reanchor()) {
                m_stats.heal_failures.fetch_add(1, std::memory_order_relaxed);
                LOG_ERROR << "[EMB-DOGE] UTXO re-anchor failed (DB wipe); set left at h="
                          << m_utxo.get_best_height();
                return false;
            }
            m_stats.rebuilds.fetch_add(1, std::memory_order_relaxed);
            if (m_host.wiped)
                m_host.wiped();
            ordered_arm(m_fill, from, to);
            m_fill.phase = "UTXO rebuild";
            m_jump_from = from;
            refill(UtxoAsk::Targeted);
            started();
            return true;
        }
        if (!rw.ok) {
            m_stats.heal_failures.fetch_add(1, std::memory_order_relaxed);
            LOG_ERROR << "[EMB-DOGE] UTXO set cannot be brought back to the best chain (" << reason << ": "
                      << rewind_why_name(rw.why) << "): stuck at h=" << rw.height << " "
                      << rw.hash.GetHex().substr(0, 16) << "...";
            return false;
        }
        if (rw.disconnected == 0 && kind == Heal::ParentMismatch) {
            LOG_WARNING << "[EMB-DOGE] Parent mismatch at h=" << before + 1
                        << " but the UTXO set's best is on the best chain; not refilling";
            return false;
        }
        if (rw.disconnected == 0 && kind == Heal::Startup)
            return true;
        // Connect the best chain in order from the set's REAL best, whatever
        // the pipeline was doing (it may have drained past the fork and may
        // hold old-branch blocks). An empty set (cold start, nothing drained
        // yet) restarts at the pipeline's own start instead.
        const bool empty = m_utxo.get_best_block().IsNull() || (m_fill.active && m_jump_from != 0);
        const bool was_cold_start = m_fill.active && m_fill.phase == "Bootstrap";
        const uint32_t best_now =
            empty ? (m_fill.active && m_fill.next_height > 0 ? m_fill.next_height - 1 : 0)
                  : m_utxo.get_best_height();
        if ((!empty || m_fill.active) && ordered_rearm_after_reorg(m_fill, best_now, target_height)) {
            if (!was_cold_start) {
                m_fill.phase = "UTXO reorg fill";
                m_jump_from = 0;
            }
            LOG_WARNING << "[EMB-DOGE] UTXO reorg fill (" << reason << "): connecting " << best_now + 1
                        << ".." << target_height << " in order";
            refill(UtxoAsk::Targeted);
            started();
        }
        return true;
    }

    core::coin::UTXOViewCache& m_utxo;
    core::coin::UTXOViewDB&    m_db;
    UtxoLaneHost               m_host;
    const uint32_t             m_keep;
    Fill                       m_fill;
    bool                       m_bootstrap_done{false};
    uint32_t                   m_jump_from{0};  // the cold start's deliberate jump (0 = none)
    UtxoLaneStats              m_stats;
};

} // namespace coin
} // namespace doge
