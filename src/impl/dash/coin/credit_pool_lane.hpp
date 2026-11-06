// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The credit-pool follower, run by the node (credit_pool_idx.hpp is the
/// ledger; this is what feeds it and asks it).
///
/// Dash Core keeps three things about the asset-unlock pool that the chain
/// does not commit to: the set of every mined unlock index, the unlocked
/// total of the last CreditPoolPeriodBlocks (576) blocks, and, from Dash Core
/// v24, the pool balance at the start of that window (UnlockLimitV24). The
/// follower rebuilds them from the v20 floor block by block and checks every
/// block's computed balance against its CbTx creditPoolBalance. This lane:
///
///   * SEED: fetches [cursor + 1, live floor - 1] over the coin P2P network,
///     the same way the EHF rescan does (bound bodies only: the header's X11
///     hash is the hash asked for and the merkle root commits the txs).
///       - WINDOW (default): from a block CreditPoolPeriodBlocks + 8 below the
///         live floor, armed with that block's own CbTx creditPoolBalance. The
///         balance, latelyUnlocked and the window-start balance (Dash Core v24
///         UnlockLimitV24) are then exact, from ~584 blocks. The unlock index
///         set is NOT complete, and Dash Core refuses a duplicate index
///         against every unlock since v20 (bad-assetunlock-duplicated-index),
///         so a window seed never admits an unlock: templates exclude them,
///         which loses only their fees.
///       - FULL (--embedded-credit-pool-seed): from the v20 floor (mainnet
///         ~580k blocks), persisted; the only seed that admits unlocks.
///   * TIP: takes the payee feeder's ordered, bound bodies once the cursor is
///     contiguous with them.
///   * REORG: keeps the follower's state after each of the last kJournal
///     blocks; a body on another branch rewinds to the fork and applies. A
///     fork deeper than that re-arms at the floor (a new seed).
///   * FAILURE: a follower that fails closed (balance cross-check, duplicate
///     index, unparseable payload) wiped itself; the lane re-arms after
///     kRearmBackoffMs and seeds again.
///   * COMPLETE: the follower is marked proven complete once its cursor meets
///     the header tip.
///   * ADMIT: the template's type-9 admission (try_admit_unlocks: version-2
///     gate, UnlockLimitV24, quorum signatures) runs only through admit().
///
/// Thread-safe: one mutex around the follower (the io thread feeds it, the
/// template build asks it).

#include <impl/dash/coin/credit_pool_idx.hpp>
#include <impl/dash/coin/credit_pool_idx_db.hpp>
#include <impl/dash/coin/ehf_tracker.hpp>   // ehf_rescan_body_binds

#include <core/log.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace dash {
namespace coin {

class CreditPoolLane
{
public:
    static constexpr uint32_t kWindow         = 64;       ///< bodies in flight at most
    static constexpr uint32_t kBatch          = 16;       ///< hashes per getdata
    static constexpr int64_t  kReaskMs        = 20'000;   ///< re-ask an unanswered body
    static constexpr size_t   kJournal        = 24;       ///< reorg depth the lane can rewind
    static constexpr int64_t  kRearmBackoffMs = 600'000;  ///< after a fail-closed

    /// Active-chain block hash at a height (header chain, or the backfill).
    using HashAtFn   = std::function<std::optional<uint256>(uint32_t)>;
    /// Header tip height.
    using TipFn      = std::function<std::optional<uint32_t>()>;
    /// Lowest height the live path still fetches itself (payee cursor + 1).
    using FloorFn    = std::function<std::optional<uint32_t>()>;
    /// One getdata for these hashes; false when no peer took it.
    using RequestFn  = std::function<bool(const std::vector<uint256>&)>;
    using BodyCheckFn = std::function<bool(const uint256& want_hash, const BlockType&)>;

    struct Seams
    {
        HashAtFn    hash_at;
        TipFn       tip;
        FloorFn     live_floor;
        RequestFn   request;
        BodyCheckFn check;   ///< empty => ehf_rescan_body_binds
    };

    enum class SeedMode : uint8_t { WINDOW, FULL };

    struct Status
    {
        SeedMode               mode{SeedMode::WINDOW};
        bool                   full_history{false};
        bool                   armed{false};
        bool                   proven_complete{false};
        bool                   seed_fetch{false};
        uint32_t               floor{0};
        uint32_t               height{0};
        int64_t                balance{0};
        int64_t                lately_unlocked{0};
        std::optional<int64_t> limit;           ///< for the next block
        std::optional<int64_t> window_start_balance;
        size_t                 index_ranges{0};
        size_t                 in_flight{0};
        uint64_t               applied{0};
        uint64_t               rejected_bodies{0};
        uint64_t               rewinds{0};
        uint64_t               failures{0};
        std::string            fail_cause;
    };

    CreditPoolLane(const CpIdxDeploySchedule& sched, int mn_rr_height, Seams seams, SeedMode mode)
        : m_follower(sched), m_seams(std::move(seams)), m_mode(mode)
    {
        if (!m_seams.check) m_seams.check = ehf_rescan_body_binds;
        m_follower.set_reward_fn([mn_rr_height](uint32_t h) {
            return compute_dash_platform_reward_post_v20_mn_rr(h, mn_rr_height);
        });
    }

    /// Attach the store (may be null) and resume from it. Arming at the floor
    /// happens in tick() once the floor block's hash is known.
    void start(CreditPoolIdxDb* db)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (db != nullptr && m_mode == SeedMode::FULL) {   // a window seed is memory only
            m_follower.attach_db(db);
            if (m_follower.try_restore()) journal_push_locked();
        }
    }

    /// Periodic drive: arm or re-arm, mark complete, drain and keep the seed
    /// window full. Returns the number of hashes requested.
    size_t tick(int64_t now_ms)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_now_ms = now_ms;
        if (!m_follower.armed()) {
            if (m_last_fail_ms != kNever && now_ms - m_last_fail_ms < kRearmBackoffMs) return 0;
            if (!arm_locked(now_ms)) return 0;
        }
        maybe_complete_locked();
        drain_locked();
        return refill_locked(now_ms);
    }

    /// The coin client's body filter: true when the seed asked for this body.
    bool on_body(const uint256& hash, const BlockType& block)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (m_pending_floor && m_pending_floor->hash == hash) {
            // The window seed's floor block: its own CbTx balance arms it.
            const auto pf = *m_pending_floor;
            vendor::CCbTx cb;
            if (!m_seams.check(pf.hash, block) || block.m_txs.empty()
                || !vendor::parse_cbtx(block.m_txs[0].extra_payload, cb)
                || cb.nVersion < vendor::CCbTx::VERSION_CLSIG_AND_BALANCE) {
                ++m_rejected;
                m_pending_floor->sent_ms = kReaskNow;
                return true;
            }
            m_pending_floor.reset();
            m_follower.arm_window(pf.height, pf.hash, cb.creditPoolBalance);
            m_journal.clear();
            journal_push_locked();
            refill_locked(m_now_ms);
            return true;
        }
        for (auto it = m_inflight.begin(); it != m_inflight.end(); ++it) {
            if (it->second.hash != hash) continue;
            if (!m_seams.check(it->second.hash, block)) {
                ++m_rejected;
                if (m_rejected <= 3 || (m_rejected % 100) == 0)
                    LOG_WARNING << "[CP-LANE] seed body for h=" << it->first << " "
                                << hash.GetHex().substr(0, 16)
                                << " does not bind to its header -- dropped, re-asking"
                                   " (rejected so far: " << m_rejected << ")";
                it->second.sent_ms = kReaskNow;
                return true;
            }
            m_arrived[it->first] = Arrived{it->second.hash, block};
            m_inflight.erase(it);
            drain_locked();
            // Event-driven refill: keep the window full between ticks.
            if (m_inflight.size() < kWindow / 2) refill_locked(m_now_ms);
            return true;
        }
        return false;
    }

    /// A bound, active-chain body from the payee feeder's ordered stream.
    void on_ordered_block(uint32_t height, const uint256& hash, const BlockType& block)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (!m_follower.armed()) return;
        const uint32_t cur = m_follower.height();
        if (height > cur + 1) return;                         // the seed closes the gap
        if (height == cur + 1 && block.m_previous_block == m_follower.block_hash()) {
            apply_locked(height, hash, block);
            return;
        }
        // Anything else is only interesting when OUR cursor has left the
        // active chain (a reorg): the ordered stream also re-delivers active-
        // chain bodies at or below the cursor (the payee replay), which are
        // simply already applied.
        const auto at_cur = m_seams.hash_at(cur);
        if (at_cur && *at_cur == m_follower.block_hash()) return;
        // Our cursor is stale: rewind to the journal state this body builds
        // on, if that state is still on the active chain.
        for (auto it = m_journal.rbegin(); it != m_journal.rend(); ++it) {
            if (it->height + 1 != height || it->hash != block.m_previous_block) continue;
            const auto on_chain = m_seams.hash_at(it->height);
            if (!on_chain || *on_chain != it->hash) continue;
            m_follower.restore_snapshot(*it);
            while (!m_journal.empty() && m_journal.back().height > it->height) m_journal.pop_back();
            ++m_rewinds;
            m_inflight.clear();
            m_arrived.clear();
            apply_locked(height, hash, block);
            return;
        }
        if (height <= cur) {
            LOG_ERROR << "[CP-LANE] reorg below the rewind journal at h=" << height
                      << " (cursor h=" << cur << " is off the active chain) -- re-arming";
            m_inflight.clear();
            m_arrived.clear();
            m_journal.clear();
            m_follower.reset();
            arm_locked(m_now_ms);   // a full seed re-arms now, a window seed asks for its floor
        }
    }

    /// The template's type-9 admission at `template_height` on `prev_hash`.
    /// nullopt: not usable (the template excludes every unlock).
    std::optional<AssetUnlockAdmission> admit(bool flag_on, uint32_t template_height,
                                              const uint256& prev_hash,
                                              const std::vector<MutableTransaction>& candidates,
                                              const std::vector<chainlock::QuorumCandidate>& quorums,
                                              const LlmqParamsView& params)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        AssetUnlockAdmission out;
        if (!m_follower.try_admit_unlocks(flag_on, template_height, prev_hash, candidates,
                                          quorums, params, out))
            return std::nullopt;
        return out;
    }

    Status status() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        Status s;
        s.mode = m_mode;
        s.full_history = m_follower.armed() && m_follower.full_history();
        s.armed = m_follower.armed();
        s.proven_complete = m_follower.proven_complete();
        s.seed_fetch = true;
        s.floor = m_follower.armed() && !m_follower.full_history()
                      ? m_window_floor_used : m_follower.schedule().v20_floor_height;
        s.height = m_follower.height();
        s.balance = m_follower.balance();
        s.lately_unlocked = m_follower.lately_unlocked();
        s.limit = m_follower.current_limit();
        if (s.armed) s.window_start_balance = m_follower.balance_at_window_start();
        s.index_ranges = m_follower.indexes().export_ranges().size();
        s.in_flight = m_inflight.size();
        s.applied = m_applied;
        s.rejected_bodies = m_rejected;
        s.rewinds = m_rewinds;
        s.failures = m_failures;
        s.fail_cause = m_last_fail_cause;
        return s;
    }

    /// Test access to the ledger (read-only).
    template <typename Fn>
    auto with_follower(Fn&& fn) const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return fn(m_follower);
    }

private:
    static constexpr int64_t kNever     = std::numeric_limits<int64_t>::min();
    static constexpr int64_t kReaskNow  = std::numeric_limits<int64_t>::min() / 2;

    static constexpr uint32_t kWindowMargin = 8;   ///< window seed: blocks below window + floor

    struct InFlight { uint256 hash; int64_t sent_ms{0}; };
    struct PendingFloor { uint32_t height{0}; uint256 hash; int64_t sent_ms{0}; };
    struct Arrived  { uint256 hash; BlockType block; };

    size_t refill_locked(int64_t now_ms)
    {
        if (!m_follower.armed()) return 0;
        const auto floor = m_seams.live_floor ? m_seams.live_floor() : std::nullopt;
        if (!floor) return 0;
        const uint32_t need = m_follower.height() + 1;
        if (need >= *floor) { m_inflight.clear(); m_arrived.clear(); return 0; }
        const uint32_t hi = std::min<uint32_t>(*floor - 1, need + kWindow - 1);
        std::vector<uint256> batch;
        size_t sent = 0;
        auto flush = [&]() {
            if (batch.empty()) return;
            if (m_seams.request && m_seams.request(batch)) sent += batch.size();
            batch.clear();
        };
        for (uint32_t h = need; h <= hi; ++h) {
            if (m_arrived.count(h)) continue;
            auto it = m_inflight.find(h);
            if (it != m_inflight.end() && now_ms - it->second.sent_ms < kReaskMs) continue;
            auto hash = m_seams.hash_at(h);
            if (!hash) break;
            m_inflight[h] = InFlight{*hash, now_ms};
            batch.push_back(*hash);
            if (batch.size() == kBatch) flush();
        }
        flush();
        for (auto it = m_inflight.begin(); it != m_inflight.end();) {
            if (it->first < need || it->first > hi) it = m_inflight.erase(it);
            else ++it;
        }
        return sent;
    }

    /// Arm now (a full seed, or a window floor at the v20 floor itself), or
    /// ask for the window seed's floor block (on_body arms it).
    bool arm_locked(int64_t now_ms)
    {
        const uint32_t v20 = m_follower.schedule().v20_floor_height;
        uint32_t floor = v20;
        if (m_mode == SeedMode::WINDOW) {
            const auto live = m_seams.live_floor ? m_seams.live_floor() : std::nullopt;
            if (!live) return false;
            const uint32_t back = m_follower.schedule().window_blocks + kWindowMargin;
            if (*live > v20 + back) floor = *live - back;
        }
        auto h = m_seams.hash_at(floor);
        if (!h) return false;
        if (floor == v20) {
            m_follower.arm(*h);   // the v20 floor: a full seed by definition
            m_journal.clear();
            journal_push_locked();
            return true;
        }
        if (m_pending_floor && m_pending_floor->height == floor && m_pending_floor->hash == *h
            && now_ms - m_pending_floor->sent_ms < kReaskMs)
            return false;
        m_pending_floor = PendingFloor{floor, *h, now_ms};
        m_window_floor_used = floor;
        if (m_seams.request) m_seams.request({*h});
        return false;
    }

    void maybe_complete_locked()
    {
        if (!m_follower.armed() || m_follower.proven_complete() || !m_seams.tip) return;
        const auto tip = m_seams.tip();
        if (!tip || *tip != m_follower.height()) return;
        const auto h = m_seams.hash_at(*tip);
        if (!h || *h != m_follower.block_hash()) return;
        m_follower.mark_proven_complete();
        LOG_INFO << "[CP-LANE] credit-pool follower at the header tip h=" << *tip
                 << " balance=" << m_follower.balance()
                 << (m_follower.full_history()
                         ? " (FULL seed from the v20 floor: unlock admission enabled)"
                         : " (WINDOW seed: balance history and limit; no unlock admission)");
    }

    void drain_locked()
    {
        for (;;) {
            if (!m_follower.armed()) break;
            const uint32_t need = m_follower.height() + 1;
            auto it = m_arrived.find(need);
            if (it == m_arrived.end()) break;
            Arrived a = std::move(it->second);
            m_arrived.erase(it);
            auto chain = m_seams.hash_at(need);
            if (!chain || *chain != a.hash) break;   // the chain moved since the ask
            if (!apply_locked(need, a.hash, a.block)) break;
        }
        const uint32_t need = m_follower.height() + 1;
        for (auto it = m_arrived.begin(); it != m_arrived.end();) {
            if (it->first < need) it = m_arrived.erase(it);
            else ++it;
        }
    }

    bool apply_locked(uint32_t height, const uint256& hash, const BlockType& block)
    {
        if (m_follower.apply_block(height, hash, block)) {
            ++m_applied;
            journal_push_locked();
            maybe_complete_locked();
            return true;
        }
        // The follower failed closed and wiped itself (its cause is logged).
        ++m_failures;
        m_last_fail_cause = m_follower.fail_cause();
        m_last_fail_ms = m_now_ms;
        m_journal.clear();
        m_inflight.clear();
        m_arrived.clear();
        return false;
    }

    void journal_push_locked()
    {
        m_journal.push_back(m_follower.snapshot());
        while (m_journal.size() > kJournal) m_journal.pop_front();
    }

    mutable std::mutex                       m_mutex;
    CreditPoolIdxFollower                    m_follower;
    Seams                                    m_seams;
    SeedMode                                 m_mode{SeedMode::WINDOW};
    std::optional<PendingFloor>              m_pending_floor;
    uint32_t                                 m_window_floor_used{0};
    std::deque<CreditPoolIdxFollower::State> m_journal;
    std::map<uint32_t, InFlight>             m_inflight;
    std::map<uint32_t, Arrived>              m_arrived;
    int64_t                                  m_now_ms{0};
    int64_t                                  m_last_fail_ms{kNever};
    uint64_t                                 m_applied{0};
    uint64_t                                 m_rejected{0};
    uint64_t                                 m_rewinds{0};
    uint64_t                                 m_failures{0};
    std::string                              m_last_fail_cause;
};

} // namespace coin
} // namespace dash
