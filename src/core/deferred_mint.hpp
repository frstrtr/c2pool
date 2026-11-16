// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Deferred local mints (design note DESIGN-DEFERRED-MINT v2, 2026-11-17).
///
/// A stratum solve that meets the share target is minted on the io thread with
/// a single try_lock of the tracker. When the compute thread (think / clean)
/// holds the lock, the solve used to be DECLINED and its PPLNS credit lost
/// (~0.8% of mints on a busy hotel node). This queue keeps such a solve and
/// mints it at the next point the lock is free, without ever waiting on the io
/// thread.
///
/// Coin-agnostic. The coin supplies the item (self-contained mint inputs) and a
/// try_mint callback with a TRI-STATE result:
///   Minted  - the share entered the chain;
///   Busy    - the tracker is held right now: the item goes back to the FRONT
///             and the drain stops (resumes at the next drain point);
///   Dropped - the item can never mint (duplicate, not backable, gate refusal,
///             ...): counted with its reason, the drain continues.
/// A throwing try_mint is counted as Dropped(threw); nothing escapes drain().
///
/// THREADING: io-thread-confined. push and drain must run on the same thread
/// (the coin's io_context), which is also the thread that mints synchronously.

#include <core/uint256.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>

namespace core {

enum class MintResult { Minted, Busy, Dropped };

enum class MintDropReason : uint8_t {
    none = 0,
    ttl,            ///< older than the queue TTL when it came up
    duplicate,      ///< the chain already holds this share
    not_backable,   ///< template txs no longer retained (cannot be relayed)
    gate,           ///< the producer rebuild refused it (identity / target)
    stale_parent,   ///< the share's parent is gone (a coin that can tell; DASH
                    ///< reports a missing parent as `gate`)
    threw,          ///< try_mint threw
    shutdown,       ///< still queued when the node stopped
    queue_full,     ///< the queue was full when it was pushed
    other,
    count_          ///< array size
};

inline const char* to_string(MintDropReason r)
{
    switch (r) {
    case MintDropReason::none:         return "none";
    case MintDropReason::ttl:          return "ttl";
    case MintDropReason::duplicate:    return "duplicate";
    case MintDropReason::not_backable: return "not_backable";
    case MintDropReason::gate:         return "gate";
    case MintDropReason::stale_parent: return "stale_parent";
    case MintDropReason::threw:        return "threw";
    case MintDropReason::shutdown:     return "shutdown";
    case MintDropReason::queue_full:   return "queue_full";
    case MintDropReason::other:        return "other";
    case MintDropReason::count_:       break;
    }
    return "?";
}

struct MintOutcome {
    MintResult     result{MintResult::Dropped};
    MintDropReason why{MintDropReason::other};
    uint256        hash;     ///< set when Minted
};

struct DeferredMintCounters {
    uint64_t deferred{0};       ///< items pushed
    uint64_t minted{0};         ///< items minted from the queue
    uint64_t busy_stops{0};     ///< drains stopped because the tracker was busy
    uint64_t budget_stops{0};   ///< drains stopped by the per-drain time budget
    std::array<uint64_t, static_cast<size_t>(MintDropReason::count_)> dropped{};
    uint64_t max_depth{0};
    int64_t  max_age_ms_at_mint{0};
    uint64_t dropped_total() const
    {
        uint64_t s = 0;
        for (auto v : dropped) s += v;
        return s;
    }
};

struct DrainStats {
    size_t minted{0};
    size_t dropped{0};
    bool   stopped_busy{false};
    bool   stopped_budget{false};   ///< the per-drain time budget ran out
};

template <class Item>
class DeferredMintQueue
{
public:
    using clock = std::chrono::steady_clock;
    /// Told about every item that leaves the queue without being minted
    /// (ttl, threw, a Dropped attempt, shutdown). May be empty.
    using OnDrop = std::function<void(const Item&, MintDropReason)>;

    explicit DeferredMintQueue(size_t capacity = 64,
                               std::chrono::milliseconds ttl = std::chrono::milliseconds(20000))
        : m_capacity(capacity), m_ttl(ttl) {}

    /// Queue a solve behind the others. false (and counted as queue_full) when
    /// the queue is full: the caller declines as before, and `item` is left
    /// untouched (it is moved from only when accepted).
    bool push_back(Item&& item, clock::time_point now = clock::now())
    {
        if (m_q.size() >= m_capacity) {
            count_drop(MintDropReason::queue_full);
            return false;
        }
        m_q.push_back(Entry{std::move(item), now});
        note_push();
        return true;
    }
    bool push_back(const Item& item, clock::time_point now = clock::now())
    {
        Item copy(item);
        return push_back(std::move(copy), now);
    }
    /// Queue a solve AHEAD of the others: a block-winning share whose bounded
    /// wait expired (the block is already submitted; its share is the most
    /// valuable one to land). Never refused for capacity: at most one per
    /// won block, so it cannot grow the queue without bound.
    void push_front(Item item, clock::time_point now = clock::now())
    {
        m_q.push_front(Entry{std::move(item), now});
        note_push();
    }

    bool   empty() const { return m_q.empty(); }
    size_t size() const { return m_q.size(); }

    /// Mint up to `max_items` items in order. Busy puts the item back at the
    /// front and stops; Dropped / Minted continue. Never throws out of a
    /// try_mint (counted as `threw`). `max_time` (0 = off) bounds the drain's
    /// wall-clock time: checked after each attempt, it stops like the item cap
    /// and leaves the rest for the next drain point (a coin whose mint is
    /// expensive on the io thread). `now` is the TTL clock (injectable).
    template <class TryMint>
    DrainStats drain(TryMint&& try_mint, const OnDrop& on_drop = {}, size_t max_items = 16,
                     clock::time_point now = clock::now(),
                     std::chrono::microseconds max_time = std::chrono::microseconds(0))
    {
        DrainStats st;
        size_t processed = 0;
        const auto wall0 = clock::now();
        while (!m_q.empty() && processed < max_items) {
            Entry e = std::move(m_q.front());
            m_q.pop_front();
            if (now - e.arrival > m_ttl) {
                drop(e.item, MintDropReason::ttl, on_drop);
                ++st.dropped;
                ++processed;
                continue;
            }
            MintOutcome out;
            try {
                out = try_mint(e.item);
            } catch (...) {
                out = MintOutcome{MintResult::Dropped, MintDropReason::threw, uint256()};
            }
            if (out.result == MintResult::Busy) {
                m_q.push_front(std::move(e));
                ++m_counters.busy_stops;
                st.stopped_busy = true;
                break;
            }
            ++processed;
            if (out.result == MintResult::Minted) {
                ++m_counters.minted;
                ++st.minted;
                const int64_t age = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - e.arrival).count();
                if (age > m_counters.max_age_ms_at_mint) m_counters.max_age_ms_at_mint = age;
            } else {
                drop(e.item, out.why == MintDropReason::none ? MintDropReason::other : out.why, on_drop);
                ++st.dropped;
            }
            if (max_time.count() > 0 && !m_q.empty() && clock::now() - wall0 >= max_time) {
                ++m_counters.budget_stops;
                st.stopped_budget = true;
                break;
            }
        }
        return st;
    }

    /// The node is stopping: nothing is minted any more; count what is left.
    size_t clear_for_shutdown(const OnDrop& on_drop = {})
    {
        const size_t n = m_q.size();
        for (const auto& e : m_q)
            drop(e.item, MintDropReason::shutdown, on_drop);
        m_q.clear();
        return n;
    }

    const DeferredMintCounters& counters() const { return m_counters; }

    /// Count a drop that happened outside the queue (e.g. queue_full seen by
    /// the caller). Internal use by DeferredMinter.
    void count_drop(MintDropReason r) { ++m_counters.dropped[static_cast<size_t>(r)]; }

private:
    struct Entry {
        Item              item;
        clock::time_point arrival;
    };

    void note_push()
    {
        ++m_counters.deferred;
        if (m_q.size() > m_counters.max_depth) m_counters.max_depth = m_q.size();
    }

    void drop(const Item& item, MintDropReason r, const OnDrop& on_drop)
    {
        count_drop(r);
        if (!on_drop) return;
        try { on_drop(item, r); } catch (...) {}
    }

    std::deque<Entry>          m_q;
    size_t                     m_capacity;
    std::chrono::milliseconds  m_ttl;
    DeferredMintCounters       m_counters;
};

/// How one mint attempt is made.
struct MintAttempt {
    bool think_after{true};   ///< false: the caller runs ONE think for the batch
    bool from_queue{false};   ///< a retry from the queue: never a bounded wait
    /// true when a Busy result will be QUEUED (the minter is on). The coin's
    /// mint body uses it only for wording: with the kill switch it keeps the
    /// old "declined" / FORFEIT log lines exactly.
    bool deferrable{false};
};

/// Point-in-time copy for readers on other threads (web/HTTP).
struct DeferredMintSnapshot {
    bool                 enabled{false};
    size_t               depth{0};
    uint64_t             thinks{0};      ///< batch thinks the minter requested
    uint64_t             off_thread{0};  ///< calls from a non-owner thread (old path taken)
    DeferredMintCounters counters;
};

/// The policy around a DeferredMintQueue for one coin's io thread.
///
///   on_solve(item)  a fresh stratum solve. Disabled: the old path, one
///                   synchronous attempt with its own think.
///                   Enabled: drain what is queued first (order kept), then
///                   try the new solve; a busy tracker queues it; anything
///                   minted gets ONE think afterwards.
///   drain_point()   an IO-phase epilogue or the backstop timer.
///   shutdown()      nothing is minted from the queue any more; the rest is
///                   counted as `shutdown`.
///
/// A block-winning solve keeps its synchronous bounded wait (mint_once sees
/// from_queue=false); only if that expires is it queued, at the FRONT.
/// on_dropped is told about every solve that is finally lost once it reached
/// the minter (queue_full, ttl, gate, ..., shutdown, a late solve after
/// shutdown), so a coin can log a lost block-winning share in one place.
///
/// OWNER THREAD. The queue is touched only by its owner: the thread that
/// constructed the minter, or the one bind_owner_thread() names (call it once,
/// before the owner starts running, if the minter is built elsewhere). A call
/// from any other thread NEVER touches the queue, in every build: on_solve
/// takes the old synchronous path (what the coin did before the queue) and
/// drain_point is a no-op; both count `off_thread`. snapshot() is the only
/// call meant for other threads. shutdown() runs on the owner, or after the
/// owner has stopped running.
template <class Item>
class DeferredMinter
{
public:
    using clock     = std::chrono::steady_clock;
    using MintOnce  = std::function<MintOutcome(const Item&, const MintAttempt&)>;
    using Think     = std::function<void()>;
    using OnDropped = std::function<void(const Item&, MintDropReason)>;

    struct SolveResult {
        MintOutcome outcome;            ///< the new solve's own attempt (Busy if it never ran)
        bool        queued{false};
        bool        behind_queue{false}; ///< queued untried, behind earlier solves
    };

    DeferredMinter(bool enabled, MintOnce mint_once, Think think, OnDropped on_dropped = {},
                   size_t capacity = 64,
                   std::chrono::milliseconds ttl = std::chrono::milliseconds(20000),
                   size_t max_per_drain = 16,
                   std::chrono::microseconds max_drain_time = std::chrono::microseconds(0))
        : m_enabled(enabled), m_owner(std::this_thread::get_id()),
          m_mint_once(std::move(mint_once)), m_think(std::move(think)),
          m_on_dropped(std::move(on_dropped)), m_queue(capacity, ttl),
          m_max_per_drain(max_per_drain), m_max_drain_time(max_drain_time)
    {
        publish();
    }

    /// Name the owner thread (default: the calling thread). Call once, before
    /// the owner starts running and before any other thread can call in.
    void bind_owner_thread(std::thread::id id = std::this_thread::get_id())
    {
        m_owner.store(id);
    }

    bool enabled() const { return m_enabled; }

    SolveResult on_solve(Item item, bool won_block, clock::time_point now = clock::now())
    {
        SolveResult r;
        if (m_stopped.load()) {
            // The node is stopping: a share minted now could not be broadcast,
            // whichever thread the solve came from. Only the owner touches the
            // queue's counters; an off-owner caller is counted as off_thread.
            const bool owner = on_owner_thread();
            if (owner)
                m_queue.count_drop(MintDropReason::shutdown);
            notify_dropped(item, MintDropReason::shutdown);
            r.outcome = MintOutcome{MintResult::Dropped, MintDropReason::shutdown, uint256()};
            if (owner)
                publish();
            return r;
        }
        if (!on_owner_thread()) {
            // Never touch the queue off the owner thread: the old path.
            r.outcome = m_mint_once(item, MintAttempt{true, false, false});
            return r;
        }
        if (!m_enabled) {
            r.outcome = m_mint_once(item, MintAttempt{true, false, false});
            return r;
        }
        size_t minted = 0;
        try {
            if (won_block) {
                // The bounded wait happens inside mint_once; the block itself
                // was submitted before the mint seam. Never behind ordinary solves.
                r.outcome = m_mint_once(item, MintAttempt{true, false, true});
                if (r.outcome.result == MintResult::Busy) {
                    m_queue.push_front(std::move(item), now);
                    r.queued = true;
                }
                publish();
                return r;
            }
            if (!m_queue.empty()) {
                minted += drain_queue(now).minted;
                if (!m_queue.empty()) {
                    // Still blocked (or a per-drain cap hit): keep arrival order.
                    r.outcome = MintOutcome{MintResult::Busy, MintDropReason::none, uint256()};
                    r.behind_queue = true;
                    r.queued = push_back_or_drop(item, now);
                    finish(minted);
                    return r;
                }
            }
            r.outcome = m_mint_once(item, MintAttempt{false, false, true});
            if (r.outcome.result == MintResult::Busy)
                r.queued = push_back_or_drop(item, now);
            if (r.outcome.result == MintResult::Minted) ++minted;
        } catch (...) {
            // The fresh attempt threw: shares the drain above already minted
            // still get their think.
            finish(minted);
            throw;
        }
        finish(minted);
        return r;
    }

    DrainStats drain_point(clock::time_point now = clock::now())
    {
        if (!on_owner_thread())
            return {};
        if (!m_enabled || m_stopped.load() || m_queue.empty())
            return {};
        const DrainStats st = drain_queue(now);
        finish(st.minted);
        return st;
    }

    size_t shutdown()
    {
        m_stopped.store(true);
        const size_t n = m_queue.clear_for_shutdown(m_on_dropped);
        publish();
        return n;
    }

    size_t depth() const { return m_queue.size(); }
    const DeferredMintCounters& counters() const { return m_queue.counters(); }
    uint64_t thinks_requested() const { return m_thinks; }
    uint64_t off_thread_calls() const { return m_off_thread.load(); }

    DeferredMintSnapshot snapshot() const
    {
        DeferredMintSnapshot s;
        {
            std::lock_guard<std::mutex> lk(m_pub_mutex);
            s = m_published;
        }
        s.off_thread = m_off_thread.load();
        return s;
    }

private:
    bool on_owner_thread()
    {
        if (m_owner.load() == std::this_thread::get_id())
            return true;
        m_off_thread.fetch_add(1);
        return false;
    }

    DrainStats drain_queue(clock::time_point now)
    {
        return m_queue.drain(
            [this](const Item& it) { return m_mint_once(it, MintAttempt{false, true, true}); },
            m_on_dropped, m_max_per_drain, now, m_max_drain_time);
    }

    void notify_dropped(const Item& item, MintDropReason why)
    {
        if (!m_on_dropped) return;
        try { m_on_dropped(item, why); } catch (...) {}
    }

    bool push_back_or_drop(Item& item, clock::time_point now)
    {
        if (m_queue.push_back(std::move(item), now))   // moved from only when accepted
            return true;
        // queue_full is already counted by the queue; tell the coin.
        notify_dropped(item, MintDropReason::queue_full);
        return false;
    }

    void finish(size_t minted)
    {
        if (minted > 0) {
            ++m_thinks;
            if (m_think) m_think();
        }
        publish();
    }

    void publish()
    {
        DeferredMintSnapshot s;
        s.enabled  = m_enabled;
        s.depth    = m_queue.size();
        s.thinks   = m_thinks;
        s.counters = m_queue.counters();
        std::lock_guard<std::mutex> lk(m_pub_mutex);
        m_published = s;
    }

    const bool                    m_enabled;
    std::atomic<bool>             m_stopped{false};
    std::atomic<std::thread::id>  m_owner;
    std::atomic<uint64_t>         m_off_thread{0};
    MintOnce                      m_mint_once;
    Think                         m_think;
    OnDropped                     m_on_dropped;
    DeferredMintQueue<Item>       m_queue;
    size_t                        m_max_per_drain;
    std::chrono::microseconds     m_max_drain_time;
    uint64_t                      m_thinks{0};
    mutable std::mutex            m_pub_mutex;
    DeferredMintSnapshot          m_published;
};

} // namespace core
