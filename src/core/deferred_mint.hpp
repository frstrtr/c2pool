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
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <utility>

namespace core {

enum class MintResult { Minted, Busy, Dropped };

enum class MintDropReason : uint8_t {
    none = 0,
    ttl,            ///< older than the queue TTL when it came up
    duplicate,      ///< the chain already holds this share
    not_backable,   ///< template txs no longer retained (cannot be relayed)
    gate,           ///< the producer rebuild refused it (identity / target)
    stale_parent,   ///< the share's parent is gone
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
};

template <class Item>
class DeferredMintQueue
{
public:
    using clock = std::chrono::steady_clock;

    explicit DeferredMintQueue(size_t capacity = 64,
                               std::chrono::milliseconds ttl = std::chrono::milliseconds(20000))
        : m_capacity(capacity), m_ttl(ttl) {}

    /// Queue a solve behind the others. false (and counted as queue_full) when
    /// the queue is full: the caller declines as before.
    bool push_back(Item item, clock::time_point now = clock::now())
    {
        return push(std::move(item), now, /*front=*/false);
    }
    /// Queue a solve AHEAD of the others (a block-winning share whose bounded
    /// wait expired: the block is already submitted, its share is the most
    /// valuable one to land).
    bool push_front(Item item, clock::time_point now = clock::now())
    {
        return push(std::move(item), now, /*front=*/true);
    }

    bool   empty() const { return m_q.empty(); }
    size_t size() const { return m_q.size(); }

    /// Mint up to `max_items` items in order. Busy puts the item back at the
    /// front and stops; Dropped / Minted continue. Never throws.
    template <class TryMint>
    DrainStats drain(TryMint&& try_mint, size_t max_items = 16, clock::time_point now = clock::now())
    {
        DrainStats st;
        size_t processed = 0;
        while (!m_q.empty() && processed < max_items) {
            Entry e = std::move(m_q.front());
            m_q.pop_front();
            if (now - e.arrival > m_ttl) {
                count_drop(MintDropReason::ttl);
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
                count_drop(out.why == MintDropReason::none ? MintDropReason::other : out.why);
                ++st.dropped;
            }
        }
        return st;
    }

    /// The node is stopping: nothing is minted any more; count what is left.
    size_t clear_for_shutdown()
    {
        const size_t n = m_q.size();
        m_counters.dropped[static_cast<size_t>(MintDropReason::shutdown)] += n;
        m_q.clear();
        return n;
    }

    const DeferredMintCounters& counters() const { return m_counters; }

private:
    struct Entry {
        Item              item;
        clock::time_point arrival;
    };

    bool push(Item item, clock::time_point now, bool front)
    {
        if (m_q.size() >= m_capacity) {
            count_drop(MintDropReason::queue_full);
            return false;
        }
        if (front) m_q.push_front(Entry{std::move(item), now});
        else       m_q.push_back(Entry{std::move(item), now});
        ++m_counters.deferred;
        if (m_q.size() > m_counters.max_depth) m_counters.max_depth = m_q.size();
        return true;
    }

    void count_drop(MintDropReason r) { ++m_counters.dropped[static_cast<size_t>(r)]; }

    std::deque<Entry>          m_q;
    size_t                     m_capacity;
    std::chrono::milliseconds  m_ttl;
    DeferredMintCounters       m_counters;
};

/// How one mint attempt is made.
struct MintAttempt {
    bool think_after{true};   ///< false: the caller runs ONE think for the batch
    bool from_queue{false};   ///< a retry from the queue: never a bounded wait
};

/// Point-in-time copy for readers on other threads (web/HTTP).
struct DeferredMintSnapshot {
    bool                 enabled{false};
    size_t               depth{0};
    uint64_t             thinks{0};      ///< batch thinks the minter requested
    DeferredMintCounters counters;
};

/// The policy around a DeferredMintQueue for one coin's io thread.
///
///   on_solve(item)  a fresh stratum solve. Disabled (the kill switch): exactly
///                   the old path, one synchronous attempt with its own think.
///                   Enabled: drain what is queued first (order kept), then
///                   try the new solve; a busy tracker queues it; anything
///                   minted gets ONE think afterwards.
///   drain_point()   an IO-phase epilogue or the backstop timer.
///   shutdown()      nothing is minted from the queue any more; the rest is
///                   counted as `shutdown`.
///
/// A block-winning solve keeps its synchronous bounded wait (mint_once sees
/// from_queue=false); only if that expires is it queued, at the FRONT.
///
/// io-thread-confined except snapshot(), which any thread may call.
template <class Item>
class DeferredMinter
{
public:
    using clock    = std::chrono::steady_clock;
    using MintOnce = std::function<MintOutcome(const Item&, const MintAttempt&)>;
    using Think    = std::function<void()>;

    struct SolveResult {
        MintOutcome outcome;      ///< the new solve's own attempt (Busy if it never ran)
        bool        queued{false};
    };

    DeferredMinter(bool enabled, MintOnce mint_once, Think think,
                   size_t capacity = 64,
                   std::chrono::milliseconds ttl = std::chrono::milliseconds(20000),
                   size_t max_per_drain = 16)
        : m_enabled(enabled), m_mint_once(std::move(mint_once)), m_think(std::move(think)),
          m_queue(capacity, ttl), m_max_per_drain(max_per_drain)
    {
        publish();
    }

    bool enabled() const { return m_enabled; }

    SolveResult on_solve(Item item, bool won_block, clock::time_point now = clock::now())
    {
        SolveResult r;
        if (!m_enabled || m_stopped) {
            r.outcome = m_mint_once(item, MintAttempt{true, false});
            return r;
        }
        if (won_block) {
            // The bounded wait happens inside mint_once; the block itself was
            // submitted before the mint seam. Never behind ordinary solves.
            r.outcome = m_mint_once(item, MintAttempt{true, false});
            if (r.outcome.result == MintResult::Busy)
                r.queued = m_queue.push_front(std::move(item), now);
            publish();
            return r;
        }
        size_t minted = 0;
        if (!m_queue.empty()) {
            minted += drain_queue(now).minted;
            if (!m_queue.empty()) {
                // Still blocked (or the per-drain cap hit): keep arrival order.
                r.outcome = MintOutcome{MintResult::Busy, MintDropReason::none, uint256()};
                r.queued = m_queue.push_back(std::move(item), now);
                if (minted > 0) think();
                publish();
                return r;
            }
        }
        r.outcome = m_mint_once(item, MintAttempt{false, false});
        if (r.outcome.result == MintResult::Busy)
            r.queued = m_queue.push_back(std::move(item), now);
        if (r.outcome.result == MintResult::Minted) ++minted;
        if (minted > 0) think();
        publish();
        return r;
    }

    DrainStats drain_point(clock::time_point now = clock::now())
    {
        if (!m_enabled || m_stopped || m_queue.empty())
            return {};
        const DrainStats st = drain_queue(now);
        if (st.minted > 0) think();
        publish();
        return st;
    }

    size_t shutdown()
    {
        m_stopped = true;
        const size_t n = m_queue.clear_for_shutdown();
        publish();
        return n;
    }

    size_t depth() const { return m_queue.size(); }
    const DeferredMintCounters& counters() const { return m_queue.counters(); }
    uint64_t thinks_requested() const { return m_thinks; }

    DeferredMintSnapshot snapshot() const
    {
        std::lock_guard<std::mutex> lk(m_pub_mutex);
        return m_published;
    }

private:
    DrainStats drain_queue(clock::time_point now)
    {
        return m_queue.drain(
            [this](const Item& it) { return m_mint_once(it, MintAttempt{false, true}); },
            m_max_per_drain, now);
    }

    void think()
    {
        ++m_thinks;
        if (m_think) m_think();
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

    bool                     m_enabled;
    bool                     m_stopped{false};
    MintOnce                 m_mint_once;
    Think                    m_think;
    DeferredMintQueue<Item>  m_queue;
    size_t                   m_max_per_drain;
    uint64_t                 m_thinks{0};
    mutable std::mutex       m_pub_mutex;
    DeferredMintSnapshot     m_published;
};

} // namespace core
