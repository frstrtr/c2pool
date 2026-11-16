// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// DIAGNOSTIC ONLY (branch dash/diag-tracker-lock-holds; never for production).
///
/// Who holds the DASH tracker's EXCLUSIVE lock, for how long, split by phase.
/// A stratum solve takes the tracker with a shared try_lock and is DECLINED
/// ("[MINT] tracker busy") whenever an exclusive holder is inside; the hotel
/// measured ~1.25% of local mints declined (11-16). This names the holders and
/// their duty cycle so the fix can target the right one.
///
///   [LOCK-HOLD]     one line per hold >= kLogHoldUs, with phase splits
///   [LOCK-HOLD-MIN] per holder per minute: n, sum, max, buckets, duty cycle
///
/// The current holder and its age are readable from any thread (current()), so
/// a decline line can name what it lost to.

#include <core/log.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace diag {

inline int64_t lock_hold_now_us()
{
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

class LockHoldRecorder
{
public:
    static constexpr int64_t kLogHoldUs = 20'000;     // per-hold line at >= 20 ms
    static constexpr int64_t kWindowUs  = 60'000'000; // per-minute summary

    void begin(const char* holder)
    {
        m_since_us.store(lock_hold_now_us(), std::memory_order_relaxed);
        m_holder.store(holder, std::memory_order_release);
    }

    /// Records one finished hold. `phases` is "name=ms ..." (may be empty).
    void end(const char* holder, int64_t held_us, const std::string& phases)
    {
        m_holder.store(nullptr, std::memory_order_release);
        if (held_us >= kLogHoldUs)
            LOG_INFO << "[LOCK-HOLD] holder=" << holder << " held=" << held_us / 1000
                     << "." << (held_us % 1000) / 100 << "ms " << phases;
        std::lock_guard<std::mutex> g(m_mu);
        const int64_t now = lock_hold_now_us();
        if (m_window_start_us == 0) m_window_start_us = now;
        auto& s = m_stats[holder];
        ++s.n;
        s.sum_us += held_us;
        if (held_us > s.max_us) s.max_us = held_us;
        const int64_t ms = held_us / 1000;
        ++s.b[ms < 1 ? 0 : ms < 5 ? 1 : ms < 20 ? 2 : ms < 100 ? 3 : ms < 500 ? 4 : 5];
        if (now - m_window_start_us >= kWindowUs) flush_locked(now);
    }

    /// The holder inside the exclusive lock right now, and for how long (ms);
    /// {nullptr, 0} when none is recorded.
    std::pair<const char*, int64_t> current() const
    {
        const char* h = m_holder.load(std::memory_order_acquire);
        if (h == nullptr) return {nullptr, 0};
        return {h, (lock_hold_now_us() - m_since_us.load(std::memory_order_relaxed)) / 1000};
    }

private:
    struct Stats {
        uint64_t n{0};
        int64_t sum_us{0};
        int64_t max_us{0};
        uint64_t b[6]{};   // <1, 1-5, 5-20, 20-100, 100-500, >=500 ms
    };

    void flush_locked(int64_t now)
    {
        const int64_t win = now - m_window_start_us;
        for (const auto& [holder, s] : m_stats) {
            LOG_INFO << "[LOCK-HOLD-MIN] holder=" << holder << " window=" << win / 1000 << "ms"
                     << " n=" << s.n << " sum=" << s.sum_us / 1000 << "ms max=" << s.max_us / 1000
                     << "ms duty=" << (win > 0 ? 100.0 * static_cast<double>(s.sum_us) / static_cast<double>(win) : 0.0)
                     << "% b=<1:" << s.b[0] << ",1-5:" << s.b[1] << ",5-20:" << s.b[2]
                     << ",20-100:" << s.b[3] << ",100-500:" << s.b[4] << ",>=500:" << s.b[5];
        }
        m_stats.clear();
        m_window_start_us = now;
    }

    std::atomic<const char*> m_holder{nullptr};
    std::atomic<int64_t> m_since_us{0};
    std::mutex m_mu;
    std::map<std::string, Stats> m_stats;
    int64_t m_window_start_us{0};
};

inline LockHoldRecorder& lock_hold_recorder()
{
    static LockHoldRecorder r;
    return r;
}

/// Scoped hold with phase marks: construct right after the exclusive lock is
/// taken; mark("phase") at each boundary (the time since the previous mark is
/// charged to that phase); the destructor records the hold.
class LockHoldScope
{
public:
    explicit LockHoldScope(const char* holder)
        : m_holder(holder), m_start_us(lock_hold_now_us()), m_last_us(m_start_us)
    {
        lock_hold_recorder().begin(holder);
    }
    void mark(const char* phase)
    {
        const int64_t now = lock_hold_now_us();
        m_phases.emplace_back(phase, now - m_last_us);
        m_last_us = now;
    }
    ~LockHoldScope()
    {
        const int64_t now = lock_hold_now_us();
        std::ostringstream os;
        for (const auto& [p, us] : m_phases) os << p << "=" << us / 1000 << "." << (us % 1000) / 100 << " ";
        if (now - m_last_us > 0 && !m_phases.empty()) os << "rest=" << (now - m_last_us) / 1000 << "." << ((now - m_last_us) % 1000) / 100;
        lock_hold_recorder().end(m_holder, now - m_start_us, os.str());
    }
    LockHoldScope(const LockHoldScope&) = delete;
    LockHoldScope& operator=(const LockHoldScope&) = delete;

private:
    const char* m_holder;
    int64_t m_start_us;
    int64_t m_last_us;
    std::vector<std::pair<const char*, int64_t>> m_phases;
};

} // namespace diag
} // namespace dash
