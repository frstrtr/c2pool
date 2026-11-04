// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// core template refresh: why a template rebuild ran, and the pacing of the
// transaction-triggered rebuild (#2137 S1).
//
// The template is rebuilt on a new block, on MWEB state for the tip and on a
// sharechain best-share change (debounced; its trailing call is dropped when
// the sharechain tip did not move). Nothing rebuilt it when transactions
// arrived, so between shares a template aged by tens of seconds while the
// mempool's fees grew. TxRefreshPacer paces a rebuild after a mempool change:
//   - gated on a mempool-change counter, never on the sharechain tip: a
//     change no rebuild has covered yet always gets one;
//   - at most one rebuild per interval, counted from the last rebuild of any
//     cause (a block's or a share's rebuild covers the changes before it);
//   - leading edge: after a quiet interval the change rebuilds at once;
//     changes inside the interval coalesce into one rebuild at its end;
//   - the interval is 1 s, 2 s while the last rebuild took over 500 ms.
// Single-threaded by contract (the caller serializes): pure, the clock is
// passed in, so the KATs pin it directly.
// ---------------------------------------------------------------------------

#include <chrono>
#include <cstdint>

namespace core {

/// Why a template rebuild ran (/local_stats "template_refresh.by_cause").
enum class RefreshCause : uint8_t {
    tx,     // the mempool changed (a tx was priced)
    share,  // a sharechain best-share change
    block,  // a new block / headers / tip change
    mweb,   // MWEB state for the tip arrived
    count
};

inline const char* refresh_cause_name(RefreshCause c)
{
    switch (c) {
        case RefreshCause::tx:    return "tx";
        case RefreshCause::share: return "share";
        case RefreshCause::block: return "block";
        case RefreshCause::mweb:  return "mweb";
        case RefreshCause::count: break;
    }
    return "unknown";
}

class TxRefreshPacer {
public:
    using clock = std::chrono::steady_clock;
    using ms = std::chrono::milliseconds;

    static constexpr ms INTERVAL{1000};       // at most one tx-triggered rebuild a second
    static constexpr ms SLOW_INTERVAL{2000};  // ... every 2 s while a rebuild is slow:
    static constexpr ms SLOW_REBUILD{500};    // the last one took longer than this

    /// What the caller does now.
    struct Plan {
        bool              rebuild{false};   // rebuild now
        bool              schedule{false};  // arm the timer for `at`
        clock::time_point at{};
    };

    /// The mempool changed at `now`.
    Plan on_change(clock::time_point now)
    {
        ++m_changes;
        if (m_timer_armed)
            return {};  // the armed timer covers this change
        return plan(now);
    }

    /// The timer armed by a Plan fired at `now`: rebuild only for a change no
    /// rebuild has covered since; re-arm when a rebuild ran meanwhile.
    Plan on_timer(clock::time_point now)
    {
        m_timer_armed = false;
        if (m_changes == m_covered)
            return {};
        return plan(now);
    }

    /// A rebuild of any cause started at `start` and took `took`; it read the
    /// mempool as of `changes_at_start` (changes() taken before it started).
    void on_rebuild(clock::time_point start, ms took, uint64_t changes_at_start)
    {
        if (changes_at_start > m_covered)
            m_covered = changes_at_start;
        m_last_start = start;
        m_rebuilt = true;
        m_last_took = took;
    }

    /// The pacing interval now.
    ms interval() const { return m_last_took > SLOW_REBUILD ? SLOW_INTERVAL : INTERVAL; }

    uint64_t changes() const { return m_changes; }
    uint64_t covered() const { return m_covered; }
    ms       last_took() const { return m_last_took; }
    bool     timer_armed() const { return m_timer_armed; }

private:
    Plan plan(clock::time_point now)
    {
        const clock::time_point due = m_rebuilt ? m_last_start + interval() : now;
        if (due <= now)
            return {true, false, now};
        m_timer_armed = true;
        return {false, true, due};
    }

    uint64_t          m_changes{0};      // mempool changes reported
    uint64_t          m_covered{0};      // changes a rebuild has read
    bool              m_rebuilt{false};  // a rebuild ran (m_last_start is set)
    bool              m_timer_armed{false};
    clock::time_point m_last_start{};
    ms                m_last_took{0};
};

} // namespace core
