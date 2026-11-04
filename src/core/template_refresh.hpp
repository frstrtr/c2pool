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
//   - the interval is at least 1 s and at least DUTY_FACTOR (4) times the
//     rebuild cost (fast-attack, slow-decay estimate over every rebuild), so
//     tx-triggered rebuilds take at most about 25 % of the io thread whatever
//     a rebuild costs on the host (#2137).
// Single-threaded by contract (the caller serializes): pure, the clock is
// passed in, so the KATs pin it directly.
// ---------------------------------------------------------------------------

#include <algorithm>
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

    static constexpr ms INTERVAL{1000};        // at most one tx-triggered rebuild a second
    static constexpr int64_t DUTY_FACTOR = 4;  // ... and one per 4 rebuild costs (<= 25 % duty)

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
        // Fast attack, slow decay: one slow rebuild widens the interval at
        // once; a run of cheap ones (a HOLD that returned early) narrows it
        // by a quarter each.
        m_cost = took > m_cost ? took : ms((3 * m_cost.count() + took.count()) / 4);
    }

    /// The pacing interval now.
    ms interval() const { return std::max(INTERVAL, ms(DUTY_FACTOR * m_cost.count())); }
    /// The rebuild cost estimate the interval scales with.
    ms cost() const { return m_cost; }

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
    ms                m_cost{0};
};

} // namespace core
