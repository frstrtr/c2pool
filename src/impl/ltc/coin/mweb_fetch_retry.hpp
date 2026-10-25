// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded LTC: fetch the tip's full block until its MWEB state is in.
///
/// A template for the next block needs the MWEB state (HogEx outpoint, value,
/// MWEB header) of the tip, which only the tip's full block (or a v3 compact
/// block reconstructed into one) carries. Until it arrives, templates HOLD.
///
///   MwebFetchRetry   — pure state machine: one armed tip hash, attempts at
///                      t = 0, 1, 3, 7, 15, 30, 45 ... s; the first three ask
///                      one peer (round-robin), later ones ask every peer;
///                      after 600 s it reports "gave up" once and keeps asking
///                      every 60 s (HOLD forever is worse than a getdata a
///                      minute). The asio glue lives in main_ltc.cpp.
///   MwebWindowStats  — the tip-change -> state-for-tip window, measured per
///                      block, plus the compact-block / fetch counters, for
///                      /local_stats "ltc_mweb".
///   SeenBlocks       — small LRU of block hashes already processed, so the
///                      second and later deliveries of a block skip the
///                      UTXO / mempool / explorer passes.
/// Header-only, no asio, so the KATs drive it with explicit time points.

#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>

namespace ltc {
namespace coin {

// ─── Retry driver ─────────────────────────────────────────────────────────────

class MwebFetchRetry {
public:
    using clock      = std::chrono::steady_clock;
    using time_point = clock::time_point;
    using duration   = clock::duration;

    /// Attempts 0..TARGETED_ATTEMPTS-1 ask one peer; later attempts ask all.
    static constexpr uint32_t TARGETED_ATTEMPTS = 3;
    /// After this long without the state: report once, then GIVEN_UP_CADENCE.
    static constexpr std::chrono::seconds GIVE_UP_AFTER{600};
    static constexpr std::chrono::seconds GIVEN_UP_CADENCE{60};

    struct Action {
        uint256  hash;
        uint32_t attempt{0};     // 0-based
        bool     broadcast{false};
        bool     gave_up{false}; // first action past GIVE_UP_AFTER (log + count once)
    };

    /// Delay after attempt `attempt` before the next one: 1, 2, 4, 8, 15, 15 ... s.
    static std::chrono::seconds next_delay(uint32_t attempt)
    {
        static constexpr int kDelays[] = {1, 2, 4, 8};
        return std::chrono::seconds(attempt < 4 ? kDelays[attempt] : 15);
    }

    /// Arm for `hash`. A no-op (returns false) when already armed for it, so
    /// repeated arms from the tip-change handler and the tick keep the
    /// schedule. A different hash (next block, reorg) restarts at attempt 0,
    /// due at now + first_delay.
    bool arm(const uint256& hash, time_point now, duration first_delay = duration::zero())
    {
        if (m_armed && m_hash == hash)
            return false;
        m_armed     = true;
        m_hash      = hash;
        m_attempt   = 0;
        m_armed_at  = now;
        m_next_due  = now + first_delay;
        m_gave_up   = false;
        m_broadcast = false;
        return true;
    }

    /// The MWEB state for `hash` arrived: stop if that is the armed hash.
    bool on_state(const uint256& hash)
    {
        if (!m_armed || m_hash != hash)
            return false;
        remember_last();
        m_armed = false;
        return true;
    }

    void disarm()
    {
        if (m_armed)
            remember_last();
        m_armed = false;
    }

    /// The next action if one is due at `now` (and advances the schedule).
    std::optional<Action> due(time_point now)
    {
        if (!m_armed || now < m_next_due)
            return std::nullopt;
        Action a;
        a.hash      = m_hash;
        a.attempt   = m_attempt;
        a.broadcast = m_attempt >= TARGETED_ATTEMPTS;
        const bool past_deadline = now - m_armed_at >= GIVE_UP_AFTER;
        if (past_deadline && !m_gave_up) {
            m_gave_up = true;
            a.gave_up = true;
        }
        m_broadcast = a.broadcast;
        m_next_due  = now + (m_gave_up ? std::chrono::duration_cast<duration>(GIVEN_UP_CADENCE)
                                       : std::chrono::duration_cast<duration>(next_delay(m_attempt)));
        ++m_attempt;
        return a;
    }

    bool armed() const { return m_armed; }
    const uint256& armed_hash() const { return m_hash; }
    /// Attempts made for the armed hash so far.
    uint32_t attempts() const { return m_armed ? m_attempt : 0; }
    bool gave_up() const { return m_armed && m_gave_up; }
    std::optional<time_point> next_due() const
    {
        if (!m_armed) return std::nullopt;
        return m_next_due;
    }

    /// Attempts made for `hash` (armed now, or the last one disarmed).
    uint32_t attempts_for(const uint256& hash) const
    {
        if (m_armed && m_hash == hash) return m_attempt;
        if (m_last_hash == hash) return m_last_attempts;
        return 0;
    }
    /// Whether the last request for `hash` went to every peer.
    bool last_was_broadcast(const uint256& hash) const
    {
        if (m_armed && m_hash == hash) return m_broadcast;
        if (m_last_hash == hash) return m_last_broadcast;
        return false;
    }

private:
    void remember_last()
    {
        m_last_hash      = m_hash;
        m_last_attempts  = m_attempt;
        m_last_broadcast = m_broadcast;
    }

    bool       m_armed{false};
    uint256    m_hash;
    uint32_t   m_attempt{0};
    time_point m_armed_at{};
    time_point m_next_due{};
    bool       m_gave_up{false};
    bool       m_broadcast{false};

    uint256    m_last_hash;
    uint32_t   m_last_attempts{0};
    bool       m_last_broadcast{false};
};

// ─── Window metrics ───────────────────────────────────────────────────────────

class MwebWindowStats {
public:
    using clock      = std::chrono::steady_clock;
    using time_point = clock::time_point;

    /// Where the MWEB state that closed a window came from.
    enum class Source : uint8_t {
        CmpctV3Reconstructed,
        CmpctV3Blocktxn,
        FullBlockTargeted,
        FullBlockBroadcast,
        Bootstrap,
    };
    static constexpr size_t SOURCE_COUNT = 5;

    static const char* source_name(Source s)
    {
        switch (s) {
        case Source::CmpctV3Reconstructed: return "cmpct_v3_reconstructed";
        case Source::CmpctV3Blocktxn:      return "cmpct_v3_blocktxn";
        case Source::FullBlockTargeted:    return "full_block_targeted";
        case Source::FullBlockBroadcast:   return "full_block_broadcast";
        case Source::Bootstrap:            return "bootstrap";
        }
        return "unknown";
    }

    /// Histogram upper bounds in seconds; one more bucket for "> 60".
    static constexpr std::array<double, 8> BUCKET_BOUNDS{0.25, 0.5, 1, 2, 5, 10, 30, 60};
    static constexpr size_t BUCKETS = BUCKET_BOUNDS.size() + 1;

    static size_t bucket_for_ms(int64_t ms)
    {
        const double s = static_cast<double>(ms) / 1000.0;
        for (size_t i = 0; i < BUCKET_BOUNDS.size(); ++i)
            if (s <= BUCKET_BOUNDS[i])
                return i;
        return BUCKET_BOUNDS.size();
    }

    /// A closed window (the caller logs it).
    struct Closed {
        uint256  tip;
        uint32_t height{0};
        int64_t  ms{0};
        Source   source{Source::FullBlockTargeted};
        uint32_t attempts{0};
    };

    /// The tip changed to `tip` (start = when the header chain reported it).
    /// If the state for `tip` is already in (a compact block reconstructed
    /// before the tip change was processed), the window closes at once with
    /// 0 ms. A previous window still open is counted as unclosed.
    std::optional<Closed> open(const uint256& tip, uint32_t height, time_point start)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_open && m_open_tip == tip)
            return std::nullopt;  // same tip reported twice
        if (m_open)
            ++m_unclosed;
        if (m_has_last_state && m_last_state_hash == tip) {
            m_open = false;
            return close_locked(tip, height, 0, m_last_state_source, m_last_state_attempts);
        }
        m_open        = true;
        m_open_tip    = tip;
        m_open_height = height;
        m_open_start  = start;
        return std::nullopt;
    }

    /// MWEB state for block `hash` was accepted. Closes the open window when
    /// `hash` is its tip.
    std::optional<Closed> note_state(const uint256& hash, Source source, uint32_t attempts,
                                     time_point now)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_has_last_state      = true;
        m_last_state_hash     = hash;
        m_last_state_source   = source;
        m_last_state_attempts = attempts;
        if (!m_open || m_open_tip != hash)
            return std::nullopt;
        m_open = false;
        const int64_t ms = std::max<int64_t>(0,
            std::chrono::duration_cast<std::chrono::milliseconds>(now - m_open_start).count());
        return close_locked(hash, m_open_height, ms, source, attempts);
    }

    void note_cmpct_rejected(const std::string& reason)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++m_cmpct_rejected[reason];
    }
    void note_cmpct_fallback(const std::string& reason)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++m_cmpct_fallback[reason];
    }

    // Counters (any thread).
    std::atomic<uint64_t> cmpct_received{0};       // cmpctblock messages
    std::atomic<uint64_t> cmpct_v3_with_mweb{0};   // ... carrying an mw::Block
    std::atomic<uint64_t> cmpct_no_hogex{0};       // ... sent to the full-block fallback
    std::atomic<uint64_t> cmpct_dup{0};            // ... for a block already in hand / in flight
    std::atomic<uint64_t> fetch_retries{0};        // full-block requests after attempt 0
    std::atomic<uint64_t> fetch_gave_up{0};        // tips past the 600 s deadline
    std::atomic<uint64_t> block_dups{0};           // full blocks delivered again
    std::atomic<uint64_t> full_blocks_received{0}; // full_block events (all sources)

    nlohmann::json to_json() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        nlohmann::json hist = nlohmann::json::object();
        for (size_t i = 0; i < BUCKETS; ++i) {
            const std::string key = i < BUCKET_BOUNDS.size()
                ? "le_" + fmt_bound(BUCKET_BOUNDS[i])
                : "gt_" + fmt_bound(BUCKET_BOUNDS.back());
            hist[key] = m_hist[i];
        }
        nlohmann::json src = nlohmann::json::object();
        for (size_t i = 0; i < SOURCE_COUNT; ++i)
            src[source_name(static_cast<Source>(i))] = m_source[i];
        nlohmann::json rejected = nlohmann::json::object();
        for (const auto& [k, v] : m_cmpct_rejected) rejected[k] = v;
        nlohmann::json fallback = nlohmann::json::object();
        for (const auto& [k, v] : m_cmpct_fallback) fallback[k] = v;
        return {
            {"window_hist", hist},
            {"window_last_ms", m_last_ms},
            {"window_count", m_count},
            {"window_unclosed", m_unclosed},
            {"window_open", m_open},
            {"state_source", src},
            {"cmpct_received", cmpct_received.load()},
            {"cmpct_v3_with_mweb", cmpct_v3_with_mweb.load()},
            {"cmpct_no_hogex", cmpct_no_hogex.load()},
            {"cmpct_fallback", fallback},
            {"cmpct_rejected", rejected},
            {"cmpct_dup", cmpct_dup.load()},
            {"fetch_retries", fetch_retries.load()},
            {"fetch_gave_up", fetch_gave_up.load()},
            {"block_dups", block_dups.load()},
            {"full_blocks_received", full_blocks_received.load()},
        };
    }

    uint64_t window_count() const { std::lock_guard<std::mutex> l(m_mutex); return m_count; }
    uint64_t window_unclosed() const { std::lock_guard<std::mutex> l(m_mutex); return m_unclosed; }
    int64_t  window_last_ms() const { std::lock_guard<std::mutex> l(m_mutex); return m_last_ms; }
    uint64_t hist_bucket(size_t i) const { std::lock_guard<std::mutex> l(m_mutex); return i < BUCKETS ? m_hist[i] : 0; }
    uint64_t source_count(Source s) const
    {
        std::lock_guard<std::mutex> l(m_mutex);
        return m_source[static_cast<size_t>(s)];
    }

private:
    static std::string fmt_bound(double b)
    {
        // 0.25 -> "0.25", 1 -> "1"
        std::string s = std::to_string(b);
        s.erase(s.find_last_not_of('0') + 1);
        if (!s.empty() && s.back() == '.') s.pop_back();
        return s;
    }

    Closed close_locked(const uint256& tip, uint32_t height, int64_t ms, Source source,
                        uint32_t attempts)
    {
        ++m_hist[bucket_for_ms(ms)];
        ++m_source[static_cast<size_t>(source)];
        ++m_count;
        m_last_ms = ms;
        return Closed{tip, height, ms, source, attempts};
    }

    mutable std::mutex m_mutex;
    bool       m_open{false};
    uint256    m_open_tip;
    uint32_t   m_open_height{0};
    time_point m_open_start{};
    bool       m_has_last_state{false};
    uint256    m_last_state_hash;
    Source     m_last_state_source{Source::FullBlockTargeted};
    uint32_t   m_last_state_attempts{0};
    std::array<uint64_t, BUCKETS> m_hist{};
    std::array<uint64_t, SOURCE_COUNT> m_source{};
    uint64_t   m_count{0};
    uint64_t   m_unclosed{0};
    int64_t    m_last_ms{0};
    std::map<std::string, uint64_t> m_cmpct_rejected;
    std::map<std::string, uint64_t> m_cmpct_fallback;
};

// ─── Seen-blocks LRU ──────────────────────────────────────────────────────────

class SeenBlocks {
public:
    explicit SeenBlocks(size_t capacity = 64) : m_capacity(capacity ? capacity : 1) {}

    bool contains(const uint256& hash) const { return m_set.count(hash) != 0; }

    /// Insert (or refresh) `hash`; evicts the oldest past capacity.
    void insert(const uint256& hash)
    {
        if (m_set.count(hash)) {
            for (auto it = m_order.begin(); it != m_order.end(); ++it) {
                if (*it == hash) { m_order.erase(it); break; }
            }
        } else {
            m_set.insert(hash);
        }
        m_order.push_back(hash);
        while (m_order.size() > m_capacity) {
            m_set.erase(m_order.front());
            m_order.pop_front();
        }
    }

    size_t size() const { return m_order.size(); }

private:
    size_t m_capacity;
    std::deque<uint256> m_order;
    std::set<uint256> m_set;
};

} // namespace coin
} // namespace ltc
