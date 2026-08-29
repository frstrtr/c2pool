// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// LANE DIAGNOSTICS — the three primitives every embedded/daemonless DASH lane
/// needs so that a log alone answers WHAT state the node is in, WHY it is not
/// serving, and HOW FAST each lane is moving.
///
/// This header is TELEMETRY ONLY. Nothing here participates in a serve
/// decision, a consensus path or an arm decision; every type is a counter, a
/// clock reading or a string. That is deliberate: the incidents below were all
/// diagnosis failures, not logic failures, and the fix must not be able to
/// change what the node does.
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHY EACH PRIMITIVE EXISTS (measured, 2026-08-04/05, mainnet .211 + contabo)
/// ─────────────────────────────────────────────────────────────────────────
///
/// • ProgressReporter — the replay, the header backfill and the MN-CKPT payee
///   bridge all advanced SILENTLY. Rate and ETA had to be reconstructed by
///   diffing log timestamps by hand. A per-lane progress line with cursor,
///   target, rate over the last window, ETA and bytes fetched removes that
///   whole manual step. Throttled on BOTH axes (every N units OR every T
///   seconds, whichever comes first) because a per-block line is a flood: the
///   same day's log carried 205k+ repeated lines from one un-throttled site.
///
/// • StallWatchdog — the WORST defect of the day. The MN-CKPT bridge froze on
///   BOTH nodes right after a completed on-demand PoSe fold (cursors
///   h=2514874 and h=2516862) for 11-12 minutes with NO warning at all. The
///   stall detector lived inside pump(), which (a) only runs on a tip change
///   (~2.5 min apart) and (b) early-returns on several paths, INCLUDING the
///   pending-snapshot path — so the detector could be skipped by the very
///   condition it exists to detect, and even when it did run it needed five
///   consecutive stalled pumps (~12 min) before it said anything. The only
///   symptom was "the arm never arms".
///
///   The rule this class encodes: A STALL DETECTOR MUST NOT LIVE ON THE PATH
///   IT WATCHES. StallWatchdog keeps a last-progress WALL-CLOCK timestamp and
///   is polled from an independent periodic timer, so a lane that stops
///   calling anything at all is exactly the case it reports fastest.
///
/// • LogSuppressor — the flood control the gate already applies by hand, made
///   reusable: identical repeated lines collapse to one line plus a
///   `suppressed=N` count on the next emit, so a storm is still COUNTED but
///   costs one line per interval instead of 205k.
///
/// All three take an explicit `now_ms` so a KAT can drive time deterministically
/// rather than sleeping.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <map>
#include <optional>
#include <sstream>
#include <string>

namespace dash {
namespace coin {
namespace diag {

/// Monotonic milliseconds. Steady, not wall — a clock step must not fabricate
/// a stall or erase one.
inline int64_t steady_now_ms()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch())
        .count();
}

/// One decimal place, fixed. Keeps `rate=142.6blk/s` greppable and parseable.
inline std::string fmt1(double v)
{
    std::ostringstream os;
    os << std::fixed << std::setprecision(1) << v;
    return os.str();
}

/// Bytes as a human unit WITHOUT losing the machine-parseable shape: the value
/// and the unit are one token (`fetched=56.9MB`), so a scraper can split on the
/// first non-numeric character.
inline std::string fmt_bytes(uint64_t bytes)
{
    if (bytes < 1024ull) return std::to_string(bytes) + "B";
    const double kb = static_cast<double>(bytes) / 1024.0;
    if (kb < 1024.0) return fmt1(kb) + "KB";
    const double mb = kb / 1024.0;
    if (mb < 1024.0) return fmt1(mb) + "MB";
    return fmt1(mb / 1024.0) + "GB";
}

/// Seconds as `19s` / `4m12s` / `1h04m`. `n/a` when the rate is unknown — an
/// ETA of 0 and an ETA that cannot be computed are different facts and the log
/// must not conflate them.
inline std::string fmt_eta(std::optional<double> seconds)
{
    if (!seconds) return "n/a";
    if (*seconds < 0) return "n/a";
    const int64_t s = static_cast<int64_t>(*seconds + 0.5);
    if (s < 60) return std::to_string(s) + "s";
    if (s < 3600) return std::to_string(s / 60) + "m" + std::to_string(s % 60) + "s";
    std::ostringstream os;
    os << (s / 3600) << "h" << std::setw(2) << std::setfill('0')
       << ((s % 3600) / 60) << "m";
    return os.str();
}

/// ─────────────────────────────────────────────────────────────────────────
/// PROGRESS + RATE, throttled on two axes
/// ─────────────────────────────────────────────────────────────────────────
///
/// `sample(units, now)` returns a filled Sample at most once per
/// `every_units` of forward progress OR once per `every_ms` of wall clock,
/// WHICHEVER COMES FIRST — so a fast lane reports by block count and a slow or
/// stopped-but-not-dead lane still reports by time. It returns nullopt
/// otherwise, and the caller emits nothing.
///
/// The rate is measured over the interval between the previous emit and this
/// one (not since the start), which is what an operator asking "is it speeding
/// up or slowing down" actually wants.
class ProgressReporter
{
public:
    struct Sample
    {
        uint64_t units{0};        ///< absolute progress counter now
        uint64_t delta{0};        ///< units since the previous emit
        int64_t  elapsed_ms{0};   ///< wall ms since the previous emit
        double   rate_per_s{0.0}; ///< delta / elapsed over THAT window
        int64_t  total_ms{0};     ///< wall ms since start()
    };

    ProgressReporter() = default;
    ProgressReporter(uint64_t every_units, int64_t every_ms)
        : m_every_units(every_units ? every_units : 1)
        , m_every_ms(every_ms > 0 ? every_ms : 1)
    {
    }

    /// (Re)arm at the start of a run. A re-armed lane must not inherit the
    /// previous run's baseline — that is how a restarted bridge reported a
    /// negative delta and an absurd rate.
    void start(uint64_t base_units, int64_t now)
    {
        m_started    = true;
        m_start_ms   = now;
        m_last_units = base_units;
        m_last_ms    = now;
    }

    bool started() const { return m_started; }

    /// Throttled sample. See the class comment for the two-axis rule.
    std::optional<Sample> sample(uint64_t units, int64_t now)
    {
        if (!m_started) start(units, now);
        const bool by_units = units >= m_last_units
                              && (units - m_last_units) >= m_every_units;
        const bool by_time = (now - m_last_ms) >= m_every_ms;
        if (!by_units && !by_time) return std::nullopt;
        return flush(units, now);
    }

    /// UNCONDITIONAL sample — for a terminal event (publish, fail-close) where
    /// the last window must be reported whatever the throttle says.
    std::optional<Sample> flush(uint64_t units, int64_t now)
    {
        if (!m_started) start(units, now);
        Sample s;
        s.units      = units;
        s.delta      = units >= m_last_units ? units - m_last_units : 0;
        s.elapsed_ms = now > m_last_ms ? now - m_last_ms : 0;
        s.total_ms   = now > m_start_ms ? now - m_start_ms : 0;
        s.rate_per_s = s.elapsed_ms > 0
                           ? (static_cast<double>(s.delta) * 1000.0
                              / static_cast<double>(s.elapsed_ms))
                           : 0.0;
        m_last_units = units;
        m_last_ms    = now;
        return s;
    }

    /// ETA for `remaining` units at the sample's rate. nullopt (printed `n/a`)
    /// when the window carried no progress — "cannot say" is a different
    /// statement from "zero seconds".
    static std::optional<double> eta_s(const Sample& s, uint64_t remaining)
    {
        if (s.rate_per_s <= 0.0) return std::nullopt;
        return static_cast<double>(remaining) / s.rate_per_s;
    }

    /// done fraction in percent, 0 when the target is not yet known.
    static double done_pct(uint64_t done, uint64_t total)
    {
        if (total == 0) return 0.0;
        return 100.0 * static_cast<double>(done) / static_cast<double>(total);
    }

private:
    uint64_t m_every_units{500};
    int64_t  m_every_ms{30000};
    bool     m_started{false};
    int64_t  m_start_ms{0};
    uint64_t m_last_units{0};
    int64_t  m_last_ms{0};
};

/// ─────────────────────────────────────────────────────────────────────────
/// STALL WATCHDOG — polled from a path the watched lane cannot skip
/// ─────────────────────────────────────────────────────────────────────────
///
/// Contract, and the whole point of the class:
///
///   • progress(now)  — called by the lane WHENEVER its cursor actually moves.
///   • due(now)       — called by an INDEPENDENT periodic timer. Never by the
///                      lane's own drive function. If the lane stops being
///                      driven entirely, `due()` still fires; that is the
///                      2026-08-04 freeze, and it is the case this must catch
///                      FASTEST rather than not at all.
///
/// `due()` returns the elapsed-since-progress ms when a warning is owed
/// (silence longer than `stall_ms`, then once per `repeat_ms`), else nullopt.
class StallWatchdog
{
public:
    StallWatchdog() = default;
    StallWatchdog(int64_t stall_ms, int64_t repeat_ms)
        : m_stall_ms(stall_ms > 0 ? stall_ms : 1)
        , m_repeat_ms(repeat_ms > 0 ? repeat_ms : 1)
    {
    }

    /// Arm the watchdog and treat NOW as the last progress. Called when a lane
    /// starts (or re-arms) — an armed-but-never-progressed lane is exactly the
    /// "never started moving" case and must be reported, not excused.
    void arm(int64_t now)
    {
        m_armed         = true;
        m_last_progress = now;
        m_last_warn     = 0;
        m_have_warned   = false;
        m_warnings      = 0;
    }

    /// Terminal or complete: stop reporting. A published/failed-closed lane is
    /// not stalled, it is DONE, and saying "stalled" about it is noise that
    /// trains operators to ignore the tag.
    void disarm() { m_armed = false; }

    bool armed() const { return m_armed; }

    /// The lane moved. Cheap enough to call per block.
    void progress(int64_t now)
    {
        m_last_progress = now;
        m_have_warned   = false;
    }

    int64_t last_progress_ms() const { return m_last_progress; }
    uint32_t warnings() const { return m_warnings; }

    /// Elapsed silence when a warning is owed, else nullopt.
    std::optional<int64_t> due(int64_t now)
    {
        if (!m_armed) return std::nullopt;
        const int64_t elapsed = now - m_last_progress;
        if (elapsed < m_stall_ms) return std::nullopt;
        if (m_have_warned && (now - m_last_warn) < m_repeat_ms)
            return std::nullopt;
        m_last_warn   = now;
        m_have_warned = true;
        ++m_warnings;
        return elapsed;
    }

    /// Elapsed silence, whether or not a warning is owed (for status lines).
    int64_t elapsed_ms(int64_t now) const
    {
        return m_armed ? (now - m_last_progress) : 0;
    }

private:
    int64_t  m_stall_ms{120000};
    int64_t  m_repeat_ms{120000};
    bool     m_armed{false};
    int64_t  m_last_progress{0};
    int64_t  m_last_warn{0};
    bool     m_have_warned{false};
    uint32_t m_warnings{0};
};

/// ─────────────────────────────────────────────────────────────────────────
/// LOG SUPPRESSOR — collapse a repeat storm to one line + `suppressed=N`
/// ─────────────────────────────────────────────────────────────────────────
///
/// `allow(key, now)` returns true at most once per `every_ms` per key. Every
/// refused call is COUNTED, and `take_suppressed(key)` hands that count to the
/// next line that is allowed — so a storm is never silently dropped, it is
/// summarised. (2026-08-04: one site emitted 205k+ identical lines in a single
/// run and buried everything else.)
///
/// The key table is bounded: a key space that grows without limit is a leak,
/// so past `kMaxKeys` the oldest entry is evicted. Callers should therefore key
/// on the SHAPE of the line (a tag + a type), never on a per-block value.
class LogSuppressor
{
public:
    static constexpr size_t kMaxKeys = 64;

    LogSuppressor() = default;
    explicit LogSuppressor(int64_t every_ms)
        : m_every_ms(every_ms > 0 ? every_ms : 1)
    {
    }

    bool allow(const std::string& key, int64_t now)
    {
        auto it = m_keys.find(key);
        if (it == m_keys.end()) {
            if (m_keys.size() >= kMaxKeys) evict_oldest();
            m_keys.emplace(key, Entry{now, 0});
            return true;
        }
        if ((now - it->second.last_emit_ms) >= m_every_ms) {
            it->second.last_emit_ms = now;
            return true;
        }
        ++it->second.suppressed;
        return false;
    }

    /// Suppressed count since the previous allowed line, and reset it. Emit it
    /// as `suppressed=N` on the line that is allowed.
    uint64_t take_suppressed(const std::string& key)
    {
        auto it = m_keys.find(key);
        if (it == m_keys.end()) return 0;
        const uint64_t n = it->second.suppressed;
        it->second.suppressed = 0;
        return n;
    }

    uint64_t suppressed(const std::string& key) const
    {
        auto it = m_keys.find(key);
        return it == m_keys.end() ? 0 : it->second.suppressed;
    }

private:
    struct Entry
    {
        int64_t  last_emit_ms{0};
        uint64_t suppressed{0};
    };

    void evict_oldest()
    {
        auto oldest = m_keys.begin();
        for (auto it = m_keys.begin(); it != m_keys.end(); ++it)
            if (it->second.last_emit_ms < oldest->second.last_emit_ms) oldest = it;
        m_keys.erase(oldest);
    }

    int64_t m_every_ms{60000};
    std::map<std::string, Entry> m_keys;
};

/// ─────────────────────────────────────────────────────────────────────────
/// MN-LIST SOURCE — the thing that most misled us, made to say its own name
/// ─────────────────────────────────────────────────────────────────────────
///
/// A DASH node can populate its payee queue from three different places, and
/// on 2026-08-04 we believed a serve was DAEMONLESS when it was in fact riding
/// a dashd `protx list` startup seed. Only an A/B run with --coin-rpc removed
/// exposed it. Every population event now states its source, and the standing
/// status line carries the authoritative one, so "which source is backing this
/// payee queue" is never again an inference.
enum class MnSource
{
    None,         ///< nothing has populated the queue
    DashdSeed,    ///< dashd RPC `protx list registered` startup seed (mn_seed)
    MnCkpt,       ///< the release-pinned checkpoint + forward-replay bridge
    ReplayFold,   ///< a masternode-list fold produced by the block replay lane
    MnDiffRepair, ///< gap repair: list reconstructed from the MN diff store's
                  ///< stored root+payee-verified fold outputs (mn_diff_store)
    Unknown       ///< populated by a path that did not name itself: a BUG
};

inline const char* mn_source_name(MnSource s)
{
    switch (s) {
        case MnSource::None:         return "none";
        case MnSource::DashdSeed:    return "dashd-seed";
        case MnSource::MnCkpt:       return "mn-ckpt";
        case MnSource::ReplayFold:   return "replay-fold";
        case MnSource::MnDiffRepair: return "mn-diff-repair";
        case MnSource::Unknown:      return "unknown";
    }
    return "unknown";
}

/// Parse back, so a test (or a scraper) can round-trip the token.
inline MnSource mn_source_from_name(const std::string& n)
{
    if (n == "dashd-seed")     return MnSource::DashdSeed;
    if (n == "mn-ckpt")        return MnSource::MnCkpt;
    if (n == "replay-fold")    return MnSource::ReplayFold;
    if (n == "mn-diff-repair") return MnSource::MnDiffRepair;
    if (n == "none")           return MnSource::None;
    return MnSource::Unknown;
}

/// Whether a source is daemon-independent. The A/B that exposed the misreading
/// is exactly this predicate, and encoding it here means the log can state the
/// conclusion instead of leaving it to the reader.
/// MnDiffRepair qualifies: the store's rows are fold OUTPUTS, written only
/// after the engine's own root+payee self-checks — no daemon involved.
inline bool mn_source_is_daemonless(MnSource s)
{
    return s == MnSource::MnCkpt || s == MnSource::ReplayFold
        || s == MnSource::MnDiffRepair;
}

} // namespace diag
} // namespace coin
} // namespace dash
