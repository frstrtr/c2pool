// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// CUMULATIVE, CROSS-RESTART persistence for the serve-gate roll-up, plus the
/// explicit QC null-arm serve counters that make the 4.51% DKG-floor coverage
/// and the never-a-reject conjunct measurable PROGRAM-LEVEL over a standing
/// soak instead of only within a single process.
///
/// THE DEFECT THIS CLOSES (measured on hotel-primary, 2026-08-23): the
/// [EMBED-GATE-ROLLUP] denominator `observed=` equalled wall-clock since the
/// LAST restart — 7211 s at the 06:00 tick for a 04:00 restart — because
/// ServeGateJournal is deliberately pure policy (no I/O, no clock of its own)
/// and every counter it holds resets when the process does. So the gate that
/// actually matters for the dashd cut — "the null-arm covered the 4.51% DKG
/// floor with 0 rejects over a STANDING soak" — cannot be read program-level:
/// each restart zeroes the numerators and the denominator, and there is no
/// explicit null-served counter at all (null-serving is only inferable from
/// the '(was null-served)' instant-upgrade log lines, which the arm emits only
/// on the null->real transition, never on a plain null serve).
///
/// This header is the I/O layer ServeGateJournal refuses to be — kept OUT of
/// serve_gate_journal.hpp on purpose, exactly as serve_gate_rollup_json.hpp is,
/// so that header stays pure. It maintains a small JSON state file:
///
///   * load_serve_gate_state() reads the PRIOR-process totals at startup and
///     bumps restart_count (a missing OR corrupt file yields a clean zero — a
///     soak state file is a convenience, never a consensus input, so a bad
///     read must never wedge the node);
///   * combine() folds the CURRENT process's live ServeGateJournal::Rollup and
///     its live-incremented QcNullServeCounters on top of the frozen prior;
///   * save_serve_gate_state_atomic() write-throughs that combined view via a
///     temp-file + rename, so a crash mid-write can never truncate the state.
///
/// DOUBLE-COUNT SAFETY — the file holds ONLY prior-process totals, frozen at
/// the moment of load. combine() = prior + live, and `live` is the process's
/// own already-cumulative rollup / monotonic counters, so writing on EVERY
/// roll-up tick REPLACES the live part rather than adding it: N writes within
/// one process produce the identical total as one write. There is no path that
/// folds this process's contribution into `prior`, so re-saving is idempotent.

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

#include <nlohmann/json.hpp>

#include <impl/dash/coin/serve_gate_journal.hpp>

namespace dash {
namespace coin {

/// Explicit, per-LLMQ-type tallies over the DKG mining-window (required,
/// not-yet-mined) tips the null-arm governs, plus the global never-a-reject
/// conjunct. These are EVENT counts (not seconds): the current process
/// increments them live and combine() sums them onto the persisted prior.
///
/// INVARIANT (held by note()): for every type,
///     window_open[t] == null_served[t] + real_served[t] + fell_back[t].
/// A required mining-window tip is encountered exactly once and takes exactly
/// one of the three dispositions:
///   * NullServed — no verified real commitment cached AND the freshness
///                  predicate held (has_mined==false on a view proven current
///                  at pindexPrev): the byte-parity null was served, dashd's
///                  own null-then-real cadence;
///   * RealServed — a verified real commitment existed for the slot, so the
///                  null-arm was NEVER consulted (verified_for precedes
///                  null_evidence): the serve-exactness guarantee, counted;
///   * FellBack   — freshness was unproven, so the whole height failed closed
///                  to the fallback (today's benign 4.51% gap, never a reject).
struct QcNullServeCounters {
    enum class Disposition { NullServed, RealServed, FellBack };

    std::map<int, int64_t> window_open;   ///< required mining-window tips seen
    std::map<int, int64_t> null_served;   ///< served the byte-parity null
    std::map<int, int64_t> real_served;   ///< a verified real commitment existed
    std::map<int, int64_t> fell_back;     ///< freshness unproven => fail-closed

    /// The never-a-reject conjunct. submits_from_null counts block submissions
    /// whose template carried at least one null commitment; rejects_from_null
    /// counts how many the NETWORK rejected. The soak gate is
    /// rejects_from_null == 0 for submits_from_null > 0. The reject door is a
    /// consensus verdict on the whole block, not a per-LLMQ-type fact, so this
    /// pair is global, not typed.
    int64_t submits_from_null{0};
    int64_t rejects_from_null{0};

    /// Record one required mining-window tip and its disposition. Bumps
    /// window_open AND exactly one disposition, preserving the invariant above.
    void note(int llmq_type, Disposition d) {
        window_open[llmq_type] += 1;
        switch (d) {
            case Disposition::NullServed: null_served[llmq_type] += 1; break;
            case Disposition::RealServed: real_served[llmq_type] += 1; break;
            case Disposition::FellBack:   fell_back[llmq_type]   += 1; break;
        }
    }

    /// Record one block submission from a null-carrying template and whether
    /// the network rejected it. `rejected` must be false on every real soak;
    /// the counter exists so a single reject is loud and cumulative.
    void note_submit(bool rejected) {
        submits_from_null += 1;
        if (rejected) rejects_from_null += 1;
    }

    /// prior + live: sum every typed bucket and both global counters. Used by
    /// combine() to fold the live process onto the frozen persisted prior.
    void add(const QcNullServeCounters& o) {
        for (const auto& kv : o.window_open) window_open[kv.first] += kv.second;
        for (const auto& kv : o.null_served) null_served[kv.first] += kv.second;
        for (const auto& kv : o.real_served) real_served[kv.first] += kv.second;
        for (const auto& kv : o.fell_back)   fell_back[kv.first]   += kv.second;
        submits_from_null += o.submits_from_null;
        rejects_from_null += o.rejects_from_null;
    }

    static int64_t sum(const std::map<int, int64_t>& m) {
        int64_t s = 0;
        for (const auto& kv : m) s += kv.second;
        return s;
    }
    int64_t total_window_open() const { return sum(window_open); }
    int64_t total_null_served() const { return sum(null_served); }
    int64_t total_real_served() const { return sum(real_served); }
    int64_t total_fell_back()   const { return sum(fell_back); }
};

/// The ON-DISK cumulative state: prior-process roll-up totals + the null-serve
/// counters + a restart counter. combine() produces the value that is BOTH
/// persisted and printed; load/save move it through the JSON state file.
struct ServeGateCumulative {
    /// Number of processes that have contributed to this file (bumped once per
    /// load). Distinguishes "one long clean run" from "N restarts covered the
    /// floor" — the standing-soak claim needs it.
    int64_t restart_count{0};
    /// Cumulative wall clock OBSERVED across all processes (the denominator);
    /// the sum of each process's ServeGateJournal::Rollup::observed_sec.
    int64_t observed_sec{0};
    /// Cumulative seconds off the embedded arm across all processes.
    int64_t off_embedded_sec{0};
    /// Cumulative per-cause seconds across all processes.
    std::map<std::string, int64_t> cause_totals;
    /// Cumulative null-arm serve counters across all processes.
    QcNullServeCounters null_serve;
};

/// prior (frozen, from the file) + this process's live rollup and counters.
/// restart_count and every prior total ride through unchanged; only the live
/// deltas are added. Because `prior` never absorbs the live part, calling this
/// on every roll-up tick and re-saving is idempotent (replace, not add).
inline ServeGateCumulative combine(const ServeGateCumulative& prior,
                                   const ServeGateJournal::Rollup& live_time,
                                   const QcNullServeCounters& live_counters) {
    ServeGateCumulative c = prior;
    c.observed_sec     += live_time.observed_sec;
    c.off_embedded_sec += live_time.off_embedded_sec;
    for (const auto& pc : live_time.per_cause)
        c.cause_totals[pc.first] += pc.second;
    c.null_serve.add(live_counters);
    return c;
}

// ── JSON shape ──────────────────────────────────────────────────────────────
// std::map<int,int64_t> serializes as a JSON object with STRING keys ("4":13),
// the natural shape for an LLMQ-type-keyed histogram. All numeric fields are
// int64 so the denominator never silently narrows on a long soak.

inline nlohmann::json to_json(const std::map<int, int64_t>& m) {
    nlohmann::json j = nlohmann::json::object();
    for (const auto& kv : m) j[std::to_string(kv.first)] = kv.second;
    return j;
}

inline std::map<int, int64_t> int_map_from_json(const nlohmann::json& j) {
    std::map<int, int64_t> m;
    if (j.is_object())
        for (auto it = j.begin(); it != j.end(); ++it)
            m[std::stoi(it.key())] = it.value().get<int64_t>();
    return m;
}

inline nlohmann::json to_json(const QcNullServeCounters& n) {
    nlohmann::json j = nlohmann::json::object();
    j["window_open"]       = to_json(n.window_open);
    j["null_served"]       = to_json(n.null_served);
    j["real_served"]       = to_json(n.real_served);
    j["fell_back"]         = to_json(n.fell_back);
    j["submits_from_null"] = n.submits_from_null;
    j["rejects_from_null"] = n.rejects_from_null;
    return j;
}

inline QcNullServeCounters null_counters_from_json(const nlohmann::json& j) {
    QcNullServeCounters n;
    if (!j.is_object()) return n;
    if (j.contains("window_open")) n.window_open = int_map_from_json(j["window_open"]);
    if (j.contains("null_served")) n.null_served = int_map_from_json(j["null_served"]);
    if (j.contains("real_served")) n.real_served = int_map_from_json(j["real_served"]);
    if (j.contains("fell_back"))   n.fell_back   = int_map_from_json(j["fell_back"]);
    if (j.contains("submits_from_null")) n.submits_from_null = j["submits_from_null"].get<int64_t>();
    if (j.contains("rejects_from_null")) n.rejects_from_null = j["rejects_from_null"].get<int64_t>();
    return n;
}

inline nlohmann::json to_json(const ServeGateCumulative& c) {
    nlohmann::json j = nlohmann::json::object();
    j["restart_count"]    = c.restart_count;
    j["observed_sec"]     = c.observed_sec;
    j["off_embedded_sec"] = c.off_embedded_sec;
    j["cause_totals"]     = c.cause_totals;  // std::map<string,int64> -> object
    j["null_serve"]       = to_json(c.null_serve);
    return j;
}

inline ServeGateCumulative cumulative_from_json(const nlohmann::json& j) {
    ServeGateCumulative c;
    if (!j.is_object()) return c;
    if (j.contains("restart_count"))    c.restart_count    = j["restart_count"].get<int64_t>();
    if (j.contains("observed_sec"))     c.observed_sec     = j["observed_sec"].get<int64_t>();
    if (j.contains("off_embedded_sec")) c.off_embedded_sec = j["off_embedded_sec"].get<int64_t>();
    if (j.contains("cause_totals") && j["cause_totals"].is_object())
        for (auto it = j["cause_totals"].begin(); it != j["cause_totals"].end(); ++it)
            c.cause_totals[it.key()] = it.value().get<int64_t>();
    if (j.contains("null_serve")) c.null_serve = null_counters_from_json(j["null_serve"]);
    return c;
}

// ── load / atomic save ──────────────────────────────────────────────────────

/// Read the prior cumulative state from `path`. A missing OR unparseable file
/// yields a clean zero state (the soak file is a convenience, never a consensus
/// input — a bad read must not wedge the node). When `bump_restart` is true
/// (the production default: one call per process at startup) restart_count is
/// incremented, so the file records how many processes have covered the soak.
inline ServeGateCumulative load_serve_gate_state(const std::string& path,
                                                 bool bump_restart = true) {
    ServeGateCumulative c;
    std::ifstream in(path);
    if (in) {
        try {
            nlohmann::json j;
            in >> j;
            c = cumulative_from_json(j);
        } catch (...) {
            c = ServeGateCumulative{};  // corrupt => clean zero, still counted
        }
    }
    if (bump_restart) c.restart_count += 1;
    return c;
}

/// Write `c` to `path` atomically: serialize to `path + ".tmp"`, flush, then
/// rename over `path`. A crash before the rename leaves the previous good file
/// intact; a crash after leaves the new one — a reader never sees a truncated
/// state. Returns false (without touching `path`) on any I/O failure.
inline bool save_serve_gate_state_atomic(const std::string& path,
                                         const ServeGateCumulative& c) {
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::out | std::ios::trunc);
        if (!out) return false;
        out << to_json(c).dump(2) << '\n';
        out.flush();
        if (!out) {
            out.close();
            std::remove(tmp.c_str());
            return false;
        }
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(tmp.c_str());
        return false;
    }
    return true;
}

// ── operator-facing log lines ────────────────────────────────────────────────

/// The CUMULATIVE roll-up line, printed ALONGSIDE the per-process
/// [EMBED-GATE-ROLLUP] so an operator reads the standing-soak denominator, not
/// the since-last-restart one. Denominator first (a percentage whose
/// denominator is implicit is how the best-share bug shipped), then per-cause.
inline std::string cumulative_rollup_line(const ServeGateCumulative& c) {
    std::ostringstream os;
    os << "[EMBED-GATE-ROLLUP-CUM] restarts=" << c.restart_count
       << " observed=" << c.observed_sec << "s"
       << " off_embedded=" << c.off_embedded_sec << "s";
    if (c.observed_sec > 0)
        os << " (" << (c.off_embedded_sec * 100 / c.observed_sec)
           << "% of wall clock)";
    os << " causes:";
    if (c.cause_totals.empty()) {
        os << " (none)";
    } else {
        for (const auto& kv : c.cause_totals) {
            os << " " << kv.first << "=" << kv.second << "s";
            if (c.observed_sec > 0)
                os << "(" << (kv.second * 100 / c.observed_sec) << "%)";
        }
    }
    return os.str();
}

/// The [QC-NULL-SERVE] counter line: per-type window-open / null / real /
/// fell-back plus the never-a-reject conjunct. This is the line that makes
/// "the null-arm covered the DKG floor, 0 rejects" greppable across restarts.
inline std::string qc_null_serve_line(const QcNullServeCounters& n) {
    std::ostringstream os;
    os << "[QC-NULL-SERVE]"
       << " window_open=" << n.total_window_open()
       << " null=" << n.total_null_served()
       << " real=" << n.total_real_served()
       << " fell_back=" << n.total_fell_back()
       << " submits=" << n.submits_from_null
       << " rejects=" << n.rejects_from_null;
    // Per-type breakout, so a floor type that never null-served is visible.
    for (const auto& kv : n.window_open) {
        const int t = kv.first;
        os << " | type" << t << ":"
           << "win=" << kv.second
           << ",null=" << (n.null_served.count(t) ? n.null_served.at(t) : 0)
           << ",real=" << (n.real_served.count(t) ? n.real_served.at(t) : 0)
           << ",fb=" << (n.fell_back.count(t) ? n.fell_back.at(t) : 0);
    }
    return os.str();
}

}  // namespace coin
}  // namespace dash
