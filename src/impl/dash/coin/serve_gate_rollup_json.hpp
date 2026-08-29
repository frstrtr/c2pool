// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// #119 FOLLOW-UP, WEB LEG — the ONE JSON shape of the serve-gate per-cause
/// TIME roll-up.
///
/// The per-cause clock itself already lives in ServeGateJournal (Decision
/// cause_sec/prev_cause_sec, the banked m_cause_totals, rollup()) and the LOG
/// already carries it (hourly [EMBED-GATE-ROLLUP], per-segment
/// [EMBED-GATE-SEG] lines). What the operator surface still published was
/// count-shaped only: arm + the last cause/value/threshold. That is exactly
/// the count-vs-time trap #119 closed in the log (measured 2026-08-06: 109
/// dmn-stale episodes vs 3 qc-plan-underivable BY COUNT, 5.6 s vs 351 s BY
/// TIME — the prioritisation inverts depending on which number you read), so
/// the web surface must carry seconds too, WITH the denominator.
///
/// This header exists so the serializer is a single definition shared by the
/// producer (DASHWorkSource::embedded_arm_status_json) and the KAT
/// (test_dash_serve_gate_journal.cpp): a test that rebuilt the shape by hand
/// beside the producer would pin nothing. Kept OUT of serve_gate_journal.hpp
/// deliberately — that header is pure policy (no I/O, no clock, no JSON) and
/// stays that way.
///
/// Field names mirror the Rollup struct verbatim; per_cause preserves the
/// roll-up's deterministic order (seconds desc, then name), so the web array
/// ranks by TIME exactly as the log line does.

#include <nlohmann/json.hpp>

#include <impl/dash/coin/serve_gate_journal.hpp>

namespace dash {
namespace coin {

inline nlohmann::json serve_gate_rollup_json(const ServeGateJournal::Rollup& r)
{
    nlohmann::json j;
    // DENOMINATOR FIRST, always present — a per-cause seconds figure with an
    // implicit denominator is how the best-share percentage shipped.
    j["observed_sec"]     = r.observed_sec;
    j["off_embedded_sec"] = r.off_embedded_sec;
    nlohmann::json causes = nlohmann::json::array();
    for (const auto& c : r.per_cause)
        causes.push_back(nlohmann::json{{"cause", c.first}, {"sec", c.second}});
    j["per_cause"] = std::move(causes);
    return j;
}

}  // namespace coin
}  // namespace dash
