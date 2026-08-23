// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The ONE serialize/deserialize + atomic-file definition for
/// ServeGateLedger::Totals, kept OUT of serve_gate_ledger.hpp so that header
/// stays pure policy (no I/O, no JSON, no clock) exactly as serve_gate_journal
/// keeps its own JSON in serve_gate_rollup_json.hpp. The producer
/// (DASHWorkSource) and the KAT share this single definition, so a test cannot
/// pin a shape the producer does not emit.
///
/// Persistence contract:
///   * write-through to <data-dir>/<net_subdir>/serve_gate_ledger.json;
///   * ATOMIC — serialize to "<path>.tmp", fsync, rename over the target, so a
///     crash mid-write never leaves a half-written ledger (a torn cumulative
///     figure is worse than a stale one);
///   * schema v1 with epochs + last_writer_commit already in Totals (the
///     measurement-without-commit rule), so a blob is never read without
///     knowing which code produced it and how many process lifetimes it spans.

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

#include <nlohmann/json.hpp>

#include <impl/dash/coin/serve_gate_ledger.hpp>

namespace dash {
namespace coin {

inline nlohmann::json serve_gate_ledger_to_json(const ServeGateLedger::Totals& t)
{
    nlohmann::json j;
    j["schema_version"]     = t.schema_version;
    j["epochs"]             = t.epochs;
    j["last_writer_commit"] = t.last_writer_commit;

    j["observed_sec"]       = t.observed_sec;
    j["off_embedded_sec"]   = t.off_embedded_sec;
    nlohmann::json pc = nlohmann::json::object();
    for (const auto& kv : t.per_cause_sec) pc[kv.first] = kv.second;
    j["per_cause_sec"]      = std::move(pc);

    j["serves_embedded_real"] = t.serves_embedded_real;
    j["serves_embedded_null"] = t.serves_embedded_null;
    j["serves_fallback"]      = t.serves_fallback;
    j["serves_no_work"]       = t.serves_no_work;

    j["blocks_won_embedded_real"] = t.blocks_won_embedded_real;
    j["blocks_won_embedded_null"] = t.blocks_won_embedded_null;
    j["blocks_won_fallback"]      = t.blocks_won_fallback;
    j["blocks_submitted"]         = t.blocks_submitted;
    j["blocks_confirmed"]         = t.blocks_confirmed;
    j["blocks_orphaned"]          = t.blocks_orphaned;
    j["local_payee_guard_rejects"] = t.local_payee_guard_rejects;

    j["rpc_rejected_embedded_real"] = t.rpc_rejected_embedded_real;
    j["rpc_rejected_embedded_null"] = t.rpc_rejected_embedded_null;
    j["rpc_rejected_fallback"]      = t.rpc_rejected_fallback;
    j["orphaned_embedded_real"]     = t.orphaned_embedded_real;
    j["orphaned_embedded_null"]     = t.orphaned_embedded_null;
    nlohmann::json rr = nlohmann::json::object();
    for (const auto& kv : t.rpc_reject_reasons) rr[kv.first] = kv.second;
    j["rpc_reject_reasons"]         = std::move(rr);

    j["null_dkg_floor_tips_served"] = t.null_dkg_floor_tips_served;
    j["null_real_quorum_available_but_null_served"] =
        t.null_real_quorum_available_but_null_served;

    j["nr_span_start_height"]  = t.nr_span_start_height;
    j["nr_span_last_height"]   = t.nr_span_last_height;
    j["nr_total_rejects"]      = t.nr_total_rejects;
    j["nr_last_reject_height"] = t.nr_last_reject_height;

    j["carry_cause"] = t.carry_cause;
    j["carry_sec"]   = t.carry_sec;
    return j;
}

inline ServeGateLedger::Totals serve_gate_ledger_from_json(const nlohmann::json& j)
{
    ServeGateLedger::Totals t;
    auto u32 = [&](const char* k, uint32_t d) { return j.value(k, d); };
    auto u64 = [&](const char* k, uint64_t d) { return j.value(k, d); };
    auto i64 = [&](const char* k, int64_t d) { return j.value(k, d); };
    auto str = [&](const char* k) { return j.value(k, std::string{}); };

    t.schema_version     = u32("schema_version", ServeGateLedger::kSchemaVersion);
    t.epochs             = u64("epochs", 0);
    t.last_writer_commit = str("last_writer_commit");

    t.observed_sec     = i64("observed_sec", 0);
    t.off_embedded_sec = i64("off_embedded_sec", 0);
    if (j.contains("per_cause_sec") && j["per_cause_sec"].is_object())
        for (auto it = j["per_cause_sec"].begin(); it != j["per_cause_sec"].end(); ++it)
            t.per_cause_sec[it.key()] = it.value().get<int64_t>();

    t.serves_embedded_real = u64("serves_embedded_real", 0);
    t.serves_embedded_null = u64("serves_embedded_null", 0);
    t.serves_fallback      = u64("serves_fallback", 0);
    t.serves_no_work       = u64("serves_no_work", 0);

    t.blocks_won_embedded_real = u64("blocks_won_embedded_real", 0);
    t.blocks_won_embedded_null = u64("blocks_won_embedded_null", 0);
    t.blocks_won_fallback      = u64("blocks_won_fallback", 0);
    t.blocks_submitted         = u64("blocks_submitted", 0);
    t.blocks_confirmed         = u64("blocks_confirmed", 0);
    t.blocks_orphaned          = u64("blocks_orphaned", 0);
    t.local_payee_guard_rejects = u64("local_payee_guard_rejects", 0);

    t.rpc_rejected_embedded_real = u64("rpc_rejected_embedded_real", 0);
    t.rpc_rejected_embedded_null = u64("rpc_rejected_embedded_null", 0);
    t.rpc_rejected_fallback      = u64("rpc_rejected_fallback", 0);
    t.orphaned_embedded_real     = u64("orphaned_embedded_real", 0);
    t.orphaned_embedded_null     = u64("orphaned_embedded_null", 0);
    if (j.contains("rpc_reject_reasons") && j["rpc_reject_reasons"].is_object())
        for (auto it = j["rpc_reject_reasons"].begin(); it != j["rpc_reject_reasons"].end(); ++it)
            t.rpc_reject_reasons[it.key()] = it.value().get<uint64_t>();

    t.null_dkg_floor_tips_served = u64("null_dkg_floor_tips_served", 0);
    t.null_real_quorum_available_but_null_served =
        u64("null_real_quorum_available_but_null_served", 0);

    t.nr_span_start_height  = u64("nr_span_start_height", 0);
    t.nr_span_last_height   = u64("nr_span_last_height", 0);
    t.nr_total_rejects      = u64("nr_total_rejects", 0);
    t.nr_last_reject_height = u64("nr_last_reject_height", 0);

    t.carry_cause = str("carry_cause");
    t.carry_sec   = i64("carry_sec", 0);
    return t;
}

/// Atomic write-through: serialize `t` to `<path>.tmp`, flush+fsync, then
/// rename over `path`. Returns false on any I/O error (the caller keeps the
/// in-memory ledger; a failed flush loses at most one cadence of durations).
inline bool serve_gate_ledger_save(const std::string& path,
                                   const ServeGateLedger::Totals& t)
{
    const std::string tmp = path + ".tmp";
    {
        std::ofstream os(tmp, std::ios::binary | std::ios::trunc);
        if (!os) return false;
        os << serve_gate_ledger_to_json(t).dump(2);
        os.flush();
        if (!os) return false;
    }
    // Best-effort durability: rename is atomic on the same filesystem.
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(tmp.c_str());
        return false;
    }
    return true;
}

/// Load a persisted ledger blob. Returns false (and leaves `out` default) when
/// the file is absent or unparseable — a fresh node starts at epoch 0.
inline bool serve_gate_ledger_load(const std::string& path,
                                   ServeGateLedger::Totals& out)
{
    std::ifstream is(path, std::ios::binary);
    if (!is) return false;
    std::stringstream ss;
    ss << is.rdbuf();
    if (ss.str().empty()) return false;
    try {
        out = serve_gate_ledger_from_json(nlohmann::json::parse(ss.str()));
    } catch (...) {
        return false;
    }
    return true;
}

}  // namespace coin
}  // namespace dash
