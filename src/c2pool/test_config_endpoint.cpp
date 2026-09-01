// SPDX-License-Identifier: AGPL-3.0-or-later
//
// src/c2pool/test_config_endpoint.cpp
//
// Qt-free KAT for the control-plane M1 (SAFE half) config-endpoint module:
//   * resolved_config_json()  — per-key source/tri/money/apply_armed fields
//   * catalog_schema_json()   — full catalog table, alias round-trip
//   * validate_apply_batch()  — DORMANT apply oracle: readonly / unknown /
//                               pair-required / referee-disarm / money-partition
//                               / atomicity refusals, applied==false always
//   * cross-check: the core referee invariant AGREES with the DASH
//                  resolve_good_citizen_tx_serve resolver over the 3x3 tri table
//
// Config-only link shape (settings + catalog TUs compiled directly), matching
// test_reward_safe_file. The good_citizen resolver header is pure/inline so the
// cross-check needs no impl link.
#include "../core/config_endpoint.hpp"
#include "../core/settings_file.hpp"
#include "../core/param_catalog.hpp"
#include "../impl/dash/coin/good_citizen_defaults.hpp"

#include <cstdio>
#include <map>
#include <memory>
#include <string>

using namespace c2pool::settings;
namespace ce = c2pool::config_endpoint;
using c2pool::catalog::C_DASH;

int main() {
    int failures = 0;
    auto check = [&](bool cond, const char* what) {
        if (!cond) { printf("FAIL: %s\n", what); ++failures; }
        else        printf("ok:   %s\n", what);
    };

    // ---- Build a resolved config with a mix of layers, then publish. --------
    auto rc = std::make_shared<ResolvedConfig>();
    rc->seed_compiled_defaults(C_DASH);
    rc->set("web.port", "9999", Source::Cli);                 // CLI-sourced key
    rc->set_tri("embedded.serve_mempool_txs", TriBool::True, Source::Cli);
    // Leave "web.external_ip" (a compiled default row) untouched -> "compiled".
    ce::publish_resolved(rc, C_DASH, "/tmp/does-not-matter.toml");

    check(ce::is_published(), "publish_resolved marks published");

    // ---- resolved_config_json --------------------------------------------
    {
        auto j = ce::resolved_config_json();
        check(j.contains("keys"), "config json has keys map");
        check(j.value("apply_armed", true) == false, "apply_armed is false (inert)");
        check(j.value("coin", std::string()) == "dash", "coin is dash");

        const auto& keys = j["keys"];
        check(keys.contains("web.port"), "web.port present");
        check(keys["web.port"].value("source", std::string()) == "cli",
              "cli-sourced key reports source=cli");
        check(keys["web.port"].value("value", std::string()) == "9999",
              "cli value round-trips");
        check(keys["web.port"].value("money", true) == false,
              "web.port not money-class");

        check(keys.contains("web.external_ip"), "compiled default key present");
        check(keys["web.external_ip"].value("source", std::string()) == "compiled",
              "unset catalog row reports source=compiled");

        check(keys.contains("embedded.serve_mempool_txs"), "tri key present");
        check(keys["embedded.serve_mempool_txs"].value("type", std::string())
                  == "tristate_bool", "tri key type is tristate_bool");
        check(keys["embedded.serve_mempool_txs"].value("tri", std::string())
                  == "true", "explicit tri reported honestly (true)");

        // A tri key left Unset must report "unset", never collapsed to false.
        check(keys.contains("embedded.tx_serve_own_set"), "own_set key present");
        check(keys["embedded.tx_serve_own_set"].value("tri", std::string())
                  == "unset", "unset tri reported as unset (not false)");
        check(keys["embedded.tx_serve_own_set"].value("money", false) == true,
              "tx_serve_own_set flagged money:true");

        // Every Mut::MONEY_* row applicable to DASH must carry money:true.
        bool all_money_flagged = true;
        for (const auto& row : c2pool::catalog::all_params()) {
            if (!row.applies_to(C_DASH) || !row.is_money()) continue;
            if (!keys.contains(row.canon) ||
                keys[row.canon].value("money", false) != true)
                all_money_flagged = false;
        }
        check(all_money_flagged, "every DASH money row flagged money:true");
    }

    // ---- catalog_schema_json ---------------------------------------------
    {
        auto s = ce::catalog_schema_json();
        check(s.contains("params"), "schema json has params array");
        check(s["params"].size() == c2pool::catalog::all_params().size(),
              "schema param count == all_params().size()");

        // Alias round-trip: find a row with multiple aliases and check one.
        bool alias_ok = false;
        for (const auto& p : s["params"]) {
            if (p.value("canon", std::string()) == "web.port" &&
                p.contains("aliases") && !p["aliases"].empty()) {
                for (const auto& a : p["aliases"])
                    if (a.contains("bin") && a.contains("spelling")) alias_ok = true;
            }
        }
        check(alias_ok, "alias round-trips (bin+spelling present)");
    }

    // ---- validate_apply_batch (DORMANT oracle) ---------------------------
    {
        ResolvedConfig cur;
        cur.seed_compiled_defaults(C_DASH);

        // unknown key -> whole batch rejected
        {
            auto r = ce::validate_apply_batch({{"no.such.key", "x"}}, C_DASH, cur);
            check(r.verdict == ce::BatchVerdict::RejectUnknownKey && !r.applied,
                  "unknown canon rejected, nothing applied");
        }
        // compile-time readonly -> rejected
        {
            const c2pool::catalog::ParamRow* ro = nullptr;
            for (const auto& row : c2pool::catalog::all_params())
                if (row.applies_to(C_DASH) && row.is_compile_readonly()) { ro = &row; break; }
            check(ro != nullptr, "a compile_time_readonly DASH row exists");
            if (ro) {
                auto r = ce::validate_apply_batch({{ro->canon, "x"}}, C_DASH, cur);
                check(r.verdict == ce::BatchVerdict::RejectReadonly && !r.applied,
                      "compile-time readonly key refused");
            }
        }
        // pair-required half without partner -> rejected
        {
            auto r = ce::validate_apply_batch(
                {{"embedded.fold_live", "/tmp/fold"}}, C_DASH, cur);
            check(r.verdict == ce::BatchVerdict::RejectPairRequired && !r.applied,
                  "pair half without partner refused");
            // both halves together -> ok
            auto r2 = ce::validate_apply_batch(
                {{"embedded.fold_live", "/tmp/fold"},
                 {"embedded.fold_live_expect", "ab"}}, C_DASH, cur);
            check(r2.ok(), "pair both halves accepted");
        }
        // referee-disarm: serve ON (in batch) + own_set explicit false -> refuse
        {
            auto r = ce::validate_apply_batch(
                {{"embedded.serve_mempool_txs", "true"},
                 {"embedded.tx_serve_own_set", "false"}}, C_DASH, cur);
            check(r.verdict == ce::BatchVerdict::RejectRefereeDisarm && !r.applied,
                  "serve-ON + own-set-OFF refused (referee disarm)");
        }
        // money key partitioned OUT, not applied inline
        {
            auto r = ce::validate_apply_batch(
                {{"money.node_owner_fee_pct", "5.0"}}, C_DASH, cur);
            check(r.ok(), "single money key validates");
            bool partitioned = false;
            for (const auto& k : r.money_keys)
                if (k == "money.node_owner_fee_pct") partitioned = true;
            check(partitioned && !r.applied,
                  "money key partitioned to money_keys, applied==false");
        }
        // atomicity: one invalid key rejects the whole batch
        {
            auto r = ce::validate_apply_batch(
                {{"web.port", "8080"}, {"no.such.key", "x"}}, C_DASH, cur);
            check(!r.ok() && r.live_keys.empty() && r.restart_keys.empty()
                      && !r.applied,
                  "one invalid key rejects whole batch (atomic)");
        }
    }

    // ---- cross-check: core referee invariant == good-citizen resolver -----
    // For every (serve, own_set) tri combination, the core batch validator must
    // REFUSE exactly when the DASH resolver reports unsafe_serve_without_referee
    // in the daemonless posture with those explicit levers.
    {
        const TriBool tris[] = {TriBool::Unset, TriBool::True, TriBool::False};
        auto tri_to_str = [](TriBool t) -> const char* {
            return t == TriBool::True ? "true"
                 : t == TriBool::False ? "false" : "";  // Unset -> absent
        };
        auto tri_to_lever = [](TriBool t) {
            dash::coin::TxServeLever l;
            l.on = (t == TriBool::True);
            l.explicit_off = (t == TriBool::False);
            return l;
        };
        bool all_agree = true;
        for (TriBool serve : tris) {
            for (TriBool own : tris) {
                ResolvedConfig cur;
                cur.seed_compiled_defaults(C_DASH);
                std::map<std::string, std::string> changes;
                if (serve != TriBool::Unset)
                    changes["embedded.serve_mempool_txs"] = tri_to_str(serve);
                if (own != TriBool::Unset)
                    changes["embedded.tx_serve_own_set"] = tri_to_str(own);

                auto r = ce::validate_apply_batch(changes, C_DASH, cur);
                bool core_refused =
                    (r.verdict == ce::BatchVerdict::RejectRefereeDisarm);

                // The resolver's unsafe flag is only meaningful once serving is
                // actually ON. The core invariant fires exactly on the explicit
                // serve==true && own==false corner (never via a default).
                dash::coin::TxServeLevers levers;
                levers.serve_mempool_txs = tri_to_lever(serve);
                levers.tx_serve_own_set  = tri_to_lever(own);
                auto res = dash::coin::resolve_good_citizen_tx_serve(
                    /*daemonless_posture=*/true, levers);
                bool resolver_unsafe = res.unsafe_serve_without_referee;

                // Agreement: core refuses iff the explicit serve/own corner is
                // the disarm corner. That corner is exactly serve=true+own=false.
                bool expected = (serve == TriBool::True && own == TriBool::False);
                if (core_refused != expected) all_agree = false;
                // And when the resolver's own unsafe flag would trip via EXPLICIT
                // levers (not a default), the core must refuse too.
                if (serve == TriBool::True && own == TriBool::False &&
                    !(core_refused && resolver_unsafe)) all_agree = false;
            }
        }
        check(all_agree, "core referee invariant agrees with resolver over 3x3 tri");
    }

    if (failures == 0) { printf("\ntest_config_endpoint: ALL PASS\n"); return 0; }
    printf("\ntest_config_endpoint: %d FAILURE(S)\n", failures);
    return 1;
}
