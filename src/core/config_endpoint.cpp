// SPDX-License-Identifier: AGPL-3.0-or-later
//
// src/core/config_endpoint.cpp — see config_endpoint.hpp.

#include "config_endpoint.hpp"

#include <algorithm>
#include <cctype>

namespace c2pool::config_endpoint {

namespace {

// Process-global published snapshot. Written ONCE per process by
// publish_resolved() before the node starts serving; read-only afterwards.
// Held by shared_ptr<const> so a future atomic swap (M1b) stays lock-free for
// readers that captured the previous pointer.
std::shared_ptr<const settings::ResolvedConfig> g_snapshot;
catalog::CoinBit g_coin = catalog::C_ALL;
std::string      g_settings_path;
bool             g_published = false;

const char* coin_name(catalog::CoinBit c) {
    switch (c) {
        case catalog::C_LTC:  return "ltc";
        case catalog::C_BTC:  return "btc";
        case catalog::C_DOGE: return "doge";
        case catalog::C_DASH: return "dash";
        case catalog::C_DGB:  return "dgb";
        case catalog::C_BCH:  return "bch";
        case catalog::C_NMC:  return "nmc";
        default:              return "all";
    }
}

const char* source_name(settings::Source s) {
    switch (s) {
        case settings::Source::CompiledDefault: return "compiled";
        case settings::Source::File:            return "file";
        case settings::Source::Cli:             return "cli";
        case settings::Source::Runtime:         return "runtime";
    }
    return "compiled";
}

const char* tri_name(settings::TriBool t) {
    switch (t) {
        case settings::TriBool::True:  return "true";
        case settings::TriBool::False: return "false";
        case settings::TriBool::Unset: return "unset";
    }
    return "unset";
}

// Parse a change-string into a tri interpretation for the referee check.
// Deliberately conservative: only unambiguous spellings map to True/False.
settings::TriBool parse_tri(const std::string& v) {
    std::string s;
    s.reserve(v.size());
    for (char c : v) s.push_back(static_cast<char>(std::tolower(
        static_cast<unsigned char>(c))));
    if (s == "true" || s == "1" || s == "on" || s == "yes")
        return settings::TriBool::True;
    if (s == "false" || s == "0" || s == "off" || s == "no")
        return settings::TriBool::False;
    return settings::TriBool::Unset;
}

// The pair(path,hex) partners the batch validator enforces (plan §2:
// "fold path+expect together"). Canonical keys only; symmetric lookup.
const char* pair_partner(const std::string& canon) {
    if (canon == "embedded.fold_live")        return "embedded.fold_live_expect";
    if (canon == "embedded.fold_live_expect") return "embedded.fold_live";
    if (canon == "embedded.utxo_fold_fees")   return "embedded.utxo_fold_expect";
    if (canon == "embedded.utxo_fold_expect") return "embedded.utxo_fold_fees";
    return nullptr;
}

// Effective tri value of a tristate key AFTER overlaying the batch on current.
settings::TriBool effective_tri(const std::string& canon,
                                const std::map<std::string, std::string>& changes,
                                const settings::ResolvedConfig& current) {
    auto it = changes.find(canon);
    if (it != changes.end()) return parse_tri(it->second);
    return current.get_tri(canon);
}

} // namespace

void publish_resolved(std::shared_ptr<const settings::ResolvedConfig> snapshot,
                      catalog::CoinBit coin,
                      std::string settings_path) {
    g_snapshot       = std::move(snapshot);
    g_coin           = coin;
    g_settings_path  = std::move(settings_path);
    g_published      = (g_snapshot != nullptr);
}

bool is_published() { return g_published && g_snapshot != nullptr; }

nlohmann::json resolved_config_json() {
    if (!is_published()) {
        return nlohmann::json{
            {"error", "config not published"},
            {"schema_version", kSchemaVersion}};
    }
    const settings::ResolvedConfig& rc = *g_snapshot;

    nlohmann::json keys = nlohmann::json::object();
    for (const auto& row : catalog::all_params()) {
        if (!row.applies_to(g_coin)) continue;

        nlohmann::json entry = nlohmann::json::object();
        entry["type"]        = catalog::ptype_name(row.type);
        entry["section"]     = catalog::section_name(row.section);
        entry["mutability"]  = catalog::mut_name(row.mutability);
        entry["money"]       = row.is_money();
        // pending_restart is always false this pass: nothing is staged, and the
        // published snapshot is the launch resolution (M1b stages restart keys).
        entry["pending_restart"] = false;

        // Source: present keys carry their layer; absent keys are pure compiled
        // defaults (reported as "compiled").
        auto src = rc.source_of(row.canon);
        entry["source"] = src ? source_name(*src) : "compiled";

        if (row.type == catalog::PType::TRISTATE_BOOL) {
            // Honest tri; NEVER collapsed. Posture-resolved effective lever
            // values are an M1b follow-up, not faked here.
            entry["tri"] = tri_name(rc.get_tri(row.canon));
        } else {
            auto v = rc.get_string(row.canon);
            entry["value"] = v ? *v : std::string();
        }
        keys[row.canon] = std::move(entry);
    }

    return nlohmann::json{
        {"coin",           coin_name(g_coin)},
        {"schema_version", kSchemaVersion},
        {"settings_path",  g_settings_path},
        // The endpoint reports the resolved LAUNCH config, not live node state.
        {"scope",          "resolved launch config"},
        {"apply_armed",    false},   // POST /api/config/apply is inert (503).
        {"keys",           std::move(keys)},
    };
}

nlohmann::json catalog_schema_json() {
    nlohmann::json params = nlohmann::json::array();
    for (const auto& row : catalog::all_params()) {
        nlohmann::json applies = nlohmann::json::array();
        static const catalog::CoinBit kBits[] = {
            catalog::C_LTC, catalog::C_BTC, catalog::C_DOGE, catalog::C_DASH,
            catalog::C_DGB, catalog::C_BCH, catalog::C_NMC};
        for (auto b : kBits)
            if (row.applies_to(b)) applies.push_back(coin_name(b));

        nlohmann::json aliases = nlohmann::json::array();
        for (const auto& a : row.aliases) {
            aliases.push_back(nlohmann::json{
                {"bin",      catalog::bin_name(a.binary)},
                {"spelling", a.spelling},
                {"style",    static_cast<int>(a.style)}});
        }

        params.push_back(nlohmann::json{
            {"canon",     row.canon},
            {"section",   catalog::section_name(row.section)},
            {"type",      catalog::ptype_name(row.type)},
            {"mutability", catalog::mut_name(row.mutability)},
            {"money",     row.is_money()},
            {"readonly",  row.is_compile_readonly()},
            {"applies",   std::move(applies)},
            {"default",   row.default_literal},
            {"validator", static_cast<int>(row.validator)},
            {"help",      row.help},
            {"aliases",   std::move(aliases)},
        });
    }
    return nlohmann::json{
        {"schema_version", kSchemaVersion},
        {"coin",           is_published() ? coin_name(g_coin) : "all"},
        {"params",         std::move(params)},
    };
}

// ---------------------------------------------------------------------------
// DORMANT apply oracle (pure; not wired to HTTP).
// ---------------------------------------------------------------------------
const char* batch_verdict_name(BatchVerdict v) {
    switch (v) {
        case BatchVerdict::Ok:                  return "ok";
        case BatchVerdict::RejectUnknownKey:    return "unknown_key";
        case BatchVerdict::RejectReadonly:      return "readonly";
        case BatchVerdict::RejectPairRequired:  return "pair_required";
        case BatchVerdict::RejectRefereeDisarm: return "referee_disarm";
        case BatchVerdict::RejectValidator:     return "validator";
    }
    return "?";
}

namespace {
BatchResult reject(BatchVerdict v, std::string key, std::string msg) {
    BatchResult r;
    r.verdict       = v;
    r.offending_key = std::move(key);
    r.message       = std::move(msg);
    return r;
}
} // namespace

BatchResult validate_apply_batch(const std::map<std::string, std::string>& changes,
                                 catalog::CoinBit coin,
                                 const settings::ResolvedConfig& current) {
    BatchResult r;

    // Pass 1: per-key catalog checks (unknown / not-applicable / readonly),
    // and partition by mutability class. Atomic: the first failure rejects the
    // whole batch (nothing is applied regardless).
    for (const auto& [canon, value] : changes) {
        const catalog::ParamRow* row = catalog::find_by_canon(canon);
        if (!row || !row->applies_to(coin))
            return reject(BatchVerdict::RejectUnknownKey, canon,
                          "unknown or not-applicable canonical key");
        if (row->is_compile_readonly())
            return reject(BatchVerdict::RejectReadonly, canon,
                          "compile-time read-only key cannot be written");

        if (row->is_money())               r.money_keys.push_back(canon);
        else if (row->mutability == catalog::Mut::RESTART)
                                           r.restart_keys.push_back(canon);
        else                               r.live_keys.push_back(canon);
        (void)value;
    }

    // Pass 2: pair-required — a pair(path,hex) half must arrive with its
    // partner, unless the partner is already set in the current resolution.
    for (const auto& [canon, value] : changes) {
        const char* partner = pair_partner(canon);
        if (!partner) continue;
        const bool partner_in_batch = changes.count(partner) != 0;
        const bool partner_present  = current.has(partner);
        if (!partner_in_batch && !partner_present)
            return reject(BatchVerdict::RejectPairRequired, canon,
                          std::string("requires its partner key '") + partner + "'");
        (void)value;
    }

    // Pass 3: referee invariant (the core-level mirror of
    // resolve_good_citizen_tx_serve; a KAT cross-checks the two agree). Serving
    // the mempool with the serve-time self-validation referee explicitly
    // disarmed is unsupported-config: REFUSE. Effective = batch overlaid on
    // current.
    const settings::TriBool serve =
        effective_tri("embedded.serve_mempool_txs", changes, current);
    const settings::TriBool own_set =
        effective_tri("embedded.tx_serve_own_set", changes, current);
    if (serve == settings::TriBool::True && own_set == settings::TriBool::False)
        return reject(BatchVerdict::RejectRefereeDisarm, "embedded.tx_serve_own_set",
                      "serving mempool txs with the self-validation referee "
                      "disarmed is unsupported-config");

    // applied stays false: the write path is not armed this pass.
    r.applied = false;
    return r;
}

void ParamApplier::register_setter(const std::string& canon, Setter fn) {
    setters_[canon] = std::move(fn);
}
bool ParamApplier::has(const std::string& canon) const {
    return setters_.count(canon) != 0;
}

} // namespace c2pool::config_endpoint
