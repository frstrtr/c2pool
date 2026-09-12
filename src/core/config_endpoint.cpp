// SPDX-License-Identifier: AGPL-3.0-or-later
//
// src/core/config_endpoint.cpp — see config_endpoint.hpp.

#include "config_endpoint.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <random>

#include "address_validator.hpp"

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

// Guards every access to the process-global gate state below (snapshot swap,
// control token, pending nonces, tripwire). Web threads read the snapshot and
// the armed apply path swaps it, so the previously lock-free read is now
// serialized behind this mutex.
std::mutex g_mu;

// Slice A gate state (all under g_mu).
std::string                                   g_control_token;   // empty => not armed
std::map<std::string, std::string>            g_pending_nonces;  // diff-digest -> nonce
std::map<std::string, int64_t>                g_nonce_issued_at; // diff-digest -> epoch s
TripwireState                                 g_tripwire;
ParamApplier                                  g_applier;

// Single-use nonce TTL. Generous; only guards against unbounded staleness.
constexpr int64_t kNonceTtlSeconds = 600;

int64_t now_epoch_s() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

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

// Schema/type validation of a single value against its catalog row. Returns
// true when the value is well-formed for the row's type + declared validator;
// on failure `err` names the reason. ADDR_COIN is NOT checked here — address
// validity is a money-path gate (AddressValidator) applied only after the
// two-phase nonce confirms, never on the cheap schema pass.
bool validate_value(const catalog::ParamRow& row, const std::string& value,
                    std::string& err) {
    using catalog::PType;
    using catalog::Validator;

    auto is_int = [](const std::string& s, long long& out) -> bool {
        if (s.empty()) return false;
        try { size_t pos = 0; out = std::stoll(s, &pos); return pos == s.size(); }
        catch (...) { return false; }
    };
    auto is_dbl = [](const std::string& s, double& out) -> bool {
        if (s.empty()) return false;
        try { size_t pos = 0; out = std::stod(s, &pos); return pos == s.size(); }
        catch (...) { return false; }
    };
    auto is_bool_word = [](const std::string& v) -> bool {
        std::string s;
        for (char c : v) s.push_back(static_cast<char>(std::tolower(
            static_cast<unsigned char>(c))));
        return s == "true" || s == "false" || s == "1" || s == "0" ||
               s == "on"   || s == "off"   || s == "yes" || s == "no";
    };
    auto is_even_hex = [](const std::string& s) -> bool {
        if (s.empty() || (s.size() % 2) != 0) return false;
        for (char c : s) if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
        return true;
    };

    long long iv = 0;
    double dv = 0.0;
    switch (row.type) {
        case PType::BOOL:
        case PType::TRISTATE_BOOL:
            if (!is_bool_word(value)) { err = "expected a boolean"; return false; }
            return true;
        case PType::UINT16:
            if (!is_int(value, iv) || iv < 0 || iv > 65535) {
                err = "expected an integer in [0,65535]"; return false; }
            return true;
        case PType::INT64:
            if (!is_int(value, iv)) { err = "expected an integer"; return false; }
            return true;
        case PType::DBL:
            if (!is_dbl(value, dv)) { err = "expected a number"; return false; }
            break;
        case PType::HEX:
            if (!value.empty() && !is_even_hex(value)) {
                err = "expected even-length hex"; return false; }
            break;
        case PType::ENUM_STR:
            if (value.empty()) { err = "enum value must be non-empty"; return false; }
            break;
        default:
            break;  // STRING/PATH/HOSTPORT/etc: shape checked by the money gate or accepted
    }

    // Declared per-key validators that are cheap + local (no coin decoder).
    switch (row.validator) {
        case Validator::PORT_RANGE:
            if (!is_int(value, iv) || iv < 0 || iv > 65535) {
                err = "port must be in [0,65535]"; return false; }
            break;
        case Validator::PCT_0_100:
            if (!is_dbl(value, dv) || dv < 0.0 || dv > 100.0) {
                err = "percent must be in [0,100]"; return false; }
            break;
        case Validator::HEX_EVEN:
        case Validator::HEX8_MAGIC:
            if (!value.empty() && !is_even_hex(value)) {
                err = "expected even-length hex"; return false; }
            if (row.validator == Validator::HEX8_MAGIC && !value.empty() && value.size() != 8) {
                err = "magic must be 8 hex chars"; return false; }
            break;
        case Validator::HASH256:
            if (!value.empty() && (value.size() != 64 || !is_even_hex(value))) {
                err = "expected a 32-byte (64-hex) hash"; return false; }
            break;
        default:
            break;
    }
    return true;
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
    std::lock_guard<std::mutex> lk(g_mu);
    g_snapshot       = std::move(snapshot);
    g_coin           = coin;
    g_settings_path  = std::move(settings_path);
    g_published      = (g_snapshot != nullptr);
}

bool is_published() {
    std::lock_guard<std::mutex> lk(g_mu);
    return g_published && g_snapshot != nullptr;
}

nlohmann::json resolved_config_json() {
    // Capture the snapshot under the lock so a concurrent armed apply that
    // swaps g_snapshot cannot free the object out from under this reader.
    std::shared_ptr<const settings::ResolvedConfig> snap;
    catalog::CoinBit coin;
    std::string      settings_path;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        snap = g_snapshot;
        coin = g_coin;
        settings_path = g_settings_path;
    }
    if (!snap) {
        return nlohmann::json{
            {"error", "config not published"},
            {"schema_version", kSchemaVersion}};
    }
    const settings::ResolvedConfig& rc = *snap;

    nlohmann::json keys = nlohmann::json::object();
    for (const auto& row : catalog::all_params()) {
        if (!row.applies_to(coin)) continue;

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
        {"coin",           coin_name(coin)},
        {"schema_version", kSchemaVersion},
        {"settings_path",  settings_path},
        // The endpoint reports the resolved LAUNCH config, not live node state.
        {"scope",          "resolved launch config"},
        // apply_armed reflects whether an operator has registered the control
        // token: false (dormant, 503) until arming, true once armed (Slice A).
        {"apply_armed",    has_control_token()},
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

        std::string verr;
        if (!validate_value(*row, value, verr))
            return reject(BatchVerdict::RejectValidator, canon, verr);

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
bool ParamApplier::invoke(const std::string& canon, const std::string& value) const {
    auto it = setters_.find(canon);
    if (it == setters_.end() || !it->second) return false;
    return it->second(value);
}

// ---------------------------------------------------------------------------
// Slice A (#157): control token, two-phase money nonce, tripwire, armed apply.
// ---------------------------------------------------------------------------
namespace {

// A random 128-bit hex token/nonce from a per-thread PRNG seeded off the OS
// entropy source. Not a secret store — a loopback-only unguessable handle.
std::string random_hex_128() {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    uint64_t a = rng(), b = rng();
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx",
                  static_cast<unsigned long long>(a),
                  static_cast<unsigned long long>(b));
    return std::string(buf, 32);
}

// Constant-time-ish string compare (avoids trivial early-out timing on the
// loopback token; defense in depth, the endpoint is loopback-only anyway).
bool ct_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char acc = 0;
    for (size_t i = 0; i < a.size(); ++i)
        acc |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    return acc == 0;
}

} // namespace

void set_control_token(std::string token) {
    std::lock_guard<std::mutex> lk(g_mu);
    g_control_token = std::move(token);
}
bool has_control_token() {
    std::lock_guard<std::mutex> lk(g_mu);
    return !g_control_token.empty();
}
bool check_control_token(const std::string& presented) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_control_token.empty()) return false;
    return ct_equal(presented, g_control_token);
}
void clear_control_token() {
    std::lock_guard<std::mutex> lk(g_mu);
    g_control_token.clear();
}

TripwireState tripwire_state() {
    std::lock_guard<std::mutex> lk(g_mu);
    return g_tripwire;
}
void reset_tripwire() {
    std::lock_guard<std::mutex> lk(g_mu);
    g_tripwire = TripwireState{};
}
// Internal: record a tripwire fire. Assumes g_mu is NOT held by the caller.
namespace {
void trip_money_wire(const std::string& key, const std::string& reason) {
    std::lock_guard<std::mutex> lk(g_mu);
    ++g_tripwire.count;
    g_tripwire.last_key    = key;
    g_tripwire.last_reason = reason;
}
} // namespace

ParamApplier& applier() { return g_applier; }

std::string money_diff_digest(const std::map<std::string, std::string>& money_changes) {
    std::vector<std::pair<std::string, std::string>> kv(
        money_changes.begin(), money_changes.end());
    return settings::SettingsFile::money_digest(kv);
}

std::string issue_money_nonce(const std::map<std::string, std::string>& money_changes) {
    const std::string digest = money_diff_digest(money_changes);
    std::string nonce = random_hex_128();
    std::lock_guard<std::mutex> lk(g_mu);
    g_pending_nonces[digest]  = nonce;
    g_nonce_issued_at[digest] = now_epoch_s();
    return nonce;
}

bool verify_money_nonce(const std::map<std::string, std::string>& money_changes,
                        const std::string& presented) {
    if (presented.empty()) return false;
    const std::string digest = money_diff_digest(money_changes);
    std::lock_guard<std::mutex> lk(g_mu);
    auto it = g_pending_nonces.find(digest);
    if (it == g_pending_nonces.end()) return false;
    // TTL: a stale nonce is refused (and swept).
    auto ta = g_nonce_issued_at.find(digest);
    if (ta != g_nonce_issued_at.end() &&
        now_epoch_s() - ta->second > kNonceTtlSeconds) {
        g_pending_nonces.erase(it);
        g_nonce_issued_at.erase(ta);
        return false;
    }
    const bool match = ct_equal(presented, it->second);
    if (match) {                       // single-use: consume on success
        g_pending_nonces.erase(it);
        g_nonce_issued_at.erase(digest);
    }
    return match;
}

void clear_money_nonces() {
    std::lock_guard<std::mutex> lk(g_mu);
    g_pending_nonces.clear();
    g_nonce_issued_at.clear();
}

const char* apply_status_name(ApplyStatus s) {
    switch (s) {
        case ApplyStatus::NotArmed:         return "not_armed";
        case ApplyStatus::NotPublished:     return "not_published";
        case ApplyStatus::RejectNoToken:    return "no_token";
        case ApplyStatus::RejectValidation: return "validation";
        case ApplyStatus::NeedConfirm:      return "need_confirm";
        case ApplyStatus::RejectMoneyGate:  return "money_gate";
        case ApplyStatus::Applied:          return "applied";
    }
    return "?";
}

nlohmann::json ApplyResponse::to_json() const {
    nlohmann::json j{
        {"schema_version", kSchemaVersion},
        {"status",         apply_status_name(status)},
        {"applied",        status == ApplyStatus::Applied},
        {"armed",          status != ApplyStatus::NotArmed},
    };
    if (!message.empty())       j["error"]         = message;   // human cause
    if (!offending_key.empty()) j["offending_key"] = offending_key;
    if (status == ApplyStatus::NeedConfirm) {
        j["need_confirm"] = true;
        j["money_nonce"]  = money_nonce;
        j["money_keys"]   = money_keys;
    }
    if (status == ApplyStatus::Applied)
        j["applied_keys"] = applied_keys;
    return j;
}

ApplyRequest parse_apply_request(const std::string& body) {
    ApplyRequest req;
    nlohmann::json j = nlohmann::json::parse(body, nullptr, /*allow_exceptions=*/false);
    if (!j.is_object()) return req;
    if (j.contains("control_token") && j["control_token"].is_string())
        req.control_token = j["control_token"].get<std::string>();
    if (j.contains("money_nonce") && j["money_nonce"].is_string())
        req.money_nonce = j["money_nonce"].get<std::string>();
    if (j.contains("changes") && j["changes"].is_object()) {
        for (auto it = j["changes"].begin(); it != j["changes"].end(); ++it) {
            if (it.value().is_string())
                req.changes[it.key()] = it.value().get<std::string>();
            else if (it.value().is_boolean())
                req.changes[it.key()] = it.value().get<bool>() ? "true" : "false";
            else if (it.value().is_number())
                req.changes[it.key()] = it.value().dump();
        }
    }
    return req;
}

ApplyResponse apply_config(const ApplyRequest& req) {
    ApplyResponse out;

    // 0) Armed? No control token registered => stay dormant (503 armed:false).
    //    This is the KAT pivot: the endpoint is INERT until an operator arms it
    //    by registering the loopback control token — never a silent default.
    if (!has_control_token()) {
        out.status = ApplyStatus::NotArmed;
        out.http_status = 503;
        out.message = "config-apply not armed; runtime mutation is operator-gated";
        return out;
    }

    // 1) A published snapshot is the apply base + reporting mirror.
    if (!is_published()) {
        out.status = ApplyStatus::NotPublished;
        out.http_status = 503;
        out.message = "config not published";
        return out;
    }

    // 2) Control token (loopback defense-in-depth; the HTTP layer also gates).
    if (!check_control_token(req.control_token)) {
        out.status = ApplyStatus::RejectNoToken;
        out.http_status = 403;
        out.message = "missing or invalid control token";
        return out;
    }

    if (req.changes.empty()) {
        out.status = ApplyStatus::RejectValidation;
        out.http_status = 400;
        out.message = "no changes requested";
        return out;
    }

    // Capture the base snapshot + coin under the lock.
    std::shared_ptr<const settings::ResolvedConfig> base;
    catalog::CoinBit coin;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        base = g_snapshot;
        coin = g_coin;
    }

    // 3) Schema + batch + referee validation (pure oracle, atomic — one bad
    //    key rejects the WHOLE batch, so nothing is applied partially).
    BatchResult batch = validate_apply_batch(req.changes, coin, *base);
    if (!batch.ok()) {
        out.status = ApplyStatus::RejectValidation;
        out.http_status = 400;
        out.message = batch.message;
        out.offending_key = batch.offending_key;
        return out;
    }

    // 4) MONEY-PATH GATE (two-phase nonce + AddressValidator + tripwire).
    if (!batch.money_keys.empty()) {
        std::map<std::string, std::string> money_diff;
        for (const auto& k : batch.money_keys) money_diff[k] = req.changes.at(k);

        // Phase 1 (no nonce): issue a nonce bound to THIS exact diff and apply
        // NOTHING. This is the sanctioned confirmation request — the tripwire
        // does NOT fire here (it is not an attempt to write without a nonce).
        if (req.money_nonce.empty()) {
            out.status = ApplyStatus::NeedConfirm;
            out.http_status = 200;
            out.money_nonce = issue_money_nonce(money_diff);
            out.money_keys = batch.money_keys;
            out.message = "money-path change requires confirmation; re-POST the "
                          "same diff with this money_nonce";
            return out;
        }

        // Phase 2: the presented nonce MUST match the one issued for THIS exact
        // diff. A miss (wrong/expired nonce, or a different diff) trips the
        // wire and refuses — no partial apply.
        if (!verify_money_nonce(money_diff, req.money_nonce)) {
            trip_money_wire(batch.money_keys.front(),
                            "money-path write without a valid confirmed nonce");
            out.status = ApplyStatus::RejectMoneyGate;
            out.http_status = 409;
            out.offending_key = batch.money_keys.front();
            out.message = "money nonce missing or mismatched for this diff; refused";
            return out;
        }

        // Server-side AddressValidator on any address-typed money value
        // (fail-closed: an unparseable address refuses + trips the wire).
        for (const auto& k : batch.money_keys) {
            const catalog::ParamRow* row = catalog::find_by_canon(k);
            if (!row || row->validator != catalog::Validator::ADDR_COIN) continue;
            const std::string& addr = money_diff.at(k);
            if (addr.empty()) continue;  // clearing an address is not an address
            c2pool::address::BlockchainAddressValidator av;
            auto res = av.validate_address_multi(addr);
            if (!res.is_valid) {
                trip_money_wire(k, "money-path address failed server-side validation");
                out.status = ApplyStatus::RejectMoneyGate;
                out.http_status = 409;
                out.offending_key = k;
                out.message = "address failed server-side validation: " +
                              res.error_message;
                return out;
            }
        }
    }

    // 5) APPLY. Atomic snapshot swap (never mutate the published snapshot in
    //    place — a web reader may hold the old pointer) + registered setters.
    //    This swaps the reporting mirror behind GET /api/config and calls any
    //    registered ParamApplier setter; it NEVER touches coinbase/subsidy/
    //    PPLNS/payee computation and never arms --embedded-tx-inject (Slice B).
    {
        std::lock_guard<std::mutex> lk(g_mu);
        auto next = std::make_shared<settings::ResolvedConfig>(*g_snapshot);
        for (const auto& [canon, value] : req.changes) {
            const catalog::ParamRow* row = catalog::find_by_canon(canon);
            if (row && row->type == catalog::PType::TRISTATE_BOOL)
                next->set_tri(canon, parse_tri(value), settings::Source::Runtime);
            else
                next->set(canon, value, settings::Source::Runtime);
        }
        g_snapshot = std::move(next);
    }
    // Invoke live setters OUTSIDE the lock (a setter must never re-enter the
    // gate). Empty by default => a bare apply is a mirror swap only.
    for (const auto& [canon, value] : req.changes)
        (void)g_applier.invoke(canon, value);

    for (const auto& [canon, value] : req.changes) { out.applied_keys.push_back(canon); (void)value; }
    out.status = ApplyStatus::Applied;
    out.http_status = 200;
    out.message.clear();
    return out;
}

} // namespace c2pool::config_endpoint
