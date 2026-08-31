// src/core/settings_file.hpp
//
// Monolithic settings-file loader for the c2pool control plane (M0).
//
// Qt-free, boost-free. Produces a typed ResolvedConfig with PER-KEY source
// tracking and a TRI-STATE for posture-affecting bool flags (Unset vs explicit
// true/false is load-bearing: the good-citizen daemonless resolver depends on
// it, so it is NEVER collapsed to bool).
//
// The four-layer precedence is:
//   L0 compiled defaults  <  L1 file  <  L2 CLI  <  L3 runtime (M1; stubbed).
//
// MONEY GATE (day one, non-negotiable): a settings FILE can never arm a
// money-class key. Every catalog row whose mutability is MONEY_* forms the
// gate key set (single source; the gate keeps no list of its own). A money-class
// key present in the file without a matching [gate].money_ack_hash is REFUSED
// (fail-closed: the node exits). Only the qt confirm dialog / the
// --ack-money-settings operator helper ever writes the hash.
#ifndef C2POOL_CORE_SETTINGS_FILE_HPP
#define C2POOL_CORE_SETTINGS_FILE_HPP

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "param_catalog.hpp"

namespace c2pool::settings {

// L0<L1<L2<L3 provenance for every resolved key.
enum class Source { CompiledDefault, File, Cli, Runtime };

// Tri-state for posture-affecting bool flags. Maps 1:1 onto the DASH
// TxServeLever {on, explicit_off}:  Unset={0,0}, True={1,0}, False={0,1}.
// NEVER collapse to plain bool.
enum class TriBool { Unset, True, False };

struct Setting {
    // Values are kept as their canonical string form (the same text the CLI or
    // file carried); typed getters parse on demand. Tri-state keys use `tri`.
    std::string value;
    TriBool     tri    = TriBool::Unset;   // only meaningful for TRISTATE_BOOL
    Source      source = Source::CompiledDefault;
    bool        present = false;           // false = pure compiled default, never set
};

// Outcome of a load attempt.
enum class LoadStatus {
    Ok,            // file applied (or absent -> pure compiled+CLI, today's behavior)
    AbsentOk,      // no file present; nothing to do
    RefusedMoney,  // money-class keys present without a valid ack hash: node must exit
    ParseError,    // malformed file / unknown key / type mismatch / bad validator
};

struct LoadResult {
    LoadStatus               status = LoadStatus::AbsentOk;
    std::vector<std::string> messages;   // human-readable, logged by the caller
    // On RefusedMoney: the offending money-class keys (full section paths).
    std::vector<std::string> offending_money_keys;
    int exit_code = 0;                    // EX_CONFIG(78) on RefusedMoney/ParseError
};

// Records which canonical keys the CLI explicitly set (generalizes main_ltc's
// `cli_explicit` set). The file overlay only fills keys NOT in the tracker.
class CliTracker {
public:
    void mark(const std::string& canon) { keys_.insert(canon); }
    bool has(const std::string& canon) const { return keys_.count(canon) != 0; }
    const std::set<std::string>& keys() const { return keys_; }
private:
    std::set<std::string> keys_;
};

// The typed, per-key-source picture. Constructed by:
//   (1) register compiled defaults (from the catalog + per-impl overrides),
//   (2) overlay file, (3) overlay CLI. L3 runtime is a stub in M0.
class ResolvedConfig {
public:
    // Seed L0 from the catalog's literal defaults (FROM_POOL_CONFIG rows are
    // filled by the per-impl register_catalog_defaults() before file overlay).
    void seed_compiled_defaults(c2pool::catalog::CoinBit coin);

    void set(const std::string& canon, const std::string& value, Source src);
    void set_tri(const std::string& canon, TriBool tri, Source src);

    bool has(const std::string& canon) const;
    bool file_set(const std::string& canon) const;  // present && source==File
    std::optional<Source> source_of(const std::string& canon) const;

    // Typed getters (assert the catalog type). Return std::nullopt if unset.
    std::optional<std::string> get_string(const std::string& canon) const;
    std::optional<int64_t>     get_i64(const std::string& canon) const;
    std::optional<double>      get_double(const std::string& canon) const;
    std::optional<uint16_t>    get_u16(const std::string& canon) const;
    TriBool                    get_tri(const std::string& canon) const;  // Unset if absent

    // L3 runtime stub — exists so M1 attaches the endpoint; only tests call it now.
    void apply_runtime(const std::string& canon, const std::string& value);

    // Canonical "canon=value source=<layer>" dump, sorted by canon.
    // Feeds --dump-resolved-config and the golden test.
    std::string dump() const;

private:
    std::map<std::string, Setting> by_canon_;
};

// The loader. Absent file => AbsentOk (byte-identical to today). Present file =>
// strict parse, per-key catalog validation, money-gate enforcement, then overlay
// of NON-money keys into `out` with Source::File (money keys only overlaid by the
// caller AFTER the gate passes; on refusal the node exits before any overlay).
class SettingsFile {
public:
    // coin selects which [<coin>] section (+ aux subsections) this binary owns.
    static LoadResult load(const std::string& path,
                           c2pool::catalog::CoinBit coin,
                           const CliTracker& cli,
                           ResolvedConfig& out);

    // Recompute the canonical money-ack hash over the money-class keys PRESENT
    // in `path` (operator --ack-money-settings helper uses this to rewrite
    // [gate].money_ack_hash). Returns lowercase hex.
    static std::string compute_money_ack_hash(const std::string& path,
                                              c2pool::catalog::CoinBit coin);

    // Exposed for tests: canonical serialization + digest of a given money-key
    // set (path -> literal), sorted lexicographically by path.
    static std::string money_digest(
        const std::vector<std::pair<std::string, std::string>>& money_kv);
};

} // namespace c2pool::settings

#endif // C2POOL_CORE_SETTINGS_FILE_HPP
