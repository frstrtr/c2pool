// src/core/settings_cli.hpp
//
// Shared, catalog-driven CLI <-> settings-file wiring for the five node mains
// (M0b). Qt-free, boost-free, link-dependency-free (core-only).
//
// The M0 loader (settings_file.hpp) owns the file layer, the money gate and the
// four-layer ResolvedConfig. This header adds the glue every main needs to hook
// that loader in WITHOUT rewriting its hand-written argv parse loop:
//
//   * scan_cli()    -- a read-only catalog-driven second walk of argv that fills
//                      a CliTracker (which canonical keys the CLI set, so the
//                      file overlay skips them: L2 > L1) and mirrors each CLI
//                      value into the ResolvedConfig with Source::Cli. It never
//                      mutates node state, so it cannot change launch behaviour.
//   * resolve_settings_path() -- --settings PATH (explicit, must exist) else
//                      <data-dir>/c2pool.toml if present, else "" (absent).
//   * wire_settings() -- the shared sequence: load the file (L1, skipping CLI
//                      keys), enforce the money gate (RefusedMoney -> exit 78),
//                      then overlay the captured CLI values (L2). Returns an
//                      exit code the caller propagates (0 = proceed).
//   * dump_resolved() -- print the fully resolved config between stable markers
//                      for --dump-resolved-config (a diagnostic; the caller then
//                      exits 0 without starting the node).
//
// PRECEDENCE (compiled L0 < file L1 < CLI L2 < runtime L3) is enforced twice,
// independently: the loader overlays a file key only when !tracker.has(canon)
// (settings_file.cpp), and wire_settings re-applies the captured CLI values with
// Source::Cli AFTER the file overlay so the CLI wins even over an acked money key.
#ifndef C2POOL_CORE_SETTINGS_CLI_HPP
#define C2POOL_CORE_SETTINGS_CLI_HPP

#include <string>

#include "param_catalog.hpp"
#include "settings_file.hpp"

namespace c2pool::settings {

// Stable extraction markers for --dump-resolved-config. Chosen so no per-main
// startup preamble (RLIMIT/SHA256 banners, print_banner) can contaminate the
// golden extraction: the harness slices strictly between BEGIN and END.
inline constexpr const char* kDumpBegin = "=== RESOLVED CONFIG BEGIN ===";
inline constexpr const char* kDumpEnd   = "=== RESOLVED CONFIG END ===";

// Map a binary enum to its coin section bit (which [<coin>] section it owns).
c2pool::catalog::CoinBit coin_of_bin(c2pool::catalog::Bin bin);

// Read-only catalog-driven walk of argv. For every recognised alias of `bin`
// it marks tracker[canon] and (for non-readonly rows) mirrors the CLI value into
// `rc` with Source::Cli, consuming value tokens per the alias style. Unknown
// tokens are skipped -- rejecting them is the real parse loop's job.
void scan_cli(int argc, char** argv, c2pool::catalog::Bin bin,
              CliTracker& tracker, ResolvedConfig& rc);

// Effective settings-file path. If explicit_path is non-empty it MUST exist
// (a typo must not silently fall through): on a missing explicit file *fatal is
// set true and *err carries a message. Otherwise returns <data-dir>/c2pool.toml
// when that file exists, else "" (absent -> today's pure compiled+CLI path).
std::string resolve_settings_path(const std::string& explicit_path,
                                  bool& fatal, std::string& err);

// Load the file layer (L1) into rc skipping CLI keys, enforce the money gate,
// then overlay the captured CLI values (L2). Diagnostics are printed to stderr.
// Returns 0 to proceed, or 78 (EX_CONFIG) on RefusedMoney/ParseError -- the
// caller must exit with the returned code before starting the node.
//
// PRECONDITION: the caller has already seeded L0 (seed_compiled_defaults +
// the per-impl register_catalog_defaults) and captured CLI keys/values via
// scan_cli into the SAME rc/tracker passed here.
int wire_settings(const std::string& path, c2pool::catalog::CoinBit coin,
                  const CliTracker& tracker, ResolvedConfig& rc);

// Print the resolved config between the stable markers. Caller exits 0 after.
void dump_resolved(const ResolvedConfig& rc);

} // namespace c2pool::settings

#endif // C2POOL_CORE_SETTINGS_CLI_HPP
