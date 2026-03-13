# Changelog

## [0.7.0] - 2026-03-12

### Added
- GitHub Actions CI workflow (Ubuntu 24.04, GCC 13, Conan 2) — builds all
  targets and runs full 94-test suite on every push/PR to `master`
- Regression test suite `test_hardening` (20 tests): `CollectSoftforkNames`,
  `SoftforkGate`, `ReplyMatcherConfig`, `ReplyMatcherResponse`,
  `ReplyMatcherTimeout`
- `src/impl/ltc/coin/softfork_check.hpp` — extracted header-only
  `ltc::coin::collect_softfork_names()` for direct unit testability
- `util/create_transition_message.py` — public Python3 CLI for authority key
  holders to sign stake-transition messages
- `util/README.md` — usage instructions for the authority tool

### Fixed
- Removed stale `libs/googletest` gitlink (mode 160000, no `.gitmodules`
  entry) that caused spurious CI warnings; GTest is provided by Conan
- All GitHub Actions now use Node.js 24-native versions (checkout@v6,
  cache@v5, setup-python@v6, upload-artifact@v7) — no deprecation warnings
- 15 stale TODO comments removed across 5 files

### Changed
- `master` is now the default branch (was `p2pool-v36-compat`); old master
  preserved as `master-legacy` at `89d0620e`
- CI uses `build_ci/` output folder to avoid stale committed `build/`
  paths (`CMakePresets.json` has hardcoded developer-local paths)
- Conan profile auto-patched to `cppstd=20` on first CI run

### Documentation
- `README.md` fully rewritten: CI badge, feature/status table, correct
  quick-start for Ubuntu 24.04, CLI examples, port/API tables, authority
  blob section, build targets table
- `doc/build-unix.md` fully rewritten for Ubuntu 24.04 + Conan 2:
  verified apt package list, PEP 668 note for pip, exact build sequence,
  test suite section, runtime examples, troubleshooting

## [Unreleased] - 2025-07-14

### Added
- **Web dashboard gate** — built-in static file serving from configurable
  `--dashboard-dir` (default `web-static/`); modern dark-theme dashboard
  with pool stats, graphs, share explorer, and auto-refresh
- **p2pool legacy API compatibility** — 7 new REST endpoints (`/local_stats`,
  `/p2pool_global_stats`, `/web/version`, `/web/currency_info`,
  `/payout_addr`, `/payout_addrs`, `/web/best_share_hash`) returning the
  exact JSON shapes the original p2pool/p2pool and jtoomim/p2pool dashboards
  expect; existing community dashboards work without modification
- **c2pool.js SDK** — universal JavaScript API client library bundled in
  `web-static/c2pool.js` with helpers for hashrate formatting, duration,
  coin display, and parallel data fetching
- **Dashboard integration guide** — comprehensive developer documentation
  in `docs/DASHBOARD_INTEGRATION.md` covering full API reference, migration
  from p2pool dashboards, custom dashboard creation, theming, and security
- `--dashboard-dir` CLI flag and `dashboard_dir` YAML key

## [Unreleased] - 2025-07-06

### Added
- **Comprehensive operational config** — 13 new CLI flags and matching YAML
  keys for logging, P2P, memory, cache, CORS, storage, and payout tuning
  (`--log-file`, `--log-level`, `--log-rotation-mb`, `--log-max-mb`,
  `--p2p-max-peers`, `--ban-duration`, `--rss-limit-mb`, `--cors-origin`,
  `--payout-window`, `--storage-save-interval`, `--max-coinbase-outputs`)
- `Logger::init()` now accepts file name, rotation MB, max total MB, and
  log level string (trace/debug/info/warning/error); old init() delegates
- Node P2P params (`MAX_PEERS`, `BAN_DURATION`, cache sizes, RSS limit) are
  now runtime-configurable via setter methods
- CORS `Access-Control-Allow-Origin` reads from `MiningInterface` config
  instead of hardcoded `"*"`
- `config/c2pool_testnet.yaml` rewritten — dead keys removed, all wired keys
  documented with inline comments
- Full configuration reference table in `README.md`
- Vardiff (variable difficulty) for stratum sessions: automatic share
  difficulty targeting via `--stratum-min-diff`, `--stratum-max-diff`,
  `--stratum-target-time`, `--no-vardiff`
- `StratumConfig` struct with CLI and YAML pipeline
- Bech32 (native SegWit) address support in payout validation

### Fixed
- `MAX_COINBASE_OUTPUTS` raised from 10 to 4000 (matching Python p2pool);
  eliminates silent payout truncation on busy pools
- `MINIMUM_PAYOUT_SATOSHIS` fixed from 100 000 to 1 — coinbase outputs are
  exempt from the dust limit
- P2P default ports corrected: mainnet 9326 → 9338
- YAML testnet ports corrected: p2p 9333 → 19338, stratum 8084 → 19327
- Ghost share tracker silenced via `vardiff_enabled_` flag
- Stale sharechain view crash on missing shares

### Added
- FreeBSD build support and compatibility
- CMake 3.30+ compatibility (automatic FindBoost fallback)
- Enhanced mining pool web server with HTTP/JSON-RPC and Stratum protocols
- Comprehensive Litecoin address validation (legacy, P2SH, Bech32)
- Automatic blockchain synchronization detection
- Mining monitoring and hashrate tracking tools

### Fixed
- CMake build system compatibility with newer CMake versions (3.30+)
- Boost library linking issues on FreeBSD and modern systems
- GTest made optional for main builds (tests only build if GTest available)
- Cross-platform build dependencies and documentation

### Changed
- Updated build system to support both old and new Boost/CMake combinations
- Improved documentation with platform-specific instructions
- Enhanced mining interface with real-time sync status

### Documentation
- Added comprehensive FreeBSD build guide
- Updated Unix build instructions with multi-platform support
- Added troubleshooting section for common build issues
- Documented mining pool features and supported protocols

## Previous Versions
See git history for earlier changes.
