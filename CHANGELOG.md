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

## [Unreleased] - 2025-07-06

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
