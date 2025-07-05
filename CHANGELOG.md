# Changelog

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
