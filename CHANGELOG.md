# Changelog

## [0.9.5] - 2026-03-27

### Milestone
- **Embedded DOGE merged mining** — first DOGE block accepted on testnet4alpha via pure embedded SPV P2P. Zero daemon dependencies for LTC+DOGE mining.

### Added
- **Embedded LTC SPV node** (`--embedded-ltc`) — HeaderChain with LevelDB persistence, P2P header sync, MWEB HogEx carry-forward, mempool with conflict detection. Blocks accepted on LTC testnet.
- **Embedded DOGE SPV node** (`--embedded-doge`) — AuxPoW header parser, DigiShield v3 difficulty, random subsidy via Mersenne Twister (boost-compatible), auto-generated `--merged DOGE:98` spec.
- **DOGE-compatible P2P protocol** — protocol version 70015, no NODE_WITNESS/NODE_MWEB, no sendcmpct v2, no feefilter, MSG_BLOCK instead of MSG_MWEB_BLOCK for DOGE peers.
- **AuxPoW header parser** — `parse_doge_headers_message()` extracts 80-byte base headers from DOGE extended P2P format (2000 headers/batch).
- **Isolated network mode** — `disable_discovery` for testnet4alpha: single-peer operation, no addr crawl, no emergency refresh.
- **DNS seed discovery** — async DNS resolution with fixed seed fallback for both LTC and DOGE networks.
- **Addrman hardening** — network group dedup, tried/new table separation, anchor peer persistence.
- **Block version from chain tip** — derives BIP9/AuxPoW version bits from tip header instead of hardcoded constants.
- **Block hex logging** — saves merged block hex to `/tmp/c2pool_doge_block_*.hex` for manual verification.

### Fixed
- **Heap corruption in refresh_work()** — two threads (embedded header callback + stratum submit) racing through `build_coinbase_parts()`. Fixed with try_lock serialization.
- **SIGSEGV #1: StratumSession timer use-after-free** — timer callbacks held raw `this` pointer. Fixed with `weak_from_this()`.
- **SIGSEGV #2: JobSnapshot map reference invalidated** — copy by value instead of holding map reference.
- **DOGE coinbase overpay** — testnet4alpha uses random rewards (Mersenne Twister seeded from prevHash), not fixed 500k DOGE. Implemented exact Dogecoin Core subsidy calculation.
- **DOGE AuxPoW version mismatch** — committed block hash used version without AuxPoW bit (0x100), causing AuxPoW proof check failure. Both commit and submit now use identical version.
- **DOGE header sync stall** — empty locator sent genesis hash causing peer to skip genesis block. Fixed: empty locator triggers genesis-inclusive response.
- **DOGE AuxPoW PoW validation** — scrypt validation on AuxPoW blocks fails because PoW is on parent chain. Skip scrypt for AuxPoW heights.
- **O(n^2) header sync** — `rebuild_height_index()` on every header. Incremental update for linear chain.
- **bits=0 after checkpoint** — chain too short for retarget. Fallback to pow_limit.
- **BIP9 version bits** — hardcoded BLOCK_VERSION=4. Derive from chain tip.
- **NODE_MWEB not advertised** — peers ignored MSG_MWEB_BLOCK requests. Added to version services.
- **Equal-work chain reorg** — testnet min-difficulty blocks have equal work. Switch tip on equal work at same height.
- **Deadlock on reorg** — tip-changed callback inside HeaderChain mutex. Deferred PendingTipChange.
- **Stale mempool transactions** — never removed confirmed txs. Added remove_for_block + conflict detection.

## [0.9.2] - 2026-03-20

### Security
- **fix: Share target validation** — Reject shares where `target > max_target` (matching p2pool-merged-v36 v0.14-alpha fix). Closes latent vulnerability present since p2pool inception.
- **fix: Bootstrap share target** — Use hardest chain bits during bootstrap instead of MAX_TARGET. Prevents easy-share flooding when joining existing networks.

### Bug Fixes
- **fix: PPLNS desired_weight cap** — V36 exponential decay now uses unlimited desired_weight (`2^288 - 1`). The cap truncated the PPLNS window to ~2 shares on testnet, causing single-miner payouts.
- **fix: merged_payout_hash consensus** — Walk VERIFIED chain only (not raw chain) to exclude c2pool's own unverified shares. Defer check until verified depth >= CHAIN_LENGTH. Fixes consensus divergence with p2pool peers.
- **fix: Share difficulty (desired_target)** — Pass MAX_TARGET (clipped to pool share difficulty) instead of block difficulty. Block difficulty made shares 2634x too hard, causing c2pool's miner to contribute negligible PPLNS weight.
- **fix: PPLNS race condition** — Recompute PPLNS from frozen prev_share in `build_connection_coinbase`. Prevents stale coinbase when chain advances between template creation and share submission.
- **fix: Log rotation** — Add target directory for log rotation, increase default to 100MB.

### Added
- **`/miner_thresholds` API endpoint** — Returns minimum viable hashrate (normal and with 30x DUST range), minimum payout per share, pool hashrate, PPLNS window duration. Enables dashboard display of miner feasibility.
- **`MinerThresholds` struct** — Pool-level computation of minimum viable hashrate from chain state.
- **SHAREREQ diagnostic** — Log first 5 SHAREREQ misses with chain size for debugging share sync issues.

### Documentation
- Analysis documents in frstrtr/the: DESIRED_WEIGHT_CAP_BUG.md, SHARE_TARGET_VALIDATION.md, SHARE_PERIOD_AND_TINY_MINERS.md, TINY_MINER_ECONOMICS.md

## [0.9.1] - 2026-03-19

### Added (untested — implemented, needs live validation)
- **BIP 152 compact blocks** — full send/receive path, SipHash-based short
  IDs, block reconstruction from mempool, wtxidrelay negotiation (BIP 339).
  LevelDB pruning of evicted shares. 20 new tests.
- **AutoRatchet V36→V37** — autonomous share version transition state machine
  with voting, activation thresholds, and rollback safety. 23 new tests.
- **Redistribute V2** — graduated boost, hybrid mode, threshold-based
  activation, opt-in per miner. 19 new tests.
- **Naughty share punishment** — ancestor propagation + head scoring penalty
  for misbehaving share chains.
- **Merged coinbase consensus verification** — 7-step chain verification
  prevents merged mining reward theft. `merged_payout_hash` verified in
  `share_check()`.
- **Canonical merged coinbase** — PPLNS coinbase with THE state root anchoring
  in merged chain blocks (DOGE, etc.).
- **Merged PPLNS compatibility** — 3-tier address normalization matching
  Python p2pool for cross-pool interop.
- **Found block persistence** — Layer +2 persistent storage with proper
  blockchain acceptance verification via RPC.
- **THE checkpoint consumer** — store, verify against blockchain, prune
  orphaned checkpoints on startup. REST API endpoints for checkpoint queries.
- **THE coinbase state commitment** — unified share retention policy with
  THE state root embedded in coinbase scriptSig.
- **Coinbase builder** — dynamic scriptSig layout with `--coinbase-text`
  operator customization and THE metadata embedding.
- **Private sharechain identity** — `--network-id` / `--chain-id` /
  `--chain-prefix` for isolated pool networks. Secure tagged-hash chain
  fingerprint (8-byte SHA256d, collision-free).
- **Startup modes** — `--genesis`, `--wait-for-peers`, `--startup-mode
  auto|genesis|wait` for flexible bootstrapping.
- **DOGE P2P header sync** — always active when P2P port configured,
  independent SPV chain for merged mining verification.
- **Merged mining coins** — added support for PEP, BELLS, LKY, JKC, SHIC,
  DINGO (chain IDs and address formats).
- **Phase 6: DigiByte** — Scrypt parent chain config for DGB as alternative
  parent chain (embedded SPV for LTC/DOGE).
- **Stratum extensions** — ASICBoost (version-rolling), NiceHash/MRR
  compatibility, address separator parsing.
- **Mining OS integration** — HiveOS, MinerStat, RaveOS deploy templates
  and flight sheet configs.
- **Dashboard API extensions** — warnings endpoint, merged chain payouts,
  daemon health tracking with contact-lost detection.
- **API reference documentation** — comprehensive REST endpoint docs.

### Fixed
- **Share PoW invalid (CRITICAL)** — p2pool rejected all c2pool shares as
  "share PoW invalid". Two root causes found and fixed:
  1. Coinbase scriptSig mismatch: `compute_ref_hash_for_work` omitted the
     32-byte THE state_root that `build_coinbase_parts` appends to the
     coinbase scriptSig, causing ref_hash divergence.
  2. Segwit merkle branches not frozen: `txid_merkle_link` branches and
     `wtxid_merkle_root` changed between GBT updates. Shares from older
     jobs used stale branch data. Now frozen at template time through
     RefHashResult → JobEntry → JobSnapshot → ShareCreationParams pipeline.
- **Variable shadowing (CRITICAL)** — `std::string gbt_block_nbits` at line
  920 of stratum_server.cpp shadowed the outer variable, causing ALL frozen
  share fields (absheight, bits, max_bits, etc.) to be zero.
- **verify_share block target** — used `share.m_bits` (share target) instead
  of `share.m_min_header.m_bits` (block target) for `merged_payout_hash`,
  causing ~100-200x weight difference in PPLNS distribution.
- **ref_stream segwit_data** — `PossiblyNoneType` serialization: c2pool
  skipped `segwit_data` when None (0 bytes) while p2pool always serializes
  default (33 bytes). Fixed to always serialize.
- **Share field drift** — ref_hash computed at template time, but share
  fields recomputed at submit time from different tracker state. Fixed by
  freezing absheight, abswork, far_share_hash, timestamp, bits, max_bits,
  merged_payout_hash at template time and passing through job snapshot chain.
- **LevelDB lock conflict** — EnhancedNode and NodeImpl both opened the same
  LevelDB database. EnhancedNode now defers to NodeImpl.
- **Persist path mismatch** — EnhancedNode used "testnet", NodeImpl used
  "litecoin_testnet". Unified to coin-prefixed path.
- **Crash during share logging** — `share.ACTION({...})` after
  `m_tracker.add(share)` accessed moved variant. Log BEFORE add.
- **Boost.Log rotation** — `keywords::target` moved debug.log to logs/.
  Removed target keyword to keep debug.log at `~/.c2pool/debug.log`.
- **"from localhost:0"** log for LevelDB-loaded and downloaded shares.
  Database shares now show "from database", downloaded shares show peer addr.

### Added
- **p2pool-style share logging** — "Received share: hash=X height=Y from
  SOURCE", "Processing N shares from SOURCE...", "GOT SHARE!", and
  "P2Pool: N shares in chain (M verified/N total) Peers: P" status line.
- **Share creation counters** — periodic logging of calls/guard_blocked/
  pow_failed/created every 60 seconds.
- **Crash handler** — catches SIGSEGV/SIGABRT, writes backtrace to
  `/tmp/c2pool_crash.log`. Also `std::set_terminate()` handler.
- **Startup banner** — framed MIT license warning in LOG_WARNING.
- **hash_link unit tests** — 11 tests including production-path coinbase
  round-trip verification. Added to CI build targets.
- **Share cross-check** — runs `share_init_verify` on self-created shares
  before broadcasting; prevents sending shares peers would reject.
- **Faster initial sync** — batch size scaled with O(chain_length) walk cost.

### Changed
- Stratum `nbits` field now sends GBT block difficulty (not share target).
  Miners put this in the 80-byte header nBits field.
- Share chain guard: only blocks on null prev_share_hash (removed wrong
  verified >= 100 guard that prevented share creation).

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
