# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is C2Pool

C2Pool is a modern C++ reimplementation of the decentralized mining pool P2Pool, targeting the V36 share format with support for Litecoin and merged mining (Dogecoin, etc.). It implements a full P2P mining pool with Stratum protocol, PPLNS payouts, VARDIFF, and a web dashboard.

## Build System

**Requirements:** CMake 3.22+, GCC 13, Conan 2.x, C++20

**System packages (Ubuntu 24.04):**
```bash
sudo apt-get install -y g++ cmake make libleveldb-dev libsecp256k1-dev python3-pip
pip install "conan>=2.0,<3.0" --break-system-packages
conan profile detect --force
```

**Build the main binary:**
```bash
mkdir build && cd build
conan install .. --build=missing --settings=build_type=Debug
cmake .. --preset conan-debug
cmake --build . --target c2pool -j$(nproc)
# Binary: build/src/c2pool/c2pool
```

There is also `build-debug.sh` at the repo root as a convenience script.

**Build and run all tests:**
```bash
cd build
cmake --build . --target test_hardening test_share_messages test_coin_broadcaster \
  test_redistribute_address core_test sharechain_test share_test -j$(nproc)
ctest --output-on-failure -j$(nproc)
# Expected: 265 tests passing
```

**Run a single test binary:**
```bash
cd build && ./test/test_hardening
cd build && ./src/core/test/core_test
```

**Python integration tests** (require a running pool):
```bash
cd test && python3 smoke_test.py
cd test && python3 integration_test.py
```

## Architecture

The codebase is split into layered modules under `src/`:

```
btclibs/          Bitcoin/crypto primitives (uint256, SHA256, ECDSA, base58, Script)
core/             Infrastructure: networking (Boost.ASIO), HTTP/Stratum server,
                  logging, YAML config, LevelDB wrapper, binary serialization
pool/             Generic P2P pool protocol (peer connections, message dispatch)
sharechain/       V36 share format, share chain data structure, LevelDB storage
impl/ltc/         Litecoin-specific: share validation, V36 authority messages,
                  litecoind RPC/P2P client, payout redistribution modes
c2pool/           Enhanced features + main entry point:
  node/           Enhanced node orchestration (ties all modules together)
  hashrate/       Real-time hashrate tracking
  difficulty/     Per-miner VARDIFF adjustment engine
  storage/        LevelDB sharechain persistence manager
  payout/         PPLNS payout calculation
  merged/         Merged mining support (DOGE, DGB)
```

**Dependency direction:** `c2pool` → `impl/ltc` → `pool` + `sharechain` + `core` → `btclibs`

The main entry point is `src/c2pool/c2pool_refactored.cpp`, which parses 100+ CLI arguments, selects an operating mode, and instantiates `EnhancedNode` from `c2pool/node/`.

**Operating modes** (selected by CLI flags):
- `--integrated` — Full pool: HTTP API + Stratum + P2P sharechain + payouts + web dashboard
- `--sharechain` — P2P node only (no mining)
- default — Solo mining (lightweight, no P2P)

## Key Files

| File | Purpose |
|------|---------|
| `src/c2pool/c2pool_refactored.cpp` | Main entry point, all CLI argument handling |
| `src/core/web_server.cpp` | HTTP/JSON-RPC/Stratum server (~2500 LOC) |
| `src/impl/ltc/share_check.hpp` | Share validation — the most complex file in the repo |
| `src/impl/ltc/share_messages.hpp` | V36 authority message encryption/decryption |
| `src/impl/ltc/node.cpp` | LTC pool node orchestration |
| `src/c2pool/payout/payout_manager.cpp` | PPLNS distribution logic |
| `src/c2pool/merged/merged_mining.cpp` | Merged mining adapter |
| `src/core/pack.hpp` | Binary serialization framework used throughout |

## REST API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/current_payouts` | Current PPLNS payout distribution by address |
| `/local_stats` | Local node statistics (peers, hashrates, shares) |
| `/global_stats` | Pool-wide statistics (pool hashrate, difficulty) |
| `/miner_thresholds` | Minimum viable hashrate, min payout per share, DUST range |
| `/recent_blocks` | Recently found blocks |
| `/connected_miners` | Currently connected stratum workers |
| `/stratum_stats` | Stratum server statistics |
| `/sharechain_stats` | Share chain state (height, verified count) |

## Configuration

Configuration priority: CLI args > YAML file (`--config config.yaml`) > env vars > defaults.

See `config/c2pool_testnet.yaml` for a full example. Key defaults: P2P port 9338, Stratum port 9327, HTTP port 8080.

## Dependencies

- **LevelDB** and **libsecp256k1** must be installed system-wide
- **Boost 1.78** (ASIO, log, thread, filesystem), **nlohmann/json 3.11.3**, **yaml-cpp 0.8.0**, **GTest 1.14.0** are managed via Conan
- `btclibs/` contains vendored/stripped Bitcoin Core utilities

## CI/CD

GitHub Actions (`.github/workflows/build.yml`) runs on Ubuntu 24.04 with GCC 13. The pipeline installs system deps, runs Conan, builds all targets, and runs `ctest`. Conan package cache is keyed by compiler/build_type.
