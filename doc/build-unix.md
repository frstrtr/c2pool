# Build instructions — Linux (Ubuntu 24.04)

## Option 1: Pre-built binary (recommended)

Download `c2pool-VERSION-linux-x86_64.tar.gz` from the
[Releases page](https://github.com/frstrtr/c2pool/releases).

```bash
VERSION="0.1.1-alpha"
wget https://github.com/frstrtr/c2pool/releases/download/v${VERSION}/c2pool-${VERSION}-linux-x86_64.tar.gz
tar xzf c2pool-${VERSION}-linux-x86_64.tar.gz
cd c2pool-${VERSION}-linux-x86_64
./start.sh
```

Dashboard: `http://localhost:8080` — Stratum: `stratum+tcp://YOUR_IP:9327`

---

## Option 2: Build from source

This guide covers building c2pool on Ubuntu 24.04 LTS.  
The same steps work on Ubuntu 22.04 and Debian 12 with minor version differences.

### Tested configuration

| Component | Version |
|-----------|---------|
| Ubuntu | 24.04.4 LTS (Noble) |
| Kernel | 6.17.0 |
| GCC | 13.3.0 |
| CMake | 3.28.3 |
| Boost | 1.90.0 (via Conan) |
| LevelDB | 1.23 |
| libsecp256k1 | 0.4.1 |
| Architecture | x86_64 |

> Other Ubuntu/Debian versions may work but are untested.

> **Low-RAM warning**: if compilation is killed mid-way, reduce parallelism:
> `cmake --build . --target c2pool -j1`

---

## 1. System packages

```bash
sudo apt-get update
sudo apt-get install -y \
    g++ \
    cmake \
    make \
    libleveldb-dev \
    libsecp256k1-dev \
    python3-pip \
    git
```

| Package | Provides |
|---------|----------|
| `g++` | GCC 13 C++ compiler |
| `cmake` | Build system (3.28 on 24.04) |
| `libleveldb-dev` | LevelDB — persistent sharechain storage |
| `libsecp256k1-dev` | secp256k1 — ECDSA crypto for btclibs |
| `python3-pip` | needed to install Conan |

> All other dependencies (Boost 1.90, nlohmann_json, yaml-cpp, GoogleTest, zlib,
> bzip2, libbacktrace) are downloaded and compiled automatically by Conan.

---

## 2. Install Conan 2

Conan 2 is the C++ package manager that handles all remaining dependencies.

```bash
pip install "conan>=2.0,<3.0" --break-system-packages
```

> On Ubuntu 24.04, `--break-system-packages` is required because of PEP 668.
> Alternatively, use a venv:
> `python3 -m venv ~/.conan-venv && source ~/.conan-venv/bin/activate && pip install conan`

Create the default toolchain profile (auto-detects GCC 13):

```bash
conan profile detect --force
```

Verify:

```bash
conan profile show
# Should show: compiler=gcc, compiler.version=13, os=Linux
```

---

## 3. Clone the repository

```bash
git clone https://github.com/frstrtr/c2pool.git
cd c2pool
```

> No submodules — a plain `git clone` is sufficient.

---

## 4. Install dependencies with Conan

```bash
mkdir build
cd build
conan install .. \
    --build=missing \
    --output-folder=. \
    --settings=build_type=Debug
```

This downloads and compiles all managed dependencies into `~/.conan2/` and
generates `conan_toolchain.cmake` and `CMakePresets.json` in `build/`.

**First run**: ~15–20 min (Boost 1.90 compiles from source if no pre-built binary exists).  
**Subsequent runs**: seconds (packages are cached in `~/.conan2/`).

---

## 5. Configure and build

```bash
# still inside build/
cmake .. --preset conan-debug
cmake --build . --target c2pool -j$(nproc)
```

The compiled binary is at `build/src/c2pool/c2pool`.

### Build the test suite (optional)

```bash
cmake --build . \
    --target test_hardening test_share_messages test_coin_broadcaster \
    -j$(nproc)
ctest --output-on-failure -j$(nproc)
# Expected: 94 tests, 0 failures
```

---

## 6. Running

All examples assume you are in the repository root.

### Integrated mode — embedded SPV (no daemon required)

The default mode uses embedded LTC and DOGE SPV nodes. No litecoind or
dogecoind installation needed.

```bash
./build/src/c2pool/c2pool --integrated --net litecoin --embedded-ltc --embedded-doge --dashboard-dir web-static
```

- Dashboard: `http://localhost:8080`
- Stratum: `stratum+tcp://YOUR_IP:9327` (miners set LTC address as username)
- P2P: port 9326 (sharechain peers)

### With external coin daemon (optional)

If you run a local litecoind, add it as a priority peer for faster sync:

```bash
./build/src/c2pool/c2pool --integrated --net litecoin \
    --embedded-ltc --embedded-doge \
    --dashboard-dir web-static \
    --coind-p2p-port 9333
```

### With YAML config file

```bash
./build/src/c2pool/c2pool --config config/c2pool_mainnet.yaml --dashboard-dir web-static
```

See `config/c2pool_mainnet.yaml` for all available options with documentation.

### Full option reference

```bash
./build/src/c2pool/c2pool --help
```

**Default ports**

| Port | Purpose |
|------|--------|
| 9326 | P2Pool sharechain peer-to-peer |
| 9327 | Stratum mining server |
| 8080 | Web dashboard / JSON-RPC API |
| 9333 | LTC P2P (embedded SPV) |
| 22556 | DOGE P2P (embedded SPV) |

---

## 7. Data directory

c2pool stores its data in `~/.c2pool/`:

```
~/.c2pool/
  debug.log                    # Main log file (rotated at 100MB)
  sharechain_leveldb/          # Persistent sharechain storage
  litecoin/embedded_headers/   # LTC SPV header cache
  dogecoin/embedded_headers/   # DOGE SPV header cache
  litecoin/utxo_leveldb/       # LTC UTXO set
  dogecoin/utxo_leveldb/       # DOGE UTXO set
  crash.log                    # Crash log (if any, at /tmp/c2pool_crash.log)
```

## 8. Configuration file (optional)

Pass `--config path/to/config.yaml` to load settings from YAML.
See `config/c2pool_mainnet.yaml` for all available options with documentation.

---

## Troubleshooting

### Compilation killed (out of memory)

```bash
cmake --build . --target c2pool -j1
```

### `libleveldb.so` not found at runtime

```bash
sudo apt-get install -y libleveldb-dev
```

### Conan packages rebuild unexpectedly

The Conan profile must match the original build. If you changed compiler
version or build type, packages will recompile once and then be cached.

### CMake 3.30+ / FindBoost warning

The project already handles `CMP0167` — no manual workaround needed.

---

## macOS

See [build-macos.md](build-macos.md).

## Windows

See [build-windows.md](build-windows.md).
