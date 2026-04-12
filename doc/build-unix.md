# Build instructions — Linux (Ubuntu 24.04)

This guide covers building c2pool on Ubuntu 24.04 LTS.  
The same steps work on Ubuntu 22.04 and Debian 12 with minor version differences.

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

> All other dependencies (Boost 1.78, nlohmann_json, yaml-cpp, GoogleTest, zlib,
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

**First run**: ~15–20 min (Boost 1.78 compiles from source).  
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

### Integrated mode — full pool (LTC + DOGE merged mining)

```bash
./build/src/c2pool/c2pool \
    --integrated \
    --net litecoin \
    --coind-address 127.0.0.1 --coind-rpc-port 9332 \
    --coind-p2p-port 9333 \
    --merged DOGE:98:127.0.0.1:44556:dogerpc:rpcpass \
    --address YOUR_LTC_ADDRESS \
    --give-author 2 \
    litecoinrpc RPCPASSWORD
```

### Testnet smoke-test

```bash
./build/src/c2pool/c2pool --integrated --testnet
```

### Sharechain-only node

```bash
./build/src/c2pool/c2pool \
    --sharechain \
    --net litecoin \
    --coind-address 127.0.0.1 --coind-rpc-port 9332 \
    litecoinrpc RPCPASSWORD
```

### Full option reference

```bash
./build/src/c2pool/c2pool --help
```

**Default ports**

| Port | Purpose |
|------|--------|
| 9338 | P2Pool sharechain peer-to-peer |
| 9327 | Stratum mining server + HTTP API |

---

## 7. Configuration file (optional)

Pass `--config path/to/config.yaml` to load settings from YAML.  
Templates are in `doc/configs-templates/`.

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

## FreeBSD

See [build-freebsd.md](build-freebsd.md).

## Windows

See [build-windows.md](build-windows.md).
