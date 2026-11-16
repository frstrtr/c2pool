# Build instructions — Linux (Ubuntu 24.04)

## Option 1: Pre-built binary (recommended)

Each coin ships as its own package, `c2pool-<coin>-VERSION-linux-x86_64.tar.gz`,
on the [Releases page](https://github.com/frstrtr/c2pool/releases). Take the
newest tag from that page:

```bash
COIN="ltc"            # or: dash, btc, dgb, bch, bip110
VERSION="0.2.12.7"    # newest tag on the Releases page, without the "v"
wget https://github.com/frstrtr/c2pool/releases/download/v${VERSION}/c2pool-${COIN}-${VERSION}-linux-x86_64.tar.gz
tar xzf c2pool-${COIN}-${VERSION}-linux-x86_64.tar.gz
cd c2pool-${COIN}-${VERSION}-linux-x86_64
./start.sh            # extra node flags go after it, e.g. ./start.sh --node-owner-address <your-address>
```

Dashboard: `http://localhost:8080`. Stratum: `stratum+tcp://YOUR_IP:<port>`, where
`start.sh` binds 9327 (LTC), 7903 (DASH), 9332 (BTC), 5025 (DGB) or 9348 (BCH);
`c2pool-bip110 --run` binds 9336 by default.
The packaged `c2pool-dash` is built with BLS (`./c2pool-dash --version` ends in
`bls=dashbls`).

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
> `cmake --build . --target c2pool-ltc -j1`

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
>
> **libsecp256k1 is the one library that must come from the system.** It is not
> in `conanfile.txt`, so `conan install` never provides it; CMake finds it with
> `find_library`/`find_path` (then `find_package(secp256k1)`). Without sudo,
> unpack the distro packages into a user prefix and point CMake at it:
> ```bash
> apt-get download libsecp256k1-dev libsecp256k1-1
> for d in libsecp256k1*.deb; do dpkg -x "$d" "$HOME/local"; done
> # then add to the cmake configure line:  -DCMAKE_PREFIX_PATH=$HOME/local/usr
> ```
>
> **No system Boost is needed (`libboost-dev` is not a dependency).** Every C++
> translation unit, including the ones that link no Boost (vendored RandomX,
> the XMR node's `monero_rpc.cpp`), resolves Boost headers from Conan's pinned
> Boost only; a system Boost under `/usr/include`, if installed, is never used.

---

## 2. Install Conan 2

Conan 2 is the C++ package manager that handles all remaining dependencies.

```bash
pip install "conan>=2.0,<3.0" --break-system-packages
```

> On Ubuntu 24.04, `--break-system-packages` is required because of PEP 668.
> Alternatively, use a venv:
> `python3 -m venv ~/.conan-venv && source ~/.conan-venv/bin/activate && pip install conan`

`pip` installs `conan` into `~/.local/bin`, which may not be on your `PATH`.
Add it for the current shell, and append the same line to `~/.bashrc` (or
`~/.zshrc`) so it sticks across sessions:

```bash
export PATH="$PATH:$HOME/.local/bin"
```

Verify `conan` is now resolvable:

```bash
command -v conan   # should print /home/<you>/.local/bin/conan
```

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
git checkout v0.2.12.7   # or the newest tag on the Releases page; omit to build master
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
    --settings=build_type=Release
```

This downloads and compiles all managed dependencies into `~/.conan2/` and
generates `conan_toolchain.cmake` and `CMakePresets.json` in `build/`.

> **Release vs Debug.** Build **Release** for any node you run. A Debug build
> (`--settings=build_type=Debug`, then `cmake .. --preset conan-debug`) is
> several times larger and slower and is for development only.

**First run**: ~15–20 min (Boost 1.90 compiles from source if no pre-built binary exists).  
**Subsequent runs**: seconds (packages are cached in `~/.conan2/`).

---

## 5. Configure and build

```bash
# still inside build/
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build . --target c2pool-ltc -j$(nproc)
```

The compiled binary is at `build/src/c2pool/c2pool-ltc`. Every coin has its own
target and binary: `c2pool-ltc`, `c2pool-dash`, `c2pool-btc`, `c2pool-dgb`,
`c2pool-bch`, `c2pool-bip110`. The target `c2pool` is a dev alias of the LTC
node.

### Dash: build with BLS

`c2pool-dash` needs **dashbls** (the BLS12-381 library dashd links) to verify
quorum commitments, ChainLocks, InstantSend locks and governance votes. Build
it once with `scripts/build_dashbls.sh`, then configure with it:

```bash
# still inside build/
sudo apt-get install -y autoconf automake libtool libgmp-dev
../scripts/build_dashbls.sh "$HOME/.c2pool-deps/dashbls"
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release \
    -DC2POOL_DASH_BLS=ON -DDASHBLS_ROOT="$HOME/.c2pool-deps/dashbls"
cmake --build . --target c2pool-dash -j$(nproc)
./src/c2pool/c2pool-dash --version   # the last line must end in: bls=dashbls
```

A fresh configure that does not pass `-DC2POOL_DASH_BLS` at all finds dashbls
by itself under `$DASHBLS_ROOT`, `$HOME/.c2pool-deps/dashbls`, `/usr/local` or
`/opt/dashbls` (`dashbls auto-detected at <prefix>`).

Without dashbls the `c2pool-dash` target **fails to build** and prints how to
fix it; every other target builds. To build a `bls=stub` binary on purpose
(only for a dashd-attached node, or CI), configure with
`-DC2POOL_DASH_ALLOW_NO_BLS=ON`: the build then ends with a
`WARNING: c2pool-dash was built WITHOUT dashbls` line, and the binary refuses a
daemonless `c2pool-dash --run` with `[BLS-STUB] refusing to start` (exit 2).
Only a dashd-attached node (`--coin-rpc`) runs on a stub build.
`-DC2POOL_DASH_BLS=ON` with the library missing is a configure error, not a
silent fallback. Running options: README
[c2pool-dash — Dash (X11)](../README.md#c2pool-dash--dash-x11).

### Build the test suite (optional)

A quick check builds three test targets and runs them directly:

```bash
# still inside build/
cmake --build . \
    --target test_hardening test_share_messages test_coin_broadcaster \
    -j$(nproc)
./test/test_hardening && ./test/test_share_messages && ./test/test_coin_broadcaster
# Expected at v0.2.12.7: 20 + 9 + 68 = 97 tests, each binary ends in [  PASSED  ]
```

Do not run `ctest` after building only these three. `ctest` runs the whole
registered suite (5,550 tests across all coins at v0.2.12.7) and reports every
test whose target was not built as *Not Run* or `…_NOT_BUILT`. For the full
suite, build all targets first (a long build), then run it:

```bash
cmake --build . -j$(nproc)
ctest --output-on-failure -j$(nproc)
```

The Dash BLS tests only run in a `-DC2POOL_DASH_BLS=ON` build (see
[Dash: build with BLS](#dash-build-with-bls)); in a stub build they compile out.

---

## 6. Running

All examples assume you are in the repository root. They run the LTC node;
each other coin's command line is in the README
([c2pool-dash](../README.md#c2pool-dash--dash-x11),
[c2pool-btc](../README.md#c2pool-btc--bitcoin-sha256d),
[c2pool-dgb](../README.md#c2pool-dgb--digibyte-scrypt),
[c2pool-bch](../README.md#c2pool-bch--bitcoin-cash-sha256d)).

### Integrated mode — embedded SPV (no daemon required)

The default mode uses embedded LTC and DOGE SPV nodes. No litecoind or
dogecoind installation needed.

```bash
./build/src/c2pool/c2pool-ltc --integrated --net litecoin --embedded-ltc --embedded-doge --dashboard-dir web-static
```

- Dashboard: `http://localhost:8080`
- Stratum: `stratum+tcp://YOUR_IP:9327` (miners set LTC address as username)
- P2P: port 9326 (sharechain peers)

### With external coin daemon (optional)

If you run a local litecoind, add it as a priority peer for faster sync:

```bash
./build/src/c2pool/c2pool-ltc --integrated --net litecoin \
    --embedded-ltc --embedded-doge \
    --dashboard-dir web-static \
    --coind-p2p-port 9333
```

### With YAML config file

```bash
./build/src/c2pool/c2pool-ltc --config config/c2pool_mainnet.yaml --dashboard-dir web-static
```

See `config/c2pool_mainnet.yaml` for all available options with documentation.

### Full option reference

```bash
./build/src/c2pool/c2pool-ltc --help
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
cmake --build . --target c2pool-ltc -j1
```

### `libleveldb.so` not found at runtime

```bash
sudo apt-get install -y libleveldb-dev
```

### Conan packages rebuild unexpectedly

The Conan profile must match the original build. If you changed compiler
version or build type, packages will recompile once and then be cached.

### `conan install` hangs / fails downloading from sourceware.org (bzip2)

The Conan Center recipe for `bzip2` fetches sources from `sourceware.org`,
which frequently times out mid-transfer even when the site loads fine in a
browser. Symptom:

```
bzip2/1.0.8: WARN: network: Download failed, check server, possibly try again
HTTPSConnectionPool(host='sourceware.org', port=443): Read timed out.
bzip2/1.0.8: Waiting 5 seconds to retry...
```

Fix — add Conan Center's backup sources mirror to `~/.conan2/global.conf`:

```
core.sources:download_urls=["https://c3i.jfrog.io/artifactory/conan-center-backup-sources/", "origin"]
core.net.http:max_retries=1
core.net.http:timeout=120
```

This tells Conan to try the reliable JFrog mirror first and fall back to
the recipe's `origin` URL only if that fails. SHA256 is validated against
`conandata.yml` either way, so integrity is preserved.

The same fallback covers other flaky upstream hosts (GNU FTP, savannah,
kernel.org) — Conan Center backs up every source tarball its recipes use.

Verify the config took effect:

```bash
conan config show "core.sources:*"
```

### CMake 3.30+ / FindBoost warning

The project already handles `CMP0167` — no manual workaround needed.

---

## macOS

See [build-macos.md](build-macos.md).

## Windows

See [build-windows.md](build-windows.md).
