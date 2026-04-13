# Build instructions — macOS (Intel & Apple Silicon)

This guide covers building c2pool from source on macOS.

### Tested configuration

| Component | Version |
|-----------|---------|
| macOS | 26.3.1 (Tahoe) |
| Xcode / Apple Clang | 21.0.0 |
| CMake | 4.3.1 |
| Boost | 1.90.0 |
| LevelDB | 1.23 |
| libsecp256k1 | 0.7.1 |
| Architecture | x86_64 (Intel Mac Pro) |

> Other macOS versions may work but are untested. Boost API changes between
> major versions are the most common source of build failures on untested
> configurations.

## Option 1: Pre-built DMG (recommended)

Download from the [Releases page](https://github.com/frstrtr/c2pool/releases):
- **Intel Mac**: `c2pool-VERSION-macos-x86_64.dmg`
- **Apple Silicon (M1/M2/M3/M4)**: `c2pool-VERSION-macos-arm64.dmg`

```bash
# Mount the DMG
hdiutil attach c2pool-*-macos-*.dmg

# Copy to your preferred location
cp -R /Volumes/c2pool-*/  ~/c2pool

# Unmount
hdiutil detach /Volumes/c2pool-*

# Run
cd ~/c2pool
./start.sh
```

Dashboard: `http://localhost:8080` — Stratum: `stratum+tcp://YOUR_IP:9327`

The DMG contains everything needed: the binary, bundled `libsecp256k1`, web dashboard,
config templates, block explorer, and a start script. No additional dependencies required.

> **macOS Gatekeeper**: On first run, macOS may block the binary. Open
> System Settings > Privacy & Security and click "Allow Anyway", or run:
> ```bash
> xattr -dr com.apple.quarantine ~/c2pool
> ```

### Verifying the download

Each release includes a `SHA256SUMS` file. Verify your download:

```bash
shasum -a 256 c2pool-*-macos-*.dmg
# Compare output with the published SHA256SUMS
```

---

## Option 2: Build from source

---

## Supported architectures

| Mac | Architecture | Homebrew prefix | Status |
|-----|-------------|-----------------|--------|
| Intel (2012–2023) | x86_64 | `/usr/local` | Tested, working |
| Apple Silicon (M1/M2/M3/M4) | arm64 | `/opt/homebrew` | Supported (same steps) |

---

## 1. Install Xcode Command Line Tools

```bash
xcode-select --install
```

Accept the license if prompted. This provides the Apple Clang compiler and system headers.

---

## 2. Install Homebrew

Skip if already installed (`brew --version` to check).

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

After installation, add Homebrew to your PATH if prompted:

**Apple Silicon (M1+):**
```bash
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"
```

**Intel Mac:**
```bash
echo 'eval "$(/usr/local/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/usr/local/bin/brew shellenv)"
```

---

## 3. Install dependencies

```bash
brew install cmake boost leveldb secp256k1 nlohmann-json yaml-cpp
```

| Package | Provides |
|---------|----------|
| `cmake` | Build system (3.28+) |
| `boost` | Networking, logging, threading, filesystem |
| `leveldb` | Persistent sharechain storage |
| `secp256k1` | ECDSA crypto for btclibs |
| `nlohmann-json` | JSON parsing |
| `yaml-cpp` | YAML config parsing |

> No Conan needed on macOS — Homebrew provides all dependencies as system libraries.

---

## 4. Clone and build

```bash
git clone https://github.com/frstrtr/c2pool.git
cd c2pool
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --target c2pool -j$(sysctl -n hw.ncpu)
```

The compiled binary is at `build/src/c2pool/c2pool`.

> **First build**: ~3–5 minutes on modern hardware.

---

## 5. Running

```bash
# From the repository root
./build/src/c2pool/c2pool --integrated --net litecoin --dashboard-dir web-static
```

The node starts in **integrated P2P pool mode** with embedded LTC and DOGE SPV nodes.
No litecoind or dogecoind required.

- Dashboard: `http://localhost:8080`
- Stratum: `stratum+tcp://YOUR_IP:9327` (miners set LTC address as username)

### With block explorer

```bash
# Terminal 1: c2pool
./build/src/c2pool/c2pool --integrated --net litecoin --dashboard-dir web-static

# Terminal 2: explorer (after c2pool is ready)
python3 explorer/explorer.py \
    --ltc-host 127.0.0.1 --ltc-port 8080 \
    --ltc-user c2pool --ltc-pass c2pool \
    --web-port 9090 --no-doge
```

Explorer: `http://localhost:9090`

### Full option reference

```bash
./build/src/c2pool/c2pool --help
```

---

## 6. Data directory

c2pool stores its data in `~/.c2pool/`:

```
~/.c2pool/
  sharechain_leveldb/      # Persistent sharechain storage
  embedded_headers/        # LTC/DOGE SPV header cache
  crash.log                # Crash log (if any)
```

---

## Cross-compiling for arm64 on an Intel Mac

If you have an Intel Mac and want to build an arm64 binary (e.g. for distribution):

### 1. Build secp256k1 for arm64

Homebrew's secp256k1 is native-only. Cross-compile from source:

```bash
git clone --depth 1 --branch v0.7.1 https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
mkdir build && cd build
cmake .. -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_INSTALL_PREFIX=$HOME/arm64-deps \
    -DSECP256K1_BUILD_TESTS=OFF \
    -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
    -DSECP256K1_BUILD_BENCHMARK=OFF \
    -DSECP256K1_BUILD_EXAMPLES=OFF
cmake --build . -j$(sysctl -n hw.ncpu)
cmake --install . --prefix $HOME/arm64-deps
```

### 2. Build c2pool for arm64

```bash
cd c2pool
mkdir build-arm64 && cd build-arm64
cmake .. -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DSECP256K1_INCLUDE_DIRS=$HOME/arm64-deps/include \
    -DSECP256K1_LIBRARIES=$HOME/arm64-deps/lib/libsecp256k1.dylib
cmake --build . --target c2pool -j$(sysctl -n hw.ncpu)
```

Binary: `build-arm64/src/c2pool/c2pool` (Mach-O arm64)

> **Important**: Use a persistent location for `arm64-deps` (not `/tmp/`).
> The arm64 secp256k1 library is needed at build time and bundled into the DMG.

### 3. Build the DMG

```bash
bash installer/macos/create-dmg.sh build-arm64/src/c2pool/c2pool arm64
```

---

## Building a DMG package

The `installer/macos/create-dmg.sh` script packages a binary with all
required assets into a distributable `.dmg` file:

```bash
# Native architecture
bash installer/macos/create-dmg.sh build/src/c2pool/c2pool

# Specific architecture
bash installer/macos/create-dmg.sh build/src/c2pool/c2pool x86_64
bash installer/macos/create-dmg.sh build-arm64/src/c2pool/c2pool arm64
```

The DMG includes: binary, `libsecp256k1.6.dylib` (with `install_name_tool`
fixup for `@executable_path`), web-static, explorer, config, start.sh, README.

---

## Troubleshooting

### `cmake` not found over SSH

Homebrew binaries are at `/usr/local/bin` (Intel) or `/opt/homebrew/bin` (Apple Silicon).
Non-login SSH sessions may not load your shell profile. Prefix commands:

```bash
export PATH=/usr/local/bin:$PATH    # Intel
export PATH=/opt/homebrew/bin:$PATH  # Apple Silicon
```

Or add to `~/.zshenv` (loaded by all zsh sessions, including non-login):

```bash
echo 'eval "$(/usr/local/bin/brew shellenv)"' >> ~/.zshenv
```

### `brew` not found after installation

Add Homebrew to your PATH:
```bash
# Apple Silicon
eval "$(/opt/homebrew/bin/brew shellenv)"

# Intel
eval "$(/usr/local/bin/brew shellenv)"
```

### Boost component not found

Homebrew Boost 1.88+ has header-only `system` component. The c2pool CMake
handles this automatically. If you see errors, try:
```bash
brew reinstall boost
```

### `std::atomic<shared_ptr>` error

Apple's libc++ does not yet support `std::atomic<std::shared_ptr>` from C++20.
The c2pool codebase uses a mutex-based fallback that works on all platforms.
Ensure you are on the latest `windows-build` or `master` branch.

### Low memory during compilation

```bash
cmake --build . --target c2pool -j1
```

---

## Other platforms

- [Ubuntu / Debian / Linux](build-unix.md)
- [Windows](build-windows.md)
