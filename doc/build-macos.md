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

## Option 1: Pre-built binary

Download from the [Releases page](https://github.com/frstrtr/c2pool/releases):
- **Intel Mac**: `c2pool-VERSION-macos-x86_64.zip`
- **Apple Silicon (M1/M2/M3/M4)**: `c2pool-VERSION-macos-arm64.zip`

```bash
unzip c2pool-*-macos-*.zip
cd c2pool-*-macos-*
./start.sh
```

Dashboard: `http://localhost:8080` — Stratum: `stratum+tcp://YOUR_IP:9327`

> **macOS Gatekeeper**: On first run, macOS may block the binary. Open System Settings > Privacy & Security and click "Allow Anyway", or run: `xattr -d com.apple.quarantine c2pool`

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

## Universal binary (optional)

To build a fat binary that runs natively on both Intel and Apple Silicon:

```bash
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_ARCHITECTURES="x86_64;arm64"
cmake --build . --target c2pool -j$(sysctl -n hw.ncpu)
```

> **Note**: Universal builds require that all Homebrew dependencies are also
> available for both architectures. This may require additional setup.
> For most users, building natively for your Mac's architecture is simpler.

---

## Troubleshooting

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
