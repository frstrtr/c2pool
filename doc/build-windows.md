# Build instructions — Windows

## Option 1: Pre-built installer (recommended)

Download `c2pool-VERSION-windows-x86_64-setup.exe` from the
[Releases page](https://github.com/frstrtr/c2pool/releases).

The installer:
- Installs c2pool to `C:\Program Files\c2pool`
- Bundles the Visual C++ Runtime (installed silently)
- Creates Start Menu and Desktop shortcuts
- Adds Windows Firewall rules for ports 9326, 9327, 8080, 9333, 22556
- Includes web dashboard, block explorer, and example configs

A portable ZIP (`c2pool-VERSION-windows-x86_64.zip`) is also available.
Extract anywhere and run `c2pool.exe`. Requires the
[Visual C++ Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe)
installed separately.

### Running

```
c2pool.exe --integrated --net litecoin --dashboard-dir web-static
```

Dashboard: `http://localhost:8080`
Stratum: `stratum+tcp://YOUR_IP:9327` (miners set LTC address as username)

---

## Option 2: Build from source

### Tested configuration

| Component | Version |
|-----------|---------|
| Windows | 11 (Build 26100) |
| Visual Studio | 2022 Community (MSVC 19.44) |
| CMake | 3.28+ |
| Conan | 2.27 |
| Architecture | x86_64 |

### Prerequisites

Install via winget (Admin PowerShell):
```powershell
winget install --source winget -e --id Microsoft.VisualStudio.2022.Community --override "--add Microsoft.VisualStudio.Workload.NativeDesktop --includeRecommended --passive"
winget install --source winget -e --id Kitware.CMake
pip install "conan>=2.0,<3.0"
```

### Build secp256k1 from source

```powershell
git clone https://github.com/bitcoin-core/secp256k1
cd secp256k1
cmake -B build -G "Visual Studio 17 2022" -A x64 ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DCMAKE_INSTALL_PREFIX=C:\secp256k1 ^
    -DSECP256K1_BUILD_TESTS=OFF ^
    -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF ^
    -DSECP256K1_BUILD_BENCHMARK=OFF ^
    -DSECP256K1_BUILD_EXAMPLES=OFF
cmake --build build --config Release
cmake --install build --config Release
```

### Build c2pool

Open a **Developer Command Prompt for VS 2022** (or run `vcvarsall.bat amd64`):

```cmd
conan profile detect --force
```

Edit `%USERPROFILE%\.conan2\profiles\default` and change `compiler.cppstd=14` to `compiler.cppstd=20`.

```cmd
git clone https://github.com/frstrtr/c2pool.git
cd c2pool
mkdir build && cd build

conan install .. --build=missing --output-folder=.

cmake .. -G "Visual Studio 17 2022" -A x64 ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake ^
    -DCMAKE_PREFIX_PATH=C:\secp256k1

cmake --build . --target c2pool --config Release -j%NUMBER_OF_PROCESSORS%
```

Binary: `build\src\c2pool\Release\c2pool.exe`

> **First build**: ~20-30 min (Boost compiles from source via Conan).

### Building the installer

Install [Inno Setup 6](https://jrsoftware.org/isdl.php), then:

```cmd
"C:\...\Inno Setup 6\ISCC.exe" ^
    /DPACKAGE_DIR=C:\path\to\package ^
    /DVCREDIST_PATH="C:\...\VC\Redist\MSVC\v143\vc_redist.x64.exe" ^
    installer\windows\c2pool-setup.iss
```

The package directory must contain: `c2pool.exe`, `start.bat`, `lib\`, `web-static\`, `explorer\`, `config\`.

---

## Firewall ports

| Port | Purpose |
|------|---------|
| 9326 | P2Pool sharechain P2P |
| 9327 | Stratum mining |
| 8080 | Web dashboard |
| 9333 | LTC P2P (embedded SPV) |
| 22556 | DOGE P2P (embedded SPV) |

The installer adds these rules automatically. For manual setup:
```cmd
netsh advfirewall firewall add rule name="c2pool" dir=in action=allow protocol=tcp localport=9326,9327,8080,9333,22556
```

---

## Other platforms

- [Ubuntu / Debian / Linux](build-unix.md)
- [macOS (Intel & Apple Silicon)](build-macos.md)
