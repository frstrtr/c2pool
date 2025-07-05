# Unix Build Instructions

This document covers building c2pool on Unix-like systems including Linux distributions and FreeBSD.

> [!WARNING]
> While compiling you may get an error like:\
> `c++: internal compiler error: Killed (program cc1plus)`\
> \
> Reasons:
> 1. Low ram/swap. Increase ram/swap or decrease the amount of make -j to 1 (more compile threads -> more mem usage).
> 2. SELinux/grsecurity/Hardened kernel: Kernels that use ASLR as a security measure tend to mess up GCC's precompiled header implementation. Try using an unhardened kernel (without ASLR), or compiling using clang, or gcc without pch. (you can get this issue when using OVH hosting).

> [!NOTE]
> **CMake 3.30+ Compatibility**: This project now supports CMake 3.30+ which removed the FindBoost module. The build system automatically detects and adapts to your CMake version.

# Dependencies
| Name      | Version    | Notes |
|-----------|------------|-------|
| CMake     | >= 3.22    | 3.30+ supported with automatic compatibility |
| OpenSSL   | >= 3.xx    | |
| GCC       | 11+        | Or equivalent Clang version |
| Boost     | 1.78+      | Components: log, log_setup, thread, filesystem, system |
| nlohmann-json | Any    | JSON library |
| yaml-cpp  | Any        | YAML configuration support |
| GoogleTest| Any        | For testing (optional) |
| LevelDB   | Any        | Database backend |

## Linux (Ubuntu/Debian) Instructions

```shell
sudo apt update & apt upgrade
sudo apt install wget
sudo apt install git

sudo apt install g++-11
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 1100 --slave /usr/bin/g++ g++ /usr/bin/g++-11

sudo apt install cmake
sudo apt install make
sudo apt-get install libleveldb-dev
sudo apt install qt6-base-dev
```

If ui config is needed:

```shell
sudo apt-get install libgl1-mesa-dev
```

install boost 1.78.0:

```shell
wget -O boost_1_78_0.tar.gz https://boostorg.jfrog.io/artifactory/main/release/1.78.0/source/boost_1_78_0.tar.gz
tar xzvf boost_1_78_0.tar.gz
cd boost_1_78_0
./bootstrap.sh --prefix=/usr/
sudo ./b2 install
```

## FreeBSD Instructions

FreeBSD users can install dependencies using the package manager:

```shell
pkg install cmake
pkg install leveldb
pkg install boost-all
pkg install googletest
pkg install nlohmann-json
pkg install yaml-cpp
```

## Building c2pool

For all Unix systems (Linux, FreeBSD, etc.):

```shell
git clone https://github.com/frstrtr/c2pool.git
cd c2pool
mkdir build
cmake -DCMAKE_BUILD_TYPE=Debug -S . -B build
make -C build c2pool -j$(nproc)
```

## Configuration

UI Config:

```shell
./build/src/c2pool/c2pool --ui_config
```

## Running

Start the mining pool with web server:

```shell
./build/src/c2pool/c2pool --web_server=0.0.0.0:8083
```

### Mining Pool Features

- **HTTP/JSON-RPC interface** on port 8083 for standard miners
- **Native Stratum protocol** on port 8084 for hardware miners
- **Automatic sync detection** - Stratum starts only when blockchain is synchronized
- **Multi-network support** - LTC, BTC, DGB
- **Comprehensive address validation** - All address formats supported

### Supported Methods

- `getwork`, `submitwork` - Standard mining interface
- `getblocktemplate`, `submitblock` - Advanced mining
- `getinfo`, `getstats` - Pool statistics
- `mining.subscribe`, `mining.authorize`, `mining.submit` - Stratum protocol

## Troubleshooting

### CMake 3.30+ Issues

If you encounter Boost-related errors with newer CMake versions, the build system automatically handles compatibility. No manual intervention required.

### Low Memory Issues

If compilation fails with "internal compiler error: Killed", reduce parallel compilation:

```shell
make -C build c2pool -j1
```

### FreeBSD Specific Notes

- Ensure all dependencies are installed via `pkg install`
- The build process is identical to Linux after dependency installation
- Some package names may differ slightly between FreeBSD versions