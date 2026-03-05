# c2pool - p2pool rebirth in c++
(started 02.02.2020)

based on Forrest Voight (https://github.com/forrestv) concept and python code (https://github.com/p2pool/p2pool)

Bitcoin wiki page - https://en.bitcoin.it/wiki/P2Pool

Bitcointalk forum thread - https://bitcointalk.org/index.php?topic=18313

Some technical details - https://bitcointalk.org/index.php?topic=457574

---

## ⚡ Want a Working Pool Right Now?

C2Pool (C++ rewrite) is actively under development. While it matures, **fully functional and live p2pool implementations** are available in these repositories:

| Repository | Coins | Status |
|---|---|---|
| [**frstrtr/p2pool-merged-v36**](https://github.com/frstrtr/p2pool-merged-v36) | Litecoin · DigiByte · Dogecoin (merged mining) | ✅ Live — V36 share format, Docker, multichain dashboard |
| [**frstrtr/p2pool-dash**](https://github.com/frstrtr/p2pool-dash) | Dash | ✅ Live — decentralized Dash pool |

Both are production-ready, actively maintained forks of the original Python p2pool with modern improvements (V36 protocol, Docker images, enhanced dashboards).

---

## 🎯 **Enhanced C2Pool - Refactored Implementation**

C2Pool has been **completely refactored** with enhanced features and clear terminology separation:

### ✨ **Key Improvements**
- **🔄 Share Type Separation** - Clear distinction between:
  - `mining_shares` - From physical miners via Stratum protocol
  - `p2p_shares` - From cross-node P2Pool communication
- **⚡ Automatic Difficulty Adjustment (VARDIFF)** - Dynamic mining difficulty
- **📊 Real-time Hashrate Tracking** - Accurate performance monitoring  
- **💾 Persistent Storage** - LevelDB-based sharechain persistence
- **🌐 Web Interface** - JSON-RPC mining interface with monitoring
- **🔐 Blockchain-specific Address Validation** - Multi-coin support
- **📈 Enhanced Statistics** - Separated mining vs P2P metrics

### 🏗️ **Modular Components**
- **`hashrate/`** - Real-time hashrate tracking with mining_share metrics
- **`difficulty/`** - Automatic difficulty adjustment engine
- **`storage/`** - Persistent LevelDB sharechain storage
- **`node/`** - Enhanced C2Pool node implementation
- **`archive/`** - Legacy code archive (for reference only)

### 🚀 **Quick Start**

#### Building
```bash
git clone https://github.com/username/c2pool.git
cd c2pool
mkdir build && cd build
cmake ..
make c2pool        # Primary executable (refactored)
make c2pool_enhanced  # Explicit enhanced version
```

#### Running
```bash
# Integrated mining pool for Litecoin testnet
./c2pool --integrated 0.0.0.0:8084 --blockchain ltc --testnet

# Enhanced sharechain node
./c2pool --sharechain --testnet --port 9333

# Help
./c2pool --help
```

### 📊 **Current Implementation**

- **Primary Entry Point**: `src/c2pool/c2pool_refactored.cpp`
- **Build Targets**: `c2pool` (primary), `c2pool_enhanced` (explicit)
- **Legacy Files**: Archived in `archive/` directory for reference

#### Build Enhanced C2Pool
```bash
mkdir -p build && cd build
cmake ..
make c2pool_enhanced -j4
```

#### Run Mining Pool with Web Interface
```bash
./src/c2pool/c2pool_enhanced --testnet --integrated 0.0.0.0:8083
```
Access web interface at: http://localhost:8083

#### Run Enhanced Sharechain Node
```bash
./src/c2pool/c2pool_enhanced --testnet --sharechain
```

#### Available Options
```bash
./src/c2pool/c2pool_enhanced --help
```

### 📊 **Features**
- ✅ Automatic difficulty adjustment (VARDIFF)
- ✅ Real-time hashrate tracking
- ✅ Legacy share tracker compatibility
- ✅ LevelDB persistent storage
- ✅ JSON-RPC mining interface
- ✅ WebUI for monitoring

See [docs/REFACTORING_SUMMARY.md](docs/REFACTORING_SUMMARY.md) for detailed technical information.

---

<details>
  
  <summary>Donations towards further development of с2pool implementation in C++</summary>


### PayPal donation:

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=9DF676HUWAHKY)

![image](https://github.com/frstrtr/c2pool/assets/4164913/51e82162-3d0b-435a-89b7-d8051983b3dc)


</details>

### Telegram
https://t.me/c2pooldev

### Discord:
https://discord.gg/yb6ujsPRsv

# Install:
### [UNIX instruction](doc/build-unix.md)
### [FreeBSD specific guide](doc/build-freebsd.md)
### [Windows instruction](doc/build-windows.md)
