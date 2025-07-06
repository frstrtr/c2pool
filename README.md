# c2pool - p2pool rebirth in c++
(started 02.02.2020)

based on Forrest Voight (https://github.com/forrestv) concept and python code (https://github.com/p2pool/p2pool)

Bitcoin wiki page - https://en.bitcoin.it/wiki/P2Pool

Bitcointalk forum thread - https://bitcointalk.org/index.php?topic=18313

Some technical details - https://bitcointalk.org/index.php?topic=457574

## 🎯 **Enhanced C2Pool - Modular Architecture**

C2Pool has been **refactored into a modular architecture** with enhanced features:

### ✨ **New Features**
- **Automatic Difficulty Adjustment (VARDIFF)** - Dynamic mining difficulty
- **Real-time Hashrate Tracking** - Accurate performance monitoring  
- **Persistent Storage** - LevelDB-based sharechain persistence
- **Web Interface** - JSON-RPC mining interface with monitoring
- **Legacy Compatibility** - Full backward compatibility maintained

### 🏗️ **Modular Components**
- **`hashrate/`** - Real-time hashrate tracking and statistics
- **`difficulty/`** - Automatic difficulty adjustment engine
- **`storage/`** - Persistent LevelDB sharechain storage
- **`bridge/`** - Legacy compatibility layer
- **`node/`** - Enhanced C2Pool node implementation

### 🚀 **Quick Start**

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

See [REFACTORING_SUMMARY.md](REFACTORING_SUMMARY.md) for detailed technical information.

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
