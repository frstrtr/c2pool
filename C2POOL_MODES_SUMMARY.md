# C2Pool Operation Modes - Complete Documentation

> **C2Pool**: A modern, high-performance implementation of P2Pool decentralized mining in C++

## Overview

C2Pool offers three distinct operation modes designed for different use cases, from full-featured mining pools to lightweight development nodes. Each mode is optimized for specific requirements and provides different levels of functionality.

---

## 🏊 **INTEGRATED MODE** (--integrated)
### Complete Mining Pool Solution - **RECOMMENDED FOR POOL OPERATORS**

**Primary Purpose:**
Run a complete, production-ready mining pool that miners can connect to directly.

**What it provides:**
- **Full Mining Pool Infrastructure**: Everything needed to operate a mining pool
- **Multi-miner Support**: Handle dozens of concurrent miners with individual tracking
- **Real-time Monitoring**: Live statistics, hashrates, and performance metrics
- **Automated Management**: Variable difficulty, payout tracking, and system optimization

**Active Components:**
- ✅ **HTTP/JSON-RPC API Server** (port 8083) - Pool monitoring and statistics
- ✅ **Stratum Mining Server** (port 8084) - Miner connection interface
- ✅ **Enhanced Sharechain Processing** - Persistent storage with LevelDB
- ✅ **Payout Management System** - Per-miner contribution tracking
- ✅ **Variable Difficulty (VARDIFF)** - Automatic per-miner adjustment
- ✅ **Real-time Monitoring** - Live hashrate and performance tracking
- ✅ **Address Validation** - All blockchain address types supported
- ✅ **Web Interface** - Browser-based pool monitoring
- ✅ **Multi-blockchain Support** - LTC, BTC, ETH, XMR, ZEC, DOGE

**Key Features:**
- **Per-miner Statistics**: Individual hashrate, share counts, difficulty levels
- **Automatic Payout Calculation**: Fair reward distribution based on contributions
- **Advanced Difficulty Management**: Maintains optimal share submission rates
- **Comprehensive API**: RESTful endpoints for external monitoring systems
- **Production-ready**: Designed for 24/7 operation with high reliability

**Use Cases:**
- 🏊‍♂️ **Pool Operators**: Run a public or private mining pool
- 🏢 **Mining Farms**: Centralized management of multiple miners
- 🧪 **Testing Environment**: Complete mining software development testing
- 📊 **Analytics**: Detailed mining performance analysis

**Network Ports:**
- `8083` - HTTP/JSON-RPC API (configurable with --http-port)
- `8084` - Stratum Mining Protocol (configurable with --stratum-port)
- `9333` - P2P Sharechain (configurable with --p2p-port)

**Command Examples:**
```bash
# Standard pool operation (Litecoin testnet)
c2pool --integrated --blockchain ltc --testnet

# Custom port configuration
c2pool --integrated --http-port 8083 --stratum-port 8084

# Bitcoin mainnet pool
c2pool --integrated --blockchain btc --http-host 127.0.0.1
```

**API Endpoints:**
- `GET /api/stats` - Pool statistics and hashrate
- `POST /api/getinfo` - Pool information and status  
- `POST /api/getminerstats` - Per-miner detailed statistics
- `POST /api/getpayoutinfo` - Payout information and balances

---

## 🔗 **SHARECHAIN MODE** (--sharechain)
### P2P Network Participation Node - **FOR NETWORK CONTRIBUTORS**

**Primary Purpose:**
Participate in the P2Pool decentralized network by processing shares and maintaining consensus.

**What it provides:**
- **Network Participation**: Contribute to P2Pool network health and decentralization
- **Share Processing**: Validate and process shares from other network nodes
- **Consensus Maintenance**: Help maintain synchronized sharechain across the network
- **Storage Services**: Provide persistent storage for network data

**Active Components:**
- ✅ **P2P Sharechain Processing** - Enhanced share validation and processing
- ✅ **LevelDB Persistent Storage** - Reliable data storage and retrieval
- ✅ **Network Communication** (port 9333) - P2Pool protocol communication
- ✅ **Share Validation** - Cryptographic verification of network shares
- ✅ **Difficulty Tracking** - Real-time network difficulty monitoring
- ✅ **Protocol Compatibility** - Full P2Pool protocol implementation

**Key Features:**
- **Decentralized Operation**: No central authority or single point of failure
- **Network Resilience**: Contributes to overall network stability
- **Data Integrity**: Maintains complete sharechain history
- **Low Resource Usage**: Optimized for efficiency and reliability
- **Protocol Compliance**: Compatible with existing P2Pool implementations

**Use Cases:**
- 🌐 **Network Support**: Contributing to P2Pool network decentralization
- 🔧 **Infrastructure**: Running dedicated sharechain infrastructure
- 📡 **Research**: Network analysis and protocol development
- 🛡️ **Security**: Enhancing network security through participation

**Network Ports:**
- `9333` - P2P Sharechain Communication (configurable with --p2p-port)

**Command Examples:**
```bash
# Litecoin testnet sharechain node
c2pool --sharechain --blockchain ltc --testnet

# Bitcoin mainnet with custom P2P port
c2pool --sharechain --blockchain btc --p2p-port 9333

# Load configuration from file
c2pool --sharechain --config pool_config.yaml
```

---

## ⚡ **SOLO MODE** (default)
### Independent Solo Mining - **FOR SOLO MINERS**

**Primary Purpose:**
Mine independently without participating in P2Pool network, keeping 100% of block rewards.

**What it provides:**
- **Direct Blockchain Connection**: Mine directly to your own node
- **100% Block Rewards**: Keep all rewards when blocks are found
- **No Pool Dependencies**: Independent operation without sharechain
- **Simple Setup**: Minimal configuration required

**Active Components:**
- ✅ **Stratum Mining Server** - Standard mining protocol support
- ✅ **Direct Blockchain Connection** - No P2Pool network dependency
- ✅ **Local Difficulty Management** - Automatic difficulty adjustment
- ✅ **Block Template Generation** - Create work directly from blockchain
- ✅ **Solo Payout System** - 100% rewards to configured address
- ✅ **Lightweight Operation** - Minimal resource usage

**Key Features:**
- **Independent Mining**: No reliance on P2Pool network or other nodes
- **Full Rewards**: 100% of block rewards go to your address
- **Direct Control**: Complete control over mining operations
- **Blockchain Integration**: Direct connection to coin daemon
- **Simple Configuration**: Minimal setup complexity
- **Resource Efficient**: Low CPU and memory footprint

**Use Cases:**
- � **Solo Miners**: Independent mining with full rewards
- 🏠 **Home Mining**: Simple setup for personal mining
- 🔬 **Testing**: Mining protocol development and testing
- 📚 **Learning**: Understanding mining fundamentals
- 🎯 **Small Operations**: Low-complexity mining setups

**Network Ports:**
- `8084` - Stratum Mining Protocol (configurable with --stratum-port)

**Command Examples:**
```bash
# Basic solo mining (Litecoin testnet)
c2pool --testnet --blockchain ltc --stratum-port 8084

# Solo mining with specific payout address
c2pool --blockchain ltc --solo-address YOUR_LTC_ADDRESS

# Custom configuration file
c2pool --config solo_config.yaml
```

**Miner Connection:**
```bash
# Connect your miners to the solo pool
cpuminer -o stratum+tcp://127.0.0.1:8084 -u YOUR_LTC_ADDRESS -p x

# Multiple miners to same solo pool
bfgminer -o stratum+tcp://POOL_IP:8084 -u YOUR_LTC_ADDRESS -p x
```

---

## Current Production Status

### ✅ **VERIFIED WORKING FEATURES**

**Active Configuration:**
- **Mode**: INTEGRATED ✅
- **Blockchain**: Litecoin Testnet ✅
- **HTTP API**: `http://0.0.0.0:8083` ✅
- **Stratum**: `stratum+tcp://0.0.0.0:8084` ✅
- **Status**: Running with real miners connected ✅

**Production Features:**
- ✅ **Multi-miner Support** - 3+ active miners connected simultaneously
- ✅ **Per-miner Payout Tracking** - Individual contribution calculation
- ✅ **Variable Difficulty (VARDIFF)** - Automatic per-miner adjustment
- ✅ **Real-time Hashrate Monitoring** - Live performance metrics
- ✅ **JSON-RPC API Endpoints** - Complete monitoring interface
- ✅ **Address Validation** - All LTC address types (legacy, P2SH, bech32)
- ✅ **Persistent Storage** - LevelDB for sharechain and miner data
- ✅ **Share Processing** - Real mining shares accepted and processed
- ✅ **Coinbase Construction** - Proper payout address integration

### 🔄 **IN DEVELOPMENT**
- 💰 **Payment Processing** - Automatic payments when blocks found
- 📊 **Advanced Analytics** - Historical data and trends
- 🔗 **Multi-coin Support** - Additional blockchain implementations
- 🌐 **Production Scaling** - High-throughput optimizations

---

## Quick Start Guide

### For Pool Operators (Recommended):
```bash
cd /home/user0/Documents/GitHub/c2pool
./build/src/c2pool/c2pool --integrated --blockchain ltc --testnet
```

### For Network Participants:
```bash
cd /home/user0/Documents/GitHub/c2pool
./build/src/c2pool/c2pool --sharechain --blockchain ltc --testnet
```

### For Developers:
```bash
cd /home/user0/Documents/GitHub/c2pool
./build/src/c2pool/c2pool --testnet --blockchain ltc
```

---

## Support & Documentation

- **GitHub Repository**: https://github.com/frstrtr/c2pool
- **Issue Tracking**: https://github.com/frstrtr/c2pool/issues
- **Documentation**: See `/doc` directory for detailed guides
