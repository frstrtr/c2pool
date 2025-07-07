# C2Pool Usage Guide - Complete Documentation

> **C2Pool v2.0**: Production-ready P2Pool implementation with enhanced features, payout management, and robust configuration

## Quick Start

### For Pool Operators (Recommended)
```bash
# Start integrated mining pool on Litecoin testnet
cd /home/user0/Documents/GitHub/c2pool
./build/src/c2pool/c2pool --integrated --blockchain ltc --testnet

# Pool will be available at:
# - HTTP API: http://localhost:8083
# - Stratum: stratum+tcp://localhost:8084
```

### For Miners
```bash
# Connect your miner to the pool
cpuminer -o stratum+tcp://POOL_IP:8084 -u YOUR_LTC_ADDRESS -p x

# Example with actual testnet address:
cpuminer -o stratum+tcp://127.0.0.1:8084 -u tltc1qw8wrek2m7nlqldll66ajnwr9mh0mz8kq2udy82 -p x
```

---

## Command Line Interface

### Enhanced Help Output
```bash
./build/src/c2pool/c2pool --help
```

The help output now includes:
- **Visual formatting** with Unicode borders and emojis
- **Clear mode descriptions** with specific use cases  
- **Complete feature lists** with checkmarks
- **Port configuration** with defaults and explanations
- **Blockchain support status** (working vs. in development)
- **Usage examples** for all three modes
- **API endpoint documentation**
- **GitHub links** for further documentation

### Operation Modes

#### 🏊 Integrated Mode (--integrated)
**Complete mining pool solution - RECOMMENDED FOR POOL OPERATORS**

```bash
# Standard pool operation
./build/src/c2pool/c2pool --integrated --blockchain ltc --testnet

# Custom port configuration  
./build/src/c2pool/c2pool --integrated --http-port 8083 --stratum-port 8084

# Bitcoin mainnet with local binding
./build/src/c2pool/c2pool --integrated --blockchain btc --http-host 127.0.0.1
```

**Active Components:**
- HTTP/JSON-RPC API Server (port 8083)
- Stratum Mining Server (port 8084)  
- Enhanced Sharechain Processing
- Payout Management System
- Variable Difficulty (VARDIFF)
- Real-time Monitoring
- LevelDB Storage

#### 🔗 Sharechain Mode (--sharechain)
**P2P network participation - FOR NETWORK CONTRIBUTORS**

```bash
# Join Litecoin testnet P2Pool network
./build/src/c2pool/c2pool --sharechain --blockchain ltc --testnet

# Bitcoin mainnet sharechain node
./build/src/c2pool/c2pool --sharechain --blockchain btc --p2p-port 9333

# Load from configuration file
./build/src/c2pool/c2pool --sharechain --config pool_config.yaml
```

**Active Components:**
- P2P Sharechain Processing
- LevelDB Persistent Storage
- Network Communication (port 9333)
- Share Validation
- Difficulty Tracking

#### ⚡ Basic Mode (default)
**Minimal node for development - FOR TESTING & DEVELOPMENT**

```bash
# Basic testnet node
./build/src/c2pool/c2pool --testnet --blockchain ltc

# Bitcoin mainnet basic node
./build/src/c2pool/c2pool --blockchain btc --p2p-port 9333

# Custom configuration
./build/src/c2pool/c2pool --config custom_config.yaml
```

**Active Components:**
- Basic P2P Functionality
- Lightweight Operation
- Core Protocol Features

---

## Port Configuration

### Robust Port Management
C2Pool now uses **explicit port configuration** with no automatic port+1 logic:

```bash
# Explicit port specification (recommended)
./build/src/c2pool/c2pool --integrated \
  --http-port 8083 \
  --stratum-port 8084 \
  --p2p-port 9333 \
  --http-host 0.0.0.0
```

### Default Ports
- **P2P Sharechain**: 9333 (for P2Pool network communication)
- **HTTP API**: 8083 (for monitoring and statistics)  
- **Stratum Mining**: 8084 (for miner connections)
- **HTTP Host**: 0.0.0.0 (bind to all interfaces)

### Port Configuration Options
```bash
--p2p-port PORT       # P2P sharechain port (default: 9333)
--http-port PORT      # HTTP/JSON-RPC API port (default: 8083)  
--stratum-port PORT   # Stratum mining port (default: 8084)
--http-host HOST      # HTTP server bind address (default: 0.0.0.0)
```

---

## API Endpoints

### HTTP/JSON-RPC API (Port 8083)
Available in **Integrated Mode** only:

#### Pool Statistics
```bash
# GET request for basic stats
curl http://localhost:8083/api/stats

# Response includes:
# - Pool hashrate
# - Connected miners count
# - Share statistics
# - Network difficulty
```

#### Detailed Pool Information  
```bash
# POST request for complete pool info
curl -X POST http://localhost:8083/api/getinfo \
  -H "Content-Type: application/json" \
  -d '{"method":"getinfo","params":[],"id":1}'

# Response includes:
# - Pool configuration
# - Network status
# - Blockchain information
# - Version details
```

#### Per-Miner Statistics
```bash
# POST request for miner-specific data
curl -X POST http://localhost:8083/api/getminerstats \
  -H "Content-Type: application/json" \
  -d '{"method":"getminerstats","params":[],"id":1}'

# Response includes:
# - Individual miner hashrates
# - Share counts and difficulty
# - Connection timestamps
# - VARDIFF adjustments
```

#### Payout Information
```bash
# POST request for payout data
curl -X POST http://localhost:8083/api/getpayoutinfo \
  -H "Content-Type: application/json" \
  -d '{"method":"getpayoutinfo","params":[],"id":1}'

# Response includes:
# - Per-miner contributions
# - Payout calculations
# - Balance information
# - Payment history
```

### Stratum Mining Protocol (Port 8084)
Standard mining protocol for miner connections:

```bash
# Miner connection string
stratum+tcp://POOL_IP:8084

# Authentication: use your payout address as username
# Password: any value (typically 'x')
```

---

## Features & Capabilities

### ✅ Production-Ready Features

#### Variable Difficulty (VARDIFF)
- **Automatic per-miner adjustment** based on hashrate
- **Target share interval**: 30 seconds per miner
- **Difficulty range**: 1 to network difficulty  
- **Real-time adaptation** to hashrate changes

#### Payout Management System
- **Per-miner contribution tracking** with persistent storage
- **Fair reward distribution** based on share contributions
- **Address validation** for all supported blockchain types
- **Automatic payout calculation** when blocks are found

#### Real-time Monitoring
- **Live hashrate tracking** for pool and individual miners
- **Share acceptance rates** and rejection monitoring  
- **Network difficulty tracking** with automatic updates
- **Connection status** and miner activity logging

#### Multi-blockchain Support
- **Litecoin (LTC)**: ✅ Full support with testnet
- **Bitcoin (BTC)**: ✅ Protocol compatibility
- **Ethereum (ETH)**: 🔧 In development
- **Monero (XMR)**: 🔧 In development  
- **Zcash (ZEC)**: 🔧 In development
- **Dogecoin (DOGE)**: 🔧 In development

#### Address Validation
Supports all address types for each blockchain:
- **Legacy addresses** (P2PKH)
- **P2SH-SegWit addresses** (P2WPKH-in-P2SH)
- **Native SegWit addresses** (bech32)

#### Persistent Storage
- **LevelDB integration** for reliable data storage
- **Sharechain persistence** across restarts
- **Miner statistics retention** for historical data
- **Configuration backup** and recovery

---

## Configuration Files

### YAML Configuration Support
```bash
# Load configuration from file
./build/src/c2pool/c2pool --config pool_config.yaml
```

### Example Configuration (c2pool_testnet.yaml)
```yaml
# C2Pool Configuration
network:
  testnet: true
  blockchain: "ltc"
  
ports:
  p2p: 9333
  http: 8083  
  stratum: 8084
  
server:
  host: "0.0.0.0"
  
pool:
  name: "C2Pool Testnet"
  description: "Modern P2Pool implementation"
```

---

## Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Check what's using the port
sudo netstat -tlnp | grep 8084

# Kill process if needed
sudo kill -9 PID

# Or use different ports
./build/src/c2pool/c2pool --integrated --stratum-port 8085
```

#### Connection Issues
```bash
# Check if pool is running
curl http://localhost:8083/api/stats

# Check firewall settings
sudo ufw allow 8083
sudo ufw allow 8084

# Verify miner connection
telnet localhost 8084
```

#### Build Issues
```bash
# Clean build
cd /home/user0/Documents/GitHub/c2pool
rm -rf build
mkdir build && cd build
cmake .. && make -j$(nproc)
```

### Log Analysis
```bash
# Monitor real-time logs
./build/src/c2pool/c2pool --integrated --testnet | grep -E "(SHARE|PAYOUT|MINER)"

# Key log patterns:
# - "SHARE ACCEPTED" - successful share submission
# - "VARDIFF" - difficulty adjustments
# - "PAYOUT" - payout calculations  
# - "MINER" - miner connections/disconnections
```

---

## Development

### Testing New Features
```bash
# Basic mode for development
./build/src/c2pool/c2pool --testnet --blockchain ltc

# Enable verbose logging
export C2POOL_LOG_LEVEL=DEBUG
./build/src/c2pool/c2pool --integrated --testnet
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Test changes with real miners
4. Submit pull request with detailed description

### Code Organization
```
src/c2pool/
├── c2pool_refactored.cpp    # Main application with CLI parsing
├── payout/                  # Payout management system
│   ├── payout_manager.hpp   # PayoutManager class
│   └── payout_manager.cpp   # Implementation
└── ...

src/core/
├── web_server.cpp           # HTTP API and Stratum server
├── web_server.hpp           # Server declarations
└── ...
```

---

## Production Deployment

### System Requirements
- **OS**: Linux (Ubuntu 20.04+ recommended)
- **CPU**: 2+ cores
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 50GB+ for blockchain data
- **Network**: Reliable internet connection

### Security Considerations
- **Firewall**: Only expose necessary ports (8083, 8084, 9333)
- **SSL/TLS**: Consider reverse proxy for HTTPS
- **Monitoring**: Set up log monitoring and alerting
- **Backups**: Regular backup of LevelDB data

### Performance Tuning
- **Connection limits**: Adjust for expected miner count
- **Database optimization**: Tune LevelDB settings
- **Network buffer sizes**: Optimize for high throughput
- **Resource monitoring**: CPU, memory, and I/O usage

---

## Support & Resources

### Documentation
- **GitHub Repository**: https://github.com/frstrtr/c2pool
- **Issue Tracking**: https://github.com/frstrtr/c2pool/issues
- **Build Instructions**: `/doc/build-unix.md`
- **Configuration Templates**: `/doc/configs-templates/`

### Community
- **Discussions**: GitHub Discussions
- **Bug Reports**: GitHub Issues  
- **Feature Requests**: GitHub Issues with enhancement label

### Status
**Current Version**: 2.0 (Production Ready)
**Last Updated**: December 2024
**Tested With**: Real Litecoin testnet mining operations
**Status**: ✅ Actively maintained and production-ready

---

*This documentation reflects the current state of C2Pool with all production features implemented and tested with real mining operations.*
