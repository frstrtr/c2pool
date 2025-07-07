# C2Pool Legacy Files Archive

This directory contains legacy C2Pool files that have been replaced by the enhanced refactored implementation.

## Archived Files

### `c2pool_legacy.cpp` (formerly `c2pool.cpp`)
- **Status**: ARCHIVED - Legacy implementation
- **Replaced by**: `../src/c2pool/c2pool_refactored.cpp`
- **Reason**: Replaced with enhanced version featuring mining_shares/p2p_shares separation
- **Last archived**: 2025-07-07

### `c2pool_node_legacy.cpp` (formerly `c2pool_node.cpp`)
- **Status**: ARCHIVED - Legacy node implementation
- **Replaced by**: Enhanced node components in `../src/c2pool/node/enhanced_node.cpp`
- **Reason**: Superseded by enhanced node with better architecture
- **Last archived**: 2025-07-07

### `c2pool_temp_legacy.cpp` (formerly `c2pool_temp.cpp`)
- **Status**: ARCHIVED - Temporary/experimental code
- **Replaced by**: Integrated into main refactored implementation
- **Reason**: Experimental features integrated into production code
- **Last archived**: 2025-07-07

## Current Active Implementation

The current C2Pool implementation is located at:
- **Main entry point**: `src/c2pool/c2pool_refactored.cpp`
- **Build target**: `c2pool` (primary) and `c2pool_enhanced` (explicit name)
- **Features**: 
  - ✅ Mining_shares vs P2P_shares terminology separation
  - ✅ Enhanced difficulty adjustment (VARDIFF)
  - ✅ Real-time hashrate tracking
  - ✅ Blockchain-specific address validation
  - ✅ LevelDB persistent storage
  - ✅ Stratum mining protocol
  - ✅ Web monitoring interface

## Key Improvements in Refactored Version

1. **Clear Terminology**: 
   - `mining_share` - Shares from physical miners via Stratum
   - `p2p_share` - Shares from cross-node P2Pool communication

2. **Enhanced Architecture**:
   - Modular component design
   - Improved error handling
   - Better logging and monitoring

3. **Production Ready**:
   - Comprehensive testing
   - Stable API
   - Full Litecoin testnet integration

## Building

To build the current implementation:
```bash
cd /home/user0/Documents/GitHub/c2pool
mkdir -p build && cd build
cmake ..
make c2pool        # Primary executable
make c2pool_enhanced  # Explicit enhanced version
```

## Running

```bash
# Integrated mining pool for Litecoin testnet
./c2pool --integrated 0.0.0.0:8084 --blockchain ltc --testnet

# Enhanced sharechain node
./c2pool --sharechain --testnet --port 9333

# Help
./c2pool --help
```

## Migration Notes

If you need to reference legacy behavior, these archived files are available for comparison, but **should not be used for production**. The refactored implementation is the official, tested, and maintained version.

---

**Note**: These files are kept for historical reference only. All development should use the refactored implementation in `src/c2pool/c2pool_refactored.cpp`.
