#pragma once

/// DigiByte Scrypt P2Pool Node
///
/// DGB Scrypt uses identical share format and PoW to Litecoin Scrypt.
/// The node implementation reuses the LTC share validation, tracker,
/// and protocol handlers — only the pool/coin configuration differs.
///
/// When c2pool is started with --net digibyte:
///   - Pool network params from dgb::PoolConfig (port 5024, share period 25s)
///   - Coin params from dgb::CoinParams (port 12024, 15s blocks, D-prefix addresses)
///   - GBT requests include rules=["scrypt"] for DGB multi-algo filtering
///   - AuxPoW merged mining works identically (DOGE, PEP, BELLS, etc.)

#include "config_pool.hpp"
#include "config_coin.hpp"

#include <string>

// DGB Scrypt shares use the same format as LTC shares.
// The share type, validation logic, tracker, and protocol are shared.
// Only config_pool and config_coin differ between LTC and DGB networks.

namespace dgb
{

// Type aliases — DGB uses the same share format as LTC
// These will be used when instantiating the node template
using PoolConfigType = dgb::PoolConfig;
using CoinParamsType = dgb::CoinParams;

// ---------------------------------------------------------------------------
// Skeleton entry points (slice #4, Option B). Defined in node.cpp.
// COMPILING SKELETON ONLY — the real node run-loop is M3 / Phase B.
// ---------------------------------------------------------------------------

// One-line summary of the DGB-Scrypt network from the header-only config
// constants (no Fileconfig instantiation).
std::string network_summary();

// Skeleton run entry. Returns a process exit code. Phase B replaces this with
// the embedded-daemon + pool/sharechain run-loop.
int run_skeleton();

} // namespace dgb
