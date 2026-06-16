#pragma once

/// DGB unified pool+coin config aggregate (pool-node layer, Phase B B2).
///
/// Mirrors src/impl/ltc/config.hpp verbatim except namespace — DGB-Scrypt
/// shares the identical pool::BaseNode<Config,...> contract as LTC.
/// COMPAT: keeps node-layer template instantiation parity with
/// frstrtr/p2pool-merged-v36; any divergence => [decision-needed].

#include "config_pool.hpp"
#include "config_coin.hpp"

namespace dgb
{

using Config = core::Config<PoolConfig, CoinConfig>;

} // namespace dgb
