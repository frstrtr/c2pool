#pragma once

#include "config_pool.hpp"
#include "config_coin.hpp"

namespace btc
{

using Config = core::Config<PoolConfig, CoinConfig>;

} // namespace btc
