// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include "config_pool.hpp"
#include "config_coin.hpp"

namespace btc
{

using Config = core::Config<PoolConfig, CoinConfig>;

} // namespace btc