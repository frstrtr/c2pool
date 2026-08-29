// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// bch::Config -- BCH coin+pool config aggregator. Ported from
// src/impl/btc/config.hpp (M3 slice 14). Binds the BCH PoolConfig (sharechain
// params, slice 5) and CoinConfig (embedded-daemon P2P/RPC params, slice 14)
// into the shared core::Config carrier -- structurally identical to the btc
// reference; all BCH divergence lives inside the two component configs.

#include "config_pool.hpp"
#include "config_coin.hpp"

namespace bch
{

using Config = core::Config<PoolConfig, CoinConfig>;

} // namespace bch