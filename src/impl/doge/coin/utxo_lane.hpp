// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded DOGE: the UTXO lane, now core::coin's (core/coin/utxo_lane.hpp,
/// shared with LTC's full set, #2137), under its DOGE names.

#include <core/coin/utxo_lane.hpp>

namespace doge {
namespace coin {

using core::coin::estimate_body_bytes;
using core::coin::full_block_peer;
using core::coin::merkle_root_of;
using core::coin::UtxoAsk;
using core::coin::UtxoLane;
using core::coin::UtxoLaneHost;
using core::coin::UtxoLaneMode;
using core::coin::UtxoLaneStats;

} // namespace coin
} // namespace doge
