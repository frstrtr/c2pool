// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded DOGE: the full UTXO set's state, now core::coin's
/// (core/coin/utxo_full_state.hpp, shared with LTC's full set, #2137),
/// under its DOGE name.

#include <core/coin/utxo_full_state.hpp>
#include <impl/doge/coin/process_memory.hpp>

namespace doge {
namespace coin {

using core::coin::UtxoFullState;

} // namespace coin
} // namespace doge
