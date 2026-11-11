// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The Dash Core v24 shared-masternode collateral template script
/// (src/evo/sharedcollateral.h): 0x04 "DSHC" OP_DROP OP_TRUE, hex
/// 04445348437551. At the script layer it is anyone-can-spend; consensus
/// (CheckSharedCollateralTemplateOutputs / CheckSharedCollateralSpends, every
/// block tx including the coinbase) allows an output paying it only as the
/// collateral of a shared v3 ProRegTx, and a spend of it only from a ProDisTx.
/// Before v24 such outputs and spends are nonstandard.
///
/// Selection (mempool.hpp): a tx paying the template rides only as a shared
/// registration whose collateral output it is, and a tx spending it only as
/// a ProDisTx, both only under v24 with the provider fold armed (the Dash
/// Core checks and the v24 fold decide them there). Matching is exact-script
/// comparison.

#include <array>
#include <cstdint>
#include <vector>

namespace dash {
namespace coin {

inline constexpr std::array<uint8_t, 7> kSharedCollateralScript = {0x04, 'D', 'S', 'H', 'C', 0x75, 0x51};

inline bool is_shared_collateral_script(const std::vector<uint8_t>& script)
{
    return script.size() == kSharedCollateralScript.size()
        && std::equal(script.begin(), script.end(), kSharedCollateralScript.begin());
}

} // namespace coin
} // namespace dash
