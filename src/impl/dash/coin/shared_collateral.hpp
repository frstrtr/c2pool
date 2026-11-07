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
/// Our templates carry neither shared registrations nor ProDisTx (the codec
/// is v1/v2 and the selection mask admits provider types 1-4 only), so the
/// selection rule is simply: a tx that pays or spends the template never
/// rides, at any height. Matching is exact-script comparison.

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
