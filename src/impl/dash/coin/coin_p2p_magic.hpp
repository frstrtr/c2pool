// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dash::coin::select_coin_p2p_magic -- pick the embedded coin-P2P wire magic
// (dashd pchMessageStart) for the E1 CoinClient.
//
// Default: mainnet bf0c6bbd / testnet cee2caff (the byte sequences dashd sends
// on a V1 plaintext connection, in wire order). A dev regtest dashd uses a
// DISTINCT V1 magic (fcc1b7dc on Dash Core v22), so an explicit override lets
// ARM A (embedded P2P relay) dial a regtest coin daemon for the E5 live-accept
// harness. Transport-only; consensus/reward-NEUTRAL. When no override is given
// the mainnet/testnet defaults are returned byte-for-byte unchanged.
// ---------------------------------------------------------------------------

#include <string>

namespace dash
{
namespace coin
{

// override_hex empty  -> testnet ? "cee2caff" : "bf0c6bbd" (unchanged defaults)
// override_hex set    -> the override verbatim (e.g. regtest "fcc1b7dc")
inline std::string select_coin_p2p_magic(const std::string& override_hex, bool testnet)
{
    if (!override_hex.empty())
        return override_hex;
    return testnet ? "cee2caff" : "bf0c6bbd";
}

} // namespace coin
} // namespace dash
