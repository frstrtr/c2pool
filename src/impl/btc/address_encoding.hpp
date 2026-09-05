// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BTC address-encoding SSOT (issue #961 blocker #3) — LEAF header.
//
// Hoisted out of btc/config_coin.hpp (which pulls yaml-cpp) so the standalone
// c2pool-qt payout validator can read BTC's version bytes / bech32 HRPs from the
// SAME source as the stratum money-path acceptance set without dragging the
// Fileconfig/yaml graph into the Qt build. Includes only <core/address_utils.hpp>
// (leaf). config_coin.hpp #includes this header, so every existing caller of
// btc::address_acceptance() is untouched.
//
// Bitcoin Core chainparams.cpp: mainnet PUBKEY_ADDRESS=0 / SCRIPT_ADDRESS=5 /
// bech32 "bc"; testnet & regtest both PUBKEY_ADDRESS=111 / SCRIPT_ADDRESS=196,
// with bech32 "tb" (testnet) vs "bcrt" (regtest). Deriving the set from the true
// network — not a mainnet-or-not bool — is what keeps a --regtest address from
// being rejected as Foreign (blocker #2).

#include <core/address_utils.hpp>   // core::CoinAddressAcceptance (issue #961)

namespace btc
{

inline core::CoinAddressAcceptance address_acceptance(bool testnet, bool regtest)
{
    core::CoinAddressAcceptance a;
    if (testnet || regtest) {
        a.p2pkh_versions = { 0x6f };  // 111 (m/n...)
        a.p2sh_versions  = { 0xc4 };  // 196 (2...)
        a.bech32_hrps    = { regtest ? "bcrt" : "tb" };
    } else {
        a.p2pkh_versions = { 0x00 };  // 1...
        a.p2sh_versions  = { 0x05 };  // 3...
        a.bech32_hrps    = { "bc" };
    }
    return a;
}

} // namespace btc
