// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BCH LEGACY-base58 address-encoding SSOT (issue #961 blocker #3) — LEAF header.
//
// Hoisted out of bch/config_coin.hpp (which pulls yaml-cpp) so the standalone
// c2pool-qt payout validator can read BCH's legacy version bytes from the SAME
// source as the stratum money-path acceptance set. Includes only
// <core/address_utils.hpp> (leaf). config_coin.hpp #includes this header.
//
// BCH legacy base58 shares Bitcoin's version bytes (BCHN chainparams.cpp):
// mainnet PUBKEY 0 / SCRIPT 5; testnet & regtest both PUBKEY 111 / SCRIPT 196.
// BCH has NO segwit/bech32 — its native CashAddr is a DISTINCT format with no
// base58 version byte (validated separately by the CashAddr codec).

#include <core/address_utils.hpp>   // core::CoinAddressAcceptance (issue #961)

namespace bch
{

inline core::CoinAddressAcceptance address_acceptance(bool testnet, bool regtest)
{
    core::CoinAddressAcceptance a;
    if (testnet || regtest) {
        a.p2pkh_versions = { 0x6f };  // 111
        a.p2sh_versions  = { 0xc4 };  // 196
    } else {
        a.p2pkh_versions = { 0x00 };
        a.p2sh_versions  = { 0x05 };
    }
    a.bech32_hrps = {};               // BCH: no bech32 (CashAddr via fallback)
    return a;
}

} // namespace bch
