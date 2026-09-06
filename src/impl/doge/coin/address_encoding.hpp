// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DOGE address-encoding SSOT (issue #961) — LEAF header.
//
// DOGE is an aux lane carried inside the LTC/BTC binaries and has no standalone
// coin params factory with an address_acceptance(); this header provides the ONE
// place DOGE's payout version bytes live so BOTH the merged-mining address
// identification (core::MergedChainAddr) AND the standalone c2pool-qt payout
// validator read the SAME bytes. Includes only <core/address_utils.hpp> (leaf).
//
// Dogecoin chainparams.cpp: mainnet PUBKEY 0x1e (30, D...) / SCRIPT 0x16 (22,
// 9.../A...); testnet PUBKEY 0x71 (113, n...) / SCRIPT 0xc4 (196). DOGE has no
// segwit/bech32.

#include <core/address_utils.hpp>   // core::CoinAddressAcceptance (issue #961)

#include <cstdint>

namespace doge
{

struct AddressEncoding { uint8_t p2pkh; uint8_t p2sh; };
inline constexpr AddressEncoding MAINNET_ADDR{ 0x1e, 0x16 };  // 30 / 22
inline constexpr AddressEncoding TESTNET_ADDR{ 0x71, 0xc4 };  // 113 / 196
inline constexpr const AddressEncoding& address_encoding(bool testnet)
{ return testnet ? TESTNET_ADDR : MAINNET_ADDR; }

// Registry-sourced payout-address acceptance for DOGE on the ACTIVE network.
// Regtest reuses the testnet base58 bytes. No bech32 on any network.
inline core::CoinAddressAcceptance address_acceptance(bool testnet, bool regtest = false)
{
    const auto& e = address_encoding(testnet || regtest);
    core::CoinAddressAcceptance a;
    a.p2pkh_versions = { e.p2pkh };
    a.p2sh_versions  = { e.p2sh };
    a.bech32_hrps    = {};
    return a;
}

} // namespace doge
