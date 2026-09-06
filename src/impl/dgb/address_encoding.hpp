// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DGB address-encoding SSOT (issue #961 blocker #3) — LEAF header.
//
// Hoisted so the standalone c2pool-qt payout validator can read DGB's version
// bytes / bech32 HRPs without pulling dgb/config_coin.hpp (yaml-cpp) or
// dgb/params.hpp (config_pool/pow) into the Qt build. Includes only
// <core/address_utils.hpp> (leaf).
//
// These constants MIRROR dgb::CoinParams (config_coin.hpp), which stays the
// node-side SSOT for every OTHER consumer; params.hpp binds the two with a
// static_assert so a drift between this leaf and CoinParams is a compile error.
// DigiByte Core: mainnet PUBKEY 0x1e (D...) / P2SH 0x3f (S...) / bech32 "dgb";
// testnet PUBKEY 0x7e / P2SH 0x8c / bech32 "dgbt"; regtest reuses the testnet
// base58 bytes with bech32 "dgbrt".

#include <core/address_utils.hpp>   // core::CoinAddressAcceptance (issue #961)

#include <cstdint>

namespace dgb
{
namespace addr
{
inline constexpr uint8_t     P2PKH_MAIN     = 0x1e;  // 30  — D... (P2PKH)
inline constexpr uint8_t     P2SH_MAIN      = 0x3f;  // 63  — S... (P2SH)
inline constexpr uint8_t     P2PKH_TESTNET  = 0x7e;  // 126 (testnet)
inline constexpr uint8_t     P2SH_TESTNET   = 0x8c;  // 140 (testnet P2SH)
inline constexpr const char* BECH32_MAIN    = "dgb";
inline constexpr const char* BECH32_TESTNET = "dgbt";
inline constexpr const char* BECH32_REGTEST = "dgbrt";
} // namespace addr

// Registry-sourced payout-address acceptance for DGB on the ACTIVE network
// (issue #961). Regtest is a distinct network: DigiByte Core CRegTestParams
// reuses the TESTNET base58 version bytes and swaps the bech32 HRP to "dgbrt" —
// deriving the set from the true network (not a mainnet-or-not bool) is what
// stops a --regtest payout address being rejected as Foreign.
inline core::CoinAddressAcceptance address_acceptance(bool testnet, bool regtest)
{
    core::CoinAddressAcceptance a;
    if (testnet || regtest) {
        a.p2pkh_versions = { addr::P2PKH_TESTNET };
        a.p2sh_versions  = { addr::P2SH_TESTNET };
        a.bech32_hrps    = { regtest ? addr::BECH32_REGTEST : addr::BECH32_TESTNET };
    } else {
        a.p2pkh_versions = { addr::P2PKH_MAIN };
        a.p2sh_versions  = { addr::P2SH_MAIN };
        a.bech32_hrps    = { addr::BECH32_MAIN };
    }
    return a;
}

} // namespace dgb
