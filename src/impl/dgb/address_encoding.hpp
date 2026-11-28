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

#include <algorithm>
#include <cstdint>
#include <vector>

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

// DGB's base58 P2PKH and P2SH versions on EVERY network (mainnet 30/63,
// testnet 126/140; regtest reuses testnet's) — StratumConfig::
// merged_parent_versions, as main_ltc publishes LTC's: a login address DGB
// could own is never identified as a merged chain's (core/merged_chain_addr.hpp).
// DGB's mainnet P2PKH 30 is also DOGE's: without this a DGB "D..." primary
// counts as a DOGE address in the login resolution.
inline std::vector<uint8_t> merged_parent_versions()
{
    std::vector<uint8_t> out;
    for (bool testnet : {false, true})
        for (bool regtest : {false, true}) {
            const auto a = address_acceptance(testnet, regtest);
            for (const auto* vs : {&a.p2pkh_versions, &a.p2sh_versions})
                for (auto v : *vs)
                    if (std::find(out.begin(), out.end(), v) == out.end())
                        out.push_back(v);
        }
    return out;
}

} // namespace dgb
