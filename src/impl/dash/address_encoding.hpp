// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH address-encoding SSOT (issue #961 blocker #3) — LEAF header.
//
// Hoisted out of dash/params.hpp so BOTH the node (params.hpp → make_coin_params
// + the stratum money-path acceptance set) AND the standalone c2pool-qt payout
// validator can read the SAME version bytes without dragging the node's
// pow/x11/config_pool graph into the Qt build. This header includes only
// <core/address_utils.hpp> (leaf: std only) + <cstdint>, so it is a pure data
// SSOT with zero heavy transitive dependencies. dash/params.hpp #includes it,
// so every existing caller is untouched; the Qt AddressValidator includes it
// directly, so the UI check can NEVER drift from the node's acceptance set.
//
// The ONE place DASH's payout version bytes live (oracle networks/dash.py):
// mainnet PUBKEY 76 (X...) / SCRIPT 16 (7...); testnet PUBKEY 140 (y...) /
// SCRIPT 19. DASH has a SINGLE P2SH version and NO segwit/bech32 on any network.

#include <core/address_utils.hpp>   // core::CoinAddressAcceptance (issue #961)

#include <cstdint>

namespace dash
{

struct AddressEncoding { uint8_t p2pkh; uint8_t p2sh; };
inline constexpr AddressEncoding MAINNET_ADDR{ 76,  16 };  // X... / 7...
inline constexpr AddressEncoding TESTNET_ADDR{ 140, 19 };  // y...
inline constexpr const AddressEncoding& address_encoding(bool testnet)
{ return testnet ? TESTNET_ADDR : MAINNET_ADDR; }

// Registry-sourced payout-address acceptance for DASH on the ACTIVE network
// (issue #961). DERIVED from the AddressEncoding SSOT above — no re-typed
// literals. DASH regtest (dashd CRegTestParams) reuses the testnet base58 version
// bytes, so a --regtest payout address decodes under the testnet set rather than
// being rejected as Foreign.
inline core::CoinAddressAcceptance address_acceptance(bool testnet, bool regtest)
{
    const auto& e = address_encoding(testnet || regtest);
    core::CoinAddressAcceptance a;
    a.p2pkh_versions = { e.p2pkh };
    a.p2sh_versions  = { e.p2sh };
    a.bech32_hrps    = {};           // DASH: no bech32 on any network
    return a;
}

} // namespace dash
