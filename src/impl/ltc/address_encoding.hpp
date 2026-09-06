// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// LTC address-encoding SSOT (issue #961 blocker #3) — LEAF header.
//
// Hoisted out of ltc/params.hpp so BOTH the node (params.hpp → make_coin_params
// + the stratum money-path acceptance set) AND the standalone c2pool-qt payout
// validator read the SAME version bytes / bech32 HRP without dragging the coin
// factory into the Qt build. Includes only <core/address_utils.hpp> (leaf) +
// <cstdint>.
//
// The ONE place LTC's payout version bytes / bech32 HRP live (p2pool-merged-v36):
// mainnet PUBKEY 48 (L...) / SCRIPT {50 (M...), 5 (legacy 3...)} / bech32 "ltc";
// testnet PUBKEY 111 / SCRIPT {196, 58 (Q...)} / bech32 "tltc". HRPs here are
// BARE; make_coin_params() appends the bech32 separator '1' for its own
// CoinParams.bech32_hrp convention. bech32_hrp2 is the secondary P2SH.

#include <core/address_utils.hpp>   // core::CoinAddressAcceptance (issue #961)

#include <cstdint>

namespace ltc
{

struct AddressEncoding {
    uint8_t     p2pkh;
    uint8_t     p2sh;
    uint8_t     p2sh2;      // secondary P2SH version (LTC only), 0 = none
    const char* hrp_bare;   // BARE bech32 HRP (no trailing '1')
};
inline constexpr AddressEncoding MAINNET_ADDR{ 48, 50, 5,  "ltc"  };
inline constexpr AddressEncoding TESTNET_ADDR{ 111, 196, 58, "tltc" };
inline constexpr const AddressEncoding& address_encoding(bool testnet)
{ return testnet ? TESTNET_ADDR : MAINNET_ADDR; }

// Registry-sourced payout-address acceptance for LTC on the ACTIVE network
// (issue #961). DERIVED from the AddressEncoding SSOT above — no re-typed
// literals. The legacy 0x05 P2SH is an inherent LTC/BTC collision (both encode
// "3..." at version byte 5): an address at 0x05 maps to the SAME hash160 the
// same key controls, so building an LTC P2SH script for it is a valid own-coin
// payout, not a misdirection. bech32 HRPs are returned BARE.
inline core::CoinAddressAcceptance address_acceptance(bool testnet)
{
    const auto& e = address_encoding(testnet);
    core::CoinAddressAcceptance a;
    a.p2pkh_versions = { e.p2pkh };
    a.p2sh_versions  = { e.p2sh };
    if (e.p2sh2 != 0) a.p2sh_versions.push_back(e.p2sh2);
    a.bech32_hrps    = { e.hrp_bare };
    return a;
}

} // namespace ltc
