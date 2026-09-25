// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Per-coin address SSOT + capability table for the cross-coin converter
// (design docs/design/c2wallet-qt.md §4.1, requirement 5). Each entry mirrors
// the convertibility table in §4.1 — the Base58Check P2PKH/P2SH version bytes,
// the (bare) bech32 HRP, and whether taproot is active — which is the SSOT the
// converter capability-gates against.
//
// SSOT NOTE: the version bytes here mirror c2pool's per-coin
//   src/impl/<coin>/**/address_encoding.hpp leaves and the M1-A hdkeys
//   CoinParams table (which already carries a cross-check KAT against that
//   SSOT). The design names two gaps to fill for M2-A:
//     (1) an NMC leaf — Namecoin has no in-tree address_encoding.hpp SSOT yet,
//         so its P2PKH 0x34 / P2SH 0x0d / no-segwit params are carried here
//         (Namecoin chainparams). A dedicated src/impl/nmc/coin/
//         address_encoding.hpp SSOT leaf is the eventual home and is a
//         cross-lane follow-up (out of this DRAFT's ui/c2wallet-qt/ scope).
//     (2) a BCH<->base58 transcode helper — see BchTranscode.hpp.

#include <core/address_utils.hpp>   // core::CoinAddressAcceptance

#include <cstdint>
#include <string>
#include <vector>

namespace c2w::convert {

// One Family-A coin's address identity + type capabilities.
struct ConvertCoin {
    std::string ticker;                    // "BTC","LTC","DOGE","DASH","DGB","BCH","NMC" (+ "-t" testnet)
    uint8_t     p2pkh_version = 0;         // preferred P2PKH version on re-encode
    uint8_t     p2sh_version  = 0;         // preferred P2SH version on re-encode
    std::vector<uint8_t> p2pkh_accept;     // accepted P2PKH version bytes (own-address gate)
    std::vector<uint8_t> p2sh_accept;      // accepted P2SH version bytes (LTC also accepts legacy 0x05)
    std::string segwit_hrp;                // BARE bech32 HRP ("bc"/"ltc"/"dgb"); "" when no segwit
    bool        has_taproot   = false;     // bech32m P2TR active on this coin
    bool        is_bch        = false;     // native encoding is CashAddr, never a prefix swap (#961)
    std::string cashaddr_prefix;           // "bitcoincash"/"bchtest" for BCH; "" otherwise
    bool        testnet       = false;     // network tag — mainnet<->testnet convert is refused
};

// The static coin table (mainnet BTC/LTC/DOGE/DASH/DGB/BCH/NMC + a couple of
// testnet entries used by the mainnet<->testnet refuse KAT).
const std::vector<ConvertCoin>& convert_coins();

// Exact, case-sensitive ticker lookup ("BTC","LTC",...,"BTC-t"); nullptr if absent.
const ConvertCoin* convert_coin(const std::string& ticker);

// The #961 acceptance triple for a coin (bare HRPs, version bytes) that the
// core classifier consumes.
core::CoinAddressAcceptance acceptance_of(const ConvertCoin& c);

} // namespace c2w::convert
