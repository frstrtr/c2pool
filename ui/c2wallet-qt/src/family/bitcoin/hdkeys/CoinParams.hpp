// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Per-coin key-layer parameters for the Bitcoin-script family.
//
// Design §2.4 / §3.1: the P2PKH / P2SH / bech32-HRP version bytes are the
// SSOT owned by src/impl/<coin>/**/address_encoding.hpp and MUST NOT be
// re-hardcoded elsewhere. This table therefore carries only what that SSOT
// does NOT express — the WIF version byte, the SLIP-44 coin_type, and the
// BIP32 (+ SLIP-132) extended-key version prefixes — and the KAT
// `bip32_versions_match_address_encoding_ssot` cross-checks the address bytes
// this table reproduces against the SSOT header so the two never drift.

#include "Bip32.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace c2w::hdkeys {

// Which single-key script type an extended-key prefix or a derivation preset
// implies (SLIP-132: a zpub hints P2WPKH intent, ypub hints P2SH-P2WPKH).
enum class ScriptHint { Unknown, P2PKH, P2SH_P2WPKH, P2WPKH, P2TR };

struct CoinParams {
    const char* name;
    const char* ticker;         // "BTC", "LTC", "DOGE", "DASH", "DGB", "BCH"; "-t" = testnet
    uint32_t    slip44;         // BIP44 coin_type (testnet is 1)
    uint8_t     p2pkh_version;  // mirrors address_encoding.hpp SSOT
    uint8_t     p2sh_version;   // mirrors address_encoding.hpp SSOT
    uint8_t     wif_version;    // NOT in the SSOT (base58 secret prefix)
    const char* bech32_hrp;     // "" when the coin has no segwit (DASH/DOGE/BCH-legacy)
    bool        testnet;
    Bip32Versions std_bip32;    // default xprv/xpub pair for this coin
};

const std::vector<CoinParams>& all_coins();
const CoinParams* coin_by_ticker(const std::string& ticker);   // exact, case-sensitive
std::vector<const CoinParams*> coins_by_wif_version(uint8_t version); // may collide (0x80)

// SLIP-132 / BIP32 extended-key prefix registry entry.
struct Slip132Entry {
    uint32_t      version;    // the 4-byte prefix (e.g. 0x04B2430C for zprv)
    bool          is_private; // xprv/yprv/zprv/... vs xpub/ypub/zpub/...
    Bip32Versions versions;   // the priv/pub pair this prefix belongs to
    ScriptHint    hint;       // implied script type
    const char*   ticker;     // owning coin (best-effort; standard xprv maps to BTC)
    const char*   label;      // "xprv","zpub","Ltpv",...
};

// Resolve a 4-byte extended-key version prefix. nullptr if unrecognised.
const Slip132Entry* lookup_bip32_version(uint32_t version);

} // namespace c2w::hdkeys
