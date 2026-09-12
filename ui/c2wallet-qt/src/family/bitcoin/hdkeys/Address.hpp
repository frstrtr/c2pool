// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Address-candidate generation (design §3.1 last paragraph): one derived
// secp256k1 privkey (or pubkey) -> the per-type candidate scriptPubKeys and
// their address encodings for a given coin:
//   P2PK (compressed + uncompressed), P2PKH (both encodings), P2WPKH,
//   P2SH-P2WPKH, P2TR key-path (x-only via secp256k1_extrakeys).
// P2SH/P2WSH/bare-P2MS are script-defined and supplied later by the constructor.
//
// Reuses c2pool's codecs: btclibs/base58 (base58check) and btclibs/bech32
// (segwit v0). bech32m (segwit v1 / P2TR) reuses the same bech32 detail
// machinery with the BIP-350 checksum constant.

#include "CoinParams.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace c2w::hdkeys {

struct AddressCandidate {
    ScriptHint  type;
    std::string label;       // "P2PK", "P2PKH", "P2WPKH", "P2SH-P2WPKH", "P2TR"
    std::string encoding;    // "compressed" / "uncompressed" (empty where N/A)
    std::string address;     // bech32/base58 string; empty for bare P2PK (no address form)
    std::string script_hex;  // the scriptPubKey, always present
};

// Generate all candidate types a single key can fund on `coin`. Segwit/taproot
// candidates are skipped when the coin has no bech32 HRP (DASH/DOGE/BCH-legacy).
// `pubkey` may be 33-byte compressed or 65-byte uncompressed; both encodings are
// produced for the types that support each.
std::vector<AddressCandidate> address_candidates(const std::vector<uint8_t>& pubkey,
                                                 const CoinParams& coin);

// Same, starting from a raw private scalar (derives the pubkey, and computes the
// P2TR output key directly from the scalar via the extrakeys taptweak).
std::vector<AddressCandidate> address_candidates_from_seckey(const uint8_t sk[32],
                                                             const CoinParams& coin);

// Encoders (exposed for tests / reuse). bech32m=true selects the BIP-350 constant.
std::string encode_p2pkh(uint8_t version, const std::array<uint8_t, 20>& h160);
std::string encode_p2sh(uint8_t version, const std::array<uint8_t, 20>& h160);
std::string encode_segwit_v(const std::string& hrp, int witver,
                            const std::vector<uint8_t>& prog, bool bech32m);

} // namespace c2w::hdkeys
