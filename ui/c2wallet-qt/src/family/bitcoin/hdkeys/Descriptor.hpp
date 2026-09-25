// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Bitcoin Core output-descriptor import (design §3.1, "Recommended primary
// advanced path"). Parses `listdescriptors`-shaped strings —
//   pkh / wpkh / sh(wpkh) / tr / wsh(multi|sortedmulti) / sh(wsh(multi)) /
//   sh(multi) / multi / sortedmulti / combo
// — with a `[fingerprint/origin']` key origin, an xpub/xprv (or SLIP-132 /
// WIF / raw-hex) key, a post-key derivation path, and a `/*` range wildcard,
// plus the Core descriptor checksum. One descriptor expresses key + script type
// + derivation + range; it maps directly onto the M1-A type system and reuses
// the M1-A address-candidate generator (Address.hpp).
//
// Single-key script types (pkh/wpkh/sh-wpkh/tr key-path) are derived to full
// addresses. Multisig (multi/sortedmulti, incl. wsh/sh wrappers) is parsed and
// its per-index witness/redeem script + P2WSH/P2SH address are assembled here
// (m-of-n CHECKMULTISIG). No secret key is required to derive addresses; xprv
// key material, if present, is held zeroizing and never needed for addresses.

#include "Bip32.hpp"
#include "CoinParams.hpp"
#include "../../../secure/SecureString.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace c2w::hdkeys {

enum class DescType {
    Unknown, P2PKH, P2WPKH, P2SH_P2WPKH, P2TR,
    WSH_MULTI, SH_WSH_MULTI, SH_MULTI, BARE_MULTI, COMBO
};

const char* to_string(DescType t);

// One key expression inside a descriptor.
struct DescKey {
    std::string        origin_fingerprint;    // 8 hex chars, "" if no [origin]
    std::vector<uint32_t> origin_path;         // hardened bits set
    bool               has_extended = false;   // xpub/xprv/SLIP-132 node present
    std::optional<HDKey> node;                 // the extended-key node (pub-capable)
    std::vector<uint8_t> fixed_pubkey;          // raw hex pubkey (33/65), if not extended
    secure::SecureBytes  scalar;                // WIF/raw private scalar, if any
    std::vector<uint32_t> derivation;           // steps after the key (non-hardened for xpub)
    int                 wildcard_step = -1;     // index into `derivation` that is `/*`, else -1
    std::string         raw;                    // the original key-expression text
};

struct Descriptor {
    DescType    type = DescType::Unknown;
    int         threshold = 0;      // multisig m; 0 for single-key
    bool        sorted = false;     // sortedmulti
    std::vector<DescKey> keys;
    bool        has_checksum = false;
    bool        checksum_valid = false;
    std::string checksum;           // the 8-char checksum as given
};

struct DescriptorParse {
    bool ok = false;
    std::string error;
    Descriptor desc;
};

// Parse (and checksum-verify, if a `#cs` is present) a descriptor string.
DescriptorParse parse_descriptor(const std::string& text);

// Compute the Core descriptor checksum for the payload (text before any '#').
// "" if the payload contains a character outside the descriptor input charset.
std::string descriptor_checksum(const std::string& payload);

struct DerivedAddress {
    uint32_t    index;
    std::string address;
    std::string script_hex;   // scriptPubKey
    std::string detail;       // e.g. witnessScript hex for multisig, else ""
};

// Derive the addresses for indices [lo, hi] (inclusive) for the given coin.
// For a non-ranged descriptor (no `/*`) a single address is produced (lo ignored).
// Returns empty + sets `error` on a derivation the parser cannot map.
std::vector<DerivedAddress> derive_descriptor(const Descriptor& d, const CoinParams& coin,
                                              uint32_t lo, uint32_t hi, std::string& error);

} // namespace c2w::hdkeys
