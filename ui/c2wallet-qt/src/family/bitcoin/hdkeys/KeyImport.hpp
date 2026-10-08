// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Family A (Bitcoin-script) single-key import formats that need no HD context:
//   * WIF   — base58check, per-coin version byte from CoinParams (SSOT-sourced,
//             not re-hardcoded), trailing 0x01 => compressed. Design §3.1.
//   * raw   — 64 hex chars => 32-byte scalar with the mandatory 1 <= k < N
//             range-check (design §3.1: reject 0 and >= N).
//
// The secret is returned in a zeroizing SecureBytes (design §5.3). Higher-level
// HD imports (BIP39/BIP32) live in Bip39/Bip32; address candidates come from
// Address.hpp.

#include "../../../secure/SecureString.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace c2w::hdkeys {

struct WifDecode {
    bool ok = false;
    std::string error;
    secure::SecureBytes scalar;               // 32-byte private key (valid iff ok)
    bool compressed = false;
    uint8_t version = 0;
    std::vector<std::string> coin_tickers;    // coins whose WIF version matches (may be >1)
};

// Decode a WIF string. The coin identity is a HINT (0x80 collides across
// BTC/DGB/BCH); the scalar and compressed flag are unambiguous. Range-checked.
WifDecode decode_wif(const std::string& wif);

struct RawHexDecode {
    bool ok = false;
    std::string error;
    secure::SecureBytes scalar;   // 32-byte private key (valid iff ok)
    bool compressed = true;
};

// Decode a 64-char hex private key with the 1 <= k < N range-check.
RawHexDecode decode_raw_hex(const std::string& hex, bool compressed = true);

} // namespace c2w::hdkeys
