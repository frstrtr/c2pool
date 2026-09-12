// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Derivation presets (design §3.1): BIP44 (P2PKH) / BIP49 (P2SH-P2WPKH) /
// BIP84 (P2WPKH) / BIP86 (P2TR), a custom-path escape hatch, and account /
// change / index range enumeration. coin_type comes from the SLIP-44 field in
// CoinParams.

#include "CoinParams.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace c2w::hdkeys {

enum class Purpose { BIP44 = 44, BIP49 = 49, BIP84 = 84, BIP86 = 86 };

// The output script type each purpose derives.
ScriptHint purpose_script(Purpose p);

// m / purpose' / coin_type' / account' / change / index   (change: 0 ext, 1 int)
std::vector<uint32_t> build_bip_path(Purpose p, uint32_t coin_type,
                                     uint32_t account, uint32_t change, uint32_t index);

// Parse "m/84'/0'/0'/0/5" (also accepts h / H for hardened; leading "m/" or ""
// both fine). Sets the hardened bit for apostrophe/h. nullopt on malformed input.
std::optional<std::vector<uint32_t>> parse_path(const std::string& path);

// Format a raw child-index vector back to "m/44'/0'/0'/0/0".
std::string format_path(const std::vector<uint32_t>& path);

// A single enumerated candidate path plus the metadata the scan UX groups by.
struct EnumeratedPath {
    std::vector<uint32_t> path;
    Purpose purpose;
    uint32_t account;
    uint32_t change;
    uint32_t index;
};

// Enumerate the default Bitcoin-Core-like scan grid (design §3.3): the given
// purposes × accounts × change chains × [index_lo, index_hi].
struct ScanRange {
    std::vector<Purpose> purposes = {Purpose::BIP44, Purpose::BIP49, Purpose::BIP84, Purpose::BIP86};
    std::vector<uint32_t> accounts = {0};
    std::vector<uint32_t> changes = {0, 1};
    uint32_t index_lo = 0;
    uint32_t index_hi = 19;   // gap-limit 20
};

std::vector<EnumeratedPath> enumerate(const ScanRange& r, uint32_t coin_type);

} // namespace c2w::hdkeys
