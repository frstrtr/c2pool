// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace c2w::hdkeys {

// Lowercase hex encode.
std::string to_hex(const uint8_t* data, size_t n);
inline std::string to_hex(const std::vector<uint8_t>& v) { return to_hex(v.data(), v.size()); }

// Strict hex decode: rejects odd length and non-hex chars. No 0x prefix handling.
std::optional<std::vector<uint8_t>> from_hex(const std::string& s);

} // namespace c2w::hdkeys
