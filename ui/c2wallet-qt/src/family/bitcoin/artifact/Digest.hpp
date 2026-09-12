// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Qt-free digest + hex helpers for the M5-A air-gap transfer artifacts
// (design docs/design/c2wallet-qt.md §5.4). Both sides of the gap compute and
// display a `sha256d` digest for cross-gap comparison; the multi-frame QR
// codec commits a per-frame `sha256`. This layer REUSES the vendored btclibs
// CSHA256 (design §2.4 reuse table: "Hash primitives") — it does NOT
// re-implement SHA-256.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace c2w::artifact {

using Bytes  = std::vector<uint8_t>;
using Hash32 = std::array<uint8_t, 32>;

// Single SHA-256.
Hash32 sha256(const uint8_t* data, size_t n);
inline Hash32 sha256(const Bytes& v) { return sha256(v.data(), v.size()); }

// Double SHA-256 (Bitcoin's HASH256) — the txid / cross-gap digest primitive.
Hash32 sha256d(const uint8_t* data, size_t n);
inline Hash32 sha256d(const Bytes& v) { return sha256d(v.data(), v.size()); }

// Lowercase hex.
std::string to_hex(const uint8_t* data, size_t n);
inline std::string to_hex(const Bytes& v)   { return to_hex(v.data(), v.size()); }
inline std::string to_hex(const Hash32& h)  { return to_hex(h.data(), h.size()); }

// Strict hex decode: rejects odd length and non-hex chars. No 0x prefix.
std::optional<Bytes> from_hex(const std::string& s);

// sha256d of `data`, rendered as a Bitcoin-style display txid (byte-reversed
// hex). This is what a c2pool loader / block explorer shows, and the value the
// wallet and the online node compare across the gap.
std::string sha256d_display(const uint8_t* data, size_t n);
inline std::string sha256d_display(const Bytes& v) { return sha256d_display(v.data(), v.size()); }

} // namespace c2w::artifact
