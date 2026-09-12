// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Digest.hpp"

#include <crypto/sha256.h> // vendored btclibs CSHA256 (design §2.4 reuse)

namespace c2w::artifact {

Hash32 sha256(const uint8_t* data, size_t n) {
    Hash32 out{};
    CSHA256().Write(data, n).Finalize(out.data());
    return out;
}

Hash32 sha256d(const uint8_t* data, size_t n) {
    Hash32 first = sha256(data, n);
    return sha256(first.data(), first.size());
}

static const char* kHex = "0123456789abcdef";

std::string to_hex(const uint8_t* data, size_t n) {
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(kHex[data[i] >> 4]);
        s.push_back(kHex[data[i] & 0x0f]);
    }
    return s;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::optional<Bytes> from_hex(const std::string& s) {
    if (s.size() % 2 != 0) return std::nullopt;
    Bytes out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = hexval(s[i]);
        int lo = hexval(s[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::string sha256d_display(const uint8_t* data, size_t n) {
    Hash32 h = sha256d(data, n);
    // Bitcoin display order is byte-reversed relative to the internal digest.
    std::string s;
    s.reserve(64);
    for (size_t i = 0; i < h.size(); ++i) {
        uint8_t b = h[h.size() - 1 - i];
        s.push_back(kHex[b >> 4]);
        s.push_back(kHex[b & 0x0f]);
    }
    return s;
}

} // namespace c2w::artifact
