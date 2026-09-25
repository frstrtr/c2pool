// SPDX-License-Identifier: AGPL-3.0-or-later
#include "HexUtil.hpp"

namespace c2w::hdkeys {

std::string to_hex(const uint8_t* data, size_t n)
{
    static const char* k = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(k[data[i] >> 4]);
        out.push_back(k[data[i] & 0x0f]);
    }
    return out;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::optional<std::vector<uint8_t>> from_hex(const std::string& s)
{
    if (s.size() % 2 != 0) return std::nullopt;
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = hexval(s[i]);
        int lo = hexval(s[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

} // namespace c2w::hdkeys
