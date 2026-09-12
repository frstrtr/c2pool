// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_p2p_kat_util.hpp
//
// Shared harness for the four C1a KATs (levin header codec, epee portable
// storage, levin messages, and the bounded fuzz pass). Counters, hex, and the
// two comparisons the goldens need.
//
// Deliberately tiny and header-only: the KATs are STL-only executables with no
// test framework, matching the Wave 0 KATs next door.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace c2pool::xmr::native::kat {

inline int g_checks = 0;
inline int g_fail   = 0;

inline void check(bool cond, const char* what) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        std::fprintf(stderr, "FAIL: %s\n", what);
    }
}

#if defined(__GNUC__)
__attribute__((format(printf, 2, 3)))
#endif
inline void checkf(bool cond, const char* fmt, ...) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        char buf[512];
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        std::fprintf(stderr, "FAIL: %s\n", buf);
    }
}

inline int report(const char* name) {
    std::printf("%s: %d checks, %d failures\n", name, g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}

// --- hex ---------------------------------------------------------------------
inline std::string to_hex(const std::vector<std::uint8_t>& v) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(v.size() * 2);
    for (std::uint8_t b : v) {
        s.push_back(d[b >> 4]);
        s.push_back(d[b & 0x0f]);
    }
    return s;
}

inline int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Ignores whitespace so goldens can be written in readable groups.
inline std::vector<std::uint8_t> from_hex(const std::string& s) {
    std::vector<std::uint8_t> out;
    int hi = -1;
    for (char c : s) {
        if (c == ' ' || c == '\n' || c == '\t' || c == '\r' || c == '_') continue;
        const int n = hex_nibble(c);
        if (n < 0) return {};
        if (hi < 0) { hi = n; } else { out.push_back(static_cast<std::uint8_t>((hi << 4) | n)); hi = -1; }
    }
    if (hi >= 0) return {};
    return out;
}

// ASCII of a name, as the encoder writes it.
inline std::vector<std::uint8_t> ascii(const char* s) {
    const std::size_t n = std::strlen(s);
    return std::vector<std::uint8_t>(reinterpret_cast<const std::uint8_t*>(s),
                                     reinterpret_cast<const std::uint8_t*>(s) + n);
}

inline void append(std::vector<std::uint8_t>& dst, const std::vector<std::uint8_t>& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

// A named entry as it appears inside a section: length byte, name, then the
// already-encoded value bytes. Used by the goldens to build expected output by
// composition instead of one unreadable hex wall.
inline std::vector<std::uint8_t> entry_bytes(const char* name,
                                             const std::vector<std::uint8_t>& value) {
    std::vector<std::uint8_t> out;
    out.push_back(static_cast<std::uint8_t>(std::strlen(name)));
    append(out, ascii(name));
    append(out, value);
    return out;
}

inline bool bytes_equal(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    return a.size() == b.size() && (a.empty() || std::memcmp(a.data(), b.data(), a.size()) == 0);
}

// Prints both sides when a golden misses -- a diff is the only useful output.
inline void check_bytes(const std::vector<std::uint8_t>& got,
                        const std::vector<std::uint8_t>& want,
                        const char* what) {
    ++g_checks;
    if (!bytes_equal(got, want)) {
        ++g_fail;
        std::fprintf(stderr, "FAIL: %s\n  got  %s\n  want %s\n",
                     what, to_hex(got).c_str(), to_hex(want).c_str());
    }
}

// --- deterministic PRNG ------------------------------------------------------
// splitmix64. Fixed seed, no <random> distribution: the fuzz KAT must produce
// the same bytes on every host and every standard library.
class Rng {
public:
    explicit Rng(std::uint64_t seed) noexcept : s_(seed) {}
    std::uint64_t next() noexcept {
        std::uint64_t z = (s_ += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    std::uint32_t below(std::uint32_t n) noexcept {
        return n ? static_cast<std::uint32_t>(next() % n) : 0;
    }
    std::uint8_t byte() noexcept { return static_cast<std::uint8_t>(next() & 0xff); }
private:
    std::uint64_t s_;
};

} // namespace c2pool::xmr::native::kat
