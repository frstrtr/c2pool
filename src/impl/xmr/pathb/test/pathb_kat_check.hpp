// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/pathb_kat_check.hpp
// Check counter shared by the Path B KATs.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

namespace pathb_kat {

inline int g_checks = 0;
inline int g_fail = 0;

inline void check(bool cond, const std::string& msg) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        std::printf("  FAIL: %s\n", msg.c_str());
    }
}

inline int finish(const char* name) {
    std::printf("%s: %s: %d checks, %d failures\n", name, g_fail ? "FAIL" : "PASS", g_checks, g_fail);
    return g_fail ? 1 : 0;
}

inline std::array<std::uint8_t, 32> seq32(std::uint8_t first) {
    std::array<std::uint8_t, 32> h{};
    for (std::size_t i = 0; i < h.size(); ++i) h[i] = static_cast<std::uint8_t>(first + i);
    return h;
}

inline std::string hex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 15]);
    }
    return s;
}

// Deterministic xorshift64* generator for the fuzz passes.
struct Rng {
    std::uint64_t s;
    explicit Rng(std::uint64_t seed) : s(seed ? seed : 1) {}
    std::uint64_t next() {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        return s * 0x2545F4914F6CDD1Dull;
    }
    std::uint64_t below(std::uint64_t n) { return n ? next() % n : 0; }
};

}  // namespace pathb_kat
