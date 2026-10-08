#pragma once
// Shared self-contained harness for the v37_rb_* KATs (stdlib only; nonzero
// exit on any failure — the same shape as v37_owed_event_mmr_kat.cpp:71).
#include <cstdint>
#include <cstdio>
#include <string>

#include <sharechain/v37/v37_hash.hpp>

namespace rbkat {

inline int g_checks = 0, g_fail = 0;

inline void ok(bool cond, const std::string& what) {
    ++g_checks;
    if (!cond) { ++g_fail; std::printf("   FAIL  %s\n", what.c_str()); }
}

inline std::string hx(const ::v37::bytes32& h) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (unsigned char c : h) { s.push_back(d[c >> 4]); s.push_back(d[c & 0xf]); }
    return s;
}

inline ::v37::bytes32 fill(std::uint8_t v) { ::v37::bytes32 k; k.fill(v); return k; }

inline std::string u128s(unsigned __int128 x) {
    if (x == 0) return "0";
    std::string s;
    while (x) { s.insert(s.begin(), char('0' + int(x % 10))); x /= 10; }
    return s;
}

struct SplitMix64 {
    std::uint64_t s;
    explicit SplitMix64(std::uint64_t seed) : s(seed) {}
    std::uint64_t next() {
        std::uint64_t z = (s += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }
    std::uint64_t below(std::uint64_t n) { return n ? next() % n : 0; }
    ::v37::bytes32 key() {
        ::v37::bytes32 k;
        for (int i = 0; i < 4; ++i) {
            std::uint64_t x = next();
            for (int j = 0; j < 8; ++j) k[i * 8 + j] = std::uint8_t(x >> (8 * j));
        }
        return k;
    }
};

inline int finish(const char* name) {
    std::printf("%s: %d checks, %d failed -> %s\n", name, g_checks, g_fail,
                g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}

}  // namespace rbkat
