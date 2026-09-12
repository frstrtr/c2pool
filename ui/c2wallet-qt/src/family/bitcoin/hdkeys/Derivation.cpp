// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Derivation.hpp"

#include <cstdio>
#include <sstream>

namespace c2w::hdkeys {

ScriptHint purpose_script(Purpose p)
{
    switch (p) {
    case Purpose::BIP44: return ScriptHint::P2PKH;
    case Purpose::BIP49: return ScriptHint::P2SH_P2WPKH;
    case Purpose::BIP84: return ScriptHint::P2WPKH;
    case Purpose::BIP86: return ScriptHint::P2TR;
    }
    return ScriptHint::Unknown;
}

std::vector<uint32_t> build_bip_path(Purpose p, uint32_t coin_type,
                                     uint32_t account, uint32_t change, uint32_t index)
{
    return {
        uint32_t(p) | kHardened,
        coin_type | kHardened,
        account | kHardened,
        change,
        index,
    };
}

std::optional<std::vector<uint32_t>> parse_path(const std::string& path)
{
    std::vector<uint32_t> out;
    std::string s = path;
    // Trim whitespace.
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
    size_t i = 0;
    // Optional leading "m" / "M".
    if (i < s.size() && (s[i] == 'm' || s[i] == 'M')) {
        ++i;
        if (i < s.size() && s[i] != '/') return std::nullopt;
    }
    if (i < s.size() && s[i] == '/') ++i;
    if (i >= s.size()) return out;   // "m" or "m/" => empty path (the node itself)

    std::istringstream is(s.substr(i));
    std::string tok;
    while (std::getline(is, tok, '/')) {
        if (tok.empty()) return std::nullopt;
        bool hardened = false;
        char last = tok.back();
        if (last == '\'' || last == 'h' || last == 'H') {
            hardened = true;
            tok.pop_back();
            if (tok.empty()) return std::nullopt;
        }
        uint64_t v = 0;
        for (char c : tok) {
            if (c < '0' || c > '9') return std::nullopt;
            v = v * 10 + uint64_t(c - '0');
            if (v > 0xFFFFFFFFull) return std::nullopt;
        }
        if (v >= kHardened) return std::nullopt;  // index must fit below the hardened bit
        out.push_back(hardened ? (uint32_t(v) | kHardened) : uint32_t(v));
    }
    return out;
}

std::string format_path(const std::vector<uint32_t>& path)
{
    std::string out = "m";
    char buf[32];
    for (uint32_t idx : path) {
        bool hardened = (idx & kHardened) != 0;
        uint32_t v = idx & ~kHardened;
        std::snprintf(buf, sizeof(buf), "/%u%s", v, hardened ? "'" : "");
        out += buf;
    }
    return out;
}

std::vector<EnumeratedPath> enumerate(const ScanRange& r, uint32_t coin_type)
{
    std::vector<EnumeratedPath> out;
    for (Purpose p : r.purposes)
        for (uint32_t acc : r.accounts)
            for (uint32_t ch : r.changes)
                for (uint32_t idx = r.index_lo; idx <= r.index_hi; ++idx) {
                    EnumeratedPath e;
                    e.path = build_bip_path(p, coin_type, acc, ch, idx);
                    e.purpose = p;
                    e.account = acc;
                    e.change = ch;
                    e.index = idx;
                    out.push_back(std::move(e));
                    if (idx == 0xFFFFFFFFu) break;  // guard against wrap
                }
    return out;
}

} // namespace c2w::hdkeys
