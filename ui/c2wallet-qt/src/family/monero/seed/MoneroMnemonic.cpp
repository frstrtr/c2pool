// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
#include "MoneroMnemonic.hpp"

#include "secure/SecureString.hpp"

#include <array>
#include <cctype>
#include <sstream>
#include <unordered_map>

namespace c2wallet::monero {

MnemonicDecode::~MnemonicDecode()
{
    c2w::secure::secure_wipe(key.data(), key.size());
}

namespace {

// Lowercase, unique-prefix truncation of a word for map keys / checksum input.
std::string trim_prefix(const std::string& w, int prefix_len)
{
    std::size_t n = static_cast<std::size_t>(prefix_len);
    return w.size() <= n ? w : w.substr(0, n);
}

std::string to_lower(const std::string& s)
{
    std::string out(s.size(), '\0');
    for (std::size_t i = 0; i < s.size(); ++i)
        out[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(s[i])));
    return out;
}

// Build (once per language) a prefix -> index map. The "unique prefix length"
// guarantees the truncated prefixes are collision-free, so this is a bijection
// that accepts both full words and prefix-truncated words.
const std::unordered_map<std::string, std::uint32_t>& prefix_map(const Wordlist& wl)
{
    static std::unordered_map<const Wordlist*, std::unordered_map<std::string, std::uint32_t>> cache;
    auto it = cache.find(&wl);
    if (it != cache.end())
        return it->second;
    std::unordered_map<std::string, std::uint32_t> m;
    m.reserve(wl.count * 2);
    for (std::uint32_t i = 0; i < wl.count; ++i)
        m.emplace(trim_prefix(wl.words[i], wl.prefix_len), i);
    auto res = cache.emplace(&wl, std::move(m));
    return res.first->second;
}

std::vector<std::string> split_words(const std::string& phrase)
{
    std::vector<std::string> out;
    std::istringstream iss(phrase);
    std::string tok;
    while (iss >> tok)
        out.push_back(to_lower(tok));
    return out;
}

} // namespace

std::uint32_t crc32_ieee(const std::uint8_t* data, std::size_t len)
{
    // Reflected CRC-32 (poly 0xEDB88320), init/xorout 0xFFFFFFFF -- identical to
    // boost::crc_32_type, which upstream Monero uses for the checksum word.
    static std::array<std::uint32_t, 256> table = [] {
        std::array<std::uint32_t, 256> t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        return t;
    }();
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < len; ++i)
        crc = table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

std::size_t mnemonic_checksum_index(const std::vector<std::string>& words, int prefix_len)
{
    std::string trimmed;
    for (const auto& w : words)
        trimmed += trim_prefix(w, prefix_len);
    std::uint32_t crc = crc32_ieee(reinterpret_cast<const std::uint8_t*>(trimmed.data()),
                                   trimmed.size());
    return static_cast<std::size_t>(crc % words.size());
}

MnemonicDecode mnemonic_decode(const std::string& phrase)
{
    MnemonicDecode r;
    std::vector<std::string> words = split_words(phrase);

    // The 32-byte-key seed is 24 data words; a 25th word is the checksum.
    if (words.size() != 24 && words.size() != 25) {
        r.error = "unsupported word count (expected 24 or 25 for a 32-byte Monero seed)";
        return r;
    }
    const bool had_checksum = (words.size() == 25);

    for (const Wordlist* wl : monero_languages()) {
        const auto& pmap = prefix_map(*wl);
        std::vector<std::uint32_t> idx;
        idx.reserve(24);
        std::vector<std::string> data_words(words.begin(), words.begin() + 24);

        bool all_found = true;
        for (const auto& w : data_words) {
            auto f = pmap.find(trim_prefix(w, wl->prefix_len));
            if (f == pmap.end()) { all_found = false; break; }
            idx.push_back(f->second);
        }
        if (!all_found)
            continue;

        if (had_checksum) {
            std::size_t ci = mnemonic_checksum_index(data_words, wl->prefix_len);
            if (trim_prefix(words[24], wl->prefix_len) != trim_prefix(data_words[ci], wl->prefix_len)) {
                r.error = "checksum word mismatch";
                r.language = wl;
                return r;
            }
        }

        // Decode 8 groups of 3 words into 8 little-endian uint32 words. uint32
        // arithmetic wraps exactly as upstream electrum-words.cpp does.
        const std::uint32_t n = static_cast<std::uint32_t>(wl->count);
        for (int g = 0; g < 8; ++g) {
            std::uint32_t w1 = idx[3 * g + 0];
            std::uint32_t w2 = idx[3 * g + 1];
            std::uint32_t w3 = idx[3 * g + 2];
            std::uint32_t val = w1
                + n * (((n - w1) + w2) % n)
                + n * n * (((n - w2) + w3) % n);
            r.key[4 * g + 0] = static_cast<std::uint8_t>(val & 0xff);
            r.key[4 * g + 1] = static_cast<std::uint8_t>((val >> 8) & 0xff);
            r.key[4 * g + 2] = static_cast<std::uint8_t>((val >> 16) & 0xff);
            r.key[4 * g + 3] = static_cast<std::uint8_t>((val >> 24) & 0xff);
        }
        r.ok = true;
        r.language = wl;
        r.had_checksum = had_checksum;
        return r;
    }

    r.error = "no registered wordlist recognizes every word";
    return r;
}

std::string mnemonic_encode(const Bytes32& key, const Wordlist& language)
{
    const std::uint32_t n = static_cast<std::uint32_t>(language.count);
    std::vector<std::string> words;
    words.reserve(25);

    for (int g = 0; g < 8; ++g) {
        std::uint32_t x = static_cast<std::uint32_t>(key[4 * g + 0])
            | (static_cast<std::uint32_t>(key[4 * g + 1]) << 8)
            | (static_cast<std::uint32_t>(key[4 * g + 2]) << 16)
            | (static_cast<std::uint32_t>(key[4 * g + 3]) << 24);
        std::uint32_t w1 = x % n;
        std::uint32_t w2 = (x / n + w1) % n;
        std::uint32_t w3 = (x / n / n + w2) % n;
        words.emplace_back(language.words[w1]);
        words.emplace_back(language.words[w2]);
        words.emplace_back(language.words[w3]);
    }

    // Append the CRC32 checksum word (one of the 24 data words).
    std::size_t ci = mnemonic_checksum_index(words, language.prefix_len);
    words.push_back(words[ci]);

    std::string out;
    for (std::size_t i = 0; i < words.size(); ++i) {
        if (i) out += ' ';
        out += words[i];
    }
    return out;
}

} // namespace c2wallet::monero
