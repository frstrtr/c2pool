// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Bip39.hpp"

#include "Csprng.hpp"
#include "HexUtil.hpp"

#include <btclibs/crypto/sha256.h>
#include <btclibs/crypto/sha512.h>
#include <btclibs/crypto/hmac_sha512.h>

#include <array>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace c2w::hdkeys {

const std::array<const char*, 2048>& wordlist_for(Language lang)
{
    switch (lang) {
    case Language::English: return wordlist_english();
    }
    throw std::runtime_error("wordlist_for: language not embedded");
}

const char* to_string(Bip39Error e)
{
    switch (e) {
    case Bip39Error::Ok:               return "ok";
    case Bip39Error::BadWordCount:     return "mnemonic must be 12/15/18/21/24 words";
    case Bip39Error::UnknownWord:      return "a word is not in the wordlist";
    case Bip39Error::BadChecksum:      return "BIP39 checksum does not verify";
    case Bip39Error::BadEntropyLength: return "entropy must be 16/20/24/28/32 bytes";
    }
    return "unknown";
}

// Build a word -> index map once per wordlist pointer.
static const std::unordered_map<std::string, int>& index_of(Language lang)
{
    static std::unordered_map<const void*, std::unordered_map<std::string, int>> cache;
    const auto& wl = wordlist_for(lang);
    const void* key = static_cast<const void*>(&wl);
    auto it = cache.find(key);
    if (it != cache.end()) return it->second;
    std::unordered_map<std::string, int> m;
    m.reserve(2048);
    for (int i = 0; i < 2048; ++i) m.emplace(wl[i], i);
    return cache.emplace(key, std::move(m)).first->second;
}

std::string Bip39::encode(const std::vector<uint8_t>& entropy, Bip39Error& err, Language lang)
{
    const size_t ent = entropy.size();
    if (ent < 16 || ent > 32 || (ent % 4) != 0) { err = Bip39Error::BadEntropyLength; return {}; }

    // checksum = first (ENT/32) bits of SHA256(entropy)
    uint8_t hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(entropy.data(), ent).Finalize(hash);
    const size_t ent_bits = ent * 8;
    const size_t cs_bits = ent_bits / 32;
    const size_t total_bits = ent_bits + cs_bits;
    const size_t words = total_bits / 11;

    const auto& wl = wordlist_for(lang);

    // Read 11-bit groups MSB-first from entropy ‖ checksum.
    auto bit_at = [&](size_t i) -> int {
        if (i < ent_bits) return (entropy[i / 8] >> (7 - (i % 8))) & 1;
        size_t j = i - ent_bits;                 // into checksum
        return (hash[j / 8] >> (7 - (j % 8))) & 1;
    };

    std::string out;
    for (size_t w = 0; w < words; ++w) {
        int idx = 0;
        for (int b = 0; b < 11; ++b) idx = (idx << 1) | bit_at(w * 11 + b);
        if (w) out.push_back(' ');
        out += wl[idx];
    }
    err = Bip39Error::Ok;
    return out;
}

static Bip39Error do_decode(const std::string& mnemonic, std::vector<uint8_t>& entropy_out, Language lang)
{
    // Tokenise on whitespace.
    std::vector<std::string> toks;
    {
        std::istringstream is(mnemonic);
        std::string t;
        while (is >> t) toks.push_back(t);
    }
    const size_t n = toks.size();
    if (n != 12 && n != 15 && n != 18 && n != 21 && n != 24)
        return Bip39Error::BadWordCount;

    const auto& idxmap = index_of(lang);
    const size_t total_bits = n * 11;
    const size_t cs_bits = total_bits / 33;   // n*11 = ENT + ENT/32; cs = total/33
    const size_t ent_bits = total_bits - cs_bits;
    const size_t ent_bytes = ent_bits / 8;

    // Reconstruct the full bitstring.
    std::vector<uint8_t> bits;
    bits.reserve(total_bits);
    for (const auto& w : toks) {
        auto it = idxmap.find(w);
        if (it == idxmap.end()) return Bip39Error::UnknownWord;
        int idx = it->second;
        for (int b = 10; b >= 0; --b) bits.push_back((idx >> b) & 1);
    }

    // Split into entropy bytes + checksum bits.
    std::vector<uint8_t> ent(ent_bytes, 0);
    for (size_t i = 0; i < ent_bits; ++i)
        ent[i / 8] |= (bits[i] << (7 - (i % 8)));

    uint8_t hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(ent.data(), ent.size()).Finalize(hash);
    for (size_t i = 0; i < cs_bits; ++i) {
        int expect = (hash[i / 8] >> (7 - (i % 8))) & 1;
        if (bits[ent_bits + i] != expect) return Bip39Error::BadChecksum;
    }

    entropy_out = std::move(ent);
    return Bip39Error::Ok;
}

Bip39Error Bip39::decode(const std::string& mnemonic, std::vector<uint8_t>& entropy_out, Language lang)
{
    return do_decode(mnemonic, entropy_out, lang);
}

Bip39Error Bip39::validate(const std::string& mnemonic, Language lang)
{
    std::vector<uint8_t> tmp;
    return do_decode(mnemonic, tmp, lang);
}

void pbkdf2_hmac_sha512(const uint8_t* pass, size_t pass_len,
                        const uint8_t* salt, size_t salt_len,
                        uint32_t iterations,
                        uint8_t* out, size_t out_len)
{
    // RFC 2898 PBKDF2 with HMAC-SHA512 as PRF.
    const size_t hlen = CHMAC_SHA512::OUTPUT_SIZE; // 64
    uint32_t blocks = static_cast<uint32_t>((out_len + hlen - 1) / hlen);
    uint8_t U[CHMAC_SHA512::OUTPUT_SIZE];
    uint8_t T[CHMAC_SHA512::OUTPUT_SIZE];
    for (uint32_t i = 1; i <= blocks; ++i) {
        uint8_t ibe[4] = { uint8_t(i >> 24), uint8_t(i >> 16), uint8_t(i >> 8), uint8_t(i) };
        // U1 = PRF(pass, salt ‖ INT(i))
        {
            CHMAC_SHA512 h(pass, pass_len);
            h.Write(salt, salt_len);
            h.Write(ibe, 4);
            h.Finalize(U);
        }
        std::memcpy(T, U, hlen);
        for (uint32_t j = 1; j < iterations; ++j) {
            CHMAC_SHA512 h(pass, pass_len);
            h.Write(U, hlen);
            h.Finalize(U);
            for (size_t k = 0; k < hlen; ++k) T[k] ^= U[k];
        }
        size_t off = (size_t)(i - 1) * hlen;
        size_t cpy = (off + hlen <= out_len) ? hlen : (out_len - off);
        std::memcpy(out + off, T, cpy);
    }
}

secure::SecureBytes Bip39::to_seed(const std::string& mnemonic, const std::string& passphrase)
{
    // salt = "mnemonic" ‖ passphrase (both UTF-8, NFKD-normalised by caller).
    std::string salt = "mnemonic" + passphrase;
    secure::SecureBytes seed(64);
    pbkdf2_hmac_sha512(reinterpret_cast<const uint8_t*>(mnemonic.data()), mnemonic.size(),
                       reinterpret_cast<const uint8_t*>(salt.data()), salt.size(),
                       2048, seed.data(), 64);
    return seed;
}

std::string Bip39::generate(int strength_bits, Language lang)
{
    if (strength_bits != 128 && strength_bits != 160 && strength_bits != 192 &&
        strength_bits != 224 && strength_bits != 256)
        throw std::invalid_argument("Bip39::generate: strength must be 128/160/192/224/256");
    std::vector<uint8_t> entropy(strength_bits / 8);
    csprng_bytes(entropy.data(), entropy.size());   // VETTED CSPRNG, not a demo RNG
    Bip39Error err = Bip39Error::Ok;
    std::string m = encode(entropy, err, lang);
    // Wipe the transient entropy buffer.
    secure::secure_wipe(entropy.data(), entropy.size());
    if (err != Bip39Error::Ok) throw std::runtime_error(to_string(err));
    return m;
}

std::string Bip39::seed_fingerprint(const secure::SecureBytes& seed)
{
    // HMAC-SHA512("c2wallet-seed-fingerprint", seed)[0:4], hex. Display-only.
    static const char* tag = "c2wallet-seed-fingerprint";
    CHMAC_SHA512 h(reinterpret_cast<const uint8_t*>(tag), std::strlen(tag));
    h.Write(seed.data(), seed.size());
    uint8_t out[CHMAC_SHA512::OUTPUT_SIZE];
    h.Finalize(out);
    return to_hex(out, 4);
}

} // namespace c2w::hdkeys
