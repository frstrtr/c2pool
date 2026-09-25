// SPDX-License-Identifier: AGPL-3.0-or-later
//
// EXPERIMENTAL custom crypto — see SeedBackup.hpp. Ported from frstrtr/mnemonic_gen
// (operator-owned; relicensed AGPL-3.0-or-later on port). NOT SLIP-39.
#include "SeedBackup.hpp"

#include "Bip39.hpp"
#include "wordlists.hpp"
#include "../../../secure/SecureString.hpp"

#include <crypto/hmac_sha256.h>   // btclibs CHMAC_SHA256
#include <crypto/scrypt.h>        // btclibs PBKDF2_SHA256 (reused)

#include <cstring>
#include <sstream>
#include <unordered_map>

namespace c2w::hdkeys {

namespace {

const char kNonceV1[] = "mnemonic-shuffle-v1";

std::vector<std::string> split_words(const std::string& s)
{
    std::vector<std::string> w;
    std::istringstream is(s);
    std::string t;
    while (is >> t) w.push_back(t);
    return w;
}

const std::unordered_map<std::string, int>& english_index()
{
    static const std::unordered_map<std::string, int> m = [] {
        std::unordered_map<std::string, int> mm;
        const auto& wl = wordlist_english();
        for (int i = 0; i < 2048; ++i) mm[wl[i]] = i;
        return mm;
    }();
    return m;
}

void hmac256(const uint8_t* key, size_t klen, const uint8_t* msg, size_t mlen, uint8_t out[32])
{
    CHMAC_SHA256(key, klen).Write(msg, mlen).Finalize(out);
}

// HMAC-DRBG (mnemonic_gen exact construction): instantiate with (key, nonce),
// output `length` bytes.
std::vector<uint8_t> hmac_drbg(const uint8_t key[32], const std::string& nonce, size_t length)
{
    uint8_t v[32], k[32];
    std::memset(v, 0x01, 32);
    std::memcpy(k, key, 32);

    auto reseed_step = [&](uint8_t sep) {
        std::vector<uint8_t> buf(v, v + 32);
        buf.push_back(sep);
        buf.insert(buf.end(), nonce.begin(), nonce.end());
        hmac256(k, 32, buf.data(), buf.size(), k);   // k = HMAC(k, v||sep||nonce)
        hmac256(k, 32, v, 32, v);                    // v = HMAC(k, v)
    };
    reseed_step(0x00);
    reseed_step(0x01);

    std::vector<uint8_t> out;
    out.reserve(length);
    while (out.size() < length) {
        hmac256(k, 32, v, 32, v);                    // v = HMAC(k, v)
        out.insert(out.end(), v, v + 32);
    }
    out.resize(length);
    secure::secure_wipe(v, 32);
    secure::secure_wipe(k, 32);
    return out;
}

bool valid_bip39(const std::string& m, size_t expect_words)
{
    if (split_words(m).size() != expect_words) return false;
    return Bip39::validate(m, Language::English) == Bip39Error::Ok;
}

} // namespace

std::vector<int> deterministic_shuffle(const std::string& password,
                                       const std::string& salt_mnemonic24,
                                       const SeedShuffleParams& params)
{
    // seed64 = BIP39 seed of the salt mnemonic (empty passphrase).
    secure::SecureBytes seed = Bip39::to_seed(salt_mnemonic24, "");
    uint8_t key[32];
    PBKDF2_SHA256(reinterpret_cast<const uint8_t*>(password.data()), password.size(),
                  seed.data(), seed.size(), params.pbkdf2_iterations, key, 32);

    const int n = 2048;
    auto drbg = hmac_drbg(key, kNonceV1, static_cast<size_t>(n) * 4);
    secure::secure_wipe(key, 32);

    // Big-endian u32 stream.
    std::vector<uint32_t> rnd(n);
    for (int i = 0; i < n; ++i) {
        rnd[i] = (uint32_t(drbg[4 * i]) << 24) | (uint32_t(drbg[4 * i + 1]) << 16) |
                 (uint32_t(drbg[4 * i + 2]) << 8) | uint32_t(drbg[4 * i + 3]);
    }

    std::vector<int> S(n);
    for (int i = 0; i < n; ++i) S[i] = i;
    // for i in reversed(range(1, n)): j = rnd[n-1-i] % (i+1); swap S[i], S[j]
    for (int i = n - 1; i >= 1; --i) {
        uint32_t j = rnd[n - 1 - i] % static_cast<uint32_t>(i + 1);
        std::swap(S[i], S[j]);
    }
    return S;
}

SplitBackup generate_split_backup(const std::string& password,
                                  const SeedShuffleParams& params,
                                  int max_probe_iters)
{
    SplitBackup r;
    const auto& eidx = english_index();
    const auto& wl = wordlist_english();

    for (int it = 0; it < max_probe_iters; ++it) {
        r.iterations_tried = it + 1;
        // Fresh 24-word master from the VETTED CSPRNG (never the demo RNG).
        std::string master = Bip39::generate(256, Language::English);
        auto words = split_words(master);
        if (words.size() != 24) continue;

        // Prefilter: plain even/odd 12-word halves must be valid BIP39.
        std::string plain_even, plain_odd;
        for (int i = 0; i < 24; i += 2) plain_even += (i ? " " : "") + words[i];
        for (int i = 1; i < 24; i += 2) plain_odd += (i > 1 ? " " : "") + words[i];
        if (!valid_bip39(plain_even, 12) || !valid_bip39(plain_odd, 12)) continue;

        // Fresh salt mnemonic from the vetted CSPRNG.
        std::string salt = Bip39::generate(256, Language::English);
        auto S = deterministic_shuffle(password, salt, params);

        // map: mapped word for original word = wl[S[index_of(word)]]
        std::string mapped_even, mapped_odd;
        bool bad = false;
        for (int i = 0; i < 24; i += 2) {
            auto f = eidx.find(words[i]); if (f == eidx.end()) { bad = true; break; }
            mapped_even += (i ? " " : "") + std::string(wl[S[f->second]]);
        }
        for (int i = 1; i < 24 && !bad; i += 2) {
            auto f = eidx.find(words[i]); if (f == eidx.end()) { bad = true; break; }
            mapped_odd += (i > 1 ? " " : "") + std::string(wl[S[f->second]]);
        }
        if (bad) continue;

        if (valid_bip39(mapped_even, 12) && valid_bip39(mapped_odd, 12)) {
            r.ok = true;
            r.master_mnemonic = master;
            r.share_even = mapped_even;
            r.share_odd = mapped_odd;
            r.salt_mnemonic = salt;
            return r;
        }
    }
    r.error = "probe exhausted without a valid share pair";
    return r;
}

RecoverResult recover_split_backup(const std::string& share_even,
                                   const std::string& share_odd,
                                   const std::string& salt_mnemonic24,
                                   const std::string& password,
                                   const SeedShuffleParams& params)
{
    RecoverResult r;
    if (!valid_bip39(share_even, 12)) { r.error = "even share is not a valid 12-word BIP39 mnemonic"; return r; }
    if (!valid_bip39(share_odd, 12)) { r.error = "odd share is not a valid 12-word BIP39 mnemonic"; return r; }
    if (!valid_bip39(salt_mnemonic24, 24)) { r.error = "salt is not a valid 24-word BIP39 mnemonic"; return r; }

    const auto& eidx = english_index();
    const auto& wl = wordlist_english();
    auto S = deterministic_shuffle(password, salt_mnemonic24, params);
    // Sinv[m] = pos such that S[pos] == m.
    std::vector<int> Sinv(2048);
    for (int pos = 0; pos < 2048; ++pos) Sinv[S[pos]] = pos;

    auto even = split_words(share_even);
    auto odd = split_words(share_odd);
    std::vector<std::string> out(24);
    for (int i = 0; i < 12; ++i) {
        auto fe = eidx.find(even[i]); auto fo = eidx.find(odd[i]);
        if (fe == eidx.end() || fo == eidx.end()) { r.error = "share word not in wordlist"; return r; }
        out[2 * i] = wl[Sinv[fe->second]];
        out[2 * i + 1] = wl[Sinv[fo->second]];
    }
    std::string m;
    for (int i = 0; i < 24; ++i) m += (i ? " " : "") + out[i];
    r.master_mnemonic = m;
    r.ok = true;   // recovered; the caller may still validate the master's own checksum
    return r;
}

} // namespace c2w::hdkeys
