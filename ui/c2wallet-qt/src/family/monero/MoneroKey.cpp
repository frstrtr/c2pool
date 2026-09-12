// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
#include "MoneroKey.hpp"

#include "seed/MoneroMnemonic.hpp"

#include <cctype>

#if defined(__linux__)
#  include <sys/random.h>   // getrandom(2)
#  include <cerrno>
#endif

namespace c2wallet::monero {

bool hex_to_bytes32(const std::string& hex, Bytes32& out)
{
    if (hex.size() != 64)
        return false;
    auto nyb = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < 32; ++i) {
        int hi = nyb(hex[2 * i]);
        int lo = nyb(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

std::string bytes32_to_hex(const Bytes32& b)
{
    static const char* d = "0123456789abcdef";
    std::string s(64, '0');
    for (std::size_t i = 0; i < 32; ++i) {
        s[2 * i]     = d[(b[i] >> 4) & 0xf];
        s[2 * i + 1] = d[b[i] & 0xf];
    }
    return s;
}

KeyImportResult keys_from_spend_key(const Bytes32& spend_seed)
{
    KeyImportResult r;
    MoneroKeys& k = r.keys;

    // monerod key recovery: spend secret = sc_reduce32(seed).
    k.spend_priv = mcrypto::reduce32(spend_seed);
    k.has_spend_priv = true;

    if (!mcrypto::secret_to_public(k.spend_priv, k.spend_pub)) {
        r.error = "spend key does not yield a valid public key";
        return r;
    }

    // view secret = H_s(spend secret), which is reduced by construction.
    k.view_priv = mcrypto::hash_to_scalar(k.spend_priv.data(), k.spend_priv.size());
    if (!mcrypto::secret_to_public(k.view_priv, k.view_pub)) {
        r.error = "derived view key does not yield a valid public key";
        return r;
    }
    r.ok = true;
    return r;
}

KeyImportResult keys_from_mnemonic(const std::string& phrase)
{
    KeyImportResult r;
    MnemonicDecode d = mnemonic_decode(phrase);
    if (!d.ok) {
        r.error = "mnemonic: " + d.error;
        return r;
    }
    return keys_from_spend_key(d.key);
}

KeyImportResult keys_from_dual_hex(const std::string& spend_priv_hex,
                                   const std::string& view_priv_hex)
{
    KeyImportResult r;
    MoneroKeys& k = r.keys;

    if (!hex_to_bytes32(spend_priv_hex, k.spend_priv)) {
        r.error = "spend private key must be 64 hex characters";
        return r;
    }
    if (!hex_to_bytes32(view_priv_hex, k.view_priv)) {
        r.error = "view private key must be 64 hex characters";
        return r;
    }
    if (!mcrypto::is_canonical_scalar(k.spend_priv)) {
        r.error = "spend private key is not a canonical ed25519 scalar";
        return r;
    }
    if (!mcrypto::is_canonical_scalar(k.view_priv)) {
        r.error = "view private key is not a canonical ed25519 scalar";
        return r;
    }
    k.has_spend_priv = true;
    if (!mcrypto::secret_to_public(k.spend_priv, k.spend_pub) ||
        !mcrypto::secret_to_public(k.view_priv, k.view_pub)) {
        r.error = "could not derive public keys from the supplied secrets";
        return r;
    }
    r.ok = true;
    return r;
}

KeyImportResult keys_view_only(const std::string& spend_pub_hex,
                               const std::string& view_priv_hex)
{
    KeyImportResult r;
    MoneroKeys& k = r.keys;

    if (!hex_to_bytes32(spend_pub_hex, k.spend_pub)) {
        r.error = "public spend key must be 64 hex characters";
        return r;
    }
    if (!hex_to_bytes32(view_priv_hex, k.view_priv)) {
        r.error = "view private key must be 64 hex characters";
        return r;
    }
    if (!mcrypto::is_canonical_scalar(k.view_priv)) {
        r.error = "view private key is not a canonical ed25519 scalar";
        return r;
    }
    k.has_spend_priv = false;   // view-only: cannot sign
    if (!mcrypto::secret_to_public(k.view_priv, k.view_pub)) {
        r.error = "view private key does not yield a valid public key";
        return r;
    }
    r.ok = true;
    return r;
}

MoneroAddress primary_address(const MoneroKeys& k, Network net)
{
    return make_standard(k.spend_pub, k.view_pub, net);
}

bool generate_wallet(GeneratedWallet& out, std::string& err)
{
    Bytes32 entropy{};
#if defined(__linux__)
    // Vetted CSPRNG (design §3.4 HARD FLAG): getrandom(2), never a demo RNG.
    std::size_t got = 0;
    while (got < entropy.size()) {
        ssize_t n = ::getrandom(entropy.data() + got, entropy.size() - got, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            err = "getrandom(2) failed";
            return false;
        }
        got += static_cast<std::size_t>(n);
    }
#else
    err = "no vetted CSPRNG available on this platform (getrandom/BCryptGenRandom required)";
    return false;
#endif

    // Reduce entropy mod l to a valid ed25519 scalar (NOT a truncation), so the
    // spend key round-trips through the mnemonic unchanged.
    Bytes32 spend_seed = mcrypto::reduce32(entropy);

    KeyImportResult ki = keys_from_spend_key(spend_seed);
    if (!ki.ok) {
        err = ki.error;
        return false;
    }
    out.keys = ki.keys;
    out.mnemonic = mnemonic_encode(out.keys.spend_priv);
    return true;
}

} // namespace c2wallet::monero
