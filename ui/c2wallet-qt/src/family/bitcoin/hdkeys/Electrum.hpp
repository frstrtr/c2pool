// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Electrum full-file wallet import (design §3.1 — locked decision 1, "import
// ANY key format"). Handles the wallet-file shapes Electrum has shipped:
//
//   * plaintext JSON wallets: seed_version + wallet_type + a `keystore` block
//     (or multisig/2fa cosigner blocks x1/, x2/, ...). Recovered material:
//     bip32 xprv, electrum `seed` (+ seed extension passphrase), old-keystore
//     `master_private_key`, and imported `keypairs` (WIF list).
//   * password-protected keystore FIELDS (Electrum `pw_encode`, version 1:
//     AES-256-CBC with key = SHA256d(password), random-IV-prefixed, base64).
//   * storage-encrypted wallet files (Electrum `BIE1` ECIES over a zlib-
//     compressed JSON body): ECDH(ephemeral_pub, key-from-password) -> SHA-512
//     -> AES-128-CBC body + HMAC-SHA256 tag. `BIE2` (XPUB_PASSWORD) is detected
//     and reported but not decryptable without the wallet's xpub.
//
// The recovered xprv/seed are mapped onto the existing hdkeys engine (Bip32 /
// Bip39). Secrets ride in zeroizing SecureBytes / std::string that the caller
// wipes. Unknown seed_version or an undecryptable variant returns a clear error.

#include "../../../secure/SecureString.hpp"

#include <string>
#include <vector>

namespace c2w::hdkeys {

struct ElectrumKeyItem {
    enum class Kind { Xprv, Seed, MasterPrivateKey, Wif };
    Kind kind;
    std::string keystore_type;   // "bip32" / "old" / "imported" / cosigner tag
    std::string source;          // which wallet block it came from (keystore, x1/, ...)
    std::string text;            // xprv / seed phrase / master_private_key (recovered plaintext)
    std::string passphrase;      // seed extension passphrase (Kind::Seed), if present
    secure::SecureBytes scalar;  // Kind::Wif: 32-byte scalar
    bool compressed = true;      // Kind::Wif
};

struct ElectrumImport {
    bool ok = false;             // parsed AND (if encrypted) decrypted
    std::string error;
    bool was_encrypted = false;  // storage-level BIE1/BIE2 present
    bool needs_password = false; // encrypted/pw_encoded but password missing or wrong
    int  seed_version = 0;
    std::string wallet_type;     // "standard" / "2fa" / "imported" / "2of3" / ...
    bool multisig = false;
    bool two_factor = false;
    std::vector<ElectrumKeyItem> items;
};

// Import an Electrum wallet file. `data` is the raw file contents (plaintext
// JSON, or a base64 BIE1/BIE2 storage blob). `password` decrypts storage and/or
// pw_encoded fields ("" if none).
ElectrumImport import_electrum_wallet(const std::string& data, const std::string& password);

// ── primitives exposed for reuse / KATs ─────────────────────────────────────
// Electrum field-level pw_decode (version 1). nullptr-safe: returns false on a
// bad pad (wrong password) or malformed base64.
bool electrum_pw_decode(const std::string& b64, const std::string& password,
                        int pw_hash_version, std::string& out_plaintext);

// Decrypt an Electrum BIE1 storage blob (base64) to its inflated plaintext JSON.
// magic must be "BIE1"; ok=false with a set error otherwise.
bool electrum_decrypt_storage(const std::string& b64_blob, const std::string& password,
                              std::string& out_json, std::string& out_error);

} // namespace c2w::hdkeys
