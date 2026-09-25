// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Bitcoin Core legacy wallet.dat import (design §3.1 — locked decision 1,
// "import ANY key format"). wallet.dat is a Berkeley DB btree file; rather than
// linking libdb into this offline signer, we read the on-disk BDB pages
// directly (metadata page + P_LBTREE leaf pages, with P_OVERFLOW chains) and
// pull out the Core wallet records:
//
//   * "key"  / "wkey"  — unencrypted keys. Value holds the OpenSSL DER-encoded
//     CPrivKey; the 32-byte secret is lifted out of the DER (02 01 01 04 20 ..).
//   * "ckey"           — encrypted keys. Value is the AES-256-CBC crypted secret
//     (IV = SHA256d(pubkey)[:16]) under the wallet master key.
//   * "mkey"           — the master key: an AES-256-CBC crypted 32-byte key,
//     unlocked by a passphrase-derived key/iv (Core crypter's EVP_BytesToKey
//     with SHA-512, nDerivationMethod 0).
//
// Unencrypted wallets yield scalars immediately. Encrypted wallets yield scalars
// when the correct passphrase is supplied; otherwise the crypted material and
// the "needs password" flag are returned. Secrets ride in zeroizing SecureBytes.

#include "../../../secure/SecureString.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace c2w::hdkeys {

struct WalletDatKey {
    std::vector<uint8_t> pubkey;    // as stored (33 compressed or 65 uncompressed)
    bool encrypted = false;         // came from a ckey record
    bool decrypted = false;         // scalar is valid (unencrypted, or decrypted ok)
    secure::SecureBytes scalar;     // 32-byte private key when decrypted
    std::vector<uint8_t> crypted;   // ckey ciphertext when not (yet) decrypted
};

struct WalletDatImport {
    bool ok = false;                // file parsed as a BDB wallet
    std::string error;
    bool is_encrypted = false;      // an mkey/ckey record was present
    bool needs_password = false;    // encrypted, and no/incorrect passphrase given
    int  key_records = 0;           // key + wkey + ckey records seen
    int  master_keys = 0;           // mkey records seen
    std::vector<WalletDatKey> keys;
};

WalletDatImport import_wallet_dat(const uint8_t* data, size_t len, const std::string& password);

} // namespace c2w::hdkeys
