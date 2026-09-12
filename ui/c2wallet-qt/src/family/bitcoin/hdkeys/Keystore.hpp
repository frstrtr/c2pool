// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Generic JSON keystore import (design §3.1 — "generic JSON keystore ... the
// common shape"). This is the permissive v1 importer: it walks a JSON document
// and harvests the key material commonly found in exported wallet keystores —
//   * a BIP39 "mnemonic" (optionally with "passphrase"),
//   * an extended private key ("xprv"/"masterPrivKey"/"master_priv"/"hdseed"),
//   * WIF strings and raw 32-byte hex scalars, singular ("wif"/"privkey"/
//     "private_key"/"key"/"secret") or inside arrays ("keys"/"private_keys"/
//     "wifs"/"addresses[].privkey").
// It does NOT decrypt password-protected keystores (Electrum full-file /
// wallet.dat are their own parsers, deferred). Each harvested secret is decoded
// through the M1-A KeyImport / Bip39 / Bip32 layers so the same validation and
// zeroizing SecureBytes custody applies.

#include "../../../secure/SecureString.hpp"

#include <string>
#include <vector>

namespace c2w::hdkeys {

struct KeystoreItem {
    enum class Kind { Wif, RawHex, Mnemonic, Xprv } kind;
    std::string source_field;      // which JSON field it came from
    secure::SecureBytes scalar;    // for Wif / RawHex (32-byte scalar)
    bool compressed = true;        // for Wif / RawHex
    std::string text;              // for Mnemonic / Xprv (the string as found)
    std::string passphrase;        // for Mnemonic, if a sibling passphrase was present
};

struct KeystoreImport {
    bool ok = false;               // true if the JSON parsed (items may still be empty)
    std::string error;
    std::vector<KeystoreItem> items;
};

// Parse a JSON keystore string and harvest key material. `ok=false` only on a
// JSON syntax error; a well-formed doc with no recognised keys returns ok=true
// with an empty item list (and a note in `error`).
KeystoreImport import_json_keystore(const std::string& json);

} // namespace c2w::hdkeys
