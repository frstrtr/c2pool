// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BIP38 passphrase-encrypted private keys (design §3.1). Supports both modes:
//   * non-EC-multiply  (prefix 0x0142): scrypt(passphrase, addresshash, 16384,
//     8, 8, 64) -> AES-256 decrypt two halves -> scalar.
//   * EC-multiply      (prefix 0x0143): scrypt owner-salt prefactor -> passpoint
//     -> scrypt(passpoint, addresshash‖ownerentropy, 1024,1,1,64) -> AES-256
//     decrypt -> seedb -> privkey = passfactor * factorb mod N. Lot/sequence
//     supported.
// CPU-bound by design (N=16384). The decrypted scalar is verified against the
// embedded address-hash checksum, so a wrong passphrase is rejected (it does not
// silently yield a different key).
//
// The scalar is returned in a zeroizing SecureBytes (design §5.3).

#include "../../../secure/SecureString.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace c2w::hdkeys {

struct Bip38Decode {
    bool ok = false;
    std::string error;
    secure::SecureBytes scalar;   // 32-byte private key (valid iff ok)
    bool compressed = false;
    bool ec_multiply = false;     // which mode the key used
    bool lot_sequence = false;    // EC-multiply lot/sequence present
    uint8_t address_version = 0;  // the P2PKH version byte whose address hash matched
};

// Decrypt a "6P..." BIP38 key with `passphrase` (UTF-8, caller-normalised).
// A wrong passphrase fails the address-hash check and returns ok=false. The
// address hash is checked over the BTC address (version 0x00), as BIP38 defines.
Bip38Decode decode_bip38(const std::string& encrypted, const std::string& passphrase);

// The same, with the address hash checked over the P2PKH address of each listed
// version byte in turn (one decryption; the first match wins and is reported in
// address_version). Altcoin BIP38 encryptors hash their own coin's address, e.g.
// DASH 0x4c. The check only screens the passphrase: a caller that needs a
// particular key must still bind the decrypted scalar to its address.
Bip38Decode decode_bip38(const std::string& encrypted, const std::string& passphrase,
                         const std::vector<uint8_t>& address_versions);

} // namespace c2w::hdkeys
