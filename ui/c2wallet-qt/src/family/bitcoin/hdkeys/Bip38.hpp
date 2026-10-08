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

namespace c2w::hdkeys {

struct Bip38Decode {
    bool ok = false;
    std::string error;
    secure::SecureBytes scalar;   // 32-byte private key (valid iff ok)
    bool compressed = false;
    bool ec_multiply = false;     // which mode the key used
    bool lot_sequence = false;    // EC-multiply lot/sequence present
};

// Decrypt a "6P..." BIP38 key with `passphrase` (UTF-8, caller-normalised).
// A wrong passphrase fails the address-hash check and returns ok=false.
Bip38Decode decode_bip38(const std::string& encrypted, const std::string& passphrase);

} // namespace c2w::hdkeys
