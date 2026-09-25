// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// AES in CBC mode with PKCS#7 padding, for the Family-A full-file importers
// (design §3.1 — "import ANY key format"). Two consumers need block-cipher CBC
// that the BIP38 single-block ECB primitive (Aes256.hpp) does not cover:
//
//   * Electrum full-file storage encryption — ECIES body is AES-128-CBC
//     (Electrum crypto.py: iv=key[0:16], key_e=key[16:32] => a 16-byte key),
//     and Electrum field-level pw_encode is AES-256-CBC (key = SHA256d(pw)).
//   * Bitcoin Core wallet.dat — the master key and every crypted key are
//     AES-256-CBC (Core crypter.cpp), PKCS#7 padded.
//
// A compact FIPS-197 AES supporting 128/192/256-bit keys lives here (the
// existing Aes256 is ECB-single-block only and 256-bit only). KAT-gated against
// FIPS-197 Appendix C vectors AND Electrum's own published AES-128/256-CBC
// self-test vectors, so the bytes are provably identical to the reference
// implementations these wallets were written with.

#include "../../../secure/SecureString.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace c2w::hdkeys {

// AES-CBC decrypt with PKCS#7 unpadding. key_len must be 16/24/32; iv is 16
// bytes; ciphertext length must be a non-zero multiple of 16. Returns nullopt on
// a bad length or an invalid PKCS#7 pad (the latter is how a wrong password is
// detected, matching Electrum/Core). Output is a zeroizing SecureBytes.
std::optional<secure::SecureBytes>
aes_cbc_decrypt_pkcs7(const uint8_t* key, size_t key_len,
                      const uint8_t iv[16],
                      const uint8_t* ct, size_t ct_len);

// AES-CBC encrypt with PKCS#7 padding. Used only by the deterministic KAT
// fixture path / round-trip checks (never on the import money-path). key_len
// 16/24/32; iv 16 bytes. Output length is ct rounded up to the next block.
std::vector<uint8_t>
aes_cbc_encrypt_pkcs7(const uint8_t* key, size_t key_len,
                      const uint8_t iv[16],
                      const uint8_t* pt, size_t pt_len);

} // namespace c2w::hdkeys
