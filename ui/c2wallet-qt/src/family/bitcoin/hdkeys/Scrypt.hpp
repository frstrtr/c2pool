// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// General scrypt(N, r, p, dkLen) KDF for BIP38 (design §3.1: "scrypt (vendored)").
//
// c2pool vendors scrypt in src/btclibs/crypto/scrypt.{h,cpp}, but ONLY as the
// fixed-parameter Litecoin PoW entrypoint scrypt_1024_1_1_256 (N=1024,r=1,p=1,
// 32-byte output on a hashed-blockheader input). BIP38 needs the two other
// parameter sets — N=16384,r=8,p=8,dkLen=64 (the passphrase/EC-multiply factor)
// and N=1024,r=1,p=1,dkLen=64 (the EC-multiply key-encryption step) — so the
// general N,r,p ROMix is provided here. It REUSES the vendored PBKDF2-HMAC-SHA256
// (scrypt.h `PBKDF2_SHA256`) for scrypt's inner/outer PBKDF2 passes, and uses the
// same Salsa20/8 lineage the vendored core is built on. KAT-gated against the
// RFC 7914 scrypt test vectors.

#include <cstddef>
#include <cstdint>
#include <vector>

namespace c2w::hdkeys {

// Compute scrypt. N must be a power of two > 1. Returns dkLen bytes.
// Throws std::invalid_argument on bad parameters, std::bad_alloc if V won't fit.
std::vector<uint8_t> scrypt_general(const uint8_t* passwd, size_t passwd_len,
                                    const uint8_t* salt, size_t salt_len,
                                    uint64_t N, uint32_t r, uint32_t p, size_t dkLen);

} // namespace c2w::hdkeys
