// SPDX-License-Identifier: AGPL-3.0-or-later
//
// BLAKE2b (RFC 7693) — sequential, unkeyed, variable digest length.
//
// Clean-room implementation of the RFC 7693 reference algorithm, isolated to
// the BIP-110 coin lane so it can never be reached from the SHA256d / scrypt /
// X11 PoW paths of the other lanes (per-coin isolation invariant). BIP-110
// (Bitcoin Knots BLAKE2b hard fork) needs BLAKE2b-256 (digest length 32) with
// no key; this header exposes exactly that plus the generic digest length so
// the primitive can be validated against the RFC BLAKE2b-512 test vector.

#ifndef C2POOL_IMPL_BIP110_CRYPTO_BLAKE2B_H
#define C2POOL_IMPL_BIP110_CRYPTO_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// One-shot unkeyed BLAKE2b. out_len must be in [1, 64]. Returns 0 on success,
// -1 on an invalid out_len. No key is supported by design (BIP-110 uses the
// unkeyed sequential mode).
int bip110_blake2b(void* out, size_t out_len, const void* in, size_t in_len);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // C2POOL_IMPL_BIP110_CRYPTO_BLAKE2B_H
