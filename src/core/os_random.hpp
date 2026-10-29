// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// OS CSPRNG, one portable entry point for code that draws key material or
// nonces (the DASH alert-relay keys and seal nonces).
//
// Only the operating system's CSPRNG is ever used. There is no fallback to
// std::random_device, mt19937 or any other userspace generator: a caller that
// gets `false` must fail closed (no key, no nonce) instead of degrading.
//
//   Linux:   getrandom(2), EINTR-retried (blocks only until the kernel pool is
//            first seeded), then a read of /dev/urandom if getrandom fails.
//   macOS:   getentropy(2) in chunks of at most 256 bytes (its per-call
//            limit), then /dev/urandom if getentropy fails.
//   Windows: BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG.
//   other POSIX: /dev/urandom.
//
// The implementation lives in os_random.cpp so that <windows.h>/<bcrypt.h>
// stay out of every header that needs random bytes.

#include <cstddef>

namespace core {

bool os_random_bytes(unsigned char* buf, std::size_t len);

} // namespace core
