// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Vetted CSPRNG for fund-guarding entropy (design §3.4 HARD FLAG). This is the
// deliberate replacement for the `mnemonic_gen` demo RNG: entropy that guards
// real funds MUST come from the OS CSPRNG, never a userspace PRNG.
//
//   Linux:   getrandom(2) (blocking until the pool is initialised; no /dev
//            fallback that could be a regular file on a tampered box).
//   Windows: BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG) — see Csprng.cpp
//            (compiled path is Linux here; the Windows arm is documented +
//            written for when the packaging matrix builds it, design decision 3).
//
// Throws std::runtime_error rather than ever returning low-quality bytes.

#include <cstddef>
#include <cstdint>
#include <vector>

namespace c2w::hdkeys {

// Fill exactly n bytes of cryptographically secure randomness. Throws on failure.
void csprng_bytes(uint8_t* out, size_t n);

std::vector<uint8_t> csprng_bytes(size_t n);

} // namespace c2w::hdkeys
