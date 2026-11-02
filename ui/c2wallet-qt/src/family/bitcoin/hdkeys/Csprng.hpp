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
//   macOS:   getentropy(2) (the kernel CSPRNG; at most 256 bytes per call, so
//            the request is filled in chunks by fill_in_chunks below).
//
// Throws std::runtime_error rather than ever returning low-quality bytes.

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace c2w::hdkeys {

namespace detail {

// Fill out[0, n) by calling fill(ptr, len) with 1 <= len <= max_chunk over
// consecutive slices until all n bytes are written. fill returns false on
// failure, which throws: the request never "succeeds" with fewer than n bytes.
// Used by the macOS arm (getentropy caps one call at 256 bytes); a template so
// the KAT can drive it with a fake source on any platform.
template <class Fill>
void fill_in_chunks(uint8_t* out, size_t n, size_t max_chunk, Fill&& fill, const char* what)
{
    if (max_chunk == 0) throw std::logic_error("csprng: chunk size must be >= 1");
    size_t got = 0;
    while (got < n) {
        const size_t len = (n - got) < max_chunk ? (n - got) : max_chunk;
        if (!fill(out + got, len)) throw std::runtime_error(what);
        got += len;
    }
}

} // namespace detail

// Fill exactly n bytes of cryptographically secure randomness. Throws on failure.
void csprng_bytes(uint8_t* out, size_t n);

std::vector<uint8_t> csprng_bytes(size_t n);

} // namespace c2w::hdkeys
