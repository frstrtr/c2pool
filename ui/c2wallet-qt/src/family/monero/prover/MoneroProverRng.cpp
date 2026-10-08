// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
#include "family/monero/prover/MoneroProverRng.hpp"

#include <stdexcept>

#include "secure/SecureString.hpp"   // c2w::secure::secure_wipe
#include "xmr_rct_ops.hpp"           // c2pool::xmr::native::rct::scalar_is_zero

extern "C" {
#include "vendor/crypto-ops.h"       // sc_reduce32
}

#if defined(__linux__)
#  include <sys/random.h>            // getrandom(2)
#  include <cerrno>
#elif defined(_WIN32)
// Windows: draw from the OS CSPRNG via BCryptGenRandom (bcrypt.lib).
#  include <windows.h>
#  include <bcrypt.h>
#endif

namespace xr = c2pool::xmr::native::rct;

namespace c2wallet::monero::prover {

namespace {

// Fill `out` with `len` bytes from the OS CSPRNG. Fail-closed: throws on any
// error rather than leave the buffer weakly seeded.
void csprng_bytes(std::uint8_t* out, std::size_t len) {
#if defined(__linux__)
    // Same vetted source MoneroKey.cpp uses for key generation: getrandom(2),
    // never a demo/PRNG. Loop over short reads and EINTR.
    std::size_t got = 0;
    while (got < len) {
        ssize_t n = ::getrandom(out + got, len - got, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            throw std::runtime_error("getrandom(2) failed: prover CSPRNG unavailable");
        }
        got += static_cast<std::size_t>(n);
    }
#elif defined(_WIN32)
    if (::BCryptGenRandom(nullptr, out, static_cast<ULONG>(len),
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw std::runtime_error("BCryptGenRandom failed: prover CSPRNG unavailable");
    }
#else
    (void)out; (void)len;
    throw std::runtime_error(
        "no vetted CSPRNG available on this platform (getrandom/BCryptGenRandom required)");
#endif
}

} // namespace

Bytes32 csprng_scalar_nonzero() {
    Bytes32 k{};
    for (;;) {
        csprng_bytes(k.data(), k.size());
        // Reduce mod l to a canonical scalar (NOT a truncation), then reject
        // zero -- identical post-processing to the node helper, CSPRNG entropy.
        sc_reduce32(k.data());
        if (!xr::scalar_is_zero(k))
            return k;
        // The all-zero reduction is astronomically unlikely; wipe and redraw.
        c2w::secure::secure_wipe(k.data(), k.size());
    }
}

} // namespace c2wallet::monero::prover
