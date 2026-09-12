// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Csprng.hpp"

#include <stdexcept>

#if defined(_WIN32)
// Windows arm (design decision 3 packaging): link bcrypt.
//   #include <windows.h>
//   #include <bcrypt.h>
//   NTSTATUS s = BCryptGenRandom(nullptr, out, (ULONG)n,
//                                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
//   if (s != 0) throw ...;
#  include <windows.h>
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt.lib")
#else
#  include <cerrno>
#  include <sys/random.h>   // getrandom(2)
#endif

namespace c2w::hdkeys {

void csprng_bytes(uint8_t* out, size_t n)
{
    if (n == 0) return;
#if defined(_WIN32)
    NTSTATUS s = ::BCryptGenRandom(nullptr, out, static_cast<ULONG>(n),
                                   BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (s != 0)
        throw std::runtime_error("csprng: BCryptGenRandom failed");
#else
    size_t got = 0;
    while (got < n) {
        // flags=0 => draw from the same pool as /dev/urandom, blocking only
        // until it has been seeded once. GRND_NONBLOCK is deliberately NOT set:
        // we would rather block than emit unseeded entropy for a wallet seed.
        ssize_t r = ::getrandom(out + got, n - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error("csprng: getrandom(2) failed");
        }
        got += static_cast<size_t>(r);
    }
#endif
}

std::vector<uint8_t> csprng_bytes(size_t n)
{
    std::vector<uint8_t> v(n);
    csprng_bytes(v.data(), n);
    return v;
}

} // namespace c2w::hdkeys
