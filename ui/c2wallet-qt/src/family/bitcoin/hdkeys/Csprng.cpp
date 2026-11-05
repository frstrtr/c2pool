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
#elif defined(__APPLE__)
#  include <sys/types.h>
#  include <sys/random.h>   // getentropy(2), macOS 10.12+
#  include <unistd.h>
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
#elif defined(__APPLE__)
    // Darwin has no getrandom(2). getentropy(2) draws from the same kernel
    // CSPRNG as arc4random and fills at most 256 bytes per call; any failure
    // throws, so no partial buffer is ever handed back as a result.
    detail::fill_in_chunks(out, n, 256,
                           [](uint8_t* p, size_t len) { return ::getentropy(p, len) == 0; },
                           "csprng: getentropy(2) failed");
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
