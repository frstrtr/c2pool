// SPDX-License-Identifier: AGPL-3.0-or-later
#include "os_random.hpp"

#include <cerrno>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>       // BCryptGenRandom (system CSPRNG)
#pragma comment(lib, "bcrypt")
#else
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/random.h>   // Linux: getrandom(2). macOS: getentropy(2).
#endif
#endif

namespace core {

#if defined(_WIN32)

bool os_random_bytes(unsigned char* buf, std::size_t len)
{
    // BCryptGenRandom takes a ULONG count; draw in ULONG-sized pieces so a
    // (theoretical) request over 4 GiB is not silently truncated.
    constexpr std::size_t kMaxChunk = 0xFFFFFFFFu;
    std::size_t got = 0;
    while (got < len) {
        const std::size_t n = (len - got < kMaxChunk) ? (len - got) : kMaxChunk;
        if (::BCryptGenRandom(nullptr, buf + got, static_cast<ULONG>(n),
                              BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)   // != STATUS_SUCCESS
            return false;
        got += n;
    }
    return true;
}

#else

bool os_random_bytes(unsigned char* buf, std::size_t len)
{
    std::size_t got = 0;
#if defined(__linux__)
    while (got < len) {
        ssize_t r = ::getrandom(buf + got, len - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        got += static_cast<std::size_t>(r);
    }
    if (got == len) return true;
#elif defined(__APPLE__)
    // getentropy(2) refuses requests over 256 bytes (EIO); it either fills the
    // whole chunk or fails.
    while (got < len) {
        const std::size_t n = (len - got < 256) ? (len - got) : 256;
        if (::getentropy(buf + got, n) != 0) break;
        got += n;
    }
    if (got == len) return true;
#endif
    // Fallback: /dev/urandom (also the kernel CSPRNG), e.g. a Linux kernel
    // older than getrandom(2).
    int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    while (got < len) {
        ssize_t r = ::read(fd, buf + got, len - got);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            ::close(fd);
            return false;
        }
        got += static_cast<std::size_t>(r);
    }
    ::close(fd);
    return true;
}

#endif

} // namespace core
