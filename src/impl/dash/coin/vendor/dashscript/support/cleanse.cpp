// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <support/cleanse.h>

#include <cstring>

// _MSC_VER (not bare WIN32) is the correct "this is MSVC" discriminator: MSVC
// predefines _WIN32/_MSC_VER but NOT WIN32 (only the build system / windows.h
// sets that token, and this vendored lib's CMake never does), so a WIN32 guard
// fell through to the GCC inline-asm branch on MSVC (C2065 __asm__/C3861
// __volatile__). Mirrors Bitcoin Core's _MSC_VER cleanse guard. MinGW-GCC
// (which supports __asm__) correctly stays on the asm branch. Linux defines
// neither token → still takes the #else memset+barrier, byte-identical.
#if defined(_MSC_VER)
#include <windows.h>
#endif

void memory_cleanse(void *ptr, size_t len)
{
#if defined(_MSC_VER)
    /* SecureZeroMemory is guaranteed not to be optimized out. */
    SecureZeroMemory(ptr, len);
#else
    std::memset(ptr, 0, len);

    /* Memory barrier that scares the compiler away from optimizing out the memset.
     *
     * Quoting Adam Langley <agl@google.com> in commit ad1907fe73334d6c696c8539646c21b11178f20f
     * in BoringSSL (ISC License):
     *    As best as we can tell, this is sufficient to break any optimisations that
     *    might try to eliminate "superfluous" memsets.
     * This method is used in memzero_explicit() the Linux kernel, too. Its advantage is that it
     * is pretty efficient because the compiler can still implement the memset() efficiently,
     * just not remove it entirely. See "Dead Store Elimination (Still) Considered Harmful" by
     * Yang et al. (USENIX Security 2017) for more background.
     */
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}
