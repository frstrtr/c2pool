// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// ui/c2wallet-qt/src/secure/SecureBuffer.hpp -- minimal zeroizing secret store
//
// c2wallet-qt §2.3 names a shared `secure/` module (SecureString, mlock,
// explicit_bzero, seccomp belt). This is a DELIBERATELY MINIMAL stand-in so the
// Family B (Monero) key layer can hold spend/view secrets that scrub themselves
// on destruction without waiting on the full module.
//
// DEDUP NOTE FOR MERGE: the parallel M1-A slice also introduces
// ui/c2wallet-qt/src/secure/. Whichever lands first owns the canonical
// SecureString/mlock surface; the other's copy should be dropped and the two
// call sites pointed at the survivor. This header is scoped to what the Monero
// seed/key/address core needs (a byte buffer and a char string that zeroize),
// so it can be folded into the richer M1-A version without API loss.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace c2wallet::secure {

// Overwrite `len` bytes at `p` such that the compiler may not elide the store.
// Prefers the platform's guaranteed-not-optimized-away scrub where present.
inline void secure_wipe(void* p, std::size_t len) noexcept
{
    if (p == nullptr || len == 0)
        return;
#if defined(__STDC_LIB_EXT1__)
    ::memset_s(p, len, 0, len);
#elif defined(__GLIBC__) || defined(__linux__)
    ::explicit_bzero(p, len);
#else
    volatile unsigned char* vp = static_cast<volatile unsigned char*>(p);
    while (len--) *vp++ = 0;
#endif
}

// A heap byte buffer that scrubs its storage on every mutation that frees it
// and on destruction. Not a general container -- just enough to carry 32-byte
// scalars/keys and short mnemonic-derived material through the key layer.
class SecureBytes {
public:
    SecureBytes() = default;
    explicit SecureBytes(std::size_t n) : buf_(n, 0) {}
    SecureBytes(const std::uint8_t* p, std::size_t n) : buf_(p, p + n) {}

    SecureBytes(const SecureBytes&) = default;
    SecureBytes& operator=(const SecureBytes& o)
    {
        if (this != &o) { wipe(); buf_ = o.buf_; }
        return *this;
    }
    SecureBytes(SecureBytes&& o) noexcept { buf_.swap(o.buf_); }
    SecureBytes& operator=(SecureBytes&& o) noexcept
    {
        if (this != &o) { wipe(); buf_.swap(o.buf_); }
        return *this;
    }

    ~SecureBytes() { wipe(); }

    std::uint8_t*       data()       noexcept { return buf_.data(); }
    const std::uint8_t* data() const noexcept { return buf_.data(); }
    std::size_t         size() const noexcept { return buf_.size(); }
    bool                empty() const noexcept { return buf_.empty(); }

    std::uint8_t&       operator[](std::size_t i)       noexcept { return buf_[i]; }
    const std::uint8_t& operator[](std::size_t i) const noexcept { return buf_[i]; }

    void resize(std::size_t n) { buf_.resize(n); }
    void assign(const std::uint8_t* p, std::size_t n) { wipe(); buf_.assign(p, p + n); }

    void wipe() noexcept
    {
        if (!buf_.empty())
            secure_wipe(buf_.data(), buf_.size());
    }

private:
    std::vector<std::uint8_t> buf_;
};

// A std::string-like holder that scrubs its bytes on destruction. Used for the
// mnemonic phrase between construction and word-splitting so the plaintext
// phrase does not linger in a freed std::string allocation.
class SecureString {
public:
    SecureString() = default;
    explicit SecureString(std::string s) : s_(std::move(s)) {}

    SecureString(const SecureString&) = default;
    SecureString& operator=(const SecureString& o)
    {
        if (this != &o) { wipe(); s_ = o.s_; }
        return *this;
    }
    SecureString(SecureString&& o) noexcept { s_.swap(o.s_); }
    SecureString& operator=(SecureString&& o) noexcept
    {
        if (this != &o) { wipe(); s_.swap(o.s_); }
        return *this;
    }

    ~SecureString() { wipe(); }

    const std::string& str() const noexcept { return s_; }
    std::size_t        size() const noexcept { return s_.size(); }
    bool               empty() const noexcept { return s_.empty(); }

    void wipe() noexcept
    {
        if (!s_.empty()) {
            secure_wipe(&s_[0], s_.size());
            s_.clear();
        }
    }

private:
    std::string s_;
};

} // namespace c2wallet::secure
