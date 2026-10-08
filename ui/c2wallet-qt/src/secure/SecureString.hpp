// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// SecureString / SecureBytes — zeroizing containers for secret material
// (seeds, private scalars, mnemonics, passphrases). Design §5.3 "Key custody".
//
// Guarantees, best-effort and defense-in-depth (none is a substitute for the
// air-gap itself, §5.1):
//   * the backing storage is wiped with a compiler-barrier'd erase on
//     destruction and on clear(), so a freed secret is not left in the heap;
//   * the pages are mlock()'d where the OS permits, so the secret is kept out
//     of swap.
//
// This header is Qt-free on purpose: the hdkeys crypto core and its KATs build
// and run without the Qt app (design §2.3 — link the leaf, not the shell).

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace c2w::secure {

// explicit_bzero-equivalent that the optimiser may not elide.
void secure_wipe(void* p, std::size_t n) noexcept;

// mlock/munlock wrappers; return false if the OS refused (e.g. RLIMIT_MEMLOCK).
// Failure is non-fatal — the wipe-on-free guarantee still holds.
bool try_lock_pages(void* p, std::size_t n) noexcept;
void try_unlock_pages(void* p, std::size_t n) noexcept;

// A byte buffer that wipes (and unlocks) its storage on destruction / clear /
// reallocation. Move-only; copying a secret is deliberately opt-in via copy().
class SecureBytes {
public:
    SecureBytes() = default;
    explicit SecureBytes(std::size_t n) { resize(n); }
    SecureBytes(const uint8_t* data, std::size_t n) { assign(data, n); }
    ~SecureBytes() { clear(); }

    SecureBytes(SecureBytes&& o) noexcept;
    SecureBytes& operator=(SecureBytes&& o) noexcept;
    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;

    SecureBytes copy() const { return SecureBytes(data_, size_); }

    void resize(std::size_t n);
    void assign(const uint8_t* data, std::size_t n);
    void clear() noexcept;

    uint8_t* data() noexcept { return data_; }
    const uint8_t* data() const noexcept { return data_; }
    std::size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
    uint8_t& operator[](std::size_t i) noexcept { return data_[i]; }
    uint8_t operator[](std::size_t i) const noexcept { return data_[i]; }

private:
    void free_storage() noexcept;
    uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t cap_ = 0;
    bool locked_ = false;
};

// A std::string-shaped secret (mnemonics, passphrases). Same wipe/lock policy.
class SecureString {
public:
    SecureString() = default;
    explicit SecureString(const std::string& s) { assign(s.data(), s.size()); }
    SecureString(const char* s, std::size_t n) { assign(s, n); }
    ~SecureString() { clear(); }

    SecureString(SecureString&&) noexcept = default;
    SecureString& operator=(SecureString&&) noexcept = default;
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;

    void assign(const char* s, std::size_t n) { buf_.assign(reinterpret_cast<const uint8_t*>(s), n); }
    void clear() noexcept { buf_.clear(); }

    std::size_t size() const noexcept { return buf_.size(); }
    bool empty() const noexcept { return buf_.empty(); }
    const uint8_t* bytes() const noexcept { return buf_.data(); }

private:
    SecureBytes buf_;
};

} // namespace c2w::secure
