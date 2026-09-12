// SPDX-License-Identifier: AGPL-3.0-or-later
#include "SecureString.hpp"

#include <cstring>
#include <new>

#if defined(_WIN32)
#  include <windows.h>
#else
#  include <sys/mman.h>
#endif

namespace c2w::secure {

void secure_wipe(void* p, std::size_t n) noexcept
{
    if (!p || n == 0) return;
#if defined(_WIN32)
    ::SecureZeroMemory(p, n);
#elif defined(__STDC_LIB_EXT1__) || defined(memset_s)
    memset_s(p, n, 0, n);
#elif defined(__GLIBC__) || defined(__BIONIC__) || defined(__APPLE__)
    ::explicit_bzero(p, n);
#else
    // Portable fallback: a volatile write the optimiser must not drop.
    volatile unsigned char* vp = reinterpret_cast<volatile unsigned char*>(p);
    while (n--) *vp++ = 0;
#endif
}

bool try_lock_pages(void* p, std::size_t n) noexcept
{
    if (!p || n == 0) return true;
#if defined(_WIN32)
    return ::VirtualLock(p, n) != 0;
#else
    return ::mlock(p, n) == 0;
#endif
}

void try_unlock_pages(void* p, std::size_t n) noexcept
{
    if (!p || n == 0) return;
#if defined(_WIN32)
    ::VirtualUnlock(p, n);
#else
    ::munlock(p, n);
#endif
}

// ── SecureBytes ────────────────────────────────────────────────────────────

void SecureBytes::free_storage() noexcept
{
    if (data_) {
        secure_wipe(data_, cap_);
        if (locked_) try_unlock_pages(data_, cap_);
        ::operator delete(data_);
    }
    data_ = nullptr;
    size_ = 0;
    cap_ = 0;
    locked_ = false;
}

void SecureBytes::clear() noexcept { free_storage(); }

void SecureBytes::resize(std::size_t n)
{
    if (n <= cap_) { size_ = n; return; }
    uint8_t* nd = static_cast<uint8_t*>(::operator new(n));
    bool nl = try_lock_pages(nd, n);
    if (data_ && size_) std::memcpy(nd, data_, size_);
    // Retire old storage.
    if (data_) {
        secure_wipe(data_, cap_);
        if (locked_) try_unlock_pages(data_, cap_);
        ::operator delete(data_);
    }
    data_ = nd;
    cap_ = n;
    size_ = n;
    locked_ = nl;
}

void SecureBytes::assign(const uint8_t* data, std::size_t n)
{
    resize(n);
    if (n && data) std::memcpy(data_, data, n);
}

SecureBytes::SecureBytes(SecureBytes&& o) noexcept
    : data_(o.data_), size_(o.size_), cap_(o.cap_), locked_(o.locked_)
{
    o.data_ = nullptr;
    o.size_ = 0;
    o.cap_ = 0;
    o.locked_ = false;
}

SecureBytes& SecureBytes::operator=(SecureBytes&& o) noexcept
{
    if (this != &o) {
        free_storage();
        data_ = o.data_;
        size_ = o.size_;
        cap_ = o.cap_;
        locked_ = o.locked_;
        o.data_ = nullptr;
        o.size_ = 0;
        o.cap_ = 0;
        o.locked_ = false;
    }
    return *this;
}

} // namespace c2w::secure
