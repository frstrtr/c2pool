// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/consensus/xmr_blob_reader.hpp
//
// The bounds-checked READ counterpart to xmr_blob.hpp's BlobWriter. c2pool has
// been able to WRITE CryptoNote blobs since the XMR lane foundation; nothing on
// master could read one back, so three separate native-node components (the
// chain-state index parsing pruned block bodies, the txpool decoding relayed
// transactions, and the block relay reconstructing a fluffy block) were each
// about to grow their own deserializer. This is the single implementation.
//
// Design rules, all of them because this parser is the first thing that touches
// bytes an unauthenticated peer chose:
//
//   1. EVERY read is bounds-checked and returns bool. There is no throwing path
//      and no unchecked accessor.
//   2. Once a read fails the reader is POISONED: ok() stays false and every
//      subsequent read fails without advancing. A caller that forgets one check
//      still cannot walk off the end.
//   3. The cursor never moves past the end, and it never moves at all on a
//      failed read. Both are class invariants, asserted by the fuzz KAT.
//   4. Varints are decoded exactly as monerod's tools::read_varint: overflow
//      past 64 bits is rejected, and so is the non-canonical encoding (a
//      continuation byte of 0x00 at a non-zero shift).
//   5. Nesting is capped at MAX_DEPTH = 8 through a scoped guard, so a crafted
//      blob cannot recurse a parser into the stack guard page.
//   6. Every counted container is read through read_count(), which takes the
//      caller's own upper bound and refuses to pre-allocate on a peer's word.
//
// STL only. No allocation is performed by the reader itself; it is a cursor
// over memory the caller owns and must keep alive.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace c2pool::xmr::native {

inline constexpr std::size_t BLOB_MAX_DEPTH = 8;

// Default ceiling for a counted container when the caller has no tighter bound.
// Chosen to match the epee decoder's entry cap used elsewhere in the lane.
inline constexpr std::uint64_t BLOB_MAX_ELEMENTS = 4096;

enum class BlobError : std::uint8_t {
    None = 0,
    Truncated,        // ran out of input
    VarintOverflow,   // more than 64 bits of payload
    VarintNonCanonical,
    CountTooLarge,    // container count above the caller's bound
    DepthExceeded,
    Malformed,        // caller-reported structural error
};

inline const char* to_string(BlobError e) noexcept {
    switch (e) {
        case BlobError::None:               return "None";
        case BlobError::Truncated:          return "Truncated";
        case BlobError::VarintOverflow:     return "VarintOverflow";
        case BlobError::VarintNonCanonical: return "VarintNonCanonical";
        case BlobError::CountTooLarge:      return "CountTooLarge";
        case BlobError::DepthExceeded:      return "DepthExceeded";
        case BlobError::Malformed:          return "Malformed";
    }
    return "?";
}

class BlobReader {
public:
    BlobReader(const std::uint8_t* data, std::size_t size) noexcept
        : data_(size ? data : nullptr), size_(data ? size : 0) {}

    explicit BlobReader(const std::vector<std::uint8_t>& v) noexcept
        : BlobReader(v.data(), v.size()) {}

    // --- state ---------------------------------------------------------------
    bool        ok()        const noexcept { return err_ == BlobError::None; }
    BlobError   error()     const noexcept { return err_; }
    std::size_t offset()    const noexcept { return pos_; }
    std::size_t size()      const noexcept { return size_; }
    std::size_t remaining() const noexcept { return size_ - pos_; }  // pos_ <= size_ always
    bool        eof()       const noexcept { return pos_ >= size_; }
    std::size_t depth()     const noexcept { return depth_; }

    // Poison the reader with a caller-detected structural error.
    bool fail(BlobError e = BlobError::Malformed) noexcept {
        if (err_ == BlobError::None) err_ = e;
        return false;
    }

    // --- primitive reads -----------------------------------------------------
    bool read_byte(std::uint8_t& out) noexcept {
        if (!ok()) return false;
        if (remaining() < 1) return fail(BlobError::Truncated);
        out = data_[pos_++];
        return true;
    }

    bool peek_byte(std::uint8_t& out) const noexcept {
        if (!ok() || remaining() < 1) return false;
        out = data_[pos_];
        return true;
    }

    bool read_bytes(void* dst, std::size_t n) noexcept {
        if (!ok()) return false;
        if (remaining() < n) return fail(BlobError::Truncated);
        if (n) std::memcpy(dst, data_ + pos_, n);
        pos_ += n;
        return true;
    }

    // Borrow n bytes without copying. The pointer is valid only while the
    // underlying buffer is.
    bool read_view(const std::uint8_t*& out, std::size_t n) noexcept {
        if (!ok()) return false;
        if (remaining() < n) return fail(BlobError::Truncated);
        out = data_ + pos_;
        pos_ += n;
        return true;
    }

    bool skip(std::size_t n) noexcept {
        if (!ok()) return false;
        if (remaining() < n) return fail(BlobError::Truncated);
        pos_ += n;
        return true;
    }

    bool read_key(std::array<std::uint8_t, 32>& out) noexcept {
        return read_bytes(out.data(), 32);
    }

    bool read_u32_le(std::uint32_t& out) noexcept {
        std::uint8_t b[4];
        if (!read_bytes(b, 4)) return false;
        out = static_cast<std::uint32_t>(b[0])
            | (static_cast<std::uint32_t>(b[1]) << 8)
            | (static_cast<std::uint32_t>(b[2]) << 16)
            | (static_cast<std::uint32_t>(b[3]) << 24);
        return true;
    }

    bool read_u64_le(std::uint64_t& out) noexcept {
        std::uint8_t b[8];
        if (!read_bytes(b, 8)) return false;
        out = 0;
        for (int i = 7; i >= 0; --i) out = (out << 8) | b[static_cast<std::size_t>(i)];
        return true;
    }

    // CryptoNote LEB128 varint, decoded exactly as monerod tools::read_varint:
    // reject overflow past 64 bits and reject the non-canonical 0x00
    // continuation byte at a non-zero shift.
    bool read_varint(std::uint64_t& out) noexcept {
        if (!ok()) return false;
        const std::size_t start = pos_;
        std::uint64_t value = 0;
        for (int shift = 0;; shift += 7) {
            if (remaining() < 1) { pos_ = start; return fail(BlobError::Truncated); }
            const std::uint8_t byte = data_[pos_++];
            if (shift + 7 >= 64
                && byte >= (1u << (64 - shift))) {   // shift < 64 here, so this is defined
                pos_ = start;
                return fail(BlobError::VarintOverflow);
            }
            if (byte == 0 && shift != 0) {
                pos_ = start;
                return fail(BlobError::VarintNonCanonical);
            }
            value |= static_cast<std::uint64_t>(byte & 0x7f) << shift;
            if ((byte & 0x80) == 0) break;
        }
        out = value;
        return true;
    }

    // A counted container. `max_allowed` is the CALLER's structural bound; the
    // count is additionally refused when it exceeds the bytes actually left,
    // so a peer cannot make us reserve memory it never has to send.
    bool read_count(std::uint64_t& out, std::uint64_t max_allowed,
                    std::size_t min_bytes_per_element = 1) noexcept {
        if (!ok()) return false;
        // The cursor is rewound on every failure path, including the two that
        // reject a varint that itself decoded fine. Class invariant: a failed
        // read leaves the cursor exactly where it was.
        const std::size_t start = pos_;
        std::uint64_t n = 0;
        if (!read_varint(n)) return false;   // read_varint rewinds itself
        if (n > max_allowed) { pos_ = start; return fail(BlobError::CountTooLarge); }
        if (min_bytes_per_element > 0) {
            // Division, not multiplication: `n` came off the wire, so a product
            // could wrap for a large caller bound.
            const std::uint64_t affordable =
                    static_cast<std::uint64_t>(remaining()) / min_bytes_per_element;
            if (n > affordable) { pos_ = start; return fail(BlobError::Truncated); }
        }
        out = n;
        return true;
    }

    // --- nesting guard -------------------------------------------------------
    // Scoped: construct one per nested structure and check ok() on the reader.
    class DepthGuard {
    public:
        explicit DepthGuard(BlobReader& r) noexcept : r_(r), entered_(false) {
            if (!r_.ok()) return;
            if (r_.depth_ >= BLOB_MAX_DEPTH) { r_.fail(BlobError::DepthExceeded); return; }
            ++r_.depth_;
            entered_ = true;
        }
        ~DepthGuard() noexcept { if (entered_) --r_.depth_; }
        DepthGuard(const DepthGuard&)            = delete;
        DepthGuard& operator=(const DepthGuard&) = delete;
        bool entered() const noexcept { return entered_; }
    private:
        BlobReader& r_;
        bool        entered_;
    };

private:
    const std::uint8_t* data_ = nullptr;
    std::size_t         size_ = 0;
    std::size_t         pos_  = 0;
    std::size_t         depth_ = 0;
    BlobError           err_  = BlobError::None;
};

} // namespace c2pool::xmr::native
