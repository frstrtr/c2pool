// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/anchor/xmr_anchor_sha256.hpp
//
// FIPS 180-4 SHA-256, header-only and STL-only, for exactly one caller: the
// anchor bundle's integrity digest.
//
// WHY NOT src/btclibs/crypto/sha256.h. That implementation is excellent and it
// is what the pool uses everywhere else, but it is a LIBRARY: it carries a
// runtime CPU-dispatch table that must be initialised before first use, and
// linking it would end the property the whole native/ tree is built around --
// every header here compiles into a single-translation-unit KAT with nothing
// but the standard library. The anchor loader is the node's trust root and the
// last thing it should need is a link-time dependency that can be initialised
// wrong. So the one hash function it needs lives here, in 90 lines, pinned by
// the KAT against the FIPS 180-4 published vectors and against a long message
// that crosses the 64-byte block and the length-padding boundary.
//
// SCOPE: this is a MESSAGE DIGEST FOR AN ACCIDENT CHECK, not a consensus
// primitive and not a defence against a forged bundle. anchor.hpp says it in
// the struct comment and it is worth repeating at the implementation: the
// anchor's real defence is that the block it names is fetched from the network
// and re-hashed. The digest catches a truncated download and a stray editor,
// which is what it is asked to catch.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace c2pool::xmr::native::anchor_hash {

namespace detail {

inline constexpr std::uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

inline constexpr std::uint32_t rotr(std::uint32_t x, int n) noexcept {
    return (x >> n) | (x << (32 - n));
}

}  // namespace detail

class Sha256 {
public:
    Sha256() noexcept { reset(); }

    void reset() noexcept {
        h_[0] = 0x6a09e667u; h_[1] = 0xbb67ae85u; h_[2] = 0x3c6ef372u; h_[3] = 0xa54ff53au;
        h_[4] = 0x510e527fu; h_[5] = 0x9b05688cu; h_[6] = 0x1f83d9abu; h_[7] = 0x5be0cd19u;
        buf_len_ = 0;
        total_bytes_ = 0;
    }

    void update(const std::uint8_t* data, std::size_t len) noexcept {
        total_bytes_ += len;
        while (len > 0) {
            const std::size_t take = (64 - buf_len_) < len ? (64 - buf_len_) : len;
            for (std::size_t i = 0; i < take; ++i) buf_[buf_len_ + i] = data[i];
            buf_len_ += take;
            data += take;
            len  -= take;
            if (buf_len_ == 64) { compress(buf_); buf_len_ = 0; }
        }
    }

    void update(const std::string& s) noexcept {
        update(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
    }

    std::array<std::uint8_t, 32> finish() noexcept {
        const std::uint64_t bits = total_bytes_ * 8ull;
        static const std::uint8_t kPad = 0x80u;
        update(&kPad, 1);
        static const std::uint8_t kZero = 0x00u;
        while (buf_len_ != 56) update(&kZero, 1);
        std::uint8_t len_be[8];
        for (int i = 0; i < 8; ++i) len_be[i] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
        // total_bytes_ is not used again, so letting the length bytes bump it is harmless.
        update(len_be, 8);

        std::array<std::uint8_t, 32> out{};
        for (int i = 0; i < 8; ++i) {
            out[4 * i + 0] = static_cast<std::uint8_t>(h_[i] >> 24);
            out[4 * i + 1] = static_cast<std::uint8_t>(h_[i] >> 16);
            out[4 * i + 2] = static_cast<std::uint8_t>(h_[i] >> 8);
            out[4 * i + 3] = static_cast<std::uint8_t>(h_[i]);
        }
        return out;
    }

private:
    void compress(const std::uint8_t* p) noexcept {
        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<std::uint32_t>(p[4 * i + 0]) << 24)
                 | (static_cast<std::uint32_t>(p[4 * i + 1]) << 16)
                 | (static_cast<std::uint32_t>(p[4 * i + 2]) << 8)
                 |  static_cast<std::uint32_t>(p[4 * i + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            const std::uint32_t s0 = detail::rotr(w[i - 15], 7) ^ detail::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const std::uint32_t s1 = detail::rotr(w[i - 2], 17) ^ detail::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
        std::uint32_t e = h_[4], f = h_[5], g = h_[6], hh = h_[7];
        for (int i = 0; i < 64; ++i) {
            const std::uint32_t S1  = detail::rotr(e, 6) ^ detail::rotr(e, 11) ^ detail::rotr(e, 25);
            const std::uint32_t ch  = (e & f) ^ (~e & g);
            const std::uint32_t t1  = hh + S1 + ch + detail::K[i] + w[i];
            const std::uint32_t S0  = detail::rotr(a, 2) ^ detail::rotr(a, 13) ^ detail::rotr(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t t2  = S0 + maj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
        h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += hh;
    }

    std::uint32_t h_[8]{};
    std::uint8_t  buf_[64]{};
    std::size_t   buf_len_ = 0;
    std::uint64_t total_bytes_ = 0;
};

inline std::array<std::uint8_t, 32> sha256(const std::string& s) noexcept {
    Sha256 h;
    h.update(s);
    return h.finish();
}

}  // namespace c2pool::xmr::native::anchor_hash
