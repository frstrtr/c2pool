// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_hello.hpp
// Path B FB_HELLO: the S4 trailer.
//
//   trailer (68 B, little-endian) = u16 epoch_cur | u16 deploy_top
//                                 | b32 deploy_digest | b32 next_digest
//   epoch_cur selects the rules block HELLO compares; deploy_top,
//   deploy_digest and next_digest are diagnostics (a local alarm, never a
//   verdict). No deployment table is on the wire.
//
// Header-only. Not included by any running component.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "pathb_params.hpp"  // Hash32, kHashBytes

namespace c2pool::xmr::pathb {

struct HelloTrailer {
    std::uint16_t epoch_cur = 0;
    std::uint16_t deploy_top = 0;
    Hash32 deploy_digest{};
    Hash32 next_digest{};

    friend bool operator==(const HelloTrailer&, const HelloTrailer&) = default;
};

inline constexpr std::size_t kHelloTrailerEpochBytes = sizeof(std::uint16_t);
inline constexpr std::size_t kHelloTrailerBytes = 2 * kHelloTrailerEpochBytes + 2 * kHashBytes;
static_assert(kHelloTrailerBytes == 68);

using HelloTrailerBytes = std::array<std::uint8_t, kHelloTrailerBytes>;

inline HelloTrailerBytes encode_hello_trailer(const HelloTrailer& t) noexcept {
    HelloTrailerBytes b{};
    std::size_t o = 0;
    for (std::uint16_t v : {t.epoch_cur, t.deploy_top}) {
        b[o++] = static_cast<std::uint8_t>(v);
        b[o++] = static_cast<std::uint8_t>(v >> 8);
    }
    for (const Hash32* h : {&t.deploy_digest, &t.next_digest})
        for (std::uint8_t x : *h) b[o++] = x;
    return b;
}

// nullopt unless exactly 68 bytes.
inline std::optional<HelloTrailer> decode_hello_trailer(std::span<const std::uint8_t> b) noexcept {
    if (b.size() != kHelloTrailerBytes) return std::nullopt;
    HelloTrailer t;
    t.epoch_cur = static_cast<std::uint16_t>(b[0] | (b[1] << 8));
    t.deploy_top = static_cast<std::uint16_t>(b[2] | (b[3] << 8));
    for (std::size_t i = 0; i < kHashBytes; ++i) {
        t.deploy_digest[i] = b[4 + i];
        t.next_digest[i] = b[4 + kHashBytes + i];
    }
    return t;
}

// Two releases with different descriptors for one epoch: equal epoch_cur and
// deploy_top with another deploy_digest, or two nonzero next_digest that
// differ. A local operator alarm only.
inline bool trailer_alarm(const HelloTrailer& ours, const HelloTrailer& theirs) noexcept {
    const Hash32 zero{};
    const bool deploy = ours.epoch_cur == theirs.epoch_cur && ours.deploy_top == theirs.deploy_top
                        && ours.deploy_digest != theirs.deploy_digest;
    const bool next = ours.next_digest != zero && theirs.next_digest != zero && ours.next_digest != theirs.next_digest;
    return deploy || next;
}

}  // namespace c2pool::xmr::pathb
