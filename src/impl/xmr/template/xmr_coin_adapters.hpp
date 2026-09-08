// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/template/xmr_coin_adapters.hpp
//
// AUTHORED. memcpy shims between the three 32-byte hash spellings that meet at
// the template seam, and the two {lo,hi} 128-bit difficulty spellings:
//
//   c2pool::xmr::hash            { uint8_t h[32] }          (template / p2pool port)
//   xmr::coin::Bytes32 & kin     { std::array<uchar,32> }   (Hash256, PublicKey, SecretKey)
//   c2pool::xmr::node::Hash      std::array<uint8_t,32>     (monerod adapter)
//
//   c2pool::xmr::difficulty_type { lo, hi }                 (template)
//   c2pool::xmr::node::Difficulty128 { lo, hi }             (adapter)
//
// Deliberately generic (any trivially-copyable 32-byte type / any {lo,hi}
// aggregate) so this header pulls in NEITHER coin/ NOR node/ headers -- the
// template tree stays include-light and the consumer picks the concrete types.
// All layouts are the same little-endian byte string Monero puts on the wire;
// the shims are pure copies, never a byte-order change.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <type_traits>

#include "xmr_coin_primitives.hpp"

namespace c2pool::xmr {

template <class T>
concept Bytes32Like = std::is_trivially_copyable_v<T> && (sizeof(T) == HASH_SIZE);

template <class D>
concept DifficultyLike = requires(D d) {
    { d.lo } -> std::convertible_to<uint64_t>;
    { d.hi } -> std::convertible_to<uint64_t>;
};

// ---- 32-byte hashes -----------------------------------------------------------
template <Bytes32Like B>
inline hash to_hash(const B& b) noexcept {
    hash h;
    std::memcpy(h.h, &b, HASH_SIZE);
    return h;
}

inline hash to_hash(const uint8_t* p) noexcept {
    hash h;
    std::memcpy(h.h, p, HASH_SIZE);
    return h;
}

template <Bytes32Like B>
inline B from_hash(const hash& h) noexcept {
    B b{};
    std::memcpy(&b, h.h, HASH_SIZE);
    return b;
}

template <Bytes32Like B>
inline void copy_hash(const hash& h, B& out) noexcept {
    std::memcpy(&out, h.h, HASH_SIZE);
}

// ---- 128-bit difficulty / target ---------------------------------------------
template <DifficultyLike D>
inline difficulty_type to_difficulty(const D& d) noexcept {
    difficulty_type t;
    t.lo = static_cast<uint64_t>(d.lo);
    t.hi = static_cast<uint64_t>(d.hi);
    return t;
}

inline difficulty_type to_difficulty(uint64_t lo, uint64_t hi = 0) noexcept {
    difficulty_type t;
    t.lo = lo;
    t.hi = hi;
    return t;
}

template <DifficultyLike D>
inline D from_difficulty(const difficulty_type& t) noexcept {
    D d{};
    d.lo = t.lo;
    d.hi = t.hi;
    return d;
}

} // namespace c2pool::xmr
