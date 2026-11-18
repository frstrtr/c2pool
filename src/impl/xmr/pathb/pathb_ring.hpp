// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_ring.hpp
// Path B roundabouts, slice C-2: the ring key and the partition.
//
//   ring_key(X)   = sha256d(TAG || binding bytes || X); X = the 32-byte payee
//                   identity (WinEntry.miner, BucketRow.miner, side.payee).
//                   TAG: its raw bytes, no NUL, no length. ChainIdLe32: chain_id
//                   as 4 bytes little-endian. Another binding encoding is a new
//                   enumerator.
//   ring_of(k, d) = {d, the first d bits of k}, byte 0 first, most significant
//                   bit first; d = 0 -> {0, 0}, no byte read; 0 <= d <= 7.
//   parent        = {d - 1, j >> 1};  child(r, bit) = {d + 1, 2j + bit}.
//   Membership    MinerPayee: the ring of an entry, a sealed row or a receipt is
//                 the ring of its miner payee (owner and author shares stay with
//                 it). None: every depth is 0.
//   ring_of_entry, ring_of_row and ring_of_payee share one body. At depth 0 it
//   computes no key. A refusal (nullopt): depth above kRingDepthBound, the parent
//   of {0, 0}, a child at kRingDepthBound, an invalid ring id, membership other
//   than MinerPayee at depth > 0, an empty tag, an unset binding.
//   The ruled rule (ruling 70): tag "V37RB", ChainIdLe32, MinerPayee.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>
#include <vector>

#include "pathb_buckets.hpp"  // BucketRow, sha256d_bytes
#include "pathb_params.hpp"   // Hash32
#include "pathb_window.hpp"   // RingId, WinEntry

namespace c2pool::xmr::pathb {

// The binding's bytes are part of the enumerator.
enum class RingBinding : std::uint8_t { Unset, ChainIdLe32 };

enum class Membership : std::uint8_t { Unset, None, MinerPayee };

struct RingKeyRule {
    std::vector<std::uint8_t> tag;  // empty = unset
    RingBinding binding = RingBinding::Unset;
    Membership membership = Membership::Unset;
};

struct RingBindingValue {
    std::uint32_t chain_id = 0;  // the lane's chain_id (StartupInputs.chain_id)
};

inline constexpr std::size_t kRingBitsPerByte = std::numeric_limits<std::uint8_t>::digits;

// The deepest ring: K17 is one u8 and K = 2^depth.
inline constexpr std::uint8_t kRingDepthBound = std::numeric_limits<std::uint8_t>::digits - 1;
static_assert(kRingDepthBound < kRingBitsPerByte, "a ring id reads key byte 0 only; its index fits a u8");

// The ruled rule (ruling 70).
inline constexpr std::string_view kRingTagRuled{"V37RB"};

inline RingKeyRule ruled_ring_key_rule() {
    RingKeyRule r;
    r.tag.assign(kRingTagRuled.begin(), kRingTagRuled.end());
    r.binding = RingBinding::ChainIdLe32;
    r.membership = Membership::MinerPayee;
    return r;
}

namespace detail_ring {
// Keys computed by ring_key on this thread (output only).
inline thread_local std::uint64_t g_key_digests = 0;
}  // namespace detail_ring

inline std::uint64_t ring_key_digests() { return detail_ring::g_key_digests; }

// TAG || binding bytes || X; nullopt for an empty tag or an unset binding.
inline std::optional<std::vector<std::uint8_t>> ring_key_preimage(const RingKeyRule& rule,
                                                                  const RingBindingValue& value, const Hash32& x) {
    if (rule.tag.empty()) return std::nullopt;
    std::vector<std::uint8_t> pre(rule.tag);
    switch (rule.binding) {
        case RingBinding::ChainIdLe32:
            for (std::size_t i = 0; i < sizeof(value.chain_id); ++i)
                pre.push_back(static_cast<std::uint8_t>(value.chain_id >> (kRingBitsPerByte * i)));
            break;
        case RingBinding::Unset:
        default:
            return std::nullopt;
    }
    pre.insert(pre.end(), x.begin(), x.end());
    return pre;
}

inline std::optional<Hash32> ring_key(const RingKeyRule& rule, const RingBindingValue& value, const Hash32& x) {
    const std::optional<std::vector<std::uint8_t>> pre = ring_key_preimage(rule, value, x);
    if (!pre) return std::nullopt;
    ++detail_ring::g_key_digests;
    return sha256d_bytes(*pre);
}

// depth <= kRingDepthBound and index < 2^depth.
inline bool ring_valid(RingId r) {
    return r.depth <= kRingDepthBound && (std::size_t{r.index} >> r.depth) == 0;
}

inline std::optional<RingId> ring_of(const Hash32& key, std::uint8_t depth) {
    if (depth > kRingDepthBound) return std::nullopt;
    std::size_t index = 0;
    for (std::size_t i = 0; i < depth; ++i) {
        const std::size_t bit = (key[i / kRingBitsPerByte] >> (kRingBitsPerByte - 1 - i % kRingBitsPerByte)) & 1u;
        index = (index << 1) | bit;
    }
    return RingId{depth, static_cast<std::uint8_t>(index)};
}

inline std::optional<RingId> parent(RingId r) {
    if (!ring_valid(r) || r.depth == 0) return std::nullopt;
    return RingId{static_cast<std::uint8_t>(r.depth - 1), static_cast<std::uint8_t>(r.index >> 1)};
}

inline std::optional<RingId> child(RingId r, bool one) {
    if (!ring_valid(r) || r.depth >= kRingDepthBound) return std::nullopt;
    return RingId{static_cast<std::uint8_t>(r.depth + 1), static_cast<std::uint8_t>((r.index << 1) | (one ? 1u : 0u))};
}

namespace detail_ring {
// The one ring function: the ring of the miner payee `miner` at `depth`.
inline std::optional<RingId> ring_of_miner(const RingKeyRule& rule, const RingBindingValue& value,
                                           const Hash32& miner, std::uint8_t depth) {
    if (depth == 0) return RingId{};
    if (depth > kRingDepthBound) return std::nullopt;
    if (rule.membership != Membership::MinerPayee) return std::nullopt;
    const std::optional<Hash32> key = ring_key(rule, value, miner);
    if (!key) return std::nullopt;
    return ring_of(*key, depth);
}
}  // namespace detail_ring

inline std::optional<RingId> ring_of_entry(const RingKeyRule& rule, const RingBindingValue& value, const WinEntry& e,
                                           std::uint8_t depth) {
    return detail_ring::ring_of_miner(rule, value, e.miner, depth);
}

inline std::optional<RingId> ring_of_row(const RingKeyRule& rule, const RingBindingValue& value, const BucketRow& r,
                                         std::uint8_t depth) {
    return detail_ring::ring_of_miner(rule, value, r.miner, depth);
}

// payee: the receipt's side.payee.
inline std::optional<RingId> ring_of_payee(const RingKeyRule& rule, const RingBindingValue& value,
                                           const Hash32& payee, std::uint8_t depth) {
    return detail_ring::ring_of_miner(rule, value, payee, depth);
}

}  // namespace c2pool::xmr::pathb
