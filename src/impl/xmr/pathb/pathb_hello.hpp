// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_hello.hpp
// Path B FB_HELLO: the tail (S3b-3) and the S4 trailer.
//
//   tail (ruling 31 P-8) = u8 codec (K22 = 2) | LE16 rules_len | rules TLV
//                          | LE128 best_cum_work | best_tip[32] | LE64 best_h
//                          | LE64 mmr_leaf_count
//     the rules block (codec, rules_len, TLV) is pathb_lane_rules.hpp's; a
//     codec byte other than 2 is refused naming K22; the TLV is compared only
//     at equal epoch_cur (hello_rules_compare); best_cum_work, best_tip and
//     best_h are claims; hello_leaf_count_check compares mmr_leaf_count with
//     leaf_count(best_tip) = max(0, H(best_tip) - F - b0 + 1) once the best
//     tip's header is held.
//   The bytes after the tail are not read here.
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

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "impl/xmr/native/contracts/types.hpp"  // U128

#include "pathb_bin_store.hpp"   // bin_leaf_count
#include "pathb_lane_rules.hpp"  // kPathbRulesCodec, kCodecKNumber, rules_block
#include "pathb_params.hpp"      // Hash32, kHashBytes

namespace c2pool::xmr::pathb {

// ---------------------------------------------------------------------------
// The Path B tail
// ---------------------------------------------------------------------------
struct HelloTail {
    std::vector<std::uint8_t> rules;              // the rules block as sent: codec | LE16 rules_len | TLV
    ::c2pool::xmr::native::U128 best_cum_work{};  // claim
    Hash32 best_tip{};                            // claim
    std::uint64_t best_h = 0;                     // claim
    std::uint64_t mmr_leaf_count = 0;             // state

    friend bool operator==(const HelloTail& a, const HelloTail& b) {
        return a.rules == b.rules && a.best_cum_work.lo == b.best_cum_work.lo &&
               a.best_cum_work.hi == b.best_cum_work.hi && a.best_tip == b.best_tip && a.best_h == b.best_h &&
               a.mmr_leaf_count == b.mmr_leaf_count;
    }
};

inline constexpr std::size_t kRulesBlockHeadBytes = kU8Bytes + kU16Bytes;
inline constexpr std::size_t kCumWorkBytes = kU64Bytes + kU64Bytes;
inline constexpr std::size_t kHelloTailStateBytes = kCumWorkBytes + kHashBytes + kU64Bytes + kU64Bytes;
static_assert(kHelloTailStateBytes == 64);

// The tail of a node with lane rules r.
inline HelloTail make_hello_tail(const PathbLaneRules& r, const ::c2pool::xmr::native::U128& best_cum_work,
                                 const Hash32& best_tip, std::uint64_t best_h, std::uint64_t mmr_leaf_count) {
    HelloTail t;
    t.rules = rules_block(r);
    t.best_cum_work = best_cum_work;
    t.best_tip = best_tip;
    t.best_h = best_h;
    t.mmr_leaf_count = mmr_leaf_count;
    return t;
}

// nullopt unless t.rules frames as a rules block (codec 2, LE16 rules_len equal
// to the bytes after it).
inline std::optional<std::vector<std::uint8_t>> encode_hello_tail(const HelloTail& t) {
    if (t.rules.size() < kRulesBlockHeadBytes || t.rules[0] != kPathbRulesCodec) return std::nullopt;
    if (lr_detail::get_le(t.rules.data() + kU8Bytes, kU16Bytes) != t.rules.size() - kRulesBlockHeadBytes)
        return std::nullopt;
    std::vector<std::uint8_t> out = t.rules;
    lr_detail::put_le(out, t.best_cum_work.lo, kU64Bytes);
    lr_detail::put_le(out, t.best_cum_work.hi, kU64Bytes);
    out.insert(out.end(), t.best_tip.begin(), t.best_tip.end());
    lr_detail::put_le(out, t.best_h, kU64Bytes);
    lr_detail::put_le(out, t.mmr_leaf_count, kU64Bytes);
    return out;
}

enum class HelloTailError : std::uint8_t {
    None,
    Truncated,  // fewer bytes than the rules block or the state fields need
    Codec,      // codec byte other than K22 = 2 (names K22)
};

struct HelloTailDecode {
    HelloTailError error = HelloTailError::None;
    std::uint8_t id = 0;       // the field the refusal names (Codec: 22)
    HelloTail tail;
    std::size_t consumed = 0;  // the tail's bytes
};

// Reads the tail from the front of b; `consumed` is its length. The TLV is
// framed, not judged (hello_rules_compare judges it at equal epoch_cur).
inline HelloTailDecode decode_hello_tail(std::span<const std::uint8_t> b) {
    HelloTailDecode d;
    if (b.size() < kRulesBlockHeadBytes) {
        d.error = HelloTailError::Truncated;
        return d;
    }
    if (b[0] != kPathbRulesCodec) {
        d.error = HelloTailError::Codec;
        d.id = kCodecKNumber;
        return d;
    }
    const std::size_t rules_len = static_cast<std::size_t>(lr_detail::get_le(b.data() + kU8Bytes, kU16Bytes));
    const std::size_t block = kRulesBlockHeadBytes + rules_len;
    if (b.size() < block || b.size() - block < kHelloTailStateBytes) {
        d.error = HelloTailError::Truncated;
        return d;
    }
    HelloTail& t = d.tail;
    t.rules.assign(b.begin(), b.begin() + static_cast<std::ptrdiff_t>(block));
    const std::uint8_t* p = b.data() + block;
    t.best_cum_work.lo = lr_detail::get_le(p, kU64Bytes);
    t.best_cum_work.hi = lr_detail::get_le(p + kU64Bytes, kU64Bytes);
    p += kCumWorkBytes;
    std::copy(p, p + kHashBytes, t.best_tip.begin());
    p += kHashBytes;
    t.best_h = lr_detail::get_le(p, kU64Bytes);
    t.mmr_leaf_count = lr_detail::get_le(p + kU64Bytes, kU64Bytes);
    d.consumed = block + kHelloTailStateBytes;
    return d;
}

// mmr_leaf_count against the best tip's header (its record H), when held.
enum class HelloLeafCount : std::uint8_t {
    Equal,
    Pending,   // the best tip's header is not held yet
    Mismatch,  // mmr_leaf_count != leaf_count(best_tip)
};

inline HelloLeafCount hello_leaf_count_check(const HelloTail& t, std::optional<std::uint64_t> best_tip_record,
                                             std::uint64_t b0, std::uint64_t F) {
    if (!best_tip_record) return HelloLeafCount::Pending;
    if (t.mmr_leaf_count != bin_leaf_count(*best_tip_record, b0, F)) return HelloLeafCount::Mismatch;
    return HelloLeafCount::Equal;
}

// ---------------------------------------------------------------------------
// The S4 trailer
// ---------------------------------------------------------------------------
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
