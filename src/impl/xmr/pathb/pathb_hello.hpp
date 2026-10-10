// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_hello.hpp
// Path B FB_HELLO: the head (S4w-a), the tail (S3b-3) and the S4 trailer.
//
//   FB_HELLO (frame version 0x02) = head | tail | node_key[32] | trailer
//   head (53 B) = 0x40 | frame version 0x02 | magic 'C2XR' | u8 network
//                 | u32 chain_id (LE) | pool_id[32] | u64 node_nonce (LE)
//                 | u16 listen_port (LE)
//   node_key    = the S6 node key slot, zero until S6 when sent; carried as
//                 received (its receive rule: TODO(U6), not ruled)
//   483 B at epoch 0 (53 + 330 + 32 + 68). A frame version 0x01 (a pre-Path-B
//   peer, codec 1) is refused naming K22.
//   pathb_hello_check: network, chain_id or pool_id differ -> TAG_MISMATCH;
//   at equal epoch_cur the rules blocks are compared (LANE_RULES_MISMATCH);
//   another epoch_cur is accepted and shown; node_nonce equal: a
//   self-connection; mmr_leaf_count against leaf_count(best_tip) only when
//   the best tip's header is bound at this node: a mismatch closes the link
//   with no strike; the trailer alarm is local. No outcome carries a token.
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
#include <string>
#include <string_view>
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
    Mismatch,  // mmr_leaf_count != leaf_count(best_tip): close the link, no strike (ruling 38)
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

// ---------------------------------------------------------------------------
// The Path B FB_HELLO: head | tail | node key | trailer
// ---------------------------------------------------------------------------
inline constexpr std::uint8_t kHelloOpcode = 0x40;
inline constexpr std::uint8_t kHelloFrameVersion = 0x02;
inline constexpr std::array<std::uint8_t, 4> kHelloMagic{'C', '2', 'X', 'R'};
inline constexpr std::size_t kHelloHeadBytes = kU8Bytes + kU8Bytes + kHelloMagic.size() + kU8Bytes + kU32Bytes
                                               + kHashBytes + kU64Bytes + kU16Bytes;
static_assert(kHelloHeadBytes == 53);
inline constexpr std::size_t kHelloNodeKeyBytes = kHashBytes;

struct PathbHello {
    std::uint8_t network = 0;     // the HELLO network byte (LaneNet)
    std::uint32_t chain_id = 0;
    Hash32 pool_id{};             // the C23 pool_id
    std::uint64_t node_nonce = 0;
    std::uint16_t listen_port = 0;
    HelloTail tail;
    Hash32 node_key{};            // the S6 slot: zero until S6
    HelloTrailer trailer;

    friend bool operator==(const PathbHello&, const PathbHello&) = default;
};

inline std::optional<std::vector<std::uint8_t>> encode_pathb_hello(const PathbHello& h) {
    const std::optional<std::vector<std::uint8_t>> tail = encode_hello_tail(h.tail);
    if (!tail) return std::nullopt;
    std::vector<std::uint8_t> out;
    out.reserve(kHelloHeadBytes + tail->size() + kHelloNodeKeyBytes + kHelloTrailerBytes);
    out.push_back(kHelloOpcode);
    out.push_back(kHelloFrameVersion);
    out.insert(out.end(), kHelloMagic.begin(), kHelloMagic.end());
    out.push_back(h.network);
    lr_detail::put_le(out, h.chain_id, kU32Bytes);
    out.insert(out.end(), h.pool_id.begin(), h.pool_id.end());
    lr_detail::put_le(out, h.node_nonce, kU64Bytes);
    lr_detail::put_le(out, h.listen_port, kU16Bytes);
    out.insert(out.end(), tail->begin(), tail->end());
    out.insert(out.end(), h.node_key.begin(), h.node_key.end());
    const HelloTrailerBytes tr = encode_hello_trailer(h.trailer);
    out.insert(out.end(), tr.begin(), tr.end());
    return out;
}

enum class HelloError : std::uint8_t {
    None,
    Truncated,
    Opcode,
    Version,  // frame version other than 0x02: refused naming K22
    Magic,
    Codec,    // the tail's codec byte other than K22 = 2: refused naming K22
    Trailer,  // the bytes after the node key are not exactly the 68-byte trailer
};

struct PathbHelloDecode {
    HelloError error = HelloError::None;
    std::uint8_t id = 0;  // the K field the refusal names (22 for Version and Codec)
    PathbHello hello;
};

inline PathbHelloDecode decode_pathb_hello(std::span<const std::uint8_t> b) {
    PathbHelloDecode d;
    const auto fail = [&d](HelloError e, std::uint8_t id = 0) {
        d.error = e;
        d.id = id;
        return d;
    };
    if (b.size() < kU8Bytes + kU8Bytes) return fail(HelloError::Truncated);
    if (b[0] != kHelloOpcode) return fail(HelloError::Opcode);
    if (b[1] != kHelloFrameVersion) return fail(HelloError::Version, kCodecKNumber);
    if (b.size() < kHelloHeadBytes) return fail(HelloError::Truncated);
    if (!std::equal(kHelloMagic.begin(), kHelloMagic.end(), b.begin() + 2)) return fail(HelloError::Magic);
    PathbHello& h = d.hello;
    const std::uint8_t* p = b.data() + 2 + kHelloMagic.size();
    h.network = p[0];
    p += kU8Bytes;
    h.chain_id = static_cast<std::uint32_t>(lr_detail::get_le(p, kU32Bytes));
    p += kU32Bytes;
    std::copy(p, p + kHashBytes, h.pool_id.begin());
    p += kHashBytes;
    h.node_nonce = lr_detail::get_le(p, kU64Bytes);
    p += kU64Bytes;
    h.listen_port = static_cast<std::uint16_t>(lr_detail::get_le(p, kU16Bytes));
    const HelloTailDecode td = decode_hello_tail(b.subspan(kHelloHeadBytes));
    if (td.error == HelloTailError::Codec) return fail(HelloError::Codec, kCodecKNumber);
    if (td.error != HelloTailError::None) return fail(HelloError::Truncated);
    h.tail = td.tail;
    const std::size_t at = kHelloHeadBytes + td.consumed;
    if (b.size() - at < kHelloNodeKeyBytes) return fail(HelloError::Truncated);
    // TODO(U6): the receive rule of the S6 node-key slot is not ruled (card U6). The slot is carried as
    // received; no verdict, refusal or strike reads its content.
    std::copy(b.begin() + at, b.begin() + at + kHelloNodeKeyBytes, h.node_key.begin());
    const std::optional<HelloTrailer> tr = decode_hello_trailer(b.subspan(at + kHelloNodeKeyBytes));
    if (!tr) return fail(HelloError::Trailer);
    h.trailer = *tr;
    return d;
}

// The receive check of a decoded Path B HELLO against the node's own.
enum class HelloVerdict : std::uint8_t {
    Accept,
    Refuse,          // TAG_MISMATCH or LANE_RULES_MISMATCH (no strike)
    Close,           // mmr_leaf_count != leaf_count(best_tip) on a bound best tip (no strike)
    SelfConnection,  // node_nonce equal
};

enum class HelloReason : std::uint8_t { None, K22, Malformed, Network, ChainId, PoolId, LaneRules, LeafCount, SelfConnection };

inline constexpr std::string_view kTagMismatchText = "TAG_MISMATCH";

struct HelloCheck {
    HelloVerdict verdict = HelloVerdict::Accept;
    HelloReason reason = HelloReason::None;
    std::uint8_t id = 0;            // LaneRules: the K field
    std::string text;
    bool trailer_alarm = false;     // a local operator alarm only
    bool other_epoch = false;       // another epoch_cur: accepted and shown, not compared
    std::uint32_t strike = 0;       // always 0
};

// node_key is not read here (TODO(U6): its receive rule is not ruled).
// bound_best_record: H(best_tip) when best_tip's header is bound at this node
// (its own S1.3 #9 matched); nullopt otherwise (no leaf-count comparison).
inline HelloCheck pathb_hello_check(const PathbHello& ours, const PathbHello& theirs,
                                    std::optional<std::uint64_t> bound_best_record, std::uint64_t b0,
                                    std::uint64_t F) {
    HelloCheck c;
    const auto refuse = [&c](HelloReason r, std::string text) {
        c.verdict = HelloVerdict::Refuse;
        c.reason = r;
        c.text = std::move(text);
        return c;
    };
    c.trailer_alarm = trailer_alarm(ours.trailer, theirs.trailer);
    if (theirs.network != ours.network)
        return refuse(HelloReason::Network, std::string(kTagMismatchText) + " field=network ours=" +
                                                    std::to_string(ours.network) + " theirs=" +
                                                    std::to_string(theirs.network));
    if (theirs.chain_id != ours.chain_id)
        return refuse(HelloReason::ChainId, std::string(kTagMismatchText) + " field=chain_id ours=" +
                                                    std::to_string(ours.chain_id) + " theirs=" +
                                                    std::to_string(theirs.chain_id));
    if (theirs.pool_id != ours.pool_id)
        return refuse(HelloReason::PoolId, std::string(kTagMismatchText) + " field=pool_id ours=" +
                                                   lr_detail::hex(ours.pool_id.data(), kHashBytes) + " theirs=" +
                                                   lr_detail::hex(theirs.pool_id.data(), kHashBytes));
    c.other_epoch = ours.trailer.epoch_cur != theirs.trailer.epoch_cur;
    const LaneRulesCompare rc =
            hello_rules_compare(ours.trailer.epoch_cur, ours.tail.rules, theirs.trailer.epoch_cur, theirs.tail.rules);
    if (rc.verdict != LaneRulesVerdict::Equal) {
        HelloCheck r = refuse(HelloReason::LaneRules, rc.text);
        r.id = rc.id;
        return r;
    }
    if (theirs.node_nonce == ours.node_nonce) {
        c.verdict = HelloVerdict::SelfConnection;
        c.reason = HelloReason::SelfConnection;
        c.text = "self-connection (node_nonce equal)";
        return c;
    }
    if (hello_leaf_count_check(theirs.tail, bound_best_record, b0, F) == HelloLeafCount::Mismatch) {
        c.verdict = HelloVerdict::Close;
        c.reason = HelloReason::LeafCount;
        c.text = "mmr_leaf_count " + std::to_string(theirs.tail.mmr_leaf_count) + " != leaf_count(best_tip)";
        return c;
    }
    return c;
}

// A received HELLO frame, in order: the frame version (0x01: refused naming
// K22), the network, the codec byte (refused naming K22), then
// pathb_hello_check. `bound_best_record` is asked for the peer's best tip
// once the frame decodes (nullopt: not bound at this node).
template <class BoundRecord>
inline HelloCheck pathb_hello_receive(const PathbHello& ours, std::span<const std::uint8_t> frame,
                                      BoundRecord&& bound_best_record, std::uint64_t b0, std::uint64_t F,
                                      PathbHello* decoded = nullptr) {
    HelloCheck c;
    const auto refuse = [&c](HelloReason r, std::string text) {
        c.verdict = HelloVerdict::Refuse;
        c.reason = r;
        c.text = std::move(text);
        return c;
    };
    const PathbHelloDecode d = decode_pathb_hello(frame);
    if (d.error == HelloError::Version)
        return refuse(HelloReason::K22, std::string(kLaneRulesMismatchText) + " refused field=K22 (frame version " +
                                                std::to_string(frame[1]) + ")");
    if (d.error != HelloError::None && d.error != HelloError::Codec) return refuse(HelloReason::Malformed, "hello: malformed");
    if (d.hello.network != ours.network)
        return refuse(HelloReason::Network, std::string(kTagMismatchText) + " field=network ours=" +
                                                    std::to_string(ours.network) + " theirs=" +
                                                    std::to_string(d.hello.network));
    if (d.error == HelloError::Codec)
        return refuse(HelloReason::K22, std::string(kLaneRulesMismatchText) + " refused field=K22");
    if (decoded) *decoded = d.hello;
    return pathb_hello_check(ours, d.hello, bound_best_record(d.hello.tail.best_tip), b0, F);
}

}  // namespace c2pool::xmr::pathb
