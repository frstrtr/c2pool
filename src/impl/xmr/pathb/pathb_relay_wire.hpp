// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_relay_wire.hpp
// Path B relay frames: family C (FC_CARRIER, FC_GETCARRIER, FC_GETHEADERS,
// FC_HEADERS) and FB_RECEIPTS with v3 bodies (S1.2; C-FH).
//
//   FH = u8 opcode | u8 frame version | u32 chain_id (LE), 6 B
//   frame version = the layout number of its own opcode:
//     0x40 FB_HELLO, 0x41 FB_RECEIPTS, 0x53 FC_HEADERS          0x02
//     0x50-0x52, 0x54, 0x55 and the kept 0x43 / 0x44, 0x48 / 0x49,
//     0x4c / 0x4d                                                0x01
//
//   0x50 FC_CARRIER     FH | carrier body (u8 ver 3 | own body | u8 n_carried
//                       | carried bodies); a frame above the frame buffer
//                       (P-11) is DROPPED before parsing; the body is
//                       admission's (pathb_admit.hpp)
//   0x51 FC_GETCARRIER  FH | u8 n | n x id[32] | u8 want_bodies (0 or 1);
//                       n <= 1 + R_MAX = 17
//   0x52 FC_GETHEADERS  FH | from[32] | stop[32] | u16 max
//   0x53 FC_HEADERS     FH | u64 first_pos | u16 n | n x header
//                       header = u8 ver 3 | own body | u8 n_carried
//                       | u128 cum_work_claim (LE); n_carried <= R_MAX
//   0x41 FB_RECEIPTS    FH | u8 n | n x v3 receipt body (no length prefix);
//                       1 <= n <= 1 + R_MAX
//
// Decoders: a count is checked against its limit before anything is
// allocated; trailing bytes refuse; a frame above its buffer is OverBuffer
// (DROP, no verdict). Encoders refuse what the decoders refuse.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "impl/xmr/native/contracts/types.hpp"  // U128

#include "pathb_bucket_wire.hpp"   // kOpFcGetBuckets, kOpFcBuckets, kFcFrameVersion
#include "pathb_caps.hpp"          // RelayBuffers
#include "pathb_header_index.hpp"  // CarrierHeader, header_bytes
#include "pathb_params.hpp"
#include "pathb_wire_v3.hpp"

namespace c2pool::xmr::pathb {

// ---------------------------------------------------------------------------
// Opcodes and frame versions
// ---------------------------------------------------------------------------
inline constexpr std::uint8_t kOpFbHello = 0x40;
inline constexpr std::uint8_t kOpFbReceipts = 0x41;
inline constexpr std::uint8_t kOpFbGetCtx = 0x43;
inline constexpr std::uint8_t kOpFbCtx = 0x44;
inline constexpr std::uint8_t kOpFbPing = 0x48;
inline constexpr std::uint8_t kOpFbPong = 0x49;
inline constexpr std::uint8_t kOpFbGetAddr = 0x4c;
inline constexpr std::uint8_t kOpFbAddr = 0x4d;
inline constexpr std::uint8_t kOpFcCarrier = 0x50;
inline constexpr std::uint8_t kOpFcGetCarrier = 0x51;
inline constexpr std::uint8_t kOpFcGetHeaders = 0x52;
inline constexpr std::uint8_t kOpFcHeaders = 0x53;

inline constexpr std::uint8_t kFrameVersion1 = 0x01;
inline constexpr std::uint8_t kFrameVersion2 = 0x02;

// The frame version of an opcode's layout; nullopt for an opcode not in this table.
inline constexpr std::optional<std::uint8_t> frame_version_of(std::uint8_t op) noexcept {
    switch (op) {
        case kOpFbHello:
        case kOpFbReceipts:
        case kOpFcHeaders: return kFrameVersion2;
        case kOpFbGetCtx:
        case kOpFbCtx:
        case kOpFbPing:
        case kOpFbPong:
        case kOpFbGetAddr:
        case kOpFbAddr:
        case kOpFcCarrier:
        case kOpFcGetCarrier:
        case kOpFcGetHeaders:
        case kOpFcGetBuckets:
        case kOpFcBuckets: return kFrameVersion1;
        default: break;
    }
    return std::nullopt;
}

static_assert(frame_version_of(kOpFcGetBuckets) == kFcFrameVersion && frame_version_of(kOpFcBuckets) == kFcFrameVersion,
              "0x54 / 0x55 at the version of pathb_bucket_wire.hpp");

// FC_GETCARRIER ids and FB_RECEIPTS bodies per frame: 1 + R_MAX.
inline constexpr std::uint64_t fc_ids_max(const LaneParams& p) noexcept { return max_receipts_per_frame(p.r_max); }

inline constexpr std::size_t kGetHeadersFrameBytes = kFrameHeaderBytes + kHashBytes + kHashBytes + kU16Bytes;
static_assert(kGetHeadersFrameBytes == 72);
inline constexpr std::size_t kHeadersFrameHeadBytes = kFrameHeaderBytes + kU64Bytes + kU16Bytes;
static_assert(kHeadersFrameHeadBytes == 16);
inline constexpr std::size_t kCumWorkClaimBytes = kU64Bytes + kU64Bytes;
inline constexpr std::size_t kHeadersMax = UINT16_MAX;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------
enum class FrameWireError : std::uint8_t {
    None,
    OverBuffer,  // longer than the frame's buffer: DROP, no verdict
    Truncated,
    Trailing,
    Opcode,      // not this frame's opcode
    Version,     // not the frame version of this opcode
    ChainId,     // not the lane's chain_id
    Count,       // a count outside its range
    Flag,        // want_bodies other than 0 / 1
    Body,        // a receipt or header body does not decode (body_error)
};

struct FrameDecode {
    FrameWireError error = FrameWireError::None;
    WireError body_error = WireError::None;  // Body: the receipt codec's word
    bool ok() const noexcept { return error == FrameWireError::None; }
};

namespace rw_detail {

inline void put_fh(std::vector<std::uint8_t>& out, std::uint8_t op, std::uint32_t chain_id) {
    out.push_back(op);
    out.push_back(frame_version_of(op).value_or(0));
    detail::put_le(out, chain_id);
}

inline FrameWireError read_fh(BlobReader& r, std::uint8_t op, std::uint32_t chain_id) {
    std::uint8_t o = 0, v = 0;
    std::uint32_t c = 0;
    if (!r.read_byte(o) || !r.read_byte(v) || !detail::get_le(r, c)) return FrameWireError::Truncated;
    if (o != op) return FrameWireError::Opcode;
    if (v != frame_version_of(op)) return FrameWireError::Version;
    if (c != chain_id) return FrameWireError::ChainId;
    return FrameWireError::None;
}

inline FrameDecode fail(FrameWireError e, WireError b = WireError::None) { return FrameDecode{e, b}; }

}  // namespace rw_detail

// ---------------------------------------------------------------------------
// The carrier header (FC_HEADERS): u8 ver | own body | u8 n_carried | LE128
// ---------------------------------------------------------------------------
inline WireError read_carrier_header(BlobReader& r, std::uint64_t r_max, CarrierHeader& out) {
    std::uint8_t ver = 0;
    if (!r.read_byte(ver)) return WireError::Truncated;
    if (ver != kCarrierBodyVersion) return WireError::Version;
    CarrierHeader h;
    if (WireError e = read_receipt_body_v3(r, h.own); e != WireError::None) return e;
    if (!r.read_byte(h.n_carried)) return WireError::Truncated;
    if (h.n_carried > r_max) return WireError::CarriedCount;
    if (!detail::get_le(r, h.cum_work_claim.lo) || !detail::get_le(r, h.cum_work_claim.hi)) return WireError::Truncated;
    out = std::move(h);
    return WireError::None;
}

// ---------------------------------------------------------------------------
// FC_CARRIER
// ---------------------------------------------------------------------------
inline std::optional<std::vector<std::uint8_t>> encode_fc_carrier(std::uint32_t chain_id, const CarrierBodyV3& c,
                                                                  std::uint64_t r_max) {
    std::vector<std::uint8_t> out;
    rw_detail::put_fh(out, kOpFcCarrier, chain_id);
    if (encode_carrier_body_v3(c, r_max, out) != WireError::None) return std::nullopt;
    return out;
}

// The FH of an FC_CARRIER frame, the frame buffer (P-11) first. The body is
// admitted by admit_carrier on the same bytes.
inline FrameDecode check_fc_carrier(std::span<const std::uint8_t> f, std::uint32_t chain_id, const RelayBuffers& b) {
    if (f.size() > b.frame) return rw_detail::fail(FrameWireError::OverBuffer);
    BlobReader r(f.data(), f.size());
    if (const FrameWireError e = rw_detail::read_fh(r, kOpFcCarrier, chain_id); e != FrameWireError::None)
        return rw_detail::fail(e);
    return {};
}

// ---------------------------------------------------------------------------
// FC_GETCARRIER
// ---------------------------------------------------------------------------
struct GetCarrier {
    std::uint32_t chain_id = 0;
    std::vector<Hash32> ids;
    bool want_bodies = false;

    friend bool operator==(const GetCarrier&, const GetCarrier&) = default;
};

inline std::optional<std::vector<std::uint8_t>> encode_fc_getcarrier(const GetCarrier& q, const LaneParams& p) {
    if (q.ids.empty() || q.ids.size() > fc_ids_max(p)) return std::nullopt;
    std::vector<std::uint8_t> out;
    rw_detail::put_fh(out, kOpFcGetCarrier, q.chain_id);
    out.push_back(static_cast<std::uint8_t>(q.ids.size()));
    for (const Hash32& id : q.ids) detail::put_hash(out, id);
    out.push_back(q.want_bodies ? 1 : 0);
    return out;
}

inline FrameDecode decode_fc_getcarrier(std::span<const std::uint8_t> f, std::uint32_t chain_id, const LaneParams& p,
                                        GetCarrier& out) {
    BlobReader r(f.data(), f.size());
    if (const FrameWireError e = rw_detail::read_fh(r, kOpFcGetCarrier, chain_id); e != FrameWireError::None)
        return rw_detail::fail(e);
    std::uint8_t n = 0;
    if (!r.read_byte(n)) return rw_detail::fail(FrameWireError::Truncated);
    if (n == 0 || n > fc_ids_max(p)) return rw_detail::fail(FrameWireError::Count);
    if (r.remaining() / kHashBytes < n) return rw_detail::fail(FrameWireError::Truncated);
    GetCarrier q;
    q.chain_id = chain_id;
    q.ids.resize(n);
    for (Hash32& id : q.ids) detail::get_hash(r, id);
    std::uint8_t wb = 0;
    if (!r.read_byte(wb)) return rw_detail::fail(FrameWireError::Truncated);
    if (wb > 1) return rw_detail::fail(FrameWireError::Flag);
    if (r.remaining() != 0) return rw_detail::fail(FrameWireError::Trailing);
    q.want_bodies = wb == 1;
    out = std::move(q);
    return {};
}

// ---------------------------------------------------------------------------
// FC_GETHEADERS
// ---------------------------------------------------------------------------
struct GetHeaders {
    std::uint32_t chain_id = 0;
    Hash32 from{};
    Hash32 stop{};
    std::uint16_t max = 0;

    friend bool operator==(const GetHeaders&, const GetHeaders&) = default;
};

inline std::vector<std::uint8_t> encode_fc_getheaders(const GetHeaders& q) {
    std::vector<std::uint8_t> out;
    out.reserve(kGetHeadersFrameBytes);
    rw_detail::put_fh(out, kOpFcGetHeaders, q.chain_id);
    detail::put_hash(out, q.from);
    detail::put_hash(out, q.stop);
    detail::put_le(out, q.max);
    return out;
}

inline FrameDecode decode_fc_getheaders(std::span<const std::uint8_t> f, std::uint32_t chain_id, GetHeaders& out) {
    BlobReader r(f.data(), f.size());
    if (const FrameWireError e = rw_detail::read_fh(r, kOpFcGetHeaders, chain_id); e != FrameWireError::None)
        return rw_detail::fail(e);
    GetHeaders q;
    q.chain_id = chain_id;
    if (!detail::get_hash(r, q.from) || !detail::get_hash(r, q.stop) || !detail::get_le(r, q.max))
        return rw_detail::fail(FrameWireError::Truncated);
    if (r.remaining() != 0) return rw_detail::fail(FrameWireError::Trailing);
    out = q;
    return {};
}

// ---------------------------------------------------------------------------
// FC_HEADERS (frame version 0x02): u64 first_pos | u16 n | n x header
// ---------------------------------------------------------------------------
struct HeadersReply {
    std::uint32_t chain_id = 0;
    std::uint64_t first_pos = 0;  // the claimed position of the first header
    std::vector<CarrierHeader> headers;

    friend bool operator==(const HeadersReply&, const HeadersReply&) = default;
};

// The frame of r with as many of its headers as fit in frame_bytes (in order);
// `packed` = the headers it holds. nullopt: a header that does not encode.
inline std::optional<std::vector<std::uint8_t>> encode_fc_headers(const HeadersReply& r, std::uint64_t frame_bytes,
                                                                  std::size_t* packed = nullptr) {
    std::vector<std::uint8_t> body;
    std::size_t n = 0;
    std::uint64_t size = kHeadersFrameHeadBytes;
    for (const CarrierHeader& h : r.headers) {
        if (n == kHeadersMax) break;
        const std::optional<std::vector<std::uint8_t>> hb = header_bytes(h);
        if (!hb) return std::nullopt;
        if (size + hb->size() > frame_bytes) break;
        size += hb->size();
        body.insert(body.end(), hb->begin(), hb->end());
        ++n;
    }
    std::vector<std::uint8_t> out;
    out.reserve(kHeadersFrameHeadBytes + body.size());
    rw_detail::put_fh(out, kOpFcHeaders, r.chain_id);
    detail::put_le(out, r.first_pos);
    detail::put_le(out, static_cast<std::uint16_t>(n));
    out.insert(out.end(), body.begin(), body.end());
    if (packed) *packed = n;
    return out;
}

inline FrameDecode decode_fc_headers(std::span<const std::uint8_t> f, std::uint32_t chain_id, std::uint64_t frame_bytes,
                                     const LaneParams& p, HeadersReply& out) {
    if (f.size() > frame_bytes) return rw_detail::fail(FrameWireError::OverBuffer);
    BlobReader r(f.data(), f.size());
    if (const FrameWireError e = rw_detail::read_fh(r, kOpFcHeaders, chain_id); e != FrameWireError::None)
        return rw_detail::fail(e);
    HeadersReply q;
    q.chain_id = chain_id;
    std::uint16_t n = 0;
    if (!detail::get_le(r, q.first_pos) || !detail::get_le(r, n)) return rw_detail::fail(FrameWireError::Truncated);
    for (std::size_t i = 0; i < n; ++i) {
        CarrierHeader h;
        if (const WireError e = read_carrier_header(r, p.r_max, h); e != WireError::None)
            return rw_detail::fail(FrameWireError::Body, e);
        q.headers.push_back(std::move(h));
    }
    if (r.remaining() != 0) return rw_detail::fail(FrameWireError::Trailing);
    out = std::move(q);
    return {};
}

// ---------------------------------------------------------------------------
// FB_RECEIPTS (frame version 0x02): u8 n | n x v3 body
// ---------------------------------------------------------------------------
inline std::optional<std::vector<std::uint8_t>> encode_fb_receipts(std::uint32_t chain_id,
                                                                   const std::vector<ReceiptBodyV3>& bodies,
                                                                   const LaneParams& p) {
    if (bodies.empty() || bodies.size() > fc_ids_max(p)) return std::nullopt;
    std::vector<std::uint8_t> out;
    rw_detail::put_fh(out, kOpFbReceipts, chain_id);
    out.push_back(static_cast<std::uint8_t>(bodies.size()));
    for (const ReceiptBodyV3& b : bodies)
        if (encode_receipt_body_v3(b, out) != WireError::None) return std::nullopt;
    return out;
}

// The bodies of an FB_RECEIPTS frame as received (each its own bytes, each
// within the receipt buffer P-10); the frame buffer P-11 first.
struct ReceiptsFrame {
    std::uint32_t chain_id = 0;
    std::vector<std::vector<std::uint8_t>> bodies;
};

inline FrameDecode decode_fb_receipts(std::span<const std::uint8_t> f, std::uint32_t chain_id, const RelayBuffers& b,
                                      const LaneParams& p, ReceiptsFrame& out) {
    if (f.size() > b.frame) return rw_detail::fail(FrameWireError::OverBuffer);
    BlobReader r(f.data(), f.size());
    if (const FrameWireError e = rw_detail::read_fh(r, kOpFbReceipts, chain_id); e != FrameWireError::None)
        return rw_detail::fail(e);
    std::uint8_t n = 0;
    if (!r.read_byte(n)) return rw_detail::fail(FrameWireError::Truncated);
    if (n == 0 || n > fc_ids_max(p)) return rw_detail::fail(FrameWireError::Count);
    ReceiptsFrame q;
    q.chain_id = chain_id;
    for (std::size_t i = 0; i < n; ++i) {
        const std::size_t before = r.remaining();
        const std::uint8_t* start = f.data() + (f.size() - before);
        ReceiptBodyV3 body;
        if (const WireError e = read_receipt_body_v3(r, body); e != WireError::None)
            return rw_detail::fail(FrameWireError::Body, e);
        const std::size_t len = before - r.remaining();
        if (len > b.receipt) return rw_detail::fail(FrameWireError::OverBuffer);
        q.bodies.emplace_back(start, start + len);
    }
    if (r.remaining() != 0) return rw_detail::fail(FrameWireError::Trailing);
    out = std::move(q);
    return {};
}

}  // namespace c2pool::xmr::pathb
