// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_wire_v3.hpp
// Path B wire formats, version 3: side_data_v3, the receipt body and the
// carrier body. Little-endian fixed-width integers; CryptoNote varints inside
// the Monero hashing blob.
//
// side_data_v3 (241 B):
//   off   0  u8   version = 3
//   off   1  32   pool_id
//   off  33  u16  rules_epoch
//   off  35  u16  ballot: own flag (bit 15) | epoch_no (bits 0..14)
//   off  37  32   payee identity
//   off  69  u64  t_origin
//   off  77  32   tip
//   off 109  32   receipts_root (pathb_ratchet_state.hpp: the carry fold)
//   off 141  32   window_root
//   off 173  32   mmr_root
//   off 205  u16  fee_rate p (basis points, 0..10000)
//   off 207  32   owner identity (zero iff p == 0)
//   off 239  u16  give_author_bp (0..10000)
//   mm_root = keccak256("c2pool-v37-xmr-side-v3" || side_data_v3)
//
// receipt body:
//   u8 blob_len (<= 78) | hashing_blob[blob_len] | extra_nonce[4] | u8 depth D
//   | branch[32 x D] | side_data_v3[241] | payee_ref[66] | owner_ref[66] iff p > 0
//   | u64 reward_total
//   hashing_blob = varint major (1 B max) | varint minor (1 B max)
//                | varint timestamp (5 B max) | prev_id[32] | nonce u32
//                | tree_root[32] | varint tx_count (3 B max)
//   key ref = u8 kind (XMR_STD) | u8 len (64) | spend[32] | view[32],
//             spend and view decompress as ed25519 points
//   RECEIPT_MAX(D) = 465 + 32 D
//
// carrier body:
//   u8 ver = 3 | receipt body (own) | u8 n_carried (<= R_MAX)
//   | n_carried x receipt body
//   (no length prefix on a receipt body; blob_len, D and p delimit it)
//
// carrier frame:
//   FH | carrier body
//   FH = u8 opcode | u8 frame version | u32 chain_id
//        (the frame header of src/c2pool/v37/xmr/relay/xmr_relay_wire.hpp)
//   frame_size(receipt bytes) = FH + 1 + 1 + (1 + R_MAX) x receipt bytes
//   (the I/O buffers and the consensus caps of pathb_caps.hpp)
//
// Decoder outcomes:
//   OverCap   the input is longer than the I/O buffer of the given limits
//             (receipt buffer, carrier_body_size at the receipt buffer);
//             checked before parsing; the object is dropped without a
//             verdict.
//   any other error: the bytes are refused (truncation, trailing bytes, a
//             field outside its width or range, a count above its limit
//             before any allocation, a non-canonical varint).
// A body is accepted only when its length equals the sum of its fields for its
// own D and p. The depth and the consensus cap are judged against the
// receipt's Monero branch (pathb_caps.hpp), not against the buffer.
// Encoders refuse a value the decoder would refuse, so decode(encode(x)) == x
// and encode(decode(b)) == b for every accepted b.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "impl/xmr/coin/xmr_keccak_midstate.hpp"           // ::xmr::coin::keccak256
extern "C" {
#include "vendor/crypto-ops.h"                             // ge_frombytes_vartime (xmr_coin)
}
#include "impl/xmr/native/consensus/xmr_blob_reader.hpp"   // BlobReader (monerod varint rules)
#include "sharechain/v37/v37_descriptor_xmr.hpp"           // XMR_STD, XMR_PAYLOAD_LEN, xmr_identity_key

#include "pathb_params.hpp"

namespace c2pool::xmr::pathb {

using ::c2pool::xmr::native::BlobReader;

// ---------------------------------------------------------------------------
// Field widths
// ---------------------------------------------------------------------------
inline constexpr std::size_t kU8Bytes = sizeof(std::uint8_t);
inline constexpr std::size_t kU16Bytes = sizeof(std::uint16_t);
inline constexpr std::size_t kU32Bytes = sizeof(std::uint32_t);
inline constexpr std::size_t kU64Bytes = sizeof(std::uint64_t);

// Coinbase extra nonce (the TX_EXTRA_NONCE payload) and the header nonce.
inline constexpr std::size_t kExtraNonceBytes = kU32Bytes;
inline constexpr std::size_t kHeaderNonceBytes = kU32Bytes;

// Declared varint widths of the hashing-blob fields (bytes).
inline constexpr std::size_t kMajorVarintMax = 1;
inline constexpr std::size_t kMinorVarintMax = 1;
inline constexpr std::size_t kTimestampVarintMax = 5;
inline constexpr std::size_t kTxCountVarintMax = 3;

// HDR_max: major, minor, timestamp, prev_id, nonce.
inline constexpr std::size_t kHashingHeaderMaxBytes =
        kMajorVarintMax + kMinorVarintMax + kTimestampVarintMax + kHashBytes + kHeaderNonceBytes;
// Hashing blob: HDR_max + tree_root + tx_count.
inline constexpr std::size_t kHashingBlobMaxBytes = kHashingHeaderMaxBytes + kHashBytes + kTxCountVarintMax;
// Smallest hashing blob: every varint one byte.
inline constexpr std::size_t kHashingBlobMinBytes = varint_len(0) + varint_len(0) + varint_len(0) + kHashBytes
                                                    + kHeaderNonceBytes + kHashBytes + varint_len(0);

static_assert(kHashingBlobMaxBytes <= UINT8_MAX, "blob_len is a u8");

// Key reference: kind, len, payload (spend || view).
inline constexpr std::size_t kKeyRefPayloadBytes = ::v37::xmr::XMR_PAYLOAD_LEN;
inline constexpr std::size_t kKeyRefBytes = kU8Bytes + kU8Bytes + kKeyRefPayloadBytes;
static_assert(kKeyRefPayloadBytes == 2 * kHashBytes, "payload = spend || view");
static_assert(kKeyRefPayloadBytes <= UINT8_MAX, "len is a u8");

inline constexpr std::uint8_t kPayeeKindXmrStd = static_cast<std::uint8_t>(::v37::xmr::XMR_STD);

// ---------------------------------------------------------------------------
// side_data_v3
// ---------------------------------------------------------------------------
namespace side_v3 {
inline constexpr std::size_t kVersionOff = 0;
inline constexpr std::size_t kPoolIdOff = kVersionOff + kU8Bytes;
inline constexpr std::size_t kRulesEpochOff = kPoolIdOff + kHashBytes;
inline constexpr std::size_t kBallotOff = kRulesEpochOff + kU16Bytes;
inline constexpr std::size_t kPayeeOff = kBallotOff + kU16Bytes;
inline constexpr std::size_t kTOriginOff = kPayeeOff + kHashBytes;
inline constexpr std::size_t kTipOff = kTOriginOff + kU64Bytes;
inline constexpr std::size_t kReceiptsRootOff = kTipOff + kHashBytes;
inline constexpr std::size_t kWindowRootOff = kReceiptsRootOff + kHashBytes;
inline constexpr std::size_t kMmrRootOff = kWindowRootOff + kHashBytes;
inline constexpr std::size_t kFeeRateOff = kMmrRootOff + kHashBytes;
inline constexpr std::size_t kOwnerOff = kFeeRateOff + kU16Bytes;
inline constexpr std::size_t kGiveAuthorOff = kOwnerOff + kHashBytes;
inline constexpr std::size_t kSize = kGiveAuthorOff + kU16Bytes;
}  // namespace side_v3

inline constexpr std::uint8_t kSideDataV3Version = 3;
inline constexpr std::string_view kSideDataV3Domain = "c2pool-v37-xmr-side-v3";

struct SideDataV3 {
    std::uint8_t version = kSideDataV3Version;
    Hash32 pool_id{};
    std::uint16_t rules_epoch = 0;
    std::uint16_t ballot = 0;
    Hash32 payee{};
    std::uint64_t t_origin = 0;
    Hash32 tip{};
    Hash32 receipts_root{};
    Hash32 window_root{};
    Hash32 mmr_root{};
    std::uint16_t fee_rate_bp = 0;
    Hash32 owner{};
    std::uint16_t give_author_bp = 0;

    friend bool operator==(const SideDataV3&, const SideDataV3&) = default;
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------
enum class WireError : std::uint8_t {
    None = 0,
    OverCap,          // input longer than the local buffer bound: drop, no verdict
    Truncated,        // input ended inside a field
    Trailing,         // bytes left after the structure
    Version,          // side_data or carrier body version != 3
    FeeRateRange,     // fee_rate p > 10000
    GiveAuthorRange,  // give_author_bp > 10000
    OwnerIdentity,    // owner identity zero/non-zero does not match p
    BlobLength,       // blob_len out of range or not equal to the parsed blob
    BlobField,        // a hashing-blob varint is non-canonical or wider than declared
    PayeeRefKind,     // payee_ref kind != XMR_STD
    PayeeRefLength,   // payee_ref len != 64
    OwnerRefKind,     // owner_ref kind != XMR_STD
    OwnerRefLength,   // owner_ref len != 64
    PayeeRefPoint,    // payee spend or view key does not decompress
    OwnerRefPoint,    // owner spend or view key does not decompress
    CarriedCount,     // n_carried above R_MAX
    Unencodable,      // encoder input outside the format
};

inline const char* to_string(WireError e) noexcept {
    switch (e) {
        case WireError::None: return "none";
        case WireError::OverCap: return "over-cap";
        case WireError::Truncated: return "truncated";
        case WireError::Trailing: return "trailing";
        case WireError::Version: return "version";
        case WireError::FeeRateRange: return "fee-rate-range";
        case WireError::GiveAuthorRange: return "give-author-range";
        case WireError::OwnerIdentity: return "owner-identity";
        case WireError::BlobLength: return "blob-length";
        case WireError::BlobField: return "blob-field";
        case WireError::PayeeRefKind: return "payee-ref-kind";
        case WireError::PayeeRefLength: return "payee-ref-length";
        case WireError::OwnerRefKind: return "owner-ref-kind";
        case WireError::OwnerRefLength: return "owner-ref-length";
        case WireError::PayeeRefPoint: return "payee-ref-point";
        case WireError::OwnerRefPoint: return "owner-ref-point";
        case WireError::CarriedCount: return "carried-count";
        case WireError::Unencodable: return "unencodable";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------
namespace detail {

template <class T>
inline void put_le(std::vector<std::uint8_t>& out, T v) {
    for (std::size_t i = 0; i < sizeof(T); ++i) out.push_back(static_cast<std::uint8_t>(v >> (CHAR_BIT * i)));
}

template <class T>
inline bool get_le(BlobReader& r, T& out) noexcept {
    T v = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        std::uint8_t b = 0;
        if (!r.read_byte(b)) return false;
        v = static_cast<T>(v | (static_cast<T>(b) << (CHAR_BIT * i)));
    }
    out = v;
    return true;
}

inline void put_hash(std::vector<std::uint8_t>& out, const Hash32& h) { out.insert(out.end(), h.begin(), h.end()); }

inline bool get_hash(BlobReader& r, Hash32& h) noexcept { return r.read_bytes(h.data(), h.size()); }

inline void put_varint(std::vector<std::uint8_t>& out, std::uint64_t v) {
    constexpr std::uint64_t kPayloadMask = (std::uint64_t{1} << kVarintPayloadBits) - 1;
    constexpr std::uint8_t kContinue = std::uint8_t{1} << kVarintPayloadBits;
    while ((v >> kVarintPayloadBits) != 0) {
        out.push_back(static_cast<std::uint8_t>((v & kPayloadMask) | kContinue));
        v >>= kVarintPayloadBits;
    }
    out.push_back(static_cast<std::uint8_t>(v));
}

inline bool is_zero(const Hash32& h) noexcept {
    for (std::uint8_t b : h)
        if (b != 0) return false;
    return true;
}

}  // namespace detail

// ---------------------------------------------------------------------------
// side_data_v3 codec
// ---------------------------------------------------------------------------
inline WireError side_data_v3_check(const SideDataV3& s) noexcept {
    if (s.version != kSideDataV3Version) return WireError::Version;
    if (s.fee_rate_bp > kBasisPointsScale) return WireError::FeeRateRange;
    if (s.give_author_bp > kBasisPointsScale) return WireError::GiveAuthorRange;
    if ((s.fee_rate_bp == 0) != detail::is_zero(s.owner)) return WireError::OwnerIdentity;
    return WireError::None;
}

inline WireError encode_side_data_v3(const SideDataV3& s, std::vector<std::uint8_t>& out) {
    if (WireError e = side_data_v3_check(s); e != WireError::None) return e;
    out.push_back(s.version);
    detail::put_hash(out, s.pool_id);
    detail::put_le(out, s.rules_epoch);
    detail::put_le(out, s.ballot);
    detail::put_hash(out, s.payee);
    detail::put_le(out, s.t_origin);
    detail::put_hash(out, s.tip);
    detail::put_hash(out, s.receipts_root);
    detail::put_hash(out, s.window_root);
    detail::put_hash(out, s.mmr_root);
    detail::put_le(out, s.fee_rate_bp);
    detail::put_hash(out, s.owner);
    detail::put_le(out, s.give_author_bp);
    return WireError::None;
}

// Reads exactly side_v3::kSize bytes from the reader.
inline WireError read_side_data_v3(BlobReader& r, SideDataV3& s) noexcept {
    if (r.remaining() < side_v3::kSize) return WireError::Truncated;
    SideDataV3 v;
    bool ok = r.read_byte(v.version) && detail::get_hash(r, v.pool_id) && detail::get_le(r, v.rules_epoch)
              && detail::get_le(r, v.ballot) && detail::get_hash(r, v.payee) && detail::get_le(r, v.t_origin)
              && detail::get_hash(r, v.tip) && detail::get_hash(r, v.receipts_root)
              && detail::get_hash(r, v.window_root) && detail::get_hash(r, v.mmr_root)
              && detail::get_le(r, v.fee_rate_bp) && detail::get_hash(r, v.owner)
              && detail::get_le(r, v.give_author_bp);
    if (!ok) return WireError::Truncated;
    if (WireError e = side_data_v3_check(v); e != WireError::None) return e;
    s = v;
    return WireError::None;
}

inline WireError decode_side_data_v3(const std::uint8_t* data, std::size_t n, SideDataV3& s) noexcept {
    if (n > side_v3::kSize) return WireError::OverCap;
    if (n < side_v3::kSize) return WireError::Truncated;
    BlobReader r(data, n);
    return read_side_data_v3(r, s);
}

// mm_root = keccak256(domain || side_data_v3 bytes).
inline Hash32 mm_root_of(const std::vector<std::uint8_t>& side_bytes) {
    std::vector<std::uint8_t> pre(kSideDataV3Domain.begin(), kSideDataV3Domain.end());
    pre.insert(pre.end(), side_bytes.begin(), side_bytes.end());
    const ::xmr::coin::Hash256 h = ::xmr::coin::keccak256(pre.data(), pre.size());
    Hash32 out{};
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = h.data()[i];
    return out;
}

inline std::optional<Hash32> mm_root_of(const SideDataV3& s) {
    std::vector<std::uint8_t> bytes;
    if (encode_side_data_v3(s, bytes) != WireError::None) return std::nullopt;
    return mm_root_of(bytes);
}

// ---------------------------------------------------------------------------
// Receipt body
// ---------------------------------------------------------------------------
struct HashingBlob {
    std::uint64_t major = 0;
    std::uint64_t minor = 0;
    std::uint64_t timestamp = 0;
    Hash32 prev_id{};
    std::uint32_t nonce = 0;
    Hash32 tree_root{};
    std::uint64_t tx_count = 0;

    friend bool operator==(const HashingBlob&, const HashingBlob&) = default;
};

struct XmrKeyRef {
    Hash32 spend{};
    Hash32 view{};

    friend bool operator==(const XmrKeyRef&, const XmrKeyRef&) = default;
};

// An ed25519 point encoding that decompresses.
inline bool point_decompresses(const Hash32& k) noexcept {
    ge_p3 p;
    return ge_frombytes_vartime(&p, k.data()) == 0;
}

inline bool key_ref_points_valid(const XmrKeyRef& r) noexcept {
    return point_decompresses(r.spend) && point_decompresses(r.view);
}

struct ReceiptBodyV3 {
    HashingBlob blob;
    std::array<std::uint8_t, kExtraNonceBytes> extra_nonce{};
    std::vector<Hash32> branch;  // depth D = branch.size()
    SideDataV3 side;
    XmrKeyRef payee;
    std::optional<XmrKeyRef> owner;  // present iff side.fee_rate_bp > 0
    std::uint64_t reward_total = 0;

    friend bool operator==(const ReceiptBodyV3&, const ReceiptBodyV3&) = default;
};

// Bytes of a receipt body without its branch, at the largest hashing blob and
// with owner_ref present.
inline constexpr std::size_t kReceiptFixedMaxBytes = kU8Bytes + kHashingBlobMaxBytes + kExtraNonceBytes + kU8Bytes
                                                     + side_v3::kSize + kKeyRefBytes + kKeyRefBytes + kU64Bytes;

// RECEIPT_MAX(D) = 465 + 32 D.
inline constexpr std::uint64_t receipt_max(std::uint64_t depth) noexcept {
    return kReceiptFixedMaxBytes + depth * kHashBytes;
}

struct ReceiptLimits {
    std::uint64_t buffer = 0;  // receipt I/O buffer, bytes (P-10)
};

// True for the buffer-bound outcome (drop without a verdict).
inline constexpr bool wire_drop_without_verdict(WireError e) noexcept { return e == WireError::OverCap; }

inline bool hashing_blob_encodable(const HashingBlob& b) noexcept {
    return varint_len(b.major) <= kMajorVarintMax && varint_len(b.minor) <= kMinorVarintMax
           && varint_len(b.timestamp) <= kTimestampVarintMax && varint_len(b.tx_count) <= kTxCountVarintMax;
}

inline void encode_hashing_blob(const HashingBlob& b, std::vector<std::uint8_t>& out) {
    detail::put_varint(out, b.major);
    detail::put_varint(out, b.minor);
    detail::put_varint(out, b.timestamp);
    detail::put_hash(out, b.prev_id);
    detail::put_le(out, b.nonce);
    detail::put_hash(out, b.tree_root);
    detail::put_varint(out, b.tx_count);
}

namespace detail {

inline bool read_bounded_varint(BlobReader& r, std::size_t max_bytes, std::uint64_t& out) noexcept {
    const std::size_t before = r.remaining();
    if (!r.read_varint(out)) return false;
    return before - r.remaining() <= max_bytes;
}

inline WireError read_hashing_blob(BlobReader& r, std::size_t blob_len, HashingBlob& b) noexcept {
    if (r.remaining() < blob_len) return WireError::Truncated;
    const std::uint8_t* view = nullptr;
    if (!r.read_view(view, blob_len)) return WireError::Truncated;
    BlobReader in(view, blob_len);
    HashingBlob v;
    if (!read_bounded_varint(in, kMajorVarintMax, v.major)) return WireError::BlobField;
    if (!read_bounded_varint(in, kMinorVarintMax, v.minor)) return WireError::BlobField;
    if (!read_bounded_varint(in, kTimestampVarintMax, v.timestamp)) return WireError::BlobField;
    if (!get_hash(in, v.prev_id)) return WireError::BlobLength;
    if (!get_le(in, v.nonce)) return WireError::BlobLength;
    if (!get_hash(in, v.tree_root)) return WireError::BlobLength;
    if (!read_bounded_varint(in, kTxCountVarintMax, v.tx_count)) return WireError::BlobField;
    if (in.remaining() != 0) return WireError::BlobLength;
    b = v;
    return WireError::None;
}

inline WireError read_key_ref(BlobReader& r, XmrKeyRef& ref, WireError kind_err, WireError len_err,
                              WireError point_err) noexcept {
    std::uint8_t kind = 0;
    std::uint8_t len = 0;
    if (!r.read_byte(kind) || !r.read_byte(len)) return WireError::Truncated;
    if (kind != kPayeeKindXmrStd) return kind_err;
    if (len != kKeyRefPayloadBytes) return len_err;
    if (!get_hash(r, ref.spend) || !get_hash(r, ref.view)) return WireError::Truncated;
    if (!key_ref_points_valid(ref)) return point_err;
    return WireError::None;
}

inline void put_key_ref(std::vector<std::uint8_t>& out, const XmrKeyRef& ref) {
    out.push_back(kPayeeKindXmrStd);
    out.push_back(static_cast<std::uint8_t>(kKeyRefPayloadBytes));
    put_hash(out, ref.spend);
    put_hash(out, ref.view);
}

}  // namespace detail

inline WireError receipt_body_v3_check(const ReceiptBodyV3& b) noexcept {
    if (!hashing_blob_encodable(b.blob)) return WireError::Unencodable;
    if (b.branch.size() > UINT8_MAX) return WireError::Unencodable;
    if (WireError e = side_data_v3_check(b.side); e != WireError::None) return e;
    if ((b.side.fee_rate_bp > 0) != b.owner.has_value()) return WireError::OwnerIdentity;
    if (!key_ref_points_valid(b.payee)) return WireError::PayeeRefPoint;
    if (b.owner && !key_ref_points_valid(*b.owner)) return WireError::OwnerRefPoint;
    return WireError::None;
}

inline WireError encode_receipt_body_v3(const ReceiptBodyV3& b, std::vector<std::uint8_t>& out) {
    if (WireError e = receipt_body_v3_check(b); e != WireError::None) return e;
    std::vector<std::uint8_t> blob;
    encode_hashing_blob(b.blob, blob);
    out.push_back(static_cast<std::uint8_t>(blob.size()));
    out.insert(out.end(), blob.begin(), blob.end());
    out.insert(out.end(), b.extra_nonce.begin(), b.extra_nonce.end());
    out.push_back(static_cast<std::uint8_t>(b.branch.size()));
    for (const Hash32& h : b.branch) detail::put_hash(out, h);
    if (WireError e = encode_side_data_v3(b.side, out); e != WireError::None) return e;
    detail::put_key_ref(out, b.payee);
    if (b.owner) detail::put_key_ref(out, *b.owner);
    detail::put_le(out, b.reward_total);
    return WireError::None;
}

// Reads one receipt body from the reader (used standalone and inside a carrier body).
inline WireError read_receipt_body_v3(BlobReader& r, ReceiptBodyV3& out) {
    std::uint8_t blob_len = 0;
    if (!r.read_byte(blob_len)) return WireError::Truncated;
    if (blob_len > kHashingBlobMaxBytes || blob_len < kHashingBlobMinBytes) return WireError::BlobLength;
    ReceiptBodyV3 v;
    if (WireError e = detail::read_hashing_blob(r, blob_len, v.blob); e != WireError::None) return e;
    if (!r.read_bytes(v.extra_nonce.data(), v.extra_nonce.size())) return WireError::Truncated;
    std::uint8_t depth = 0;
    if (!r.read_byte(depth)) return WireError::Truncated;
    if (r.remaining() / kHashBytes < depth) return WireError::Truncated;
    v.branch.resize(depth);
    for (Hash32& h : v.branch)
        if (!detail::get_hash(r, h)) return WireError::Truncated;
    if (WireError e = read_side_data_v3(r, v.side); e != WireError::None) return e;
    if (WireError e = detail::read_key_ref(r, v.payee, WireError::PayeeRefKind, WireError::PayeeRefLength,
                                              WireError::PayeeRefPoint);
        e != WireError::None)
        return e;
    if (v.side.fee_rate_bp > 0) {
        XmrKeyRef owner;
        if (WireError e = detail::read_key_ref(r, owner, WireError::OwnerRefKind, WireError::OwnerRefLength,
                                                  WireError::OwnerRefPoint);
            e != WireError::None)
            return e;
        v.owner = owner;
    }
    if (!detail::get_le(r, v.reward_total)) return WireError::Truncated;
    out = std::move(v);
    return WireError::None;
}

inline WireError decode_receipt_body_v3(const std::uint8_t* data, std::size_t n, const ReceiptLimits& lim,
                                        ReceiptBodyV3& out) {
    if (n > lim.buffer) return WireError::OverCap;
    BlobReader r(data, n);
    if (WireError e = read_receipt_body_v3(r, out); e != WireError::None) return e;
    if (r.remaining() != 0) return WireError::Trailing;
    return WireError::None;
}

// Identity binding of the side data to the refs next to it:
// side.payee == xmr_identity_key(payee_ref), side.owner == xmr_identity_key(owner_ref) when present.
inline Hash32 key_ref_identity(const XmrKeyRef& ref) {
    ::v37::ScriptRef s;
    s.kind = ::v37::xmr::XMR_STD;
    s.payload.reserve(kKeyRefPayloadBytes);
    s.payload.insert(s.payload.end(), ref.spend.begin(), ref.spend.end());
    s.payload.insert(s.payload.end(), ref.view.begin(), ref.view.end());
    return ::v37::xmr::xmr_identity_key(s);
}

inline bool identities_bound(const ReceiptBodyV3& b) {
    if (b.side.payee != key_ref_identity(b.payee)) return false;
    if (b.owner && b.side.owner != key_ref_identity(*b.owner)) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Carrier body
// ---------------------------------------------------------------------------
inline constexpr std::uint8_t kCarrierBodyVersion = 3;

struct CarrierBodyV3 {
    ReceiptBodyV3 own;
    std::vector<ReceiptBodyV3> carried;

    friend bool operator==(const CarrierBodyV3&, const CarrierBodyV3&) = default;
};

struct CarrierLimits {
    std::uint64_t receipt_buffer = 0;  // receipt I/O buffer, bytes (P-10)
    std::uint64_t r_max = 0;           // K08
};

// kFbMaxReceiptsPerFrame: the receipts a carrier frame holds = 1 + R_MAX (the
// carrier and up to R_MAX carried; 8 -> 1 + R_MAX = 17 at R_MAX 16, v2.4).
inline constexpr std::uint64_t max_receipts_per_frame(std::uint64_t r_max) noexcept {
    return 1 + r_max;
}

// kFbMaxReceiptsPerFrame at the ruled R_MAX (the S2 relay literal is 8; v2.4 = 17).
inline constexpr std::uint64_t kFbMaxReceiptsPerFrame = max_receipts_per_frame(kRuledLaneParams.r_max);
static_assert(kFbMaxReceiptsPerFrame == 17, "a carrier frame holds the carrier + R_MAX = 16 carried receipts");

// Carrier body of an own and R_MAX carried bodies of `receipt_bytes` each:
// ver + kFbMaxReceiptsPerFrame x receipt + n_carried.
inline constexpr std::uint64_t carrier_body_size(std::uint64_t receipt_bytes, std::uint64_t r_max) noexcept {
    return kU8Bytes + kU8Bytes + max_receipts_per_frame(r_max) * receipt_bytes;
}

// The carrier body buffer of the limits.
inline constexpr std::uint64_t carrier_body_buffer(const CarrierLimits& lim) noexcept {
    return carrier_body_size(lim.receipt_buffer, lim.r_max);
}

// ---------------------------------------------------------------------------
// Carrier frame
// ---------------------------------------------------------------------------
// FH: the relay frame header, u8 opcode | u8 frame version | u32 chain_id.
inline constexpr std::size_t kFrameOpcodeBytes = kU8Bytes;
inline constexpr std::size_t kFrameVersionBytes = kU8Bytes;
inline constexpr std::size_t kFrameChainIdBytes = kU32Bytes;
inline constexpr std::size_t kFrameHeaderBytes = kFrameOpcodeBytes + kFrameVersionBytes + kFrameChainIdBytes;

// FH + carrier_body_size(receipt_bytes, r_max).
inline constexpr std::uint64_t frame_size(std::uint64_t receipt_bytes, std::uint64_t r_max) noexcept {
    return kFrameHeaderBytes + carrier_body_size(receipt_bytes, r_max);
}

// The frame I/O buffer of the limits (P-11).
inline constexpr std::uint64_t frame_buffer(const CarrierLimits& lim) noexcept {
    return frame_size(lim.receipt_buffer, lim.r_max);
}

inline WireError encode_carrier_body_v3(const CarrierBodyV3& c, std::uint64_t r_max, std::vector<std::uint8_t>& out) {
    if (c.carried.size() > r_max || c.carried.size() > UINT8_MAX) return WireError::CarriedCount;
    std::vector<std::uint8_t> tmp;
    tmp.push_back(kCarrierBodyVersion);
    if (WireError e = encode_receipt_body_v3(c.own, tmp); e != WireError::None) return e;
    tmp.push_back(static_cast<std::uint8_t>(c.carried.size()));
    for (const ReceiptBodyV3& b : c.carried)
        if (WireError e = encode_receipt_body_v3(b, tmp); e != WireError::None) return e;
    out.insert(out.end(), tmp.begin(), tmp.end());
    return WireError::None;
}

inline WireError decode_carrier_body_v3(const std::uint8_t* data, std::size_t n, const CarrierLimits& lim,
                                        CarrierBodyV3& out) {
    if (n > carrier_body_buffer(lim)) return WireError::OverCap;
    BlobReader r(data, n);
    std::uint8_t ver = 0;
    if (!r.read_byte(ver)) return WireError::Truncated;
    if (ver != kCarrierBodyVersion) return WireError::Version;
    CarrierBodyV3 v;
    if (WireError e = read_receipt_body_v3(r, v.own); e != WireError::None) return e;
    std::uint8_t n_carried = 0;
    if (!r.read_byte(n_carried)) return WireError::Truncated;
    if (n_carried > lim.r_max) return WireError::CarriedCount;
    v.carried.resize(n_carried);
    for (ReceiptBodyV3& b : v.carried)
        if (WireError e = read_receipt_body_v3(r, b); e != WireError::None) return e;
    if (r.remaining() != 0) return WireError::Trailing;
    out = std::move(v);
    return WireError::None;
}

}  // namespace c2pool::xmr::pathb
