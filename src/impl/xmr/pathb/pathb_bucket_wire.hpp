// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_bucket_wire.hpp
// Path B FC_GETBUCKETS / FC_BUCKETS (ruling 31 P-7; E-8, E-9): the L1 buckets
// of sealed bins with their MMR proofs, bound to a carrier `at`, paged.
//
//   FC_GETBUCKETS  FH(0x54) | at[32] | u64 bin_lo | u64 bin_hi           bin_lo <= bin_hi
//   FC_BUCKETS     FH(0x55) | at[32] | u64 leaf_count | u8 n_peaks | n_peaks x peak[32]
//                  | S_parent(at)[134] | u32 n_refs | n_refs x key_ref[66]
//                  | u16 n | n x entry
//     entry        LeafPayload v1[96] | u32 rows_total | u32 row_first | u16 n_rows
//                  | n_rows x row[160] | u8 path_len | path_len x sibling[32]
//   FH = u8 opcode | u8 frame version | u32 chain_id (LE), frame version 1.
//
//   leaf_count    = leaf_count(at) = max(0, H(at) - F - b0 + 1) (E-8; P-3,
//                   b0 = H(0)); peaks = the peaks of that prefix, n_peaks =
//                   popcount(leaf_count), bagged under leaf_count to the root
//                   over leaf_count(at) leaves of at's chain.
//   leaf_index    is not sent: leaf_index = bin_lo - b0 (E-8); the sibling
//                   sides follow from it (mmr_proof_shape_ok).
//   key_ref       u8 kind (XMR_STD) | u8 len 64 | spend[32] | view[32]; one
//                   reference per identity of the frame's rows (miners and
//                   non-zero owners), strictly ascending by identity =
//                   xmr_identity_key(ref) (key_ref_identity).
//   paging        the rows of one bin span entries and frames (row_first,
//                   rows_total); the entries of one server continue in (bin,
//                   row_first) order from (bin_lo, 0) without a gap, inside
//                   [bin_lo, bin_hi]; a server may stop after any entry.
//   S_parent(at)  the 134-byte ratchet state at at's parent, checked against
//                   at's receipts_root fold once at's carried ids are held.
//   not served    n = 0, leaf_count = 0, no peaks, S zero, no references.
//
// Serving rule: `at` on the server's best chain at or below its tip; bins in
// order from bin_lo while the server proves the leaf at leaf_count(at), holds
// the rows and holds a reference for every identity; otherwise n = 0. No
// strike either way.
//
// Receiver, per frame, in order (BucketsAssembly::add_frame):
//   frame above the buffer (P-39)                         DROP, no token
//   the bytes decode (opcode, version, chain_id, n_peaks == popcount(leaf_count),
//     no element allocated before its bytes are read, no trailing byte)
//   at == the request's at                                 else DROP
//   n == 0                                                 ask another peer, no verdict
//   at held as a header                                    else DEFER
//   leaf_count == leaf_count(at)
//   the root over leaf_count(at) leaves held               else DEFER
//   the peaks bag to that root under leaf_count
//   S_parent equal in every frame of one server; folded with at's
//     receipts_root when at's carried ids are held (else pending)
//   references strictly ascending by identity, each decompressing (I-7)
//   per entry, before its rows are allocated:
//     the server's next (bin, row_first); bin <= bin_hi;
//     leaf_index = bin - b0 < leaf_count;
//     bin_lo == bin_hi == b0 + leaf_index;
//     the MMR proof of its LeafPayload verifies;
//     rows_total <= raw_sum / d_min, rows_total == 0 iff raw_sum == 0;
//     rows_total equal on every page of the bin;
//     row_first + n_rows <= rows_total, n_rows > 0 unless rows_total == 0
//   the frame's row identities == its reference identities (no missing, no stray)
//   a bin whose rows from one server are complete: bucket_check
// A failure refuses the frame and strikes its server once; that server's pages
// are discarded and its later frames for the request are dropped. A bin
// completes from the pages of ONE server; a page not received is asked from
// another server (abandon()).
//
// Policy (ruling 23; defaults with a reason and a flag; a different value
// changes no verdict, it costs a fetch or a DEFER): P-39 frame buffer, P-41
// requests in flight per peer, P-42 bytes per peer per minute.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "pathb_bin_store.hpp"          // BinStore, SealedBin, bin_leaf_count, kBucketRowBytes, kLeafPayloadBytes
#include "pathb_buckets.hpp"            // L1Bucket, BucketRow, BinMmr, mmr_verify, bucket_check
#include "pathb_caps.hpp"               // blob_cap_ctx (P-14)
#include "pathb_joiner.hpp"             // peaks_match_root
#include "pathb_params.hpp"
#include "pathb_ratchet_state.hpp"      // RatchetStateBytes, decode_ratchet_state
#include "pathb_receipt_admission.hpp"  // check_carried_fold
#include "pathb_wire_v3.hpp"            // XmrKeyRef, key_ref_identity, key_ref_points_valid, FH sizes

namespace c2pool::xmr::pathb {

// ---------------------------------------------------------------------------
// Opcodes and sizes
// ---------------------------------------------------------------------------
inline constexpr std::uint8_t kOpFcGetBuckets = 0x54;  // family C (ruling 31 P-7)
inline constexpr std::uint8_t kOpFcBuckets = 0x55;
inline constexpr std::uint8_t kFcFrameVersion = 1;     // the frame version of the relay frames

inline constexpr std::size_t kRatchetStateBytes = rs_layout::kSize;
static_assert(kRatchetStateBytes == 134);

inline constexpr std::size_t kGetBucketsFrameBytes = kFrameHeaderBytes + kHashBytes + kU64Bytes + kU64Bytes;
static_assert(kGetBucketsFrameBytes == 54);

// FC_BUCKETS bytes before the peaks, between the peaks and the references, and after them.
inline constexpr std::size_t kBucketsHeadBytes = kFrameHeaderBytes + kHashBytes + kU64Bytes + kU8Bytes;
inline constexpr std::size_t kBucketsMidBytes = kRatchetStateBytes + kU32Bytes;
inline constexpr std::size_t kBucketsEntryCountBytes = kU16Bytes;
// One entry without its rows and siblings.
inline constexpr std::size_t kEntryFixedBytes = kLeafPayloadBytes + kU32Bytes + kU32Bytes + kU16Bytes + kU8Bytes;
static_assert(kEntryFixedBytes == 107);
inline constexpr std::size_t kNotServedFrameBytes = kBucketsHeadBytes + kBucketsMidBytes + kBucketsEntryCountBytes;
static_assert(kNotServedFrameBytes == 187);

inline constexpr std::size_t kMaxEntriesPerFrame = UINT16_MAX;
inline constexpr std::size_t kMaxRowsPerEntry = UINT16_MAX;
inline constexpr std::size_t kMaxPathLen = UINT8_MAX;

// ---------------------------------------------------------------------------
// Policy (ruling 23)
// ---------------------------------------------------------------------------
// P-39 FC_BUCKETS frame buffer: one frame is bounded like every other frame (the
// transport ceiling P-14 = FB_CTX header + blob_cap_ctx); a larger bucket pages.
inline constexpr std::string_view kBucketFrameFlag = "--pathb-bucket-frame";
// P-41 FC_GETBUCKETS in flight per peer, default 1: a joiner pages sequentially;
// more are DROPPED, no verdict.
inline constexpr std::uint64_t kBucketInflightDefault = 1;
inline constexpr std::string_view kBucketInflightFlag = "--pathb-bucket-inflight";
// P-42 FC_BUCKETS bytes per peer per minute, default kBucketRateFrames x P-39: a
// joiner needs a few MB once; above it DROP, no verdict.
inline constexpr std::uint64_t kBucketRateFrames = 10;
inline constexpr std::string_view kBucketRateFlag = "--pathb-bucket-rate";
inline constexpr std::uint64_t kSecondsPerMinute = 60;

// The FB_CTX frame header: FH | id[32] | u32 len.
inline constexpr std::uint64_t kCtxFrameHeaderBytes = kFrameHeaderBytes + kHashBytes + kU32Bytes;

// P-14 at the node's view: FB_CTX header + blob_cap_ctx(hf, Z).
inline constexpr std::optional<std::uint64_t> transport_ceiling(std::uint8_t hf, std::uint64_t z_view) noexcept {
    const std::optional<std::uint64_t> cap = blob_cap_ctx(hf, z_view);
    if (!cap || *cap > UINT64_MAX - kCtxFrameHeaderBytes) return std::nullopt;
    return kCtxFrameHeaderBytes + *cap;
}

struct BucketWirePolicy {
    std::uint64_t frame_bytes = 0;       // P-39
    std::uint64_t inflight = 0;          // P-41
    std::uint64_t bytes_per_minute = 0;  // P-42

    friend bool operator==(const BucketWirePolicy&, const BucketWirePolicy&) = default;
};

inline constexpr std::optional<BucketWirePolicy> bucket_wire_policy_default(std::uint8_t hf,
                                                                            std::uint64_t z_view) noexcept {
    const std::optional<std::uint64_t> frame = transport_ceiling(hf, z_view);
    if (!frame || *frame > UINT64_MAX / kBucketRateFrames) return std::nullopt;
    return BucketWirePolicy{*frame, kBucketInflightDefault, kBucketRateFrames * *frame};
}

// ---------------------------------------------------------------------------
// Codec errors (bytes that do not decode are refused; OverBuffer is a DROP)
// ---------------------------------------------------------------------------
enum class BucketsWireError : std::uint8_t {
    None,
    Truncated,  // fewer bytes than a field or a count needs (checked before allocating)
    Trailing,   // bytes after the last field
    Opcode,     // not this frame's opcode
    Version,    // frame version other than 1
    ChainId,    // FH chain_id other than the lane's
    PeakCount,  // n_peaks != popcount(leaf_count)
    RefKind,    // a reference of a kind other than XMR_STD
    RefLength,  // a reference whose len is not 64
    BinRange,   // request with bin_lo > bin_hi
};

namespace bw_detail {

inline void put_frame_header(std::vector<std::uint8_t>& out, std::uint8_t op, std::uint32_t chain_id) {
    out.push_back(op);
    out.push_back(kFcFrameVersion);
    detail::put_le(out, chain_id);
}

inline BucketsWireError read_frame_header(BlobReader& r, std::uint8_t op, std::uint32_t chain_id) {
    std::uint8_t o = 0, ver = 0;
    std::uint32_t cid = 0;
    if (!r.read_byte(o) || !r.read_byte(ver) || !detail::get_le(r, cid)) return BucketsWireError::Truncated;
    if (o != op) return BucketsWireError::Opcode;
    if (ver != kFcFrameVersion) return BucketsWireError::Version;
    if (cid != chain_id) return BucketsWireError::ChainId;
    return BucketsWireError::None;
}

inline std::uint64_t le64_at(const std::uint8_t* p) noexcept {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < kU64Bytes; ++i) v |= std::uint64_t{p[i]} << (CHAR_BIT * i);
    return v;
}

inline Work le256_at(const std::uint8_t* p) {
    std::array<std::uint8_t, kHashBytes> b{};
    std::copy(p, p + b.size(), b.begin());
    return lane_rec::work_from_le256(b);
}

}  // namespace bw_detail

// LeafPayload v1 (96 B) -> its fields (rows empty).
inline L1Bucket decode_leaf_payload(const std::uint8_t* p) {
    L1Bucket b;
    std::size_t o = 0;
    b.bin_lo = bw_detail::le64_at(p + o);
    o += kU64Bytes;
    b.bin_hi = bw_detail::le64_at(p + o);
    o += kU64Bytes;
    b.raw_sum = bw_detail::le256_at(p + o);
    o += kHashBytes;
    b.miner_count = bw_detail::le64_at(p + o);
    o += kU64Bytes;
    b.d_min = bw_detail::le64_at(p + o);
    o += kU64Bytes;
    std::copy(p + o, p + o + kHashBytes, b.comp_root_v.begin());
    return b;
}

// Bucket row (160 B) -> its fields.
inline BucketRow decode_bucket_row(const std::uint8_t* p) {
    BucketRow r;
    std::size_t o = 0;
    std::copy(p + o, p + o + kHashBytes, r.miner.begin());
    o += kHashBytes;
    std::copy(p + o, p + o + kHashBytes, r.owner.begin());
    o += kHashBytes;
    r.w_miner = bw_detail::le256_at(p + o);
    o += kHashBytes;
    r.w_owner = bw_detail::le256_at(p + o);
    o += kHashBytes;
    r.w_author = bw_detail::le256_at(p + o);
    return r;
}

// ---------------------------------------------------------------------------
// FC_GETBUCKETS
// ---------------------------------------------------------------------------
struct GetBuckets {
    std::uint32_t chain_id = 0;
    Hash32 at{};
    std::uint64_t bin_lo = 0;
    std::uint64_t bin_hi = 0;

    friend bool operator==(const GetBuckets&, const GetBuckets&) = default;
};

inline std::optional<std::vector<std::uint8_t>> encode_getbuckets(const GetBuckets& q) {
    if (q.bin_lo > q.bin_hi) return std::nullopt;
    std::vector<std::uint8_t> out;
    out.reserve(kGetBucketsFrameBytes);
    bw_detail::put_frame_header(out, kOpFcGetBuckets, q.chain_id);
    detail::put_hash(out, q.at);
    detail::put_le(out, q.bin_lo);
    detail::put_le(out, q.bin_hi);
    return out;
}

inline BucketsWireError decode_getbuckets(std::span<const std::uint8_t> f, std::uint32_t chain_id, GetBuckets& out) {
    BlobReader r(f.data(), f.size());
    if (BucketsWireError e = bw_detail::read_frame_header(r, kOpFcGetBuckets, chain_id); e != BucketsWireError::None)
        return e;
    GetBuckets q;
    q.chain_id = chain_id;
    if (!detail::get_hash(r, q.at) || !detail::get_le(r, q.bin_lo) || !detail::get_le(r, q.bin_hi))
        return BucketsWireError::Truncated;
    if (r.remaining() != 0) return BucketsWireError::Trailing;
    if (q.bin_lo > q.bin_hi) return BucketsWireError::BinRange;
    out = q;
    return BucketsWireError::None;
}

// ---------------------------------------------------------------------------
// FC_BUCKETS
// ---------------------------------------------------------------------------
struct BucketEntry {
    L1Bucket payload;               // LeafPayload v1 fields (payload.rows unused)
    std::uint32_t rows_total = 0;
    std::uint32_t row_first = 0;
    std::vector<BucketRow> rows;    // this page's rows
    std::vector<Hash32> path;       // siblings from the leaf to its peak
};

struct BucketsReply {
    std::uint32_t chain_id = 0;
    Hash32 at{};
    std::uint64_t leaf_count = 0;
    std::vector<Hash32> peaks;
    RatchetStateBytes s_parent{};
    std::vector<XmrKeyRef> refs;
    std::vector<BucketEntry> entries;
};

// nullopt for a value the decoder refuses as bytes (n_peaks != popcount, a count
// above its width).
inline std::optional<std::vector<std::uint8_t>> encode_buckets(const BucketsReply& r) {
    if (r.peaks.size() != popcount64(r.leaf_count)) return std::nullopt;
    if (r.refs.size() > UINT32_MAX || r.entries.size() > kMaxEntriesPerFrame) return std::nullopt;
    std::vector<std::uint8_t> out;
    bw_detail::put_frame_header(out, kOpFcBuckets, r.chain_id);
    detail::put_hash(out, r.at);
    detail::put_le(out, r.leaf_count);
    out.push_back(static_cast<std::uint8_t>(r.peaks.size()));
    for (const Hash32& p : r.peaks) detail::put_hash(out, p);
    out.insert(out.end(), r.s_parent.begin(), r.s_parent.end());
    detail::put_le(out, static_cast<std::uint32_t>(r.refs.size()));
    for (const XmrKeyRef& k : r.refs) detail::put_key_ref(out, k);
    detail::put_le(out, static_cast<std::uint16_t>(r.entries.size()));
    for (const BucketEntry& e : r.entries) {
        if (e.rows.size() > kMaxRowsPerEntry || e.path.size() > kMaxPathLen) return std::nullopt;
        const std::array<std::uint8_t, kLeafPayloadBytes> p = leaf_payload_bytes(e.payload);
        out.insert(out.end(), p.begin(), p.end());
        detail::put_le(out, e.rows_total);
        detail::put_le(out, e.row_first);
        detail::put_le(out, static_cast<std::uint16_t>(e.rows.size()));
        for (const BucketRow& row : e.rows) {
            const std::array<std::uint8_t, kBucketRowBytes> b = bucket_row_bytes(row);
            out.insert(out.end(), b.begin(), b.end());
        }
        out.push_back(static_cast<std::uint8_t>(e.path.size()));
        for (const Hash32& s : e.path) detail::put_hash(out, s);
    }
    return out;
}

// One decoded entry whose rows are not yet allocated: they stay bytes inside
// the frame until the entry's checks have passed.
struct BucketEntryView {
    L1Bucket payload;
    std::uint32_t rows_total = 0;
    std::uint32_t row_first = 0;
    std::uint16_t n_rows = 0;
    const std::uint8_t* rows = nullptr;  // n_rows x 160 bytes inside the frame
    std::vector<Hash32> path;
};

struct BucketsFrameView {
    std::uint32_t chain_id = 0;
    Hash32 at{};
    std::uint64_t leaf_count = 0;
    std::vector<Hash32> peaks;
    RatchetStateBytes s_parent{};
    std::vector<XmrKeyRef> refs;
    std::vector<BucketEntryView> entries;
};

// Decodes the frame's bytes. Nothing is allocated for an element before its
// bytes have been read (a count never sizes a buffer), and rows are not
// allocated at all: BucketEntryView::rows points into f, which must outlive
// the view.
inline BucketsWireError decode_buckets_view(std::span<const std::uint8_t> f, std::uint32_t chain_id,
                                            BucketsFrameView& out) {
    BlobReader r(f.data(), f.size());
    if (BucketsWireError e = bw_detail::read_frame_header(r, kOpFcBuckets, chain_id); e != BucketsWireError::None)
        return e;
    BucketsFrameView v;
    v.chain_id = chain_id;
    std::uint8_t n_peaks = 0;
    if (!detail::get_hash(r, v.at) || !detail::get_le(r, v.leaf_count) || !r.read_byte(n_peaks))
        return BucketsWireError::Truncated;
    if (n_peaks != popcount64(v.leaf_count)) return BucketsWireError::PeakCount;
    for (std::size_t i = 0; i < n_peaks; ++i) {
        Hash32 p{};
        if (!detail::get_hash(r, p)) return BucketsWireError::Truncated;
        v.peaks.push_back(p);
    }
    std::uint32_t n_refs = 0;
    if (!r.read_bytes(v.s_parent.data(), v.s_parent.size()) || !detail::get_le(r, n_refs))
        return BucketsWireError::Truncated;
    for (std::uint32_t i = 0; i < n_refs; ++i) {
        std::uint8_t kind = 0, len = 0;
        XmrKeyRef k;
        if (!r.read_byte(kind) || !r.read_byte(len)) return BucketsWireError::Truncated;
        if (kind != kPayeeKindXmrStd) return BucketsWireError::RefKind;
        if (len != kKeyRefPayloadBytes) return BucketsWireError::RefLength;
        if (!detail::get_hash(r, k.spend) || !detail::get_hash(r, k.view)) return BucketsWireError::Truncated;
        v.refs.push_back(k);
    }
    std::uint16_t n = 0;
    if (!detail::get_le(r, n)) return BucketsWireError::Truncated;
    for (std::size_t i = 0; i < n; ++i) {
        BucketEntryView e;
        const std::uint8_t* payload = nullptr;
        if (!r.read_view(payload, kLeafPayloadBytes)) return BucketsWireError::Truncated;
        e.payload = decode_leaf_payload(payload);
        if (!detail::get_le(r, e.rows_total) || !detail::get_le(r, e.row_first) || !detail::get_le(r, e.n_rows))
            return BucketsWireError::Truncated;
        if (!r.read_view(e.rows, std::size_t{e.n_rows} * kBucketRowBytes)) return BucketsWireError::Truncated;
        std::uint8_t path_len = 0;
        if (!r.read_byte(path_len)) return BucketsWireError::Truncated;
        for (std::size_t k = 0; k < path_len; ++k) {
            Hash32 s{};
            if (!detail::get_hash(r, s)) return BucketsWireError::Truncated;
            e.path.push_back(s);
        }
        v.entries.push_back(std::move(e));
    }
    if (r.remaining() != 0) return BucketsWireError::Trailing;
    out = std::move(v);
    return BucketsWireError::None;
}

// The whole frame with its rows (round trips; the verifier uses the view).
inline BucketsWireError decode_buckets(std::span<const std::uint8_t> f, std::uint32_t chain_id, BucketsReply& out) {
    BucketsFrameView v;
    if (BucketsWireError e = decode_buckets_view(f, chain_id, v); e != BucketsWireError::None) return e;
    BucketsReply r;
    r.chain_id = v.chain_id;
    r.at = v.at;
    r.leaf_count = v.leaf_count;
    r.peaks = std::move(v.peaks);
    r.s_parent = v.s_parent;
    r.refs = std::move(v.refs);
    for (BucketEntryView& e : v.entries) {
        BucketEntry x;
        x.payload = e.payload;
        x.rows_total = e.rows_total;
        x.row_first = e.row_first;
        x.rows.reserve(e.n_rows);
        for (std::size_t i = 0; i < e.n_rows; ++i) x.rows.push_back(decode_bucket_row(e.rows + i * kBucketRowBytes));
        x.path = std::move(e.path);
        r.entries.push_back(std::move(x));
    }
    out = std::move(r);
    return BucketsWireError::None;
}

// The reply of a server that does not serve the request.
inline std::vector<std::uint8_t> encode_buckets_not_served(std::uint32_t chain_id, const Hash32& at) {
    BucketsReply r;
    r.chain_id = chain_id;
    r.at = at;
    return *encode_buckets(r);
}

// The MMR proof of leaf_index against the root over leaf_count leaves, from the
// wire's siblings: the sides and the own peak follow from leaf_index.
inline MmrProof wire_proof(std::uint64_t leaf_index, std::uint64_t leaf_count, const std::vector<Hash32>& path,
                           const std::vector<Hash32>& peaks) {
    MmrProof pr;
    pr.leaf_index = leaf_index;
    pr.leaf_count = leaf_count;
    pr.peaks = peaks;
    std::uint64_t lo = 0;
    std::size_t p = 0;
    for (const auto& [start, sz] : mmr_peak_ranges(leaf_count)) {
        if (leaf_index >= start && leaf_index < start + sz) {
            pr.own_peak = p;
            lo = start;
            break;
        }
        ++p;
    }
    std::uint64_t pos = leaf_index >= lo ? leaf_index - lo : 0;
    for (const Hash32& s : path) {
        pr.path.emplace_back(s, (pos & 1u) == 0);
        pos >>= 1;
    }
    return pr;
}

// The identities of a row set: miners and non-zero owners.
inline std::set<Hash32> row_identities(const std::vector<BucketRow>& rows) {
    std::set<Hash32> ids;
    for (const BucketRow& r : rows) {
        ids.insert(r.miner);
        if (!(r.owner == kZeroHash)) ids.insert(r.owner);
    }
    return ids;
}

// rows_total against the LeafPayload: 0 iff raw_sum is 0; otherwise d_min > 0 and
// 1 <= rows_total <= raw_sum / d_min (each row holds a live receipt of work >= d_min).
inline bool rows_total_ok(const L1Bucket& payload, std::uint32_t rows_total) {
    if (payload.raw_sum.is_zero()) return rows_total == 0;
    if (payload.d_min == 0 || rows_total == 0) return false;
    return !(wide::mul_u256_u64(payload.raw_sum, 1) < wide::mul_u256_u64(Work(payload.d_min), rows_total));
}

// ---------------------------------------------------------------------------
// The receiver
// ---------------------------------------------------------------------------
// What the receiver holds about `at` when a frame is judged.
struct BucketsAnchor {
    bool header_held = false;                         // at held as a header (else DEFER)
    std::uint64_t record = 0;                         // H(at)
    std::optional<Hash32> mmr_root;                   // the root over leaf_count(at) leaves of at's chain (else DEFER)
    Hash32 receipts_root{};                           // at's side_data receipts_root
    std::optional<std::vector<Hash32>> carried_ids;   // at's carried ids in canonical order, once its body is held
};

enum class FrameVerdict : std::uint8_t {
    Accepted,   // the frame's pages are taken
    NotServed,  // n == 0: ask another peer, no verdict
    Defer,      // at's header or root not held: fetch, judge the frame again
    Drop,       // no verdict, no token
    Refused,    // the server is struck once
};

enum class BucketsFault : std::uint8_t {
    None,
    OverBuffer,    // DROP: the frame is above the buffer (P-39)
    Unsolicited,   // DROP: another at, or a server already refused / abandoned for this request
    AtUnknown,     // DEFER
    RootUnknown,   // DEFER
    Wire,          // the bytes do not decode (BucketsWireError)
    LeafCount,     // leaf_count != leaf_count(at)
    Peaks,         // the peaks do not bag to the root under leaf_count
    SChanged,      // S_parent differs from an earlier frame of the same server
    SParent,       // S_parent does not fold with at's receipts_root
    RefOrder,      // references not strictly ascending by identity
    RefPoint,      // a reference key does not decompress
    BinRange,      // an entry beyond bin_hi
    LeafIndex,     // bin below b0 or not a leaf at leaf_count(at); bin_lo != b0 + leaf_index; bin_hi != bin_lo
    Proof,         // the MMR proof of the LeafPayload fails
    RowsTotal,     // rows_total against raw_sum / d_min
    Order,         // the entry is not the server's next (bin, row_first)
    PageConflict,  // rows_total differs between pages of one bin
    PageRange,     // row_first + n_rows > rows_total, or an empty page of a non-empty bin
    RefMissing,    // a row identity without a reference
    RefStray,      // a reference whose identity is not in the frame's rows
    Bucket,        // the completed bucket fails bucket_check (BucketFault)
};

struct FrameOutcome {
    FrameVerdict verdict = FrameVerdict::Accepted;
    BucketsFault fault = BucketsFault::None;
    BucketsWireError wire = BucketsWireError::None;
    BucketFault bucket = BucketFault::None;
    std::uint32_t strike = 0;           // strike tokens for the server (1 on Refused)
    std::uint64_t bins_completed = 0;   // bins this frame completed
};

// A sealed bin received and verified: the bucket with its rows, its MMR leaf,
// and the references of its identities (ascending by identity).
struct ServedBin {
    L1Bucket bucket;
    Hash32 leaf{};
    std::vector<XmrKeyRef> refs;
};

struct SResolution {
    bool pending = true;                      // at's carried ids not held
    std::optional<RatchetState> adopted;      // the S of a server whose S folds
    std::vector<std::uint64_t> struck;        // servers whose S does not fold (one token each)
};

// One FC_GETBUCKETS request and the frames answering it, from any number of servers.
class BucketsAssembly {
public:
    BucketsAssembly(const GetBuckets& req, std::uint64_t b0, std::uint64_t F, std::uint64_t frame_bytes)
        : req_(req), b0_(b0), f_(F), frame_bytes_(frame_bytes) {}

    const GetBuckets& request() const noexcept { return req_; }

    FrameOutcome add_frame(std::uint64_t server, std::span<const std::uint8_t> frame, const BucketsAnchor& a) {
        if (frame.size() > frame_bytes_) {
            servers_[server].closed = true;
            return drop(BucketsFault::OverBuffer);
        }
        Server& src = servers_[server];
        if (src.closed) return drop(BucketsFault::Unsolicited);
        BucketsFrameView v;
        if (BucketsWireError e = decode_buckets_view(frame, req_.chain_id, v); e != BucketsWireError::None) {
            FrameOutcome o = refuse(src, BucketsFault::Wire);
            o.wire = e;
            return o;
        }
        if (v.at != req_.at) return drop(BucketsFault::Unsolicited);
        if (v.entries.empty()) return FrameOutcome{FrameVerdict::NotServed};
        if (!a.header_held) return defer(BucketsFault::AtUnknown);
        const std::uint64_t lc = bin_leaf_count(a.record, b0_, f_);
        if (v.leaf_count != lc) return refuse(src, BucketsFault::LeafCount);
        if (!a.mmr_root) return defer(BucketsFault::RootUnknown);
        const Hash32 root = a.mmr_root.value_or(kZeroHash);
        if (!peaks_match_root(v.peaks, v.leaf_count, root)) return refuse(src, BucketsFault::Peaks);
        if (src.s && *src.s != v.s_parent) return refuse(src, BucketsFault::SChanged);
        if (a.carried_ids && !s_folds(a, v.s_parent)) return refuse(src, BucketsFault::SParent);

        // references: strictly ascending by identity, decompressing
        std::vector<Hash32> ref_ids;
        ref_ids.reserve(v.refs.size());
        for (const XmrKeyRef& k : v.refs) {
            const Hash32 id = key_ref_identity(k);
            if (!ref_ids.empty() && !(ref_ids.back() < id)) return refuse(src, BucketsFault::RefOrder);
            if (!key_ref_points_valid(k)) return refuse(src, BucketsFault::RefPoint);
            ref_ids.push_back(id);
        }

        // entries: every check before the rows are allocated
        Next nx = src.next.value_or(Next{req_.bin_lo, 0});
        std::map<std::uint64_t, std::uint32_t> totals = src.totals;
        for (const BucketEntryView& e : v.entries) {
            if (nx.bin > req_.bin_hi) return refuse(src, BucketsFault::BinRange);
            if (nx.bin < b0_ || nx.bin - b0_ >= v.leaf_count) return refuse(src, BucketsFault::LeafIndex);
            const std::uint64_t leaf_index = nx.bin - b0_;
            if (e.payload.bin_lo != b0_ + leaf_index) return refuse(src, BucketsFault::LeafIndex);
            if (e.payload.bin_hi != e.payload.bin_lo) return refuse(src, BucketsFault::LeafIndex);
            if (!mmr_verify(root, mmr_leaf_of(e.payload), wire_proof(leaf_index, v.leaf_count, e.path, v.peaks)))
                return refuse(src, BucketsFault::Proof);
            if (!rows_total_ok(e.payload, e.rows_total)) return refuse(src, BucketsFault::RowsTotal);
            if (e.row_first != nx.row_first) return refuse(src, BucketsFault::Order);
            if (const auto t = totals.find(nx.bin); t != totals.end() && t->second != e.rows_total)
                return refuse(src, BucketsFault::PageConflict);
            if (std::uint64_t{e.row_first} + e.n_rows > e.rows_total) return refuse(src, BucketsFault::PageRange);
            if (e.n_rows == 0 && e.rows_total != 0) return refuse(src, BucketsFault::PageRange);
            totals[nx.bin] = e.rows_total;
            nx = std::uint64_t{e.row_first} + e.n_rows == e.rows_total
                         ? Next{nx.bin + 1, 0}
                         : Next{nx.bin, e.row_first + e.n_rows};
        }

        // rows (allocated only now)
        std::vector<std::vector<BucketRow>> page_rows(v.entries.size());
        std::vector<BucketRow> frame_rows;
        for (std::size_t i = 0; i < v.entries.size(); ++i) {
            const BucketEntryView& e = v.entries[i];
            page_rows[i].reserve(e.n_rows);
            for (std::size_t k = 0; k < e.n_rows; ++k)
                page_rows[i].push_back(decode_bucket_row(e.rows + k * kBucketRowBytes));
            rows_allocated_ += e.n_rows;
            frame_rows.insert(frame_rows.end(), page_rows[i].begin(), page_rows[i].end());
        }
        const std::set<Hash32> ids = row_identities(frame_rows);
        std::map<Hash32, XmrKeyRef> frame_refs;
        for (std::size_t r = 0; r < v.refs.size(); ++r) frame_refs.emplace(ref_ids[r], v.refs[r]);
        for (const Hash32& id : ids)
            if (frame_refs.count(id) == 0) return refuse(src, BucketsFault::RefMissing);
        for (const auto& [id, k] : frame_refs)
            if (ids.count(id) == 0) return refuse(src, BucketsFault::RefStray);

        // pages -> bins; a bin complete from this server is checked before anything is kept
        std::map<std::uint64_t, std::vector<BucketRow>> rows = src.rows;
        std::map<std::uint64_t, L1Bucket> payloads = src.payloads;
        std::vector<std::uint64_t> completed;
        for (std::size_t i = 0; i < v.entries.size(); ++i) {
            const BucketEntryView& e = v.entries[i];
            const std::uint64_t bin = e.payload.bin_lo;
            payloads[bin] = e.payload;
            std::vector<BucketRow>& acc = rows[bin];
            acc.insert(acc.end(), page_rows[i].begin(), page_rows[i].end());
            if (acc.size() == e.rows_total) completed.push_back(bin);
        }
        std::map<std::uint64_t, ServedBin> done;
        for (std::uint64_t bin : completed) {
            ServedBin sb;
            sb.bucket = payloads[bin];
            sb.bucket.rows = std::move(rows[bin]);
            if (const BucketFault bf = bucket_check(sb.bucket); bf != BucketFault::None) {
                FrameOutcome o = refuse(src, BucketsFault::Bucket);
                o.bucket = bf;
                return o;
            }
            sb.leaf = mmr_leaf_of(sb.bucket);
            for (const Hash32& id : row_identities(sb.bucket.rows)) {
                const auto in_frame = frame_refs.find(id);
                sb.refs.push_back(in_frame != frame_refs.end() ? in_frame->second : src.refs.at(id));
            }
            done.emplace(bin, std::move(sb));
            rows.erase(bin);
            payloads.erase(bin);
            totals.erase(bin);
        }

        // commit
        src.next = nx;
        src.totals = std::move(totals);
        src.rows = std::move(rows);
        src.payloads = std::move(payloads);
        src.s = v.s_parent;
        for (const auto& [id, k] : frame_refs) {
            src.refs.emplace(id, k);
            refs_.emplace(id, k);
        }
        FrameOutcome o;
        for (auto& [bin, sb] : done)
            if (bins_.emplace(bin, std::move(sb)).second) ++o.bins_completed;
        return o;
    }

    // A server whose page did not arrive in time: its pages are discarded and its
    // later frames for this request are dropped; the request goes to another server.
    void abandon(std::uint64_t server) {
        Server& s = servers_[server];
        s.closed = true;
        s.rows.clear();
        s.payloads.clear();
        s.totals.clear();
    }

    // The bins received and verified, by bin.
    const std::map<std::uint64_t, ServedBin>& bins() const noexcept { return bins_; }
    // The first bin from bin_lo not yet received (bin_hi + 1 when complete).
    std::uint64_t complete_through() const {
        std::uint64_t b = req_.bin_lo;
        while (b <= req_.bin_hi && bins_.count(b) != 0) ++b;
        return b;
    }
    bool complete() const { return complete_through() > req_.bin_hi; }
    // References of accepted frames, by identity.
    const std::map<Hash32, XmrKeyRef>& refs() const noexcept { return refs_; }
    // Rows allocated so far (a row is allocated only after its entry's checks).
    std::uint64_t rows_allocated() const noexcept { return rows_allocated_; }

    // S_parent(at) of the servers whose frames were accepted, once at's carried
    // ids are held: a server whose S does not fold with at's receipts_root is
    // struck once.
    SResolution resolve_s(const BucketsAnchor& a) {
        SResolution out;
        if (!a.carried_ids) return out;
        out.pending = false;
        for (auto& [id, s] : servers_) {
            if (!s.s || s.s_judged) continue;
            s.s_judged = true;
            if (s_folds(a, *s.s)) {
                if (!out.adopted) out.adopted = decode_ratchet_state(*s.s);
            } else {
                out.struck.push_back(id);
            }
        }
        return out;
    }

    // true while an accepted S_parent waits for at's carried ids.
    bool s_pending() const {
        for (const auto& [id, s] : servers_)
            if (s.s && !s.s_judged) return true;
        return false;
    }

private:
    struct Next {
        std::uint64_t bin = 0;
        std::uint32_t row_first = 0;
    };
    struct Server {
        bool closed = false;
        std::optional<Next> next;
        std::map<std::uint64_t, std::uint32_t> totals;          // rows_total per incomplete bin
        std::map<std::uint64_t, std::vector<BucketRow>> rows;   // rows of incomplete bins
        std::map<std::uint64_t, L1Bucket> payloads;             // their LeafPayloads
        std::map<Hash32, XmrKeyRef> refs;                       // references of accepted frames
        std::optional<RatchetStateBytes> s;
        bool s_judged = false;
    };

    static bool s_folds(const BucketsAnchor& a, const RatchetStateBytes& s) {
        return check_carried_fold(a.receipts_root, *a.carried_ids, decode_ratchet_state(s)) == FoldVerdict::Match;
    }

    static FrameOutcome drop(BucketsFault f) { return FrameOutcome{FrameVerdict::Drop, f}; }
    static FrameOutcome defer(BucketsFault f) { return FrameOutcome{FrameVerdict::Defer, f}; }
    FrameOutcome refuse(Server& s, BucketsFault f) {
        s.closed = true;
        s.rows.clear();
        s.payloads.clear();
        s.totals.clear();
        s.s.reset();
        FrameOutcome o{FrameVerdict::Refused, f};
        o.strike = 1;
        return o;
    }

    GetBuckets req_;
    std::uint64_t b0_;
    std::uint64_t f_;
    std::uint64_t frame_bytes_;
    std::map<std::uint64_t, Server> servers_;
    std::map<std::uint64_t, ServedBin> bins_;
    std::map<Hash32, XmrKeyRef> refs_;
    std::uint64_t rows_allocated_ = 0;
};

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------
// What a server holds for `at` on its best chain.
struct BucketServeSource {
    std::uint64_t b0 = 0;
    std::uint64_t leaf_count = 0;                                   // leaf_count(at); 0: nothing to serve
    const BinMmr* mmr = nullptr;                                    // proves leaves below leaf_count
    std::function<const SealedBin*(std::uint64_t bin)> bucket;      // a sealed bin's body; nullptr when not held
    RatchetStateBytes s_parent{};                                   // S at at's parent
};

namespace bw_detail {

inline std::uint64_t head_bytes(std::size_t n_peaks) { return kBucketsHeadBytes + n_peaks * kHashBytes + kBucketsMidBytes + kBucketsEntryCountBytes; }
inline std::uint64_t entry_head_bytes(std::size_t path_len) { return kEntryFixedBytes + path_len * kHashBytes; }

// true when every identity of the bin's rows has a reference.
inline bool refs_complete(const SealedBin& sb, std::map<Hash32, XmrKeyRef>& by_id) {
    std::map<Hash32, XmrKeyRef> held;
    for (const XmrKeyRef& k : sb.refs) held.emplace(key_ref_identity(k), k);
    for (const Hash32& id : row_identities(sb.bucket.rows)) {
        const auto it = held.find(id);
        if (it == held.end()) return false;
        by_id.emplace(id, it->second);
    }
    return true;
}

}  // namespace bw_detail

// The FC_BUCKETS frames answering req from src, each at most frame_bytes; one
// not-served frame when nothing can be served.
inline std::vector<std::vector<std::uint8_t>> serve_buckets_from(const BucketServeSource& src, const GetBuckets& req,
                                                                 std::uint64_t frame_bytes) {
    const std::vector<std::vector<std::uint8_t>> none{encode_buckets_not_served(req.chain_id, req.at)};
    if (src.leaf_count == 0 || src.mmr == nullptr || req.bin_lo > req.bin_hi) return none;
    const std::optional<std::vector<Hash32>> peaks = src.mmr->prefix_peaks(src.leaf_count);
    if (!peaks) return none;

    struct Served {
        const SealedBin* sb;
        std::vector<Hash32> path;
    };
    std::vector<Served> served;
    std::map<Hash32, XmrKeyRef> by_id;
    for (std::uint64_t bin = req.bin_lo; bin <= req.bin_hi; ++bin) {
        // leaf_index = bin - b0; a bin below b0 wraps to an index no MMR proves
        const std::uint64_t i = bin - src.b0;
        const std::optional<MmrProof> pr = src.mmr->prefix_proof(i, src.leaf_count);
        if (!pr) break;  // not provable at leaf_count(at)
        const SealedBin* sb = src.bucket ? src.bucket(bin) : nullptr;
        if (sb == nullptr) break;  // rows not held
        if (sb->bucket.bin_lo != bin || src.mmr->leaf(i) != std::optional<Hash32>(sb->leaf)) break;  // not the leaf's body
        std::map<Hash32, XmrKeyRef> ids = by_id;
        if (!bw_detail::refs_complete(*sb, ids)) break;  // an identity without its reference
        Served s{sb, {}};
        for (const auto& step : pr->path) s.path.push_back(step.first);
        served.push_back(std::move(s));
        by_id = std::move(ids);
        if (bin == UINT64_MAX) break;
    }

    const std::uint64_t head = bw_detail::head_bytes(peaks->size());
    std::vector<std::vector<std::uint8_t>> frames;
    BucketsReply cur;
    std::set<Hash32> cur_ids;
    std::uint64_t cur_bytes = head;
    const auto fresh = [&] {
        cur = BucketsReply{};
        cur.chain_id = req.chain_id;
        cur.at = req.at;
        cur.leaf_count = src.leaf_count;
        cur.peaks = *peaks;
        cur.s_parent = src.s_parent;
        cur_ids.clear();
        cur_bytes = head;
    };
    const auto flush = [&] {
        if (!cur.entries.empty()) {
            for (const Hash32& id : cur_ids) cur.refs.push_back(by_id.at(id));
            frames.push_back(*encode_buckets(cur));
        }
        fresh();
    };
    const auto row_cost = [&](const BucketRow& r) {
        std::uint64_t c = kBucketRowBytes;
        if (cur_ids.count(r.miner) == 0) c += kKeyRefBytes;
        if (!(r.owner == kZeroHash) && cur_ids.count(r.owner) == 0 && r.owner != r.miner) c += kKeyRefBytes;
        return c;
    };
    fresh();
    for (const Served& s : served) {
        const std::vector<BucketRow>& rows = s.sb->bucket.rows;
        const std::uint64_t eh = bw_detail::entry_head_bytes(s.path.size());
        const std::uint64_t one_row = rows.empty() ? 0 : kBucketRowBytes + 2 * kKeyRefBytes;
        if (head + eh + one_row > frame_bytes || rows.size() > UINT32_MAX) break;  // an empty frame cannot hold it
        std::size_t k = 0;
        do {
            const std::uint64_t first = k < rows.size() ? row_cost(rows[k]) : 0;
            if (cur_bytes + eh + first > frame_bytes || cur.entries.size() == kMaxEntriesPerFrame) flush();
            BucketEntry e;
            e.payload = s.sb->bucket;
            e.payload.rows.clear();
            e.rows_total = static_cast<std::uint32_t>(rows.size());
            e.row_first = static_cast<std::uint32_t>(k);
            e.path = s.path;
            cur_bytes += eh;
            while (k < rows.size() && e.rows.size() < kMaxRowsPerEntry) {
                const std::uint64_t c = row_cost(rows[k]);
                if (cur_bytes + c > frame_bytes) break;
                cur_bytes += c;
                cur_ids.insert(rows[k].miner);
                if (!(rows[k].owner == kZeroHash)) cur_ids.insert(rows[k].owner);
                e.rows.push_back(rows[k]);
                ++k;
            }
            cur.entries.push_back(std::move(e));
            if (k < rows.size()) flush();
        } while (k < rows.size());
    }
    flush();
    if (frames.empty()) return none;
    return frames;
}

// The serving rule over the node's BinStore: `at` on the best chain (at or
// below its tip); S_parent(at) from the caller (the ratchet state at at's
// parent; nullopt: not served).
inline std::vector<std::vector<std::uint8_t>> serve_buckets(const BinStore& store, const GetBuckets& req,
                                                            const std::optional<RatchetStateBytes>& s_parent,
                                                            std::uint64_t frame_bytes) {
    const LaneView view = store.view_at(req.at);
    if (!view.ok()) return {encode_buckets_not_served(req.chain_id, req.at)};
    if (view.fork_pos() != view.pos()) return {encode_buckets_not_served(req.chain_id, req.at)};  // best chain only
    if (!s_parent) return {encode_buckets_not_served(req.chain_id, req.at)};
    BucketServeSource src;
    src.b0 = store.b0();
    src.leaf_count = view.leaf_count();
    src.mmr = &store.best_mmr();
    src.bucket = [&view](std::uint64_t bin) { return view.bucket(bin); };
    src.s_parent = s_parent.value_or(RatchetStateBytes{});
    return serve_buckets_from(src, req, frame_bytes);
}

// ---------------------------------------------------------------------------
// Per-peer serving budget (P-41, P-42): a request over budget is DROPPED, no
// verdict. now_s is the caller's monotonic clock in seconds.
// ---------------------------------------------------------------------------
class BucketServeBudget {
public:
    explicit BucketServeBudget(const BucketWirePolicy& p) : p_(p) {}

    // true: serve the request (counted in flight until done()); false: DROP.
    bool admit(std::uint64_t peer, std::uint64_t now_s) {
        Peer& s = peers_[peer];
        roll(s, now_s);
        if (s.inflight >= p_.inflight) return false;
        if (s.bytes >= p_.bytes_per_minute) return false;
        ++s.inflight;
        return true;
    }

    void sent(std::uint64_t peer, std::uint64_t bytes, std::uint64_t now_s) {
        Peer& s = peers_[peer];
        roll(s, now_s);
        s.bytes = bytes > UINT64_MAX - s.bytes ? UINT64_MAX : s.bytes + bytes;
    }

    void done(std::uint64_t peer) {
        const auto it = peers_.find(peer);
        if (it != peers_.end() && it->second.inflight > 0) --it->second.inflight;
    }

    std::uint64_t inflight(std::uint64_t peer) const {
        const auto it = peers_.find(peer);
        return it == peers_.end() ? 0 : it->second.inflight;
    }

private:
    struct Peer {
        bool started = false;
        std::uint64_t window_start = 0;
        std::uint64_t bytes = 0;
        std::uint64_t inflight = 0;
    };

    static void roll(Peer& s, std::uint64_t now_s) {
        if (!s.started || now_s - s.window_start >= kSecondsPerMinute || now_s < s.window_start) {
            s.started = true;
            s.window_start = now_s;
            s.bytes = 0;
        }
    }

    BucketWirePolicy p_;
    std::map<std::uint64_t, Peer> peers_;
};

}  // namespace c2pool::xmr::pathb
