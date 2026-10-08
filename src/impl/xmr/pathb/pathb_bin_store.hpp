// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_bin_store.hpp
// Path B, slice S3b-1a: the bin store per held branch, the seal driver and the
// crash-consistent lane records.
//
//   BinStore        every held carrier inside the journal (J positions, P-01),
//                   each with its delta {placements at its position, bins
//                   sealed there, leaf_count and mmr root after it}; the best
//                   chain's state is materialised (records H, placements per
//                   bin, placed ids, buckets, the MMR).
//   view_at(x)      the lane state of x's own chain through x: the best
//                   chain's state through the fork point plus x's side deltas.
//                   A fork point below the journal is Deep (DEFER); a view is
//                   never taken from another branch.
//   ingest(c, r)    r placed by carrier c at q = pos(c), read on c's chain at
//                   its parent:
//                     Expired    the origin bin is sealed: !open_at(H(q - 1),
//                                h(r), F), or h(r) < b0 (a bin without a leaf)
//                     Duplicate  the id is placed on c's chain (S2.3 #8)
//                     Accepted   otherwise; #17 (delta 1) is decided here on
//                                the placing chain; a dead placement is kept
//                                for dedup and never enters S(b)
//                   A carrier is ingested as its carried list (canonical
//                   order), then itself; then seal(c).
//   seal(c)         every bin b with lc(H(parent(c))) <= b - b0 < lc(H(c))
//                   seals at c, in bin order: S(b) = the live placements of bin
//                   b on c's chain with q <= pos(c) (D_fin 0, K06); one leaf per
//                   bin, a bin without a live receipt appends the E-8 empty leaf;
//                   leaf_index = b - b0.
//   lc(H)           = max(0, H - F - b0 + 1)                (E-8; P-3 = ruling 31)
//   mmr_root_at(t)  = the root over the first lc(H(t)) leaves of t's chain.
//   switch_best(t)  rewinds the materialised state to the fork point (records,
//                   placements, placed ids, buckets, the MMR truncated) and
//                   replays t's deltas; fills one record batch.
//   retention       P-37 / P-38 (policy, ruling 23): by default every placement
//                   and every sealed bucket body is kept (leaf hashes always).
//                   A node may drop the placements of bins below a floor (at
//                   most min(H(L - J), H(L) - F - Fresh) - F - Fresh + 1, L the
//                   best tip) and the bucket bodies of bins below a floor; a
//                   read of a dropped bin is MissingEntries / MissingBucket
//                   (DEFER), never an empty bin. restore_bucket takes a served
//                   body back when it hashes to the held leaf.
//
// Lane records (node-local; a different layout forks nothing). Kinds proposed
// for the store census (registered by S4): K_BMMR 11, K_BLEAF 12, K_BLHASH 13.
//   v37s:bmmr:<chain %010u>                       K_BMMR
//     hdr | u64 b0 | u64 leaf_count | root[32] | u32 n_peaks | n_peaks x peak[32]
//         | u64 tip_pos | tip_id[32]
//   v37s:blhash:<chain %010u>:<leaf_index %020u>  K_BLHASH   hdr | leaf[32]
//   v37s:bleaf:<chain %010u>:<leaf_index %020u>   K_BLEAF
//     hdr | LeafPayload v1 (96) | u32 n_rows | n_rows x row (160) | u32 n_refs
//         | n_refs x key_ref (66)
//   One batch per best-chain change (with the carrier record, the caller's):
//   deletes K_BLHASH / K_BLEAF from lc(fork), writes the new branch's leaves and
//   K_BMMR. load_lane: K_BMMR.tip == the carrier store's tip; leaf_count ==
//   lc(H(tip_pos)); the MMR over K_BLHASH [0, leaf_count) == K_BMMR.root; every
//   K_BLEAF held hashes to its K_BLHASH and decodes consistent; any failure
//   refuses (the caller discards the lane store and rebuilds); records at or
//   beyond leaf_count are ignored and deleted.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "sharechain/v37/v37_hash.hpp"  // ::v37::sha256d

#include "pathb_buckets.hpp"
#include "pathb_params.hpp"
#include "pathb_receipt_admission.hpp"  // open_at, live
#include "pathb_retarget.hpp"           // record_height, carrier_height_admissible
#include "pathb_window.hpp"             // WinEntry, detail_win::rows_of
#include "pathb_wire_v3.hpp"            // XmrKeyRef, key_ref_identity, kPayeeKindXmrStd

namespace c2pool::xmr::pathb {

// ---------------------------------------------------------------------------
// The dense leaf count (E-8; P-3 = ruling 31): a chain whose record is H has
// sealed the bins b0 .. H - F, one leaf each.
// ---------------------------------------------------------------------------
inline constexpr std::uint64_t bin_leaf_count(std::uint64_t H, std::uint64_t b0, std::uint64_t F) noexcept {
    if (H < b0 || H - b0 < F) return 0;
    return H - F - b0 + 1;
}

// ---------------------------------------------------------------------------
// S(b) -> the sealed L1 bucket (E-8; P-2 = ruling 31): rows =
// rows_of(entries); raw_sum = the sum of work; miner_count = distinct row.miner;
// d_min = the smallest live receipt work; no entry -> the E-8 empty bucket.
// Every committed field is computed from the entries, none is an input.
// ---------------------------------------------------------------------------
inline L1Bucket seal_from_entries(std::uint64_t bin, const std::vector<WinEntry>& entries) {
    L1Bucket b;
    b.bin_lo = bin;
    b.bin_hi = bin;
    b.rows = detail_win::rows_of(entries);
    bool first = true;
    for (const WinEntry& e : entries) {
        b.raw_sum += Work(e.work);
        if (first || e.work < b.d_min) b.d_min = e.work;
        first = false;
    }
    b.miner_count = miner_count_of(b.rows);
    b.comp_root_v = comp_root(b.rows);
    return b;
}

// ---------------------------------------------------------------------------
// Placements, deltas, verdicts
// ---------------------------------------------------------------------------
struct Placement {
    Hash32 id{};                         // receipt_id = keccak256(hashing_blob)
    std::uint64_t bin = 0;               // origin bin b = h(r)
    std::uint64_t q = 0;                 // placing position (set by ingest)
    std::uint64_t p_own = 0;             // p(r), own position (the caller's, through off-chain tips)
    Hash32 payee{};                      // identities; owner zero iff p == 0
    Hash32 owner{};
    std::uint16_t p = 0;
    std::uint16_t give_author_bp = 0;
    std::uint64_t work = 0;              // work(T_origin), R-1 (checked at #11)
    bool live = false;                   // #17 at placement on the placing chain (set by ingest)
    Hash32 carrier{};                    // the placing carrier (set by ingest)
    std::optional<XmrKeyRef> payee_ref;  // key references when held (K_BLEAF table)
    std::optional<XmrKeyRef> owner_ref;
};

inline WinEntry win_entry_of(const Placement& x) {
    WinEntry e;
    e.miner = x.payee;
    e.owner = x.owner;
    e.work = x.work;
    e.p = x.p;
    e.give_author_bp = x.give_author_bp;
    e.position = x.q;
    e.id = x.id;
    return e;
}

struct SealedBin {
    L1Bucket bucket;
    Hash32 leaf{};                // mmr_leaf_of(bucket)
    std::uint64_t sealed_at = 0;  // the fold position on its chain (not a record field)
    std::vector<XmrKeyRef> refs;  // key references of the bucket's identities, ascending by identity
    bool held = true;             // the body (rows, references) is held; the leaf always is (P-38)
};

// ---------------------------------------------------------------------------
// Retention (policy, ruling 23). Defaults keep everything.
//   P-37 placements: kept for every bin; a floor drops the placements of the
//        bins below it, clamped to min(H(L - J), H(L) - F - Fresh) - F - Fresh
//        + 1. Flag --pathb-entry-retention.
//   P-38 bucket bodies: kept for every sealed bin from b0, leaf hashes always;
//        a floor drops the bodies of the bins below it. Flag
//        --pathb-bucket-retention.
// A read of a dropped bin is a DEFER (MissingEntries / MissingBucket); the
// verdicts do not depend on either value.
// ---------------------------------------------------------------------------
struct LaneRetention {
    std::uint64_t entry_keep_from = 0;   // keep the placements of bins >= this (0: every bin)
    std::uint64_t bucket_keep_from = 0;  // keep the bucket bodies of bins >= this (0: every bin)
};
inline constexpr LaneRetention kLaneRetentionDefault{};
inline constexpr std::string_view kEntryRetentionFlag = "--pathb-entry-retention";
inline constexpr std::string_view kBucketRetentionFlag = "--pathb-bucket-retention";

// The key references of a bucket: strictly ascending by identity, each the
// identity of one of its rows (miner or owner).
inline bool refs_bound_to_rows(const std::vector<BucketRow>& rows, const std::vector<XmrKeyRef>& refs) {
    std::set<Hash32> row_ids;
    for (const BucketRow& row : rows) {
        row_ids.insert(row.miner);
        if (!(row.owner == kZeroHash)) row_ids.insert(row.owner);
    }
    Hash32 prev{};
    for (std::size_t i = 0; i < refs.size(); ++i) {
        const Hash32 id = key_ref_identity(refs[i]);
        if (i > 0 && !(prev < id)) return false;
        if (row_ids.count(id) == 0) return false;
        prev = id;
    }
    return true;
}

// One held carrier: its position, record and what it changed on its chain.
struct LaneDelta {
    Hash32 id{};
    Hash32 parent{};
    std::uint64_t pos = 0;
    std::uint64_t h = 0;             // template height
    std::uint64_t H = 0;             // record at pos on its chain
    std::vector<Placement> placed;   // q = pos: the carried list, then the carrier
    std::vector<SealedBin> sealed;   // bins sealed at pos, bin order
    std::uint64_t leaf_count = 0;    // after pos
    Hash32 root{};                   // mmr root after pos (the journal's root per position)
    bool sealed_done = false;        // seal() ran; no further placement
};

enum class Ingest : std::uint8_t { Accepted, Duplicate, Expired };

enum class AddVerdict : std::uint8_t {
    Added,
    Duplicate,      // already held
    ParentUnknown,  // DEFER + fetch (headers first), or the parent's seal has not run
    Deep,           // fork point below the journal: DEFER (rebuild), never judged
    NotCarrier,     // h(c) < H(parent)
};

// A carrier whose chain state cannot be read is never judged (no token).
inline constexpr bool add_defers(AddVerdict a) noexcept {
    return a == AddVerdict::ParentUnknown || a == AddVerdict::Deep;
}

enum class ViewStatus : std::uint8_t { Ok, Unknown, Deep };

enum class SwitchVerdict : std::uint8_t { Switched, Unknown, Deep, NotSealed };

class BinStore;

// ---------------------------------------------------------------------------
// LaneView: read-only state of ONE chain through carrier x (positions <= pos()).
// Valid until the store changes.
// ---------------------------------------------------------------------------
class LaneView {
public:
    ViewStatus status() const noexcept { return st_; }
    bool ok() const noexcept { return st_ == ViewStatus::Ok; }
    std::uint64_t pos() const noexcept { return pos_; }
    std::uint64_t fork_pos() const noexcept { return fork_; }

    // H(x) on this chain; x > pos() or a view that is not Ok throws (fails closed).
    std::uint64_t record(std::uint64_t x) const;
    // S2.3 #8: the id is placed on this chain in a bin still open at pos().
    bool placed_open(const Hash32& id) const;
    // The live placements of a bin on this chain with q <= q_max, by (q, list order).
    std::vector<const Placement*> live_entries(std::uint64_t bin, std::uint64_t q_max) const;
    // false when the placements of the bin are no longer held (P-37).
    bool entries_held(std::uint64_t bin) const;
    // Placements on this chain (live and dead), for counts.
    std::size_t placement_count() const;
    // The bucket of a bin sealed on this chain through pos(); nullptr if not
    // sealed or its body is not held (P-38).
    const SealedBin* bucket(std::uint64_t bin) const;
    std::uint64_t leaf_count_at(std::uint64_t x) const;
    Hash32 mmr_root_at(std::uint64_t x) const;
    std::uint64_t leaf_count() const { return leaf_count_at(pos_); }
    Hash32 mmr_root() const { return mmr_root_at(pos_); }

private:
    friend class BinStore;
    const BinStore* s_ = nullptr;
    ViewStatus st_ = ViewStatus::Unknown;
    std::uint64_t pos_ = 0;
    std::uint64_t fork_ = 0;                // the newest best-chain position of this chain
    std::vector<const LaneDelta*> side_;    // positions fork_ + 1 .. pos_, oldest first
};

// ---------------------------------------------------------------------------
// Lane records: keys, batches, codecs
// ---------------------------------------------------------------------------
inline constexpr std::uint8_t kLaneRecSchemaVer = 1;
inline constexpr std::uint8_t K_BMMR = 11;    // proposed RecordKind ids (S4 registers them)
inline constexpr std::uint8_t K_BLEAF = 12;
inline constexpr std::uint8_t K_BLHASH = 13;

namespace lane_keys {
inline std::string chain_fmt(std::uint32_t c) {
    char b[16];
    std::snprintf(b, sizeof b, "%010u", static_cast<unsigned>(c));
    return b;
}
inline std::string index_fmt(std::uint64_t i) {
    char b[24];
    std::snprintf(b, sizeof b, "%020llu", static_cast<unsigned long long>(i));
    return b;
}
inline std::string bmmr(std::uint32_t c) { return "v37s:bmmr:" + chain_fmt(c); }
inline std::string blhash_prefix(std::uint32_t c) { return "v37s:blhash:" + chain_fmt(c) + ":"; }
inline std::string bleaf_prefix(std::uint32_t c) { return "v37s:bleaf:" + chain_fmt(c) + ":"; }
inline std::string blhash(std::uint32_t c, std::uint64_t i) { return blhash_prefix(c) + index_fmt(i); }
inline std::string bleaf(std::uint32_t c, std::uint64_t i) { return bleaf_prefix(c) + index_fmt(i); }
// The leaf index of a key under prefix (20 decimal digits), nullopt otherwise.
inline std::optional<std::uint64_t> index_of(const std::string& key, const std::string& prefix) {
    if (key.size() != prefix.size() + 20 || key.compare(0, prefix.size(), prefix) != 0) return std::nullopt;
    std::uint64_t v = 0;
    for (std::size_t i = prefix.size(); i < key.size(); ++i) {
        const char ch = key[i];
        if (ch < '0' || ch > '9') return std::nullopt;
        const std::uint64_t d = static_cast<std::uint64_t>(ch - '0');
        if (v > (UINT64_MAX - d) / 10) return std::nullopt;
        v = v * 10 + d;
    }
    return v;
}
}  // namespace lane_keys

// A node-local write batch: ordered puts and deletes (nullopt), applied atomically.
struct LaneBatch {
    std::vector<std::pair<std::string, std::optional<std::string>>> ops;
    void put(std::string k, std::string v) { ops.emplace_back(std::move(k), std::move(v)); }
    void del(std::string k) { ops.emplace_back(std::move(k), std::nullopt); }
};

using LaneKv = std::map<std::string, std::string>;

inline void apply_batch(LaneKv& kv, const LaneBatch& b) {
    for (const auto& [k, v] : b.ops) {
        if (v)
            kv[k] = *v;
        else
            kv.erase(k);
    }
}

namespace lane_rec {

struct Writer {
    std::string s;
    void u8(std::uint8_t x) { s.push_back(static_cast<char>(x)); }
    void u32(std::uint32_t x) {
        for (int i = 0; i < 4; ++i) s.push_back(static_cast<char>((x >> (8 * i)) & 0xffu));
    }
    void u64(std::uint64_t x) {
        for (int i = 0; i < 8; ++i) s.push_back(static_cast<char>((x >> (8 * i)) & 0xffu));
    }
    template <std::size_t N>
    void bytes(const std::array<std::uint8_t, N>& b) {
        s.append(reinterpret_cast<const char*>(b.data()), b.size());
    }
    void hdr(std::uint8_t kind) {
        u8(kLaneRecSchemaVer);
        u8(kind);
    }
};

struct Reader {
    const std::string& s;
    std::size_t o = 0;
    bool ok = true;
    explicit Reader(const std::string& src) : s(src) {}
    std::size_t remaining() const noexcept { return o <= s.size() ? s.size() - o : 0; }
    bool need(std::size_t n) {
        if (!ok || n > remaining()) {
            ok = false;
            return false;
        }
        return true;
    }
    std::uint8_t u8() { return need(1) ? static_cast<std::uint8_t>(s[o++]) : 0; }
    std::uint32_t u32() {
        if (!need(4)) return 0;
        std::uint32_t x = 0;
        for (int i = 0; i < 4; ++i) x |= std::uint32_t{static_cast<std::uint8_t>(s[o++])} << (8 * i);
        return x;
    }
    std::uint64_t u64() {
        if (!need(8)) return 0;
        std::uint64_t x = 0;
        for (int i = 0; i < 8; ++i) x |= std::uint64_t{static_cast<std::uint8_t>(s[o++])} << (8 * i);
        return x;
    }
    template <std::size_t N>
    std::array<std::uint8_t, N> bytes() {
        std::array<std::uint8_t, N> b{};
        if (!need(N)) return b;
        for (std::size_t i = 0; i < N; ++i) b[i] = static_cast<std::uint8_t>(s[o++]);
        return b;
    }
    bool done() const noexcept { return ok && o == s.size(); }
};

// fail-closed on underrun, a newer schema or another kind.
inline bool read_hdr(Reader& r, std::uint8_t want_kind) {
    const std::uint8_t ver = r.u8();
    const std::uint8_t kind = r.u8();
    return r.ok && ver != 0 && ver <= kLaneRecSchemaVer && kind == want_kind;
}

inline Work work_from_le256(const std::array<std::uint8_t, 32>& b) {
    Work w;
    for (std::size_t limb = 0; limb < 4; ++limb) {
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < 8; ++i) v |= std::uint64_t{b[limb * 8 + i]} << (8 * i);
        w.v[limb] = v;
    }
    return w;
}

}  // namespace lane_rec

// K_BMMR: the lane's MMR head at the best tip.
struct BmmrHead {
    std::uint64_t b0 = 0;
    std::uint64_t leaf_count = 0;
    Hash32 root{};
    std::vector<Hash32> peaks;
    std::uint64_t tip_pos = 0;
    Hash32 tip_id{};
    friend bool operator==(const BmmrHead&, const BmmrHead&) = default;
};

inline std::string encode_bmmr(const BmmrHead& h) {
    lane_rec::Writer w;
    w.hdr(K_BMMR);
    w.u64(h.b0);
    w.u64(h.leaf_count);
    w.bytes(h.root);
    w.u32(static_cast<std::uint32_t>(h.peaks.size()));
    for (const Hash32& p : h.peaks) w.bytes(p);
    w.u64(h.tip_pos);
    w.bytes(h.tip_id);
    return w.s;
}

// The MMR law n_peaks == popcount(leaf_count) is enforced before allocating; the
// root must be the root of the peaks.
inline std::optional<BmmrHead> decode_bmmr(const std::string& v) {
    lane_rec::Reader r(v);
    if (!lane_rec::read_hdr(r, K_BMMR)) return std::nullopt;
    BmmrHead h;
    h.b0 = r.u64();
    h.leaf_count = r.u64();
    h.root = r.bytes<kHashBytes>();
    const std::uint32_t np = r.u32();
    if (!r.ok) return std::nullopt;
    if (np != popcount64(h.leaf_count)) return std::nullopt;
    if (np > r.remaining() / kHashBytes) return std::nullopt;
    h.peaks.resize(np);
    for (Hash32& p : h.peaks) p = r.bytes<kHashBytes>();
    h.tip_pos = r.u64();
    h.tip_id = r.bytes<kHashBytes>();
    if (!r.done()) return std::nullopt;
    if (mmr_root_of(h.leaf_count, h.peaks) != h.root) return std::nullopt;
    return h;
}

inline std::string encode_blhash(const Hash32& leaf) {
    lane_rec::Writer w;
    w.hdr(K_BLHASH);
    w.bytes(leaf);
    return w.s;
}

inline std::optional<Hash32> decode_blhash(const std::string& v) {
    lane_rec::Reader r(v);
    if (!lane_rec::read_hdr(r, K_BLHASH)) return std::nullopt;
    const Hash32 h = r.bytes<kHashBytes>();
    if (!r.done()) return std::nullopt;
    return h;
}

inline constexpr std::size_t kBucketRowBytes = 160;
inline constexpr std::size_t kLeafPayloadBytes = 96;
inline constexpr std::size_t kKeyRefRecordBytes = 2 + 2 * kHashBytes;  // kind | len | spend | view

inline std::string encode_bleaf(const SealedBin& sb) {
    lane_rec::Writer w;
    w.hdr(K_BLEAF);
    w.bytes(leaf_payload_bytes(sb.bucket));
    w.u32(static_cast<std::uint32_t>(sb.bucket.rows.size()));
    for (const BucketRow& r : sb.bucket.rows) w.bytes(bucket_row_bytes(r));
    w.u32(static_cast<std::uint32_t>(sb.refs.size()));
    for (const XmrKeyRef& ref : sb.refs) {
        w.u8(kPayeeKindXmrStd);
        w.u8(static_cast<std::uint8_t>(2 * kHashBytes));
        w.bytes(ref.spend);
        w.bytes(ref.view);
    }
    return w.s;
}

// K_BLEAF decoder: counts bounded by the bytes left before allocating; the
// bucket consistent with its rows; bin_lo == b0 + leaf_index; references
// strictly ascending by identity = xmr_identity_key(ref), each identity one of
// the bucket's row identities.
inline std::optional<SealedBin> decode_bleaf(const std::string& v, std::uint64_t leaf_index, std::uint64_t b0) {
    lane_rec::Reader r(v);
    if (!lane_rec::read_hdr(r, K_BLEAF)) return std::nullopt;
    SealedBin sb;
    L1Bucket& b = sb.bucket;
    b.bin_lo = r.u64();
    b.bin_hi = r.u64();
    b.raw_sum = lane_rec::work_from_le256(r.bytes<32>());
    b.miner_count = r.u64();
    b.d_min = r.u64();
    b.comp_root_v = r.bytes<kHashBytes>();
    const std::uint32_t n_rows = r.u32();
    if (!r.ok || n_rows > r.remaining() / kBucketRowBytes) return std::nullopt;
    b.rows.resize(n_rows);
    for (BucketRow& row : b.rows) {
        row.miner = r.bytes<kHashBytes>();
        row.owner = r.bytes<kHashBytes>();
        row.w_miner = lane_rec::work_from_le256(r.bytes<32>());
        row.w_owner = lane_rec::work_from_le256(r.bytes<32>());
        row.w_author = lane_rec::work_from_le256(r.bytes<32>());
    }
    const std::uint32_t n_refs = r.u32();
    if (!r.ok || n_refs > r.remaining() / kKeyRefRecordBytes) return std::nullopt;
    sb.refs.resize(n_refs);
    for (XmrKeyRef& ref : sb.refs) {
        const std::uint8_t kind = r.u8();
        const std::uint8_t len = r.u8();
        if (kind != kPayeeKindXmrStd || len != 2 * kHashBytes) return std::nullopt;
        ref.spend = r.bytes<kHashBytes>();
        ref.view = r.bytes<kHashBytes>();
    }
    if (!r.done()) return std::nullopt;
    if (!bucket_consistent(b)) return std::nullopt;
    if (b.bin_lo < b0 || b.bin_lo - b0 != leaf_index) return std::nullopt;
    if (!refs_bound_to_rows(b.rows, sb.refs)) return std::nullopt;
    sb.leaf = mmr_leaf_of(b);
    return sb;
}

// ---------------------------------------------------------------------------
// BinStore
// ---------------------------------------------------------------------------
class BinStore {
public:
    // Genesis carrier at position 0 with template height genesis_height; the
    // lane's first bin b0 = H(0) = genesis_height (P-3 = ruling 31); journal_depth
    // J (P-01); chain = the record key's chain id.
    BinStore(const LaneParams& p, std::uint64_t journal_depth, const Hash32& genesis_id, std::uint64_t genesis_height,
             std::uint32_t chain = 0)
        : p_(p), b0_(genesis_height), j_(journal_depth), chain_id_(chain) {
        LaneDelta g;
        g.id = genesis_id;
        g.parent = genesis_id;
        g.pos = 0;
        g.h = genesis_height;
        g.H = genesis_height;
        // bins sealed at genesis: lc(H(0)) = 0 for F >= 1 (b0 = H(0)).
        BinMmr m;
        for (std::uint64_t i = 0; i < bin_leaf_count(g.H, b0_, p_.open_bins); ++i) {
            SealedBin sb;
            sb.bucket = seal_from_entries(b0_ + i, {});
            sb.leaf = mmr_leaf_of(sb.bucket);
            m.append(sb.leaf);
            g.sealed.push_back(std::move(sb));
        }
        g.leaf_count = m.leaf_count();
        g.root = m.root();
        g.sealed_done = true;
        records_.push_back(g.H);
        chain_.push_back(g.id);
        chain_pos_[g.id] = 0;
        for (const SealedBin& sb : g.sealed) {
            mmr_.append(sb.leaf);
            buckets_.push_back(sb);
        }
        journal_.emplace(g.id, std::move(g));
    }

    const LaneParams& params() const noexcept { return p_; }
    std::uint64_t b0() const noexcept { return b0_; }
    std::uint64_t journal_depth() const noexcept { return j_; }
    std::uint64_t tip_pos() const noexcept { return chain_.size() - 1; }
    const Hash32& best_tip() const noexcept { return chain_.back(); }
    // The newest position the journal no longer holds deltas for (never moves
    // back: a rewind keeps it, as RewindJournal does).
    std::uint64_t base_pos() const noexcept {
        const std::uint64_t by_depth = tip_pos() > j_ ? tip_pos() - j_ : 0;
        return std::max(by_depth, floor_);
    }
    std::size_t journal_size() const noexcept { return journal_.size(); }
    const BinMmr& best_mmr() const noexcept { return mmr_; }

    bool holds(const Hash32& id) const { return journal_.count(id) != 0 || on_best(id); }

    const LaneDelta* delta(const Hash32& id) const {
        const auto it = journal_.find(id);
        return it == journal_.end() ? nullptr : &it->second;
    }

    LaneView view_at(const Hash32& x) const {
        LaneView v;
        v.s_ = this;
        if (const auto bi = chain_pos_.find(x); bi != chain_pos_.end() && chain_[bi->second] == x) {
            v.st_ = ViewStatus::Ok;
            v.pos_ = v.fork_ = bi->second;
            return v;
        }
        const auto it = journal_.find(x);
        if (it == journal_.end()) {
            v.st_ = ViewStatus::Unknown;
            return v;
        }
        std::vector<const LaneDelta*> path;
        const LaneDelta* d = &it->second;
        std::uint64_t fork = 0;
        for (;;) {
            path.push_back(d);
            if (on_best(d->parent)) {
                fork = chain_pos_.at(d->parent);
                break;
            }
            const auto pj = journal_.find(d->parent);
            if (pj == journal_.end()) {  // the side branch left the journal
                v.st_ = ViewStatus::Deep;
                return v;
            }
            d = &pj->second;
        }
        if (!fork_in_journal(fork)) {
            v.st_ = ViewStatus::Deep;
            return v;
        }
        std::reverse(path.begin(), path.end());
        v.side_ = std::move(path);
        v.pos_ = it->second.pos;
        v.fork_ = fork;
        v.st_ = ViewStatus::Ok;
        return v;
    }

    // A carrier announced on parent with template height h.
    AddVerdict add_carrier(const Hash32& id, const Hash32& parent, std::uint64_t h) {
        if (holds(id)) return AddVerdict::Duplicate;
        if (const LaneDelta* pd = delta(parent); pd && !pd->sealed_done) return AddVerdict::ParentUnknown;
        const LaneView pv = view_at(parent);
        if (pv.status() == ViewStatus::Unknown) return AddVerdict::ParentUnknown;
        if (pv.status() == ViewStatus::Deep || !fork_in_journal(pv.fork_pos())) return AddVerdict::Deep;
        const std::uint64_t parent_record = pv.record(pv.pos());
        if (!carrier_height_admissible(parent_record, h)) return AddVerdict::NotCarrier;
        LaneDelta d;
        d.id = id;
        d.parent = parent;
        d.pos = pv.pos() + 1;
        d.h = h;
        d.H = record_height(parent_record, h);
        journal_.emplace(id, std::move(d));
        return AddVerdict::Added;
    }

    // Places r in carrier c (S2.3 #7 before #8 on c's chain at its parent; #17).
    // nullopt: c is not held, its seal already ran, or the placements of r's
    // open bin are no longer held (P-37) (nothing is stored).
    std::optional<Ingest> ingest(const Hash32& carrier, Placement r) {
        const auto it = journal_.find(carrier);
        if (it == journal_.end() || it->second.sealed_done) return std::nullopt;
        LaneDelta& d = it->second;
        const LaneView pv = view_at(d.parent);  // c's own chain at its parent
        if (!pv.ok()) return std::nullopt;
        r.q = d.pos;
        r.carrier = carrier;
        const std::uint64_t record_parent = pv.record(pv.pos());  // H(q - 1) on c's chain
        if (r.bin < b0_ || !open_at(record_parent, r.bin, p_.open_bins)) return Ingest::Expired;
        if (r.bin < entry_floor_) return std::nullopt;  // placements not held (P-37): no verdict
        if (pv.placed_open(r.id)) return Ingest::Duplicate;
        for (const Placement& x : d.placed)
            if (x.id == r.id) return Ingest::Duplicate;
        r.live = live(r.bin, r.q, r.p_own, [&](std::uint64_t x) { return pv.record(x); });
        d.placed.push_back(std::move(r));
        return Ingest::Accepted;
    }

    // The seal driver at carrier c (after its placements). Returns the number of
    // bins sealed at c; nullopt when c is not held, its view is not Ok, a bin's
    // placements are not held (P-37) or a bucket fails bucket_consistent (then
    // nothing is sealed at c).
    std::optional<std::uint64_t> seal(const Hash32& carrier) {
        const auto it = journal_.find(carrier);
        if (it == journal_.end()) return std::nullopt;
        LaneDelta& d = it->second;
        if (d.sealed_done) return std::uint64_t{0};
        const LaneView pv = view_at(d.parent);
        if (!pv.ok()) return std::nullopt;
        const std::uint64_t lc_parent = pv.leaf_count();
        const std::uint64_t lc_new = bin_leaf_count(d.H, b0_, p_.open_bins);  // bound(c) = H(c) - F
        const std::uint64_t q_seal = d.pos;                                     // S(b): q <= f (D_fin 0)
        BinMmr m = chain_mmr(pv);
        std::vector<SealedBin> sealed;
        for (std::uint64_t i = lc_parent; i < lc_new; ++i) {
            const std::uint64_t b = b0_ + i;
            if (b < entry_floor_) return std::nullopt;  // S(b) not held (P-37): nothing is sealed
            std::vector<const Placement*> s_b = pv.live_entries(b, q_seal);
            for (const Placement& x : d.placed)
                if (x.bin == b && x.live && x.q <= q_seal) s_b.push_back(&x);
            std::vector<WinEntry> entries;
            entries.reserve(s_b.size());
            for (const Placement* x : s_b) entries.push_back(win_entry_of(*x));
            SealedBin sb;
            sb.bucket = seal_from_entries(b, entries);
            if (!bucket_consistent(sb.bucket)) return std::nullopt;  // asserted: nothing is sealed
            sb.leaf = mmr_leaf_of(sb.bucket);
            sb.sealed_at = d.pos;
            sb.refs = refs_of(s_b);
            m.append(sb.leaf);
            sealed.push_back(std::move(sb));
        }
        d.sealed = std::move(sealed);
        d.leaf_count = m.leaf_count();
        d.root = m.root();
        d.sealed_done = true;
        return lc_new > lc_parent ? lc_new - lc_parent : 0;
    }

    // Makes new_tip the best tip: rewind to the fork point, replay its deltas.
    // A fork point below the journal base (a best-chain ancestor included) is
    // Deep and changes nothing (as RewindJournal's RebuildRequired). The lane
    // records of the change go into *out (one batch).
    SwitchVerdict switch_best(const Hash32& new_tip, LaneBatch* out = nullptr) {
        const LaneView v = view_at(new_tip);
        if (v.status() == ViewStatus::Unknown) return SwitchVerdict::Unknown;
        if (!v.ok()) return SwitchVerdict::Deep;
        if (!fork_in_journal(v.fork_pos())) return SwitchVerdict::Deep;
        for (const LaneDelta* d : v.side_)
            if (!d->sealed_done) return SwitchVerdict::NotSealed;
        const std::uint64_t fork = v.fork_pos();
        const std::vector<const LaneDelta*> replay = v.side_;
        const std::uint64_t lc_old = mmr_.leaf_count();
        // every delta to rewind (tip .. fork + 1) is found before anything changes
        std::vector<const LaneDelta*> undo;
        for (std::uint64_t x = tip_pos(); x > fork; --x) {
            const auto it = journal_.find(chain_[x]);
            if (it == journal_.end()) throw std::logic_error("BinStore::switch_best: a delta to rewind is not held");
            undo.push_back(&it->second);
        }
        // rewind tip .. fork + 1
        for (const LaneDelta* dp : undo) {
            const LaneDelta& d = *dp;
            for (auto pl = d.placed.rbegin(); pl != d.placed.rend(); ++pl) {
                placed_q_.erase(pl->id);
                auto bit = by_bin_.find(pl->bin);
                if (bit == by_bin_.end()) continue;
                while (!bit->second.empty() && bit->second.back().q > fork) bit->second.pop_back();
                if (bit->second.empty()) by_bin_.erase(bit);
            }
            chain_pos_.erase(d.id);
        }
        chain_.resize(fork + 1);
        records_.resize(fork + 1);
        const std::uint64_t lc_fork = bin_leaf_count(records_[fork], b0_, p_.open_bins);
        mmr_.truncate(lc_fork);
        buckets_.resize(lc_fork);
        // replay fork + 1 .. new_tip
        for (const LaneDelta* d : replay) {
            chain_.push_back(d->id);
            records_.push_back(d->H);
            chain_pos_[d->id] = d->pos;
            for (const Placement& pl : d->placed) {
                by_bin_[pl.bin].push_back(pl);
                placed_q_[pl.id] = PlacedAt{pl.bin, pl.q};
            }
            for (const SealedBin& sb : d->sealed) {
                mmr_.append(sb.leaf);
                buckets_.push_back(sb);
            }
        }
        if (out) write_records(lc_fork, lc_old, *out);
        prune();
        return SwitchVerdict::Switched;
    }

    // ---- retention (P-37 / P-38) ----

    // The highest P-37 floor the best tip allows: min(H(L - J), H(L) - F -
    // Fresh) - F - Fresh + 1 (saturating; never below b0).
    std::uint64_t entry_floor_limit() const noexcept {
        const std::uint64_t span = p_.open_bins + p_.fresh_max;
        const std::uint64_t h_tip = records_.back();
        const std::uint64_t h_j = records_[tip_pos() > j_ ? tip_pos() - j_ : 0];
        const std::uint64_t a = std::min(h_j, h_tip > span ? h_tip - span : 0);
        const std::uint64_t x = a > span ? a - span : 0;
        return std::max(b0_, x + 1);
    }
    std::uint64_t entry_floor() const noexcept { return entry_floor_; }

    // Drops the placements of the best chain's bins below keep_from (clamped to
    // entry_floor_limit(); the floor never moves back). Returns the floor.
    std::uint64_t prune_entries(std::uint64_t keep_from) {
        const std::uint64_t to = std::min(keep_from, entry_floor_limit());
        if (to <= entry_floor_) return entry_floor_;
        entry_floor_ = to;
        for (auto it = by_bin_.begin(); it != by_bin_.end() && it->first < entry_floor_;) it = by_bin_.erase(it);
        for (auto it = placed_q_.begin(); it != placed_q_.end();) {
            if (it->second.bin < entry_floor_)
                it = placed_q_.erase(it);
            else
                ++it;
        }
        return entry_floor_;
    }

    // Drops the bodies of the best chain's sealed buckets of bins below
    // keep_from (the leaves stay). Returns the number of bodies dropped.
    std::size_t prune_buckets(std::uint64_t keep_from) {
        std::size_t n = 0;
        for (std::size_t i = 0; i < buckets_.size() && b0_ + i < keep_from; ++i) {
            SealedBin& sb = buckets_[i];
            if (!sb.held) continue;
            sb.held = false;
            sb.bucket.rows.clear();
            sb.bucket.rows.shrink_to_fit();
            sb.refs.clear();
            sb.refs.shrink_to_fit();
            ++n;
        }
        return n;
    }

    void apply_retention(const LaneRetention& r) {
        if (r.entry_keep_from > b0_) prune_entries(r.entry_keep_from);
        if (r.bucket_keep_from > b0_) prune_buckets(r.bucket_keep_from);
    }

    // A served body of a best-chain sealed bin whose body is not held: taken
    // back iff it is consistent, its references are bound to its rows and it
    // hashes to the held leaf.
    bool restore_bucket(const L1Bucket& b, const std::vector<XmrKeyRef>& refs) {
        if (b.bin_lo < b0_) return false;
        const std::uint64_t i = b.bin_lo - b0_;
        if (i >= buckets_.size() || buckets_[i].held) return false;
        if (!bucket_consistent(b) || !refs_bound_to_rows(b.rows, refs)) return false;
        if (mmr_leaf_of(b) != buckets_[i].leaf) return false;
        buckets_[i].bucket = b;
        buckets_[i].refs = refs;
        buckets_[i].held = true;
        return true;
    }

    // The K_BMMR head of the best tip.
    BmmrHead head() const {
        BmmrHead h;
        h.b0 = b0_;
        h.leaf_count = mmr_.leaf_count();
        h.root = mmr_.root();
        h.peaks = mmr_.peaks();
        h.tip_pos = tip_pos();
        h.tip_id = best_tip();
        return h;
    }

    // Every lane record of the best tip (the first write, or after a rebuild).
    void write_all(LaneBatch& out) const { write_records(0, 0, out); }

private:
    friend class LaneView;

    struct PlacedAt {
        std::uint64_t bin = 0;
        std::uint64_t q = 0;
    };

    bool on_best(const Hash32& id) const {
        const auto it = chain_pos_.find(id);
        return it != chain_pos_.end() && chain_[it->second] == id;
    }

    // A fork point the journal can rewind to (RewindJournal: base <= fork).
    bool fork_in_journal(std::uint64_t fork) const noexcept { return fork >= base_pos(); }

    // The MMR of the viewed chain through pos(): the best prefix at the fork
    // point plus the side deltas' leaves (O(log n) + side leaves).
    BinMmr chain_mmr(const LaneView& v) const {
        const std::uint64_t lc_fork = bin_leaf_count(records_[v.fork_pos()], b0_, p_.open_bins);
        BinMmr m = BinMmr::from_peaks(lc_fork, mmr_.prefix_peaks(lc_fork).value()).value();
        for (const LaneDelta* d : v.side_)
            for (const SealedBin& sb : d->sealed) m.append(sb.leaf);
        return m;
    }

    // Key references of S(b): one per identity held, ascending by identity.
    static std::vector<XmrKeyRef> refs_of(const std::vector<const Placement*>& s_b) {
        std::map<Hash32, XmrKeyRef> by_id;
        for (const Placement* x : s_b) {
            if (x->payee_ref && key_ref_identity(*x->payee_ref) == x->payee) by_id.emplace(x->payee, *x->payee_ref);
            if (x->owner_ref && !(x->owner == kZeroHash) && key_ref_identity(*x->owner_ref) == x->owner)
                by_id.emplace(x->owner, *x->owner_ref);
        }
        std::vector<XmrKeyRef> out;
        out.reserve(by_id.size());
        for (const auto& [id, ref] : by_id) out.push_back(ref);
        return out;
    }

    void write_records(std::uint64_t lc_from, std::uint64_t lc_old, LaneBatch& out) const {
        for (std::uint64_t i = lc_from; i < lc_old; ++i) {
            out.del(lane_keys::blhash(chain_id_, i));
            out.del(lane_keys::bleaf(chain_id_, i));
        }
        for (std::uint64_t i = lc_from; i < buckets_.size(); ++i) {
            out.put(lane_keys::blhash(chain_id_, i), encode_blhash(buckets_[i].leaf));
            if (buckets_[i].held)
                out.put(lane_keys::bleaf(chain_id_, i), encode_bleaf(buckets_[i]));
            else
                out.del(lane_keys::bleaf(chain_id_, i));
        }
        out.put(lane_keys::bmmr(chain_id_), encode_bmmr(head()));
    }

    // Deltas at or below the journal base are dropped (the best chain's stay
    // materialised; a side branch forking there is Deep from now on).
    void prune() {
        const std::uint64_t base = base_pos();
        floor_ = base;
        for (auto it = journal_.begin(); it != journal_.end();) {
            if (it->second.pos <= base && it->second.pos != 0)
                it = journal_.erase(it);
            else
                ++it;
        }
    }

    LaneParams p_;
    std::uint64_t b0_;
    std::uint64_t j_;
    std::uint32_t chain_id_;
    std::uint64_t floor_ = 0;  // the journal base reached so far
    std::uint64_t entry_floor_ = 0;  // placements of bins below it are not held (P-37)

    // the best chain, materialised
    std::vector<std::uint64_t> records_;                       // H by position
    std::vector<Hash32> chain_;                                // carrier id by position
    std::map<Hash32, std::uint64_t> chain_pos_;                // id -> position
    std::map<std::uint64_t, std::vector<Placement>> by_bin_;   // placements per bin, q ascending
    std::map<Hash32, PlacedAt> placed_q_;                      // placed ids
    std::vector<SealedBin> buckets_;                           // by leaf index
    BinMmr mmr_;

    // held carriers above the journal base on every branch (and genesis)
    std::map<Hash32, LaneDelta> journal_;
};

// ---------------------------------------------------------------------------
// LaneView
// ---------------------------------------------------------------------------
inline std::uint64_t LaneView::record(std::uint64_t x) const {
    if (!ok() || x > pos_) throw std::out_of_range("LaneView::record: not a position of this view");
    if (x <= fork_) return s_->records_[x];
    return side_[x - fork_ - 1]->H;
}

inline bool LaneView::placed_open(const Hash32& id) const {
    const std::uint64_t record_here = record(pos_);
    if (const auto it = s_->placed_q_.find(id); it != s_->placed_q_.end() && it->second.q <= fork_)
        return open_at(record_here, it->second.bin, s_->p_.open_bins);
    for (const LaneDelta* d : side_)
        for (const Placement& x : d->placed)
            if (x.id == id) return open_at(record_here, x.bin, s_->p_.open_bins);
    return false;
}

inline std::vector<const Placement*> LaneView::live_entries(std::uint64_t bin, std::uint64_t q_max) const {
    std::vector<const Placement*> out;
    const std::uint64_t q_best = std::min(q_max, fork_);
    if (const auto it = s_->by_bin_.find(bin); it != s_->by_bin_.end()) {
        for (const Placement& x : it->second) {
            if (x.q > q_best) break;
            if (x.live) out.push_back(&x);
        }
    }
    for (const LaneDelta* d : side_) {
        if (d->pos > q_max) break;
        for (const Placement& x : d->placed)
            if (x.bin == bin && x.live) out.push_back(&x);
    }
    return out;
}

inline std::size_t LaneView::placement_count() const {
    std::size_t n = 0;
    for (const auto& [id, at] : s_->placed_q_)
        if (at.q <= fork_) ++n;
    for (const LaneDelta* d : side_) n += d->placed.size();
    return n;
}

inline const SealedBin* LaneView::bucket(std::uint64_t bin) const {
    if (bin < s_->b0_) return nullptr;
    const std::uint64_t i = bin - s_->b0_;
    if (i >= leaf_count()) return nullptr;
    if (i < leaf_count_at(fork_)) {
        if (i >= s_->buckets_.size() || !s_->buckets_[i].held) return nullptr;
        return &s_->buckets_[i];
    }
    for (const LaneDelta* d : side_)
        for (const SealedBin& sb : d->sealed)
            if (sb.bucket.bin_lo == bin) return &sb;
    return nullptr;
}

inline bool LaneView::entries_held(std::uint64_t bin) const { return bin >= s_->entry_floor_; }

inline std::uint64_t LaneView::leaf_count_at(std::uint64_t x) const {
    return bin_leaf_count(record(x), s_->b0_, s_->p_.open_bins);
}

inline Hash32 LaneView::mmr_root_at(std::uint64_t x) const {
    if (!ok() || x > pos_) throw std::out_of_range("LaneView::mmr_root_at: not a position of this view");
    if (x <= fork_) return s_->mmr_.prefix_root(leaf_count_at(x)).value();  // throws if the MMR lags the record
    return side_[x - fork_ - 1]->root;
}

// ---------------------------------------------------------------------------
// load_lane: the lane records of a restart, checked against the carrier store.
// ---------------------------------------------------------------------------
enum class LoadFault : std::uint8_t { None, NoHead, BadHead, B0, Tip, LeafCount, LeafHash, Root, Body };

struct LaneLoad {
    LoadFault fault = LoadFault::NoHead;
    BmmrHead head;
    BinMmr mmr;
    std::vector<std::optional<SealedBin>> bodies;  // per leaf index; nullopt: the body is not held
    LaneBatch cleanup;                             // records at or beyond leaf_count (deleted)
};

// carrier_tip_id / carrier_tip_pos: the carrier store's best tip; record_at_tip:
// H(carrier_tip_pos) from the carrier records. A fault means: discard the lane
// store and take the rebuild / joiner path.
inline LaneLoad load_lane(const LaneKv& kv, std::uint32_t chain, std::uint64_t b0, std::uint64_t F,
                          const Hash32& carrier_tip_id, std::uint64_t carrier_tip_pos, std::uint64_t record_at_tip) {
    LaneLoad out;
    const auto fail = [&out](LoadFault f) {
        out.fault = f;
        return std::move(out);
    };
    const auto hi = kv.find(lane_keys::bmmr(chain));
    if (hi == kv.end()) return fail(LoadFault::NoHead);
    const std::optional<BmmrHead> head = decode_bmmr(hi->second);
    if (!head) return fail(LoadFault::BadHead);
    out.head = *head;
    if (head->b0 != b0) return fail(LoadFault::B0);
    if (head->tip_id != carrier_tip_id || head->tip_pos != carrier_tip_pos) return fail(LoadFault::Tip);
    if (head->leaf_count != bin_leaf_count(record_at_tip, b0, F)) return fail(LoadFault::LeafCount);
    for (std::uint64_t i = 0; i < head->leaf_count; ++i) {
        const auto li = kv.find(lane_keys::blhash(chain, i));
        if (li == kv.end()) return fail(LoadFault::LeafHash);
        const std::optional<Hash32> leaf = decode_blhash(li->second);
        if (!leaf) return fail(LoadFault::LeafHash);
        out.mmr.append(*leaf);
    }
    if (out.mmr.root() != head->root) return fail(LoadFault::Root);
    out.bodies.resize(head->leaf_count);
    for (std::uint64_t i = 0; i < head->leaf_count; ++i) {
        const auto bi = kv.find(lane_keys::bleaf(chain, i));
        if (bi == kv.end()) continue;  // pruned body (the leaf hash stays)
        std::optional<SealedBin> sb = decode_bleaf(bi->second, i, b0);
        if (!sb || sb->leaf != out.mmr.leaf(i)) return fail(LoadFault::Body);
        out.bodies[i] = std::move(sb);
    }
    for (const std::string& prefix : {lane_keys::blhash_prefix(chain), lane_keys::bleaf_prefix(chain)}) {
        for (auto it = kv.lower_bound(prefix); it != kv.end() && it->first.compare(0, prefix.size(), prefix) == 0;
             ++it) {
            const std::optional<std::uint64_t> i = lane_keys::index_of(it->first, prefix);
            if (!i || *i >= head->leaf_count) out.cleanup.del(it->first);
        }
    }
    out.fault = LoadFault::None;
    return out;
}

}  // namespace c2pool::xmr::pathb
