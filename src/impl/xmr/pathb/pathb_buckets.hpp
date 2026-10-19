// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_buckets.hpp
// Path B, slice S3: the sealed-bin L1 bucket, its comp_root, the LeafPayload v1
// and the append-only MMR of sealed bins. These are the consensus commitments
// that lift mmr_root (side_data offset 173) off its S1/S2 zero stub.
//
// PINNED serialization (the golden-vector authority; S3.2, extends C-DOM):
//   bucket row (160 B)  = miner[32] || owner[32] || LE256(w_miner) ||
//                         LE256(w_owner) || LE256(w_author)
//   row_leaf            = sha256d(0x04 || row)
//   comp_root           = binary Merkle over row leaves sorted ascending by the
//                         64-byte key miner||owner (memcmp); parent =
//                         sha256d(0x05 || l || r); lone node promoted; one row ->
//                         that row_leaf; empty -> 32 zero bytes.
//   LeafPayload v1 (96) = LE64(bin_lo) || LE64(bin_hi) || LE256(raw_sum) ||
//                         LE64(miner_count) || LE64(d_min) || comp_root[32]
//   mmr_leaf            = sha256d(0x00 || LeafPayload v1)   (hashes 97 bytes)
//   mmr internal node   = sha256d(0x03 || l || r)
//   mmr root            = sha256d(0x02 || LE64(leaf_count) || bag), bag the
//                         right-to-left fold of the peaks (0x03 tag), n_peaks ==
//                         popcount(leaf_count).
//
// Slice S3b: bucket_check / bucket_consistent (the committed fields are
// functions of the rows; miner_count = distinct row.miner, P-2 = ruling 31);
// BinMmr stores every complete subtree: append O(log n), prefix_root(n) and
// prefix_proof(i, n) O(log n), truncate(n); from_peaks starts a prefix MMR.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include "sharechain/v37/v37_hash.hpp"  // ::v37::sha256d

#include "pathb_params.hpp"
#include "pathb_wide.hpp"  // Work, le256

namespace c2pool::xmr::pathb {

// Domain bytes (C-DOM extended; S3.2). One byte per hashed shape, frozen.
inline constexpr std::uint8_t kDomMmrLeaf = 0x00;    // MMR bin leaf
inline constexpr std::uint8_t kDomMmrRoot = 0x02;    // MMR root bag
inline constexpr std::uint8_t kDomMmrNode = 0x03;    // MMR internal / branch node
inline constexpr std::uint8_t kDomRowLeaf = 0x04;    // bucket row leaf
inline constexpr std::uint8_t kDomCompNode = 0x05;   // comp_root internal node
inline constexpr std::uint8_t kDomWinLeaf = 0x06;    // window-sum leaf
inline constexpr std::uint8_t kDomWinNode = 0x07;    // window-sum internal node

inline Hash32 sha256d_bytes(const std::vector<std::uint8_t>& pre) { return ::v37::sha256d(pre); }

inline Hash32 sha256d_tag_pair(std::uint8_t tag, const Hash32& a, const Hash32& b) {
    std::vector<std::uint8_t> pre;
    pre.reserve(1 + 2 * kHashBytes);
    pre.push_back(tag);
    pre.insert(pre.end(), a.begin(), a.end());
    pre.insert(pre.end(), b.begin(), b.end());
    return ::v37::sha256d(pre);
}

inline constexpr Hash32 kZeroHash{};

// ---------------------------------------------------------------------------
// Bucket row (frozen at the seal; ruling 20 Q-K): one per (miner, owner) group.
// ---------------------------------------------------------------------------
struct BucketRow {
    Hash32 miner{};
    Hash32 owner{};  // all-zero when p == 0
    Work w_miner{};
    Work w_owner{};
    Work w_author{};
};

inline std::array<std::uint8_t, 160> bucket_row_bytes(const BucketRow& r) {
    std::array<std::uint8_t, 160> out{};
    std::size_t o = 0;
    auto put = [&](const Hash32& h) { for (std::uint8_t b : h) out[o++] = b; };
    auto put_w = [&](const Work& w) { for (std::uint8_t b : le256(w)) out[o++] = b; };
    put(r.miner);
    put(r.owner);
    put_w(r.w_miner);
    put_w(r.w_owner);
    put_w(r.w_author);
    return out;
}

inline Hash32 row_leaf(const BucketRow& r) {
    const std::array<std::uint8_t, 160> row = bucket_row_bytes(r);
    std::vector<std::uint8_t> pre;
    pre.reserve(1 + row.size());
    pre.push_back(kDomRowLeaf);
    pre.insert(pre.end(), row.begin(), row.end());
    return ::v37::sha256d(pre);
}

// 64-byte key miner || owner (memcmp order), for the comp_root sort.
inline bool row_key_less(const BucketRow& a, const BucketRow& b) {
    if (a.miner != b.miner) return std::lexicographical_compare(a.miner.begin(), a.miner.end(),
                                                                b.miner.begin(), b.miner.end());
    return std::lexicographical_compare(a.owner.begin(), a.owner.end(), b.owner.begin(), b.owner.end());
}

// comp_root over the rows (sorted ascending by miner||owner): pair adjacent
// leaves, parent = sha256d(0x05 || l || r); a lone rightmost node is PROMOTED
// unchanged (no duplication). One row -> that row_leaf. Empty -> 32 zero bytes.
inline Hash32 comp_root(std::vector<BucketRow> rows) {
    if (rows.empty()) return kZeroHash;
    std::sort(rows.begin(), rows.end(), row_key_less);
    std::vector<Hash32> level;
    level.reserve(rows.size());
    for (const BucketRow& r : rows) level.push_back(row_leaf(r));
    while (level.size() > 1) {
        std::vector<Hash32> next;
        next.reserve((level.size() + 1) / 2);
        for (std::size_t i = 0; i < level.size(); i += 2) {
            if (i + 1 < level.size())
                next.push_back(sha256d_tag_pair(kDomCompNode, level[i], level[i + 1]));
            else
                next.push_back(level[i]);  // promote lone node
        }
        level.swap(next);
    }
    return level.front();
}

// ---------------------------------------------------------------------------
// L1 bucket + LeafPayload v1.
// ---------------------------------------------------------------------------
struct L1Bucket {
    std::uint64_t bin_lo = 0;
    std::uint64_t bin_hi = 0;  // == bin_lo in v1 (a towed multi-bin leaf is S7)
    Work raw_sum{};
    std::uint64_t miner_count = 0;
    std::uint64_t d_min = 0;
    Hash32 comp_root_v{};
    std::vector<BucketRow> rows;  // kept for merge-back and comp_root recompute
};

inline std::array<std::uint8_t, 96> leaf_payload_bytes(const L1Bucket& b) {
    std::array<std::uint8_t, 96> out{};
    std::size_t o = 0;
    auto put_u64 = [&](std::uint64_t v) {
        for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) out[o++] = static_cast<std::uint8_t>(v >> (8 * i));
    };
    auto put_w = [&](const Work& w) { for (std::uint8_t x : le256(w)) out[o++] = x; };
    put_u64(b.bin_lo);
    put_u64(b.bin_hi);
    put_w(b.raw_sum);
    put_u64(b.miner_count);
    put_u64(b.d_min);
    for (std::uint8_t x : b.comp_root_v) out[o++] = x;
    return out;
}

inline Hash32 mmr_leaf_of(const L1Bucket& b) {
    const std::array<std::uint8_t, 96> p = leaf_payload_bytes(b);
    std::vector<std::uint8_t> pre;
    pre.reserve(1 + p.size());
    pre.push_back(kDomMmrLeaf);
    pre.insert(pre.end(), p.begin(), p.end());
    return ::v37::sha256d(pre);
}

// Seal an L1 bucket from its rows + bin metadata (fills comp_root).
inline L1Bucket seal_bucket(std::uint64_t bin, const std::vector<BucketRow>& rows, const Work& raw_sum,
                            std::uint64_t miner_count, std::uint64_t d_min) {
    L1Bucket b;
    b.bin_lo = bin;
    b.bin_hi = bin;
    b.raw_sum = raw_sum;
    b.miner_count = miner_count;
    b.d_min = d_min;
    b.rows = rows;
    b.comp_root_v = comp_root(rows);
    return b;
}

// ---------------------------------------------------------------------------
// Bucket consistency (P-2 = ruling 31; E-8; E-11). A sealed bucket's
// committed fields are functions of its rows:
//   bin_lo == bin_hi; rows strictly ascending by miner||owner (one row per
//   group); comp_root == comp_root(rows); raw_sum == sum of
//   (w_miner + w_owner + w_author) over the rows (exact: p + give_author_bp
//   <= 10000 at #2); miner_count == the number of distinct row.miner, rows
//   whose w_miner is 0 included; empty <=> no rows <=> raw_sum 0 <=> d_min 0
//   <=> miner_count 0; rows x d_min <= raw_sum (every row holds at least one
//   live receipt of work >= d_min).
// d_min itself is not a function of the rows (it is the smallest live receipt
// work of the bin), so only its bound is checked here.
// ---------------------------------------------------------------------------
inline std::uint64_t miner_count_of(const std::vector<BucketRow>& rows) {
    std::set<Hash32> miners;
    for (const BucketRow& r : rows) miners.insert(r.miner);
    return miners.size();
}

inline Work rows_weight_sum(const std::vector<BucketRow>& rows) {
    Work sum;
    for (const BucketRow& r : rows) sum += r.w_miner + r.w_owner + r.w_author;
    return sum;
}

enum class BucketFault : std::uint8_t { None, BinRange, RowOrder, CompRoot, RawSum, MinerCount, Empty, RowBound };

inline BucketFault bucket_check(const L1Bucket& b) {
    if (b.bin_lo != b.bin_hi) return BucketFault::BinRange;
    for (std::size_t i = 1; i < b.rows.size(); ++i)
        if (!row_key_less(b.rows[i - 1], b.rows[i])) return BucketFault::RowOrder;
    if (b.comp_root_v != comp_root(b.rows)) return BucketFault::CompRoot;
    if (b.raw_sum != rows_weight_sum(b.rows)) return BucketFault::RawSum;
    if (b.miner_count != miner_count_of(b.rows)) return BucketFault::MinerCount;
    const bool empty = b.rows.empty();
    if (b.raw_sum.is_zero() != empty || (b.d_min == 0) != empty || (b.miner_count == 0) != empty)
        return BucketFault::Empty;
    if (!empty && wide::mul_u256_u64(b.raw_sum, 1) < wide::mul_u256_u64(Work(b.d_min), b.rows.size()))
        return BucketFault::RowBound;
    return BucketFault::None;
}

inline bool bucket_consistent(const L1Bucket& b) { return bucket_check(b) == BucketFault::None; }

// ---------------------------------------------------------------------------
// Append-only MMR of sealed-bin leaves (S3.2, E-9 bytes). Every complete
// aligned subtree is stored (about 2n hashes): append O(log n) worst case,
// root() O(popcount n), prefix_root(n) and prefix_proof(i, n) O(log n) from
// the stored nodes, truncate(n) exact. Node (k, j) is the subtree of height k
// over leaves [j 2^k, (j + 1) 2^k).
//
// A prefix MMR (from_peaks) starts from the peaks of its first leaf_count0
// leaves (a joiner's served prefix, a side branch's fork point): roots for
// every n >= leaf_count0, proofs only for leaves >= leaf_count0. Every peak of
// a prefix n >= leaf_count0 is a peak of leaf_count0 or a node built after it.
// ---------------------------------------------------------------------------
inline std::size_t popcount64(std::uint64_t x) noexcept { return static_cast<std::size_t>(std::popcount(x)); }

// Perfect-subtree peak ranges of a leaf count, largest (leftmost) first:
// (first leaf, size) with power-of-two sizes.
inline std::vector<std::pair<std::uint64_t, std::uint64_t>> mmr_peak_ranges(std::uint64_t n) {
    std::vector<std::pair<std::uint64_t, std::uint64_t>> out;
    std::uint64_t start = 0;
    for (int bit = 63; bit >= 0; --bit) {
        const std::uint64_t sz = std::uint64_t{1} << bit;
        if (n & sz) {
            out.emplace_back(start, sz);
            start += sz;
        }
    }
    return out;
}

// bag = right-to-left fold of the peaks (high index to low), 0x03 tag; one
// peak -> that peak; none -> zero.
inline Hash32 mmr_bag(const std::vector<Hash32>& pk, std::uint64_t* hashes = nullptr) {
    if (pk.empty()) return kZeroHash;
    Hash32 bag = pk.back();
    for (std::size_t i = pk.size() - 1; i-- > 0;) {
        bag = sha256d_tag_pair(kDomMmrNode, pk[i], bag);
        if (hashes) ++*hashes;
    }
    return bag;
}

// root = sha256d(0x02 || LE64(leaf_count) || bag); an empty MMR has the zero root.
inline Hash32 mmr_root_of(std::uint64_t leaf_count, const std::vector<Hash32>& pk, std::uint64_t* hashes = nullptr) {
    if (leaf_count == 0) return kZeroHash;
    std::vector<std::uint8_t> pre;
    pre.reserve(1 + sizeof(std::uint64_t) + kHashBytes);
    pre.push_back(kDomMmrRoot);
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) pre.push_back(static_cast<std::uint8_t>(leaf_count >> (8 * i)));
    const Hash32 bag = mmr_bag(pk, hashes);
    pre.insert(pre.end(), bag.begin(), bag.end());
    if (hashes) ++*hashes;
    return ::v37::sha256d(pre);
}

// O(log n) membership proof for a leaf against the root over leaf_count
// leaves: the co-path inside its own peak subtree plus every peak (so the
// verifier rebags against the committed root).
struct MmrProof {
    std::uint64_t leaf_index = 0;
    std::uint64_t leaf_count = 0;
    std::vector<std::pair<Hash32, bool>> path;  // (sibling, sibling_is_right)
    std::vector<Hash32> peaks;                   // all peaks, left-to-right
    std::size_t own_peak = 0;                    // index of the peak holding the leaf
};

class BinMmr {
public:
    BinMmr() = default;

    // The prefix MMR of leaf_count0 leaves known by their peaks (left to right).
    // nullopt when the peak count is not popcount(leaf_count0).
    static std::optional<BinMmr> from_peaks(std::uint64_t leaf_count0, const std::vector<Hash32>& peaks0) {
        if (peaks0.size() != popcount64(leaf_count0)) return std::nullopt;
        BinMmr m;
        m.first_ = leaf_count0;
        m.n_ = leaf_count0;
        std::size_t i = 0;
        for (const auto& range : mmr_peak_ranges(leaf_count0)) {
            const unsigned k = static_cast<unsigned>(std::countr_zero(range.second));
            m.ensure_level(k);
            m.lv_[k].push_back(peaks0[i++]);  // index (leaf_count0 >> k) - 1 == off_[k]
        }
        return m;
    }

    std::uint64_t leaf_count() const noexcept { return n_; }
    // The first leaf this MMR can prove (0 for a full MMR).
    std::uint64_t first_provable() const noexcept { return first_; }

    void append(const Hash32& leaf) {
        ensure_level(0);
        lv_[0].push_back(leaf);
        std::uint64_t j = n_++;
        unsigned k = 0;
        while (j & 1u) {  // node (k, j) completes its parent (k + 1, j >> 1)
            const Hash32 parent = hash_node(*node(k, j - 1), *node(k, j));
            ensure_level(k + 1);
            lv_[k + 1].push_back(parent);
            j >>= 1;
            ++k;
        }
    }

    std::vector<std::pair<std::uint64_t, std::uint64_t>> peak_ranges() const { return mmr_peak_ranges(n_); }
    std::size_t n_peaks() const noexcept { return popcount64(n_); }

    // Peaks of the prefix of n leaves; nullopt unless first_provable() <= n <=
    // leaf_count() (n == 0 is the empty prefix).
    std::optional<std::vector<Hash32>> prefix_peaks(std::uint64_t n) const {
        if (n > n_ || (n < first_ && n != 0)) return std::nullopt;
        std::vector<Hash32> out;
        for (const auto& [start, sz] : mmr_peak_ranges(n)) {
            const unsigned k = static_cast<unsigned>(std::countr_zero(sz));
            const Hash32* h = node(k, start >> k);
            if (!h) return std::nullopt;
            out.push_back(*h);
        }
        return out;
    }

    std::vector<Hash32> peaks() const { return *prefix_peaks(n_); }

    static Hash32 bag_peaks(const std::vector<Hash32>& pk) { return mmr_bag(pk); }

    // The root over the first n leaves (the root committed at leaf_count n).
    std::optional<Hash32> prefix_root(std::uint64_t n) const {
        const std::optional<std::vector<Hash32>> pk = prefix_peaks(n);
        if (!pk) return std::nullopt;
        return mmr_root_of(n, *pk, &hashes_);
    }

    Hash32 root() const { return *prefix_root(n_); }

    // Proof of leaf i against the root over the first n leaves; nullopt unless
    // first_provable() <= i < n <= leaf_count().
    std::optional<MmrProof> prefix_proof(std::uint64_t i, std::uint64_t n) const {
        const std::uint64_t cnt = n;  // the committed leaf_count the proof is for
        if (i < first_ || i >= cnt || cnt > n_) return std::nullopt;
        MmrProof pr;
        pr.leaf_index = i;
        pr.leaf_count = cnt;
        std::optional<std::vector<Hash32>> pk = prefix_peaks(cnt);
        if (!pk) return std::nullopt;
        pr.peaks = std::move(*pk);
        std::size_t p = 0;
        for (const auto& [start, sz] : mmr_peak_ranges(cnt)) {
            if (i >= start && i < start + sz) {
                pr.own_peak = p;
                const unsigned height = static_cast<unsigned>(std::countr_zero(sz));
                for (unsigned k = 0; k < height; ++k) {
                    const std::uint64_t j = i >> k;
                    const Hash32* sib = node(k, j ^ 1u);
                    if (!sib) return std::nullopt;
                    pr.path.emplace_back(*sib, (j & 1u) == 0);
                }
                break;
            }
            ++p;
        }
        return pr;
    }

    // Leaf hash i (nullopt when not held: i >= leaf_count() or i below a prefix).
    std::optional<Hash32> leaf(std::uint64_t i) const {
        if (i >= n_) return std::nullopt;
        const Hash32* h = node(0, i);
        if (!h) return std::nullopt;
        return *h;
    }

    // Drops every leaf from n on (rewind): node (k, j) stays iff (j + 1) 2^k <= n.
    // false (nothing changes) unless first_provable() <= n <= leaf_count().
    bool truncate(std::uint64_t n) {
        if (n > n_ || n < first_) return false;
        for (std::size_t k = 0; k < lv_.size(); ++k) {
            const std::uint64_t keep_j = n >> k;  // nodes j < keep_j are complete
            const std::uint64_t keep = keep_j > off_[k] ? keep_j - off_[k] : 0;
            if (keep < lv_[k].size()) lv_[k].resize(keep);
        }
        n_ = n;
        return true;
    }

    // Hashes computed by this MMR (append, roots); a proof reads stored nodes.
    std::uint64_t hash_count() const noexcept { return hashes_; }

private:
    void ensure_level(std::size_t k) {
        while (lv_.size() <= k) {
            const std::size_t lvl = lv_.size();
            // level lvl starts at the prefix peak of height lvl (when bit lvl of
            // first_ is set) at index (first_ >> lvl) - 1, else at first_ >> lvl.
            off_.push_back(lvl < 64 ? ((first_ >> lvl) & ~std::uint64_t{1}) : 0);
            lv_.emplace_back();
        }
    }

    const Hash32* node(std::size_t k, std::uint64_t j) const {
        if (k >= lv_.size() || j < off_[k]) return nullptr;
        const std::uint64_t at = j - off_[k];
        if (at >= lv_[k].size()) return nullptr;
        return &lv_[k][at];
    }

    Hash32 hash_node(const Hash32& l, const Hash32& r) const {
        ++hashes_;
        return sha256d_tag_pair(kDomMmrNode, l, r);
    }

    std::uint64_t first_ = 0;                // leaves below first_ are known by their peaks only
    std::uint64_t n_ = 0;                    // leaf_count
    std::vector<std::uint64_t> off_;         // index of the first stored node per level
    std::vector<std::vector<Hash32>> lv_;    // stored nodes per level
    mutable std::uint64_t hashes_ = 0;
};

// Proof of a leaf against the MMR's current root (leaf_count = m.leaf_count()).
// An index the MMR cannot prove gives a proof that never verifies.
inline MmrProof mmr_proof(const BinMmr& m, std::uint64_t leaf_index) {
    if (std::optional<MmrProof> p = m.prefix_proof(leaf_index, m.leaf_count())) return *p;
    MmrProof pr;
    pr.leaf_index = leaf_index;
    pr.leaf_count = m.leaf_count();
    return pr;
}

// The proof's shape is a function of (leaf_index, leaf_count): leaf_index <
// leaf_count; peaks.size() == popcount(leaf_count); own_peak = the peak holding
// leaf_index; path length = that peak's height; sibling k on the right iff bit k
// of (leaf_index - first leaf of that peak) is 0. leaf_index = b - b0 (E-8).
inline bool mmr_proof_shape_ok(const MmrProof& pr) {
    const std::uint64_t n = pr.leaf_count;
    if (n == 0 || pr.leaf_index >= n) return false;
    std::size_t n_peaks = 0, peak = 0;
    std::uint64_t start = 0, lo = 0, sz = 0;
    for (int bit = 63; bit >= 0; --bit) {
        const std::uint64_t span = std::uint64_t{1} << bit;
        if (!(n & span)) continue;
        if (sz == 0 && pr.leaf_index >= start && pr.leaf_index < start + span) {
            peak = n_peaks;
            lo = start;
            sz = span;
        }
        start += span;
        ++n_peaks;
    }
    if (pr.peaks.size() != n_peaks || pr.own_peak != peak) return false;
    std::size_t height = 0;
    for (std::uint64_t s = sz; s > 1; s >>= 1) ++height;
    if (pr.path.size() != height) return false;
    std::uint64_t pos = pr.leaf_index - lo;
    for (const auto& step : pr.path) {
        if (step.second != ((pos & 1u) == 0)) return false;
        pos >>= 1;
    }
    return true;
}

// Verify a leaf against a committed mmr_root: the proof's shape must match its
// leaf_index (mmr_proof_shape_ok), fold the leaf up its co-path to its peak,
// confirm it equals the proof's own peak, then bag all peaks and compare the root
// (with the committed leaf_count). A forged bucket breaks the fold; a forged peak
// set breaks the root; a valid co-path under another leaf_index breaks the shape.
inline bool mmr_verify(const Hash32& mmr_root, const Hash32& leaf, const MmrProof& pr) {
    if (pr.own_peak >= pr.peaks.size()) return false;
    if (!mmr_proof_shape_ok(pr)) return false;
    Hash32 h = leaf;
    for (const auto& [sib, sib_is_right] : pr.path)
        h = sib_is_right ? sha256d_tag_pair(kDomMmrNode, h, sib) : sha256d_tag_pair(kDomMmrNode, sib, h);
    if (h != pr.peaks[pr.own_peak]) return false;
    return mmr_root_of(pr.leaf_count, pr.peaks) == mmr_root;
}

// ---------------------------------------------------------------------------
// fold_pos / seal depth (S3.4 `fold_pos`; K06, ruling 27 K-11). H is the Monero
// height record over CARRIERS of the chain; the bin b seals at the first carrier
// f with H(f) >= b + F, D_fin = 0.
// ---------------------------------------------------------------------------
template <class RecordH>
inline std::uint64_t fold_pos(RecordH&& h_at, std::uint64_t n_positions, std::uint64_t origin_bin,
                              std::uint64_t open_bins, bool& found) {
    found = false;
    for (std::uint64_t f = 0; f < n_positions; ++f) {
        if (h_at(f) >= origin_bin + open_bins) {
            found = true;
            return f;
        }
    }
    return n_positions;
}

}  // namespace c2pool::xmr::pathb
