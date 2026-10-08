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
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
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
// Append-only MMR of sealed-bin leaves (S3.2; master's owed-event MMR primitive
// re-cut for the bin leaf, keeping n_peaks == popcount(leaf_count)). Functional:
// stores the leaf hashes; peaks / root / proof are derived by binary
// decomposition of leaf_count, so a rebuild (restart, reorg, joiner) is exact.
// ---------------------------------------------------------------------------
class BinMmr {
public:
    void append(const Hash32& leaf) { leaves_.push_back(leaf); }
    std::uint64_t leaf_count() const noexcept { return leaves_.size(); }

    // Perfect-subtree peak ranges by binary decomposition of count, largest
    // (leftmost / oldest) first: [starts..) with power-of-two sizes.
    std::vector<std::pair<std::uint64_t, std::uint64_t>> peak_ranges() const {
        std::vector<std::pair<std::uint64_t, std::uint64_t>> out;
        std::uint64_t start = 0;
        const std::uint64_t n = leaves_.size();
        for (int bit = 63; bit >= 0; --bit) {
            const std::uint64_t sz = std::uint64_t{1} << bit;
            if (n & sz) {
                out.emplace_back(start, sz);
                start += sz;
            }
        }
        return out;
    }

    // Fold a perfect subtree [lo, lo+sz) into its peak hash (node = 0x03).
    Hash32 fold_range(std::uint64_t lo, std::uint64_t sz) const {
        std::vector<Hash32> level(leaves_.begin() + static_cast<std::ptrdiff_t>(lo),
                                  leaves_.begin() + static_cast<std::ptrdiff_t>(lo + sz));
        while (level.size() > 1) {
            std::vector<Hash32> next;
            next.reserve(level.size() / 2);
            for (std::size_t i = 0; i < level.size(); i += 2)
                next.push_back(sha256d_tag_pair(kDomMmrNode, level[i], level[i + 1]));
            level.swap(next);
        }
        return level.front();
    }

    std::vector<Hash32> peaks() const {
        std::vector<Hash32> out;
        for (auto [lo, sz] : peak_ranges()) out.push_back(fold_range(lo, sz));
        return out;
    }

    std::size_t n_peaks() const { return peak_ranges().size(); }

    // bag = right-to-left fold of the peaks (high index to low), 0x03 tag; one
    // peak -> that peak.
    static Hash32 bag_peaks(const std::vector<Hash32>& pk) {
        if (pk.empty()) return kZeroHash;
        Hash32 bag = pk.back();
        for (std::size_t i = pk.size() - 1; i-- > 0;) bag = sha256d_tag_pair(kDomMmrNode, pk[i], bag);
        return bag;
    }

    Hash32 root() const {
        if (leaves_.empty()) return kZeroHash;
        std::vector<std::uint8_t> pre;
        pre.reserve(1 + sizeof(std::uint64_t) + kHashBytes);
        pre.push_back(kDomMmrRoot);
        const std::uint64_t n = leaves_.size();
        for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) pre.push_back(static_cast<std::uint8_t>(n >> (8 * i)));
        const Hash32 bag = bag_peaks(peaks());
        pre.insert(pre.end(), bag.begin(), bag.end());
        return ::v37::sha256d(pre);
    }

    const std::vector<Hash32>& leaves() const noexcept { return leaves_; }

private:
    std::vector<Hash32> leaves_;
};

// O(log n) membership proof for a leaf: the co-path inside its own peak subtree
// plus every peak's hash (so the verifier rebags against the committed root).
struct MmrProof {
    std::uint64_t leaf_index = 0;
    std::uint64_t leaf_count = 0;
    std::vector<std::pair<Hash32, bool>> path;  // (sibling, sibling_is_right)
    std::vector<Hash32> peaks;                   // all peaks, left-to-right
    std::size_t own_peak = 0;                    // index of the peak holding the leaf
};

inline MmrProof mmr_proof(const BinMmr& m, std::uint64_t leaf_index) {
    MmrProof pr;
    pr.leaf_index = leaf_index;
    pr.leaf_count = m.leaf_count();
    pr.peaks = m.peaks();
    const auto ranges = m.peak_ranges();
    // locate the peak subtree holding leaf_index
    std::uint64_t lo = 0, sz = 0;
    for (std::size_t i = 0; i < ranges.size(); ++i) {
        if (leaf_index >= ranges[i].first && leaf_index < ranges[i].first + ranges[i].second) {
            pr.own_peak = i;
            lo = ranges[i].first;
            sz = ranges[i].second;
            break;
        }
    }
    // co-path up the perfect subtree [lo, lo+sz): rebuild level by level.
    std::vector<Hash32> level(m.leaves().begin() + static_cast<std::ptrdiff_t>(lo),
                              m.leaves().begin() + static_cast<std::ptrdiff_t>(lo + sz));
    std::uint64_t pos = leaf_index - lo;
    while (level.size() > 1) {
        const std::uint64_t sib = (pos ^ 1u);
        const bool sib_is_right = (sib > pos);
        pr.path.emplace_back(level[sib], sib_is_right);
        std::vector<Hash32> next;
        next.reserve(level.size() / 2);
        for (std::size_t i = 0; i < level.size(); i += 2)
            next.push_back(sha256d_tag_pair(kDomMmrNode, level[i], level[i + 1]));
        level.swap(next);
        pos >>= 1;
    }
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
    std::vector<std::uint8_t> pre;
    pre.reserve(1 + sizeof(std::uint64_t) + kHashBytes);
    pre.push_back(kDomMmrRoot);
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i)
        pre.push_back(static_cast<std::uint8_t>(pr.leaf_count >> (8 * i)));
    const Hash32 bag = BinMmr::bag_peaks(pr.peaks);
    pre.insert(pre.end(), bag.begin(), bag.end());
    return ::v37::sha256d(pre) == mmr_root;
}

// popcount(leaf_count) — the structural law n_peaks == popcount(leaf_count).
inline std::size_t popcount64(std::uint64_t x) noexcept { return static_cast<std::size_t>(std::popcount(x)); }

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
