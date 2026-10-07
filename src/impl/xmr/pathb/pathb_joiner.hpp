// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_joiner.hpp
// Path B, slice S3: the recent-window JOINER (S3.1a; ruling 15 Q8, 20 Q-E; V-10,
// C43). A new node reaches the byte-equal lane digest from the recent window
// only: it downloads span headers + N_rt retarget-prefix headers, checks the MMR
// peaks + leaf_count of the first span carrier against its mmr_root, verifies the
// sealed-bin L1 buckets against mmr_root with their MMR proofs, then verifies the
// span in FULL (S1.3 + S2.3 + the S3 window / coinbase checks). No older history
// and no previous-share inputs (ruling 27 K-10).
//
//   span = max(J_0, ceil((F + Fresh) x 120 / T) + D_fin) = 1,176 positions at
//          D_fin 0 (J_0 = max(ceil(3 h x 3600 / T), ceil(F x 120 / T) + D_fin)
//          = 1,152, the DEFAULT journal formula; card 2e not accepted, 27 K-11)
//   N_rt = 2,160 retarget-prefix headers (K03a, = retarget_span).
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <vector>

#include "pathb_buckets.hpp"
#include "pathb_params.hpp"

namespace c2pool::xmr::pathb {

// The 3-hour default-journal term J_0, in positions (never the node's journal
// flag P-01; the span stays a CONSENSUS value).
inline constexpr std::uint64_t kJournalHours = 3;

inline std::uint64_t journal_j0(const LaneParams& p, std::uint64_t d_fin) noexcept {
    const std::uint64_t by_time = ceil_div(kJournalHours * kSecondsPerHour, p.carrier_interval_s);
    const std::uint64_t by_open = ceil_div(p.open_bins * DIFFICULTY_TARGET_V2, p.carrier_interval_s) + d_fin;
    return by_time > by_open ? by_time : by_open;
}

// span = max(J_0, ceil((F + Fresh) x 120 / T) + D_fin).
inline std::uint64_t join_span(const LaneParams& p, std::uint64_t d_fin) noexcept {
    const std::uint64_t j0 = journal_j0(p, d_fin);
    const std::uint64_t by_fresh = ceil_div((p.open_bins + p.fresh_max) * DIFFICULTY_TARGET_V2, p.carrier_interval_s) + d_fin;
    return j0 > by_fresh ? j0 : by_fresh;
}

// N_rt retarget-prefix headers before the span (hash-linked; PoW not needed).
inline std::uint64_t join_n_rt(const LaneParams& p) noexcept { return p.retarget_span; }

// The first span carrier's peaks + leaf_count must bag to its committed mmr_root.
inline bool peaks_match_root(const std::vector<Hash32>& peaks, std::uint64_t leaf_count, const Hash32& mmr_root) {
    if (static_cast<std::size_t>(popcount64(leaf_count)) != peaks.size()) return false;  // n_peaks law
    std::vector<std::uint8_t> pre;
    pre.reserve(1 + sizeof(std::uint64_t) + kHashBytes);
    pre.push_back(kDomMmrRoot);
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i)
        pre.push_back(static_cast<std::uint8_t>(leaf_count >> (8 * i)));
    const Hash32 bag = BinMmr::bag_peaks(peaks);
    pre.insert(pre.end(), bag.begin(), bag.end());
    return ::v37::sha256d(pre) == mmr_root;
}

// A sealed-bin bucket served to the joiner with its MMR proof (FC_GETBUCKETS).
struct ServedBucket {
    L1Bucket bucket;
    MmrProof proof;
};

// Verify one served bucket against the committed mmr_root: its MMR leaf verifies
// (a forged composition changes comp_root -> the leaf -> the fold, refused).
inline bool verify_served_bucket(const Hash32& mmr_root, const ServedBucket& sb) {
    // the comp_root must match the bucket's rows (a forged composition fails here
    // before the MMR check).
    if (sb.bucket.comp_root_v != comp_root(sb.bucket.rows)) return false;
    return mmr_verify(mmr_root, mmr_leaf_of(sb.bucket), sb.proof);
}

// The joiner's bucket pass: every served bucket verifies, and the first span
// carrier's peaks bag to its mmr_root.
inline bool joiner_bucket_pass(const std::vector<Hash32>& c0_peaks, std::uint64_t c0_leaf_count,
                               const Hash32& c0_mmr_root, const std::vector<ServedBucket>& buckets) {
    if (!peaks_match_root(c0_peaks, c0_leaf_count, c0_mmr_root)) return false;
    for (const ServedBucket& sb : buckets)
        if (!verify_served_bucket(c0_mmr_root, sb)) return false;
    return true;
}

}  // namespace c2pool::xmr::pathb
