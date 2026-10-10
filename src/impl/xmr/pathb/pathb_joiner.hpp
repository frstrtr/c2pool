// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_joiner.hpp
// Path B, slice S3: the recent-window JOINER (S3.1a; ruling 15 Q8, 20 Q-E; V-10,
// C43): its constants and the span of a join.
//
//   join_span = max(J_0, ceil((F + Fresh) x 120 / T) + D_fin) = 1,176 positions
//               at D_fin 0 (J_0 = max(ceil(3 h x 3600 / T), ceil(F x 120 / T) +
//               D_fin) = 1,152, the DEFAULT journal formula; card 2e not
//               accepted, 27 K-11)
//   N_rt      = 2,160 retarget-prefix headers (K03a, = retarget_span).
//   span_bounds(L)  (slice S3b-4b; ruling 31 P-10 as amended by ruling 44
//               S3b4-6 (a); the young chain of ruling 41 S3b4-1 (a)):
//     L'  = min(L - N_rt, the last x with H(x) <= H(L) - F - Fresh)
//     x0  = min(L' - (join_span - 1), the first x with H(x) > H(L') - F - Fresh)
//     x1  = the first x with H(x) >= H(x0 - 1) + F + Fresh            (x1 <= L')
//     no L' (L < N_rt, or no x with H(x) <= H(L) - F - Fresh) or x0 <= 0:
//           the young chain, x0 = x1 = 1 (the whole chain [1, L], no claim).
//     The span [x0, L] holds at least N_rt + join_span = 3,336 positions.
//   pre_start(x0)  the start of the claimed retarget prefix (ruling 53, E-99):
//     x_pre = max(1, min(x0 - N_rt, the first x with H(x) > H(max(0, x0 - 1
//             - J_0)) - F - Fresh)), on the candidate's records at L.
//   peaks_match_root  the first span carrier's peaks bag to its mmr_root.
//   The bucket assembly of a join is BucketsAssembly (pathb_bucket_wire.hpp)
//   driven by JoinBuckets (pathb_join.hpp).
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <optional>
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

// ---------------------------------------------------------------------------
// span_bounds: the span of a join at L (slice S3b-4b)
// ---------------------------------------------------------------------------
struct SpanBounds {
    bool young = false;         // x0 = x1 = 1: the whole chain [1, L] in full, no claim
    std::uint64_t l_prime = 0;  // L' (young: 0)
    std::uint64_t x0 = 1;
    std::uint64_t x1 = 1;
};

enum class SpanStatus : std::uint8_t { Ok, NeedRecord };

struct SpanResult {
    SpanStatus status = SpanStatus::Ok;
    SpanBounds bounds;
    std::uint64_t need = 0;  // NeedRecord: the position whose record the span needs (below what is held)
};

// rec(x) -> std::optional<std::uint64_t>: H(x) on the candidate's chain for a
// position the caller holds (rec(0) = H(0) = b0, from the pool identity);
// nullopt: not held (the result names the position). H is monotone along a
// chain of carriers (S1.3 #6).
// b0 (H(0)): where it is given (non-zero) and the formula gives x0 >= 1 with no
// bin sealed before x0 (lc(H(x0 - 1)) = 0, i.e. H(x0 - 1) - b0 < F), the span
// is the young chain (RULED 47 (a), E-79): fetch A could bring no S_{x0-1}.
// x0 = 1 is such a case (lc(H(0)) = 0).
template <class Rec>
inline SpanResult span_bounds(const LaneParams& p, std::uint64_t L, Rec&& rec, std::uint64_t b0 = 0) {
    SpanResult out;
    const std::uint64_t fr = p.open_bins + p.fresh_max;           // F + Fresh
    const std::uint64_t nrt = join_n_rt(p);                        // N_rt
    const std::uint64_t back = join_span(p, kSealDepth) - 1;       // E-16's 1,175
    const auto young = [&] {
        out.status = SpanStatus::Ok;
        out.bounds = SpanBounds{true, 0, 1, 1};
        return out;
    };
    const auto need = [&](std::uint64_t x) {
        out.status = SpanStatus::NeedRecord;
        out.need = x;
        return out;
    };
    if (L < nrt) return young();
    const std::optional<std::uint64_t> hl = rec(L);
    if (!hl) return need(L);
    if (*hl < fr) return young();
    const std::uint64_t thr = *hl - fr;  // H(L) - F - Fresh
    // L' = min(L - N_rt, the last x with H(x) <= thr)
    std::uint64_t lp = L - nrt;
    for (;;) {
        const std::optional<std::uint64_t> h = rec(lp);
        if (!h) return need(lp);
        if (*h <= thr) break;
        if (lp == 0) return young();  // no L'
        --lp;
    }
    if (lp <= back) return young();  // x0 <= 0
    const std::optional<std::uint64_t> hlp = rec(lp);
    if (!hlp) return need(lp);
    if (*hlp < fr) return young();
    const std::uint64_t thr2 = *hlp - fr;  // H(L') - F - Fresh
    // x0 = min(L' - 1,175, the first x with H(x) > thr2)
    std::uint64_t x0 = lp - back;
    {
        const std::optional<std::uint64_t> hz = rec(x0);
        if (!hz) return need(x0);
        if (*hz > thr2) {
            for (;;) {
                if (x0 == 0) return young();
                const std::optional<std::uint64_t> h = rec(x0 - 1);
                if (!h) return need(x0 - 1);
                if (*h <= thr2) break;
                --x0;
            }
        }
    }
    if (x0 == 0) return young();
    // x1 = the first x with H(x) >= H(x0 - 1) + F + Fresh
    const std::optional<std::uint64_t> hb = rec(x0 - 1);
    if (!hb) return need(x0 - 1);
    // ruling 47 (E-79): x0 >= 1 with no bin sealed before x0 (lc(H(x0 - 1)) = 0, i.e. H(x0 - 1) - b0 < F) -> the young
    // chain; x0 = 1 included (H(0) = b0, lc = 0): no seed_joiner(S_0, 1).
    if (b0 != 0 && (*hb < b0 || *hb - b0 < p.open_bins)) return young();
    const std::uint64_t want = *hb + fr;
    std::uint64_t x1 = x0;
    for (;; ++x1) {
        const std::optional<std::uint64_t> h = rec(x1);
        if (!h) return need(x1);
        if (*h >= want || x1 >= lp) break;
    }
    out.status = SpanStatus::Ok;
    out.bounds = SpanBounds{false, lp, x0, x1};
    return out;
}

// ---------------------------------------------------------------------------
// pre_start: the start x_pre of the claimed retarget prefix [x_pre, x0 - 1] of
// a join (ruling 53 JC-1ii-M (a), A (3); E-99): a formula of N_rt, J_0, F and
// Fresh over the candidate's records, as E-16's x0. The first x with H(x)
// above the threshold is known once the record of x - 1 is held (rec(0) = b0):
// `read_lo` is the lowest position whose record the formula reads (x_pre - 1
// where that first x decides and lies at or above 2), never below it.
// ---------------------------------------------------------------------------
struct PreStart {
    SpanStatus status = SpanStatus::Ok;
    std::uint64_t x_pre = 1;
    std::uint64_t read_lo = 1;  // the lowest position (>= 1) whose record the formula reads
    std::uint64_t need = 0;     // NeedRecord: the position whose record it needs next
};

template <class Rec>
inline PreStart pre_start(const LaneParams& p, std::uint64_t x0, Rec&& rec) {
    PreStart out;
    const auto need = [&](std::uint64_t x) {
        out.status = SpanStatus::NeedRecord;
        out.need = x;
        return out;
    };
    const std::uint64_t fr = p.open_bins + p.fresh_max;  // F + Fresh
    const std::uint64_t nrt = join_n_rt(p);
    const std::uint64_t j0 = journal_j0(p, kSealDepth);
    const std::uint64_t y = x0 > j0 ? x0 - 1 - j0 : 0;  // max(0, x0 - 1 - J_0)
    const std::optional<std::uint64_t> hy = rec(y);
    if (!hy) return need(y);
    out.read_lo = y > 0 ? y : 1;
    // the threshold H(y) - F - Fresh; below 0 every record exceeds it (the first x is 0)
    const bool all_above = *hy < fr;
    const std::uint64_t thr = all_above ? 0 : *hy - fr;
    const auto above = [&](std::uint64_t h) { return all_above || h > thr; };
    if (x0 <= nrt) {  // min(x0 - N_rt, .) <= 0: max(1, .) = 1
        out.x_pre = 1;
        out.read_lo = 1;
        return out;
    }
    const std::uint64_t top = x0 - nrt;
    const std::optional<std::uint64_t> ht = rec(top);
    if (!ht) return need(top);
    if (!above(*ht)) {  // the first x lies above x0 - N_rt
        out.x_pre = top;
        out.read_lo = std::min(out.read_lo, top);
        return out;
    }
    std::uint64_t x = top;  // H(x) above the threshold: the first such x is x or below
    while (x >= 1) {
        const std::optional<std::uint64_t> h = rec(x - 1);
        if (!h) return need(x - 1);
        if (!above(*h)) break;
        --x;
    }
    out.x_pre = std::max<std::uint64_t>(1, x);
    out.read_lo = x >= 2 ? x - 1 : 1;
    return out;
}

}  // namespace c2pool::xmr::pathb
