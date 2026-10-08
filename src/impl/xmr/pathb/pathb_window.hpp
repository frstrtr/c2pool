// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_window.hpp
// Path B, slice S3: the payout WINDOW measured in work, the owner / author weight
// shares and merge-back, the exact hf-16 split of the full reward R, the output
// order and the Merkle-SUM window_root (side_data offset 141).
//
//   window(bins, D_net, B, f_spend, N, author): whole bins back from the block's
//     OWN tip until the raw work reaches COVERAGE x D_net, never past W_max per
//     entry ((W + w_b) x f_spend <= B x min(d_min, d_min(b))), no decay; then the
//     N rule (drop the oldest bin while payees > N; one bin left -> cut by carrier
//     position, newest first then id ascending). [C38, K09, K11a, rulings 15/19]
//   shares: w_owner = floor(work x p / 10000), w_author = floor(work x ga /
//     10000), w_miner = work - w_owner - w_author. [K15, K16]
//   merge_back: identity X whose TOTAL window weight w_X (miner + owner + author
//     parts, before merge-back) has w_X x B(A_t) < W x f_spend returns its owner /
//     author share to the contributing receipts' miners; W constant. [K11b, 24 K-1]
//   split(R, w): q_i = floor(R w_i / W), largest remainder, ties by identity
//     ascending, Sum(vout) == R exactly; no outputs when the weights do not
//     sum to W. [K29a, C07, C21]
//   window_root: Merkle-SUM, leaf = (sha256d(0x06 || payee || LE256(w)), w),
//     node sums bound into the hash (0x07). [S3.2]
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <numeric>
#include <set>
#include <vector>

#include "pathb_buckets.hpp"  // BucketRow, domain bytes, sha256d helpers
#include "pathb_emission.hpp"
#include "pathb_params.hpp"
#include "pathb_wide.hpp"

namespace c2pool::xmr::pathb {

// COVERAGE (K09, ruling 19 R-C1): a unit of work is paid in 2 blocks on average.
inline constexpr std::uint64_t kCoverage = 2;

// One live receipt entry placed in a window bin (carrier or carried; a dead
// receipt is never passed here — it carries weight 0 and never enters the window).
struct WinEntry {
    Hash32 miner{};              // the receipt's payee identity
    Hash32 owner{};              // zero iff p == 0
    std::uint64_t work = 0;      // raw work(T_origin)
    std::uint16_t p = 0;         // fee_rate basis points (K15)
    std::uint16_t give_author_bp = 0;  // donation basis points (K16)
    std::uint64_t position = 0;  // carrier position (in-bin cut key)
    Hash32 id{};                 // receipt id (in-bin cut tiebreak)
};

struct WinBin {
    std::uint64_t bin = 0;  // origin bin h(r); newest bins come first in the list
    std::vector<WinEntry> entries;  // live receipt entries only
};

// The shares of a receipt are defined iff p + give_author_bp <= 10000: then
// w_owner + w_author <= work and the three shares sum to the work exactly.
// A receipt with p + give_author_bp > 10000 has no canonical coinbase and is
// refused at admission #12 (canonical_coinbase_ok_split); a window holding such
// an entry has no split (split() returns no outputs).
inline constexpr bool shares_defined(std::uint16_t p, std::uint16_t ga) noexcept {
    return static_cast<std::uint32_t>(p) + ga <= kBasisPointsScale;
}

// shares of one receipt's raw work (S3.1 item 10). Precondition:
// shares_defined(p, ga).
struct Shares {
    std::uint64_t w_miner = 0;
    std::uint64_t w_owner = 0;
    std::uint64_t w_author = 0;
};

inline Shares shares_of(std::uint64_t work, std::uint16_t p, std::uint16_t ga) {
    Shares s;
    s.w_owner = share_floor(work, p);
    s.w_author = share_floor(work, ga);
    const std::uint64_t taken = s.w_owner + s.w_author;
    s.w_miner = taken <= work ? work - taken : 0;
    return s;
}

// A resolved window: payee -> weight (after shares and merge-back), the window
// total W, and the sealed-bin-equivalent bucket rows the merge-back read.
struct Window {
    std::map<Hash32, Work> weight;  // final payee weights, identity order
    Work W{};
    std::vector<BucketRow> rows;    // one per (miner, owner) group, pre-merge-back
    bool empty_finder_only = false; // no window payee: one output of R to the finder
};

namespace detail_win {

// Raw live-work sum and the smallest live receipt-entry work of a bin.
inline void bin_stats(const WinBin& b, Work& raw_sum, std::uint64_t& d_min) {
    raw_sum = Work{};
    d_min = 0;
    bool first = true;
    for (const WinEntry& e : b.entries) {
        raw_sum += Work(e.work);
        if (first || e.work < d_min) {
            d_min = e.work;
            first = false;
        }
    }
}

// Group entries into (miner, owner) bucket rows with summed shares.
inline std::vector<BucketRow> rows_of(const std::vector<WinEntry>& entries) {
    std::map<std::pair<Hash32, Hash32>, BucketRow> by;
    for (const WinEntry& e : entries) {
        const Shares s = shares_of(e.work, e.p, e.give_author_bp);
        auto& row = by[{e.miner, e.owner}];
        row.miner = e.miner;
        row.owner = e.owner;
        row.w_miner += Work(s.w_miner);
        row.w_owner += Work(s.w_owner);
        row.w_author += Work(s.w_author);
    }
    std::vector<BucketRow> out;
    out.reserve(by.size());
    for (auto& [k, v] : by) out.push_back(v);
    return out;
}

// weight_X x B  <  W x f_spend   (below the spend floor), both sides U320.
inline bool below_floor(const Work& weight_x, std::uint64_t B, const Work& W, std::uint64_t f_spend) {
    return wide::mul_u256_u64(weight_x, B) < wide::mul_u256_u64(W, f_spend);
}

// Shares + merge-back over a set of live entries. author is the fixed donation
// identity; author weight merges back exactly like an owner's.
inline Window resolve(const std::vector<WinEntry>& entries, std::uint64_t B, std::uint64_t f_spend,
                      const Hash32& author) {
    Window w;
    w.rows = rows_of(entries);
    // window total W = total raw work (shares partition work exactly).
    for (const WinEntry& e : entries) w.W += Work(e.work);

    std::map<Hash32, Work> miner_w, owner_w;
    Work author_w{};
    for (const BucketRow& r : w.rows) {
        miner_w[r.miner] += r.w_miner;
        if (!(r.owner == kZeroHash)) owner_w[r.owner] += r.w_owner;
        author_w += r.w_author;
    }
    // w_X: the identity's total window weight before merge-back (miner + owner +
    // author parts). Every floor test reads these pre-merge totals.
    const bool have_author = !(author == kZeroHash);
    auto total_of = [&](const Hash32& x) {
        Work t;
        if (auto it = miner_w.find(x); it != miner_w.end()) t += it->second;
        if (auto it = owner_w.find(x); it != owner_w.end()) t += it->second;
        if (have_author && x == author) t += author_w;
        return t;
    };
    std::set<Hash32> owners_merging;
    for (const auto& [oid, ow] : owner_w)
        if (below_floor(total_of(oid), B, w.W, f_spend)) owners_merging.insert(oid);
    const bool author_merges = !have_author || author_w.is_zero()
                               || below_floor(total_of(author), B, w.W, f_spend);
    // merge-back: an owner below the floor returns its share to each contributing
    // receipt group's miner.
    for (const Hash32& oid : owners_merging) {
        for (const BucketRow& r : w.rows)
            if (r.owner == oid) miner_w[r.miner] += r.w_owner;
        owner_w[oid] = Work{};  // merged back: no owner share
    }
    if (author_merges) {
        for (const BucketRow& r : w.rows) miner_w[r.miner] += r.w_author;
    }
    // assemble final payees by identity.
    for (auto& [id, mw] : miner_w)
        if (!mw.is_zero()) w.weight[id] += mw;
    for (auto& [oid, ow] : owner_w)
        if (!ow.is_zero()) w.weight[oid] += ow;
    if (!author_merges && !author_w.is_zero()) w.weight[author] += author_w;
    return w;
}

// Distinct identity count the N rule bounds (the window payees).
inline std::size_t payee_count(const Window& w) { return w.weight.size(); }

// Pre-merge distinct identities (miners + owners with p > 0 + the author when
// any donation is present): an upper bound on the output count, monotone in the
// entry set, so the N rule can cut in one pass (merge-back only lowers it).
inline std::size_t distinct_identities(const std::vector<WinEntry>& entries, const Hash32& author) {
    std::set<Hash32> ids;
    bool any_author = false;
    for (const WinEntry& e : entries) {
        ids.insert(e.miner);
        if (e.p > 0 && !(e.owner == kZeroHash)) ids.insert(e.owner);
        if (e.give_author_bp > 0) any_author = true;
    }
    if (any_author && !(author == kZeroHash)) ids.insert(author);
    return ids.size();
}

}  // namespace detail_win

// step 1 of window(): select whole bins back to COVERAGE x D_net, never past
// W_max per entry ((W + w_b) x f_spend <= B x min(d_min, d_min(b))), no decay.
// Exposed so the spend-floor KAT can assert the F6 1,500-bin stop.
inline std::vector<WinBin> select_window_bins(const std::vector<WinBin>& bins_newest_first, std::uint64_t D_net,
                                              std::uint64_t B, std::uint64_t f_spend) {
    Work coverage_target;
    for (std::uint64_t i = 0; i < kCoverage; ++i) coverage_target += Work(D_net);
    std::vector<WinBin> sel;
    Work cum;              // running raw work == running W
    std::uint64_t d_min_g = 0;
    bool have_dmin = false;
    for (const WinBin& b : bins_newest_first) {
        if (!(cum < coverage_target)) break;  // reached coverage
        if (b.entries.empty()) continue;
        Work bin_raw;
        std::uint64_t bin_dmin = 0;
        detail_win::bin_stats(b, bin_raw, bin_dmin);
        const Work W_new = cum + bin_raw;
        const std::uint64_t dmin_new = have_dmin ? std::min(d_min_g, bin_dmin) : bin_dmin;
        // W_max per entry: (W + w_b) x f_spend <= B x min(d_min, d_min(b)).
        if (wide::mul_u64_u64(B, dmin_new) < wide::mul_u256_u64(W_new, f_spend)) break;
        sel.push_back(b);
        cum = W_new;
        d_min_g = dmin_new;
        have_dmin = true;
    }
    return sel;
}

// window(bins newest-first, D_net, B, f_spend, N, author): the whole slice-1
// payout window (D2.7 steps 0-6).
inline Window window(const std::vector<WinBin>& bins_newest_first, std::uint64_t D_net, std::uint64_t B,
                     std::uint64_t f_spend, std::uint64_t N, const Hash32& author) {
    // --- step 1: select whole bins back to COVERAGE x D_net, never past W_max ---
    std::vector<WinBin> sel = select_window_bins(bins_newest_first, D_net, B, f_spend);

    // flatten live entries of the selected bins.
    auto entries_of = [](const std::vector<WinBin>& v) {
        std::vector<WinEntry> e;
        for (const WinBin& b : v)
            for (const WinEntry& x : b.entries) e.push_back(x);
        return e;
    };

    // --- step 2: N rule. Drop the OLDEST bin while the (pre-merge) distinct
    // identities exceed N; one bin left -> cut it by carrier position (newest
    // first, then id ascending). Single pass (merge-back only lowers the count). ---
    if (N >= 1) {
        while (sel.size() > 1 && detail_win::distinct_identities(entries_of(sel), author) > N)
            sel.pop_back();  // drop the OLDEST selected bin (list is newest-first)
        if (sel.size() == 1 && detail_win::distinct_identities(sel.front().entries, author) > N) {
            std::vector<WinEntry>& e = sel.front().entries;
            std::sort(e.begin(), e.end(), [](const WinEntry& a, const WinEntry& b) {
                if (a.position != b.position) return a.position > b.position;  // newest first
                return std::lexicographical_compare(a.id.begin(), a.id.end(), b.id.begin(), b.id.end());
            });
            // keep the largest newest prefix whose distinct identities stay <= N.
            // distinct count is monotone, so one pass with one set (no copies).
            std::set<Hash32> ids;
            bool any_author = false;
            std::size_t keep = 0;
            const bool have_author = !(author == kZeroHash);
            for (std::size_t i = 0; i < e.size(); ++i) {
                ids.insert(e[i].miner);
                if (e[i].p > 0 && !(e[i].owner == kZeroHash)) ids.insert(e[i].owner);
                if (e[i].give_author_bp > 0) any_author = true;
                const std::size_t cnt = ids.size() + (any_author && have_author ? 1 : 0);
                if (cnt <= N)
                    keep = i + 1;
                else
                    break;  // monotone: once over N, no later prefix fits
            }
            e.resize(keep);
        }
    }

    // --- steps 3-5: shares + merge-back over the surviving entries. ---
    Window w = detail_win::resolve(entries_of(sel), B, f_spend, author);
    if (w.weight.empty()) w.empty_finder_only = true;
    return w;
}

// ---------------------------------------------------------------------------
// split(R, window) (S3.4 `split`; K29a, C07, C21): q_i = floor(R w_i / W) in
// U320, largest remainder, ties by payee identity ascending, Sum(vout) == R.
// A window whose weights do not sum to W (an entry with p + give_author_bp >
// 10000) has no split: no outputs.
// ---------------------------------------------------------------------------
struct SplitOutput {
    Hash32 payee{};
    std::uint64_t amount = 0;
};

// The payee weights sum to W exactly (merge-back only moves weight).
inline bool weights_sum_to_W(const Window& w) {
    Work sum;
    for (const auto& [payee, wt] : w.weight) sum += wt;
    return sum == w.W;
}

inline std::vector<SplitOutput> split(std::uint64_t R, const Window& w) {
    std::vector<SplitOutput> out;
    if (w.weight.empty()) return out;       // empty window -> finder-only (caller)
    if (!weights_sum_to_W(w)) return out;   // shares undefined: no split
    struct Row {
        Hash32 payee;
        Work w;
        std::uint64_t q;
        Work rem;
    };
    std::vector<Row> rows;
    rows.reserve(w.weight.size());
    std::uint64_t assigned = 0;
    for (const auto& [payee, wt] : w.weight) {  // std::map -> identity ascending
        Work rem;
        const std::uint64_t q = wide::divmod_u320_u256(wide::mul_u256_u64(wt, R), w.W, rem);
        assigned += q;
        rows.push_back({payee, wt, q, rem});
    }
    std::uint64_t deficit = R - assigned;  // 0 <= deficit < count (structural)
    // largest remainder: rank by remainder desc, ties by identity ascending
    // (rows are already in identity order, so a stable sort keeps the tie order).
    std::vector<std::size_t> order(rows.size());
    std::iota(order.begin(), order.end(), 0);
    std::stable_sort(order.begin(), order.end(),
                     [&](std::size_t a, std::size_t b) { return rows[b].rem < rows[a].rem; });
    for (std::size_t j = 0; j < order.size() && deficit > 0; ++j) {
        ++rows[order[j]].q;
        --deficit;
    }
    for (const Row& r : rows) out.push_back({r.payee, r.q});  // identity order
    return out;
}

// ---------------------------------------------------------------------------
// window_root (S3.4 `window_root`; S3.2): the Merkle-SUM root over (payee, w),
// payees sorted ascending by identity. Returns (hash, sum == W). Empty -> zero.
// ---------------------------------------------------------------------------
inline Hash32 window_sum_leaf(const Hash32& payee, const Work& w) {
    std::vector<std::uint8_t> pre;
    pre.reserve(1 + kHashBytes + 32);
    pre.push_back(kDomWinLeaf);
    pre.insert(pre.end(), payee.begin(), payee.end());
    const auto wb = le256(w);
    pre.insert(pre.end(), wb.begin(), wb.end());
    return ::v37::sha256d(pre);
}

inline Hash32 window_sum_node(const Hash32& lh, const Work& ls, const Hash32& rh, const Work& rs) {
    std::vector<std::uint8_t> pre;
    pre.reserve(1 + 2 * (kHashBytes + 32));
    pre.push_back(kDomWinNode);
    pre.insert(pre.end(), lh.begin(), lh.end());
    const auto lb = le256(ls);
    pre.insert(pre.end(), lb.begin(), lb.end());
    pre.insert(pre.end(), rh.begin(), rh.end());
    const auto rb = le256(rs);
    pre.insert(pre.end(), rb.begin(), rb.end());
    return ::v37::sha256d(pre);
}

inline Hash32 window_root(const Window& w, Work* sum_out = nullptr) {
    if (w.weight.empty()) {
        if (sum_out) *sum_out = Work{};
        return kZeroHash;
    }
    std::vector<std::pair<Hash32, Work>> level;  // (hash, sum) per node
    level.reserve(w.weight.size());
    for (const auto& [payee, wt] : w.weight) level.emplace_back(window_sum_leaf(payee, wt), wt);
    while (level.size() > 1) {
        std::vector<std::pair<Hash32, Work>> next;
        next.reserve((level.size() + 1) / 2);
        for (std::size_t i = 0; i < level.size(); i += 2) {
            if (i + 1 < level.size())
                next.emplace_back(window_sum_node(level[i].first, level[i].second, level[i + 1].first,
                                                  level[i + 1].second),
                                  level[i].second + level[i + 1].second);
            else
                next.push_back(level[i]);  // promote lone node (hash and sum)
        }
        level.swap(next);
    }
    if (sum_out) *sum_out = level.front().second;
    return level.front().first;
}

}  // namespace c2pool::xmr::pathb
