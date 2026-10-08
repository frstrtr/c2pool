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
//     OWN tip until the raw work reaches COVERAGE x D_net (D_net u128, compared
//     in U256), never past W_max per entry ((W + w_b) x f_spend <= B x
//     min(d_min, d_min(b))), no decay; when the newest bin alone fails W_max it
//     is cut by carrier position while W_kept x f_spend <= B x d_min(kept)
//     (R-12); then the N rule (drop the oldest bin while payees > N; one bin
//     left -> cut by carrier position, newest first then id ascending). Payees
//     counted for N: the identities whose total weight after shares (miner +
//     owner + author parts, before merge-back) is > 0 (R-13). [C38, C13, K09,
//     K11a, rulings 15/19]
//   A bin is OPEN (its live entries) or SEALED (its L1 bucket: raw_sum, d_min,
//     rows); both give the same window (ruling 20 Q-K). The bins are read
//     newest first from a source that may name a bin it does not hold
//     (MissingBucket / MissingEntries): the window is then not evaluated.
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
#include <utility>
#include <vector>

#include "pathb_buckets.hpp"  // BucketRow, domain bytes, sha256d helpers
#include "pathb_emission.hpp"
#include "pathb_params.hpp"
#include "pathb_wide.hpp"

namespace c2pool::xmr::pathb {

// COVERAGE (K09, ruling 19 R-C1).
inline constexpr std::uint64_t kCoverage = 2;

// D_net (D2.13): u128; COVERAGE x D_net is compared with the window work in U256.
using DNet = wide::u128;

// A receipt's work is >= d_min (K02) > 10000 basis points, so a share at bp >= 1
// is >= 1: owner and author presence reads the same from rows and from entries.
static_assert(kRuledLaneParams.d_min > kBasisPointsScale, "d_min must exceed the basis-point scale");

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
    std::vector<WinEntry> entries;     // open bin: live receipt entries only
    const L1Bucket* sealed = nullptr;  // sealed bin: its bucket (raw_sum, d_min, rows); entries empty
};

// shares of one receipt's raw work (S3.1 item 10). The shares are defined iff
// p + give_author_bp <= 10000: then w_owner + w_author <= work and the three
// shares sum to the work exactly. A receipt with p + give_author_bp > 10000 is
// refused at admission #2 (side_data_v3_check, STRIKE); a window holding such an
// entry has no split (split() returns no outputs).
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

inline bool bin_empty(const WinBin& b) { return b.sealed != nullptr ? b.sealed->rows.empty() : b.entries.empty(); }

// Raw live-work sum and the smallest live receipt-entry work of a bin (a sealed
// bin: its bucket's raw_sum and d_min).
inline void bin_stats(const WinBin& b, Work& raw_sum, std::uint64_t& d_min) {
    if (b.sealed != nullptr) {
        raw_sum = b.sealed->raw_sum;
        d_min = b.sealed->d_min;
        return;
    }
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

// The rows of a set of bins: open entries after shares and sealed bucket rows,
// aggregated by (miner, owner); W = their raw work.
inline std::vector<BucketRow> rows_of_bins(const std::vector<WinBin>& bins, Work& W) {
    std::map<std::pair<Hash32, Hash32>, BucketRow> by;
    W = Work{};
    for (const WinBin& b : bins) {
        if (b.sealed != nullptr) {
            for (const BucketRow& r : b.sealed->rows) {
                auto& row = by[{r.miner, r.owner}];
                row.miner = r.miner;
                row.owner = r.owner;
                row.w_miner += r.w_miner;
                row.w_owner += r.w_owner;
                row.w_author += r.w_author;
            }
            W += b.sealed->raw_sum;
            continue;
        }
        for (const WinEntry& e : b.entries) {
            const Shares s = shares_of(e.work, e.p, e.give_author_bp);
            auto& row = by[{e.miner, e.owner}];
            row.miner = e.miner;
            row.owner = e.owner;
            row.w_miner += Work(s.w_miner);
            row.w_owner += Work(s.w_owner);
            row.w_author += Work(s.w_author);
            W += Work(e.work);
        }
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

// Merge-back over the window rows (W = the window's raw work). author is the
// fixed donation identity; author weight merges back exactly like an owner's.
inline Window resolve_rows(std::vector<BucketRow> rows, const Work& W, std::uint64_t B, std::uint64_t f_spend,
                           const Hash32& author) {
    Window w;
    w.rows = std::move(rows);
    w.W = W;

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

// Shares + merge-back over a set of window bins.
inline Window resolve_bins(const std::vector<WinBin>& bins, std::uint64_t B, std::uint64_t f_spend,
                           const Hash32& author) {
    Work W;
    std::vector<BucketRow> rows = rows_of_bins(bins, W);
    return resolve_rows(std::move(rows), W, B, f_spend, author);
}

// Shares + merge-back over a set of live entries.
inline Window resolve(const std::vector<WinEntry>& entries, std::uint64_t B, std::uint64_t f_spend,
                      const Hash32& author) {
    std::vector<WinBin> one(1);
    one.front().entries = entries;
    return resolve_bins(one, B, f_spend, author);
}

// Distinct identity count the N rule bounds (the window payees).
inline std::size_t payee_count(const Window& w) { return w.weight.size(); }

// The payees the N rule counts (R-13): the identities whose total window weight
// after shares (miner + owner + author parts, before merge-back) is > 0. The
// parts are >= 0, so an identity counts once any part of it is > 0; the count is
// monotone in the entry set and reads the same from entries and from rows.
class PayeeCount {
public:
    explicit PayeeCount(const Hash32& author) : author_(author), have_author_(!(author == kZeroHash)) {}

    void add_entry(const WinEntry& e) {
        const Shares s = shares_of(e.work, e.p, e.give_author_bp);
        if (s.w_miner > 0) ids_.insert(e.miner);
        if (!(e.owner == kZeroHash) && s.w_owner > 0) ids_.insert(e.owner);
        if (have_author_ && s.w_author > 0) ids_.insert(author_);
    }
    void add_row(const BucketRow& r) {
        if (!r.w_miner.is_zero()) ids_.insert(r.miner);
        if (!(r.owner == kZeroHash) && !r.w_owner.is_zero()) ids_.insert(r.owner);
        if (have_author_ && !r.w_author.is_zero()) ids_.insert(author_);
    }
    void add_bin(const WinBin& b) {
        if (b.sealed != nullptr) {
            for (const BucketRow& r : b.sealed->rows) add_row(r);
            return;
        }
        for (const WinEntry& e : b.entries) add_entry(e);
    }
    std::size_t count() const noexcept { return ids_.size(); }

private:
    Hash32 author_;
    bool have_author_;
    std::set<Hash32> ids_;
};

inline std::size_t distinct_identities(const std::vector<WinEntry>& entries, const Hash32& author) {
    PayeeCount c(author);
    for (const WinEntry& e : entries) c.add_entry(e);
    return c.count();
}

// The in-bin cut order: carrier position descending (newest first), then id ascending.
inline void sort_newest_first(std::vector<WinEntry>& e) {
    std::sort(e.begin(), e.end(), [](const WinEntry& a, const WinEntry& b) {
        if (a.position != b.position) return a.position > b.position;
        return std::lexicographical_compare(a.id.begin(), a.id.end(), b.id.begin(), b.id.end());
    });
}

// W_max over a prefix: W x f_spend <= B x d_min.
inline bool within_w_max(const Work& W, std::uint64_t d_min, std::uint64_t B, std::uint64_t f_spend) {
    return !(wide::mul_u64_u64(B, d_min) < wide::mul_u256_u64(W, f_spend));
}

}  // namespace detail_win

// ---------------------------------------------------------------------------
// The bins of a window are read newest first from a source: a Bin, the End of
// the lane, or a bin the source does not hold (its bucket, or the placements of
// an open bin). A window is never evaluated over a partial bin list.
// ---------------------------------------------------------------------------
enum class PullKind : std::uint8_t { Bin, End, MissingBucket, MissingEntries };

struct BinPull {
    PullKind kind = PullKind::End;
    WinBin bin;
    std::uint64_t missing_bin = 0;
};

enum class WinStatus : std::uint8_t {
    Ok,
    MissingBucket,   // missing_bin: the sealed bin whose bucket is not held (fetch it)
    MissingEntries,  // missing_bin: the open bin whose placements are not held (rebuild)
    SealedCut,       // a cut by carrier position would fall in a sealed bin (no window)
};

struct WinSelect {
    WinStatus status = WinStatus::Ok;
    std::uint64_t missing_bin = 0;
    std::vector<WinBin> bins;  // selected, newest first
    std::uint64_t read = 0;    // bins read from the source
};

// step 1 of window(): select whole bins back to COVERAGE x D_net, never past
// W_max per entry ((W + w_b) x f_spend <= B x min(d_min, d_min(b))), no decay.
// The newest non-empty bin failing W_max on its own is cut by carrier position
// while W_kept x f_spend <= B x d_min(kept) (R-12). pull() yields the next bin.
template <class Pull>
inline WinSelect select_window_bins_from(Pull&& pull, DNet D_net, std::uint64_t B, std::uint64_t f_spend) {
    Work coverage_target;
    const Work d_net = Work::from_u128(D_net);
    for (std::uint64_t i = 0; i < kCoverage; ++i) coverage_target += d_net;
    WinSelect out;
    Work cum;              // running raw work == running W
    std::uint64_t d_min_g = 0;
    bool have_dmin = false;
    for (;;) {
        if (!(cum < coverage_target)) break;  // reached coverage
        BinPull p = pull();
        if (p.kind == PullKind::End) break;
        ++out.read;
        if (p.kind == PullKind::MissingBucket || p.kind == PullKind::MissingEntries) {
            out.status = p.kind == PullKind::MissingBucket ? WinStatus::MissingBucket : WinStatus::MissingEntries;
            out.missing_bin = p.missing_bin;
            out.bins.clear();
            return out;
        }
        WinBin& b = p.bin;
        if (detail_win::bin_empty(b)) continue;
        Work bin_raw;
        std::uint64_t bin_dmin = 0;
        detail_win::bin_stats(b, bin_raw, bin_dmin);
        const Work W_new = cum + bin_raw;
        const std::uint64_t dmin_new = have_dmin ? std::min(d_min_g, bin_dmin) : bin_dmin;
        // W_max per entry: (W + w_b) x f_spend <= B x min(d_min, d_min(b)).
        if (!detail_win::within_w_max(W_new, dmin_new, B, f_spend)) {
            if (out.bins.empty()) {  // the newest bin alone fails W_max: cut it (R-12)
                if (b.sealed != nullptr) {
                    out.status = WinStatus::SealedCut;
                    out.missing_bin = b.bin;
                    return out;
                }
                std::vector<WinEntry>& e = b.entries;
                detail_win::sort_newest_first(e);
                Work W;
                std::uint64_t d = 0;
                std::size_t keep = 0;
                for (std::size_t i = 0; i < e.size(); ++i) {
                    W += Work(e[i].work);
                    d = i == 0 ? e[i].work : std::min(d, e[i].work);
                    if (!detail_win::within_w_max(W, d, B, f_spend)) break;  // monotone in the prefix
                    keep = i + 1;
                }
                e.resize(keep);
                if (keep > 0) out.bins.push_back(std::move(b));
            }
            break;
        }
        out.bins.push_back(std::move(b));
        cum = W_new;
        d_min_g = dmin_new;
        have_dmin = true;
    }
    return out;
}

// A source over bins already listed newest first.
struct ListedBins {
    const std::vector<WinBin>& bins;
    std::size_t next = 0;
    BinPull operator()() {
        if (next == bins.size()) return BinPull{};
        return BinPull{PullKind::Bin, bins[next++], 0};
    }
};

// step 1 over listed bins. Exposed so the spend-floor KAT can assert the F6
// 1,500-bin stop.
inline std::vector<WinBin> select_window_bins(const std::vector<WinBin>& bins_newest_first, DNet D_net,
                                              std::uint64_t B, std::uint64_t f_spend) {
    WinSelect s = select_window_bins_from(ListedBins{bins_newest_first}, D_net, B, f_spend);
    return std::move(s.bins);
}

// A window evaluated from a source, or the bin that stopped it.
struct WinEval {
    WinStatus status = WinStatus::Ok;
    std::uint64_t missing_bin = 0;
    Window window;
    std::uint64_t read = 0;        // bins read from the source
    std::uint64_t oldest_bin = 0;  // the oldest bin left in the window (0: none)
};

// window(source, D_net, B, f_spend, N, author): the whole payout window (D2.7
// steps 0-6) over the bins the source yields newest first.
template <class Pull>
inline WinEval window_from(Pull&& pull, DNet D_net, std::uint64_t B, std::uint64_t f_spend, std::uint64_t N,
                           const Hash32& author) {
    WinEval out;
    // --- step 1: select whole bins back to COVERAGE x D_net, never past W_max ---
    WinSelect s = select_window_bins_from(std::forward<Pull>(pull), D_net, B, f_spend);
    out.read = s.read;
    if (s.status != WinStatus::Ok) {
        out.status = s.status;
        out.missing_bin = s.missing_bin;
        return out;
    }
    std::vector<WinBin>& sel = s.bins;

    // --- steps 3-4: N rule. Drop the OLDEST bin while the payees (R-13) exceed
    // N: keep the longest newest prefix whose count stays <= N (the count is
    // monotone); the newest bin alone over N -> cut it by carrier position
    // (newest first, then id ascending), keeping the longest prefix within N. ---
    if (N >= 1 && !sel.empty()) {
        detail_win::PayeeCount pc(author);
        std::size_t k = 0;
        for (; k < sel.size(); ++k) {
            pc.add_bin(sel[k]);
            if (pc.count() > N) break;
        }
        if (k >= 1) {
            sel.resize(k);  // the oldest bins leave the window
        } else {
            sel.resize(1);
            if (sel.front().sealed != nullptr) {
                out.status = WinStatus::SealedCut;
                out.missing_bin = sel.front().bin;
                return out;
            }
            std::vector<WinEntry>& e = sel.front().entries;
            detail_win::sort_newest_first(e);
            detail_win::PayeeCount cut(author);
            std::size_t keep = 0;
            for (std::size_t i = 0; i < e.size(); ++i) {
                cut.add_entry(e[i]);
                if (cut.count() > N) break;  // monotone: once over N, no later prefix fits
                keep = i + 1;
            }
            e.resize(keep);
        }
    }

    // --- step 5: shares + merge-back over the surviving bins. ---
    out.oldest_bin = sel.empty() ? 0 : sel.back().bin;
    out.window = detail_win::resolve_bins(sel, B, f_spend, author);
    if (out.window.weight.empty()) out.window.empty_finder_only = true;
    return out;
}

// window(bins newest-first, D_net, B, f_spend, N, author) over listed bins. A
// list that stops the window (a cut inside a sealed bin) gives an empty window
// that is not finder-only.
inline Window window(const std::vector<WinBin>& bins_newest_first, DNet D_net, std::uint64_t B,
                     std::uint64_t f_spend, std::uint64_t N, const Hash32& author) {
    WinEval e = window_from(ListedBins{bins_newest_first}, D_net, B, f_spend, N, author);
    if (e.status != WinStatus::Ok) return Window{};
    return std::move(e.window);
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
