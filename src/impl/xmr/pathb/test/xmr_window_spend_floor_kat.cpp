// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// xmr_window_spend_floor_kat (pathb_window.hpp / pathb_emission.hpp, C38, K11a):
//   W_max = B(A_t) x d / f_spend PER ENTRY; the F6 vector stops the window at
//   1,500 bins (W 1,440,000,000, entry value 33,333,333; bin 1,501 would give
//   W 1,440,240,000, entry value 8,331,944); a window of 47,885 entries at one d
//   (B / f_spend at 6e11, hf 16) and no payee output below f_spend, entry 47,886
//   excluded; the cap stops at <= (W x f == B x d_min kept, one unit more cut);
//   f_spend(6e11, 300k, hf16) == 12,530,000; f_spend(6e11, 625k, hf17) ==
//   12,660,000 (reference weight 12,500, no 0.95); a larger fee median M
//   quarters the fee per byte; B(A_t) on both sides (the window reads B, never R:
//   signature); d_min over receipt entries (a carried entry below every carrier
//   in its bin cuts the bin; a carriers-only reading would keep it); two build
//   orders (carrier entries first / carried entries first, placements in chain
//   order / reverse) give one window_root and one split, the in-bin cut included.
// S3b-1b (pathb_window_chain.hpp; P-37 / P-38, C38, C41):
//   through the store: carrier-first, carried-first and reversed cross-bin
//   ingest orders give one window_root (N 3,747 / 6 / 2, the in-bin cut at one
//   placing position included); a dead placement of work 100 does not lower
//   d_min;
//   M(A_t) doubles between two tips (300,000 -> 600,000 at A_t; f_spend
//   12,530,000 -> 3,140,000): the second window reaches bins older than every
//   window in the journal; a store whose bucket bodies are pruned to the oldest
//   bin those windows read DEFERs (MissingBucket, 54 fetches), never a
//   different window_root, and after the fetches is byte-equal to a store that
//   never pruned; a served body that does not hash to the leaf is refused;
//   placements pruned at the P-37 limit: every tip in the journal unchanged,
//   an older tip DEFERs (MissingEntries).
// ---------------------------------------------------------------------------
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <type_traits>
#include <vector>

#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "impl/xmr/pathb/pathb_window_chain.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_kat_lane.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

pb::Hash32 rep(std::uint8_t b) { pb::Hash32 h{}; h.fill(b); return h; }
pb::WinEntry e(std::uint8_t miner, std::uint64_t work, std::uint64_t pos) {
    pb::WinEntry x; x.miner = rep(miner); x.work = work; x.position = pos; x.id = rep(miner); return x;
}
// identity with `i` in the last 8 bytes big-endian: memcmp order == numeric order.
pb::Hash32 id_of(std::uint64_t i) {
    pb::Hash32 h{};
    for (int b = 0; b < 8; ++b) h[31 - b] = static_cast<std::uint8_t>(i >> (8 * b));
    return h;
}
std::uint64_t raw_work(const std::vector<pb::WinBin>& bins) {
    std::uint64_t w = 0;
    for (const pb::WinBin& b : bins)
        for (const pb::WinEntry& x : b.entries) w += x.work;
    return w;
}
std::uint64_t smallest(const std::vector<pb::SplitOutput>& o) {
    std::uint64_t s = ~std::uint64_t{0};
    for (const auto& x : o) s = x.amount < s ? x.amount : s;
    return s;
}

// The window reads B(A_t) and f_spend; R (base + fees) is not an input.
static_assert(std::is_same_v<decltype(&pb::select_window_bins),
                             std::vector<pb::WinBin> (*)(const std::vector<pb::WinBin>&, pb::DNet, std::uint64_t,
                                                         std::uint64_t)>,
              "select_window_bins(bins, D_net, B, f_spend)");
static_assert(std::is_same_v<decltype(&pb::window),
                             pb::Window (*)(const std::vector<pb::WinBin>&, pb::DNet, std::uint64_t, std::uint64_t,
                                            std::uint64_t, const pb::Hash32&)>,
              "window(bins, D_net, B, f_spend, N, author)");
static_assert(std::is_same_v<pb::DNet, unsigned __int128>, "D_net is u128");

constexpr pb::DNet kHuge = pb::DNet{1} << 100;

pb::WindowParams params(std::uint64_t N) {
    pb::WindowParams wp;
    wp.d_net = kHuge;
    wp.B = 600000000000ull;
    wp.f_spend = pb::f_spend(wp.B, 300000, 16);
    wp.N = N;
    return wp;
}

// ---- build orders through the store ----
void s3b_store_build_orders() {
    const pb::LaneParams P = pb::kRuledLaneParams;
    constexpr std::uint64_t b0 = 5000;
    // the carried list of position 4 holds bins b0 and b0 + 1 (canonical: bin ascending).
    struct C { std::uint64_t pos, h; std::vector<pb::Placement> own, carried; };
    const std::vector<C> chain{
            {1, b0, {rcpt(idn(0xD5, 1), b0, 1, idn(0xA5, 1), 30000)}, {}},
            {2, b0, {rcpt(idn(0xD5, 2), b0, 2, idn(0xA5, 2), 31000)}, {}},
            {3, b0, {rcpt(idn(0xD5, 3), b0, 3, idn(0xA5, 3), 32000)}, {}},
            {4, b0 + 1, {rcpt(idn(0xD5, 4), b0 + 1, 4, idn(0xA5, 4), 33000)},
             {rcpt(idn(0xD6, 5), b0, 3, idn(0xA5, 5), 34000), rcpt(idn(0xD6, 6), b0 + 1, 3, idn(0xA5, 6), 35000)}},
            {5, b0 + 1, {rcpt(idn(0xD5, 7), b0 + 1, 5, idn(0xA5, 7), 36000)},
             {rcpt(idn(0xD6, 8), b0 + 1, 4, idn(0xA5, 8), 37000), rcpt(idn(0xD6, 9), b0 + 1, 4, idn(0xA5, 9), 38000)}},
    };
    // 0: carried list then the carrier (canonical); 1: the carrier first; 2: carried list reversed.
    std::vector<pb::Hash32> roots[3];
    for (int order = 0; order < 3; ++order) {
        pb::BinStore s(P, 64, idn(0xC5, 0), b0);
        bool ok = true;
        for (const C& c : chain) {
            std::vector<pb::Placement> pls;
            std::vector<pb::Placement> carried = c.carried;
            if (order == 2) std::reverse(carried.begin(), carried.end());
            if (order == 1) pls.insert(pls.end(), c.own.begin(), c.own.end());
            pls.insert(pls.end(), carried.begin(), carried.end());
            if (order != 1) pls.insert(pls.end(), c.own.begin(), c.own.end());
            ok = ok && extend(s, idn(0xC5, c.pos), idn(0xC5, c.pos - 1), c.h, pls, true);
        }
        check(ok, "store build order " + std::to_string(order) + ": chain built");
        for (const std::uint64_t N : {std::uint64_t{3747}, std::uint64_t{6}, std::uint64_t{2}}) {
            const pb::TipWindow w = pb::tip_window(s, idn(0xC5, 5), params(N), 16);
            roots[order].push_back(w.ok() ? w.window_root : pb::Hash32{});
            if (order == 0 && N == 3747) check(w.ok() && w.window->weight.size() == 9, "store: N 3,747 -> 9 payees");
            if (order == 0 && N == 6) check(w.ok() && w.window->weight.size() == 5, "store: N 6 -> the newest bin, 5 payees");
            if (order == 0 && N == 2) check(w.ok() && w.window->weight.size() == 2, "store: N 2 -> cut at position 5, 2 payees");
        }
    }
    check(roots[0] == roots[1] && roots[0] == roots[2] && roots[0].size() == 3,
          "store: carrier-first, carried-first and reversed cross-bin orders give one window_root (N 3,747 / 6 / 2)");
}

// ---- d_min over LIVE receipt entries through the store ----
void s3b_store_dead_dmin() {
    const pb::LaneParams P = pb::kRuledLaneParams;
    constexpr std::uint64_t b0 = 6000;
    pb::BinStore s(P, 64, idn(0xC6, 0), b0);
    bool ok = true;
    for (std::uint64_t pos = 1; pos <= 6; ++pos) {
        const std::uint64_t h = pos <= 3 ? b0 : b0 + 5;
        std::vector<pb::Placement> pls{rcpt(idn(0xD7, pos), h, pos, idn(0xA7, pos), 3000000)};
        // position 6 carries a receipt of bin b0 + 1 whose own position reads H = b0 + 5: dead.
        if (pos == 6) pls.insert(pls.begin(), rcpt(idn(0xD8, 6), b0 + 1, 6, idn(0xA8, 6), 100));
        ok = ok && extend(s, idn(0xC6, pos), idn(0xC6, pos - 1), h, pls, true);
    }
    check(ok, "dead d_min: chain built");
    const pb::WinResult bins = pb::win_bins_at(s, idn(0xC6, 6));
    check(bins.view == pb::ViewStatus::Ok && bins.status == pb::WinStatus::Ok && bins.bins.size() == 8
                  && bins.bins[2].entries.size() == 3 && bins.bins[6].entries.empty() && bins.bins[7].entries.size() == 3,
          "dead d_min: win_bins_at b0 + 7 .. b0: 3 live entries in b0 + 5, none in b0 + 1, 3 in b0");
    bool dead_stored = false;
    for (const pb::Placement& x : s.delta(idn(0xC6, 6))->placed)
        if (x.id == idn(0xD8, 6)) dead_stored = !x.live;
    check(dead_stored, "dead d_min: the work-100 placement is stored dead");
    const pb::TipWindow w = pb::tip_window(s, idn(0xC6, 6), params(3747), 16);
    check(w.ok() && w.window->weight.size() == 6 && w.window->W == pb::Work(18000000ull),
          "dead d_min: the dead entry does not lower d_min: 6 payees, W 18,000,000");
    check(w.ok() && w.window->weight.count(idn(0xA8, 6)) == 0, "dead d_min: the dead receipt is not credited");
}

// ---- M(A_t) doubles; P-38 / P-37 retention ----
void s3b_m_doubles_and_retention() {
    const pb::LaneParams P = pb::kRuledLaneParams;
    constexpr std::uint64_t b0 = 1000;
    constexpr std::uint8_t kTag = 0x4d;
    constexpr std::uint64_t kJ = 64;
    constexpr std::uint64_t kSmallPos = 180;
    constexpr std::uint64_t kL = 20000000;
    const std::uint64_t t1 = 299, t2 = 300;
    // A_t of t2 is Monero 1,239 (P_t2 = 1,299): Z = M = 600,000 there, 300,000 elsewhere.
    KatMoneroRows m = monero_chain(kTag, 1305, 2000000000ull, [](std::uint64_t h) {
        return std::optional<pb::RowWeights>(h == 1239 ? rw(kTailAgc, 600000, 600000) : rw(kTailAgc, 300000, 300000));
    });
    const pb::FollowerBranchView view(m);
    pb::BinStore full(P, kJ, idn(0xC7, 0), b0), pruned(P, kJ, idn(0xC7, 0), b0), ent(P, kJ, idn(0xC7, 0), b0);
    bool ok = true;
    for (std::uint64_t pos = 1; pos <= t2; ++pos) {
        const std::vector<pb::Placement> pls{
                rcpt(idn(0xD9, pos), b0 + pos, pos, idn(0xA9, pos % 8), pos == kSmallPos ? 18180 : kL)};
        for (pb::BinStore* st : {&full, &pruned, &ent})
            ok = ok && extend(*st, idn(0xC7, pos), idn(0xC7, pos - 1), b0 + pos, pls, true);
    }
    check(ok, "M doubles: three stores of 300 carriers, one height per position");
    const pb::Hash32 author{};
    auto eval = [&](const pb::BinStore& st, std::uint64_t pos) {
        return pb::evaluate_window_at(st, idn(0xC7, pos), block_id(kTag, b0 + pos - 1), view, 16, author);
    };
    check(pb::f_spend(600000000000ull, 300000, 16) == 12530000ull && pb::f_spend(600000000000ull, 600000, 16) == 3140000ull,
          "M doubles: f_spend 12,530,000 at M 300,000, 3,140,000 at M 600,000");

    // every tip in the journal before t2: windows stop above the small bin.
    std::uint64_t min_oldest = std::numeric_limits<std::uint64_t>::max(), min_read = min_oldest;
    bool journal_ok = true;
    std::vector<pb::Hash32> journal_roots;
    for (std::uint64_t pos = t2 - kJ; pos < t2; ++pos) {
        const pb::TipWindow w = eval(full, pos);
        journal_ok = journal_ok && w.ok() && w.inputs.weights.fee_median == 300000;
        if (!w.ok()) continue;
        journal_roots.push_back(w.window_root);
        min_oldest = std::min(min_oldest, w.oldest_bin);
        min_read = std::min(min_read, b0 + pos + P.fresh_max + 1 - w.bins_read);
    }
    check(journal_ok, "M doubles: the 64 tips before t2 evaluate at M 300,000");
    check(min_oldest == b0 + kSmallPos + 1 && min_read == b0 + kSmallPos,
          "M doubles: their windows stop at bin b0 + 181 and read down to b0 + 180");
    const pb::TipWindow w1 = eval(full, t1);
    check(w1.ok() && w1.oldest_bin == b0 + kSmallPos + 1 && w1.window->W == pb::Work(119 * kL),
          "M doubles: window(t1): bins b0 + 299 .. b0 + 181, W 2,380,000,000");
    const pb::TipWindow w2 = eval(full, t2);
    check(w2.ok() && w2.inputs.weights.fee_median == 600000 && w2.oldest_bin == b0 + 127,
          "M doubles: window(t2) at M 600,000 reaches bin b0 + 127, older than every window before it");
    check(w2.ok() && w2.window->W == pb::Work(173 * kL + 18180), "M doubles: window(t2) W 3,460,018,180");

    // P-38: bucket bodies pruned to the oldest bin the journal's windows read.
    const std::size_t dropped = pruned.prune_buckets(min_read);
    check(dropped == kSmallPos, "P-38: 180 bucket bodies dropped (bins b0 .. b0 + 179), leaves kept");
    check(pruned.best_mmr().root() == full.best_mmr().root(), "P-38: the MMR is unchanged");
    bool same_journal = true;
    for (std::uint64_t pos = t2 - kJ, i = 0; pos < t2; ++pos, ++i) {
        const pb::TipWindow w = eval(pruned, pos);
        same_journal = same_journal && w.ok() && i < journal_roots.size() && w.window_root == journal_roots[i];
    }
    check(same_journal, "P-38: every tip before t2 evaluates on the pruned store with the same window_root");
    std::uint64_t defers = 0;
    bool only_missing_bucket = true, refused_bad = false, refused_held = false;
    pb::TipWindow w2p = eval(pruned, t2);
    check(!w2p.ok() && w2p.defer == pb::WindowDefer::MissingBucket && w2p.missing_bin == b0 + 179,
          "P-38: window(t2) on the pruned store DEFERs: MissingBucket b0 + 179");
    while (!w2p.ok() && defers < 1000) {
        only_missing_bucket = only_missing_bucket && w2p.defer == pb::WindowDefer::MissingBucket;
        if (w2p.defer != pb::WindowDefer::MissingBucket) break;
        ++defers;
        const pb::SealedBin* sb = full.view_at(full.best_tip()).bucket(w2p.missing_bin);
        if (sb == nullptr) break;
        if (defers == 1) {
            pb::L1Bucket bad = sb->bucket;  // consistent, but not the sealed body
            bad.rows.front().w_miner += pb::Work(1);
            bad.raw_sum += pb::Work(1);
            bad.comp_root_v = pb::comp_root(bad.rows);
            refused_bad = pb::bucket_consistent(bad) && !pruned.restore_bucket(bad, sb->refs);
        }
        pruned.restore_bucket(sb->bucket, sb->refs);
        w2p = eval(pruned, t2);
    }
    {
        const pb::SealedBin* held = full.view_at(full.best_tip()).bucket(b0 + 200);
        refused_held = held != nullptr && !pruned.restore_bucket(held->bucket, held->refs);
    }
    check(only_missing_bucket && defers == 54, "P-38: 54 DEFERs (b0 + 179 .. b0 + 126), each a MissingBucket");
    check(refused_bad && refused_held, "P-38: a served body that does not hash to the leaf, or of a held bin, is refused");
    check(w2p.ok() && w2.ok() && w2p.window_root == w2.window_root && w2p.sum == w2.sum
                  && w2p.mmr_root == w2.mmr_root && w2p.window->weight == w2.window->weight
                  && w2p.oldest_bin == w2.oldest_bin,
          "P-38: after the fetches window(t2) is byte-equal to the never-pruned store");

    // P-37: placements pruned at the limit.
    const std::uint64_t limit = ent.entry_floor_limit();
    check(limit == b0 + 105, "P-37: the limit at tip 300, J 64: min(H(236), H(300) - 98) - 98 + 1 = b0 + 105");
    check(ent.prune_entries(std::numeric_limits<std::uint64_t>::max()) == limit && ent.entry_floor() == limit,
          "P-37: a floor above the limit is clamped to it");
    bool ent_journal = true;
    for (std::uint64_t pos = t2 - kJ, i = 0; pos < t2; ++pos, ++i) {
        const pb::TipWindow w = eval(ent, pos);
        ent_journal = ent_journal && w.ok() && i < journal_roots.size() && w.window_root == journal_roots[i];
    }
    const pb::TipWindow w2e = eval(ent, t2);
    check(ent_journal && w2e.ok() && w2e.window_root == w2.window_root,
          "P-37: every tip in the journal and t2 unchanged");
    const pb::TipWindow old_full = eval(full, 150), old_ent = eval(ent, 150);
    check(old_full.ok() && !old_ent.ok() && old_ent.defer == pb::WindowDefer::MissingEntries
                  && old_ent.missing_bin == b0 + 104,
          "P-37: a tip below the journal whose open bins were pruned DEFERs: MissingEntries b0 + 104");
}

}  // namespace

int main() {
    const std::uint64_t B = 600000000000ull;  // 6e11
    const std::uint64_t kHugeDnet = 1000000000000000ull;  // COVERAGE never binds

    // ---- f_spend values (K11d, ruling 5) ----
    check(pb::f_spend(B, 300000, 16) == 12530000ull, "f_spend(6e11, M 300k, hf16) == 12,530,000");
    // fee per byte scales as 1/M^2: M 600k -> a quarter of the M 300k value.
    check(pb::fee_per_byte(B, 600000, 16) * 4 == pb::fee_per_byte(B, 300000, 16),
          "fee per byte at M 600k == 1/4 of the M 300k value");
    // the floor at max(M, zone): M below the penalty-free zone reads the zone.
    check(pb::f_spend(B, 100000, 16) == pb::f_spend(B, 300000, 16), "f_spend floors M at the zone");

    // hf 17 constants at hf 17: reference weight 12,500, no 0.95, zone 625,000.
    check(pb::fee_per_byte(B, 625000, 17) == 19200ull, "fee per byte (6e11, M 625k, hf17) == 19,200");
    check(pb::f_spend(B, 625000, 17) == 12660000ull, "f_spend(6e11, M 625k, hf17) == 12,660,000");
    check(pb::f_spend(B, 300000, 17) == 12660000ull, "f_spend(6e11, M 300k, hf17) floors M at the hf 17 zone");
    check(pb::fee_per_byte(B, 300000, 15) == pb::fee_per_byte(B, 300000, 16), "0.95 at hf 15 and 16");

    const std::uint64_t f = pb::f_spend(B, 300000, 16);  // 12,530,000

    // ---- the F6 W_max vector: 1,500 bins at d 80,000 then bins at d 20,000 ----
    {
        std::vector<pb::WinBin> bins;
        std::uint64_t pos = 2000000;
        for (int k = 0; k < 1500; ++k) {           // newest-first, d = 80,000
            pb::WinBin b; b.bin = 2000000 - k;
            for (int j = 0; j < 12; ++j) b.entries.push_back(e(static_cast<std::uint8_t>(0x60 + j), 80000, pos--));
            bins.push_back(b);
        }
        for (int k = 0; k < 20; ++k) {             // then d = 20,000
            pb::WinBin b; b.bin = 1000000 - k;
            for (int j = 0; j < 12; ++j) b.entries.push_back(e(static_cast<std::uint8_t>(0x60 + j), 20000, pos--));
            bins.push_back(b);
        }
        const auto sel = pb::select_window_bins(bins, kHugeDnet, B, f);
        check(sel.size() == 1500, "W_max per entry stops the window at 1,500 bins (F6)");
        const std::uint64_t W = raw_work(sel);
        check(W == 1440000000ull && B * 80000 / W == 33333333ull && B * 80000 / W >= f,
              "F6: W 1,440,000,000, entry value 33,333,333 >= f_spend");
        const std::uint64_t W1501 = W + 12 * 20000;
        check(W1501 == 1440240000ull && B * 20000 / W1501 == 8331944ull && B * 20000 / W1501 < f,
              "F6: bin 1,501 would give W 1,440,240,000, entry value 8,331,944 < f_spend");
        const pb::Window w = pb::window(bins, kHugeDnet, B, f, 3747, pb::Hash32{});
        check(w.W == pb::Work(1440000000ull) && w.weight.size() == 12, "F6: window() W 1,440,000,000, 12 payees");
    }

    // ---- 47,885 entries at one d: B / f_spend = 47,885.03 (6e11, hf 16) ----
    {
        const std::uint64_t n = 47886;  // one entry per bin, distinct payees, newest first
        std::vector<pb::WinBin> bins;
        bins.reserve(n);
        for (std::uint64_t k = 0; k < n; ++k) {
            pb::WinBin b; b.bin = 5000000 - k;
            pb::WinEntry x; x.miner = id_of(k + 1); x.work = 80000; x.position = 9000000 - k; x.id = x.miner;
            b.entries.push_back(x);
            bins.push_back(b);
        }
        const std::uint64_t N = pb::n_rule(3830978, 16, B);
        check(N == 47885, "N(B) at Z 3,830,978 hf16 == 47,885 (the N rule does not bind)");
        const auto sel = pb::select_window_bins(bins, kHugeDnet, B, f);
        check(sel.size() == 47885, "47,885 entries kept, entry 47,886 excluded");
        const pb::Window w = pb::window(bins, kHugeDnet, B, f, N, pb::Hash32{});
        check(w.weight.size() == 47885 && w.W == pb::Work(47885ull * 80000), "window of 47,885 payees");
        const auto outs = pb::split(B, w);
        check(outs.size() == 47885 && smallest(outs) >= f && smallest(outs) == 12530019ull,
              "no payee output below f_spend in a window of 47,885 entries (smallest 12,530,019)");
    }

    // ---- the cap stops at <=: W x f == B x d_min is kept, one unit more is cut ----
    {
        // d_min 12,530: B x d_min = 7.518e15 = 600,000,000 x f.
        std::vector<pb::WinBin> eq{{11, {e(0x51, 12530, 21)}}, {10, {e(0x52, 599987470, 20)}}};
        std::vector<pb::WinBin> over{{11, {e(0x51, 12530, 21)}}, {10, {e(0x52, 599987471, 20)}}};
        check(pb::select_window_bins(eq, kHugeDnet, B, f).size() == 2, "W x f == B x d_min: bin kept");
        check(pb::select_window_bins(over, kHugeDnet, B, f).size() == 1, "W x f == B x d_min + f: bin cut");
    }

    // ---- d_min over RECEIPT entries: a carried entry below every carrier ----
    {
        // bins 3 and 2 hold one carrier each (d 3,000,000); bin 1 holds a carrier
        // (d 3,000,000) and a carried entry (d 100, placed by the carrier at 35).
        std::vector<pb::WinBin> bins;
        bins.push_back({3, {e(0x70, 3000000, 30)}});
        bins.push_back({2, {e(0x71, 3000000, 20)}});
        bins.push_back({1, {e(0x72, 3000000, 10), e(0x73, 100, 35)}});
        const auto sel = pb::select_window_bins(bins, kHugeDnet, B, f);
        check(sel.size() == 2, "d_min over receipt entries: the carried entry's bin is cut by W_max");
        std::vector<pb::WinBin> carriers_only = bins;
        carriers_only[2].entries.pop_back();
        check(pb::select_window_bins(carriers_only, kHugeDnet, B, f).size() == 3,
              "a reading over carriers only would keep that bin");
        const auto outs = pb::split(B, pb::window(bins, kHugeDnet, B, f, 3747, pb::Hash32{}));
        check(outs.size() == 2 && smallest(outs) >= f, "no output below f_spend");
    }

    // ---- two build orders give one window (carrier-first vs carried-first,
    // placements in chain order vs reverse), the in-bin N cut included ----
    {
        struct Placement {
            std::uint64_t origin_bin;
            std::uint8_t miner;
            std::uint64_t work;
            std::uint64_t carrier_pos;  // the position that placed it
            bool carried;
        };
        // chain order: each carrier, then the receipts it carries.
        const std::vector<Placement> chain{
                {50, 1, 1000, 100, false}, {50, 2, 1100, 101, false},
                {51, 3, 1200, 102, false}, {50, 4, 900, 102, true},
                {51, 1, 1000, 103, false}, {51, 5, 950, 103, true},
                {52, 2, 1300, 104, false}, {50, 6, 800, 104, true}, {51, 7, 850, 104, true},
                {52, 8, 700, 105, false},  {52, 9, 600, 105, true}, {52, 10, 650, 105, true},
        };
        auto build = [](const std::vector<Placement>& ps) {
            std::map<std::uint64_t, pb::WinBin> by;
            for (const Placement& p : ps) {
                pb::WinEntry x;
                x.miner = rep(p.miner);
                x.work = p.work;
                x.position = p.carrier_pos;
                x.id = id_of(1000 * p.carrier_pos + p.miner);
                by[p.origin_bin].bin = p.origin_bin;
                by[p.origin_bin].entries.push_back(x);
            }
            std::vector<pb::WinBin> out;
            for (auto it = by.rbegin(); it != by.rend(); ++it) out.push_back(it->second);  // newest first
            return out;
        };
        std::vector<Placement> carried_first;
        for (const Placement& p : chain)
            if (p.carried) carried_first.push_back(p);
        for (const Placement& p : chain)
            if (!p.carried) carried_first.push_back(p);
        const std::vector<Placement> reverse(chain.rbegin(), chain.rend());
        const auto a = build(chain), b = build(carried_first), c = build(reverse);
        check(!(a.front().entries.front().id == b.front().entries.front().id)
                      && !(a.front().entries.front().id == c.front().entries.front().id),
              "three build orders give three entry orders");
        const std::uint64_t R = B + 3000000000ull;
        for (const std::uint64_t N : {std::uint64_t{3747}, std::uint64_t{3}}) {
            const pb::Window wa = pb::window(a, kHugeDnet, B, f, N, pb::Hash32{});
            const pb::Window wb = pb::window(b, kHugeDnet, B, f, N, pb::Hash32{});
            const pb::Window wc = pb::window(c, kHugeDnet, B, f, N, pb::Hash32{});
            const std::string tag = " (N " + std::to_string(N) + ")";
            check(pb::window_root(wa) == pb::window_root(wb) && pb::window_root(wa) == pb::window_root(wc),
                  "build orders give one window_root" + tag);
            const auto sa = pb::split(R, wa), sb = pb::split(R, wb), sc = pb::split(R, wc);
            bool same = sa.size() == sb.size() && sa.size() == sc.size();
            for (std::size_t i = 0; same && i < sa.size(); ++i)
                same = sa[i].payee == sb[i].payee && sa[i].payee == sc[i].payee && sa[i].amount == sb[i].amount
                       && sa[i].amount == sc[i].amount;
            check(same, "build orders give one split" + tag);
            if (N == 3)
                check(wa.weight.size() == 3 && wa.weight.count(rep(8)) && wa.weight.count(rep(9))
                              && wa.weight.count(rep(10)) && wa.W == pb::Work(1950),
                      "N 3: newest bin cut by carrier position: miners 8, 9, 10 (W 1,950)");
            else
                check(wa.weight.size() == 10 && wa.W == pb::Work(11050), "N 3747: 10 payees, W 11,050");
        }
    }

    s3b_store_build_orders();
    s3b_store_dead_dmin();
    s3b_m_doubles_and_retention();

    return finish("xmr_window_spend_floor_kat");
}
