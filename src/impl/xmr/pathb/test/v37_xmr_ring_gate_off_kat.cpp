// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_ring_gate_off_kat, depth-0 part (pathb_window.hpp,
// pathb_window_chain.hpp):
//   on every vector of the K = 1 window golden (v37_xmr_ring_c1_vectors.hpp):
//     min_bin == oldest_bin; W1 >= W, equal exactly when the N rule cut nothing;
//     min_bin 0 on the empty window;
//   the lazy read: two bins, COVERAGE x D_net equal to the newest bin's work,
//     the older buckets absent: a verdict from one unit, never a deferral;
//   entries in the Fresh bins above H(pos(t)) are in the window;
//   V2: the newest bin holds 47,886 receipts of equal work: 47,885 kept;
//   a sealed bin taken whole weighs raw_sum;
//   one implementation: tip_window calls window_from, its window equals
//     window_from over the listed bins of t, and no other header holds a copy of
//     the W_max test or the cut order.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "v37_xmr_ring_c1_vectors.hpp"

#ifndef PATHB_SRC_DIR
#define PATHB_SRC_DIR "."
#endif

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

std::string read_file(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

std::size_t count_of(const std::string& s, const std::string& what) {
    std::size_t n = 0;
    for (std::size_t at = s.find(what); at != std::string::npos; at = s.find(what, at + what.size())) ++n;
    return n;
}

void every_vector() {
    ring_c1::Recorder rec;
    std::uint64_t evals = 0, tips = 0, bad_min = 0, bad_w1 = 0, cut_cases = 0;
    std::string first_bad;
    auto w1_ok = [&](const pb::Work& W1, const pb::Work& W, bool cut) {
        if (W1 < W) return false;
        return cut ? W < W1 : W1 == W;
    };
    rec.on_eval = [&](const std::string& name, const pb::WinEval& e) {
        ++evals;
        if (e.min_bin != e.oldest_bin) {
            ++bad_min;
            if (first_bad.empty()) first_bad = name;
        }
        if (e.status == pb::WinStatus::Ok) {
            const bool cut = e.n_dropped_bins || e.n_cut_position;
            cut_cases += cut ? 1 : 0;
            if (!w1_ok(e.W1, e.window.W, cut)) {
                ++bad_w1;
                if (first_bad.empty()) first_bad = name;
            }
        }
    };
    rec.on_tip = [&](const std::string& name, const pb::TipWindow& t) {
        ++tips;
        if (t.min_bin != t.oldest_bin) {
            ++bad_min;
            if (first_bad.empty()) first_bad = name;
        }
        if (t.ok()) {
            const bool cut = t.n_dropped_bins || t.n_cut_position;
            cut_cases += cut ? 1 : 0;
            if (!w1_ok(t.W1, t.window->W, cut)) {
                ++bad_w1;
                if (first_bad.empty()) first_bad = name;
            }
        }
    };
    ring_c1::all_vectors(rec);
    std::printf("  every vector: %llu evaluations, %llu tip windows, %llu with an N cut\n",
                static_cast<unsigned long long>(evals), static_cast<unsigned long long>(tips),
                static_cast<unsigned long long>(cut_cases));
    check(evals > 3000 && tips > 300 && cut_cases > 300,
          "every vector: " + std::to_string(evals) + " evaluations, " + std::to_string(tips) + " tip windows, " +
                  std::to_string(cut_cases) + " with an N cut");
    check(bad_min == 0, "every vector: min_bin == oldest_bin (first failing: " + first_bad + ")");
    check(bad_w1 == 0, "every vector: W1 >= W, equal exactly when the N rule cut nothing (first failing: " + first_bad + ")");
    const std::vector<pb::WinBin> none;
    const pb::WinEval z = pb::window_from(pb::ListedBins{none}, 1000, ring_c1::kB, 1, 3747, pb::Hash32{});
    check(z.status == pb::WinStatus::Ok && z.window.empty_finder_only && z.min_bin == 0 && z.oldest_bin == 0
                  && z.W1 == pb::Work{},
          "the empty window: min_bin 0, W1 0");
}

void lazy_read() {
    using ring_c1::wparams;
    const pb::LaneParams P = ring_c1::small_params(1);
    constexpr std::uint64_t b0 = 7000;
    pb::BinStore s(P, 4, idn(0xF0, 0), b0);
    for (std::uint64_t pos = 1; pos <= 12; ++pos) {
        std::vector<pb::Placement> pls{rcpt(idn(0xF1, pos), b0 + pos, pos, idn(0xF2, pos), 300000)};
        if (pos == 12) pls.push_back(rcpt(idn(0xF3, pos), b0 + pos + 2, pos, idn(0xF4, pos), 1000000));
        extend(s, idn(0xF0, pos), idn(0xF0, pos - 1), b0 + pos, pls, true);
    }
    check(s.prune_buckets(b0 + 1000) > 0, "lazy read: the sealed buckets' bodies dropped");
    const pb::TipWindow w = pb::tip_window(s, idn(0xF0, 12), wparams(500000, ring_c1::kB, ring_c1::f16(), 3747), 16);
    check(w.ok() && w.bins_read == 1 && w.window->W == pb::Work(1000000) && w.window->weight.size() == 1,
          "lazy read: COVERAGE x D_net = the newest bin's work 1,000,000: a verdict from one unit, never a deferral");
    const pb::TipWindow d = pb::tip_window(s, idn(0xF0, 12), wparams(1000000, ring_c1::kB, ring_c1::f16(), 3747), 16);
    check(!d.ok() && d.defer == pb::WindowDefer::MissingBucket,
          "lazy read (control): a window that needs the older buckets defers on them");
}

void fresh_bins_and_one_implementation() {
    const pb::LaneParams P = pb::kRuledLaneParams;
    constexpr std::uint64_t b0 = 8000;
    pb::BinStore s(P, 64, idn(0xF5, 0), b0);
    for (std::uint64_t pos = 1; pos <= 8; ++pos) {
        const std::uint64_t h = b0 + pos;
        std::vector<pb::Placement> pls{rcpt(idn(0xF6, pos), h, pos, idn(0xF7, pos % 5), 40000 + pos)};
        if (pos % 2 == 0) pls.push_back(rcpt(idn(0xF8, pos), h + 1, pos, idn(0xF7, 7), 50000));
        if (pos % 3 == 0) pls.push_back(rcpt(idn(0xF9, pos), h + 2, pos, idn(0xF7, 8), 60000));
        extend(s, idn(0xF5, pos), idn(0xF5, pos - 1), h, pls, true);
    }
    const pb::Hash32 t = idn(0xF5, 8);
    const pb::TipWindow w = pb::tip_window(s, t, ring_c1::wparams(ring_c1::kHugeDnet, ring_c1::kB, ring_c1::f16(), 3747), 16);
    check(w.ok() && w.window->weight.count(idn(0xF7, 7)) == 1 && w.bins_read == 11,
          "Fresh bins: the receipts of bins H(pos(t)) + 1 and + 2 are in the window (bins read from H(pos(t)) + 2)");
    bool same = true;
    for (std::uint64_t pos = 1; pos <= 8; ++pos)
        for (const std::uint64_t N : {std::uint64_t{3747}, std::uint64_t{2}})
            for (const pb::DNet d : {ring_c1::kHugeDnet, pb::DNet{60000}}) {
                const pb::Hash32 x = idn(0xF5, pos);
                const pb::WindowParams wp = ring_c1::wparams(d, ring_c1::kB, ring_c1::f16(), N);
                const pb::TipWindow a = pb::tip_window(s, x, wp, 16);
                const pb::WinResult bins = pb::win_bins_at(s, x);
                const pb::WinEval b = pb::window_from(pb::ListedBins{bins.bins}, wp.d_net, wp.B, wp.f_spend, wp.N, wp.author);
                same = same && a.ok() && b.status == pb::WinStatus::Ok && a.window->weight == b.window.weight
                       && a.window->W == b.window.W && a.window->rows.size() == b.window.rows.size()
                       && a.bins_read == b.read && a.oldest_bin == b.oldest_bin && a.W1 == b.W1;
            }
    check(same, "one implementation: tip_window's window equals window_from over t's listed bins (48 windows)");
    const std::string chain = read_file(std::string(PATHB_SRC_DIR) + "/pathb_window_chain.hpp");
    const std::size_t at = chain.find("inline TipWindow tip_window(");
    const std::size_t end = chain.find("inline TipWindow evaluate_window_at(");
    check(at != std::string::npos && end != std::string::npos && end > at
                  && chain.substr(at, end - at).find("window_from(src,") != std::string::npos,
          "one implementation: tip_window calls window_from over its TipBins source");
    std::size_t copies = 0;
    std::string where;
    for (const auto& f : std::filesystem::directory_iterator(PATHB_SRC_DIR)) {
        if (f.path().extension() != ".hpp" || f.path().filename() == "pathb_window.hpp") continue;
        const std::string body = read_file(f.path().string());
        const std::size_t n = count_of(body, "within_w_max(") + count_of(body, "sort_newest_first(")
                              + count_of(body, "PayeeCount ") + count_of(body, "select_window_bins_from(");
        copies += n;
        if (n) where += " " + f.path().filename().string();
    }
    const std::string win = read_file(std::string(PATHB_SRC_DIR) + "/pathb_window.hpp");
    check(copies == 0 && count_of(win, "inline WinSelect select_window_bins_from(") == 1
                  && count_of(win, "inline WinEval window_from(") == 1,
          "one implementation: one select loop and one window_from; no other header copies the steps (" + where + ")");
}

void v2() {
    std::vector<pb::WinBin> bins(1);
    bins[0].bin = 900;
    for (std::uint64_t k = 0; k < 47886; ++k) bins[0].entries.push_back(ring_c1::cx_entry(k + 1, 80000, 5000000 + k, 9000000 + k));
    const pb::WinEval e = pb::window_from(pb::ListedBins{bins}, ring_c1::kHugeDnet, ring_c1::kB, ring_c1::f16(), 100000,
                                          pb::Hash32{});
    check(e.status == pb::WinStatus::Ok && e.window.weight.size() == 47885 && e.window.W == pb::Work(47885ull * 80000)
                  && e.W1 == e.window.W && e.read == 1 && e.window.weight.count(ring_c1::id_of(1)) == 0,
          "V2: 47,886 receipts of equal work in the newest bin: the 47,885 newest kept, a verdict");
}

void sealed_whole() {
    std::vector<pb::WinEntry> es;
    for (std::uint64_t k = 0; k < 6; ++k) {
        pb::WinEntry e = ring_c1::cx_entry(10 + k, 100000 + 17 * k, 60 - k, 70 + k);
        if (k % 2 == 0) {
            e.owner = ring_c1::id_of(50);
            e.p = 250;
        }
        if (k % 3 == 0) e.give_author_bp = 40;
        es.push_back(e);
    }
    const pb::L1Bucket bk = pb::seal_from_entries(30, es);
    std::vector<pb::WinBin> bins(1);
    bins[0].bin = 30;
    bins[0].sealed = &bk;
    const pb::WinEval e = pb::window_from(pb::ListedBins{bins}, ring_c1::kHugeDnet, ring_c1::kB, 1, 3747,
                                          ring_c1::id_of(0xAA));
    check(e.status == pb::WinStatus::Ok && e.window.W == bk.raw_sum && e.W1 == bk.raw_sum && e.min_bin == 30,
          "a sealed bin taken whole weighs raw_sum");
}

}  // namespace

int main() {
    run_part("every_vector", every_vector);
    run_part("lazy_read", lazy_read);
    run_part("fresh_bins_and_one_implementation", fresh_bins_and_one_implementation);
    run_part("v2", v2);
    run_part("sealed_whole", sealed_whole);
    return finish("v37_xmr_ring_gate_off_kat");
}
