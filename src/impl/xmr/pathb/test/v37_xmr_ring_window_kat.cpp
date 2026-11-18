// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_ring_window_kat, WIN part (pathb_window.hpp): window_from over a
// hand-built unit source (no ring key), one vector per place:
//   (1) a stop on coverage reads no further unit; an empty unit is followed by a
//       new peek; End from the peek gives a verdict, never a loop;
//   (2) a RING-ROWS first unit cut by W_max and one cut by N: each a verdict;
//       the WHOLE-BUCKET forms: SealedCut;
//   (4) a cut on atoms at shift 1;
//   (5) a cut RING-ROWS unit's W is the sum of its kept rows;
//   (6) the whole-unit datum is bin-wide (u_1 d 1e10; u_2 the ring's 9e10, the
//       bin's d_min 1e6): the window stops after u_1;
//   (7) work 1,000,005,000 at 1 bp, shift 1: owner weight 200,000; W the sum of
//       the scaled weights;
//   (7b) a RING-ROWS unit's payee count is its own rows';
//   (8) a datum above 2^64 after the shift passes test (ii) and the cut;
//   (9) a RING-ROWS unit with rows is not empty;
//   V1: a sealed first cell of one ring (rows 5e10 and 1e7, the bin's d_min 1e6):
//       both rows kept, a verdict; row 2's output at R = B is 119,976,005.
// Test-only sources; every production source is depth 0.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_bin_store.hpp"  // seal_from_entries
#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

pb::Hash32 id_of(std::uint64_t i) {
    pb::Hash32 h{};
    for (int b = 0; b < 8; ++b) h[31 - b] = static_cast<std::uint8_t>(i >> (8 * b));
    return h;
}

constexpr pb::DNet kHuge = pb::DNet{1} << 100;
constexpr std::uint64_t kB = 600000000000ull;
const std::uint64_t kF = pb::f_spend(kB, 300000, 16);  // 12,530,000

// A hand-built source: unit i is pulled after a peek giving clocks[i] (or, when
// clocks is empty, the raw work of the non-empty units pulled so far); End after
// the last unit, or at end_at. The calls are logged ('P' peek, 'U' pull).
struct HandSource {
    std::vector<pb::UnitPull> items;
    std::vector<pb::Work> clocks;
    std::size_t end_at = SIZE_MAX;
    std::size_t next = 0;
    pb::Work clock{};
    std::string log;

    pb::ClockPeek peek() {
        log += 'P';
        if (next >= items.size() || next >= end_at) return pb::ClockPeek{};
        return pb::ClockPeek{pb::PeekKind::Clock, clocks.empty() ? clock : clocks[next]};
    }
    pb::UnitPull pull() {
        log += 'U';
        if (next >= items.size()) return pb::UnitPull{};
        pb::UnitPull p = items[next++];
        if (p.kind == pb::PullKind::Bin && !pb::detail_win::unit_empty(p.unit)) clock += p.unit.raw;
        return p;
    }
};

pb::UnitPull unit_pull(pb::WinUnit u) {
    pb::UnitPull p;
    p.kind = pb::PullKind::Bin;
    p.unit = std::move(u);
    return p;
}

pb::WinEntry entry(std::uint64_t miner, std::uint64_t work, std::uint64_t pos) {
    pb::WinEntry e;
    e.miner = id_of(miner);
    e.work = work;
    e.position = pos;
    e.id = id_of(1000000 + pos);
    return e;
}

// An OPEN unit; raw and d_min_bin from its entries unless given.
pb::WinUnit open_unit(std::uint64_t bin, std::vector<pb::WinEntry> es, std::uint8_t shift = 0,
                      std::uint64_t d_min_bin = 0) {
    pb::WinUnit u;
    u.bin = bin;
    u.shift = shift;
    std::uint64_t d = 0;
    for (const pb::WinEntry& e : es) {
        u.raw += pb::Work(e.work);
        d = d == 0 || e.work < d ? e.work : d;
    }
    u.d_min_bin = d_min_bin ? d_min_bin : d;
    u.entries = std::move(es);
    return u;
}

pb::BucketRow row(std::uint64_t miner, std::uint64_t w_miner) {
    pb::BucketRow r;
    r.miner = id_of(miner);
    r.w_miner = pb::Work(w_miner);
    return r;
}

// A RING-ROWS unit: raw = the sum of its rows.
pb::WinUnit rows_unit(std::uint64_t bin, std::vector<pb::BucketRow> rows, std::uint64_t d_min_bin, std::uint8_t shift = 0,
                      std::uint8_t depth = 1, std::uint8_t index = 0) {
    pb::WinUnit u;
    u.bin = bin;
    u.ring = pb::RingId{depth, index};
    u.shift = shift;
    for (const pb::BucketRow& r : rows) u.raw += r.w_miner + r.w_owner + r.w_author;
    u.rows = std::move(rows);
    u.d_min_bin = d_min_bin;
    return u;
}

pb::WinEval run(HandSource& s, pb::DNet d, std::uint64_t B, std::uint64_t f, std::uint64_t N,
                const pb::Hash32& author = pb::Hash32{}) {
    return pb::window_from(s, d, B, f, N, author);
}

void place1() {
    {   // a stop on coverage reads no further unit
        HandSource s;
        for (std::uint64_t k = 0; k < 3; ++k) s.items.push_back(unit_pull(open_unit(10 - k, {entry(k + 1, 100, 50 - k)})));
        const pb::WinEval e = run(s, 75, kB, 1, 3747);  // COVERAGE x D_net = 150
        check(e.status == pb::WinStatus::Ok && e.read == 2 && s.next == 2 && e.window.W == pb::Work(200)
                      && e.window.weight.size() == 2 && s.log == "PUPUP",
              "(1) coverage: the peeked clock 200 >= 150 stops WIN; unit 3 is never pulled (" + s.log + ")");
    }
    {   // the stop reads the PEEKED clock, not the unit's: a source clock above W stops WIN first
        HandSource s;
        for (std::uint64_t k = 0; k < 3; ++k) s.items.push_back(unit_pull(open_unit(10 - k, {entry(k + 1, 100, 50 - k)})));
        s.clocks = {pb::Work(0), pb::Work(150), pb::Work(150)};
        const pb::WinEval e = run(s, 75, kB, 1, 3747);
        check(e.status == pb::WinStatus::Ok && e.read == 1 && e.window.W == pb::Work(100) && e.W1 == pb::Work(100),
              "(1) a peeked clock at the target stops WIN after one unit; W stays the taken units' 100");
    }
    {   // an empty unit is followed by a new peek
        HandSource s;
        s.items.push_back(unit_pull(open_unit(10, {})));
        s.items.push_back(unit_pull(open_unit(9, {entry(1, 100, 40)})));
        const pb::WinEval e = run(s, kHuge, kB, 1, 3747);
        check(e.status == pb::WinStatus::Ok && e.read == 2 && s.log == "PUPUP" && e.window.weight.size() == 1,
              "(1) an empty unit: skipped, then a new peek (" + s.log + ")");
    }
    {   // End from the peek gives a verdict, never a loop
        HandSource s;
        s.items.push_back(unit_pull(open_unit(10, {entry(1, 100, 40)})));
        s.items.push_back(unit_pull(open_unit(9, {entry(2, 100, 39)})));
        s.end_at = 1;
        const pb::WinEval e = run(s, kHuge, kB, 1, 3747);
        check(e.status == pb::WinStatus::Ok && e.read == 1 && s.log == "PUP" && e.window.weight.size() == 1,
              "(1) End from the peek after one unit: a verdict over that unit (" + s.log + ")");
        HandSource none;
        const pb::WinEval z = run(none, kHuge, kB, 1, 3747);
        check(z.status == pb::WinStatus::Ok && z.read == 0 && none.log == "P" && z.window.empty_finder_only,
              "(1) End at the first peek: the empty window, a verdict");
    }
}

void place2() {
    // V1-shaped RING-ROWS cut by W_max: rows 5e10 and 1e7 against the bin's d_min 1e6.
    {
        HandSource s;
        s.items.push_back(unit_pull(rows_unit(20, {row(1, 50000000000ull), row(2, 10000000ull)}, 1000000)));
        const pb::WinEval e = run(s, kHuge, kB, kF, 3747);
        check(e.status == pb::WinStatus::Ok && e.window.weight.size() == 2 && e.window.W == pb::Work(50010000000ull),
              "(2) a RING-ROWS first unit failing W_max as a whole: cut over its rows, a VERDICT (both kept)");
        const auto outs = pb::split(kB, e.window);
        check(outs.size() == 2 && outs[1].payee == id_of(2) && outs[1].amount == 119976005ull,
              "V1: row 2's output at R = B is 119,976,005");
    }
    {   // a RING-ROWS first unit cut by W_max to a strict prefix
        HandSource s;
        s.items.push_back(unit_pull(rows_unit(20, {row(1, 50000000000ull), row(2, 10000000ull), row(3, 18180)}, 18180)));
        const pb::WinEval e = run(s, kHuge, kB, kF, 3747);
        check(e.status == pb::WinStatus::Ok && e.window.weight.size() == 2 && e.window.weight.count(id_of(3)) == 0,
              "(2) a RING-ROWS unit cut by W_max keeps rows 1, 2 in the source's order: a VERDICT");
    }
    {   // a RING-ROWS first unit cut by N
        HandSource s;
        s.items.push_back(unit_pull(rows_unit(20, {row(1, 30000), row(2, 30000), row(3, 30000)}, 30000)));
        s.items.push_back(unit_pull(open_unit(19, {entry(4, 30000, 10)})));
        const pb::WinEval e = run(s, kHuge, kB, 1, 2);
        check(e.status == pb::WinStatus::Ok && e.n_cut_position && e.n_dropped_bins && e.window.weight.size() == 2
                      && e.window.weight.count(id_of(1)) && e.window.weight.count(id_of(2)),
              "(2) a RING-ROWS first unit over N: cut over its rows to N 2, a VERDICT");
    }
    {   // the WHOLE-BUCKET forms stay SealedCut
        std::vector<pb::WinEntry> es{entry(1, 1000000000000ull, 30), entry(2, 20000, 29)};
        const pb::L1Bucket bk = pb::seal_from_entries(40, es);
        pb::WinUnit u;
        u.bin = 40;
        u.sealed = &bk;
        u.raw = bk.raw_sum;
        u.d_min_bin = bk.d_min;
        HandSource s;
        s.items.push_back(unit_pull(u));
        const pb::WinEval e = run(s, kHuge, kB, kF, 3747);
        check(e.status == pb::WinStatus::SealedCut && e.missing_bin == 40,
              "(2) a WHOLE-BUCKET first unit failing W_max alone: SealedCut");
        std::vector<pb::WinEntry> three{entry(1, 30000, 3), entry(2, 30000, 2), entry(3, 30000, 1)};
        const pb::L1Bucket b3 = pb::seal_from_entries(41, three);
        pb::WinUnit v;
        v.bin = 41;
        v.sealed = &b3;
        v.raw = b3.raw_sum;
        v.d_min_bin = b3.d_min;
        HandSource t;
        t.items.push_back(unit_pull(v));
        const pb::WinEval n = run(t, kHuge, kB, 1, 2);
        check(n.status == pb::WinStatus::SealedCut && n.missing_bin == 41,
              "(2) a WHOLE-BUCKET unit alone over N: SealedCut");
    }
}

void place4() {
    // shift 1, eight equal entries; B 10, f 3: atoms of weight 2w cut while 6k <= 20.
    const std::uint64_t w = 20000;
    std::vector<pb::WinEntry> es;
    for (std::uint64_t k = 0; k < 8; ++k) es.push_back(entry(k + 1, w, 100 - k));
    HandSource s;
    s.items.push_back(unit_pull(open_unit(30, es, 1)));
    const pb::WinEval e = run(s, kHuge, 10, 3, 3747);
    check(e.status == pb::WinStatus::Ok && e.window.weight.size() == 3 && e.window.W == pb::Work(6 * w)
                  && e.W1 == pb::Work(6 * w),
          "(4) a cut on atoms at shift 1: three atoms of weight 2w kept (W 6w)");
}

void place5() {
    HandSource s;
    s.items.push_back(unit_pull(rows_unit(20, {row(1, 50000000000ull), row(2, 10000000ull), row(3, 18180)}, 18180, 1)));
    const pb::WinEval e = run(s, kHuge, kB, kF, 3747);
    check(e.status == pb::WinStatus::Ok && e.window.weight.size() == 2
                  && e.window.W == pb::Work(2 * (50000000000ull + 10000000ull)) && e.W1 == e.window.W,
          "(5) a cut RING-ROWS unit's W is the sum of its kept rows (shift 1), not its raw");
}

void place6() {
    HandSource s;
    s.items.push_back(unit_pull(open_unit(50, {entry(1, 10000000000ull, 90)})));
    std::vector<pb::WinEntry> ring;
    for (std::uint64_t k = 0; k < 9; ++k) ring.push_back(entry(10 + k, 10000000000ull, 80 - k));
    s.items.push_back(unit_pull(open_unit(49, ring, 0, 1000000)));  // the bin's d_min: another ring's 1e6
    const pb::WinEval e = run(s, kHuge, kB, kF, 3747);
    check(e.status == pb::WinStatus::Ok && e.read == 2 && e.window.weight.size() == 1
                  && e.window.W == pb::Work(10000000000ull),
          "(6) the whole-unit datum is bin-wide: (1e10 + 9e10) x 12,530,000 > 6e11 x 1e6, WIN stops after u_1");
}

void place7() {
    pb::WinEntry x = entry(1, 1000005000ull, 10);
    x.owner = id_of(2);
    x.p = 1;
    HandSource s;
    s.items.push_back(unit_pull(open_unit(60, {x}, 1)));
    const pb::WinEval e = run(s, kHuge, kB, 1, 3747);
    check(e.status == pb::WinStatus::Ok && e.window.weight.count(id_of(2)) == 1
                  && e.window.weight.at(id_of(2)) == pb::Work(200000),
          "(7) shares on the raw work, then scaled: the owner weight is 2 x floor(1,000,005,000 / 10,000) = 200,000");
    check(e.window.W == pb::Work(2000010000ull) && e.window.weight.at(id_of(1)) == pb::Work(2000010000ull - 200000),
          "(7) W is the sum of the scaled weights (2,000,010,000)");
}

void place7b() {
    HandSource s;
    s.items.push_back(unit_pull(rows_unit(20, {row(1, 30000), row(2, 30000), row(3, 30000)}, 30000)));
    const pb::WinEval e = run(s, kHuge, kB, 1, 2);
    check(e.status == pb::WinStatus::Ok && e.n_cut_position && e.window.weight.size() == 2,
          "(7b) a RING-ROWS unit's payee count is its own rows': 3 > N 2, cut to 2");
}

void place8() {
    const std::uint64_t big = std::uint64_t{1} << 63;
    {
        std::vector<pb::WinEntry> es{entry(1, big, 20), entry(2, big, 19)};
        HandSource s;
        s.items.push_back(unit_pull(open_unit(70, es, 2)));
        const pb::WinEval e = run(s, kHuge, 10, 1, 3747);
        pb::Work want = pb::detail_win::scaled(pb::Work(big), 2);
        want += want;
        check(e.status == pb::WinStatus::Ok && e.window.weight.size() == 2 && e.window.W == want,
              "(8) a datum of 2^65 (2^63 << 2) passes test (ii) untruncated: both entries, W 2^66");
    }
    {
        std::vector<pb::WinEntry> es;
        for (std::uint64_t k = 0; k < 12; ++k) es.push_back(entry(k + 1, big, 50 - k));
        HandSource s;
        s.items.push_back(unit_pull(open_unit(71, es, 2)));
        const pb::WinEval e = run(s, kHuge, 10, 1, 3747);
        check(e.status == pb::WinStatus::Ok && e.window.weight.size() == 10,
              "(8) the cut on atoms of datum 2^65 keeps 10 of 12 (12 x 2^65 > 10 x 2^65)");
    }
}

void place9() {
    HandSource s;
    s.items.push_back(unit_pull(rows_unit(20, {row(1, 30000), row(2, 40000)}, 30000)));
    const pb::WinEval e = run(s, kHuge, kB, 1, 3747);
    check(e.status == pb::WinStatus::Ok && e.read == 1 && e.window.weight.size() == 2 && e.window.W == pb::Work(70000),
          "(9) a RING-ROWS unit with rows (sealed null, no entries) is not empty");
}

}  // namespace

int main() {
    place1();
    place2();
    place4();
    place5();
    place6();
    place7();
    place7b();
    place8();
    place9();
    return finish("v37_xmr_ring_window_kat");
}
