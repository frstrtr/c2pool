// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_native_inject_select_kat.cpp
//
// The OPERATOR-INJECT SELECTION KAT. It proves, over synthetic backlogs, the
// operator ruling (2026-09-19) end to end at the pure-selector layer:
//
//   (a) an operator-injected 0-fee tx is ALWAYS in the produced template, ahead
//       of every fee-paying transaction (inject first, no fee test);
//   (b) with a FLOOD of cheap mempool txs the block weight NEVER exceeds the cap
//       AND the injected tx is still present (variant-B take-all UP TO the cap);
//   (c) backlog Sigma >> cap ("mempool full") => all injects present, fee tail
//       trimmed, never overfilled;
//   (d) injects ALONE > cap => the inject prefix is kept, inject_dropped_by_cap
//       is counted BY NAME, the block is never empty;
//   (e) with ZERO injects the selection is BYTE-EQUAL to select_good_citizen
//       (the good-citizen path is untouched when nobody injects);
//   (f) determinism -- same inputs, same selection;
//   (g) inject inclusion order is the order the pool handed us (priority then
//       FIFO is proved in the pool KAT; here we prove the selector preserves it);
//   (h) the 128 KB hash-carrier cap is UNREACHABLE under the weight budget
//       (n_tx*32 + k < MAX_BLOCK_SIZE), so a fee-sorted carrier-cap drop can
//       never reach a 0-fee inject.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "impl/xmr/native/inject/xmr_inject_select.hpp"

using namespace c2pool::xmr::native;
namespace node = c2pool::xmr::node;

static int g_checks = 0;
static int g_fail   = 0;

static void check(bool cond, const char* msg) {
    ++g_checks;
    if (!cond) { ++g_fail; std::printf("  FAIL: %s\n", msg); }
}

// Build a backlog entry with an explicit id so membership / order can be
// asserted. The id is a deterministic function of a small integer tag.
static node::TxBacklogEntry mk(std::uint64_t tag, std::uint64_t weight, std::uint64_t fee) {
    node::TxBacklogEntry e;
    e.weight    = weight;
    e.blob_size = weight;
    e.fee       = fee;
    for (int i = 0; i < 8; ++i) e.id[i] = static_cast<std::uint8_t>((tag >> (8 * i)) & 0xff);
    e.id[31] = 0xC2;   // marks a synthetic entry
    return e;
}

static bool same_id(const node::Hash& a, const node::Hash& b) { return a == b; }

// A realistic mainnet-scale state: HF v16, ~17M XMR emitted, median at floor.
static constexpr std::uint8_t  HF_V16  = 16;
static constexpr std::uint64_t AGC     = 17'000'000ull * 1'000'000'000'000ull;
static constexpr std::uint64_t MEDIAN  = 300'000;
static constexpr std::uint64_t MAX_TXW = 149'400;

int main() {
    std::printf("xmr_native_inject_select_kat\n");

    // The block-size cap the selector computes, restated here so the tests can
    // assert against the same number the code uses.
    // weight_cap = min(1.5*median, 2*median - 600), clamped >= median.
    const std::uint64_t CB_RESERVED = 600;
    const std::uint64_t CONSENSUS_CEIL = 2 * MEDIAN - CB_RESERVED;         // 599400
    const std::uint64_t GROWTH_CAP     = static_cast<std::uint64_t>(1.5 * MEDIAN); // 450000
    const std::uint64_t WEIGHT_CAP     = GROWTH_CAP < CONSENSUS_CEIL ? GROWTH_CAP : CONSENSUS_CEIL;

    // -- (a) a 0-fee inject is placed FIRST, ahead of every fee-paying tx ------
    {
        std::vector<node::TxBacklogEntry> fee_ordered;
        for (std::uint64_t i = 0; i < 20; ++i) fee_ordered.push_back(mk(100 + i, 2000, 100000));
        std::vector<node::TxBacklogEntry> injects{ mk(1, 1500, 0) };   // 0-fee inject

        auto sel = select_inject_first(injects, fee_ordered, MEDIAN, AGC, HF_V16);
        check(!sel.chosen.empty(), "(a) selection non-empty with a 0-fee inject");
        check(sel.inject_n == 1, "(a) the one inject is placed");
        check(same_id(sel.chosen.front().id, injects[0].id),
              "(a) the 0-fee inject is FIRST, ahead of every fee-paying tx");
        check(sel.chosen.front().fee == 0, "(a) the first selected tx is the 0-fee inject");
        // every fee-paying tx that fits is still there (take-all)
        check(sel.chosen.size() == 1 + fee_ordered.size(),
              "(a) all fee-paying txs still taken after the inject (take-all)");
    }

    // -- (b) flood of cheap txs + inject: never overfill, inject still present -
    {
        std::vector<node::TxBacklogEntry> fee_ordered;
        for (std::uint64_t i = 0; i < 1000; ++i) fee_ordered.push_back(mk(1000 + i, 1400, 1)); // cheap flood
        std::vector<node::TxBacklogEntry> injects{ mk(2, 1500, 0) };

        auto sel = select_inject_first(injects, fee_ordered, MEDIAN, AGC, HF_V16);
        check(sel.inject_n == 1 && same_id(sel.chosen.front().id, injects[0].id),
              "(b) inject present and first under a 1000-tx cheap flood");
        // NEVER overfill: coinbase-inclusive weight stays within the cap.
        check(sel.total_weight + CB_RESERVED <= WEIGHT_CAP,
              "(b) block weight never exceeds the weight cap under a flood");
        check(sel.total_weight + CB_RESERVED <= CONSENSUS_CEIL,
              "(b) block weight never crosses the consensus ceiling under a flood");
        // (h) the 128 KB carrier cap is unreachable: n_tx*32 + slack << 131072.
        const std::uint64_t MAX_BLOCK_SIZE = 128 * 1024;
        check(sel.chosen.size() * 32 + 4096 < MAX_BLOCK_SIZE,
              "(h) hash-carrier cap unreachable: n_tx*32 fits far under 128 KB");
    }

    // -- (c) backlog Sigma >> cap: all injects present, tail trimmed ----------
    {
        std::vector<node::TxBacklogEntry> fee_ordered;
        // ~1.4 MB of would-be txs, far above the ~450 KB cap.
        for (std::uint64_t i = 0; i < 1000; ++i) fee_ordered.push_back(mk(2000 + i, 1400, 500));
        std::vector<node::TxBacklogEntry> injects{ mk(3, 1500, 0), mk(4, 1500, 0), mk(5, 1500, 0) };

        auto sel = select_inject_first(injects, fee_ordered, MEDIAN, AGC, HF_V16);
        check(sel.inject_n == 3 && sel.inject_dropped_by_cap == 0,
              "(c) all 3 injects present when the mempool is full");
        // the three injects are the first three selected, in order
        bool prefix_ok = sel.chosen.size() >= 3
            && same_id(sel.chosen[0].id, injects[0].id)
            && same_id(sel.chosen[1].id, injects[1].id)
            && same_id(sel.chosen[2].id, injects[2].id);
        check(prefix_ok, "(c) injects are the leading prefix, in order");
        check(sel.chosen.size() < 3 + fee_ordered.size(),
              "(c) the fee tail was trimmed (mempool did not all fit)");
        check(sel.total_weight + CB_RESERVED <= WEIGHT_CAP,
              "(c) trimmed block still within the weight cap");
    }

    // -- (d) injects ALONE exceed the cap: prefix kept, dropped counted -------
    {
        // Each inject ~149 KB; the cap is ~450 KB, so ~3 fit and the rest drop.
        std::vector<node::TxBacklogEntry> injects;
        for (std::uint64_t i = 0; i < 10; ++i) injects.push_back(mk(10 + i, MAX_TXW, 0));
        std::vector<node::TxBacklogEntry> fee_ordered;   // empty mempool

        auto sel = select_inject_first(injects, fee_ordered, MEDIAN, AGC, HF_V16);
        check(!sel.chosen.empty(), "(d) never empty even when injects alone exceed the cap");
        check(sel.inject_n >= 1, "(d) at least the first inject is taken");
        check(sel.inject_n + sel.inject_dropped_by_cap == injects.size(),
              "(d) every inject is either placed or counted as dropped-by-cap (named)");
        check(sel.inject_dropped_by_cap > 0, "(d) some injects are dropped by the cap and counted");
        check(sel.total_weight + CB_RESERVED <= WEIGHT_CAP,
              "(d) the kept inject prefix stays within the weight cap");
        // the kept injects are a prefix of the ordered inject list (never reordered)
        bool prefix = true;
        for (std::size_t i = 0; i < sel.inject_n; ++i)
            if (!same_id(sel.chosen[i].id, injects[i].id)) prefix = false;
        check(prefix, "(d) kept injects are a prefix of the ordered inject list, never reordered");
    }

    // -- (e) ZERO injects => byte-equal to select_good_citizen ----------------
    {
        std::vector<node::TxBacklogEntry> pool;
        for (std::uint64_t i = 0; i < 400; ++i) pool.push_back(mk(500 + i, 1500 + (i % 7) * 200, 3000 + i));

        auto citizen = select_good_citizen(pool, MEDIAN, AGC, HF_V16);
        auto inject0 = select_inject_first({}, pool, MEDIAN, AGC, HF_V16);

        bool equal = citizen.chosen.size() == inject0.chosen.size()
                  && citizen.total_weight == inject0.total_weight
                  && citizen.total_fee == inject0.total_fee;
        for (std::size_t i = 0; equal && i < citizen.chosen.size(); ++i) {
            if (!same_id(citizen.chosen[i].id, inject0.chosen[i].id)) equal = false;
            if (citizen.chosen[i].weight != inject0.chosen[i].weight) equal = false;
            if (citizen.chosen[i].fee    != inject0.chosen[i].fee)    equal = false;
        }
        check(equal, "(e) zero-inject selection is BYTE-EQUAL to select_good_citizen (good-citizen untouched)");
        check(inject0.inject_n == 0 && inject0.inject_dropped_by_cap == 0,
              "(e) zero-inject selection reports no injects");
    }

    // -- (e') good-citizen non-empty invariant preserved with injects present -
    {
        // pool empty, one inject -> non-empty
        auto a = select_inject_first({ mk(6, 1500, 0) }, {}, MEDIAN, AGC, HF_V16);
        check(a.chosen.size() == 1, "(e') one inject, empty pool -> non-empty block");
        // pool non-empty, no inject -> non-empty (good-citizen R-CIT-1)
        auto b = select_inject_first({}, { mk(7, 2000, 5) }, MEDIAN, AGC, HF_V16);
        check(b.chosen.size() == 1, "(e') no inject, one pool tx -> non-empty block");
        // both empty -> empty
        auto c = select_inject_first({}, {}, MEDIAN, AGC, HF_V16);
        check(c.chosen.empty(), "(e') both empty -> empty block");
    }

    // -- (f) determinism ------------------------------------------------------
    {
        std::vector<node::TxBacklogEntry> fee_ordered;
        for (std::uint64_t i = 0; i < 300; ++i) fee_ordered.push_back(mk(3000 + i, 1500 + (i % 5) * 300, 100 + i));
        std::vector<node::TxBacklogEntry> injects{ mk(20, 1500, 0), mk(21, 1500, 0) };
        auto x = select_inject_first(injects, fee_ordered, MEDIAN, AGC, HF_V16);
        auto y = select_inject_first(injects, fee_ordered, MEDIAN, AGC, HF_V16);
        bool same = x.chosen.size() == y.chosen.size() && x.total_weight == y.total_weight
                 && x.inject_n == y.inject_n && x.inject_dropped_by_cap == y.inject_dropped_by_cap;
        check(same, "(f) selection is deterministic");
    }

    // -- (g) selector preserves the inject order it was handed ----------------
    {
        // Injects handed in a specific order; the selector must place them in
        // exactly that order (the pool KAT proves priority-then-FIFO produces it).
        std::vector<node::TxBacklogEntry> injects{ mk(30, 1500, 0), mk(31, 1500, 0), mk(32, 1500, 0) };
        std::vector<node::TxBacklogEntry> fee_ordered{ mk(200, 2000, 900) };
        auto sel = select_inject_first(injects, fee_ordered, MEDIAN, AGC, HF_V16);
        bool order_ok = sel.inject_n == 3
            && same_id(sel.chosen[0].id, injects[0].id)
            && same_id(sel.chosen[1].id, injects[1].id)
            && same_id(sel.chosen[2].id, injects[2].id);
        check(order_ok, "(g) selector places injects in the exact order handed to it");
    }

    std::printf("%s: %d checks, %d failures\n", g_fail ? "FAIL" : "PASS", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
