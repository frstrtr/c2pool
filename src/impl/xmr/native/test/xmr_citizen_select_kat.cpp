// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_citizen_select_kat.cpp
//
// The GOOD-CITIZEN selection KAT. It proves, over synthetic backlogs, that the
// template never emits an empty or under-filled block when the pool has valid
// transactions, and that "fee versus penalty" is ordering-only, never a gate:
//
//   R-CIT-1  a non-empty backlog always yields a non-empty selection, and an
//            empty backlog yields an empty selection.
//   R-CIT-2  every transaction under the median is taken, no fee test.
//   R-CIT-3  above the median, lowering the accept threshold from monerod's
//            1.0 to the good-citizen 0.98 STRICTLY increases inclusion -- we
//            keep transactions monerod would drop -- while never crossing the
//            consensus ceiling (2*median - reserved) or the soft growth cap.
//   determinism -- same backlog in, same selection out.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "impl/xmr/native/template/xmr_citizen_select.hpp"

using namespace c2pool::xmr::native;
namespace node = c2pool::xmr::node;

static int g_checks = 0;
static int g_fail   = 0;

static void check(bool cond, const char* msg) {
    ++g_checks;
    if (!cond) { ++g_fail; std::printf("  FAIL: %s\n", msg); }
}

static node::TxBacklogEntry mk(std::uint64_t weight, std::uint64_t fee) {
    node::TxBacklogEntry e;
    e.weight    = weight;
    e.blob_size = weight;
    e.fee       = fee;
    return e;
}

// A realistic mainnet-scale state: HF v16, ~17M XMR already emitted, median at
// the 300 kB floor.
static constexpr std::uint8_t  HF_V16   = 16;
static constexpr std::uint64_t AGC      = 17'000'000ull * 1'000'000'000'000ull;
static constexpr std::uint64_t MEDIAN   = 300'000;
static constexpr std::uint64_t MAX_TXW  = 149'400;   // consensus tx weight limit

int main() {
    std::printf("xmr_citizen_select_kat\n");

    // -- R-CIT-1: empty in, empty out -----------------------------------------
    {
        auto sel = select_good_citizen({}, MEDIAN, AGC, HF_V16);
        check(sel.chosen.empty(), "empty backlog yields empty selection");
    }

    // -- R-CIT-1: a single transaction is always mined ------------------------
    {
        std::vector<node::TxBacklogEntry> pool{ mk(2000, 1000) };
        auto sel = select_good_citizen(pool, MEDIAN, AGC, HF_V16);
        check(sel.chosen.size() == 1, "a single valid tx is always selected (never an empty block)");
    }

    // -- R-CIT-1 (extreme): one MAX-weight tx still fits and is mined ----------
    {
        std::vector<node::TxBacklogEntry> pool{ mk(MAX_TXW, 0) };
        auto sel = select_good_citizen(pool, MEDIAN, AGC, HF_V16);
        check(sel.chosen.size() == 1, "even a max-weight zero-marginal tx is mined, never dropped to empty");
    }

    // -- R-CIT-2: everything under the median is taken, no fee test ------------
    {
        std::vector<node::TxBacklogEntry> pool;
        for (int i = 0; i < 10; ++i) pool.push_back(mk(2000, i == 3 ? 0 : 1000)); // one zero-fee
        auto sel = select_good_citizen(pool, MEDIAN, AGC, HF_V16);
        check(sel.chosen.size() == 10, "all sub-median txs taken including a zero-fee one (penalty-free zone)");
        // order preserved (pool order is authoritative; selector never re-sorts)
        bool order_ok = true;
        for (std::size_t i = 0; i < sel.chosen.size(); ++i)
            if (sel.chosen[i].fee != pool[i].fee) order_ok = false;
        check(order_ok, "selection preserves the pool's fee-ordered sequence");
    }

    // -- R-CIT-3: 0.98 threshold includes STRICTLY more than monerod's 1.0 ----
    // Fill the penalty-free zone with fee-bearing txs, then offer zero-fee txs
    // that only fit in the penalty zone. monerod (1.0) drops every zero-fee
    // penalty-zone tx; the good-citizen 0.98 keeps them until the coinbase
    // would fall below 98%.
    {
        std::vector<node::TxBacklogEntry> pool;
        for (int i = 0; i < 149; ++i) pool.push_back(mk(2000, 5000));   // ~298600 block_w
        for (int i = 0; i < 200; ++i) pool.push_back(mk(1000, 0));      // push into penalty zone

        CitizenPolicy monerod;   monerod.accept_threshold = 1.0;
        CitizenPolicy citizen;   citizen.accept_threshold = 0.98;

        auto s_monerod = select_good_citizen(pool, MEDIAN, AGC, HF_V16, monerod);
        auto s_citizen = select_good_citizen(pool, MEDIAN, AGC, HF_V16, citizen);

        check(!s_monerod.chosen.empty(), "monerod-threshold selection is non-empty");
        check(!s_citizen.chosen.empty(), "good-citizen selection is non-empty");
        check(s_citizen.chosen.size() > s_monerod.chosen.size(),
              "good-citizen 0.98 includes strictly more txs than monerod's 1.0 (bias to inclusion)");

        // Neither selection ever crosses the hard consensus ceiling ...
        const std::uint64_t ceiling = 2 * MEDIAN - 600;
        check(s_citizen.total_weight + 600 <= ceiling, "citizen selection stays under consensus ceiling 2*median-600");
        check(s_monerod.total_weight + 600 <= ceiling, "monerod selection stays under consensus ceiling 2*median-600");
        // ... nor the soft growth cap (1.5 * median).
        check(s_citizen.total_weight + 600 <= static_cast<std::uint64_t>(1.5 * MEDIAN),
              "citizen selection stays under soft growth cap 1.5*median");
    }

    // -- consensus ceiling holds under a flood of max-weight txs ---------------
    {
        std::vector<node::TxBacklogEntry> pool;
        for (int i = 0; i < 500; ++i) pool.push_back(mk(MAX_TXW, 100000));
        auto sel = select_good_citizen(pool, MEDIAN, AGC, HF_V16);
        check(!sel.chosen.empty(), "max-weight flood still yields a non-empty block");
        check(sel.total_weight + 600 <= 2 * MEDIAN - 600,
              "max-weight flood never crosses the consensus ceiling");
    }

    // -- determinism ----------------------------------------------------------
    {
        std::vector<node::TxBacklogEntry> pool;
        for (int i = 0; i < 300; ++i) pool.push_back(mk(1500 + (i % 7) * 200, 3000 + i));
        auto a = select_good_citizen(pool, MEDIAN, AGC, HF_V16);
        auto b = select_good_citizen(pool, MEDIAN, AGC, HF_V16);
        bool same = a.chosen.size() == b.chosen.size() && a.total_weight == b.total_weight;
        check(same, "selection is deterministic for a fixed backlog");
    }

    std::printf("%s: %d checks, %d failures\n", g_fail ? "FAIL" : "PASS", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
