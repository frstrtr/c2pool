/*
 * This file is part of c2pool <https://github.com/frstrtr/c2pool>
 * Copyright (c) 2024-2026 The c2pool developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.  (Full header: xmr_node_types.hpp)
 */

// ===========================================================================
// src/impl/xmr/node/xmr_node_index_check.cpp  --  standalone sanity check
//
// AUTHORED for c2pool (not ported). A dependency-free, single-TU exercise of the
// consensus-relevant node-leg logic: RandomX seed math, >= 2112-block seed reach,
// retention that pins seed-epoch anchors, and Extend/Reorg/Orphan classification
// + confirmation-depth. NOT the production test suite (that is X8 goldens); this
// is the light check the OOM-pressured build host can run:
//     g++ -std=c++20 -O1 xmr_node_index_check.cpp -o /tmp/xmrn && /tmp/xmrn
// ===========================================================================
#include "mainchain_index.hpp"

#include <cstdio>
#include <cstdlib>

using namespace c2pool::xmr::node;

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { std::printf("  ok  : %s\n", msg); } \
    else { std::printf("  FAIL: %s\n", msg); ++g_fail; } } while (0)

// Deterministic pseudo-hash: 32 bytes, first 8 = tag LE, byte 8 = salt.
static Hash H(uint64_t tag, uint8_t salt = 0) {
    Hash h{};
    for (int i = 0; i < 8; ++i) h[i] = static_cast<uint8_t>((tag >> (8 * i)) & 0xff);
    h[8] = salt;
    return h;
}

static ChainMainBlock mk(uint64_t height, uint8_t salt = 0) {
    ChainMainBlock b;
    b.height     = height;
    b.id         = H(height, salt);
    b.prev_id    = (height > 0) ? H(height - 1, salt) : Hash{};
    b.timestamp  = 1600000000ull + height * 120;
    b.reward     = 600000000000ull; // 0.6 XMR tail emission
    b.difficulty = Difficulty128{height * 1000ull, 0};
    return b;
}

int main() {
    std::printf("== seed math (monerod rx_seedheight parity) ==\n");
    CHECK(rx_seed_height(0)    == 0,    "rx_seed_height(0)==0");
    CHECK(rx_seed_height(2112) == 0,    "rx_seed_height(2112)==0 (epoch+lag boundary)");
    CHECK(rx_seed_height(2113) == 2048, "rx_seed_height(2113)==2048");
    CHECK(rx_seed_height(4160) == 2048, "rx_seed_height(4160)==2048 (max 2112 reach)");
    CHECK(4160 - rx_seed_height(4160) == SEED_REACH_MIN, "reach at lag boundary == 2112");
    CHECK(rx_seed_height(4161) == 4096, "rx_seed_height(4161)==4096 (just crossed lag)");

    std::printf("== extend / confirmation depth ==\n");
    {
        std::vector<MainchainEvent> log;
        MainchainIndex idx(720, [&](const MainchainEvent& e){ log.push_back(e); });
        for (uint64_t h = 1; h <= 10; ++h) idx.apply(mk(h));
        CHECK(idx.best_height() == 10, "best_height==10 after 10 extends");
        CHECK(log.size() == 10, "10 Extend events emitted");
        bool all_extend = true; for (auto& e : log) if (e.kind != MainchainEventKind::Extend) all_extend = false;
        CHECK(all_extend, "all events were Extend");
        CHECK(idx.confirmation_depth(H(10)) == 1, "tip depth==1");
        CHECK(idx.confirmation_depth(H(6))  == 5, "height6 depth==5");
        CHECK(idx.confirmation_depth(H(999)) == 0, "unknown id depth==0");
    }

    std::printf("== >= 2112 seed reach + anchor pinning under prune ==\n");
    {
        MainchainIndex idx(720);
        for (uint64_t h = 1; h <= 4880; ++h) idx.apply(mk(h));
        CHECK(idx.best_height() == 4880, "best_height==4880");
        // Anchors 4096 and 2048 must both be resident despite the 720 window.
        auto a2048 = idx.by_height(2048);
        auto a4096 = idx.by_height(4096);
        CHECK(a2048.has_value(), "seed anchor 2048 pinned (well below 720 window)");
        CHECK(a4096.has_value(), "seed anchor 4096 pinned");
        // Window bottom 4160's seed is 2048 -> full 2112 reach below the window.
        auto s = idx.seed_hash_for_height(4160);
        CHECK(s.has_value() && *s == H(2048), "seed_hash_for_height(4160)==id(2048)");
        CHECK(4160 - 2048 == 2112, "verified reach depth from window bottom == 2112");
        CHECK(idx.seed_reach_satisfied(), "seed reach satisfied (no missing anchors)");
        CHECK(idx.missing_seed_heights().empty(), "missing_seed_heights empty");
        // Everything strictly older than the window and not an anchor is pruned.
        CHECK(!idx.by_height(100).has_value(), "old non-anchor height 100 pruned");
        CHECK(idx.by_height(4200).has_value(), "recent height 4200 retained");
    }

    std::printf("== reorg / orphan events (W4 un-confirm) ==\n");
    {
        std::vector<MainchainEvent> log;
        MainchainIndex idx(720, [&](const MainchainEvent& e){ log.push_back(e); });
        for (uint64_t h = 1; h <= 20; ++h) idx.apply(mk(h, /*salt*/0));
        log.clear();
        // monerod rolls back to height 19 on a competing branch (salt=1): new
        // best tip is 19', so 20(old) and 19(old) are orphaned, depth==2.
        ChainMainBlock competitor19 = mk(19, /*salt*/1);
        idx.apply(competitor19);
        int orphans = 0, reorgs = 0; uint64_t reorg_depth = 0;
        for (auto& e : log) {
            if (e.kind == MainchainEventKind::Orphan) ++orphans;
            if (e.kind == MainchainEventKind::Reorg) { ++reorgs; reorg_depth = e.depth; }
        }
        CHECK(orphans == 2, "2 Orphan events (heights 20 and 19)");
        CHECK(reorgs == 1, "1 Reorg event");
        CHECK(reorg_depth == 2, "reorg depth == 2");
        CHECK(idx.best_height() == 19, "best_height rolled back to 19");
        CHECK(idx.best_id() == H(19, 1), "best tip is the competitor 19'");
        CHECK(idx.confirmation_depth(H(20, 0)) == 0, "orphaned old tip 20 depth==0");
        CHECK(idx.confirmation_depth(H(19, 0)) == 0, "orphaned old 19 depth==0");
        CHECK(idx.confirmation_depth(H(19, 1)) == 1, "new tip 19' depth==1");
        CHECK(idx.confirmation_depth(H(18, 0)) == 2, "common-ancestor 18 depth==2 (survived)");
    }

    std::printf("== tx backlog dedup / remove-on-mined ==\n");
    {
        MainchainIndex idx(720);
        TxBacklogEntry a; a.id = H(0xAA); a.weight = 1500; a.fee = 3000;
        TxBacklogEntry b; b.id = H(0xBB); b.weight = 2000; b.fee = 8000;
        idx.add_backlog_tx(a); idx.add_backlog_tx(b); idx.add_backlog_tx(a); // dup
        CHECK(idx.backlog().size() == 2, "backlog dedups by id");
        idx.remove_backlog_txs({H(0xAA)});
        CHECK(idx.backlog().size() == 1 && idx.backlog()[0].id == H(0xBB), "mined tx removed from backlog");
    }

    std::printf("\n%s (%d failure%s)\n", g_fail ? "RESULT: FAIL" : "RESULT: PASS",
                g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
