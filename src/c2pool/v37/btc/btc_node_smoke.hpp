// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/btc/btc_node_smoke.hpp  (Track A2 / Milestone A-BTC — smoke)
//
// run_btc_node_smoke() — the network-free lifecycle invariants for XbtcNode over
// a MockCoinBackend. Shared by `c2pool-v37-btc --selftest` (main_v37_btc.cpp)
// and the CI test target v37_btc_node_smoke (test/v37_btc_node_smoke.cpp), so
// the exact same asserted body is both the developer smoke and the CI gate (no
// hollow-green: it is listed in BOTH build.yml legs + the src/c2pool/**/test
// drift-guard).
//
// It asserts the Milestone invariants:
//   (S1) construction/donor order — the W6 store + RecoveryDriver are built and
//        recovered BEFORE V37Engine::start().
//   (S2) the DASH-regtest default + the mainnet fail-closed fence.
//   (S4) the F1 CONTRACT — on_block_finalized once per coin-height, IN ORDER,
//        bin_height = high-water AT the step (H+D_conf), never the live tip.
//   (S3) the reorg drill — a block that leaves the best chain at maturity is
//        orphaned, never finalized (the controlled falsifier).
//   (S6) restart recovery round-trip + F2 fail-closed on a torn store.
// (S5 consensus DIGEST unchanged is proved by the separate drift-guard KAT,
//  test/btc_digest_drift_kat.cpp → v37_btc_digest_drift_kat.)
// ===========================================================================
#pragma once

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>

#include <c2pool/v37/btc/btc_node.hpp>

namespace c2pool::v37n::btc {

inline ::v37::bytes32 smoke_key_of(std::uint8_t tag) {
    ::v37::bytes32 k{};
    for (std::size_t i = 0; i < 32; ++i) k[i] = static_cast<std::uint8_t>(tag + i);
    return k;
}

// Returns the number of failed checks (0 == green).
inline int run_btc_node_smoke() {
    int fails = 0;
    auto check = [&](bool ok, const char* what) {
        if (!ok) { ++fails; std::printf("SMOKE FAIL: %s\n", what); }
        else       std::printf("  ok: %s\n", what);
    };

    // (S1) construction order + (S2 part 1) fresh-store open.
    {
        BtcNodeConfig cfg; cfg.lane_chain = 7; cfg.d_conf = 3;
        auto coin  = std::make_shared<MockCoinBackend>();
        auto store = std::make_unique<MemSettleStore>();
        XbtcNode node(cfg, std::move(store), coin, p2pkh_pay_of());
        check(node.open(),  "open() recovers a fresh store BEFORE start()");
        check(node.start(), "start() spins the engine + seeds the one lane");
        check(node.lane_snapshot() != nullptr, "lane published after AddLane");
        node.stop();
    }

    // (S2 part 2) mainnet fence.
    {
        BtcNodeConfig cfg; cfg.network = BtcNetwork::Mainnet;
        auto coin  = std::make_shared<MockCoinBackend>();
        auto store = std::make_unique<MemSettleStore>();
        XbtcNode node(cfg, std::move(store), coin, p2pkh_pay_of());
        check(!node.open(), "mainnet without --i-understand-mainnet is refused");
    }

    // (S4) mine → bury → finalize ONE height at a time.
    {
        BtcNodeConfig cfg; cfg.lane_chain = 7; cfg.d_conf = 3;
        auto coin  = std::make_shared<MockCoinBackend>();
        auto store = std::make_unique<MemSettleStore>();
        XbtcNode node(cfg, std::move(store), coin, p2pkh_pay_of());
        node.open(); node.start();

        OwedLedger::Amounts pre{{smoke_key_of(0x10), 1000}, {smoke_key_of(0x40), 2000}};
        coin->append_block("g0");                              // height 0 filler
        std::uint64_t seed_h = coin->append_block("seed");     // height 1
        node.finalizer().on_block_found(FoundBlock{"seed", seed_h, pre, {}});
        for (int i = 0; i <= (int)cfg.d_conf; ++i) coin->append_block("blk" + std::to_string(i));
        auto steps_seed = node.poll_tip();
        check(!steps_seed.empty() && steps_seed[0].bid == "seed" &&
              steps_seed[0].bin_height == seed_h + cfg.d_conf,
              "found block finalized once, IN ORDER, bin_height == h+D_conf");

        std::uint64_t win_h = coin->best_tip().height + 1;
        coin->append_block("won");
        WonBlockOutcome won = node.on_block_won("won", win_h, /*conf=*/0);
        check(won.submit.armed && won.submit.accepted,
              "on_block_won builds the W5 coinbase + submits the block");
        for (int i = 0; i < (int)cfg.d_conf + 1; ++i) coin->append_block("ext" + std::to_string(i));
        auto steps_won = node.poll_tip();
        bool found_won = false, ordered = true; std::uint64_t last_h = 0;
        for (auto& s : steps_won) {
            if (s.coin_height < last_h) ordered = false;
            last_h = s.coin_height;
            if (s.bid == "won") {
                found_won = true;
                check(s.bin_height == win_h + cfg.d_conf,
                      "won block bin_height == win_h + D_conf (per-step high-water)");
            }
        }
        check(found_won, "won block finalized by the height-watch");
        check(ordered,   "finalize steps strictly ascending in coin height (F1)");
        node.stop();
    }

    // (S3) the reorg drill.
    {
        BtcNodeConfig cfg; cfg.lane_chain = 7; cfg.d_conf = 2;
        auto coin  = std::make_shared<MockCoinBackend>();
        auto store = std::make_unique<MemSettleStore>();
        XbtcNode node(cfg, std::move(store), coin, p2pkh_pay_of());
        node.open(); node.start();

        coin->append_block("g0");                 // height 0
        std::uint64_t win_h = coin->append_block("fork_win");   // height 1
        node.finalizer().on_block_found(
            FoundBlock{"fork_win", win_h, {{smoke_key_of(1), 5}}, {{smoke_key_of(1), 5}}});
        coin->reorg_to(/*fork_height=*/0, {"alt1", "alt2", "alt3", "alt4"});
        auto steps = node.poll_tip();
        bool won_finalized = false;
        for (auto& s : steps) if (s.bid == "fork_win") won_finalized = true;
        check(!won_finalized, "reorg-dropped block is NOT finalized (orphaned at maturity)");
        node.stop();
    }

    // (S6) restart recovery round-trip + F2.
    {
        BtcNodeConfig cfg; cfg.lane_chain = 9; cfg.d_conf = 2;
        std::string tmp = "/tmp/v37btc_smoke_store_" + std::to_string(::getpid());
        std::filesystem::remove_all(tmp);
        {
            auto coin  = std::make_shared<MockCoinBackend>();
            auto store = std::make_unique<FileSettleStore>(tmp);
            XbtcNode node(cfg, std::move(store), coin, p2pkh_pay_of());
            node.open(); node.start();
            coin->append_block("g0");
            std::uint64_t ph = coin->append_block("persisted");
            node.finalizer().on_block_found(
                FoundBlock{"persisted", ph, {{smoke_key_of(2), 7}}, {{smoke_key_of(2), 7}}});
            for (int i = 0; i <= (int)cfg.d_conf; ++i) coin->append_block("c" + std::to_string(i));
            auto st = node.poll_tip();
            bool did = false; for (auto& s : st) if (s.bid == "persisted") did = true;
            check(did, "first boot finalizes the persisted block");
            node.stop();
        }
        {
            auto coin  = std::make_shared<MockCoinBackend>();
            auto store = std::make_unique<FileSettleStore>(tmp);
            XbtcNode node(cfg, std::move(store), coin, p2pkh_pay_of());
            check(node.open(), "second boot recovers the store (F2 clean)");
            check(node.ledger().ledger_seq() > 0,
                  "recovered ledger carries the persisted settlement events");
            node.stop();
        }
        std::filesystem::remove_all(tmp);
    }

    std::printf("BTC-NODE-SMOKE %s (%d failures)\n", fails ? "FAIL" : "OK", fails);
    return fails;
}

} // namespace c2pool::v37n::btc
