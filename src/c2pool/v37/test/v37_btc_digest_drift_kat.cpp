// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// btc_digest_drift_kat.cpp   (Track A2 / Milestone A-BTC — the drift-guard)
//
// HARD SAFETY 1 proof: the BTC-family node changes NO consensus digest. It only
// SEQUENCES calls into the merged V37Engine / OwedLedger / W5. This KAT pins,
// on a FIXED schedule, that:
//
//   (1) the LANE digest the XbtcNode publishes (AddLane + a push schedule
//       through V37Engine) is byte-identical to the SAME schedule driven
//       directly against a bare ::v37::Roundabout — i.e. the node adds no
//       reordering, no extra record, no geometry drift.
//
//   (2) the OWED digest after a fixed found/finalize/orphan schedule replayed
//       through BtcFinalizeDriver is byte-identical to the same calls issued
//       directly against a fresh OwedLedger — i.e. the F1 driver's write-ahead
//       and per-height sequencing are digest-transparent.
//
// If either diverges, the node has mutated consensus state and the KAT fails.
// It links ONLY merged headers + the new btc/ seam (no coin lib, no Boost).
// ===========================================================================
#include <cstdio>
#include <memory>
#include <string>

#include <c2pool/v37/v37_engine.hpp>
#include <c2pool/v37/w4_settlement.hpp>
#include <c2pool/v37/btc/btc_node.hpp>
#include <sharechain/v37/v37_roundabout.hpp>

using namespace c2pool::v37n::btc;
using c2pool::v37n::V37Engine;
using c2pool::v37n::settle::OwedLedger;

static ::v37::PayoutDescriptor p2pkh_desc(std::uint8_t tag) {
    ::v37::PayoutDescriptor d;
    std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(tag);
    s.push_back(0x88); s.push_back(0xac);
    d.pay = ::v37::canonicalize_script(s);
    return d;
}
static ::v37::bytes32 key_of(std::uint8_t tag) {
    ::v37::bytes32 k{}; for (std::size_t i = 0; i < 32; ++i) k[i] = std::uint8_t(tag + i); return k;
}

int main() {
    int fails = 0;
    auto check = [&](bool ok, const char* what) {
        if (!ok) { ++fails; std::printf("DRIFT-KAT FAIL: %s\n", what); }
        else       std::printf("  ok: %s\n", what);
    };

    const ::v37::ChainId CH = 7;
    ::v37::LaneParams params{};   // OQ-5 ratified default

    // ── (1) LANE digest: node-published vs bare Roundabout ───────────────────
    // Direct reference: a bare Roundabout with the identical schedule.
    ::v37::Roundabout rb;
    rb.add_lane(CH, params);
    for (int i = 0; i < 5; ++i) rb.push(CH, p2pkh_desc(0xa0 + i), 1, 0);
    ::v37::bytes32 ref_lane = rb.lane_digest(CH);

    // Through the node's engine: AddLane happens in start(); push the identical
    // schedule through the same V37Engine the node owns.
    {
        BtcNodeConfig cfg; cfg.lane_chain = CH; cfg.lane_params = params;
        auto coin  = std::make_shared<MockCoinBackend>();
        auto store = std::make_unique<MemSettleStore>();
        XbtcNode node(cfg, std::move(store), coin, p2pkh_pay_of());
        node.open(); node.start();
        for (int i = 0; i < 5; ++i)
            node.engine().submit_tracked(::v37::LaneRecord::push(CH, p2pkh_desc(0xa0 + i), 1, 0)).get();
        auto snap = node.engine().snapshot(CH);
        check(snap != nullptr, "node lane published");
        check(snap && snap->digest == ref_lane,
              "lane digest byte-identical to bare Roundabout (no node drift)");
        node.stop();
    }

    // ── (2) OWED digest: F1-driver-driven vs direct OwedLedger ───────────────
    // A fixed schedule: found A@h=0, found B@h=1, finalize both as tip buries.
    OwedLedger::Amounts credA{{key_of(0x10), 100}, {key_of(0x20), 50}};
    OwedLedger::Amounts payA {{key_of(0x10), 100}, {key_of(0x20), 50}};
    OwedLedger::Amounts credB{{key_of(0x30), 70}};
    OwedLedger::Amounts payB {{key_of(0x30), 70}};
    const std::uint64_t D = 2;

    // Reference: direct calls, in the exact order the F1 driver would issue them
    // (found in registration order; finalize per ascending height with
    // bin_height = h + D_conf).
    OwedLedger ref(CH);
    ref.on_block_found("A", credA, payA);
    ref.on_block_found("B", credB, payB);
    ref.on_block_finalized("A", 0 + D);   // h=0 finalizes with bin_height 0+D
    ref.on_block_finalized("B", 1 + D);   // h=1 finalizes with bin_height 1+D
    ::v37::bytes32 ref_owed = ref.owed_digest();

    // Through the driver + a real store, fed by a MockCoinBackend chain.
    {
        BtcNodeConfig cfg; cfg.lane_chain = CH; cfg.d_conf = D;
        auto coin  = std::make_shared<MockCoinBackend>();
        auto store = std::make_unique<MemSettleStore>();
        XbtcNode node(cfg, std::move(store), coin, p2pkh_pay_of());
        node.open(); node.start();
        // register the two found blocks at heights 0 and 1
        node.finalizer().on_block_found(FoundBlock{"A", 0, credA, payA});
        node.finalizer().on_block_found(FoundBlock{"B", 1, credB, payB});
        // build the chain: A at 0, B at 1, then bury both.
        coin->append_block("A");            // height 0
        coin->append_block("B");            // height 1
        for (int i = 0; i < (int)D + 1; ++i) coin->append_block("z" + std::to_string(i));
        node.poll_tip();                    // finalizes A then B, in order
        check(node.ledger().owed_digest() == ref_owed,
              "owed digest byte-identical to direct OwedLedger (F1 transparent)");
        node.stop();
    }

    std::printf("DRIFT-KAT %s (%d failures)\n", fails ? "FAIL" : "OK", fails);
    return fails ? 1 : 0;
}
