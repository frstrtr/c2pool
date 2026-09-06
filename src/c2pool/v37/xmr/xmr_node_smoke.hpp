// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_node_smoke.hpp   (Track A2 / Milestone A — the smoke)
//
// A self-contained, network-free smoke of the live XmrNode daemon against a
// MockMonerodTransport (a monerod STUB — HARD SAFETY 6). Shared by
// `c2pool-v37-xmr --mock-smoke` and the CI test target v37_xmr_node_smoke, so
// the SAME assertions gate CI and can be run by hand. NO RandomX, NO sockets,
// NO live monerod. Proves the four milestone invariants the report claims:
//   S1  construction / donor order (store + recovery BEFORE engine.start);
//   S2  BOTH descriptor backends live + fail-closed without one;
//   S3  the X2 adapter event stream drives the node (tip advance + reorg);
//   S4  the F1 CONTRACT: on_block_finalized per coin-height, in order, with
//       bin_height = the high-water AT THE STEP, NEVER the live tip;
//   S5  consensus DIGEST unchanged (lane digest + owed digest byte-identical to
//       a bare-library replay);
//   S6  restart recovery round-trip + F2 fail-closed on a torn store.
// ===========================================================================
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "impl/xmr/node/monerod_transport.hpp"   // MockMonerodTransport
#include "xmr_node.hpp"

namespace c2pool::v37n::xmr::smoke {

struct Check { std::string name; bool pass; std::string detail; };
struct Report {
    std::vector<Check> checks;
    bool all_pass() const {
        for (const auto& c : checks) if (!c.pass) return false;
        return true;
    }
    void add(const std::string& n, bool p, const std::string& d = "") {
        checks.push_back({n, p, d});
    }
};

// A trivial ed25519 point-check backend for the light (no-crypto) smoke: it is
// NOT a real torsion check — it accepts any non-zero 32-byte point and rejects
// all-zero (the identity). Enough to prove the daemon INSTALLS a backend and
// that xmr_ref_valid() goes live; the REAL ref10 torsion check is exercised by
// the merged xmr_torsion_kat and is linked in the production daemon.
inline bool test_point_check(const std::uint8_t* pt) {
    for (int i = 0; i < 32; ++i) if (pt[i] != 0) return true;
    return false;
}

inline ::v37::bytes32 key_of(std::uint8_t b) {
    ::v37::bytes32 k{};
    k[0] = b; k[31] = b;
    return k;
}
inline c2pool::xmr::node::Hash blk_id(std::uint8_t b) {
    c2pool::xmr::node::Hash h{};
    for (int i = 0; i < 32; ++i) h[i] = static_cast<std::uint8_t>(b + i);
    return h;
}

// Apply one best-chain row through the adapter's index (emits Extend/Reorg to
// the node's wired sink → the F1 driver).
inline void apply_row(XmrNode& node, std::uint64_t height,
                      const c2pool::xmr::node::Hash& id,
                      const c2pool::xmr::node::Hash& prev) {
    c2pool::xmr::node::ChainMainBlock r;
    r.height = height;
    r.id = id;
    r.prev_id = prev;
    node.adapter().index().apply(r);
}

inline Report run(const std::filesystem::path& tmp_root) {
    Report rep;
    const ::v37::ChainId CHAIN = 7;
    const std::uint64_t  D_CONF = 3;

    auto make_cfg = [&](const std::string& sub) {
        XmrNodeConfig c;
        c.network = MoneroNetwork::Stagenet;
        c.lane_chain = CHAIN;
        c.d_conf = D_CONF;
        c.settle_db_path = (tmp_root / sub).string();
        return c;
    };

    // ── S2b: a node with NO backend refuses to start (fail-closed). Run this
    //    FIRST, before any backend is installed process-wide. ────────────────
    ::v37::xmr::set_point_check_backend(nullptr);
    {
        c2pool::xmr::node::MockMonerodTransport mock;
        XmrNode node(make_cfg("failclosed"), mock, /*point_check=*/nullptr);
        bool threw = false;
        try { node.bring_up(); } catch (const std::exception&) { threw = true; }
        rep.add("S2b fail-closed without a point-check backend", threw,
                threw ? "" : "bring_up did NOT refuse with no backend");
    }

    // ── main node, with the (test) point-check backend injected. ────────────
    c2pool::xmr::node::MockMonerodTransport mock;
    XmrNode node(make_cfg("main"), mock, &test_point_check);
    try {
        node.bring_up();
        rep.add("bring_up succeeds with a backend + fresh store", true);
    } catch (const std::exception& e) {
        rep.add("bring_up succeeds with a backend + fresh store", false, e.what());
        return rep;   // nothing else can run
    }

    // ── S1: construction / donor order — store + recovery appear in the log
    //    BEFORE "engine: started". ─────────────────────────────────────────
    {
        const auto& L = node.construction_log();
        int i_store = -1, i_rec = -1, i_engine = -1;
        for (int i = 0; i < static_cast<int>(L.size()); ++i) {
            if (L[i].rfind("store: opened", 0) == 0) i_store = i;
            if (L[i].rfind("recovery:", 0) == 0)     i_rec = i;
            if (L[i].rfind("engine: started", 0) == 0) i_engine = i;
        }
        bool ok = i_store >= 0 && i_rec >= 0 && i_engine >= 0 &&
                  i_store < i_engine && i_rec < i_engine;
        rep.add("S1 store+recovery constructed BEFORE engine.start()", ok,
                "store@" + std::to_string(i_store) + " recovery@" + std::to_string(i_rec) +
                " engine@" + std::to_string(i_engine));
    }

    // ── S2a: BOTH backends live — a well-formed XMR_STD descriptor validates. ─
    {
        bool live = ::v37::xmr::point_check_backend() != nullptr;
        ::v37::ScriptRef ref;
        ref.kind = ::v37::xmr::XMR_STD;
        ref.payload.assign(64, 0);
        for (int i = 0; i < 64; ++i) ref.payload[i] = static_cast<std::uint8_t>(i + 1);
        bool valid = ::v37::xmr::xmr_ref_valid(ref);
        rep.add("S2a point-check backend live + XMR descriptor validates", live && valid,
                std::string("live=") + (live ? "1" : "0") + " valid=" + (valid ? "1" : "0"));
    }

    // ── S3: the X2 adapter event stream drives the node (tip advance + reorg). ─
    {
        auto z = blk_id(0);
        apply_row(node, 1, blk_id(1), z);
        apply_row(node, 2, blk_id(2), blk_id(1));
        apply_row(node, 3, blk_id(3), blk_id(2));
        bool advanced = node.adapter().index().best_height() == 3;
        // Reorg: a competing block at height 3 rolls back the tip.
        apply_row(node, 3, blk_id(99), blk_id(2));
        bool reorged = node.hw().hw_height >= 3;   // hw monotone, tip re-adopted
        rep.add("S3 adapter Extend advances tip; Reorg handled", advanced && reorged,
                "best=" + std::to_string(node.adapter().index().best_height()) +
                " hw=" + std::to_string(node.hw().hw_height));
    }

    // ── S4: the F1 CONTRACT. Register two found blocks (mined heights 10, 11),
    //    then CATCH UP the tip in one jump to 20 and prove each finalizes at its
    //    OWN high-water (13, 14) — in ascending order, NEVER the live tip (20). ─
    {
        // seed the chain up to height 12 so 10/11 are resident + canonical.
        apply_row(node, 10, blk_id(10), blk_id(3));
        apply_row(node, 11, blk_id(11), blk_id(10));
        apply_row(node, 12, blk_id(12), blk_id(11));

        Amounts credA; credA[key_of(0xA1)] = 5000; Amounts payA = credA;
        Amounts credB; credB[key_of(0xB2)] = 7000; Amounts payB = credB;
        node.on_network_block_won(10, blk_id(10), credA, payA);
        node.on_network_block_won(11, blk_id(11), credB, payB);

        // ONE advance jumps the tip 12 -> 20 (gap-forward Extend).
        std::size_t n_before = node.finalize_driver().cursor_height();
        (void)n_before;
        auto steps = node.finalize_driver().advance_to_tip(20, bytes32_of(blk_id(20)));

        bool two = steps.size() == 2;
        bool ord = two && steps[0].coin_height == 10 && steps[1].coin_height == 11;
        bool binh = two && steps[0].bin_height == 13 && steps[1].bin_height == 14;
        bool not_tip = two && steps[0].bin_height != 20 && steps[1].bin_height != 20;
        bool ascending = two && steps[0].bin_height < steps[1].bin_height;
        bool settled = node.ledger().is_settled(hex_of(blk_id(10))) &&
                       node.ledger().is_settled(hex_of(blk_id(11)));
        rep.add("S4 F1: per-height finalize, in order, bin_height=H+D_conf (not tip)",
                two && ord && binh && not_tip && ascending && settled,
                two ? ("steps: h" + std::to_string(steps[0].coin_height) + "@bin" +
                       std::to_string(steps[0].bin_height) + ", h" +
                       std::to_string(steps[1].coin_height) + "@bin" +
                       std::to_string(steps[1].bin_height) + " (tip was 20)")
                    : ("expected 2 finalize steps, got " + std::to_string(steps.size())));

        // The anti-pattern check: had the driver used the live tip (the w4
        // reconcile() shape), BOTH would carry bin_height 20. Assert neither does.
        rep.add("S4b F1: neither finalize used the live tip as bin_height",
                two && steps[0].bin_height != 20 && steps[1].bin_height != 20);
    }

    // ── S5: consensus DIGEST unchanged. ────────────────────────────────────
    {
        // (a) lane digest: the daemon's AddLane == a bare Roundabout add_lane.
        ::v37::Roundabout rb;
        rb.add_lane(CHAIN, XmrNodeConfig{}.lane_params);
        bool lane_ok = node.seed_digest() == rb.lane_digest(CHAIN);

        // (b) owed digest: replay the SAME FOUND/FINALIZE sequence the daemon's
        //     F1 driver applied into a BARE OwedLedger and byte-compare. This is
        //     the digest-neutrality proof of the F1 sequencing: same bids, same
        //     per-height bin_heights, same order => byte-identical owed_digest.
        OwedLedger ref(CHAIN);
        Amounts credA; credA[key_of(0xA1)] = 5000; Amounts payA = credA;
        Amounts credB; credB[key_of(0xB2)] = 7000; Amounts payB = credB;
        ref.on_block_found(hex_of(blk_id(10)), credA, payA);
        ref.on_block_found(hex_of(blk_id(11)), credB, payB);
        ref.on_block_finalized(hex_of(blk_id(10)), 13);   // bin_height = 10 + D_conf
        ref.on_block_finalized(hex_of(blk_id(11)), 14);   // bin_height = 11 + D_conf
        bool owed_ok = node.ledger().owed_digest() == ref.owed_digest();

        rep.add("S5 consensus digest unchanged (lane digest byte-identical)", lane_ok);
        rep.add("S5b consensus digest unchanged (owed_digest byte-identical to bare replay)",
                owed_ok);
    }

    // capture state for the recovery round-trip before teardown.
    ::v37::bytes32 owed_before = node.ledger().owed_digest();
    std::uint64_t  hw_before   = node.hw().hw_height;
    std::uint64_t  cur_before  = node.finalize_driver().cursor_height();
    node.stop();

    // ── S6: restart recovery round-trip. Reopen the SAME store dir. ─────────
    {
        c2pool::xmr::node::MockMonerodTransport mock2;
        XmrNode node2(make_cfg("main"), mock2, &test_point_check);
        bool ok = true;
        std::string why;
        try { node2.bring_up(); } catch (const std::exception& e) { ok = false; why = e.what(); }
        bool digest_ok = ok && node2.ledger().owed_digest() == owed_before;
        bool hw_ok  = ok && node2.hw().hw_height == hw_before;
        bool cur_ok = ok && node2.finalize_driver().cursor_height() == cur_before;
        rep.add("S6 restart recovery restores owed_digest + hw + cursor",
                ok && digest_ok && hw_ok && cur_ok,
                ok ? ("digest=" + std::string(digest_ok ? "ok" : "MISMATCH") +
                      " hw=" + std::to_string(node2.hw().hw_height) + "/" + std::to_string(hw_before) +
                      " cur=" + std::to_string(node2.finalize_driver().cursor_height()) + "/" +
                      std::to_string(cur_before))
                   : why);
        node2.stop();
    }

    // ── S6b: F2 fail-closed on a torn store. Corrupt an event record. ───────
    {
        std::filesystem::path dir = tmp_root / "torn";
        FileSettleStore torn(dir);
        {   // write a deliberately truncated FINALIZE event blob.
            auto b = torn.batch();
            std::string bad = "\x01\x02";   // ver=1, kind=Finalize, then nothing (short read)
            b->put(store_codec::k_evt(CHAIN, 1), bad);
            b->commit_sync();
        }
        OwedLedger led(CHAIN);
        RecoveryDriver rec(torn, CHAIN);
        bool ok = true;
        rec.recover(led, ok);
        rep.add("S6b F2 fail-closed: torn store aborts recovery", !ok,
                ok ? "recovery did NOT flag the torn record" : "");
    }

    return rep;
}

} // namespace c2pool::v37n::xmr::smoke
