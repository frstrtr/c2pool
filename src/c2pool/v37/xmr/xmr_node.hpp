// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_node.hpp   (Track A2 / Milestone A — the live node)
//
// XmrNode — the single-node stagenet-capable c2pool-v37 Monero/RandomX daemon
// object. It OWNS the wiring of the merged Family-B lane against a live monerod
// and stands up the whole mine-and-settle path. It defines NO consensus digest:
// every consensus operation is delegated to the merged V37Engine / OwedLedger /
// lane executor / X6 coinbase builder (HARD SAFETY 1).
//
// CONSTRUCTION ORDER (donor lifecycle — register before the loop, tear down
// after; bring_up() records each step in construction_log() for the smoke):
//   1. install BOTH descriptor backends (P-1 descriptor validator + ed25519
//      point-check) and ASSERT they are live (fail-closed — HARD SAFETY 4);
//   2. open the W6 settlement store at config_path()/<net>/v37_settle_db;
//   3. run RecoveryDriver over it to rebuild the OWED ledger + high-water +
//      finalize cursor  — BEFORE the engine starts (a torn store aborts: F2);
//   4. start the V37Engine and seed AddLane for the Monero-parent lane;
//   5. bind the X2 MonerodAdapter to the transport, route its Extend/Reorg/
//      Orphan stream into the F1 finalize driver;
//   6. start the adapter (ZMQ subs + initial RPC sync).
// Teardown (stop()) reverses it: stop the network first, THEN drain-and-join the
// engine, so no monerod callback can submit into a torn-down engine.
// ===========================================================================
#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <core/filesystem.hpp>                       // core::filesystem::config_path
#include <c2pool/v37/v37_engine.hpp>                 // V37Engine (merged)
#include <c2pool/v37/w4_settlement.hpp>              // OwedLedger, SettleHW (merged)
#include <c2pool/v37/v37_drop_harvest.hpp>           // ★ DROPS T3: DropHarvester
#include <c2pool/v37/v37_drops_enrollment.hpp>       // ★ R-SYBIL: EnrollmentBook
#include <sharechain/v37/v37_descriptor_xmr.hpp>     // point_check_backend, xmr_ref_valid
#include <sharechain/v37/v37_roundabout.hpp>

#include "impl/xmr/node/monero_node_adapter.hpp"     // MonerodAdapter (merged X2)
#include "impl/xmr/node/monerod_transport.hpp"       // IMonerodTransport

#include "xmr_node_config.hpp"
#include "xmr_settle_store.hpp"
#include "xmr_finalize_driver.hpp"

namespace c2pool::v37n::xmr {

// ── resolve the settlement-store path (out-of-line body for the config decl) ──
inline std::string XmrNodeConfig_resolved(const XmrNodeConfig& c) {
    if (!c.settle_db_path.empty()) return c.settle_db_path;
    std::filesystem::path p =
        core::filesystem::config_path() / net_dir(c.network) / "v37_settle_db";
    return p.string();
}

// small hex helpers for block-id <-> string keys and the SettleHW tip bytes.
inline std::string hex_of(const c2pool::xmr::node::Hash& h) {
    static const char* k = "0123456789abcdef";
    std::string s; s.reserve(64);
    for (std::uint8_t b : h) { s.push_back(k[b >> 4]); s.push_back(k[b & 0xf]); }
    return s;
}
inline ::v37::bytes32 bytes32_of(const c2pool::xmr::node::Hash& h) {
    ::v37::bytes32 b{};
    for (std::size_t i = 0; i < 32 && i < h.size(); ++i) b[i] = h[i];
    return b;
}

class XmrNode {
public:
    // `transport` is the live I/O seam (production: LiveMonerodTransport; tests:
    // MockMonerodTransport). Ownership stays with the caller so a test can drive
    // frames into it directly. `point_check` optionally injects the ed25519
    // backend explicitly (production links the ref10 registrar, which also
    // auto-installs at static init; a light test with no crypto link passes a
    // test predicate so the fail-closed guard can be exercised).
    XmrNode(XmrNodeConfig cfg, c2pool::xmr::node::IMonerodTransport& transport,
            ::v37::xmr::xmr_point_check_fn point_check = nullptr)
        : m_cfg(std::move(cfg)), m_transport(transport),
          m_injected_point_check(point_check),
          m_ledger(m_cfg.lane_chain) {}

    ~XmrNode() { stop(); }

    XmrNode(const XmrNode&) = delete;
    XmrNode& operator=(const XmrNode&) = delete;

    // ── M3: the DAEMONLESS tip driver seam ─────────────────────────────────
    //
    // Under --arm-order daemon-first (the default) the X2 MonerodAdapter is the
    // tip: it fills a MainchainIndex from get_miner_data / ZMQ and answers the
    // finalize driver's "is this block still at this height" from that mirror.
    //
    // Under --arm-order p2p-first there is no adapter at all. The tip is the
    // native node's own levin-driven, RandomX-verified C2 index, and these two
    // functions are how it gets in: the consumer installs the presence test
    // BEFORE bring_up(), and pumps each mainchain event the native index
    // produced from its own loop.
    //
    // The presence test is installed before bring_up rather than after because
    // an uninstalled one cannot be made safe: XmrFinalizeDriver asks it at
    // maturity, a false answer ORPHANS a block that is perfectly canonical, and
    // there is no third value to return. So bring_up() REFUSES p2p-first
    // without it rather than starting into a window where the answer is wrong.
    using ChainPresenceFn = std::function<bool(std::uint64_t height, const std::string& bid_hex)>;
    void set_native_chain_presence(ChainPresenceFn fn) { m_native_presence = std::move(fn); }

    // D2-0: "which block does the best chain carry at height h" (lowercase hex),
    // from the native index in p2p-first. Used to deliver the REORG-IN blocks
    // below a Reorg tip to the booking observer (on_mainchain_event) and by the
    // D2 minority re-derivation (chain_bid_at). Unset = nullopt (daemon-first
    // answers from the adapter's mirror instead).
    using RowLookupFn = std::function<std::optional<std::string>(std::uint64_t height)>;
    void set_native_row_lookup(RowLookupFn fn) { m_native_row = std::move(fn); }

    // The block id (lowercase hex) the best chain carries at `height`, or nullopt
    // (above the tip / outside the retention window / header fetch failed).
    std::optional<std::string> chain_bid_at(std::uint64_t height) {
        if (m_adapter) {
            auto b = m_adapter->index().by_height(height);
            if (!b || is_zero_id(b->id)) {
                bool fetch_failed = false;
                b = m_adapter->ensure_row(height, fetch_failed);
            }
            if (!b || is_zero_id(b->id)) return std::nullopt;
            return hex_of(b->id);
        }
        if (m_native_row) return m_native_row(height);
        return std::nullopt;
    }
    std::uint64_t reorg_redelivered() const noexcept { return m_reorg_redelivered; }

    // Feed ONE mainchain event from the native index. Same body the adapter's
    // event sink runs, called from the consumer's main loop instead of from a
    // monerod callback -- so Extend/Reorg advance settlement and Orphan disposes
    // exactly as they always did, off a chain no daemon described to us.
    void pump_mainchain_event(const c2pool::xmr::node::MainchainEvent& ev) {
        on_mainchain_event(ev);
    }

    // True when the daemon-backed X2 adapter is the tip driver. False in
    // p2p-first: adapter() must not be called, and nothing may poll monerod.
    bool daemon_tip_active() const noexcept { return m_adapter != nullptr; }

    // ── c2pool#1551: the ONE chain-observation seam ────────────────────────
    //
    // Every block this node's chain tells it about -- a new tip, a reorg tip, an
    // orphan -- is announced here, whichever arm drives the tip. The accounting
    // layer above needs it to SEE a same-height race at all, and it has to be
    // one seam and not two: a prefer-own tiebreak fed by the daemon adapter in
    // one mode and by the native index in the other would be two policies that
    // happened to share a name.
    using ChainObserverFn = std::function<void(std::uint64_t height, const std::string& bid_hex)>;
    void set_chain_observer(ChainObserverFn fn) { m_chain_observer = std::move(fn); }
    //  fed ONLY for Extend/Reorg (a block joined the best chain), never for Orphan.
    void set_chain_extend_observer(ChainObserverFn fn) { m_cba_extend_observer = std::move(fn); }

    // The canonical test the F1 finalize driver runs at maturity, exposed so the
    // accounting layer asks the SAME question of the SAME chain. A tiebreak that
    // consulted a different oracle than the one that finalizes would be a
    // second, disagreeing consensus -- and the one it disagreed with would be
    // the one holding the money.
    // Two-valued view (race book / diagnostics): true iff the chain POSITIVELY
    // carries bid at height. An UNKNOWN answer reads false here, so callers that
    // must not act on "unknown" (the finalize walk, the booking gate, the
    // deferred-drop) use chain_carries3() instead.
    bool chain_carries(std::uint64_t height, const std::string& bid_hex) {
        return chain_carries3(height, bid_hex) == Carry::Yes;
    }

    // R-C rework-2 (O3.5 false-orphan fix): the TRI-STATE canonical answer.
    //   Yes     -- the mirror (or a fresh daemon header) carries bid at height;
    //   No      -- the mirror/daemon carries a DIFFERENT block there, or height is
    //              above the tip (the chain genuinely does not carry it now);
    //   Unknown -- the row is absent AND the daemon header fetch FAILED (or the
    //              mirror is still empty). Never evidence the block left the
    //              chain: the finalize walk HOLDS on it (xmr_finalize_driver.hpp
    //              set_carry_probe), the booking gate keeps holding, a deferred
    //              block is kept -- never a false orphan.
    using Carry = XmrFinalizeDriver::Carry;
    Carry chain_carries3(std::uint64_t height, const std::string& bid_hex) {
        if (m_adapter) {
            auto b = m_adapter->index().by_height(height);
            bool fetch_failed = false;
            if (!b || is_zero_id(b->id)) {
                // Restart-liveness fix: initial_sync() seeds only the TIP row, so after a
                // restart every height below the tip is absent from the mirror. An absent
                // row is NOT evidence the block left the chain. Fill the row from the
                // daemon once (synchronous settled-header fetch, never moves the tip).
                b = m_adapter->ensure_row(height, fetch_failed);
                log(std::string("chain_carries: mirror row h=") + std::to_string(height) +
                    (b ? " was absent -> backfilled from the daemon (restart-liveness)"
                       : fetch_failed ? " absent and the daemon header fetch FAILED -> UNKNOWN (hold, never a false orphan)"
                                      : " absent (above the tip) -> not carried"));
                if (!b && fetch_failed) { ++m_carry_unknown; return Carry::Unknown; }
            }
            return (b && hex_of(b->id) == bid_hex) ? Carry::Yes : Carry::No;
        }
        return (m_native_presence && m_native_presence(height, bid_hex)) ? Carry::Yes : Carry::No;
    }
    std::uint64_t carry_unknown_answers() const { return m_carry_unknown; }

    // ── R-C rework-2 (F2): the chain-GAP RE-DRIVE ───────────────────────────
    // Extend is the ONLY booking trigger (the extend observer -> FinalizeConnect::
    // book_chain_block). Lane blocks mined while this node was DOWN, or across a
    // ZMQ gap wider than the adapter's 64-row reconcile walk, never produced an
    // Extend here (initial_sync direct-applies only the tip; MainchainIndex::apply
    // sets resync_needed_ on a forward gap and nothing consumes it), so they were
    // NEVER booked -- and the cursor then stepped past them (late_unbooked, the
    // credit lost). With the re-drive enabled the node tracks the highest height
    // whose Extend reached the installed extend observer (the SCAN height) and
    //   * on every Extend/Reorg at H > scan + 1 re-drives every interior height
    //     (scan, H) ascending through the SAME observers (header per height from
    //     the mirror or one synchronous daemon fetch -- ensure_row);
    //   * holds the finalize walk (a node-side booking gate) at any h with
    //     h + D_conf > scan: an unscanned height may carry a lane block the synced
    //     node had booked before FINALIZE(h) ran;
    //   * on a RESUMED store starts the scan at the recovered finalize cursor, so
    //     the boot tip (applied by initial_sync BEFORE the consumer installed its
    //     observers) and every height the node missed while down are re-driven by
    //     redrive_gap_to_tip() -- FinalizeConnect calls it from
    //     reseed_after_bring_up(). Deferred-but-unbooked blocks that died with the
    //     previous process (R6 m_deferred is in-memory) are recovered the same way.
    // Dedup is FinalizeConnect's (pending / settled / memoized bids are skipped).
    // A header-fetch failure stops the re-drive at that height (scan stays below
    // it, the gate keeps holding) and the next event/tick retries. A gap wider
    // than the mirror retention is truncated LOUDLY (counted). daemon-first only
    // (the native index pumps every block it connects).
    // Call BEFORE bring_up().
    void enable_gap_redrive(bool on = true) { m_gap_redrive = on; }
    bool gap_redrive_enabled() const noexcept { return m_gap_redrive; }
    std::uint64_t scan_height() const noexcept { return m_scan_h; }
    struct GapStats {
        std::uint64_t redriven_heights = 0, redrive_calls = 0, fetch_failed = 0,
                      truncated = 0, truncated_heights = 0, gate_holds = 0;
    };
    const GapStats& gap_stats() const noexcept { return m_gap; }

    // Re-drive (scan, best] now (the boot path; also safe to call every tick).
    // Returns the number of heights delivered. Advances settlement afterwards so
    // the held walk resumes (the consumer's booking gate governs from here).
    std::size_t redrive_gap_to_tip() {
        if (!m_gap_redrive || !m_adapter || !m_cba_extend_observer) return 0;
        const std::uint64_t best = m_adapter->index().best_height();
        if (m_adapter->index().empty() || best == 0) return 0;
        if (m_scan_h == 0) { m_scan_h = best; return 0; }   // fresh store: nothing precedes us
        if (best <= m_scan_h) return 0;
        const std::size_t n = redrive_range(m_scan_h + 1, best);
        if (n && m_finalize && m_hw.hw_height) (void)readvance_settlement();
        return n;
    }

    // Seed a SETTLED owed amount THROUGH the event log (F1). See
    // XmrFinalizeDriver::seed_settled. Returns false when the store already holds
    // it (resumed store) or before bring_up().
    bool seed_settled_owed(const std::string& bid, const Amounts& credit, std::uint64_t bin_height) {
        if (!m_finalize) return false;
        const bool fresh = m_finalize->seed_settled(bid, credit, bin_height);
        log(std::string("seed: ") + bid + (fresh ? " FOUND+FINALIZE written through the event log"
                                                 : " already in the replayed store (resumed) -> not re-applied"));
        return fresh;
    }

    // The consumer's booking gate (FinalizeConnect R4/R6). The node composes it
    // with its own gap gate; install through here, not on the driver directly.
    void set_booking_gate(XmrFinalizeDriver::BookingGateFn g) { m_consumer_gate = std::move(g); }

    static bool is_zero_id(const c2pool::xmr::node::Hash& h) { for (auto c : h) if (c) return false; return true; }

    // The best height the settlement path is working against, from whichever
    // driver is live. In p2p-first this is the highest height a pumped event
    // carried, which is the same number the finalize cursor chases.
    std::uint64_t best_height() const {
        if (m_adapter) return m_adapter->index().best_height();
        return m_tip_height;
    }

    // Full bring-up in donor order. Throws std::runtime_error on a fail-closed
    // condition (no descriptor backend; a torn store; a rejected AddLane; a
    // mainnet coinbase without acknowledgement is refused later, at submit).
    void bring_up() {
        log("bring_up: begin (network=" + std::string(to_string(m_cfg.network)) + ")");

        // 1) BOTH descriptor backends live, or refuse to run (fail-closed).
        install_descriptor_backends();
        log("backends: point-check installed; XMR descriptors validate");

        // 2) open the W6 settlement store.
        std::string dbdir = XmrNodeConfig_resolved(m_cfg);
        m_store = std::make_unique<FileSettleStore>(dbdir);
        log("store: opened " + dbdir);

        // 3) RecoveryDriver BEFORE engine.start() — rebuild ledger + hw + cursor.
        {
            RecoveryDriver rec(*m_store, m_cfg.lane_chain);
            bool ok = false;
            m_boot_digests.clear(); m_boot_since.clear();
            m_boot_digests.push_back(m_ledger.owed_digest());   // the empty anchor / anchor-boot state
            m_boot_since.push_back(0);
            // R-C rework-3 (D7): pair every replayed digest state with the coin
            // height it became current at (Finalize: bin_height - D_conf; the
            // formula XmrFinalizeDriver::since_of_bin applies live).
            std::uint64_t since = 0;
            m_recovered = rec.recover(m_ledger, ok, {}, [this, &since](const OwedLedger& l, const SettleEvent& e) {
                if (e.kind == SettleEvKind::Finalize)
                    since = e.bin_height >= m_cfg.d_conf ? e.bin_height - m_cfg.d_conf : 0;
                const ::v37::bytes32 d = l.owed_digest();
                if (!(m_boot_digests.back() == d)) {   // R-B(i) follow-up: canonical D(c) history
                    m_boot_digests.push_back(d);
                    m_boot_since.push_back(since);
                }
            });
            m_boot_last_since = since;
            if (!ok)
                throw std::runtime_error(
                    "XmrNode: settlement store is torn (F2 fail-closed) — refusing to start");
            m_hw = m_recovered.hw;
            log("recovery: hw_height=" + std::to_string(m_hw.hw_height) +
                " cursor=" + std::to_string(m_recovered.finalize_cursor_height) +
                " events=" + std::to_string(m_recovered.max_event_seq) +
                (m_recovered.recovered ? " (resumed)" : " (fresh)"));
        }

        // 4) start the engine and seed the Monero-parent lane (AddLane).
        m_engine.start();
        auto r = m_engine.submit_tracked(
                     ::v37::LaneRecord::add_lane(m_cfg.lane_chain, m_cfg.lane_params)).get();
        if (!r.applied())
            throw std::runtime_error("XmrNode: AddLane for the XMR parent lane was rejected");
        auto snap = m_engine.snapshot(m_cfg.lane_chain);
        if (!snap || snap->version != 1)
            throw std::runtime_error("XmrNode: lane seed produced no v1 snapshot");
        m_seed_digest = snap->digest;
        log("engine: started; AddLane(chain=" + std::to_string(m_cfg.lane_chain) +
            ") committed; lane v1 seeded");

        // 5) bind the tip driver and route its event stream into the F1 driver.
        //    M3 (R-ARMORDER): WHICH driver is the switch. daemon-first builds
        //    the X2 adapter; p2p-first builds none and takes the native node's
        //    own chain index instead, which is what makes the find path
        //    daemonless rather than merely daemon-light.
        const bool daemon_tip = (m_cfg.arm_order == ArmOrderMode::DaemonFirst);
        if (!daemon_tip && !m_native_presence)
            throw std::runtime_error(
                "XmrNode: --arm-order p2p-first requires the native chain presence test to be "
                "installed before bring_up() (set_native_chain_presence). Fail-closed: a finalize "
                "driver that cannot ask whether a block is still on the best chain would orphan "
                "every block it settles.");

        if (daemon_tip)
            m_adapter = std::make_unique<c2pool::xmr::node::MonerodAdapter>(
                m_transport, m_cfg.monerod,
                static_cast<std::uint64_t>(m_cfg.index_retain_recent));

        m_finalize = std::make_unique<XmrFinalizeDriver>(
            m_ledger, m_hw, *m_store, m_cfg.lane_chain, m_cfg.d_conf,
            m_recovered.finalize_cursor_height, m_recovered.max_event_seq,
            [this](std::uint64_t h, const std::string& bid) { return chain_carries(h, bid); });
        m_finalize->set_digest_since(m_boot_last_since);   // R-C rework-3 (D7): continue the replayed since-height
        // R-C rework-2: tri-state carry (Unknown holds, never a false orphan) and
        // the composed booking gate (node gap gate AND the consumer's R4/R6 gate).
        m_finalize->set_carry_probe(
            [this](std::uint64_t h, const std::string& bid) { return chain_carries3(h, bid); });
        m_finalize->set_booking_gate([this](std::uint64_t h) {
            if (!gap_gate(h)) return false;
            return m_consumer_gate ? m_consumer_gate(h) : true;
        });
        // F2: a RESUMED store's scan starts at the recovered finalize cursor --
        // every height above it must be (re-)driven through the extend observer
        // before the walk may step there.
        m_scan_h = (m_gap_redrive && daemon_tip && m_recovered.recovered)
                       ? m_recovered.finalize_cursor_height : 0;
        if (m_scan_h)
            log("gap-redrive: armed; scan starts at the recovered finalize cursor " + std::to_string(m_scan_h) +
                " (every canonical height above it is re-driven through the booking observer before FINALIZE)");

        if (daemon_tip) {
            m_adapter->set_event_sink(
                [this](const c2pool::xmr::node::MainchainEvent& ev) { on_mainchain_event(ev); });

            // 6) start the adapter: subscribe ZMQ topics + one-shot RPC sync.
            m_adapter->start();
            m_adapter->initial_sync();
            log("adapter: started; subscribed miner_data/chain_main/txpool; initial_sync issued");
        } else {
            log("adapter: NOT built (--arm-order p2p-first) — the tip, the canonical test and "
                "the found-block relay all come from the native node's own levin chain; "
                "monerod is not on the find path");
        }

        m_up = true;
        log("bring_up: complete");
    }

    // Teardown in donor order: network first, then drain-and-join the engine.
    void stop() {
        if (!m_up) { m_engine.stop(); return; }
        m_up = false;
        log("stop: tearing down adapter, then engine (donor order)");
        m_adapter.reset();          // stop consuming monerod callbacks first
        m_engine.stop();            // then drain + join the executor thread
    }

    // ── the mine path (X5 stratum → X6 coinbase) hooks ─────────────────────

    // Called when an accepted share cleared the Monero NETWORK target (a real
    // block win). Builds the X6 coinbase from the finality-gated OWED ledger and
    // submits the block to monerod. FCMP-fenced + mainnet-fenced (HARD SAFETY 3
    // and 5). Registered with the F1 driver as a FOUND settlement block.
    //
    // The crypto build (coinbase derivation) is gated on V37_XMR_HAVE_MONERO_
    // CRYPTO; without it the node runs (index/settle/finalize) but cannot build
    // a coinbase — the fail-closed posture for a light/OOM build.
    bool on_network_block_won(std::uint64_t monero_height,
                              const c2pool::xmr::node::Hash& block_id,
                              const Amounts& credit, const Amounts& payout) {
        if (m_cfg.network == MoneroNetwork::Mainnet && !m_cfg.i_understand_mainnet) {
            log("win: REFUSED to settle a MAINNET block without --i-understand-mainnet");
            return false;
        }
        FoundBlock fb;
        fb.bid = hex_of(block_id);
        fb.height = monero_height;
        fb.credit = credit;
        fb.payout = payout;
        // ── ★ DROPS T3 (XMR arm) — the hook the BTC/DASH shell already has ──
        // Parity, not a second mechanism: the XMR finalize driver composes the
        // very same compose_credit_replace() the BTC-family driver does, so all
        // it was ever missing was a FoundBlock that carried the lane gate, the
        // buried harvest and the composition context. Without these four lines
        // an XMR node could take the flip, be gate-ON, and still credit nobody
        // for ever — the dormancy this PR exists to remove, in the one shell it
        // had not been removed from.
        //
        // EVERY PIECE DEFAULTS INERT. No harvester attached => buried_harvest()
        // returns {} and the composition returns fb.credit byte for byte. No
        // enrolment book => nobody is enrolled => nothing is composed even with
        // a full harvest. No price function => WorkPrice{}.valid == false =>
        // entitlement_of_work() returns 0 on BOTH sides of the replace. So a
        // default XMR node settles exactly as master does, and the seams below
        // are what an XMR shell calls once it has a DropsWiring to hand them.
        fb.params = m_cfg.lane_params;
        {
            ::c2pool::v37n::settle::DropsCompose dctx;
            // ★ DROPS-R1: how work becomes coin AT THIS CUT. The XMR arm has no
            // in-node fold to read a price off (credit arrives ready-made from
            // the X6 coinbase path), so the price is a supplied seam. Absent, it
            // is INVALID, which credits zero rather than crediting hash counts
            // as atomic units — the R1 blowup, refused by default.
            if (m_drops_price) dctx.price = m_drops_price();
            dctx.enrollment = m_enroll;     // ★ R-SYBIL: null => nobody enrolled
            fb.drops = dctx;
            fb.harvested = buried_harvest(monero_height);
        }
        m_finalize->on_block_found(fb);
        log("win: FOUND block " + fb.bid.substr(0, 12) + "… at height " +
            std::to_string(monero_height) + " registered (awaiting D_conf=" +
            std::to_string(m_cfg.d_conf) + ")");
        if (m_drops) log_drops_found(fb, monero_height);   // ★ DROPS: attached only under the flip
        return true;
    }

    // ── ★ DROPS T3 seams (XMR arm) — the BTC/DASH set, verbatim ──────────
    //
    // NOT attached by default, and that default is the safe one on every seam:
    // no harvester => empty harvest; no book => nobody enrolled; no price =>
    // zero on both sides of the replace. The node owns none of these lifetimes;
    // the shell that owns the W2 admitter owns them, because that is who feeds
    // them (v37_drops_wiring.hpp bundles all three and sources the enrolment
    // clock from the chain TIP, which is the property the seams themselves
    // cannot enforce).
    void set_drop_harvester(::c2pool::v37n::DropHarvester* h) { m_drops = h; }
    ::c2pool::v37n::DropHarvester* drop_harvester() const { return m_drops; }

    void set_enrollment_book(const ::c2pool::v37n::EnrollmentBook* b) { m_enroll = b; }
    const ::c2pool::v37n::EnrollmentBook* enrollment_book() const { return m_enroll; }

    // Called with the BURIAL FRONTIER immediately before the harvest is taken,
    // so the share-count producer can declare every interval's S before the
    // fail-closed release rule withholds it. Wire it to
    // DropsWiring::pre_harvest().
    using PreHarvestFn = std::function<void(std::uint64_t bury_before)>;
    void set_pre_harvest(PreHarvestFn f) { m_pre_harvest = std::move(f); }

    // ★ DROPS-R1: the (reward, SUM weight) pair at the cut this win settles.
    using DropsPriceFn = std::function<::c2pool::v37n::settle::WorkPrice()>;
    void set_drops_price_fn(DropsPriceFn f) { m_drops_price = std::move(f); }

    // How many harvest rows the last FOUND folded (diagnostic; 0 when detached).
    std::size_t last_harvest_rows() const { return m_last_harvest_rows; }

    // ★ DROPS diagnostic (never consensus): the delta the finalize driver just
    // composed into this FOUND, re-derived by the SAME pure function it calls,
    // plus the lowest credited interval per payee (the ex-ante witness: it must
    // be >= that payee's effective_from). Only reachable with a harvester
    // attached, i.e. only under the flip.
    void log_drops_found(const FoundBlock& fb, std::uint64_t monero_height) {
        const auto delta = ::c2pool::v37n::settle::subthreshold_credit(fb.params, fb.harvested, fb.drops);
        long long sum = 0;
        std::string rows;
        auto hex_of_key = [](const ::v37::bytes32& b) {
            static constexpr char kHex[] = "0123456789abcdef";
            std::string h;
            for (const auto x : b) { h.push_back(kHex[x >> 4]); h.push_back(kHex[x & 0x0f]); }
            return h;
        };
        for (const auto& [k, v] : delta) {
            sum += v;
            std::uint64_t lo = ~0ull, eff = 0;
            for (const auto& hr : fb.harvested)
                if (hr.payee == k && fb.drops.enrolled(hr.payee, hr.interval) && hr.interval < lo) lo = hr.interval;
            if (m_enroll) if (const auto* r = m_enroll->find(k)) eff = r->effective_from;
            rows += " " + hex_of_key(k).substr(0, 12) + "=" + std::to_string(v) +
                    "(min_iv=" + std::to_string(lo) + ",eff=" + std::to_string(eff) + ")";
        }
        log("drops: FOUND h=" + std::to_string(monero_height) + " bid=" + fb.bid.substr(0, 12) +
            " harvest_rows=" + std::to_string(fb.harvested.size()) +
            " price=" + (fb.drops.price.valid ? "valid" : "INVALID") +
            " delta_payees=" + std::to_string(delta.size()) + " delta_sum=" + std::to_string(sum) + rows);
    }

    // ── accessors (for the smoke / a dashboard) ────────────────────────────
    OwedLedger&        ledger()            { return m_ledger; }
    SettleHW&          hw()                { return m_hw; }
    V37Engine&         engine()            { return m_engine; }
    XmrFinalizeDriver& finalize_driver()   { return *m_finalize; }
    c2pool::xmr::node::MonerodAdapter& adapter() { return *m_adapter; }
    const ::v37::bytes32& seed_digest() const { return m_seed_digest; }
    const std::vector<std::string>& construction_log() const { return m_log; }
    const RecoveredState& recovered() const { return m_recovered; }
    // R-B(i) follow-up: every distinct owed_digest state the replayed store passed
    // through, oldest first (ends at the live digest). Seeds the RECON candidate ring
    // so a RESUMED node matches peer roots against its full canonical history (the
    // fix for a resumed node starting with a 1-entry ring -> first peer block
    // root-unknown forever).
    const std::vector<::v37::bytes32>& boot_digest_history() const { return m_boot_digests; }
    // R-C rework-3 (D7): parallel to boot_digest_history(): the coin height at
    // which each replayed state became current (the RECON root-age bound).
    const std::vector<std::uint64_t>&  boot_digest_since() const { return m_boot_since; }

    // R6 (two-sided chain-ordered booking): re-run the F1 finalize walk against
    // the CURRENT persisted high-water without a new chain event. FinalizeConnect
    // calls this after it has booked a DEFERRED lane block (one that arrived at a
    // height above cursor + 1 + D_conf and was held back until the cursor reached
    // it), so the cursor can step onto the next height in the same tick instead
    // of waiting for the next Extend. Same per-height bin_height, same in-order
    // stepping, same booking gate: advance_to_tip is idempotent at an unchanged
    // high-water (O5.5 admits an equal height; the walk resumes at cursor + 1).
    std::vector<FinalizeStep> readvance_settlement() {
        std::vector<FinalizeStep> steps;
        if (!m_finalize || m_hw.hw_height == 0) return steps;
        steps = m_finalize->advance_to_tip(m_hw.hw_height, m_hw.hw_tip);
        for (const auto& s : steps)
            log("finalize: block " + s.bid.substr(0, 12) + "… (mined h=" +
                std::to_string(s.coin_height) + ") SETTLED at bin_height=" +
                std::to_string(s.bin_height) + " (re-advance after deferred booking)");
        return steps;
    }

private:
    // ── ★ DROPS T3: the buried harvest for a win at Monero height H_b ──────
    // F1: only intervals strictly BELOW the burial frontier may be shown to the
    // estimator, and take_buried() consumes them so the same interval can never
    // be folded into two blocks. The frontier is the same D_conf the finalize
    // driver gates on. Identical to the BTC-family body (btc_node.hpp), because
    // the F1 contract is the same contract.
    std::vector<::c2pool::v37n::settle::HarvestedReceipt> buried_harvest(
        std::uint64_t won_height) {
        if (!m_drops) { m_last_harvest_rows = 0; return {}; }
        const std::uint64_t frontier =
            won_height > m_cfg.d_conf ? won_height - m_cfg.d_conf : 0;
        if (m_pre_harvest) m_pre_harvest(frontier);   // ★ declare S before release
        auto rows = m_drops->take_buried(frontier);
        m_last_harvest_rows = rows.size();
        return rows;
    }

    // Install the ed25519 point-check backend (which is ALSO what makes the P-1
    // XMR descriptor validator live: xmr_ref_valid() fails closed with no
    // backend). Under V37_XMR_HAVE_MONERO_CRYPTO the ref10 registrar TU has
    // already auto-installed at static init; we (a) honour an explicit injection,
    // (b) ASSERT a backend is live, and (c) refuse to run otherwise.
    void install_descriptor_backends() {
        if (m_injected_point_check)
            ::v37::xmr::set_point_check_backend(m_injected_point_check);
        if (::v37::xmr::point_check_backend() == nullptr)
            throw std::runtime_error(
                "XmrNode: no ed25519 point-check backend installed — XMR descriptors "
                "would fail closed. Link v37_descriptor_xmr_point_check_ref10.cpp "
                "(V37_XMR_HAVE_MONERO_CRYPTO) or inject a backend.");
    }

    // Route the X2 mainchain event stream into the F1 finalize driver.
    // F2 node-side gate: never step onto h while a height <= h + D_conf has not
    // been driven through the booking observer yet (scan below it).
    bool gap_gate(std::uint64_t h) {
        if (!m_gap_redrive || m_scan_h == 0) return true;
        if (h + m_cfg.d_conf <= m_scan_h) return true;
        ++m_gap.gate_holds;
        return false;
    }

    // Deliver heights [lo, hi] ascending through the extend + chain observers.
    // Stops at the first header-fetch failure (scan stays below it). Returns the
    // number of heights delivered; m_scan_h advances to the last delivered one.
    std::size_t redrive_range(std::uint64_t lo, std::uint64_t hi) {
        if (lo > hi || !m_adapter) return 0;
        ++m_gap.redrive_calls;
        const std::uint64_t cap = m_cfg.index_retain_recent ? static_cast<std::uint64_t>(m_cfg.index_retain_recent) : 720;
        if (hi - lo + 1 > cap) {
            const std::uint64_t skip = (hi - lo + 1) - cap;
            ++m_gap.truncated; m_gap.truncated_heights += skip;
            log("gap-redrive ALARM: gap [" + std::to_string(lo) + ", " + std::to_string(hi) + "] is " +
                std::to_string(hi - lo + 1) + " heights, wider than the mirror retention " + std::to_string(cap) +
                " -> TRUNCATED: the lowest " + std::to_string(skip) + " height(s) are NOT re-driven (their lane blocks, if any, "
                "stay unbooked: late_unbooked/credit divergence risk; W6 resync territory)");
            lo += skip;
            m_scan_h = lo - 1;
        }
        std::size_t n = 0;
        for (std::uint64_t h = lo; h <= hi; ++h) {
            bool fetch_failed = false;
            auto row = m_adapter->ensure_row(h, fetch_failed);
            if (!row || is_zero_id(row->id)) {
                ++m_gap.fetch_failed;
                log("gap-redrive: header h=" + std::to_string(h) + (fetch_failed ? " fetch FAILED" : " absent") +
                    " -> re-drive stops at " + std::to_string(h - 1) + " (retried next event/tick; the finalize walk holds)");
                break;
            }
            const std::string bid = hex_of(row->id);
            if (m_cba_extend_observer) m_cba_extend_observer(h, bid);
            if (m_chain_observer) m_chain_observer(h, bid);
            m_scan_h = h; ++n; ++m_gap.redriven_heights;
        }
        if (n) log("gap-redrive: re-drove " + std::to_string(n) + " height(s) [" + std::to_string(lo) + ".." +
                   std::to_string(lo + n - 1) + "] through the booking observer");
        return n;
    }

    // D2-0: deliver the heights a Reorg re-applied below its tip. The lowest
    // re-applied height is the lowest height an Orphan event of this switch
    // vacated (disconnect_to raises one Orphan per block it rolls back, before
    // the Reorg); without one, tip - depth. Bounded (a switch deeper than 64
    // is far past the finality boundary; the F2 gap re-drive / W6 own that).
    void redeliver_reorg_interior(const c2pool::xmr::node::MainchainEvent& ev) {
        const std::uint64_t H = ev.block.height;
        std::uint64_t lo = m_reorg_lo ? *m_reorg_lo : (ev.depth && H > ev.depth ? H - ev.depth : H);
        if (lo == 0) lo = 1;
        if (H > lo + 64) lo = H - 64;
        std::size_t n = 0;
        for (std::uint64_t h = lo; h < H; ++h) {
            const auto bid = chain_bid_at(h);
            if (!bid || bid->size() != 64) continue;
            if (m_cba_extend_observer) m_cba_extend_observer(h, *bid);
            if (m_chain_observer) m_chain_observer(h, *bid);
            ++n; ++m_reorg_redelivered;
        }
        if (n) log("reorg-in: delivered " + std::to_string(n) + " re-applied height(s) [" + std::to_string(lo) + ".." +
                   std::to_string(H - 1) + "] below the Reorg tip h=" + std::to_string(H) + " (depth " +
                   std::to_string(ev.depth) + ") to the booking observer BEFORE the tip (D2-0)");
    }

    void on_mainchain_event(const c2pool::xmr::node::MainchainEvent& ev) {
        using K = c2pool::xmr::node::MainchainEventKind;
        // F2: re-drive the interior of a forward gap BEFORE the tip event (so
        // chain order is preserved), and track the scan height. Before the
        // consumer's observer is installed (bring_up's initial_sync) nothing is
        // delivered and the scan does not move: redrive_gap_to_tip() covers it.
        if (m_gap_redrive && m_adapter && m_cba_extend_observer && ev.kind != K::Orphan) {
            const std::uint64_t H = ev.block.height;
            if (m_scan_h != 0 && H > m_scan_h + 1) (void)redrive_range(m_scan_h + 1, H - 1);
        }
        // D2-0: a Reorg event carries only the NEW TIP. The blocks the switch
        // re-applied BELOW it (the chain index drops their per-block Extends,
        // xmr_chain_index.hpp drop_queued_extends_after_) never reached the
        // booking observer: a same-height replace (our own h, then the peer's h
        // and h+1) left the peer's block at h unbooked on this node while every
        // node that followed the peer's branch directly booked it -- the fix2 /
        // base D2 evidence fork (docs/xmr-lane/d2-minority-converge.md §1.3).
        // Deliver the re-applied heights [lowest orphaned height, tip - 1]
        // ascending through the SAME observers, BEFORE the tip. book_chain_block
        // dedups on ledger state and re-books a block that is canonical again.
        if (ev.kind == K::Orphan) {
            if (!m_reorg_lo || ev.block.height < *m_reorg_lo) m_reorg_lo = ev.block.height;
        } else if (ev.kind == K::Reorg && m_cba_extend_observer) {
            redeliver_reorg_interior(ev);
        }
        if (ev.kind != K::Orphan) m_reorg_lo.reset();
        // c2pool#1551: announce the block BEFORE settlement moves on it, so a
        // rival that arrives in the same event is already in the race book when
        // the finalize driver reaches the height.
        if (m_cba_extend_observer && ev.kind != K::Orphan) {
            m_cba_extend_observer(ev.block.height, hex_of(ev.block.id));   //  book BEFORE the race book + BEFORE advance
            // scan moves only across a CONTIGUOUS delivery: a gap whose re-drive
            // stopped on a fetch failure keeps the scan (and so the gate) below it.
            if (m_gap_redrive && (m_scan_h == 0 || ev.block.height <= m_scan_h + 1)) m_scan_h = ev.block.height;
        }
        if (m_chain_observer) {
            if (ev.kind == K::Orphan) m_chain_observer(ev.block.height, hex_of(ev.orphaned_id));
            else                      m_chain_observer(ev.block.height, hex_of(ev.block.id));
        }
        switch (ev.kind) {
            case K::Extend:
            case K::Reorg: {
                if (ev.block.height > m_tip_height) m_tip_height = ev.block.height;
                // Advance settlement finality per the F1 contract off the new
                // best height (the driver steps per-height internally; it NEVER
                // jumps to the tip for bin_height).
                auto steps = m_finalize->advance_to_tip(ev.block.height, bytes32_of(ev.block.id));
                for (const auto& s : steps)
                    log("finalize: block " + s.bid.substr(0, 12) + "… (mined h=" +
                        std::to_string(s.coin_height) + ") SETTLED at bin_height=" +
                        std::to_string(s.bin_height));
                break;
            }
            case K::Orphan:
                // A block left the best chain — dispose per the ledger's O3.5
                // rule (pre-SETTLED removal / post-SETTLED priced residual).
                m_finalize->on_block_orphaned(hex_of(ev.orphaned_id));
                break;
        }
    }

    void log(const std::string& s) { m_log.push_back(s); }

    // ★ DROPS T3 (XMR arm): all four detached by default — see the seams above.
    ::c2pool::v37n::DropHarvester*         m_drops  = nullptr;
    const ::c2pool::v37n::EnrollmentBook*  m_enroll = nullptr;
    PreHarvestFn                           m_pre_harvest{};
    DropsPriceFn                           m_drops_price{};
    std::size_t                            m_last_harvest_rows = 0;

    XmrNodeConfig                          m_cfg;
    c2pool::xmr::node::IMonerodTransport&  m_transport;
    ::v37::xmr::xmr_point_check_fn         m_injected_point_check;

    std::unique_ptr<ISettleStore>          m_store;
    OwedLedger                             m_ledger;
    SettleHW                               m_hw;
    RecoveredState                         m_recovered;
    std::vector<::v37::bytes32>            m_boot_digests;   // R-B(i) follow-up: canonical owed_digest history from boot replay
    std::vector<std::uint64_t>             m_boot_since;     // R-C rework-3 (D7): since-height per boot digest
    std::uint64_t                          m_boot_last_since = 0;

    V37Engine                              m_engine;
    ::v37::bytes32                         m_seed_digest{};

    std::unique_ptr<c2pool::xmr::node::MonerodAdapter> m_adapter;
    std::unique_ptr<XmrFinalizeDriver>                 m_finalize;

    // M3: the p2p-first tip driver. Null adapter + this predicate is the
    // daemonless posture; an adapter and no predicate is the default one.
    ChainPresenceFn                        m_native_presence;
    RowLookupFn                            m_native_row;             // D2-0: best-chain block at h (p2p-first)
    std::optional<std::uint64_t>           m_reorg_lo;               // D2-0: lowest height vacated by this switch's Orphans
    std::uint64_t                          m_reorg_redelivered = 0;  // D2-0: re-applied heights delivered below a Reorg tip
    std::uint64_t                          m_tip_height = 0;

    // c2pool#1551: installed by the accounting layer (FinalizeConnect).
    ChainObserverFn                        m_chain_observer;
    ChainObserverFn                        m_cba_extend_observer;   // 

    // R-C rework-2
    XmrFinalizeDriver::BookingGateFn       m_consumer_gate;          // FinalizeConnect's R4/R6 gate
    bool                                   m_gap_redrive = false;    // F2 re-drive armed (daemon-first)
    std::uint64_t                          m_scan_h = 0;             // F2: highest height delivered to the extend observer (0 = unset)
    GapStats                               m_gap;
    std::uint64_t                          m_carry_unknown = 0;      // tri-state: Unknown answers given

    std::vector<std::string>               m_log;
    bool                                   m_up = false;
};

} // namespace c2pool::v37n::xmr

// Out-of-line definition of the config's path resolver (declared in the config
// header; defined here where <filesystem> + core are already pulled in).
namespace c2pool::v37n::xmr {
inline std::string XmrNodeConfig::resolved_settle_db_path() const {
    return XmrNodeConfig_resolved(*this);
}
} // namespace c2pool::v37n::xmr
