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
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <core/filesystem.hpp>                       // core::filesystem::config_path
#include <c2pool/v37/v37_engine.hpp>                 // V37Engine (merged)
#include <c2pool/v37/w4_settlement.hpp>              // OwedLedger, SettleHW (merged)
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
            m_recovered = rec.recover(m_ledger, ok);
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

        // 5) bind the X2 adapter and route its event stream into the F1 driver.
        m_adapter = std::make_unique<c2pool::xmr::node::MonerodAdapter>(
            m_transport, m_cfg.monerod,
            static_cast<std::uint64_t>(m_cfg.index_retain_recent));

        m_finalize = std::make_unique<XmrFinalizeDriver>(
            m_ledger, m_hw, *m_store, m_cfg.lane_chain, m_cfg.d_conf,
            m_recovered.finalize_cursor_height, m_recovered.max_event_seq,
            [this](std::uint64_t h, const std::string& bid) {
                auto b = m_adapter->index().by_height(h);
                return b && hex_of(b->id) == bid;
            });

        m_adapter->set_event_sink(
            [this](const c2pool::xmr::node::MainchainEvent& ev) { on_mainchain_event(ev); });

        // 6) start the adapter: subscribe ZMQ topics + one-shot RPC sync.
        m_adapter->start();
        m_adapter->initial_sync();
        log("adapter: started; subscribed miner_data/chain_main/txpool; initial_sync issued");

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
        m_finalize->on_block_found(fb);
        log("win: FOUND block " + fb.bid.substr(0, 12) + "… at height " +
            std::to_string(monero_height) + " registered (awaiting D_conf=" +
            std::to_string(m_cfg.d_conf) + ")");
        return true;
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

private:
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
    void on_mainchain_event(const c2pool::xmr::node::MainchainEvent& ev) {
        using K = c2pool::xmr::node::MainchainEventKind;
        switch (ev.kind) {
            case K::Extend:
            case K::Reorg: {
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

    XmrNodeConfig                          m_cfg;
    c2pool::xmr::node::IMonerodTransport&  m_transport;
    ::v37::xmr::xmr_point_check_fn         m_injected_point_check;

    std::unique_ptr<ISettleStore>          m_store;
    OwedLedger                             m_ledger;
    SettleHW                               m_hw;
    RecoveredState                         m_recovered;

    V37Engine                              m_engine;
    ::v37::bytes32                         m_seed_digest{};

    std::unique_ptr<c2pool::xmr::node::MonerodAdapter> m_adapter;
    std::unique_ptr<XmrFinalizeDriver>                 m_finalize;

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
