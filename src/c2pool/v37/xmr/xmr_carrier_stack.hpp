// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_carrier_stack.hpp   (X2 / S-1c — the carrier layer,
//                                             assembled for the Monero family)
//
// The DASH daemon stands this up inline in main_v37_btc_dash.cpp (lines 358-606
// on master): tracker, live index, ingest, peer node, relay, send queue, the
// wire-freeze boot self-check, --p2p-bind and --peer. The Monero daemon needs
// the identical assembly — the layer is coin-agnostic by construction; only the
// INDEX and the IDENTITY differ — so it is factored here rather than copied,
// and the two families cannot drift apart by editing one of them.
//
// WHAT THE LAYER IS FOR, on the XMR side specifically:
//   RECEIVE  a peer's carrier is decoded, gated by the W3-B5 frozen-wire policy,
//            W2-admitted and ACCOUNTED in THIS node's engine — which is how a
//            second node's miners earn weight in our lane at all.
//   SEND     every own accepted share (XmrLaneShareSink) and every own block win
//            (the S-1c descriptor mint) is minted as a frozen CarrierWire frame
//            and flooded, so a peer can account it.
//   CONVERGE a BLOCK-winning carrier rides wire v0x02 with the flat cut
//            descriptor naming the winner's fold. The receive seam hands it to
//            FinalizeConnect::offer_peer_win, which re-runs settle::fold_eb at
//            THAT prefix out of its OWN ring. That, and nothing else, is what
//            makes two nodes' owed_digest converge.
//
// HONEST BOUNDARY (restated, because it is easy to overclaim): the minted
// carrier carries the SYNTHETIC RDWR sha256d envelope ground to
// consensus_lz(parent height), NOT the miner's RandomX share — a peer cannot
// verify the Monero PoW from the frame. What is REAL is the wire (frozen), the
// index (the live Monero chain this node follows), the payout identity (a real
// XMR_STD/XMR_SUB descriptor), the lane weight, and the cross-node flow.
//
// SCOPE FENCE: consumer tree, header-only. Every append rides CarrierRelay ->
// CarrierIngest -> V37Engine::submit; src/sharechain/v37 is untouched.
// ===========================================================================
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <c2pool/v37/carrier_ingest.hpp>     // CarrierIngest, MemShareTracker
#include <c2pool/v37/carrier_net.hpp>        // CarrierPeerNode
#include <c2pool/v37/carrier_send.hpp>       // CarrierSendQueue, OwnWinRequest
#include <c2pool/v37/w3_relay.hpp>           // CarrierRelay, CutDescriptor, cut_bid_*
#include <c2pool/v37/w3_wire_freeze.hpp>     // selfcheck + make_relay_policy

#include "xmr_carrier_share_sink.hpp"        // XmrCarrierIndex, XmrLaneShareSink
#include "xmr_node.hpp"                      // XmrNode
#include "xmr_o2_finalize_connect.hpp"       // FinalizeConnect::offer_peer_win
#include "xmr_s1_fold.hpp"                   // XmrPeerWin

namespace c2pool::v37n::xmr::o2 {

// ── inbound telemetry (never consensus) ─────────────────────────────────────
struct XmrCarrierInboundStats {
    std::atomic<std::uint64_t> frames{0}, admitted{0}, echo{0}, wire_rejected{0},
        policy_rejected{0}, admit_rejected{0};
    std::atomic<std::uint64_t> cut_frames{0};   // admitted carriers carrying a v0x02 cut
    std::atomic<std::uint64_t> cut_offered{0};  // handed to FinalizeConnect
};

// ═══════════════════════════════════════════════════════════════════════════
// XmrCarrierStack — construct AFTER node.bring_up() (the engine is running and
// the lane is seeded, so the AddLane incarnation is readable) and BEFORE the
// stratum listener starts. Destroy BEFORE the node: the send worker and the
// peer reader threads both reach into the engine.
// ═══════════════════════════════════════════════════════════════════════════
class XmrCarrierStack {
public:
    struct Options {
        std::string   p2p_bind;              // "HOST:PORT"; empty = no inbound bind
        std::vector<std::string> peers;      // "HOST:PORT", repeatable
        std::uint64_t index_horizon = 64;    // context horizon below the tip (0 = off)
        std::optional<::v37::PayoutDescriptor> pool_desc;  // the X2 / fallback identity
    };
    using LogFn = std::function<void(bool warn, const std::string& line)>;

    XmrCarrierStack(XmrNode& node, ::v37::ChainId chain, Options opt, LogFn log)
        : m_node(node), m_chain(chain), m_opt(std::move(opt)), m_log(std::move(log)) {}

    ~XmrCarrierStack() { stop(); }
    XmrCarrierStack(const XmrCarrierStack&) = delete;
    XmrCarrierStack& operator=(const XmrCarrierStack&) = delete;

    // Returns "" on success, else the loud reason (the caller must then refuse
    // to run: a node that cannot stand its wire up must not flood frames).
    std::string start(FinalizeConnect& fc) {
        // W3-B5 BOOT SELF-CHECK before any listen/dial. A build whose CarrierWire
        // drifted from the frozen golden must never put frames on a network.
        const wire_freeze::SelfCheck sc = wire_freeze::selfcheck();
        if (!sc.ok())
            return "W3-B5 wire-freeze SELFCHECK FAILED (" + std::to_string(sc.failures) + "/" +
                   std::to_string(sc.checks) + "): this build's CarrierWire drifted from the "
                   "frozen golden; refusing to peer\n" + sc.log;
        say(false, "[v37-xmr-carrier] wire-freeze selfcheck OK [" +
                       std::string(wire_freeze::layout_id()) + " | " +
                       std::string(wire_freeze::layout_id_v2()) + "] " +
                       std::to_string(sc.checks) + " checks; tag cap=" +
                       std::to_string(wire_freeze::kTagMaxBytes));
        say(true, "[v37-xmr-carrier] " + std::string(wire_freeze::flag_day_id()) +
                      " — this build EMITS v0x02 and ACCEPTS {v0x01,v0x02}; a v0x01-only peer "
                      "will REJECT our frames (expected at the flag day)");

        auto snap = m_node.engine().snapshot(m_chain);
        const std::uint64_t incarnation = snap ? snap->incarnation : 1;

        m_tracker = std::make_unique<MemShareTracker>();
        // ONE index, handed to BOTH sides: the send side resolves a share's
        // parent with it and the receive side admits a peer's carrier against
        // it, so origin and peers agree on height, horizon and byte order.
        m_index = std::make_unique<XmrCarrierIndex>(
            [this](const ::c2pool::xmr::node::Hash& id) { return m_node.chain_height_of(id); },
            [this] { return m_node.best_height(); }, m_opt.index_horizon);
        m_ingest = std::make_unique<CarrierIngest>(m_node.engine(), m_chain, *m_index,
                                                   *m_tracker, incarnation);
        m_net   = std::make_unique<CarrierPeerNode>();
        m_relay = std::make_unique<CarrierRelay>(m_ingest->fn(), *m_net);
        m_relay->set_frame_policy(wire_freeze::make_relay_policy(&m_policy_stats));

        CarrierSendQueue::Options so;
        so.fallback_desc = m_opt.pool_desc;   // block-win-without-identity fallback
        m_send = std::make_unique<CarrierSendQueue>(*m_relay, *m_index, m_chain, so);
        m_send->set_log([this](bool warn, const std::string& l) { say(warn, l); });
        m_send->start();

        m_net->set_inbound([this, &fc](const std::vector<std::uint8_t>& f) {
            on_inbound(f, fc);
        });

        if (!m_opt.p2p_bind.empty()) {
            const auto c = m_opt.p2p_bind.rfind(':');
            if (c == std::string::npos) return "bad --p2p-bind " + m_opt.p2p_bind;
            const std::string h = m_opt.p2p_bind.substr(0, c);
            const std::uint16_t p =
                static_cast<std::uint16_t>(std::stoi(m_opt.p2p_bind.substr(c + 1)));
            if (!m_net->listen(h, p))
                return "carrier p2p bind " + m_opt.p2p_bind + " failed";
            say(false, "[v37-xmr-carrier] listening on " + h + ":" +
                           std::to_string(m_net->listen_port()));
        }
        for (const auto& p : m_opt.peers) {
            const auto c = p.rfind(':');
            if (c == std::string::npos) { say(true, "[v37-xmr-carrier] bad --peer " + p); continue; }
            const bool up = m_net->add_peer(p.substr(0, c),
                                            static_cast<std::uint16_t>(std::stoi(p.substr(c + 1))));
            say(!up, "[v37-xmr-carrier] peer " + p + (up ? " connected" : " UNREACHABLE"));
        }
        say(false, "[v37-xmr-carrier] up: peers=" + std::to_string(m_net->n_peers()) +
                       " index_horizon=" + std::to_string(m_opt.index_horizon));
        return "";
    }

    // Teardown order mirrors the DASH daemon: the send worker first (it may be
    // mid-flood), then the sockets, then the relay/ingest that they reach into.
    void stop() {
        if (m_send) m_send->stop();
        if (m_net)  m_net->stop();
        m_send.reset();
        m_relay.reset();
        m_net.reset();
        m_ingest.reset();
        m_index.reset();
        m_tracker.reset();
    }

    // ── ★ S-1c SEND SIDE: name this fold for our peers ──────────────────────
    //
    // Called on the MAIN thread from FinalizeConnect's on-registered-found hook,
    // i.e. AFTER the fold exists. The carrier is keyed to the WON BLOCK'S PARENT
    // (`prev_id`), which is the block the work was done on — the same parent the
    // shares that earned this E_b were keyed to.
    //
    // A fold that REFUSED carries no descriptor: asking peers to fold at a cut
    // that does not exist would be worse than asking them to credit nothing, and
    // crediting nothing is what they will do — which is the SAME number we
    // credited, so the two nodes still converge. That is said out loud rather
    // than left to inference.
    //
    // ★ R-7. `payout_emitted` says whether THIS block's coinbase actually paid
    // owed balances. Under option A it never does (monerod's template pays
    // --payout-address, no v37 identity) and under option B it does whenever the
    // ledger had owed to settle. It used to be hardcoded false, which was a
    // statement about DASH's burial-gated W5 coinbase, not about this one: a
    // peer that reads `false` credits E_b and deducts nothing, while the winner
    // deducted a real payout — the two ledgers then diverge silently, which is
    // the one failure mode S-1c exists to remove. Told the truth, the peer's
    // existing fail-closed rule refuses the block LOUDLY instead (the payout map
    // is not on the frozen v0x02 wire and cannot be reproduced from it). Peer-
    // side reproduction of a K_fair payout is the open `canonical_coinbase_
    // matches` ACCEPT-gate ruling (xmr_o2_settlement_provider.hpp banner), not
    // something this path may invent.
    bool mint_block_winner(const std::string& bid_hex, std::uint64_t h_b,
                           const std::string& prev_id_hex, const XmrEbCut& cut,
                           const ::v37::bytes32& owed_at_win,
                           bool payout_emitted = false) {
        if (!m_send) return false;
        ::c2pool::xmr::node::Hash prev{};
        if (!parse_hex32(prev_id_hex, prev)) {
            say(true, "[v37-xmr-carrier] S-1c: block " + bid_hex + " carries no usable prev_id — "
                      "no block-winner carrier minted, so no peer can credit this block");
            return false;
        }
        OwnWinRequest req;
        req.prev_block_internal = lane_prev_of_block_id(prev);
        req.won_block           = true;
        req.descriptor          = m_opt.pool_desc;
        req.tag                 = "win:" + bid_hex.substr(0, 16);
        if (cut.folded) {
            const auto bid_bytes = cut_bid_bytes(bid_hex);
            if (!bid_bytes) {
                say(true, "[v37-xmr-carrier] S-1c: block id " + bid_hex +
                              " is not 64 hex chars — no cut descriptor carried");
            } else {
                CutDescriptor d;
                d.bid                = *bid_bytes;
                d.h_b                = h_b;
                d.cut_next_pos       = cut.next_pos;
                d.cut_spine_digest   = cut.lane_digest;
                d.reward             = cut.reward;
                d.payout_emitted     = payout_emitted;   // ★ R-7: the truth, not a constant
                d.owed_digest_at_win = owed_at_win;
                req.cut = d;
            }
        } else {
            say(true, "[v37-xmr-carrier] S-1c: no cut descriptor for " + bid_hex +
                          " — our own fold gave no credit, so peers credit nothing either "
                          "(both sides stay at the same owed_digest)");
        }
        return m_send->submit(std::move(req));
    }

    // ── read seams ──────────────────────────────────────────────────────────
    CarrierSendQueue*    send()  { return m_send.get(); }
    XmrCarrierIndex*     index() { return m_index.get(); }
    CarrierPeerNode*     net()   { return m_net.get(); }
    const XmrCarrierInboundStats& inbound() const { return m_in; }
    const wire_freeze::PolicyStats& policy() const { return m_policy_stats; }

private:
    void on_inbound(const std::vector<std::uint8_t>& f, FinalizeConnect& fc) {
        const CarrierRelay::Outcome o = m_relay->handle_inbound(f);
        m_in.frames.fetch_add(1, std::memory_order_relaxed);
        if (o.wire == WireStatus::REJECT_POLICY) {
            m_in.policy_rejected.fetch_add(1, std::memory_order_relaxed);
            say(true, "[v37-xmr-carrier] inbound REJECT_POLICY (tag cap / descriptor validity), " +
                          std::to_string(f.size()) + " B");
            return;
        }
        if (o.wire != WireStatus::OK) {
            m_in.wire_rejected.fetch_add(1, std::memory_order_relaxed);
            say(true, "[v37-xmr-carrier] inbound wire-rejected status=" +
                          std::to_string(static_cast<int>(o.wire)) + ", " +
                          std::to_string(f.size()) + " B");
            return;
        }
        if (!o.admitted) {
            if (o.admission.carrier_status == CarrierStatus::REJECT_DEDUP) {
                // The flood-fill ECHO (W3 §5.2.1): expected once per hop per
                // carrier, never a fault — W2's credit-once window is authority.
                m_in.echo.fetch_add(1, std::memory_order_relaxed);
            } else {
                m_in.admit_rejected.fetch_add(1, std::memory_order_relaxed);
                say(true, "[v37-xmr-carrier] inbound rejected by W2: carrier_status=" +
                              std::to_string(static_cast<int>(o.admission.carrier_status)) +
                              " (1=RMAX 2=PoW/target/chain/unresolvable-parent)");
            }
            return;
        }
        m_in.admitted.fetch_add(1, std::memory_order_relaxed);
        if (!o.admission.pushes.empty()) {
            const auto& p0 = o.admission.pushes.front();
            say(false, "[v37-xmr-carrier] inbound ADMITTED tag=" + p0.tag + " parent@" +
                           std::to_string(p0.carrier_bin) + " w_raw=" + std::to_string(p0.w_raw) +
                           " pushes=" + std::to_string(o.admission.pushes.size()) +
                           " peers_reached=" + std::to_string(o.peers_reached) +
                           (o.cut ? " [S-1c BLOCK-WINNER carrier]" : ""));
        }
        if (!o.cut) return;

        // ── ★ S-1c RECEIVE SEAM ────────────────────────────────────────────
        m_in.cut_frames.fetch_add(1, std::memory_order_relaxed);
        XmrPeerWin w;
        w.bid                = cut_bid_hex(o.cut->bid);
        w.h_b                = o.cut->h_b;
        w.cut_next_pos       = o.cut->cut_next_pos;
        w.cut_spine_digest   = o.cut->cut_spine_digest;
        w.reward             = o.cut->reward;
        w.payout_emitted     = o.cut->payout_emitted;
        w.owed_digest_at_win = o.cut->owed_digest_at_win;
        fc.offer_peer_win(w);      // thread-safe; drained on the main thread
        m_in.cut_offered.fetch_add(1, std::memory_order_relaxed);
    }

    static bool parse_hex32(const std::string& hex, ::c2pool::xmr::node::Hash& out) {
        if (hex.size() != 64) return false;
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        for (std::size_t i = 0; i < 32; ++i) {
            const int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
            if (hi < 0 || lo < 0) return false;
            out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
        }
        return true;
    }
    void say(bool warn, const std::string& line) const { if (m_log) m_log(warn, line); }

    XmrNode&        m_node;
    ::v37::ChainId  m_chain;
    Options         m_opt;
    LogFn           m_log;

    std::unique_ptr<MemShareTracker>  m_tracker;
    std::unique_ptr<XmrCarrierIndex>  m_index;
    std::unique_ptr<CarrierIngest>    m_ingest;
    std::unique_ptr<CarrierPeerNode>  m_net;
    std::unique_ptr<CarrierRelay>     m_relay;
    std::unique_ptr<CarrierSendQueue> m_send;   // declared last: destroyed first
    wire_freeze::PolicyStats          m_policy_stats;
    XmrCarrierInboundStats            m_in;
};

} // namespace c2pool::v37n::xmr::o2
