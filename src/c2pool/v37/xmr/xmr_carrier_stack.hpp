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

#include "xmr_carrier_defer.hpp"             // ★ R-B: park/re-offer + winner re-flood
#include "xmr_carrier_share_sink.hpp"        // XmrCarrierIndex, XmrLaneShareSink
#include "xmr_cut_projector.hpp"             // ★ R-A: project the view at a peer's P
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
    // ★ R-B: a block-winner carrier that W2 would not admit. `cut_deferred` is
    // the ones taken into the park-and-re-offer register (recoverable);
    // `cut_lost` is the ones the register could not take (its cap) — the only
    // shape that is still a silent-ish drop, and it is now COUNTED, which it
    // was not before.
    std::atomic<std::uint64_t> cut_deferred{0};
    std::atomic<std::uint64_t> cut_lost{0};
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
        // ★ R-A: retained push records for the cut projector (0 = the module's
        // own default). Wider = a longer window in which a winner prefix the
        // executor coalesced through can still be projected.
        std::size_t   cut_projector_log = 0;
        // ★ R-B: EXTRA floods of each own block-winner frame (0 = off).
        unsigned      winner_reflood = 2;
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
                       std::string(wire_freeze::layout_id_v2()) + " | " +
                       std::string(wire_freeze::layout_id_v3()) + "] " +
                       std::to_string(sc.checks) + " checks; tag cap=" +
                       std::to_string(wire_freeze::kTagMaxBytes));
        say(true, "[v37-xmr-carrier] " + std::string(wire_freeze::flag_day_id()) +
                      " — a peer that does not speak this build's wire version will REJECT "
                      "our frames outright (expected at the flag day; loud, never a silently "
                      "half-read settlement trailer)");

        m_fc = &fc;
        auto snap = m_node.engine().snapshot(m_chain);
        const std::uint64_t incarnation = snap ? snap->incarnation : 1;

        // ── ★ R-A: stand the cut projector up BEFORE the ingest that feeds it ──
        // Seeded from the engine's OWN v1 snapshot, so the replica's geometry is
        // the geometry the executor committed rather than a second reading of
        // the config. The lane is empty at this point (bring_up asserts
        // version == 1), which is exactly the replica's starting prefix.
        if (snap && snap->next_pos == 0) {
            XmrCutProjector::Options po;
            if (m_opt.cut_projector_log) po.max_log = m_opt.cut_projector_log;
            m_projector = std::make_unique<XmrCutProjector>(m_chain, po);
            m_projector->seed(snap->params, incarnation);
            fc.set_cut_projector(m_projector.get());
            say(false, "[v37-xmr-carrier] S-1c cut projector armed (log<=" +
                           std::to_string(po.max_log) + " records): a winner prefix this "
                           "node's executor COALESCED through is now replayed from the "
                           "record log and folded at a MATCHING lane digest instead of "
                           "refused");
        } else {
            say(true, "[v37-xmr-carrier] S-1c cut projector NOT armed (lane snapshot " +
                          std::string(snap ? "is past its genesis prefix" : "absent") +
                          "): a winner prefix the executor coalesced through will be "
                          "REFUSED exactly as before R-A");
        }

        m_tracker = std::make_unique<MemShareTracker>();
        // ONE index, handed to BOTH sides: the send side resolves a share's
        // parent with it and the receive side admits a peer's carrier against
        // it, so origin and peers agree on height, horizon and byte order.
        m_index = std::make_unique<XmrCarrierIndex>(
            [this](const ::c2pool::xmr::node::Hash& id) { return m_node.chain_height_of(id); },
            [this] { return m_node.best_height(); }, m_opt.index_horizon);
        m_ingest = std::make_unique<CarrierIngest>(m_node.engine(), m_chain, *m_index,
                                                   *m_tracker, incarnation);
        // ★ R-A: the tee. Bound INSIDE CarrierIngest's admit lock, so the
        // projector's record stream is the engine's committed order by
        // construction (carrier_ingest.hpp set_record_tee).
        if (m_projector) {
            XmrCutProjector* p = m_projector.get();
            m_ingest->set_record_tee([p](const ::v37::PayoutDescriptor& d,
                                         ::c2pool::v37n::u64 w, std::uint32_t f) {
                p->note_push(d, w, f);
            });
        }
        m_net   = std::make_unique<CarrierPeerNode>();
        m_relay = std::make_unique<CarrierRelay>(m_ingest->fn(), *m_net);
        m_relay->set_frame_policy(wire_freeze::make_relay_policy(&m_policy_stats));

        CarrierSendQueue::Options so;
        so.fallback_desc = m_opt.pool_desc;   // block-win-without-identity fallback
        // ★ R-B: hold each own block-winner frame for a bounded re-announce.
        if (m_opt.winner_reflood) {
            XmrWinnerReflood::Options ro;
            ro.repeats = m_opt.winner_reflood;
            m_reflood = std::make_unique<XmrWinnerReflood>(ro);
            XmrWinnerReflood* rf = m_reflood.get();
            so.on_winner_frame = [rf](std::vector<std::uint8_t>&& f) {
                rf->hold(std::move(f));
            };
        }
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

    // ── ★ R-B: the deferred-carrier / re-flood tick (MAIN thread) ───────────
    // Drive this once per daemon loop, next to FinalizeConnect::tick(). It is
    // cheap and does nothing at all when both registers are empty, which is the
    // healthy steady state.
    struct PumpReport {
        std::size_t recovered = 0;   // parked block-winner carriers re-admitted
        std::size_t refloods  = 0;   // own winner frames put back on the wire
    };
    PumpReport pump() {
        PumpReport r;
        if (!m_relay || !m_index || !m_fc) return r;
        std::vector<std::string> lines;
        r.recovered = m_defer.pump(
            [this](const bytes32& prev) {
                // The I-2 tri-state gate, asked of the SAME index the admission
                // asks: a value means Have, nullopt means Missing OR Unknown and
                // the frame simply waits for the next tick.
                return m_index->height_of(prev).has_value();
            },
            [this](const std::vector<std::uint8_t>& f) {
                return handle_frame(f, *m_fc, /*from_defer=*/true);
            },
            &lines);
        for (const std::string& l : lines) say(false, l);
        if (m_reflood && m_net) {
            XmrCarrierStack* self = this;
            r.refloods = m_reflood->pump([self](const std::vector<std::uint8_t>& f) {
                return self->m_net->broadcast(f);
            });
            if (r.refloods)
                say(false, "[v37-xmr-carrier] S-1c bounded RE-ANNOUNCE: " +
                               std::to_string(r.refloods) +
                               " own block-winner frame(s) re-flooded (a peer that already "
                               "took one answers DEDUP and credits nothing twice; a peer "
                               "that missed one admits it and can finally credit the block)");
        }
        return r;
    }

    // Teardown order mirrors the DASH daemon: the send worker first (it may be
    // mid-flood), then the sockets, then the relay/ingest that they reach into.
    // The projector goes LAST of all: the ingest tee holds a raw pointer to it
    // and FinalizeConnect borrows one too, so both are unbound first.
    void stop() {
        if (m_send) m_send->stop();
        if (m_net)  m_net->stop();
        m_send.reset();
        m_relay.reset();
        m_net.reset();
        m_ingest.reset();
        m_index.reset();
        m_tracker.reset();
        m_reflood.reset();
        if (m_fc) m_fc->set_cut_projector(nullptr);
        m_projector.reset();
        m_fc = nullptr;
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
    // `payout` is the block's OWN K_fair owed-deduction map — the Owed-role
    // coinbase outputs this block actually paid, exactly as the ledger booked
    // them (FinalizeConnect::PendingRec::payout). It rides the v0x03 trailer so
    // a peer FOLDS it instead of recomputing it; `payout_emitted` stays the
    // truth about whether there was anything to carry.
    bool mint_block_winner(const std::string& bid_hex, std::uint64_t h_b,
                           const std::string& prev_id_hex, const XmrEbCut& cut,
                           const ::v37::bytes32& owed_at_win,
                           bool payout_emitted = false,
                           const settle::OwedLedger::Amounts& payout = {}) {
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
                // ★★ WIRE-CARRY: the v0x03 section 2 map. Built ONLY when the
                // coinbase actually settled, and only from rows the wire can
                // express (strictly positive, inside the reward). A row the wire
                // would refuse is not silently dropped — the whole map is left
                // off and payout_emitted alone tells the peer to fail closed,
                // which is the loud outcome, not the lossy one.
                if (payout_emitted && !payout.empty()) {
                    KfairPayout k;
                    k.pay.reserve(payout.size());
                    bool sane = true;
                    for (const auto& [id, amt] : payout) {
                        if (amt <= 0) { sane = false; break; }
                        k.pay.emplace_back(id, static_cast<std::uint64_t>(amt));
                    }
                    if (sane && CarrierWire::payout_encodable(k, cut.reward)) {
                        req.payout = std::move(k);
                    } else {
                        say(true, "[v37-xmr-carrier] WIRE-CARRY: our own K_fair map for " +
                                  bid_hex + " is not wire-expressible (" +
                                  std::to_string(payout.size()) + " row(s) against reward " +
                                  std::to_string(cut.reward) + ") — the block-winner carrier "
                                  "goes out WITHOUT section 2, so every peer fail-closes on it "
                                  "instead of folding a map we could not state exactly");
                    }
                }
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
    XmrCutProjector*       projector()      { return m_projector.get(); }
    const XmrCutProjector* projector() const { return m_projector.get(); }
    XmrDeferStats          deferred()  const { return m_defer.stats(); }
    XmrRefloodStats        reflood()   const {
        return m_reflood ? m_reflood->stats() : XmrRefloodStats{};
    }

private:
    void on_inbound(const std::vector<std::uint8_t>& f, FinalizeConnect& fc) {
        (void)handle_frame(f, fc, /*from_defer=*/false);
    }

    // Returns true iff W2 ADMITTED the carrier this time round. `from_defer`
    // says the frame is already in the park register, so a repeat failure must
    // NOT re-park it (the register owns its own attempt accounting).
    bool handle_frame(const std::vector<std::uint8_t>& f, FinalizeConnect& fc,
                      bool from_defer) {
        const CarrierRelay::Outcome o = m_relay->handle_inbound(f);
        if (!from_defer) m_in.frames.fetch_add(1, std::memory_order_relaxed);
        if (o.wire == WireStatus::REJECT_POLICY) {
            m_in.policy_rejected.fetch_add(1, std::memory_order_relaxed);
            say(true, "[v37-xmr-carrier] inbound REJECT_POLICY (tag cap / descriptor validity), " +
                          std::to_string(f.size()) + " B");
            return false;
        }
        if (o.wire != WireStatus::OK) {
            m_in.wire_rejected.fetch_add(1, std::memory_order_relaxed);
            say(true, "[v37-xmr-carrier] inbound wire-rejected status=" +
                          std::to_string(static_cast<int>(o.wire)) + ", " +
                          std::to_string(f.size()) + " B");
            return false;
        }
        if (!o.admitted) {
            if (o.admission.carrier_status == CarrierStatus::REJECT_DEDUP) {
                // The flood-fill ECHO (W3 §5.2.1): expected once per hop per
                // carrier, never a fault — W2's credit-once window is authority.
                // It is ALSO what a bounded R-B re-announce looks like on a peer
                // that already took the block: no lane weight, no second credit.
                m_in.echo.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
            m_in.admit_rejected.fetch_add(1, std::memory_order_relaxed);
            // ── ★ R-B: DO NOT DROP A BLOCK-WINNER DESCRIPTOR ────────────────
            // carrier_status 2 covers "unresolvable parent" as well as a real
            // PoW/target/chain failure, and the unresolvable case is MOMENTARY:
            // the parent is a block already on the winner's chain, so this node
            // places it a poll later. Dropping the frame here cost node B block
            // h=86 permanently on the 2-node regtest (A emitted 45 winner
            // carriers, B offered 44) and no path re-offered it. Park it, keyed
            // by (h_b, bid), and let pump() re-ask the I-2 tri-state gate.
            const bool momentary = (o.admission.carrier_status == CarrierStatus::REJECT_POW);
            if (o.cut && momentary && !from_defer) {
                bytes32 prev{};
                const std::string bid = cut_bid_hex(o.cut->bid);
                if (carrier_prev_of(f, prev) &&
                    m_defer.park(o.cut->h_b, bid, prev, f)) {
                    m_in.cut_deferred.fetch_add(1, std::memory_order_relaxed);
                    say(true, "[v37-xmr-carrier] inbound BLOCK-WINNER carrier for " +
                                  bid.substr(0, 12) + "\xe2\x80\xa6 h=" +
                                  std::to_string(o.cut->h_b) +
                                  " rejected by W2 (carrier_status=2: its parent is not in "
                                  "THIS node's index yet) — PARKED and re-offered every tick "
                                  "until the parent resolves, instead of dropped");
                    return false;
                }
                m_in.cut_lost.fetch_add(1, std::memory_order_relaxed);
                say(true, "[v37-xmr-carrier] inbound BLOCK-WINNER carrier for " +
                              bid.substr(0, 12) + "\xe2\x80\xa6 h=" +
                              std::to_string(o.cut->h_b) +
                              " rejected by W2 and could NOT be parked (register full, or the "
                              "frame would not re-decode) — this node will not credit that "
                              "block and its owed_digest will not converge for it");
                return false;
            }
            if (!from_defer)
                say(true, "[v37-xmr-carrier] inbound rejected by W2: carrier_status=" +
                              std::to_string(static_cast<int>(o.admission.carrier_status)) +
                              " (1=RMAX 2=PoW/target/chain/unresolvable-parent)" +
                              (o.cut ? " [block-winner carrier]" : ""));
            return false;
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
        if (!o.cut) return true;

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
        // ★★ WIRE-CARRY: hand the winner's K_fair deduction map straight through.
        // The codec has already enforced its shape (bounded, strictly ascending,
        // every amount positive, Sum inside this frame's own reward), so what
        // arrives here is foldable or the frame never decoded at all.
        if (o.payout) {
            w.payout_carried = true;
            for (const auto& [id, amt] : o.payout->pay)
                w.payout[id] = static_cast<long long>(amt);
        }
        // c2pool#1627's section 1 rides the same frame. This build has no DROPS
        // ledger leg, so a credit map it cannot apply must NOT be silently
        // dropped: the peer path refuses the block outright (see
        // xmr_o2_finalize_connect.hpp drain_peer_wins), and the flag is carried
        // here so that refusal can name the reason.
        w.drops_carried = o.drops.has_value();
        fc.offer_peer_win(w);      // thread-safe; drained on the main thread
        m_in.cut_offered.fetch_add(1, std::memory_order_relaxed);
        // ★ R-B: whatever route brought this descriptor in, the block is now
        // offered — so any parked copy of it has done its job.
        m_defer.retire(w.h_b, w.bid);
        return true;
    }

    // ★ R-B: the carrier's own prev_block_hash, taken by re-decoding the frame.
    // The relay decodes it once already but does not surface it, and the retry
    // gate must re-ask the index the IDENTICAL question the admission asked — so
    // the value is read back out of the frame rather than reconstructed. Only
    // ever run on a REJECTED block-winner frame, which is rare by construction.
    static bool carrier_prev_of(const std::vector<std::uint8_t>& f, bytes32& out) {
        const DecodeResult dr = CarrierWire::decode(f);
        if (!dr.ok()) return false;
        out = dr.carrier.carrier.prev_block_hash;
        return true;
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
    FinalizeConnect* m_fc = nullptr;   // borrowed, bound in start(), cleared in stop()

    // ★ R-A: declared FIRST so it is destroyed LAST — the ingest tee and
    // FinalizeConnect both borrow a raw pointer to it.
    std::unique_ptr<XmrCutProjector>  m_projector;
    // ★ R-B: the two bounded registers.
    XmrDeferredCarriers               m_defer;
    std::unique_ptr<XmrWinnerReflood> m_reflood;

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
