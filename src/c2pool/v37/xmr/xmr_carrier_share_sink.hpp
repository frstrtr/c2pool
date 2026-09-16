// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_carrier_share_sink.hpp   (X2 — the lane share-push)
//
// THE DEFECT THIS CLOSES. The XMR stratum path was a pure pass-through:
//
//   XmrStratumServer -> StratumListener::SinkTap  (fetch_add + a log line)
//                    -> GatedShareSinkT           (the exact 128-bit gate)
//                    -> LiveSubmitShareSink / P2pBlockPublisher
//
// Nothing on that chain ever appended a record to the lane. `AddLane` was the
// only engine write the whole daemon made, so the Monero lane stood at
// raw_total = 0 with an empty identity set for the life of the process. Every
// consequence followed from that one fact: E_b folded to {} at every prefix, no
// payout identity ever existed, and the OWED ledger had nothing to commit to.
//
// WHAT THIS IS. A forwarding strat::IShareSink, inserted OUTSIDE the RandomX
// exact gate (listener -> XmrLaneShareSink -> GatedShareSinkT -> publisher), so
// the network-block decision is byte-identical to before. Every share the X5
// server ACCEPTED — it is already PoW-verified and target-checked at that point
// — is turned into a carrier mint request and handed to the SAME
// CarrierSendQueue the DASH daemon uses, on the SAME O(1) non-blocking seam:
// the listener thread does a queue push and nothing else, and the send worker
// does the parent resolve, the grind, the local admit (which is the lane
// append) and the flood.
//
// WHY THE PARENT IS THE TEMPLATE'S prev_id. A carrier is keyed to a MAINCHAIN
// block — the parent it was worked on — because that is what fixes its bin and
// its consensus leading-zero target (w2_receipt.hpp consensus_lz). The Monero
// template's `prev_id` IS that block, and unlike a Bitcoin header's
// hashPrevBlock it needs NO byte reversal: a Monero block id is already in the
// order every Monero interface speaks. Getting that backwards would make every
// parent unresolvable and every share silently vanish, which is why the
// no-reversal decision is stated here rather than inferred from a memcpy.
//
// IDENTITY, HONESTLY BOUNDED. A carrier's payout identity is a v37
// PayoutDescriptor, and for Monero that is an XMR_STD / XMR_SUB ref over the
// (spend, view) key pair — NOT a base58 address string. There is no base58
// address decoder in this tree (xmr_stratum_messages.hpp says the login address
// is "decoded downstream" and nothing downstream decodes it), so V1 credits
// every share to ONE pool-level identity: the operator's own --payee-spend-hex
// / --payee-view-hex pair, the same keys the FOUND/FINALIZE records are already
// keyed by. That is the DASH "fallback identity" posture, and it is a real
// limitation: per-miner identity needs a base58 decoder and is a follow-on.
// AcceptedShare::address is carried into the tag so the mapping is auditable
// the moment that decoder exists.
//
// SCOPE FENCE: consumer tree, header-only, STL only. Every append rides
// CarrierSendQueue -> CarrierRelay -> CarrierIngest -> V37Engine::submit, which
// is the ONE producer seam; src/sharechain/v37 is untouched.
// ===========================================================================
#pragma once

#include <atomic>
#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include <c2pool/v37/carrier_send.hpp>       // CarrierSendQueue, OwnWinRequest
#include <c2pool/v37/w2_admission.hpp>       // IMainchainIndex
#include <c2pool/v37/w2_receipt.hpp>         // bytes32
#include <sharechain/v37/v37_descriptor.hpp> // ::v37::PayoutDescriptor

#include "impl/xmr/stratum/xmr_stratum.hpp"  // strat::IShareSink, AcceptedShare
#include "impl/xmr/node/xmr_node_types.hpp"  // c2pool::xmr::node::Hash

namespace c2pool::v37n::xmr::o2 {

namespace strat = ::v37::xmr::stratum;

// ── bytes32 <-> Monero Hash, with NO reordering ─────────────────────────────
// Both are std::array<uint8_t,32>. A Monero block id is not byte-reversed for
// display the way a Bitcoin hash is, so the carrier's `prev_block_hash` and the
// id the chain index is keyed by are the SAME 32 bytes in the SAME order.
inline ::c2pool::v37n::bytes32 lane_prev_of_block_id(const ::c2pool::xmr::node::Hash& id) {
    ::c2pool::v37n::bytes32 b{};
    for (std::size_t i = 0; i < 32; ++i) b[i] = id[i];
    return b;
}
inline ::c2pool::xmr::node::Hash block_id_of_lane_prev(const ::c2pool::v37n::bytes32& b) {
    ::c2pool::xmr::node::Hash h{};
    for (std::size_t i = 0; i < 32; ++i) h[i] = b[i];
    return h;
}

// ═══════════════════════════════════════════════════════════════════════════
// XmrCarrierIndex — the v37 IMainchainIndex over the Monero chain THIS node
// follows, whichever arm is driving it.
//
// The send side and the receive side MUST resolve a parent the same way, or a
// carrier one node minted is one its peer cannot place (and vice versa), so
// this is the single implementation both are handed.
//
// The CONTEXT HORIZON is not decoration. Without it an ancient block resolves
// as happily as the tip, and an ancient parent means a small consensus_lz —
// which is to say a carrier that is cheap to grind and would be admitted with
// real weight. `horizon == 0` disables the check and is only for a test whose
// chain is shorter than the window.
// ═══════════════════════════════════════════════════════════════════════════
class XmrCarrierIndex final : public ::c2pool::v37n::IMainchainIndex {
public:
    using HeightOfFn = std::function<std::optional<std::uint64_t>(
        const ::c2pool::xmr::node::Hash&)>;
    using BestHeightFn = std::function<std::uint64_t()>;

    XmrCarrierIndex(HeightOfFn height_of, BestHeightFn best_height,
                    std::uint64_t horizon)
        : m_height_of(std::move(height_of)), m_best(std::move(best_height)),
          m_horizon(horizon) {}

    std::optional<::c2pool::v37n::u64> height_of(
        const ::c2pool::v37n::bytes32& prev_block_hash) const override {
        m_queries.fetch_add(1, std::memory_order_relaxed);
        if (!m_height_of) return std::nullopt;
        const auto h = m_height_of(block_id_of_lane_prev(prev_block_hash));
        if (!h) {
            m_unknown.fetch_add(1, std::memory_order_relaxed);
            return std::nullopt;
        }
        if (m_horizon && m_best) {
            const std::uint64_t best = m_best();
            if (best > m_horizon && *h + m_horizon < best) {
                m_off_horizon.fetch_add(1, std::memory_order_relaxed);
                return std::nullopt;
            }
        }
        m_resolved.fetch_add(1, std::memory_order_relaxed);
        return static_cast<::c2pool::v37n::u64>(*h);
    }

    std::uint64_t queries()     const { return m_queries.load(std::memory_order_relaxed); }
    std::uint64_t resolved()    const { return m_resolved.load(std::memory_order_relaxed); }
    std::uint64_t unknown()     const { return m_unknown.load(std::memory_order_relaxed); }
    std::uint64_t off_horizon() const { return m_off_horizon.load(std::memory_order_relaxed); }
    std::uint64_t horizon()     const { return m_horizon; }

private:
    HeightOfFn   m_height_of;
    BestHeightFn m_best;
    std::uint64_t m_horizon;
    mutable std::atomic<std::uint64_t> m_queries{0}, m_resolved{0}, m_unknown{0},
        m_off_horizon{0};
};

// ── share-push counters (diagnostics only — never consensus) ────────────────
struct XmrLaneShareStats {
    std::uint64_t shares      = 0;   // accepted shares seen on the tap
    std::uint64_t pushed      = 0;   // queued onto the CarrierSendQueue
    std::uint64_t no_template = 0;   // the template the share was solved on is gone
    std::uint64_t no_identity = 0;   // no pool payout descriptor configured
    std::uint64_t shed        = 0;   // the send queue refused (queue full)
    std::uint64_t network_blocks = 0;// shares that ALSO cleared the network target
};

// ═══════════════════════════════════════════════════════════════════════════
// XmrLaneShareSink — the X2 seam.
//
// PLACEMENT MATTERS. This wraps the gate, it does not replace it: the listener
// calls THIS, and this calls the gate. A share that the exact 128-bit network
// rule would later reject is still real WORK and still belongs in the lane; a
// block that the gate refuses to submit must still not be submitted. Putting
// the push inside the gate would have coupled those two decisions for no
// reason.
//
// A NETWORK-BLOCK share is pushed here as an ORDINARY share (won_block=false).
// Its BLOCK-winning carrier — the one that carries the S-1c cut descriptor — is
// minted later, on the main thread, once FinalizeConnect has registered the
// FOUND and the fold has a cut to name. Minting it here would mean naming a
// fold that has not happened yet, and guessing a peer's cut is the one thing
// the cut rule forbids.
// ═══════════════════════════════════════════════════════════════════════════
class XmrLaneShareSink final : public strat::IShareSink {
public:
    // (template_id) -> the template's parent block id. False when that template
    // has already been evicted, in which case the share cannot be keyed to a
    // parent and is counted, never guessed at.
    using PrevOfTemplateFn =
        std::function<bool(std::uint32_t template_id, ::c2pool::xmr::node::Hash& prev_out)>;
    using LogFn = std::function<void(bool warn, const std::string& line)>;

    XmrLaneShareSink(strat::IShareSink& inner, CarrierSendQueue& send,
                     PrevOfTemplateFn prev_of_template,
                     std::optional<::v37::PayoutDescriptor> pool_desc)
        : m_inner(inner), m_send(send), m_prev(std::move(prev_of_template)),
          m_desc(std::move(pool_desc)) {}

    void set_log(LogFn f) { m_log = std::move(f); }

    void on_accepted_share(const strat::AcceptedShare& s) override {
        push(s);
        m_inner.on_accepted_share(s);
    }

    void submit_network_block(std::uint32_t template_id, std::uint32_t nonce,
                              std::uint32_t extra_nonce) override {
        // Untouched: the exact network gate and the publish arm own this path.
        m_inner.submit_network_block(template_id, nonce, extra_nonce);
    }

    XmrLaneShareStats stats() const {
        XmrLaneShareStats o;
        o.shares         = m_shares.load(std::memory_order_relaxed);
        o.pushed         = m_pushed.load(std::memory_order_relaxed);
        o.no_template    = m_no_template.load(std::memory_order_relaxed);
        o.no_identity    = m_no_identity.load(std::memory_order_relaxed);
        o.shed           = m_shed.load(std::memory_order_relaxed);
        o.network_blocks = m_network.load(std::memory_order_relaxed);
        return o;
    }

private:
    void push(const strat::AcceptedShare& s) {
        m_shares.fetch_add(1, std::memory_order_relaxed);
        if (s.is_network_block) m_network.fetch_add(1, std::memory_order_relaxed);

        if (!m_desc) {
            m_no_identity.fetch_add(1, std::memory_order_relaxed);
            say(true, "[v37-xmr-x2] share NOT pushed to the lane: no pool payout identity "
                      "(--payee-spend-hex/--payee-view-hex). The lane accrues no work and "
                      "E_b will fold to {} at every prefix");
            return;
        }
        ::c2pool::xmr::node::Hash prev{};
        if (!m_prev || !m_prev(s.template_id, prev)) {
            m_no_template.fetch_add(1, std::memory_order_relaxed);
            say(true, "[v37-xmr-x2] share NOT pushed: template " +
                          std::to_string(s.template_id) +
                          " is gone, so the share cannot be keyed to a parent block");
            return;
        }

        OwnWinRequest req;
        req.prev_block_internal = lane_prev_of_block_id(prev);
        req.won_block           = false;   // see the class comment
        req.descriptor          = m_desc;  // the XMR identity, honoured ahead of payout_script
        req.tag                 = "share:" + hex16(s.pow_hash);
        if (!m_send.submit(std::move(req))) {
            m_shed.fetch_add(1, std::memory_order_relaxed);
            say(true, "[v37-xmr-x2] share SHED by the carrier send queue (full)");
            return;
        }
        m_pushed.fetch_add(1, std::memory_order_relaxed);
    }

    static std::string hex16(const std::array<std::uint8_t, strat::HASH_SIZE>& h) {
        static const char* k = "0123456789abcdef";
        std::string s;
        for (std::size_t i = 0; i < 8 && i < h.size(); ++i) {
            s.push_back(k[h[i] >> 4]);
            s.push_back(k[h[i] & 0x0f]);
        }
        return s;
    }
    void say(bool warn, const std::string& line) const { if (m_log) m_log(warn, line); }

    strat::IShareSink&                     m_inner;
    CarrierSendQueue&                      m_send;
    PrevOfTemplateFn                       m_prev;
    std::optional<::v37::PayoutDescriptor> m_desc;
    LogFn                                  m_log;
    std::atomic<std::uint64_t> m_shares{0}, m_pushed{0}, m_no_template{0},
        m_no_identity{0}, m_shed{0}, m_network{0};
};

} // namespace c2pool::v37n::xmr::o2
