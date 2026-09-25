// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_drops_wiring.hpp — DROPS on the XMR lane: the live
// shell wiring (the XMR twin of main_v37_btc_dash.cpp's Step-2 block).
//
// WHAT WAS MISSING. XmrNode carries the four DROPS T3 seams (set_drop_harvester,
// set_enrollment_book, set_pre_harvest, set_drops_price_fn) and the finalize
// driver composes compose_credit_replace() at every FOUND, but main_v37_xmr.cpp
// never built a DropsWiring and never called a seam. After the operator flip
// every XMR node would be gate-ON and DORMANT: it converges and credits nobody.
// This header is what the shell holds instead; the shell makes the calls.
//
// FOUR XMR FACTS THE BTC WIRING DOES NOT HAVE TO FACE, AND HOW EACH IS MET:
//
// (1) THE CLOCK. An XMR work event's origin bin is its TEMPLATE height — the
//     height of the block it would become (relay Admitted::bin, the stratum
//     AcceptedShare::height) — which is the native tip + 1. The bin a payee is
//     drawing in RIGHT NOW is therefore tip + 1, so the ex-ante clock fed to the
//     TipBin is open_bin_of_tip(tip) = tip + 1, and an enrolment made now takes
//     effect at tip + 2: strictly after every draw the payee can have seen.
//     Under --arm-order p2p-first the tip is the NATIVE node's verified levin
//     tip (the shell's pump_tip height watch). It is never the burial frontier
//     (that enters only through pre_harvest -> declare_at_frontier) and never a
//     monerod poll.
//
// (2) THE TARGET GEOMETRY. The estimator is written for leading-zero-bit
//     targets (h_T = 2^(256-lz) - 1, T = 2^lz); a Monero share is a DIFFICULTY
//     test, H_le * share_diff < 2^256. normalized_hash() maps the RandomX hash
//     onto the fixed geometry lz = kXmrDropsLz EXACTLY:
//         N = floor(H_le * share_diff / 2^lz)      N < 2^(256-lz)  <=>  share
//     so a share is a hash at or below h_T, a raindrop is a hash above it, and
//     the estimator's work unit is 2^lz normalised attempts = ONE share.
//
// (3) THE DENOMINATION (DROPS-R1). A share enters the XMR lane as ONE push of
//     w_raw = receipt_weight (relay::kReceiptWeight = 1, or fee::kFeeReceipt
//     Weight with the fee model ON), not as 2^lz. The seam prices work as
//     floor(reward * (work << Q) / SUM weight), so the WorkPrice handed to the
//     node carries SUM weight re-expressed in the estimator's unit:
//         sum' = floor((SUM weight << lz) / receipt_weight)
//     so ONE share of estimated work prices exactly like ONE real share at the
//     cut. Same cut, same project(), one integer rescale, no new constant.
//
// (4) REPLICATION. The XMR arm composes on EVERY node for EVERY lane block
//     (FinalizeConnect -> XmrNode::on_network_block_won), from the node's OWN
//     harvest. A raindrop only one node saw would move only that node's
//     owed_digest. So raindrops travel the receipt relay exactly like shares
//     (RandomX-verified by every receiver, flooded, deduped), and every node's
//     harvester sees the same set; see XmrRelayNode::submit_own_drop.
//
// GATE OFF (the shipped default): make() returns nullptr, the shell constructs
// nothing, attaches nothing, and every path below is unreachable.
// ===========================================================================
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include <c2pool/v37/v37_drops_wiring.hpp>   // DropsWiring, TipBin, EnrollOutcome, kDropsWiringArmed
#include <c2pool/v37/w4_settlement.hpp>      // settle::WorkPrice, work_price_at

namespace c2pool::v37n::xmr::drops {

using ::v37::bytes32;

// The fixed leading-zero geometry every XMR raindrop and share-count row is
// expressed in. 32 bits of head-room keeps the normalisation exact for every
// share_diff < 2^32 (a product never saturates) and the estimator's h_T far
// from both ends of the u256 range.
inline constexpr unsigned kXmrDropsLz = 32;

// A raindrop must still be real work: at least share_diff / kDropsFloorDiv
// (and at least difficulty 1). The receiver RandomX-verifies it against this
// floor exactly as it verifies a share against share_diff, so a peer cannot
// flood the harvest with free hashes. A function of share_diff alone, and
// share_diff is HELLO-checked, so every node applies the same floor.
inline constexpr std::uint64_t kDropsFloorDiv = 64;
inline std::uint64_t drops_floor_diff(std::uint64_t share_diff) {
    const std::uint64_t f = share_diff / kDropsFloorDiv;
    return f ? f : 1;
}

// (1) the ex-ante clock: the bin a payee is drawing in at native tip `tip`.
inline std::uint64_t open_bin_of_tip(std::uint64_t tip_height) { return tip_height + 1; }

// (2) N = floor(H_le * share_diff / 2^kXmrDropsLz), saturated, as a big-endian
// bytes32 (the W2 / estimator convention: byte 0 most significant).
inline bytes32 normalized_hash(const bytes32& pow_le, std::uint64_t share_diff) {
    std::array<std::uint64_t, 5> p{0, 0, 0, 0, 0};
    unsigned __int128 carry = 0;
    for (int w = 0; w < 4; ++w) {
        std::uint64_t word = 0;
        for (int i = 0; i < 8; ++i)
            word |= static_cast<std::uint64_t>(pow_le[static_cast<std::size_t>(w * 8 + i)]) << (8 * i);
        const unsigned __int128 prod = static_cast<unsigned __int128>(word) * share_diff + carry;
        p[static_cast<std::size_t>(w)] = static_cast<std::uint64_t>(prod);
        carry = prod >> 64;
    }
    p[4] = static_cast<std::uint64_t>(carry);
    static_assert(kXmrDropsLz > 0 && kXmrDropsLz < 64, "single-limb shift");
    std::array<std::uint64_t, 4> n{};
    for (int i = 0; i < 4; ++i)
        n[static_cast<std::size_t>(i)] = (p[static_cast<std::size_t>(i)] >> kXmrDropsLz) |
                                         (p[static_cast<std::size_t>(i + 1)] << (64 - kXmrDropsLz));
    if (p[4] >> kXmrDropsLz) n = {~0ull, ~0ull, ~0ull, ~0ull};   // saturate (far above h_T)
    bytes32 out{};
    for (int i = 0; i < 4; ++i)                                     // limb 3 = most significant
        for (int b = 0; b < 8; ++b)
            out[static_cast<std::size_t>((3 - i) * 8 + (7 - b))] =
                static_cast<std::uint8_t>(n[static_cast<std::size_t>(i)] >> (8 * b));
    return out;
}

// (3) the WorkPrice at a cut, re-expressed in the estimator's unit.
inline ::c2pool::v37n::settle::WorkPrice rescale_price(::c2pool::v37n::settle::WorkPrice wp,
                                                       std::uint64_t receipt_weight) {
    if (!wp.valid || receipt_weight == 0) { wp.valid = false; return wp; }
    // (sum << lz): a 5-limb value; then floor-divide by receipt_weight.
    std::array<std::uint64_t, 5> s{0, 0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        s[static_cast<std::size_t>(i)] |= wp.sum_weight.v[static_cast<std::size_t>(i)] << kXmrDropsLz;
        s[static_cast<std::size_t>(i + 1)] |= wp.sum_weight.v[static_cast<std::size_t>(i)] >> (64 - kXmrDropsLz);
    }
    unsigned __int128 rem = 0;
    std::array<std::uint64_t, 5> q{0, 0, 0, 0, 0};
    for (int i = 4; i >= 0; --i) {
        const unsigned __int128 cur = (rem << 64) | s[static_cast<std::size_t>(i)];
        q[static_cast<std::size_t>(i)] = static_cast<std::uint64_t>(cur / receipt_weight);
        rem = cur % receipt_weight;
    }
    if (q[4]) { wp.valid = false; return wp; }   // beyond U256: no conversion expressible (fail closed)
    for (int i = 0; i < 4; ++i) wp.sum_weight.v[static_cast<std::size_t>(i)] = q[static_cast<std::size_t>(i)];
    wp.valid = !wp.sum_weight.is_zero();
    return wp;
}

// The price at the SAME cut, through the SAME view, the fold reads.
template <class View>
inline ::c2pool::v37n::settle::WorkPrice drops_price_at(std::uint64_t reward, const View& v,
                                                        std::uint64_t receipt_weight) {
    return rescale_price(::c2pool::v37n::settle::work_price_at(reward, v), receipt_weight);
}

// ── THE XMR BUNDLE: one per lane, owned by the shell ────────────────────────
class XmrDropsWiring {
public:
    // ★ THE DORMANCY GATE. nullptr unless the build took the consensus
    // activation AND the lane geometry carries the gate AND there is a share
    // difficulty to normalise against — the XMR twin of make_drops_wiring().
    static std::unique_ptr<XmrDropsWiring> make(const ::v37::LaneParams& p,
                                                std::uint64_t share_diff,
                                                std::uint64_t receipt_weight) {
        if constexpr (!::c2pool::v37n::kDropsWiringArmed) {
            (void)p; (void)share_diff; (void)receipt_weight;
            return nullptr;
        } else {
            if (!p.subthreshold.enabled || share_diff == 0 || receipt_weight == 0) return nullptr;
            return std::unique_ptr<XmrDropsWiring>(
                new XmrDropsWiring(p.subthreshold.K, share_diff, receipt_weight));
        }
    }
    // The same construction without the build gate, for a KAT that must drive
    // the gate-ON object inside a default (flip 0) build.
    static std::unique_ptr<XmrDropsWiring> make_for_test(std::uint32_t K, std::uint64_t share_diff,
                                                         std::uint64_t receipt_weight) {
        return std::unique_ptr<XmrDropsWiring>(new XmrDropsWiring(K, share_diff, receipt_weight));
    }

    XmrDropsWiring(const XmrDropsWiring&) = delete;
    XmrDropsWiring& operator=(const XmrDropsWiring&) = delete;

    std::uint64_t share_diff() const { return m_share_diff; }
    std::uint64_t floor_diff() const { return drops_floor_diff(m_share_diff); }
    std::uint64_t receipt_weight() const { return m_receipt_weight; }

    // ── (1) the clock: fed ONLY from the native tip ─────────────────────────
    void observe_native_tip(std::uint64_t tip_height) { m_core.observe_tip(open_bin_of_tip(tip_height)); }
    std::optional<std::uint64_t> now_interval() const { return m_core.now_interval(); }
    ::c2pool::v37n::EnrollOutcome enroll_at_tip(const bytes32& payee) { return m_core.enroll_at_tip(payee); }
    bool arm_at_tip() { return m_core.arm_at_tip(); }

    // ── the node seams ─────────────────────────────────────────────────────
    template <class Node>
    void attach(Node& node) {
        node.set_drop_harvester(&m_core.harvester());
        node.set_enrollment_book(&m_core.enrollment());
        node.set_pre_harvest(m_core.pre_harvest());
        node.set_drops_price_fn([this]() { return take_cut_price(); });
    }
    template <class Node>
    static void detach(Node& node) {
        node.set_drop_harvester(nullptr);
        node.set_enrollment_book(nullptr);
        node.set_pre_harvest({});
        node.set_drops_price_fn({});
    }

    // ── the price at the cut the NEXT on_network_block_won settles ──────────
    // Set by the shell's booking callback from the view it folded E_b from;
    // taken (one-shot) by the node inside on_network_block_won, so a win that
    // was not booked through a fold can never reuse a neighbour's price.
    void set_cut_price(const ::c2pool::v37n::settle::WorkPrice& wp) {
        std::lock_guard<std::mutex> lk(m_pmtx);
        m_price = rescale_price(wp, m_receipt_weight);
    }
    void clear_cut_price() {
        std::lock_guard<std::mutex> lk(m_pmtx);
        m_price = {};
    }
    ::c2pool::v37n::settle::WorkPrice take_cut_price() {
        std::lock_guard<std::mutex> lk(m_pmtx);
        auto p = m_price;
        m_price = {};
        if (p.valid) ++m_priced; else ++m_unpriced;
        return p;
    }

    // ── the two producers ──────────────────────────────────────────────────
    // A relay-admitted RAINDROP (own or peer): a RandomX hash that met the
    // floor but not share_diff. Returns false (and harvests nothing) for a hash
    // that is actually a share or is below the floor: never both, never twice.
    bool on_raindrop(const bytes32& payee_identity, std::uint64_t bin, const bytes32& pow_le) {
        const bytes32 n = normalized_hash(pow_le, m_share_diff);
        const unsigned lz = ::c2pool::v37n::leading_zero_bits(n);
        if (lz >= kXmrDropsLz) { ++m_refused_share; return false; }   // a SHARE: the lane path owns it
        ::c2pool::v37n::HarvestedDrop d;
        d.payee = payee_identity;
        d.interval = bin;
        d.hash = n;
        d.consensus_lz = kXmrDropsLz;
        d.own_lz = lz;
        m_drop_sink(d);
        return true;
    }
    // A relay receipt the lane just pushed: ONE share at (identity, origin bin).
    void on_share_pushed(const bytes32& payee_identity, std::uint64_t bin) {
        ::c2pool::v37n::EmittedPush p;
        p.identity = payee_identity;
        p.origin_bin = bin;
        p.carrier_bin = bin;
        p.w_raw = m_receipt_weight;
        m_share_tee(p);
    }

    // ── diagnostics (never consensus) ──────────────────────────────────────
    ::c2pool::v37n::DropsWiring& core() { return m_core; }
    const ::c2pool::v37n::DropsWiring& core() const { return m_core; }
    std::uint64_t priced() const { return m_priced; }
    std::uint64_t unpriced() const { return m_unpriced; }
    std::uint64_t refused_share() const { return m_refused_share; }

private:
    XmrDropsWiring(std::uint32_t K, std::uint64_t share_diff, std::uint64_t receipt_weight)
        : m_core(K, [](std::uint64_t) { return kXmrDropsLz; }),
          m_share_diff(share_diff), m_receipt_weight(receipt_weight) {
        m_drop_sink = m_core.drop_sink();
        m_share_tee = m_core.sink_filter()(::c2pool::v37n::RecordSink{});
    }

    ::c2pool::v37n::DropsWiring m_core;
    std::uint64_t m_share_diff = 0;
    std::uint64_t m_receipt_weight = 0;
    ::c2pool::v37n::DropSink   m_drop_sink;
    ::c2pool::v37n::RecordSink m_share_tee;
    mutable std::mutex m_pmtx;
    ::c2pool::v37n::settle::WorkPrice m_price{};
    std::uint64_t m_priced = 0, m_unpriced = 0, m_refused_share = 0;
};

}  // namespace c2pool::v37n::xmr::drops
