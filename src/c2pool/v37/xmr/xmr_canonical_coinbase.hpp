// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_canonical_coinbase.hpp
//                       (CANON -- the canonical-coinbase rule, LaneParams::canon)
//
// In classic p2pool a share that can also be a block candidate hashes a header
// whose coinbase ALREADY pays every miner by the PPLNS rule; a node that changes
// the payout changes the header, so the work is on a different block. The v37
// XMR lane books whatever the winner's on-chain coinbase paid (coinbase
// authority), so a builder that re-ordered or skipped payees kept its work
// credited. This header closes that: the coinbase of a lane block is a
// DETERMINISTIC function of replicated lane state, and a verifier can recompute
// it from the receipt it is handed.
//
//   canonical coinbase = X6(  owed ledger at the builder's cursor (finalized
//                             partition + the pending payouts of lane blocks
//                             the builder had booked),
//                             the committed credit cut (V37C) and the view at it,
//                             the declared total reward (V37R),
//                             the parent (major version, height, prev_id),
//                             the lane-constant output cap kCanonOutputCap,
//                             the protocol donation output (fee model v1),
//                             the receipt's own 0x02 payload  )
//
// The receipt already carries what a verifier compares: the Keccak midstate over
// the coinbase prefix (outputs included), the prefix tail and the tx_extra in the
// clear. Recompute the prefix, cut the opening from it, compare. No extra
// traffic. A block's bytes compare directly (verify_block).
//
// Three outcomes, never conflated:
//   Match        the coinbase is the canonical one.
//   Mismatch     the verifier holds the builder's state and the coinbase differs
//                (a payee omitted / reordered / re-weighted, a wrong tail field).
//   Undecidable  the verifier cannot reproduce the builder's state: its ledger
//                committed another digest, the view at the cut is not readable,
//                a payee ref is not learned yet, another pool lineage. Never a
//                verdict against the builder; a caller holds it for a bounded
//                time (stage 2) and counts it.
//
// Pure: no I/O, no clock, no node state. The caller hands the ledger (already
// rolled to the builder's pending set: ledger_before) and a pay_of resolver.
// ===========================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "xmr_canon_params.hpp"
#include "xmr_canon_verdict.hpp"
#include "xmr_credit_cut.hpp"
#include "xmr_paynow.hpp"
#include "xmr_o2_settlement_fixture.hpp"   // XmrSettlementConfig, XmrParentContext, build_settlement_source
#include "impl/xmr/receipt/xmr_receipt.hpp"          // CoinbaseOpening
#include "impl/xmr/receipt/xmr_receipt_verify.hpp"   // build_coinbase_opening, parse_tx_extra

namespace c2pool::v37n::xmr::canon {

namespace o2 = ::c2pool::v37n::xmr::o2;
namespace x6 = ::v37::xmr::settle;

// What a verifier learns about the block a receipt (or a chain blob) commits.
struct BlockFacts {
    std::uint8_t         major = 0;       // hashing blob / block header major version
    std::uint64_t        height = 0;      // coinbase txin_gen height (= origin bin + 1 for a receipt)
    ::xmr::coin::Hash256 prev_id{};       // parent block id
    std::vector<unsigned char> tx_extra;  // the coinbase tx_extra, in the clear
};

// The recomputed coinbase plus the verdict that could already be reached while
// computing it (Undecidable / Mismatch before any byte comparison).
struct Expected {
    Result                pre;           // v == Match means "recompute succeeded, compare bytes"
    x6::BuiltCoinbase     cb;            // canonical prefix / tx_extra / outputs
    std::vector<std::uint8_t> payload;   // the 0x02 payload the recompute was fed
    std::size_t           carried_unpayable = 0;
    bool ready() const { return pre.v == Verdict::Match; }
};

// The ledger as the BUILDER saw it: the verifier's ledger with every lane block
// the verifier booked at height >= `height` removed again (a pre-SETTLED orphan is
// a pure removal of a pending entry). The finalized partition is untouched, so a
// verifier that has finalized past the builder's cursor commits another
// owed_digest and the recompute reports Undecidable (mm root differs).
inline o2::OwedLedger ledger_before(const o2::OwedLedger& live,
                                    const std::vector<std::pair<std::string, o2::OwedLedger::Amounts>>& pending_from) {
    o2::OwedLedger l = live;
    for (const auto& [bid, payout] : pending_from)
        if (l.is_pending(bid)) l.on_block_orphaned(bid, payout);
    return l;
}

// Recompute the canonical coinbase for `f`. `cfg` is this node's settlement
// config (residual sink / donation, h_min, pool_tag, paynow_source ...); `ledger`
// the builder-side ledger (ledger_before); `pay_of` the ref resolver.
inline Expected expected_coinbase(const o2::XmrSettlementConfig& cfg, const o2::OwedLedger& ledger,
                                  const o2::PayOfFn& pay_of, const BlockFacts& f) {
    Expected e;
    auto undec = [&](std::string w) { e.pre = {Verdict::Undecidable, std::move(w)}; return e; };
    auto mism  = [&](std::string w) { e.pre = {Verdict::Mismatch, std::move(w)}; return e; };

    const auto nf = credit::extra_nonce_field(f.tx_extra);
    if (!nf) return mism("coinbase tx_extra has no 0x02 field");
    e.payload = *nf;
    const std::vector<std::uint8_t>& p = e.payload;

    const auto total = paynow::parse_reward_payload(p);
    if (!total || *total == 0) return mism("no V37R: the coinbase does not declare its total reward (not a canonical build)");

    // Another pool's lineage is not ours to judge.
    ::v37::bytes32 tag{};
    const auto tp = credit::parse_pool_tag_payload(p, &tag);
    if (tp == credit::PoolTagParse::Malformed) return undec("malformed V37P field");
    if (cfg.pool_tag) {
        if (tp != credit::PoolTagParse::Present || tag != *cfg.pool_tag)
            return undec("coinbase is not of this pool's lineage");
    } else if (tp == credit::PoolTagParse::Present) {
        return undec("coinbase carries a pool tag this node does not commit");
    }

    // The builder's state must be ours, else there is nothing to compare.
    ::v37::xmr::verify::ParsedTxExtra px;
    if (!::v37::xmr::verify::parse_tx_extra(f.tx_extra, px) || !px.has_mm || !px.has_pubkey)
        return mism("tx_extra is not a v37 lane coinbase (needs 0x01 + 0x02 + 0x03)");
    {
        const ::xmr::coin::Hash256 want = x6::mm_commitment_root(cfg.chain_id, ledger.owed_digest());
        ::v37::bytes32 w{}; std::memcpy(w.data(), want.data(), 32);
        if (w != px.mm_root)
            return undec("the coinbase commits another owed_digest than this ledger's state at that height");
    }

    // Replicated inputs, taken from the block itself where the builder commits them.
    o2::XmrSettlementConfig c = cfg;
    c.canonical = true;
    const auto cut = credit::parse_tail(p);
    if (cut) { const credit::CreditCut cc = *cut;
        c.credit_cut_source = [cc](std::uint64_t& P, ::v37::bytes32& dg) { P = cc.next_pos; dg = cc.spine_digest; return true; };
    } else c.credit_cut_source = nullptr;
    c.ecut_finder = paynow::parse_finder_payload(p);
    bool view_missing = false;
    {
        auto inner = cfg.paynow_source;
        c.paynow_source = [inner, &view_missing](std::uint64_t P, const ::v37::bytes32& dg,
                                                 std::vector<::c2pool::v37n::settle::WeightedPayee>& out) -> bool {
            const bool ok = inner ? inner(P, dg, out) : false;
            if (!ok) view_missing = true;
            return ok;
        };
    }

    o2::XmrParentContext parent;
    parent.monero_major_version = f.major;
    parent.height = f.height;
    parent.prev_id = f.prev_id;
    parent.base_reward = *total;   // the split only needs the budget; subsidy/fee split is informational
    parent.fees = 0;

    std::string why;
    std::unique_ptr<o2::XmrOwedSettlementSource> src = o2::build_settlement_source(c, parent, ledger, pay_of, *total, &why);
    if (view_missing && paynow::parse_payload(p)) return undec("the lane view at the committed credit cut is not readable here yet");
    if (!src) return mism("no canonical coinbase exists at this state: " + why);
    e.carried_unpayable = src->carried_unpayable();

    // Tail fields: the builder's claims (V37F / V37N / V37R / V37D / V37P / V37C) must be
    // the ones the canonical source commits, byte for byte at the end of the payload.
    std::vector<std::uint8_t> tail = src->extra_nonce_tail();
    {
        const std::size_t at = std::min(src->reward_tail_offset(), tail.size());
        const std::vector<std::uint8_t> r = paynow::encode_reward_tail(*total);
        tail.insert(tail.begin() + static_cast<std::ptrdiff_t>(at), r.begin(), r.end());
    }
    if (p.size() < 4 + tail.size() || std::memcmp(p.data() + p.size() - tail.size(), tail.data(), tail.size()) != 0)
        return mism("the 0x02 tail (V37F/V37N/V37R/V37D/V37P/V37C) differs from the canonical one");

    std::vector<unsigned char> en(p.begin(), p.end());
    e.cb = src->build_at(*total, en);
    if (!e.cb.ok) return mism("canonical build refused: " + e.cb.detail);
    e.pre = {Verdict::Match, {}};
    return e;
}

// A Mismatch reached while payee refs were missing is not the builder's fault.
inline Result settle_verdict(Result r, const Expected& e) {
    if (r.v == Verdict::Mismatch && e.carried_unpayable > 0) {
        r.v = Verdict::Undecidable;
        r.why = "differs, but " + std::to_string(e.carried_unpayable) +
                " owed key(s) have no learned payout ref here (REJOIN-PAYEE): " + r.why;
    }
    return r;
}

// Receipt side: compare the recomputed opening with the receipt's own.
inline Result verify_opening(const Expected& e, const ::v37::xmr::CoinbaseOpening& got) {
    if (!e.ready()) return settle_verdict(e.pre, e);
    ::v37::xmr::CoinbaseOpening want;
    if (e.cb.tx_extra.size() > e.cb.prefix.size() ||
        !::v37::xmr::verify::build_coinbase_opening(e.cb.prefix, e.cb.prefix.size() - e.cb.tx_extra.size(), want))
        return {Verdict::Undecidable, "cannot cut the canonical opening"};
    if (want.midstate != got.midstate || want.prefix_tail != got.prefix_tail || want.tx_extra != got.tx_extra)
        return settle_verdict({Verdict::Mismatch, "the receipt's coinbase opening (outputs/amounts) differs from the canonical one"}, e);
    return {Verdict::Match, {}};
}

// Block side: compare the miner_tx prefix bytes of a block.
inline Result verify_block_prefix(const Expected& e, const std::vector<std::uint8_t>& prefix) {
    if (!e.ready()) return settle_verdict(e.pre, e);
    if (e.cb.prefix.size() != prefix.size() ||
        (!prefix.empty() && std::memcmp(e.cb.prefix.data(), prefix.data(), prefix.size()) != 0))
        return settle_verdict({Verdict::Mismatch, "the block's miner_tx prefix differs from the canonical one"}, e);
    return {Verdict::Match, {}};
}

} // namespace c2pool::v37n::xmr::canon
