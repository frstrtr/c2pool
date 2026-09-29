// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_coinbase_recompute.hpp -- EVERY NODE RECOMPUTES THE
// LANE COINBASE (operator rulings 2026-09-29: fee model v1 is mandatory; a
// block whose coinbase is not the canonical one has its payouts DEBITED and
// its credit DROPPED; in force from the lane's genesis, no activation gate).
//
// THE GAP IT CLOSES. Under coinbase authority (xmr_coinbase_authority.hpp) a
// receiver books whatever payout map a lane block carries. Nothing compared a
// payout with any owed balance, so a modified builder could over-pay a known
// key, and an honest builder that built before booking the previous lane
// block could pay one balance twice (external review 01b / 01c, #1861). The
// K_fair order, the pay-now split and the owed base were builder policy.
//
// THE RULE. A lane block B at height h is CANONICAL iff its coinbase is,
// byte for byte (tx pubkey R, every output's amount, one-time key and view
// tag, the whole tx_extra), the coinbase the builder pipeline itself
// produces from inputs every node holds at B's booking point:
//
//   ledger      the receiver's OwedLedger BEFORE B is booked. R6 books B with
//               the finalize cursor at exactly h - 1 - D_conf on every node
//               (xmr_o2_finalize_connect.hpp), which is also where a synced
//               builder's cursor stands while it builds on the tip h - 1:
//               the same finalized partition and the same pending set. The
//               block's committed lane_commitment must therefore BE this
//               ledger's owed_digest; any other state is not canonical.
//   pay_of      the receiver's payee resolver (the refs the lane taught it,
//               including every payee of the view at B's cut: REJOIN-PAYEE).
//   lane cfg    chain id, owed floor, owed-selection cap, the residual sink
//               and fixed outputs (fee model v1: the protocol donation output,
//               compiled in), the pool tag. Identical on every node of a lane.
//   the block   height, prev_id, major version, the exact-sum total, the
//               credit cut (V37C), the pay-now payees projected from the view
//               at that cut (the SAME view fold_eb books), the committed owed
//               base B (V37N), the empty-cut finder (V37F), and the 0x02
//               payload's worker-specific head (nonce, rbind, padding).
//
// THE TWO BUILDER INPUTS A RECEIVER DOES NOT HAVE, and why neither matters:
//   * the reward hint. The builder picks its owed takes at its own
//     base_reward + Σ(mempool fees) >= the block's final total. With V37N the
//     base B = Σfixed + Σtakes is committed, and a greedy K_fair pass over
//     budget B - Σfixed reproduces the takes exactly. B may not be below the
//     takes at the block's own total (that would shift owed money to pay-now:
//     "under-take"). Without V37N the X6 pass at the final total truncates
//     the takes to exactly the greedy pass at that total, so the recompute
//     runs at the total.
//   * the output cap. The assembler resolves a weight-aware cap from its own
//     transaction set. The recompute accepts the caps that can have produced
//     the block's output count (n and n + 1) and the lane ceiling. A smaller
//     cap only truncates the owed pass, which a builder can already force by
//     filling its block with transactions: stated, not hidden.
//
// OUTCOME (ruling 2): a non-canonical lane block is booked with its on-chain
// payouts DEBITED (money that left the pool on-chain is never forgotten:
// forward repair, never a clawback) and its credit DROPPED (the block is
// treated as a withheld block). Refusing the whole block would leave a
// double-paid key undebited, which is strictly worse. The verdict is a pure
// function of the inputs above, so every node reaches the same one.
// ===========================================================================
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>
#include <sharechain/v37/v37_hash.hpp>
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"   // parse_block
#include "impl/xmr/settle/xmr_coinbase.hpp"                // canonical_coinbase_matches
#include "impl/xmr/template/xmr_block_assembly.hpp"        // parse_coinbase_prefix
#include "xmr_coinbase_authority.hpp"                      // CoinbaseBooking
#include "xmr_credit_cut.hpp"                              // extra_nonce_field
#include "xmr_o2_settlement_source.hpp"                    // XmrOwedSettlementSource (the builder)
#include "xmr_paynow.hpp"                                  // V37N / V37F

#define C2POOL_V37_XMR_COINBASE_RECOMPUTE 1   // feature probe for KATs built on both trees

namespace c2pool::v37n::xmr::recompute {

namespace x6 = ::v37::xmr::settle;
using OwedLedger = ::c2pool::v37n::settle::OwedLedger;

// The lane's own settlement parameters: the receiver's XmrSettlementConfig
// values (identical on every node of the lane), never anything the block says.
struct LaneInputs {
    std::uint32_t    chain_id = 0;
    std::uint64_t    h_min = 0;                 // owed floor (0 on XMR)
    std::uint32_t    owed_cap = 2700;           // the owed-selection cap (XmrSettlementConfig::resolved_output_cap)
    std::uint32_t    wire_cap = 2700;           // the assembler's output ceiling (AssemblyInputs::wire_cap)
    ::v37::ScriptRef residual_sink;             // fee model v1: the donation ref
    ::v37::bytes32   residual_sink_identity{};
    std::vector<x6::FixedOutput> fixed;         // fee model v1: {donation_marker}
    std::optional<::v37::bytes32> pool_tag;     // V37P (POOL-LINEAGE)
    o2::KFairSource  kfair = o2::KFairSource::W4Propose;
};

// What the block's booking already established.
struct CutInputs {
    // The view at the block's on-chain credit cut exists and its geometry is
    // ratified (fold_at_cut succeeded), and these are settle::project(view):
    // the builder's paynow_source returns exactly this list.
    bool has_view = false;
    std::vector<::c2pool::v37n::settle::WeightedPayee> payees;
};

enum class Verdict : std::uint8_t {
    Canonical = 0,     // byte-identical to the recompute
    Mismatch = 1,      // decided: not the canonical coinbase (debit payouts, drop credit)
    Undecidable = 2,   // the recompute could not run on this node (internal); never a verdict
};
inline const char* to_string(Verdict v) {
    return v == Verdict::Canonical ? "canonical" : v == Verdict::Mismatch ? "mismatch" : "undecidable";
}

struct Result {
    Verdict       verdict = Verdict::Undecidable;
    std::string   why;               // "" when canonical
    std::uint32_t cap = 0;           // the output cap that reproduced the block (canonical only)
    int           first_bad = -1;    // x6::MatchResult::first_bad_index of the closest candidate
    // The canonical coinbase's payout per identity (sink / folded donation
    // coverage excluded, like CoinbaseBooking::payout), for the alarm line.
    std::map<::v37::bytes32, long long> expected_payout;
    bool canonical() const { return verdict == Verdict::Canonical; }
};

namespace detail {
inline std::string hex12(const ::v37::bytes32& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 6; ++i) { s += d[b[i] >> 4]; s += d[b[i] & 15]; }
    return s;
}
inline bool ends_with(const std::vector<std::uint8_t>& p, const std::vector<std::uint8_t>& t) {
    return p.size() >= t.size() && std::equal(t.begin(), t.end(), p.end() - static_cast<std::ptrdiff_t>(t.size()));
}
}  // namespace detail

// Recompute the canonical coinbase of a decoded lane block and compare it
// with the block's own. `bk` must be the coinbase-authority decode of `blob`
// with a matched lane root (bk.is_lane); `ledger` the receiver's ledger
// BEFORE the block is booked; `pay_of` its payee resolver.
inline Result verify_lane_coinbase(const std::vector<std::uint8_t>& blob,
                                   const authority::CoinbaseBooking& bk,
                                   const OwedLedger& ledger, const o2::PayOfFn& pay_of,
                                   const LaneInputs& lane, const CutInputs& cut) {
    namespace cons = ::c2pool::xmr::native;
    Result res;
    auto mismatch = [&](const std::string& w, int bad = -1) { res.verdict = Verdict::Mismatch; res.why = "recompute-mismatch: " + w; res.first_bad = bad; return res; };
    auto undecidable = [&](const std::string& w) { res.verdict = Verdict::Undecidable; res.why = "recompute-undecidable: " + w; return res; };

    if (!bk.is_lane) return undecidable("not a decoded lane block");

    // --- 1. the ledger state the block commits must be the canonical one ---
    if (!(ledger.owed_digest() == bk.lane_commitment))
        return mismatch("the block commits owed_digest " + detail::hex12(bk.lane_commitment) +
                        "... but the canonical ledger state at its booking point is " +
                        detail::hex12(ledger.owed_digest()) +
                        "... (built on a lagging, ahead or foreign ledger state)");

    // --- 2. the coinbase as the block carries it ---
    cons::ParsedBlock pb;
    const cons::BlockParseStatus st = cons::parse_block(blob.data(), blob.size(), pb);
    if (st != cons::BlockParseStatus::Ok && st != cons::BlockParseStatus::TxCountMismatch)
        return undecidable(std::string("block does not parse: ") + cons::to_string(st));
    x6::ReceivedCoinbase got;
    std::uint64_t height = 0; std::size_t used = 0;
    if (!::c2pool::xmr::assembly::parse_coinbase_prefix(blob.data() + pb.miner_tx_offset, pb.miner_tx_size, got, &height, &used))
        return undecidable("coinbase prefix does not parse");
    const auto payload = credit::extra_nonce_field(got.tx_extra);
    if (!payload) return mismatch("no 0x02 extra-nonce payload");

    // --- 3. the builder's context, from the lane config + the block ---
    o2::XmrCoinbaseContext ctx;
    ctx.monero_major_version = bk.major;
    ctx.height               = height;
    std::memcpy(ctx.prev_id.data(), pb.header.prev_id.data(), 32);
    ctx.base_reward          = bk.total;   // X6 reads only base_reward + fees
    ctx.fees                 = 0;
    ctx.chain_id             = lane.chain_id;
    ctx.lane_commitment      = bk.lane_commitment;
    ctx.residual_sink        = lane.residual_sink;
    ctx.residual_sink_identity = lane.residual_sink_identity;
    ctx.fixed                = lane.fixed;
    ctx.h_min                = lane.h_min;
    ctx.output_cap           = lane.owed_cap;
    ctx.has_credit_cut       = bk.has_credit_cut;
    ctx.credit_cut           = bk.credit_cut;
    if (lane.pool_tag) { ctx.has_pool_tag = true; ctx.pool_tag = *lane.pool_tag; }
    ctx.has_paynow           = ctx.has_credit_cut && cut.has_view;
    if (ctx.has_paynow) ctx.paynow_payees = cut.payees;

    std::uint64_t fixed_sum = 0;
    for (const auto& f : lane.fixed) fixed_sum += f.amount;

    // --- 4. the owed takes: at the block's total, or from its committed base ---
    std::string why;
    auto at_total = o2::XmrOwedSettlementSource::build(ledger, pay_of, ctx, bk.total, &why, lane.kfair);
    if (!at_total) return mismatch("the canonical coinbase cannot be built at this block's total: " + why);
    std::unique_ptr<o2::XmrOwedSettlementSource> src;
    if (bk.paynow_base) {
        const std::uint64_t B = *bk.paynow_base;
        if (B < fixed_sum) return mismatch("V37N base " + std::to_string(B) + " < the fixed outputs " + std::to_string(fixed_sum));
        std::uint64_t took_at_total = 0;
        for (const auto& e : at_total->inputs().owed) took_at_total += e.owed;
        const std::uint64_t took = B - fixed_sum;
        if (took < took_at_total)
            return mismatch("under-take: the V37N base commits owed takes " + std::to_string(took) +
                            " < " + std::to_string(took_at_total) + " the K_fair pass pays at this block's total " +
                            std::to_string(bk.total) + " (owed money shifted to pay-now)");
        src = o2::XmrOwedSettlementSource::build(ledger, pay_of, ctx, bk.total, &why, lane.kfair, {}, took);
        if (!src) return mismatch("the canonical coinbase cannot be built at the committed base: " + why);
    } else {
        src = std::move(at_total);
    }
    // EMPTY-CUT FINDER: the block names its finder; the same snapshot re-armed for it.
    if (bk.ecut_finder_malformed) return mismatch("malformed V37F finder field");
    if (bk.ecut_finder) {
        auto f = src->with_finder(*bk.ecut_finder, &why);
        if (!f) return mismatch("V37F finder not canonical here: " + why);
        src = std::move(f);
    }

    // --- 5. the committed 0x02 tail must be exactly the canonical one ---
    const std::vector<std::uint8_t> tail = src->extra_nonce_tail();
    if (!detail::ends_with(*payload, tail)) {
        std::string w = "the 0x02 tail is not the canonical one";
        const auto want_n = paynow::parse_payload(tail);
        if (want_n != bk.paynow_base)
            w += want_n ? (bk.paynow_base ? " (V37N base " + std::to_string(*bk.paynow_base) + " != canonical " + std::to_string(*want_n) + ")"
                                          : " (V37N absent, canonical base " + std::to_string(*want_n) + ")")
                        : " (V37N present, canonical coinbase has no pay-now)";
        const auto want_d = fee::parse_donation_owed_payload(tail);
        if (want_d != bk.donation_owed_in)
            w += " (V37D owed_in " + (bk.donation_owed_in ? std::to_string(*bk.donation_owed_in) : std::string("absent")) +
                 " != canonical " + (want_d ? std::to_string(*want_d) : std::string("absent")) + ")";
        return mismatch(w);
    }

    // --- 6. byte-compare R, every output and the whole tx_extra ---
    std::vector<std::uint32_t> caps;
    auto add_cap = [&](std::uint64_t c) {
        if (c < 1 || c > lane.wire_cap) return;
        if (std::find(caps.begin(), caps.end(), static_cast<std::uint32_t>(c)) == caps.end()) caps.push_back(static_cast<std::uint32_t>(c));
    };
    add_cap(lane.wire_cap);
    add_cap(got.amounts.size());
    add_cap(got.amounts.size() + 1);
    x6::MatchResult first{false, x6::IDX_BUILD, "no candidate cap"};
    for (const std::uint32_t c : caps) {
        x6::CoinbaseInputs in = src->inputs_at(bk.total, *payload);
        in.output_cap = c;
        const x6::MatchResult m = x6::canonical_coinbase_matches(in, got);
        if (m.matches) {
            res.verdict = Verdict::Canonical;
            res.cap = c;
            res.why.clear();
            for (const auto& o : x6::allocate_exact_sum(in))
                if (!(o.identity == lane.residual_sink_identity)) res.expected_payout[o.identity] += static_cast<long long>(o.amount);
            return res;
        }
        if (c == caps.front()) first = m;   // report against the lane ceiling
    }
    {
        x6::CoinbaseInputs in = src->inputs_at(bk.total, *payload);
        in.output_cap = caps.front();
        for (const auto& o : x6::allocate_exact_sum(in))
            if (!(o.identity == lane.residual_sink_identity)) res.expected_payout[o.identity] += static_cast<long long>(o.amount);
    }
    const std::string at = first.first_bad_index >= 0 ? " at output " + std::to_string(first.first_bad_index) : "";
    return mismatch(first.reason + at + " (canonical coinbase recomputed from the booking-point ledger; tried " +
                    std::to_string(caps.size()) + " output cap(s))", first.first_bad_index);
}

}  // namespace c2pool::v37n::xmr::recompute
