// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_paynow.hpp -- SAME-BLOCK PAY-NOW (operator ruling
// 09-25), the commitment and the receive-side booking.
//
// THE DEFECT IT CLOSES. A block's own reward is credited to its miners only
// at FINALIZE (on_block_finalized, E_b from the on-chain credit cut). Before
// this rule, whatever the oldest-first owed pass did not use -- the WHOLE
// reward of the first block and of every block found before the first one
// finalized -- folded into the donation output (or the residual sink) as
// coverage, never deducted, while the miners were still credited that block's
// E_b in full at finalization: the pool ran one D_conf window behind forever
// with the float parked in the donation wallet.
//
// THE RULE (X6 allocate_exact_sum, impl/xmr/settle/xmr_coinbase.cpp). After
// the owed pass, the pool P = what is left above the folded donation minimum
// (whole residual when the sink is a separate output) pays the payees whose
// work THIS block credits, pro rata to their E_b at this block's cut
// (x6::paynow_split: exact-sum, each <= its own E_b, identity ASC). Rule L:
// the ONLY over-owed payment allowed is <= the payee's own E_b of THIS block.
//
// THE COMMITMENT. Every node must book the block identically from the chain
// alone, but the owed set the builder paid depends on node-local pending state
// (owed_digest commits the finalized partition only). So the builder commits
// the reward-INDEPENDENT base  B = Σ owed takes of its input set + Σ fixed
// declared amounts  as the 12-byte 0x02 tail "V37N" || u64le(B), placed before
// the fee model's "V37D" tail, the POOL-LINEAGE "V37P" field and the V37C
// credit-cut tail. Receiver: P =
// total - B (0 when negative: the owed pass then exhausted the budget), and
// alloc = paynow_split(P, E_b at the on-chain cut) -- the SAME function over
// the SAME map fold_eb books. Absent tail => no pay-now in this block.
//
// THE BOOKING (net at FOUND, finalized at FINALIZE). For every payee with
// alloc_k > 0: its credit for this block is booked NET of what the block
// already paid it (credit_k -= alloc_k) and the pay-now leaves the payout map
// (payout_k -= alloc_k), so EffectiveOwed during the pending window is exactly
// master's (finalW - owed payouts), FINALIZE adds E_b - paid, never double
// pays and never goes negative. The residual-sink identity's share is inside
// the sink / donation output, which is coverage (D1: never a ledger
// deduction), so only its credit is netted. ORPHAN (pre-SETTLED) removes the
// pending row whole: an orphan paid nothing on-chain and credits nothing, so
// nothing is netted. A coinbase that does not pay what the commitment claims
// (payout_k < alloc_k) is REFUSED, never partially booked.
// ===========================================================================
#pragma once

#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <sharechain/v37/v37_descriptor_xmr.hpp>   // xmr_identity_key / xmr_ref_valid (EMPTY-CUT FINDER)
#include <sharechain/v37/v37_hash.hpp>
#include "impl/xmr/settle/xmr_coinbase.hpp"   // x6::paynow_split
#include "xmr_credit_cut.hpp"                 // extra_nonce_field, kMagic/kTailBytes (V37C)
#include "xmr_fee_model.hpp"                  // kDonationOwedMagic/kDonationOwedTailBytes (V37D)

namespace c2pool::v37n::xmr::paynow {

namespace x6 = ::v37::xmr::settle;

inline constexpr unsigned char kPayNowMagic[4] = {'V', '3', '7', 'N'};
inline constexpr std::size_t   kPayNowTailBytes = 4 + 8;   // 12

inline std::vector<std::uint8_t> encode_tail(std::uint64_t base) {
    std::vector<std::uint8_t> t(kPayNowMagic, kPayNowMagic + 4);
    for (int i = 0; i < 8; ++i) t.push_back(static_cast<std::uint8_t>(base >> (8 * i)));
    return t;
}

// The base B from a 0x02 payload: strip the V37C tail, then the POOL-LINEAGE
// V37P field, then the V37D tail (each only if present), then read "V37N"
// u64le at the end. nullopt = no pay-now. Canonical order of a lane payload:
//     [ nonce | rbind? | pad | "V37F" finder? | "V37N" B | "V37D" owed_in? | "V37P" v pool_tag? | "V37C" P spine ]
// (V37F: the EMPTY-CUT FINDER field below, only in an empty-cut block.)
// A malformed V37P field (unknown version) is NOT skipped, so the V37N magic
// check fails closed (the lineage gate has already made such a block ordinary).
// The payload offset right after the V37N field (== where V37D / V37P / V37C
// begin), after stripping those three from the end exactly like the readers do.
inline std::size_t end_before_donation_tail(const std::vector<std::uint8_t>& p) {
    std::size_t end = credit::end_before_credit_tail(p);
    if (credit::parse_pool_tag_payload(p) == credit::PoolTagParse::Present) end -= credit::kPoolTagFieldBytes;
    if (end >= fee::kDonationOwedTailBytes &&
        std::memcmp(p.data() + end - fee::kDonationOwedTailBytes, fee::kDonationOwedMagic, 4) == 0)
        end -= fee::kDonationOwedTailBytes;
    return end;
}
inline std::optional<std::uint64_t> parse_payload(const std::vector<std::uint8_t>& p) {
    const std::size_t end = end_before_donation_tail(p);
    if (end < kPayNowTailBytes) return std::nullopt;
    const std::uint8_t* t = p.data() + end - kPayNowTailBytes;
    if (std::memcmp(t, kPayNowMagic, 4) != 0) return std::nullopt;
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(t[4 + i]) << (8 * i);
    return v;
}
inline std::optional<std::uint64_t> parse(const std::vector<unsigned char>& tx_extra) {
    const auto nf = credit::extra_nonce_field(tx_extra);
    if (!nf) return std::nullopt;
    return parse_payload(*nf);
}

// The receive-side allocation: pool = total - base (0 if negative), split over
// the E_b credit map (key ASC == the builder's identity ASC). Returns the
// per-key pay-now (only keys with alloc > 0).
inline std::map<::v37::bytes32, long long> allocation(std::uint64_t total, std::uint64_t base,
                                                      const std::map<::v37::bytes32, long long>& credit) {
    std::map<::v37::bytes32, long long> out;
    const std::uint64_t pool = total > base ? total - base : 0;
    if (pool == 0) return out;
    std::vector<::v37::bytes32> keys;
    std::vector<std::uint64_t> eb;
    for (const auto& [k, v] : credit) {
        if (v <= 0) continue;
        keys.push_back(k);
        eb.push_back(static_cast<std::uint64_t>(v));
    }
    const std::vector<std::uint64_t> a = x6::paynow_split(pool, eb);
    for (std::size_t i = 0; i < keys.size(); ++i)
        if (a[i] > 0) out[keys[i]] = static_cast<long long>(a[i]);
    return out;
}

// ===========================================================================
// EMPTY-CUT FINDER (operator ruling 09-26). THE GAP IT CLOSES: a block whose
// on-chain credit cut is EMPTY (a brand-new pool's first 1-3 blocks: nobody's
// work is at the cut yet) credits nobody, so pay-now had no payee and the
// whole reward went to the donation output / residual sink.
//
// THE RULE. In an empty cut the finder's own share counts as the work: the
// block pays its FINDER the pool P = total - B (B = the V37N base: sum of owed
// takes + sum of fixed), i.e. reward - 1 with the fee model ON (the donation
// keeps its 1-piconero marker) and the whole reward with the fee model OFF
// (nothing is left for the residual sink, which then emits no output), minus
// any owed takes the block also pays.
//
// THE FINDER IS WHAT THE BLOCK COMMITS. The coinbase outputs are one set per
// template (the per-worker bytes live only in the 0x02 region), so the finder
// is the payee the template was built for: the building node's own payee
// (the same payee its FOUND records carry). The builder commits it in full as
// the 0x02 field
//     "V37F" || u8 kind || payee[64]            (69 bytes, right before V37N)
// so every node derives finder_identity = xmr_identity_key(payee) from the
// block bytes alone: no ledger, no relay, no learned ref.
//
// THE RECEIVE SIDE (a pure function of the block + the fold at its cut):
//   V37F absent             -> nothing (every non-empty-cut block, unchanged).
//   V37F present, and
//     malformed (kind)      -> REFUSED
//     V37N absent           -> not a finder block (V37F is read only before a
//                              V37N field); its finder output is unmapped ->
//                              fail-closed like any unknown payee
//     payee not a valid XMR -> REFUSED
//     the fold is NON-empty -> REFUSED (a finder claim on a cut that credits
//                              work would take the pool from those miners)
//     else                  -> credit := { finder_identity : P } (P > 0); the
//                              ordinary pay-now booking (net_booking) then
//                              requires the coinbase to pay the finder >= P
//                              and books the block NET: the finder's credit
//                              and payout both drop by P, so FINALIZE never
//                              pays it twice.
// A coinbase that pays anyone but the committed finder is unmapped (fail-
// closed) or under-pays the finder (net_booking refuses it).
// ===========================================================================
#define C2POOL_V37_XMR_ECUT_FINDER 1   // feature probe for KATs built on both trees
inline constexpr unsigned char kFinderMagic[4] = {'V', '3', '7', 'F'};
inline constexpr std::size_t   kFinderFieldBytes = 4 + 1 + 64;   // 69

// Empty when `payee` is not an XMR-kind 64-byte ref (the builder then arms nothing).
inline std::vector<std::uint8_t> encode_finder_field(const ::v37::ScriptRef& payee) {
    if (!::v37::xmr::is_xmr_kind(payee.kind) || payee.payload.size() != 64) return {};
    std::vector<std::uint8_t> f(kFinderMagic, kFinderMagic + 4);
    f.push_back(static_cast<std::uint8_t>(payee.kind));
    f.insert(f.end(), payee.payload.begin(), payee.payload.end());
    return f;
}

// Where the V37F field would start (nullopt: no V37N field, or no room).
inline std::optional<std::size_t> finder_field_pos(const std::vector<std::uint8_t>& p) {
    if (!parse_payload(p)) return std::nullopt;
    const std::size_t end = end_before_donation_tail(p) - kPayNowTailBytes;
    if (end < kFinderFieldBytes) return std::nullopt;
    if (std::memcmp(p.data() + end - kFinderFieldBytes, kFinderMagic, 4) != 0) return std::nullopt;
    return end - kFinderFieldBytes;
}
// True iff the V37F magic sits right before V37N, whatever its kind byte.
inline bool finder_magic_present(const std::vector<std::uint8_t>& p) { return finder_field_pos(p).has_value(); }
// The committed finder payee; nullopt when absent or its kind is not XMR.
inline std::optional<::v37::ScriptRef> parse_finder_payload(const std::vector<std::uint8_t>& p) {
    const auto pos = finder_field_pos(p);
    if (!pos) return std::nullopt;
    const std::uint8_t* f = p.data() + *pos;
    ::v37::ScriptRef r;
    r.kind = static_cast<::v37::ScriptKind>(f[4]);
    if (!::v37::xmr::is_xmr_kind(r.kind)) return std::nullopt;
    r.payload.assign(f + 5, f + kFinderFieldBytes);
    return r;
}
inline std::optional<::v37::ScriptRef> parse_finder(const std::vector<unsigned char>& tx_extra) {
    const auto nf = credit::extra_nonce_field(tx_extra);
    if (!nf) return std::nullopt;
    return parse_finder_payload(*nf);
}
inline bool finder_malformed(const std::vector<unsigned char>& tx_extra) {
    const auto nf = credit::extra_nonce_field(tx_extra);
    return nf && finder_magic_present(*nf) && !parse_finder_payload(*nf);
}

// Receive side: turn the EMPTY fold at the cut into the finder's credit. A
// no-op (true) when the block commits no finder. On a refusal `credit` is
// left untouched and *why says why.
inline bool apply_empty_cut_finder(const std::optional<::v37::ScriptRef>& finder, bool malformed,
                                   const std::optional<std::uint64_t>& base, std::uint64_t total,
                                   std::map<::v37::bytes32, long long>& credit, std::string* why = nullptr,
                                   ::v37::bytes32* finder_id = nullptr) {
    auto no = [&](const std::string& w) { if (why) *why = "ecut-finder-refused: " + w; return false; };
    if (malformed) return no("the V37F field is malformed (its payee kind is not XMR)");
    if (!finder) return true;
    if (!base) return no("V37F without a V37N base (the finder pool is undefined)");
    if (!::v37::xmr::xmr_ref_valid(*finder)) return no("the committed finder payee is not a valid XMR ref");
    for (const auto& kv : credit)
        if (kv.second > 0) return no("V37F on a NON-empty credit cut (the cut credits work; the finder rule is for an empty cut only)");
    const ::v37::bytes32 id = ::v37::xmr::xmr_identity_key(*finder);
    if (finder_id) *finder_id = id;
    credit.clear();
    const std::uint64_t pool = total > *base ? total - *base : 0;
    if (pool > 0) credit[id] = static_cast<long long>(pool);
    return true;
}

struct NetResult {
    bool          ok = true;
    std::string   why;
    std::uint64_t pool = 0;         // total - base (0 when the tail is absent)
    long long     netted = 0;       // Σ alloc booked against credit
    std::map<::v37::bytes32, long long> alloc;   // per-key pay-now
};

// Book the block NET of its pay-now. `credit` = E_b at the on-chain cut (the
// fold), `payout` = the on-chain owed payouts (sink/donation coverage NOT in
// it), `sink_total` = the coverage amount the sink / donation output carries
// beyond its own owed part, `sink_identity` = its identity. No tail => a no-op.
// On a refusal the maps are left untouched and ok == false.
inline NetResult net_booking(const std::optional<std::uint64_t>& base, std::uint64_t total,
                             std::map<::v37::bytes32, long long>& credit,
                             std::map<::v37::bytes32, long long>& payout,
                             long long sink_total, const ::v37::bytes32& sink_identity,
                             long long sink_reserved = 0) {
    NetResult r;
    if (!base) return r;
    r.pool = total > *base ? total - *base : 0;
    r.alloc = allocation(total, *base, credit);
    for (const auto& [k, a] : r.alloc) {
        if (k == sink_identity) {
            if (sink_total - sink_reserved < a) {
                r.ok = false;
                r.why = "paynow-refused: the sink/donation output carries " + std::to_string(sink_total - sink_reserved) +
                        " coverage < its committed pay-now " + std::to_string(a);
                return r;
            }
            continue;
        }
        const auto it = payout.find(k);
        const long long paid = it == payout.end() ? 0 : it->second;
        if (paid < a) {
            r.ok = false;
            r.why = "paynow-refused: a payee is paid " + std::to_string(paid) + " < its committed pay-now " +
                    std::to_string(a) + " (the V37N base does not match the coinbase)";
            return r;
        }
    }
    for (const auto& [k, a] : r.alloc) {
        auto c = credit.find(k);
        if (c != credit.end()) { c->second -= a; if (c->second == 0) credit.erase(c); }
        if (!(k == sink_identity)) {
            auto p = payout.find(k);
            p->second -= a;
            if (p->second == 0) payout.erase(p);
        }
        r.netted += a;
    }
    return r;
}

} // namespace c2pool::v37n::xmr::paynow
