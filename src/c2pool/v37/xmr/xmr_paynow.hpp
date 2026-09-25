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
//     [ nonce | rbind? | pad | "V37N" B | "V37D" owed_in? | "V37P" v pool_tag? | "V37C" P spine ]
// A malformed V37P field (unknown version) is NOT skipped, so the V37N magic
// check fails closed (the lineage gate has already made such a block ordinary).
inline std::optional<std::uint64_t> parse_payload(const std::vector<std::uint8_t>& p) {
    std::size_t end = credit::end_before_credit_tail(p);
    if (credit::parse_pool_tag_payload(p) == credit::PoolTagParse::Present) end -= credit::kPoolTagFieldBytes;
    if (end >= fee::kDonationOwedTailBytes &&
        std::memcmp(p.data() + end - fee::kDonationOwedTailBytes, fee::kDonationOwedMagic, 4) == 0)
        end -= fee::kDonationOwedTailBytes;
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
