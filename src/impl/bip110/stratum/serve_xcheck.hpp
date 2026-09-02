// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// bip110::stratum::serve_xcheck — INDEPENDENT pre-serve fee re-derivation (GAP5).
//
// The pre-serve reward-safety xcheck (work_source.cpp) claimed a "fee re-sum"
// that was only a COMMENT: fee_total had a single provenance (the assembler's
// total_fee). This makes the claim REAL — a second-source re-derivation that
// operates ONLY on the frozen BIP144 body bytes the block will actually carry,
// never on the assembler's AssembledTx structs:
//
//   for each decoded tx, resolve every input value from EXACTLY two sources —
//     (i)  an earlier-decoded in-template tx's vout (a txid→values map built as
//          the loop advances, from the DECODED bytes), or
//     (ii) utxo_get() on the live post-anchor UTXO view;
//   an input resolving via NEITHER ⇒ nullopt (fail: "fee-resum-unresolvable").
//   Per-value / per-sum / per-fee MoneyRange + fee>=0 guards mirror the pricer.
//
// This is TOTAL under GAP2's inclusion rule (every included input is in-view or
// in-template), so sources (i)+(ii) always suffice — no mempool access, no side
// table, no third tier.
//
// HONESTY (scope): for view-resolved inputs the VALUE ultimately comes from the
// same UTXOViewCache the pricer used — this is an independent DERIVATION
// (different code path: frozen bytes, decoded-parent map, independent summation),
// NOT an independent LEDGER. It catches assembler bugs, stale-snapshot fees,
// emission/accounting skew, and any tampered fee_total; it does NOT catch a
// corrupted UTXO view itself (that is GAP4's reorg job). ZERO DASH code.
// ---------------------------------------------------------------------------

#include "../coin/transaction.hpp"

#include <core/coin/utxo.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace bip110 {
namespace stratum {

// Re-sum the provable fees across a template's frozen BIP144 body txs.
// Returns nullopt on any decode failure, trailing bytes, unresolvable input, or
// MoneyRange / negative-fee violation. Otherwise the summed fee.
inline std::optional<uint64_t> xcheck_resum_fees(
    const std::vector<std::vector<unsigned char>>& frozen_body_bytes,
    const std::function<bool(const core::coin::Outpoint&, core::coin::Coin&)>& utxo_get,
    const core::coin::ChainLimits& limits)
{
    std::map<uint256, std::vector<int64_t>> decoded_vout;  // in-template parents
    // BELT-3(b) — TEMPLATE-WIDE outpoint set across ALL decoded txs' inputs. A
    // failed insert catches BOTH an across-tx double-spend AND a within-tx
    // duplicate input (CVE-2018-17144) directly from the frozen bytes the block
    // will actually carry — independent of add_tx and the assembler.
    std::set<std::pair<uint256, uint32_t>> seen_outpoints;
    uint64_t fee_sum = 0;

    for (const auto& bytes : frozen_body_bytes) {
        PackStream ps(bytes);
        bip110::coin::MutableTransaction dtx;
        try { bip110::coin::UnserializeTransaction(dtx, ps, bip110::coin::TX_WITH_WITNESS); }
        catch (...) { return std::nullopt; }
        if (!ps.empty()) return std::nullopt;    // trailing bytes ⇒ malformed

        // BELT-3(a) — structural floor on the DECODED bytes: an empty-vin or
        // empty-vout tx must never sit in a served template (an empty-vout tx
        // otherwise prices fee=value_in and would PASS the re-sum below).
        if (dtx.vin.empty() || dtx.vout.empty()) return std::nullopt;

        // txid over the NON-witness serialization (segwit-invariant).
        uint256 txid;
        {
            auto packed = pack(bip110::coin::TX_NO_WITNESS(dtx));
            txid = Hash(packed.get_span());
        }

        int64_t value_in = 0;
        for (const auto& vin : dtx.vin) {
            // BELT-3(b) — template-wide outpoint uniqueness (within-tx AND across-tx).
            if (!seen_outpoints.insert({vin.prevout.hash, vin.prevout.index}).second)
                return std::nullopt;
            int64_t v = -1;
            auto pit = decoded_vout.find(vin.prevout.hash);
            if (pit != decoded_vout.end() && vin.prevout.index < pit->second.size()) {
                v = pit->second[vin.prevout.index];      // (i) in-template parent
            } else {
                core::coin::Outpoint op(vin.prevout.hash, vin.prevout.index);
                core::coin::Coin coin;
                if (utxo_get && utxo_get(op, coin)) v = coin.value;   // (ii) UTXO view
            }
            if (v < 0 || !core::coin::money_range(v, limits)) return std::nullopt;
            value_in += v;
            if (!core::coin::money_range(value_in, limits)) return std::nullopt;
        }

        int64_t value_out = 0;
        std::vector<int64_t> vals;
        vals.reserve(dtx.vout.size());
        for (const auto& o : dtx.vout) {
            value_out += o.value;
            if (!core::coin::money_range(value_out, limits)) return std::nullopt;
            vals.push_back(o.value);
        }

        int64_t fee = value_in - value_out;
        if (fee < 0 || !core::coin::money_range(fee, limits)) return std::nullopt;
        fee_sum += static_cast<uint64_t>(fee);

        decoded_vout[txid] = std::move(vals);   // available to later children
    }
    return fee_sum;
}

} // namespace stratum
} // namespace bip110
