// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// bip110::coin::check_transaction — structural transaction validity, ported
// 1:1 from Bitcoin Core consensus/tx_check.cpp CheckTransaction(), plus the
// mempool-context coinbase rejection from MemPoolAccept::PreChecks.
//
// This is the fail-closed structural FLOOR between the wire (p2p new_tx) and the
// serve mempool/template. Before this, NO structural validation existed between
// a decoded tx and the block template, so a peer-suppliable tx could reach a
// consensus-INVALID served block via two proven shapes:
//   (a) WITHIN-TX DUPLICATE INPUT (bad-txns-inputs-duplicate / CVE-2018-17144):
//       a tx whose own vin lists the same outpoint twice was admitted; the fee
//       pricer double-counted that coin => a FABRICATED positive fee off a
//       value-destroying tx (e.g. 2*100000-150000 = 50000).
//   (b) EMPTY VOUT (bad-txns-vout-empty): admitted with fee = whole input.
// Both then priced, selected, and INCLUDED (the serve arm defaults ON).
//
// check_transaction() closes the CLASS ("no structural validation"), not just
// the two shapes. It is lock-free (reads the tx only), so it runs BEFORE the
// mempool mutex and BEFORE pricing; on ANY failure the caller rejects the tx by
// its exact Bitcoin Core error name and it is NEVER priced, NEVER stored.
//
// ZERO DASH code. Per-coin isolation: src/impl/bip110/* only.
// ---------------------------------------------------------------------------

#include "transaction.hpp"
#include "../params.hpp"

#include <core/coin/utxo.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <set>
#include <string>
#include <utility>

namespace bip110 {
namespace coin {

// Mempool-context coinbase test (Bitcoin Core CTransaction::IsCoinBase):
// exactly one input whose prevout is null (hash all-zero, index 0xffffffff).
inline bool is_coinbase(const MutableTransaction& tx) {
    return tx.vin.size() == 1
        && tx.vin[0].prevout.hash.IsNull()
        && tx.vin[0].prevout.index == 0xffffffffu;
}

// Port of Bitcoin Core consensus/tx_check.cpp CheckTransaction() + the
// MemPoolAccept coinbase rejection (PreChecks). Returns true iff `tx` is
// structurally valid AND admissible to a relay/serve mempool. On failure,
// `reason` is set to the EXACT Core error string and the function returns false.
// Reads only `tx` — safe to call outside the mempool mutex.
//
// Rule order mirrors Core so the FIRST structural fault is named:
//   1  vin non-empty                         bad-txns-vin-empty
//   2  vout non-empty                        bad-txns-vout-empty
//   3  base size * 4 <= weight cap           bad-txns-oversize
//   4  each vout.value >= 0                   bad-txns-vout-negative
//   5  each vout.value <= MAX_MONEY           bad-txns-vout-toolarge
//   6  running output sum in range            bad-txns-txouttotal-toolarge
//   7  no duplicate prevout within own vin    bad-txns-inputs-duplicate
//   8  coinbase scriptSig length 2..100       bad-cb-length
//   9  non-coinbase: no null prevout          bad-txns-prevout-null
//  10  mempool context: not a coinbase        coinbase
inline bool check_transaction(const MutableTransaction& tx,
                              const core::coin::ChainLimits& lim,
                              std::string& reason)
{
    // 1-2. vin/vout non-empty. (bad-txns-vin-empty / bad-txns-vout-empty)
    if (tx.vin.empty())  { reason = "bad-txns-vin-empty";  return false; }
    if (tx.vout.empty()) { reason = "bad-txns-vout-empty"; return false; }

    // 3. Oversize. Core bounds the BASE (non-witness) serialized size:
    //    base_size * WITNESS_SCALE_FACTOR(4) > MAX_BLOCK_WEIGHT. In the RDTS
    //    context the cap is bip110::RDTS_MAX_BLOCK_WEIGHT (800000 WU), so
    //    base_size*4 > 800000 rejects. (Full BIP141 weight is additionally
    //    bounded by the assembler cap + serve_xcheck (d); this is Core-exact.)
    {
        auto legacy = pack(TX_NO_WITNESS(tx));
        if (static_cast<uint64_t>(legacy.size()) * 4u > bip110::RDTS_MAX_BLOCK_WEIGHT) {
            reason = "bad-txns-oversize"; return false;
        }
    }

    // 4-6. Per-output value range + running-sum overflow. value<0 is checked
    //      BEFORE the add (as Core does) so a negative can't hide inside a
    //      passing sum.
    int64_t value_out = 0;
    for (const auto& out : tx.vout) {
        if (out.value < 0)             { reason = "bad-txns-vout-negative"; return false; }
        if (out.value > lim.max_money) { reason = "bad-txns-vout-toolarge"; return false; }
        value_out += out.value;
        if (!core::coin::money_range(value_out, lim)) {
            reason = "bad-txns-txouttotal-toolarge"; return false;
        }
    }

    // 7. No duplicate prevout WITHIN this tx's own vin (CVE-2018-17144 shape).
    {
        std::set<std::pair<uint256, uint32_t>> seen;
        for (const auto& in : tx.vin) {
            if (!seen.insert({in.prevout.hash, in.prevout.index}).second) {
                reason = "bad-txns-inputs-duplicate"; return false;
            }
        }
    }

    // 8-9. Coinbase scriptSig length; else no null prevout in a normal tx.
    if (is_coinbase(tx)) {
        const size_t cblen = tx.vin[0].scriptSig.m_data.size();
        if (cblen < 2 || cblen > 100) { reason = "bad-cb-length"; return false; }
    } else {
        for (const auto& in : tx.vin) {
            if (in.prevout.hash.IsNull() && in.prevout.index == 0xffffffffu) {
                reason = "bad-txns-prevout-null"; return false;
            }
        }
    }

    // 10. MEMPOOL CONTEXT (Core MemPoolAccept::PreChecks): a coinbase is never a
    //     standalone mempool/relay tx. Named AFTER the faithful structural port
    //     so a malformed coinbase still surfaces its structural fault first.
    if (is_coinbase(tx)) { reason = "coinbase"; return false; }

    return true;
}

} // namespace coin
} // namespace bip110
