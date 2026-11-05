// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining (phase DB) — DGB-as-PARENT trait specialization.
//
// The shared DOGE aux module (ltc-doge's domain, src/impl/doge/coin/auxpow.hpp)
// is templated on the parent coinbase type (PR #313).  Its params traits
// resolve the TxParams from the PARENT type, defaulting to bitcoin_family's —
// correct for every parent that reuses bitcoin_family::coin::TxParams (LTC,
// DASH):
//   * `doge::coin::parent_coinbase_no_witness<ParentCoinbaseTx>` — the txid
//     (witness-stripped, parent_coinbase_txid);
//   * `doge::coin::parent_coinbase_wire_params<ParentCoinbaseTx>` — the wire
//     form inside CMerkleTx, witness ALLOWED as Dogecoin Core reads and writes
//     it (a DGB coinbase received from the network carries its witness-
//     reserved value since segwit, 2017).
//
// DGB declares its OWN dgb::coin::TxParams type, so a DGB-as-parent coinbase
// handed bitcoin_family's TxParams cannot serialize through dgb's Serialize-
// Transaction (distinct type -> hard compile error).  The #313 doc prescribes
// the resolution explicitly: "A parent with its OWN TxParams type specializes
// this in ITS OWN tree (never here)".  This header is that specialization —
// it lives in src/impl/dgb/ (per-coin isolation), CONSUMES the shared trait,
// and modifies nothing in the shared module.  Any translation unit that
// instantiates the aux module with dgb::coin::MutableTransaction as the parent
// must include this header first so the specialization is visible at the point
// of instantiation.
// ---------------------------------------------------------------------------

#include <impl/doge/coin/auxpow.hpp>        // primary templates parent_coinbase_no_witness<>, parent_coinbase_wire_params<>
#include <impl/dgb/coin/transaction.hpp>    // dgb::coin::MutableTransaction + dgb::coin::TX_NO_WITNESS / TX_WITH_WITNESS

namespace doge::coin {

// DGB parent coinbase serializes through dgb::coin::TxParams, not bitcoin_family's.
template <>
struct parent_coinbase_no_witness<dgb::coin::MutableTransaction>
{
    static constexpr auto value = dgb::coin::TX_NO_WITNESS;
};

template <>
struct parent_coinbase_wire_params<dgb::coin::MutableTransaction>
{
    static constexpr auto value = dgb::coin::TX_WITH_WITNESS;
};

} // namespace doge::coin