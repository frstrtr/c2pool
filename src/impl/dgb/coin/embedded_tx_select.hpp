// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ===========================================================================
// embedded_tx_select.hpp -- production EmbeddedTxSource factory.
//
// Builds the dgb::coin::EmbeddedTxSource that EmbeddedCoinNode injects to fill
// the embedded work template's transactions[] from the in-process Mempool. The
// actual shaping (Mempool::SelectedTx -> {data,txid,hash,fee}) is the heavy
// tx/UTXO serialization codec, so it lives OUT-OF-LINE in embedded_tx_select.cpp
// (compiled into dgb_coin) -- NOT in this header and NOT in embedded_coin_node.hpp.
// Keeping the codec in a .cpp is what holds the #143 btclibs SCC trap shut: a
// guard-weight TU that reaches embedded_coin_node.hpp never compiles the
// transaction serialization templates.
//
// This header DOES pull mempool.hpp (-> transaction.hpp), so include it ONLY
// from TUs that already link the full dgb_coin codec (main_dgb.cpp + the codec
// conformance test), never from a guard-weight TU.
// ===========================================================================

#include <cstdint>

#include "embedded_coin_node.hpp"   // EmbeddedTxSource / EmbeddedTxSelection
#include "mempool.hpp"              // dgb::coin::Mempool

namespace dgb::coin
{

// Build an EmbeddedTxSource that, on each invocation, selects up to max_weight
// BIP141 weight units of fee-sorted transactions from `pool` and shapes them
// into the GBT transactions[] form build_work_template passes through verbatim:
//   {data: hex(TX_WITH_WITNESS), txid: txid, hash: wtxid, fee: <int|null>}
// The returned selection's total_fees is the sum of the known fees across the
// selected txs (the SAME figure get_sorted_txs_with_fees reports), folded into
// coinbasevalue by EmbeddedCoinNode via resolve_coinbase_value (#207 SSOT) --
// NOT added to the template here.
//
// `pool` is captured by reference -- it MUST outlive the returned source (the
// embedded node and its mempool share a lifetime).
EmbeddedTxSource make_mempool_tx_source(Mempool& pool, uint32_t max_weight);

} // namespace dgb::coin