// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ===========================================================================
// c2pool::dgb::wire_mempool_ingest -- connect the embedded P2P transaction
// relay to the in-process Mempool so live `tx` messages populate the pool the
// embedded work template selects from.
//
// The embedded coin P2P layer (coin/p2p_node.hpp, ADD_P2P_HANDLER(tx)) parses
// each received `tx` message into a coin::Transaction and fires
// dgb::interfaces::Node::new_tx (coin/node_interface.hpp). Until this slice
// nothing consumed that event for the Mempool: relayed transactions were
// dropped on the floor, so the embedded mempool stayed empty regardless of P2P
// traffic and EmbeddedCoinNode's injected EmbeddedTxSource
// (make_mempool_tx_source) had nothing to select -- transactions[] in the
// served template was always empty and coinbasevalue carried subsidy only.
//
// wire_mempool_ingest subscribes the pool to that feed. Each announced
// transaction is converted to the Mempool's MutableTransaction form and handed
// to Mempool::add_tx, which is the single insertion SSOT: it computes the txid,
// rejects duplicates, weighs the tx (BIP141) and enforces the byte cap. This
// connector adds NO policy of its own -- it is the tx analog of
// wire_header_ingest (coin/header_ingest.hpp) for the new_headers feed.
//
// FEE POSTURE: add_tx accepts an OPTIONAL UTXOViewCache. When the caller
// passes nullptr (the default, and every pre-existing call site), fees stay
// fee_known=false — byte-identical to the feed-only slice: make_mempool_tx_source
// emits fee=null and EXCLUDES unknown-fee value from the coinbasevalue fold, so
// a P2P-fed pool with no view cannot desync coinbasevalue versus a daemon's GBT.
// When the caller passes a live UTXOViewCache (the embedded fee-proof lane wired
// in main_dgb behind --embedded-serve-mempool-txs), add_tx computes the fee
// against that spent-aware view (Mempool::compute_fee_locked): a tx whose inputs
// all resolve, pass MoneyRange, and clear coinbase maturity becomes fee_known and
// is eligible for the fee-bearing template; a tx that does not remains excluded
// (never overstated). This is the tx analog of BTC main_btc.cpp new_tx ->
// add_tx(mtx, &utxo_cache).
//
// LIFETIME: the handler captures `pool` by reference, so `pool` MUST outlive
// `node`. The returned EventDisposable lets a caller tear the subscription down
// explicitly; while it (and the node) live, every new_tx relay is ingested.
// ===========================================================================

#include <memory>

#include <core/events.hpp>

#include "node_interface.hpp"   // dgb::interfaces::Node (new_tx feed)
#include "mempool.hpp"          // dgb::coin::Mempool / MutableTransaction
#include "transaction.hpp"      // dgb::coin::Transaction -> MutableTransaction

namespace c2pool::dgb
{

// Subscribe `pool` to `node.new_tx`. Returns the subscription handle so the
// caller controls teardown; the subscription persists for the node's life if
// the handle is dropped (EventDisposable does not auto-dispose on destruction).
//
// `utxo` is an OPTIONAL spent-aware UTXO view. nullptr (the default) preserves
// the feed-only behaviour exactly (fee_known=false). A non-null view is fee-
// proved per tx by Mempool::add_tx. The pointer is captured by value; it MUST
// outlive `node` (in main_dgb the UTXOViewCache, Mempool and coin_iface share a
// scope). Passing the SAME view here and to Mempool::set_utxo keeps ingest-time
// and selection-time fee views identical.
//
// NOTE: pulls mempool.hpp -> transaction.hpp (the tx serialization codec), so
// include this header ONLY from a TU that already links the full dgb_coin
// codec (main_dgb.cpp + the codec conformance test), never a guard-weight TU
// -- the #143 btclibs SCC trap, identical to embedded_tx_select.hpp.
inline std::shared_ptr<EventDisposable>
wire_mempool_ingest(::dgb::interfaces::Node& node, ::dgb::coin::Mempool& pool,
                    core::coin::UTXOViewCache* utxo = nullptr)
{
    return node.new_tx.subscribe(
        [&pool, utxo](const ::dgb::coin::Transaction& tx)
        {
            pool.add_tx(::dgb::coin::MutableTransaction(tx), utxo);
        });
}

} // namespace c2pool::dgb