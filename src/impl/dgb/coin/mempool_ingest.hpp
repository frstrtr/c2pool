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
// FEE POSTURE: add_tx is called WITHOUT a UTXOViewCache here, so fees stay
// fee_known=false until a UTXO view feeds them. That is deliberate and matches
// the embedded shaper's conservative default (make_mempool_tx_source emits
// fee=null and excludes unknown-fee value from the coinbasevalue fold), so a
// P2P-fed mempool cannot desync coinbasevalue versus a daemon's GBT. Wiring a
// real UTXO view is a later slice; this one only opens the feed.
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
// NOTE: pulls mempool.hpp -> transaction.hpp (the tx serialization codec), so
// include this header ONLY from a TU that already links the full dgb_coin
// codec (main_dgb.cpp + the codec conformance test), never a guard-weight TU
// -- the #143 btclibs SCC trap, identical to embedded_tx_select.hpp.
inline std::shared_ptr<EventDisposable>
wire_mempool_ingest(::dgb::interfaces::Node& node, ::dgb::coin::Mempool& pool)
{
    return node.new_tx.subscribe(
        [&pool](const ::dgb::coin::Transaction& tx)
        {
            pool.add_tx(::dgb::coin::MutableTransaction(tx));
        });
}

} // namespace c2pool::dgb
