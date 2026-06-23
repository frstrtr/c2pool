#pragma once

// ---------------------------------------------------------------------------
// dash::interfaces::Node -- minimal coin-node shared-state surface for the
// launcher slice-3 external-RPC client.
//
// DASH is NOT structurally BTC/DGB-shaped here: its WorkData (DashWorkData,
// coin/rpc_data.hpp) is a RICH self-contained payload that already carries the
// parsed transactions (m_txs/m_tx_data_hex), masternode/superblock payments
// (m_packed_payments/m_payment_amount) and the DIP3/DIP4 coinbase extra payload
// (m_coinbase_payload). NodeRPC::getwork() populates all of that directly from
// the GBT JSON, so DASH does NOT need DGB's TXIDCache (the txid is recomputed
// per-tx from the parsed MutableTransaction via dash::coin::dash_txid). This
// surface is therefore deliberately leaner than dgb::interfaces::Node: it
// carries only the mempool-known-tx map the broadcaster arm consults.
//
// The embedded NodeP2P feed events (new_block/new_tx/new_headers/full_block)
// that DGB's Node exposes are NOT added here: the embedded-P2P relay leg of the
// won-block broadcaster is still DEFERRED (this slice ships the dashd-RPC
// submitblock fallback only). They land with the dash p2p_node broadcaster.
// ---------------------------------------------------------------------------

#include <map>

#include "transaction.hpp"

#include <core/uint256.hpp>

namespace dash
{

namespace interfaces
{

struct Node
{
    // Mempool-known txs (gbt data -> tx). Populated by the embedded ingest path
    // when it lands; the RPC getwork() path is self-contained and does not
    // require it, but the broadcaster reconstruction arm consults it.
    std::map<uint256, coin::Transaction> known_txs;
};

} // namespace interfaces

} // namespace dash
