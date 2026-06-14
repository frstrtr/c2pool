#pragma once

// ---------------------------------------------------------------------------
// dgb::interfaces::Node -- coin-node shared-state surface.
//
// Phase A (#82) RESTORES the members the Path-A stub deliberately deferred,
// now that the types they reference exist (block.hpp / transaction.hpp /
// txidcache.hpp ported in this slice). 1:1 mirror of
// src/impl/btc/coin/node_interface.hpp -- DGB is structurally BTC-shaped
// (NON-MWEB); the Scrypt PoW divergence lives in header_chain.hpp, not here.
// The embedded NodeP2P (p2p_node.hpp) binds against this full surface:
//
//   work       : Variable<rpc::WorkData>          -- get_work result
//   new_block  : Event<uint256>                   -- block-hash announce
//   new_tx     : Event<coin::Transaction>         -- mempool tx relay
//   new_headers: Event<vector<BlockHeaderType>>   -- header-chain feed
//   full_block : Event<coin::BlockType>           -- full block (txs)
//   txidcache  : coin::TXIDCache                  -- gbt data -> txid cache
//   known_txs  : map<uint256, coin::Transaction>  -- mempool-known txs
// ---------------------------------------------------------------------------

#include <map>
#include <vector>

#include "block.hpp"
#include "rpc_data.hpp"
#include "transaction.hpp"
#include "txidcache.hpp"

#include <core/uint256.hpp>
#include <core/events.hpp>

#include <nlohmann/json.hpp>

namespace dgb
{

namespace interfaces
{

struct Node
{
    Variable<dgb::coin::rpc::WorkData> work;                // get_work result
    Event<uint256> new_block;                               // block_hash
    Event<coin::Transaction> new_tx;                        // bitcoin_data.tx_type
    Event<std::vector<coin::BlockHeaderType>> new_headers;  // bitcoin_data.block_header_type
    Event<coin::BlockType> full_block;                      // full block with txs

    coin::TXIDCache txidcache;
    std::map<uint256, coin::Transaction> known_txs;
};

} // namespace interfaces

} // namespace dgb
