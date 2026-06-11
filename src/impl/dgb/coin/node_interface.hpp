#pragma once

// ---------------------------------------------------------------------------
// dgb::interfaces::Node -- coin-node shared-state surface (Path A
// minimal-stub). Mirrors src/impl/btc/coin/node_interface.hpp TRIMMED to the
// members the family-1 ICoinNode seam actually binds today:
//
//   work      : Variable<rpc::WorkData> -- get_work result (NodeRPC fills,
//               CoinNode retains coin-side per the WorkView seam contract)
//   new_block : Event<uint256>          -- block-hash announce (header-chain
//               feed; uint256 only, no per-coin type needed)
//
// Deliberately ABSENT until the M3 type ports land (each pulls a type dgb
// does not have yet): Event<Transaction> new_tx, Event<vector<
// BlockHeaderType>> new_headers, Event<BlockType> full_block, TXIDCache
// txidcache, known_txs map. Restoring them is additive; nothing in the seam
// depends on their absence.
// ---------------------------------------------------------------------------

#include <core/events.hpp>
#include <core/uint256.hpp>

#include "rpc_data.hpp"

namespace dgb
{

namespace interfaces
{

struct Node
{
    Variable<dgb::coin::rpc::WorkData> work; // get_work result
    Event<uint256> new_block;                // block_hash
};

} // namespace interfaces

} // namespace dgb
