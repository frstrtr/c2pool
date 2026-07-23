// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <map>
#include <vector>

#include "block.hpp"
#include "rpc_data.hpp"
#include "transaction.hpp"
#include "txidcache.hpp"

#include <core/uint256.hpp>
#include <core/events.hpp>

#include <nlohmann/json.hpp>

// ---------------------------------------------------------------------------
// bch::interfaces::Node -- ported from src/impl/btc/coin/node_interface.hpp.
//
// Coin-agnostic in shape; the per-coin types it aggregates are the bch::coin
// ports landed in M3 slices 1-2 (rpc::WorkData, Transaction, BlockHeaderType,
// BlockType, TXIDCache).
//
// >>> BCH DIVERGENCE (M1 4.1): NO MWEB <<<
// The BTC source documented full_block as "full block with txs + MWEB data".
// MWEB is a Litecoin extension-block construct and has no analogue on BCH, so
// full_block here carries the plain BlockType only -- no extension payload.
// ---------------------------------------------------------------------------

namespace bch
{

namespace interfaces
{

struct Node
{
	Variable<bch::coin::rpc::WorkData> work;				// get_work result
	Event<uint256> new_block;								// block_hash
	Event<coin::Transaction> new_tx;						// bitcoin_data.tx_type
	Event<std::vector<coin::BlockHeaderType>> new_headers;	// bitcoin_data.block_header_type
	Event<coin::BlockType> full_block;						// full block with txs (no MWEB on BCH)

	coin::TXIDCache txidcache;
	std::map<uint256, coin::Transaction> known_txs; // TODO: move to other?
};

} // namespace interfaces

} // namespace bch