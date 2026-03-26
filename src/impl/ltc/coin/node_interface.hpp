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

namespace ltc
{

namespace interfaces
{

struct Node
{
	Variable<ltc::coin::rpc::WorkData> work;							//get_work result
    Event<uint256> new_block;								//block_hash
	Event<coin::Transaction> new_tx;						//bitcoin_data.tx_type
	Event<std::vector<coin::BlockHeaderType>> new_headers;	//bitcoin_data.block_header_type
	Event<coin::BlockType> full_block;						// full block with txs + MWEB data

	coin::TXIDCache txidcache;
	std::map<uint256, coin::Transaction> known_txs; // TODO: move to other?
};

} // namespace interfaces

} // namespace ltc::coin


