#pragma once

#include <vector>

#include "block.hpp"
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
	Variable<nlohmann::json> work;							//get_work result
    Event<uint256> new_block;								//block_hash
	Event<coin::Transaction> new_tx;						//bitcoin_data.tx_type
	Event<std::vector<coin::BlockHeaderType>> new_headers;	//bitcoin_data.block_header_type

	coin::TXIDCache txid_cache;
};

} // namespace interfaces

} // namespace ltc::coin


