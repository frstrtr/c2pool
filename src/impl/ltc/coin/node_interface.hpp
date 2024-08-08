#pragma once

#include <vector>

#include "block.hpp"
#include "transaction.hpp"

#include <core/uint256.hpp>
#include <core/events.hpp>

#include <nlohmann/json.hpp>

namespace ltc::coin::p2p
{

namespace interfaces
{

struct Node
{
	Event<nlohmann::json> m_work;								//get_work result
    Event<uint256> m_new_block;									//block_hash
	Event<coin::Transaction> m_new_tx;							//bitcoin_data.tx_type
	Event<std::vector<coin::BlockHeaderType>> m_new_headers;	//bitcoin_data.block_header_type

};

} // namespace interfaces

} // namespace ltc::coin::p2p


