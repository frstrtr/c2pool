#pragma once

#include <vector>

#include "block.hpp"
#include "transaction.hpp"

#include <core/uint256.hpp>
#include <core/events.hpp>
    
namespace ltc
{
    
namespace coin
{

namespace p2p
{

namespace interfaces
{

struct Node
{
    Event<uint256> m_new_block;                               //block_hash
	Event<coin::Transaction> m_new_tx;                        //bitcoin_data.tx_type
	Event<std::vector<coin::BlockHeaderType>> m_new_headers;  //bitcoin_data.block_header_type

};

} // namespace interfaces

} // namespace p2p

} // namespace coin

} // namespace ltc


