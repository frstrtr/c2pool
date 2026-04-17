#pragma once

#include "block.hpp"
#include "transaction.hpp"

#include <core/uint256.hpp>
#include <core/events.hpp>

#include <map>
#include <vector>

namespace dash
{
namespace interfaces
{

struct Node
{
    Variable<uint256> best_block_hash;
    Event<uint256> new_block;
    Event<coin::Transaction> new_tx;
    Event<std::vector<coin::BlockHeaderType>> new_headers;
    Event<coin::BlockType> full_block;

    std::map<uint256, coin::Transaction> known_txs;
};

} // namespace interfaces
} // namespace dash
