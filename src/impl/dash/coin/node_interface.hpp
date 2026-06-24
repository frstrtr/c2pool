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

    // SPV A1 (parity audit): fires when dashd announces a ChainLock has
    // been aggregated for a block. Carries {block_hash, height}.
    // Consumers (e.g. block-find submit handler) can consult
    // m_chainlocked_blocks to know whether a found block is now
    // irreversible.
    Event<std::pair<uint256, int32_t>> new_chainlock;
    std::map<uint256, int32_t> chainlocked_blocks; // block_hash → height

    std::map<uint256, coin::Transaction> known_txs;
};

} // namespace interfaces
} // namespace dash
