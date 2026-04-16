#pragma once

// Dash block types: standard Bitcoin 80-byte header, no MWEB.
// Uses generic headers from bitcoin_family, adds simple BlockType.

#include <impl/bitcoin_family/coin/base_block.hpp>
#include <impl/bitcoin_family/coin/base_transaction.hpp>

#include <core/pack_types.hpp>

#include <vector>

namespace dash
{
namespace coin
{

// Import generic header types from bitcoin_family
using bitcoin_family::coin::SmallBlockHeaderType;
using bitcoin_family::coin::BlockHeaderType;

// Forward declaration
struct MutableTransaction;

// Dash BlockType: standard Bitcoin block (header + transactions).
// No MWEB, no HogEx — simpler than LTC's BlockType.
struct BlockType : BlockHeaderType
{
    std::vector<MutableTransaction> m_txs;

    template <typename Stream>
    void Serialize(Stream& s) const {
        BlockHeaderType::Serialize(s);
        // TODO: Serialize with proper tx params once DashTransaction is complete
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        BlockHeaderType::Unserialize(s);
        // TODO: Unserialize transactions
    }

    BlockType() : BlockHeaderType() { }

    void SetNull() { BlockHeaderType::SetNull(); }
    bool IsNull() const { return BlockHeaderType::IsNull(); }
};

} // namespace coin
} // namespace dash
