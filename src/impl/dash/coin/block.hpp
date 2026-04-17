#pragma once

// Dash block types: standard Bitcoin 80-byte header, no MWEB.
// Uses generic headers from bitcoin_family, adds simple BlockType.

#include <impl/bitcoin_family/coin/base_block.hpp>

#include <core/pack_types.hpp>

#include <vector>

namespace dash
{
namespace coin
{

using bitcoin_family::coin::SmallBlockHeaderType;
using bitcoin_family::coin::BlockHeaderType;

struct MutableTransaction;

struct BlockType : BlockHeaderType
{
    std::vector<MutableTransaction> m_txs;

    template <typename Stream>
    void Serialize(Stream& s) const {
        BlockHeaderType::Serialize(s);
        s << m_txs;
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        BlockHeaderType::Unserialize(s);
        s >> m_txs;
    }

    BlockType() : BlockHeaderType() { }
    void SetNull() { BlockHeaderType::SetNull(); m_txs.clear(); }
    bool IsNull() const { return BlockHeaderType::IsNull(); }
};

} // namespace coin
} // namespace dash
