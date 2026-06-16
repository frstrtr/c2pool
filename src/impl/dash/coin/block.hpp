#pragma once

// Dash block types: standard Bitcoin 80-byte header, no MWEB.
// Uses generic headers from bitcoin_family.
//
// S3 (SPV header-chain) consumes headers only, so BlockType is a header-only
// block here. The full block body (std::vector<MutableTransaction> m_txs +
// transaction-aware (de)serialization) lands in S5 (block-replay) together
// with the dash transaction type; defining it now would force a complete
// MutableTransaction that S3 does not yet provide.

#include <impl/bitcoin_family/coin/base_block.hpp>

namespace dash
{
namespace coin
{

using bitcoin_family::coin::SmallBlockHeaderType;
using bitcoin_family::coin::BlockHeaderType;

struct BlockType : BlockHeaderType
{
    template <typename Stream>
    void Serialize(Stream& s) const {
        BlockHeaderType::Serialize(s);
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        BlockHeaderType::Unserialize(s);
    }

    BlockType() : BlockHeaderType() { }
    void SetNull() { BlockHeaderType::SetNull(); }
    bool IsNull() const { return BlockHeaderType::IsNull(); }
};

} // namespace coin
} // namespace dash
