#pragma once

// Dash block types: standard Bitcoin 80-byte header, no MWEB.
// Uses generic headers from bitcoin_family.
//
// NOTE: the `m_txs` block-body member below was ADVANCED FROM S5 (block-replay)
// into the S4-pre foundation (branch dash/pr0-foundation-s4) to close
// credit_pool.apply_block(), which walks block.m_txs for asset-lock/unlock
// accounting. This is the SINGLE canonical declaration of the member: S5 builds
// on it (adding the transaction-aware (de)serialization of m_txs) rather than
// re-authoring it, to avoid a double-add collision on this struct.
//
// S3/S4-pre serialization stays HEADER-ONLY here; transaction-aware
// (de)serialization of m_txs remains deferred to S5 along with the wire format.

#include <impl/bitcoin_family/coin/base_block.hpp>
#include <impl/dash/coin/transaction.hpp>  // complete MutableTransaction for m_txs member

#include <vector>

namespace dash
{
namespace coin
{

using bitcoin_family::coin::SmallBlockHeaderType;
using bitcoin_family::coin::BlockHeaderType;

struct BlockType : BlockHeaderType
{
    // Advanced from S5 to close credit_pool.apply_block(). Transaction-aware
    // (de)serialization of this member lands in S5; not serialized here.
    std::vector<MutableTransaction> m_txs;

    template <typename Stream>
    void Serialize(Stream& s) const {
        BlockHeaderType::Serialize(s);
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        BlockHeaderType::Unserialize(s);
    }

    BlockType() : BlockHeaderType() { }
    void SetNull() { BlockHeaderType::SetNull(); m_txs.clear(); }
    bool IsNull() const { return BlockHeaderType::IsNull(); }
};

} // namespace coin
} // namespace dash
