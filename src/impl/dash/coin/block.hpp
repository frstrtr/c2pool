// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Dash block types: standard Bitcoin 80-byte header, no MWEB.
// Uses generic headers from bitcoin_family.
//
// NOTE: the `m_txs` block-body member below was ADVANCED FROM S5 (block-replay)
// into the S4-pre foundation (branch dash/pr0-foundation-s4) to close
// credit_pool.apply_block(), which walks block.m_txs for asset-lock/unlock
// accounting. This is the SINGLE canonical declaration of the member.
//
// E2a (#738) closes the S5 deferral: BlockType now (de)serializes m_txs as the
// standard Bitcoin block body (CompactSize tx-count + txs), mirroring the DGB
// sibling (src/impl/dgb/coin/block.hpp) minus witness (Dash is non-segwit, non-
// MWEB). This is what a live dashd `block` message body needs to deserialize
// into the tx set the embedded ingest legs consume, and it makes the multi-entry
// `headers` message round-trip too: on the wire each `headers` entry is an 80-
// byte header followed by a CompactSize(0) tx-count, which now deserializes as a
// header + empty m_txs. The E1 coin-P2P client explicitly deferred this parser
// to E2a.

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
    // Block body. E2a: transaction-aware (de)serialization below. Dash is
    // non-segwit / non-MWEB, so the tx vector is the plain CompactSize-prefixed
    // MutableTransaction sequence (MutableTransaction carries its own Dash
    // version|type<<16 + extra_payload codec) — no TX_WITH_WITNESS wrapper.
    std::vector<MutableTransaction> m_txs;

    template <typename Stream>
    void Serialize(Stream& s) const {
        BlockHeaderType::Serialize(s);
        ::Serialize(s, m_txs);
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        BlockHeaderType::Unserialize(s);
        ::Unserialize(s, m_txs);
    }

    BlockType() : BlockHeaderType() { }
    void SetNull() { BlockHeaderType::SetNull(); m_txs.clear(); }
    bool IsNull() const { return BlockHeaderType::IsNull(); }
};

} // namespace coin
} // namespace dash