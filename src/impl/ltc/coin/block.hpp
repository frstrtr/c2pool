#pragma once

// LTC block types: inherit generic headers from bitcoin_family,
// extend BlockType with MWEB (MimbleWimble Extension Blocks) support.

#include "transaction.hpp"
#include <impl/bitcoin_family/coin/base_block.hpp>

#include <core/uint256.hpp>
#include <core/pack_types.hpp>
#include <core/netaddress.hpp>

namespace ltc
{

namespace coin
{

// Import generic header types from bitcoin_family
using bitcoin_family::coin::SmallBlockHeaderType;
using bitcoin_family::coin::BlockHeaderType;

// LTC-specific BlockType: extends BlockHeaderType with MWEB support.
// Dash/BTC/DOGE would use a simpler BlockType without m_mweb_raw.
struct BlockType : BlockHeaderType
{
	std::vector<MutableTransaction> m_txs;
	// MWEB extension block raw bytes (present when last tx is HogEx).
	// Includes the OptionalPtr presence byte (0x01) + mw::Block serialized data.
	std::vector<unsigned char> m_mweb_raw;

    template <typename Stream>
    void Serialize(Stream& s) const {
        // Header
        BlockHeaderType::Serialize(s);
        // Transactions (with witness)
        ::Serialize(s, TX_WITH_WITNESS(m_txs));
        // MWEB extension: if we have HogEx (last tx), write MWEB data
        if (!m_txs.empty() && m_txs.back().m_hogEx && !m_mweb_raw.empty()) {
            // Write OptionalPtr(0x01) + raw mw::Block bytes
            uint8_t presence = 0x01;
            ::Serialize(s, presence);
            // Write raw MWEB bytes directly via span
            auto sp = std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(m_mweb_raw.data()), m_mweb_raw.size());
            s.write(sp);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        // Header
        BlockHeaderType::Unserialize(s);
        // Transactions (with witness — handles MWEB flag 0x08 for HogEx)
        ::Unserialize(s, TX_WITH_WITNESS(m_txs));
        // MWEB extension: if last tx is HogEx, read the MWEB block data
        m_mweb_raw.clear();
        if (m_txs.size() >= 2 && m_txs.back().m_hogEx) {
            // Read OptionalPtr presence byte
            uint8_t presence = 0;
            ::Unserialize(s, presence);
            if (presence == 0x01) {
                // Read remaining bytes as raw MWEB block data (mw::Block serialized).
                size_t remaining = s.cursor_size();
                if (remaining > 0) {
                    m_mweb_raw.resize(remaining);
                    auto sp = std::span<std::byte>(
                        reinterpret_cast<std::byte*>(m_mweb_raw.data()), remaining);
                    s.read(sp);
                }
            }
        }
    }

    BlockType() : BlockHeaderType() { }

    void SetNull()
    {
        BlockHeaderType::SetNull();
        m_mweb_raw.clear();
    }

    bool IsNull() const
    {
        return BlockHeaderType::IsNull();
    }
};

} // namespace coin

} // namespace ltc
