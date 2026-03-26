#pragma once

#include "transaction.hpp"

#include <core/uint256.hpp>
#include <core/pack_types.hpp>
#include <core/netaddress.hpp>

namespace ltc
{

namespace coin
{

struct SmallBlockHeaderType
{
    uint64_t m_version {};
    uint256 m_previous_block{};
    uint32_t m_timestamp{};
    uint32_t m_bits{};
    uint32_t m_nonce{};

    SERIALIZE_METHODS(SmallBlockHeaderType) { READWRITE(VarInt(obj.m_version), obj.m_previous_block, obj.m_timestamp, obj.m_bits, obj.m_nonce); }

    SmallBlockHeaderType() {}

    void SetNull()
    {
        m_version = 0;
        m_previous_block.SetNull();
        m_timestamp = 0;
        m_bits = 0;
        m_nonce = 0;
    }

    bool IsNull() const
    {
        return (m_bits == 0);
    }
};

struct BlockHeaderType : SmallBlockHeaderType
{
    uint256 m_merkle_root;

    // Full block header uses fixed 4-byte int32 version (not VarInt like SmallBlockHeaderType)
    template<typename Stream>
    void Serialize(Stream& s) const {
        uint32_t version32 = static_cast<uint32_t>(m_version);
        ::Serialize(s, version32);
        ::Serialize(s, m_previous_block);
        ::Serialize(s, m_merkle_root);
        ::Serialize(s, m_timestamp);
        ::Serialize(s, m_bits);
        ::Serialize(s, m_nonce);
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        uint32_t version32;
        ::Unserialize(s, version32);
        m_version = version32;
        ::Unserialize(s, m_previous_block);
        ::Unserialize(s, m_merkle_root);
        ::Unserialize(s, m_timestamp);
        ::Unserialize(s, m_bits);
        ::Unserialize(s, m_nonce);
    }

    BlockHeaderType() : SmallBlockHeaderType() { }

    void SetNull()
    {
        SmallBlockHeaderType::SetNull();
        m_merkle_root.SetNull();
    }

    bool IsNull() const
    {
        return (m_bits == 0);
    }

};

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