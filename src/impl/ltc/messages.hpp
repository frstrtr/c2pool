#pragma once

#include "types.hpp"
#include "transaction.hpp"

#include <string>

#include <core/message.hpp>
#include <pool/message_macro.hpp>
#include <sharechain/share.hpp>

namespace ltc
{

// message_version
BEGIN_MESSAGE(version)
    MESSAGE_FIELDS
    (
        (uint32_t, m_version),
        (uint64_t, m_services),
        (addr_t , m_addr_to),
        (addr_t, m_addr_from),
        (uint64_t, m_nonce),
        (std::string, m_subversion),
        (uint32_t, m_mode), //# always 1 for legacy compatibility
        (uint256, m_best_share)
    )
    {
        READWRITE(obj.m_version, obj.m_services, obj.m_addr_to, obj.m_addr_from, obj.m_nonce, obj.m_subversion, obj.m_mode, obj.m_best_share);
    }
END_MESSAGE()

// message_ping
BEGIN_MESSAGE(ping)
    WITHOUT_MESSAGE_FIELDS() { }
END_MESSAGE()

// message_addrme
BEGIN_MESSAGE(addrme)
    MESSAGE_FIELDS
    (
        (uint16_t, m_port)
    )
    {
        READWRITE(obj.m_port);
    }
END_MESSAGE()

// message_getaddrs
BEGIN_MESSAGE(getaddrs)
    MESSAGE_FIELDS
    (
        (uint32_t, m_count)
    )
    {
        READWRITE(obj.m_count);
    }
END_MESSAGE()

// message_addrs
BEGIN_MESSAGE(addrs)
    MESSAGE_FIELDS
    (
        (std::vector<addr_record_t>, m_addrs)
    )
    {
        READWRITE(obj.m_addrs);
    }
END_MESSAGE()

// message_shares
BEGIN_MESSAGE(shares)
    MESSAGE_FIELDS
    (
        (std::vector<chain::RawShare>, m_shares)
    )
    {
        READWRITE(obj.m_shares);
    }
END_MESSAGE()

// message_sharereq
BEGIN_MESSAGE(sharereq)
    MESSAGE_FIELDS
    (
        (uint256, m_id),
        (std::vector<uint256>, m_hashes),
        (uint64_t, m_parents),
        (std::vector<uint256>, m_stops)
    )
    {
        READWRITE(obj.m_id, obj.m_hashes, VarInt(obj.m_parents), obj.m_stops);
    }
END_MESSAGE()

enum ShareReplyResult
{
    good = 0,
    too_long = 1,
    unk2 = 2,
    unk3 = 3,
    unk4 = 4,
    unk5 = 5,
    unk6 = 6
};

// message_sharereply
BEGIN_MESSAGE(sharereply)
    MESSAGE_FIELDS
    (
        (uint256, m_id),
        (ShareReplyResult, m_result),
        (std::vector<chain::RawShare>, m_shares)
    )
    {
        READWRITE(obj.m_id, Using<EnumType<CompactFormat>>(obj.m_result), obj.m_shares);
    }
END_MESSAGE()

// message_bestblock
BEGIN_MESSAGE(bestblock)
    MESSAGE_FIELDS
    (
        (ltc::BlockHeaderType, m_header)
    )
    {
        READWRITE(obj.m_header);
    }
END_MESSAGE()

// message_have_tx
BEGIN_MESSAGE(have_tx)
    MESSAGE_FIELDS
    (
        (std::vector<uint256>, m_tx_hashes)
    )
    {
        READWRITE(obj.m_tx_hashes);
    }
END_MESSAGE()

// message_losing_tx
BEGIN_MESSAGE(losing_tx)
    MESSAGE_FIELDS
    (
        (std::vector<uint256>, m_tx_hashes)
    )
    {
        READWRITE(obj.m_tx_hashes);
    }
END_MESSAGE()

// message_forget_tx
BEGIN_MESSAGE(forget_tx)
    MESSAGE_FIELDS
    (
        (std::vector<uint256>, m_tx_hashes)
    )
    {
        READWRITE(obj.m_tx_hashes);
    }
END_MESSAGE()

// message_remember_tx
BEGIN_MESSAGE(remember_tx)
    MESSAGE_FIELDS
    (
        (std::vector<uint256>, m_tx_hashes),
        (std::vector<ltc::MutableTransaction>, m_txs)
    )
    {
        READWRITE(obj.m_tx_hashes, ltc::TX_WITH_WITNESS(obj.m_txs));
    }
END_MESSAGE()

} // namespace ltc
