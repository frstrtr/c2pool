#pragma once

// Dash p2pool P2P protocol messages.
// Same wire format as LTC p2pool but different identifier/prefix.
// Protocol version 1700.

#include "coin/block.hpp"

#include <string>

#include <core/message.hpp>
#include <core/message_macro.hpp>
#include <sharechain/share.hpp>

namespace dash
{

// message_version (p2pool handshake)
BEGIN_MESSAGE(version)
    MESSAGE_FIELDS
    (
        (uint32_t, m_version),
        (uint64_t, m_services),
        (addr_t, m_addr_to),
        (addr_t, m_addr_from),
        (uint64_t, m_nonce),
        (std::string, m_subversion),
        (uint32_t, m_mode),
        (uint256, m_best_share)
    )
    {
        READWRITE(obj.m_version, obj.m_services, obj.m_addr_to, obj.m_addr_from, obj.m_nonce, obj.m_subversion, obj.m_mode, obj.m_best_share);
    }
END_MESSAGE()

BEGIN_MESSAGE(ping)
    WITHOUT_MESSAGE_FIELDS() { }
END_MESSAGE()

BEGIN_MESSAGE(addrme)
    MESSAGE_FIELDS
    (
        (uint16_t, m_port)
    )
    {
        READWRITE(obj.m_port);
    }
END_MESSAGE()

BEGIN_MESSAGE(getaddrs)
    MESSAGE_FIELDS
    (
        (uint32_t, m_count)
    )
    {
        READWRITE(obj.m_count);
    }
END_MESSAGE()

BEGIN_MESSAGE(addrs)
    MESSAGE_FIELDS
    (
        (std::vector<addr_record_t>, m_addrs)
    )
    {
        READWRITE(obj.m_addrs);
    }
END_MESSAGE()

BEGIN_MESSAGE(shares)
    MESSAGE_FIELDS
    (
        (std::vector<chain::RawShare>, m_shares)
    )
    {
        READWRITE(obj.m_shares);
    }
END_MESSAGE()

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
};

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

BEGIN_MESSAGE(bestblock)
    MESSAGE_FIELDS
    (
        (coin::BlockHeaderType, m_header)
    )
    {
        READWRITE(obj.m_header);
    }
END_MESSAGE()

BEGIN_MESSAGE(have_tx)
    MESSAGE_FIELDS
    (
        (std::vector<uint256>, m_tx_hashes)
    )
    {
        READWRITE(obj.m_tx_hashes);
    }
END_MESSAGE()

BEGIN_MESSAGE(losing_tx)
    MESSAGE_FIELDS
    (
        (std::vector<uint256>, m_tx_hashes)
    )
    {
        READWRITE(obj.m_tx_hashes);
    }
END_MESSAGE()

BEGIN_MESSAGE(forget_tx)
    MESSAGE_FIELDS
    (
        (std::vector<uint256>, m_tx_hashes)
    )
    {
        READWRITE(obj.m_tx_hashes);
    }
END_MESSAGE()

BEGIN_MESSAGE(remember_tx)
    MESSAGE_FIELDS
    (
        (std::vector<uint256>, m_tx_hashes),
        (std::vector<coin::MutableTransaction>, m_txs)
    )
    {
        READWRITE(obj.m_tx_hashes, obj.m_txs);
    }
END_MESSAGE()

using Handler = MessageHandler<
    message_ping,
    message_addrme,
    message_getaddrs,
    message_addrs,
    message_shares,
    message_sharereq,
    message_sharereply,
    message_bestblock,
    message_have_tx,
    message_losing_tx,
    message_forget_tx,
    message_remember_tx
>;

} // namespace dash
