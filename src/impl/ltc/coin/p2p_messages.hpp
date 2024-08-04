#pragma once

#include "transaction.hpp"
#include "block.hpp"

#include <vector>

#include <core/uint256.hpp>
#include <core/netaddress.hpp>
#include <core/message.hpp>
#include <core/message_macro.hpp>

namespace ltc
{
namespace coin
{

namespace p2p
{

//[+] void handle_message_version(std::shared_ptr<coind::messages::message_version> msg, CoindProtocol* protocol); //
//[+] void handle_message_verack(std::shared_ptr<coind::messages::message_verack> msg, CoindProtocol* protocol); //
//[+] void handle_message_ping(std::shared_ptr<coind::messages::message_ping> msg, CoindProtocol* protocol); //
//[+] void handle_message_pong(std::shared_ptr<coind::messages::message_pong> msg, CoindProtocol* protocol); //
//[+] void handle_message_alert(std::shared_ptr<coind::messages::message_alert> msg, CoindProtocol* protocol); // 
//[+] void handle_message_inv(std::shared_ptr<coind::messages::message_inv> msg, CoindProtocol* protocol); //
//[+] void handle_message_tx(std::shared_ptr<coind::messages::message_tx> msg, CoindProtocol* protocol); //
//[+] void handle_message_block(std::shared_ptr<coind::messages::message_block> msg, CoindProtocol* protocol); //
//[+] void handle_message_headers(std::shared_ptr<coind::messages::message_headers> msg, CoindProtocol* protocol); //

// message_version
BEGIN_MESSAGE(version)
    MESSAGE_FIELDS
    (
        (uint32_t, m_version),
        (uint64_t, m_services),
        (uint64_t, m_timestamp),
        (addr_t , m_addr_to),
        (addr_t, m_addr_from),
        (uint64_t, m_nonce),
        (std::string, m_subversion),
        (uint32_t, m_start_height)
    )
    {
        READWRITE(obj.m_version, obj.m_services, obj.m_timestamp, obj.m_addr_to, obj.m_addr_from, obj.m_nonce, obj.m_subversion, obj.m_start_height);
    }
END_MESSAGE()

BEGIN_MESSAGE(verack)
    WITHOUT_MESSAGE_FIELDS() { }
END_MESSAGE()

BEGIN_MESSAGE(ping)
    MESSAGE_FIELDS
    (
        (uint64_t, m_nonce)
    )
    {
        READWRITE(obj.m_nonce);
    }
END_MESSAGE()

BEGIN_MESSAGE(pong)
    MESSAGE_FIELDS
    (
        (uint64_t, m_nonce)
    )
    {
        READWRITE(obj.m_nonce);
    }
END_MESSAGE()

BEGIN_MESSAGE(alert)
    MESSAGE_FIELDS
    (
        (std::string, m_message), 
        (std::string, m_signature)
    )
    {
        READWRITE(obj.m_message, obj.m_signature);
    }
END_MESSAGE()

struct inventory_type
{
    enum inv_type
    {
        tx = 1,
        block = 2
    };

    inv_type m_type;
    uint256 m_hash;

    inventory_type() { }
    inventory_type(inv_type type, uint256 hash) : m_type(type), m_hash(hash) { }

    SERIALIZE_METHODS(inventory_type) {READWRITE(Using<EnumType<IntType<32>>>(obj.m_type), obj.m_hash);}
};

BEGIN_MESSAGE(inv)
    MESSAGE_FIELDS
    (
        (std::vector<inventory_type>, m_invs)
    )
    {
        READWRITE(obj.m_invs);
    }
END_MESSAGE()

BEGIN_MESSAGE(getdata)
    MESSAGE_FIELDS
    (
        (std::vector<inventory_type>, m_requests)
    )
    {
        READWRITE(obj.m_requests);
    }
END_MESSAGE()

BEGIN_MESSAGE(getblocks)
    MESSAGE_FIELDS
    (
        (uint32_t, m_version),
        (std::vector<uint256>, m_have),
        (uint256, m_last)
    )
    {
        READWRITE(obj.m_version, obj.m_have, obj.m_last);
    }
END_MESSAGE()

BEGIN_MESSAGE(getheaders)
    MESSAGE_FIELDS
    (
        (uint32_t, m_version),
        (std::vector<uint256>, m_have),
        (uint256, m_last)
    )
    {
        READWRITE(obj.m_version, obj.m_have, obj.m_last);
    }
END_MESSAGE()

BEGIN_MESSAGE(tx)
    MESSAGE_FIELDS
    (
        (MutableTransaction, m_tx)
    )
    {
        READWRITE(TX_WITH_WITNESS(obj.m_tx));
    }
END_MESSAGE()

BEGIN_MESSAGE(block)
    MESSAGE_FIELDS
    (
        (BlockType, m_block)
    )
    {
        READWRITE(obj.m_block);
    }
END_MESSAGE()

BEGIN_MESSAGE(headers)
    MESSAGE_FIELDS
    (
        (std::vector<BlockType>, m_headers)
    )
    {
        READWRITE(obj.m_headers);
    }
END_MESSAGE()

using Handler = MessageHandler<
    message_version,
    message_verack,
    message_ping,
    message_pong,
    message_alert,
    message_inv,
    message_tx,
    message_block,
    message_headers
>;

} // namespace p2p

} // namespace coin

} // namespace ltc