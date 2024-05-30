#pragma once

#include <string>

#include <core/pack.hpp>

#include <pool/message.hpp>
#include <pool/message_macro.hpp>

namespace ltc
{

// TODO: message_version
BEGIN_MESSAGE(version)
    MESSAGE_FIELDS
    (
        (uint32_t, m_version),
        (uint64_t, m_services),
        //TODO: address_type addr_to
        //TODO: address_type addr_from
        (uint64_t, m_nonce),
        (std::string, m_subversion),
        (uint32_t, m_mode) //# always 1 for legacy compatibility
        //TODO: PossibleNoneType<IntType(256)> m_best_share;
    )
    {
        READWRITE(obj.m_version, obj.m_services, /*m_addr_to, m_addr_from,*/ obj.m_nonce, obj.m_subversion, obj.m_mode/*, m_best_share*/);
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

// TODO: message_addrs
// BEGIN_MESSAGE(addrs)
//     MESSAGE_FIELDS
//     (
//         //TODO: (std::vector<addr_type, m_addrs)
//     )
//     {
//         READWRITE(obj.m_addrs);
//     }
// END_MESSAGE()

// TODO: message_shares
// BEGIN_MESSAGE(shares)
//     MESSAGE_FIELDS
//     (
//         //TODO: (std::vector<PackedShareData, m_shares)
//     )
//     {
//         READWRITE(obj.m_shares);
//     }
// END_MESSAGE()

// TODO: message_sharereq
// BEGIN_MESSAGE(sharereq)
//     MESSAGE_FIELDS
//     (
//         (uint256, m_id),
//         (std::vector<uint256>, m_hashes),
//         (VarIntType, m_parents),
//         (std::vector<uint256> m_stops)
//     )
//     {
//         READWRITE(obj.m_id, obj.m_hashes, obj.m_parents, obj.m_stops);
//     }
// END_MESSAGE()

// TODO: message_sharereply
// BEGIN_MESSAGE(sharereply)
//     MESSAGE_FIELDS
//     (
//         (uint256, m_id),
//         (EnumType<ShareReplyResult, VarIntType>, m_result),
//         (std::vector<PackedShareData>, m_shares)
//     )
//     {
//         READWRITE(obj.m_id, obj.m_result, obj.m_shares);
//     }
// END_MESSAGE()

// TODO: message_bestblock
// BEGIN_MESSAGE(bestblock)
//     MESSAGE_FIELDS
//     (
//         (BlockHeaderType, m_header),
//     )
//     {
//         READWRITE(obj.m_header);
//     }
// END_MESSAGE()

// TODO: message_have_tx
// BEGIN_MESSAGE(have_tx)
//     MESSAGE_FIELDS
//     (
//         (std::vector<uint256>, m_tx_hashes)
//     )
//     {
//         READWRITE(obj.m_tx_hashes);
//     }
// END_MESSAGE()

// TODO: message_losing_tx
// BEGIN_MESSAGE(losing_tx)
//     MESSAGE_FIELDS
//     (
//         (std::vector<uint256>, m_tx_hashes)
//     )
//     {
//         READWRITE(obj.m_tx_hashes);
//     }
// END_MESSAGE()

// TODO: message_forget_tx
// BEGIN_MESSAGE(forget_tx)
//     MESSAGE_FIELDS
//     (
//         (std::vector<uint256>, m_tx_hashes)
//     )
//     {
//         READWRITE(obj.m_tx_hashes);
//     }
// END_MESSAGE()

// TODO: message_remember_tx
// BEGIN_MESSAGE(remember_tx)
//     MESSAGE_FIELDS
//     (
//         (std::vector<uint256>, m_tx_hashes),
//         (std::vector<ltc::tx_type> m_txs)
//     )
//     {
//         READWRITE(obj.m_tx_hashes, obj.m_txs);
//     }
// END_MESSAGE()

} // namespace ltc
