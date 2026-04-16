#pragma once

// Generic Bitcoin wire protocol message types.
// Messages that don't reference coin-specific block/tx types are defined directly.
// Messages that reference BlockType/Transaction (block, tx, headers) must be
// defined per-coin since block/tx structures differ (LTC has MWEB, Dash has no segwit).
//
// This file provides: version, verack, ping, pong, alert, inventory_type,
// inv, getdata, getblocks, getheaders, getaddr, addr, reject, sendheaders,
// notfound, feefilter, mempool, sendcmpct, wtxidrelay, sendaddrv2,
// btc_addr_record_t.

#include <impl/bitcoin_family/coin/base_block.hpp>

#include <vector>

#include <core/uint256.hpp>
#include <core/netaddress.hpp>
#include <core/message.hpp>
#include <core/message_macro.hpp>

namespace bitcoin_family
{
namespace coin
{
namespace p2p
{

// Bitcoin wire protocol uses uint32_t timestamp in addr messages,
// unlike the pool protocol which uses uint64_t.
struct btc_addr_record_t : addr_t
{
    uint32_t m_timestamp{};

    btc_addr_record_t() : addr_t() {}

    SERIALIZE_METHODS(btc_addr_record_t) { READWRITE(obj.m_timestamp, AsBase<addr_t>(obj)); }
};

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
    enum inv_type : uint32_t
    {
        tx              = 1,
        block           = 2,
        filtered_block  = 3,
        cmpct_block     = 4,
        wtx             = 5,            // MSG_WTX (BIP 339)
        witness_tx      = 0x40000001,   // MSG_WITNESS_TX (BIP 144)
        witness_block   = 0x40000002,   // MSG_WITNESS_BLOCK (BIP 144)
    };

    static constexpr uint32_t MSG_WITNESS_FLAG = 0x40000000;

    inv_type m_type;
    uint256 m_hash;

    inventory_type() { }
    inventory_type(inv_type type, uint256 hash) : m_type(type), m_hash(hash) { }

    inv_type base_type() const
    {
        return static_cast<inv_type>(static_cast<uint32_t>(m_type) & ~MSG_WITNESS_FLAG);
    }

    bool is_witness() const
    {
        return (static_cast<uint32_t>(m_type) & MSG_WITNESS_FLAG) != 0;
    }

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

// P2P address discovery
BEGIN_MESSAGE(getaddr)
    WITHOUT_MESSAGE_FIELDS() { }
END_MESSAGE()

BEGIN_MESSAGE(addr)
    MESSAGE_FIELDS
    (
        (std::vector<btc_addr_record_t>, m_addrs)
    )
    {
        READWRITE(obj.m_addrs);
    }
END_MESSAGE()

// BIP 61 — reject
BEGIN_MESSAGE(reject)
    MESSAGE_FIELDS
    (
        (std::string, m_message),
        (uint8_t, m_ccode),
        (std::string, m_reason),
        (uint256, m_data)
    )
    {
        READWRITE(obj.m_message, obj.m_ccode, obj.m_reason, obj.m_data);
    }
END_MESSAGE()

// BIP 130 — sendheaders
BEGIN_MESSAGE(sendheaders)
    WITHOUT_MESSAGE_FIELDS() { }
END_MESSAGE()

// notfound
BEGIN_MESSAGE(notfound)
    MESSAGE_FIELDS
    (
        (std::vector<inventory_type>, m_invs)
    )
    {
        READWRITE(obj.m_invs);
    }
END_MESSAGE()

// BIP 133 — feefilter
BEGIN_MESSAGE(feefilter)
    MESSAGE_FIELDS
    (
        (uint64_t, m_feerate)
    )
    {
        READWRITE(obj.m_feerate);
    }
END_MESSAGE()

// BIP 35 — mempool
BEGIN_MESSAGE(mempool)
    WITHOUT_MESSAGE_FIELDS() { }
END_MESSAGE()

// BIP 152 — sendcmpct (negotiation only — actual compact block messages
// are coin-specific because they reference coin's BlockType)
BEGIN_MESSAGE(sendcmpct)
    MESSAGE_FIELDS
    (
        (bool, m_announce),
        (uint64_t, m_version)
    )
    {
        READWRITE(obj.m_announce, obj.m_version);
    }
END_MESSAGE()

// BIP 339 — wtxidrelay
BEGIN_MESSAGE(wtxidrelay)
    WITHOUT_MESSAGE_FIELDS() { }
END_MESSAGE()

// BIP 155 — sendaddrv2
BEGIN_MESSAGE(sendaddrv2)
    WITHOUT_MESSAGE_FIELDS() { }
END_MESSAGE()

} // namespace p2p
} // namespace coin
} // namespace bitcoin_family
