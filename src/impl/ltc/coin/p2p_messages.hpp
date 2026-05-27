#pragma once

// LTC coin daemon P2P messages.
// Generic messages (version, ping, inv, etc.) imported from bitcoin_family.
// Coin-specific messages (block, tx, headers, compact blocks) defined here
// because they reference LTC's BlockType and MutableTransaction (MWEB-aware).

#include "transaction.hpp"
#include "block.hpp"
#include "compact_blocks.hpp"

#include <impl/bitcoin_family/coin/base_p2p_messages.hpp>

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

// Import all generic messages from bitcoin_family
using bitcoin_family::coin::p2p::btc_addr_record_t;
using bitcoin_family::coin::p2p::message_version;
using bitcoin_family::coin::p2p::message_verack;
using bitcoin_family::coin::p2p::message_ping;
using bitcoin_family::coin::p2p::message_pong;
using bitcoin_family::coin::p2p::message_alert;
using bitcoin_family::coin::p2p::inventory_type;
using bitcoin_family::coin::p2p::message_inv;
using bitcoin_family::coin::p2p::message_getdata;
using bitcoin_family::coin::p2p::message_getblocks;
using bitcoin_family::coin::p2p::message_getheaders;
using bitcoin_family::coin::p2p::message_getaddr;
using bitcoin_family::coin::p2p::message_addr;
using bitcoin_family::coin::p2p::message_reject;
using bitcoin_family::coin::p2p::message_sendheaders;
using bitcoin_family::coin::p2p::message_notfound;
using bitcoin_family::coin::p2p::message_feefilter;
using bitcoin_family::coin::p2p::message_mempool;
using bitcoin_family::coin::p2p::message_sendcmpct;
using bitcoin_family::coin::p2p::message_wtxidrelay;
using bitcoin_family::coin::p2p::message_sendaddrv2;

// ── LTC-specific messages (reference MWEB-aware BlockType/Transaction) ──

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
        (BlockType, m_block),
        (std::vector<uint8_t>, m_raw_payload)
    )
    {
        READWRITE(obj.m_block);
    }
END_MESSAGE()

BEGIN_MESSAGE(headers)
    MESSAGE_FIELDS
    (
        (std::vector<BlockType>, m_headers),
        (std::vector<uint8_t>, m_raw_payload)
    )
    {
        READWRITE(obj.m_headers);
    }
END_MESSAGE()

// BIP 152 — cmpctblock (HeaderAndShortIDs)
class message_cmpctblock : public Message {
private:
    using message_type = message_cmpctblock;
public:
    message_cmpctblock() : Message("cmpctblock") {}

    CompactBlock m_compact_block;

    static std::unique_ptr<RawMessage> make_raw(const CompactBlock& cb) {
        auto temp = std::make_unique<message_type>();
        temp->m_compact_block = cb;
        auto result = std::make_unique<RawMessage>(temp->m_command, pack(*temp));
        return result;
    }
    static std::unique_ptr<RawMessage> make_raw() {
        return std::make_unique<RawMessage>("cmpctblock", PackStream{});
    }
    static std::unique_ptr<message_type> make(PackStream& stream) {
        auto result = std::make_unique<message_type>();
        stream >> *result;
        return result;
    }
    template<typename Stream> void Serialize(Stream& s) const { m_compact_block.Serialize(s); }
    template<typename Stream> void Unserialize(Stream& s) { m_compact_block.Unserialize(s); }
};

// BIP 152 — getblocktxn (request missing transactions)
class message_getblocktxn : public Message {
private:
    using message_type = message_getblocktxn;
public:
    message_getblocktxn() : Message("getblocktxn") {}

    BlockTransactionsRequest m_request;

    static std::unique_ptr<RawMessage> make_raw(const BlockTransactionsRequest& req) {
        auto temp = std::make_unique<message_type>();
        temp->m_request = req;
        auto result = std::make_unique<RawMessage>(temp->m_command, pack(*temp));
        return result;
    }
    static std::unique_ptr<RawMessage> make_raw() {
        return std::make_unique<RawMessage>("getblocktxn", PackStream{});
    }
    static std::unique_ptr<message_type> make(PackStream& stream) {
        auto result = std::make_unique<message_type>();
        stream >> *result;
        return result;
    }
    template<typename Stream> void Serialize(Stream& s) const { m_request.Serialize(s); }
    template<typename Stream> void Unserialize(Stream& s) { m_request.Unserialize(s); }
};

// BIP 152 — blocktxn (missing transactions response)
class message_blocktxn : public Message {
private:
    using message_type = message_blocktxn;
public:
    message_blocktxn() : Message("blocktxn") {}

    BlockTransactionsResponse m_response;

    static std::unique_ptr<RawMessage> make_raw(const BlockTransactionsResponse& resp) {
        auto temp = std::make_unique<message_type>();
        temp->m_response = resp;
        auto result = std::make_unique<RawMessage>(temp->m_command, pack(*temp));
        return result;
    }
    static std::unique_ptr<RawMessage> make_raw() {
        return std::make_unique<RawMessage>("blocktxn", PackStream{});
    }
    static std::unique_ptr<message_type> make(PackStream& stream) {
        auto result = std::make_unique<message_type>();
        stream >> *result;
        return result;
    }
    template<typename Stream> void Serialize(Stream& s) const { m_response.Serialize(s); }
    template<typename Stream> void Unserialize(Stream& s) { m_response.Unserialize(s); }
};

// wtxidrelay and sendaddrv2 imported from bitcoin_family via using declarations above.

using Handler = MessageHandler<
    message_version,
    message_verack,
    message_ping,
    message_pong,
    message_alert,
    message_inv,
    message_getdata,
    message_getblocks,
    message_getheaders,
    message_tx,
    message_block,
    message_headers,
    message_getaddr,
    message_addr,
    message_reject,
    message_sendheaders,
    message_notfound,
    message_feefilter,
    message_mempool,
    message_sendcmpct,
    message_cmpctblock,
    message_getblocktxn,
    message_blocktxn,
    message_wtxidrelay,
    message_sendaddrv2
>;

} // namespace p2p

} // namespace coin

} // namespace ltc