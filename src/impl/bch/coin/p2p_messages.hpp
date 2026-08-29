// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BCH P2P wire messages (M3 slice 7).
//
// Ported from btc/coin/p2p_messages.hpp with the SegWit/BIP-339 surface
// removed -- BCH has no witness, so there is no wtxid, no MSG_WTX, no
// witness inventory flag, and no wtxidrelay negotiation. tx payloads carry
// the plain (legacy) serialization that is already the only form BCH txs
// have (see bch/coin/transaction.hpp banner).
//
// The BIP-152 compact-block carrier messages (cmpctblock / getblocktxn /
// blocktxn) are wired below (M3 slice 10, cmpct-wireback). They wrap the
// CompactBlock / BlockTransactions{Request,Response} types from
// compact_blocks.hpp (slice 9). The BCH divergences -- no-witness tx
// bodies, short IDs over txid (compute_txid), and no CTOR re-sort -- live
// in those wrapped types, so the carrier wiring here is structurally the
// same as btc. The sendcmpct negotiation message has no CompactBlock
// dependency and has been present since slice 7 -- BCHN speaks BIP-152.
// Unlike btc there is NO wtxidrelay carrier: BCH has no wtxid.
//
// Source refs: bitcoin-cash-node/src/protocol.{h,cpp} (GetDataMsg enum,
// NetMsgType command strings) and src/net_processing.cpp.

#include "transaction.hpp"
#include "block.hpp"
#include "compact_blocks.hpp"

#include <vector>

#include <core/uint256.hpp>
#include <core/netaddress.hpp>
#include <core/message.hpp>
#include <core/message_macro.hpp>

namespace bch
{
namespace coin
{

namespace p2p
{

// Bitcoin wire protocol uses uint32_t timestamp in addr messages,
// unlike the pool protocol which uses uint64_t. Identical to BTC -- the
// addr record wire format is fork-inherited.
struct bch_addr_record_t : addr_t
{
    uint32_t m_timestamp{};

    bch_addr_record_t() : addr_t() {}

    C2POOL_SERIALIZE_METHODS(bch_addr_record_t) { READWRITE(obj.m_timestamp, AsBase<addr_t>(obj)); }
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
    // BCH GetDataMsg (bitcoin-cash-node/src/protocol.h). No witness flag and
    // no MSG_WTX -- BCH never adopted SegWit/BIP-339. doublespendproof is the
    // one BCH-specific addition (DSPROOF, CHIP-2021-01).
    enum inv_type : uint32_t
    {
        tx               = 1,
        block            = 2,
        filtered_block   = 3,
        cmpct_block      = 4,
        doublespendproof = 0x94a0,   // MSG_DOUBLESPENDPROOF (BCH DSPROOF)
    };

    inv_type m_type;
    uint256 m_hash;

    inventory_type() { }
    inventory_type(inv_type type, uint256 hash) : m_type(type), m_hash(hash) { }

    C2POOL_SERIALIZE_METHODS(inventory_type) {READWRITE(Using<EnumType<IntType<32>>>(obj.m_type), obj.m_hash);}
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
        // No TX_WITH_WITNESS wrapper: BCH tx serialization is witness-free.
        READWRITE(obj.m_tx);
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

// P2P address discovery messages (used by coin broadcaster)
BEGIN_MESSAGE(getaddr)
    WITHOUT_MESSAGE_FIELDS() { }
END_MESSAGE()

BEGIN_MESSAGE(addr)
    MESSAGE_FIELDS
    (
        (std::vector<bch_addr_record_t>, m_addrs)
    )
    {
        READWRITE(obj.m_addrs);
    }
END_MESSAGE()

// BIP 61 — reject message (still emitted by some BCH peers)
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

// BIP 130 — sendheaders (empty, signals header-first block announcements)
BEGIN_MESSAGE(sendheaders)
    WITHOUT_MESSAGE_FIELDS() { }
END_MESSAGE()

// notfound — same layout as inv; response when getdata items are unavailable
BEGIN_MESSAGE(notfound)
    MESSAGE_FIELDS
    (
        (std::vector<inventory_type>, m_invs)
    )
    {
        READWRITE(obj.m_invs);
    }
END_MESSAGE()

// BIP 133 — feefilter (minimum feerate for tx relay, in sat/kB)
BEGIN_MESSAGE(feefilter)
    MESSAGE_FIELDS
    (
        (uint64_t, m_feerate)
    )
    {
        READWRITE(obj.m_feerate);
    }
END_MESSAGE()

// BIP 35 — mempool (empty, requests peer to send inv for all mempool txs)
BEGIN_MESSAGE(mempool)
    WITHOUT_MESSAGE_FIELDS() { }
END_MESSAGE()

// BIP 152 — sendcmpct (compact block negotiation). Kept ahead of the
// compact-block carrier messages because it has no CompactBlock dependency.
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

// BIP 152 — cmpctblock (HeaderAndShortIDs). Wraps CompactBlock from
// compact_blocks.hpp: legacy (no-witness) tx bodies, short IDs over txid.
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

// BIP 152 — blocktxn (missing transactions response). Tx bodies are legacy
// (no-witness) per BlockTransactionsResponse in compact_blocks.hpp.
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

// BIP 155 — sendaddrv2 (empty, signals addrv2 support; sent before verack)
BEGIN_MESSAGE(sendaddrv2)
    WITHOUT_MESSAGE_FIELDS() { }
END_MESSAGE()

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
    message_sendaddrv2
>;

} // namespace p2p

} // namespace coin

} // namespace bch