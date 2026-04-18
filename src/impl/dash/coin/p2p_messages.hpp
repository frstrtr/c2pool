#pragma once

// Dash coin daemon P2P messages.
// Generic messages imported from bitcoin_family.
// Coin-specific messages (block, tx, headers) use Dash types (no MWEB, no segwit).

#include "transaction.hpp"
#include "block.hpp"

#include <impl/bitcoin_family/coin/base_p2p_messages.hpp>

#include <vector>

#include <core/uint256.hpp>
#include <core/netaddress.hpp>
#include <core/message.hpp>
#include <core/message_macro.hpp>

namespace dash
{
namespace coin
{
namespace p2p
{

// Import generic messages from bitcoin_family
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
using bitcoin_family::coin::p2p::message_sendaddrv2;

// ── Dash-specific messages (no segwit, no MWEB) ──

BEGIN_MESSAGE(tx)
    MESSAGE_FIELDS
    (
        (MutableTransaction, m_tx)
    )
    {
        READWRITE(obj.m_tx);
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

// SPV A1 (parity audit): Dash ChainLockSig (clsig) message.
// Reference: dashcore/src/chainlock/clsig.h — ChainLockSig struct.
// Wire layout: nHeight(i32 LE) + blockHash(32B LE) + sig(96B BLS blob).
// Peers push this unsolicited when a ChainLock is freshly aggregated,
// and also on demand via inv+getdata(MSG_CLSIG=29). Parsing the sig is
// not required — we treat it as opaque bytes; the fact that we received
// the message at all is dashd's signal that the block is finalized.
BEGIN_MESSAGE(clsig)
    MESSAGE_FIELDS
    (
        (int32_t, m_height),
        (uint256, m_block_hash),
        (std::vector<uint8_t>, m_sig)
    )
    {
        READWRITE(obj.m_height);
        READWRITE(obj.m_block_hash);
        READWRITE(Using<ArrayType<DefaultFormat, 96>>(obj.m_sig));
    }
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
    message_sendaddrv2,
    message_clsig
>;

} // namespace p2p
} // namespace coin
} // namespace dash
