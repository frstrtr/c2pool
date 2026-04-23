#pragma once

// Dash coin daemon P2P messages.
// Generic messages imported from bitcoin_family.
// Coin-specific messages (block, tx, headers) use Dash types (no MWEB, no segwit).

#include "transaction.hpp"
#include "block.hpp"
#include "vendor/blockencodings.hpp"
#include "vendor/smldiff.hpp"

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
using bitcoin_family::coin::p2p::BIP155Network;
using bitcoin_family::coin::p2p::bip155_address_size;
using bitcoin_family::coin::p2p::MAX_ADDRV2_RECORDS;
using bitcoin_family::coin::p2p::btc_addrv2_record_t;
using bitcoin_family::coin::p2p::message_addrv2;

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
// ── BIP 152 compact-block messages (Phase S2) ─────────────────────────────
// Wire types vendored from dashcore at src/impl/dash/coin/vendor/; see
// vendor/README.md for the adaptation notes.

BEGIN_MESSAGE(cmpctblock)
    MESSAGE_FIELDS
    (
        (vendor::CBlockHeaderAndShortTxIDs, m_cmpct)
    )
    {
        READWRITE(obj.m_cmpct);
    }
END_MESSAGE()

BEGIN_MESSAGE(getblocktxn)
    MESSAGE_FIELDS
    (
        (vendor::BlockTransactionsRequest, m_req)
    )
    {
        READWRITE(obj.m_req);
    }
END_MESSAGE()

BEGIN_MESSAGE(blocktxn)
    MESSAGE_FIELDS
    (
        (vendor::BlockTransactions, m_txs)
    )
    {
        READWRITE(obj.m_txs);
    }
END_MESSAGE()

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

// ── Phase C-SML step 4: Simplified MN List sync messages ──────────────
// Wire commands (dashcore protocol.cpp:68-69):
//   "getmnlistd"  — request: baseBlockHash + blockHash
//   "mnlistdiff"  — reply:   full diff struct (see vendor/smldiff.hpp)
// Used to maintain a local SML for CBTX merkleRootMNList verification
// and (in later phases) ChainLock signature validation. Dashcore full
// nodes do NOT receive mnlistdiff (they Misbehaving(100) on receipt) —
// the protocol is exclusively for light clients, which c2pool-dash now
// is on the SML axis.

BEGIN_MESSAGE(getmnlistd)
    MESSAGE_FIELDS
    (
        (uint256, m_base_block_hash),
        (uint256, m_block_hash)
    )
    {
        READWRITE(obj.m_base_block_hash);
        READWRITE(obj.m_block_hash);
    }
END_MESSAGE()

BEGIN_MESSAGE(mnlistdiff)
    MESSAGE_FIELDS
    (
        (vendor::CSimplifiedMNListDiff, m_diff)
    )
    {
        READWRITE(obj.m_diff);
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
    message_addrv2,
    message_cmpctblock,
    message_getblocktxn,
    message_blocktxn,
    message_clsig,
    message_getmnlistd,
    message_mnlistdiff
>;

} // namespace p2p
} // namespace coin
} // namespace dash
