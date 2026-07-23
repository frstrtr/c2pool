// SPDX-License-Identifier: AGPL-3.0-or-later
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

// ── E-SUPERBLOCK: governance sync (daemonless superblock payee sourcing) ──
// Wire commands (dashcore protocol.cpp):
//   "govsync"    — MNGOVERNANCESYNC:      request objects+votes (we SEND this)
//   "govobj"     — MNGOVERNANCEOBJECT:    a governance object (we INGEST this)
//   "govobjvote" — MNGOVERNANCEOBJECTVOTE: a governance vote  (we INGEST this)
//
// Field layouts are ported from dashcore governance/object.h (CGovernanceObject)
// and governance/vote.h (CGovernanceVote). The masternode outpoint is a
// COutPoint (32-byte txid + 4-byte LE index), identical to TxPrevOut's wire.
//
// ⚠ PIN-BEFORE-ENABLE: these layouts must be byte-pinned against a real
// from-wire govobj/govobjvote capture before the daemonless superblock arm is
// switched on in production. The arm is opt-in and DEFAULT-OFF; until pinned +
// BLS-operator vote-verify lands, a superblock height fails closed to dashd. A layout
// mismatch only makes ingestion fail (objects/votes rejected) => the store
// stays empty => the arm keeps failing closed. It can never MISpay: the payee
// vector is re-derived from the trigger's own vchData and budget-checked.

// COutPoint (masternode outpoint) — mirrors bitcoin_family TxPrevOut wire.
struct GovOutPoint {
    uint256  hash;
    uint32_t index{0xffffffff};
    C2POOL_SERIALIZE_METHODS(GovOutPoint) { READWRITE(obj.hash, obj.index); }

    // dashcore COutPoint::ToStringShort() == "<txid-hex>-<index>", the store's
    // per-MN vote key (latest-vote-wins keying).
    std::string to_key() const { return hash.GetHex() + "-" + std::to_string(index); }
};

// MNGOVERNANCEOBJECT — CGovernanceObject (governance/object.h SERIALIZE_METHODS).
// Order: nHashParent, nRevision, nTime, nCollateralHash, vchData, nObjectType,
// masternodeOutpoint, vchSig. nObjectType: 1=proposal, 2=trigger (superblock).
BEGIN_MESSAGE(govobj)
    MESSAGE_FIELDS
    (
        (uint256,                    m_hash_parent),
        (int32_t,                    m_revision),
        (int64_t,                    m_time),
        (uint256,                    m_collateral_hash),
        (std::vector<uint8_t>,       m_vch_data),
        (int32_t,                    m_object_type),
        (GovOutPoint,                m_masternode_outpoint),
        (std::vector<uint8_t>,       m_vch_sig)
    )
    {
        READWRITE(obj.m_hash_parent);
        READWRITE(obj.m_revision);
        READWRITE(obj.m_time);
        READWRITE(obj.m_collateral_hash);
        READWRITE(obj.m_vch_data);
        READWRITE(obj.m_object_type);
        READWRITE(obj.m_masternode_outpoint);
        READWRITE(obj.m_vch_sig);
    }
END_MESSAGE()

// MNGOVERNANCEOBJECTVOTE — CGovernanceVote (governance/vote.h SERIALIZE_METHODS).
// Order: masternodeOutpoint, nParentHash, nVoteOutcome, nVoteSignal, nTime,
// vchSig. Outcome: 1=yes 2=no 3=abstain. Signal: 1=funding (superblock tally).
BEGIN_MESSAGE(govobjvote)
    MESSAGE_FIELDS
    (
        (GovOutPoint,                m_masternode_outpoint),
        (uint256,                    m_parent_hash),
        (int32_t,                    m_vote_outcome),
        (int32_t,                    m_vote_signal),
        (int64_t,                    m_time),
        (std::vector<uint8_t>,       m_vch_sig)
    )
    {
        READWRITE(obj.m_masternode_outpoint);
        READWRITE(obj.m_parent_hash);
        READWRITE(obj.m_vote_outcome);
        READWRITE(obj.m_vote_signal);
        READWRITE(obj.m_time);
        READWRITE(obj.m_vch_sig);
    }
END_MESSAGE()

// MNGOVERNANCESYNC (request) — dashcore sends uint256 nProp + CBloomFilter.
// We only ever SEND this to pull the store; a zero nProp requests ALL objects.
// The bloom filter is optional in the protocol; we send an EMPTY filter
// (vData=empty, nHashFuncs=0, nTweak=0, nFlags=0) — "match nothing extra",
// which dashcore treats as "send everything" for a zero nProp sync.
BEGIN_MESSAGE(govsync)
    MESSAGE_FIELDS
    (
        (uint256,                    m_prop),
        (std::vector<uint8_t>,       m_filter_vdata),
        (uint32_t,                   m_filter_nhashfuncs),
        (uint32_t,                   m_filter_ntweak),
        (uint8_t,                    m_filter_nflags)
    )
    {
        READWRITE(obj.m_prop);
        READWRITE(obj.m_filter_vdata);
        READWRITE(obj.m_filter_nhashfuncs);
        READWRITE(obj.m_filter_ntweak);
        READWRITE(obj.m_filter_nflags);
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
    message_mnlistdiff,
    message_govobj,
    message_govobjvote,
    message_govsync
>;

} // namespace p2p
} // namespace coin
} // namespace dash