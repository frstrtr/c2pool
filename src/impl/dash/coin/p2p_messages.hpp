// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Dash coin daemon P2P messages.
// Generic messages imported from bitcoin_family.
// Coin-specific messages (block, tx, headers) use Dash types (no MWEB, no segwit).

#include "transaction.hpp"
#include "block.hpp"
#include "vendor/blockencodings.hpp"
#include "vendor/smldiff.hpp"
#include "vendor/llmq_commitment.hpp"
#include "vendor/quorum_rotation_info.hpp"

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
//
// ACQUISITION: Dash Core ANNOUNCES a ChainLock by inv and serves the object
// only on getdata (announce: chainlock/handler.cpp:128 + RelayInv; serve:
// net_processing.cpp:2992-2998). It does NOT push clsig unsolicited — so the
// inv→getdata(MSG_CLSIG=29) leg in p2p_client's inv handler is what makes this
// message reachable at all. dashd serves ONLY its current best ChainLock, so a
// getdata for a superseded announcement returns notfound; that is benign.
//
// ⚠ THE SIGNATURE IS NOT OPAQUE. Receiving this message is NOT by itself
// evidence that the block is finalized — a clsig arrives from an arbitrary
// peer and its height/blockHash/sig are committed into the coinbase of every
// template we then serve (CCbTx bestCLHeightDiff/bestCLSignature). The 96-byte
// recovered threshold signature MUST be BLS-verified against the quorum
// dashcore's SelectQuorumForSigning designates before any of it is adopted —
// see chainlock_verify.hpp and CoinStateMaintainer::on_new_chainlock, which is
// fail-closed without a verifier.
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

// ── DIP-0010 InstantSend lock (isdlock) ────────────────────────────────────
// dashcore instantsend/lock.h InstantSendLock wire layout: nVersion(u8) +
// vector<COutPoint> inputs + txid(32B) + cycleHash(32B) + sig(96B BLS blob).
// Announced by inv MSG_ISDLOCK=31 and served only on getdata (net_processing
// relays only VERIFIED islocks), so the inv→getdata leg in inv_type_is_pulled
// below is what makes this message reachable at all — the same registry rule
// as clsig/qfcommit.
//
// ⚠ TRUST POSTURE (deliberate, documented): the 96-byte recovered threshold
// signature is CARRIED but NOT BLS-verified in this slice — verifying it needs
// the DIP-24 rotated SIGNING-quorum selection (GetRequestId + cycleHash →
// quorum), which is not yet ported. The consumers are therefore restricted to
// the FEE-ONLY-SAFE directions (Mempool::add_islock): an islock can EXCLUDE a
// conflicting tx from the embedded template / evict it from the pool (worst
// case = forgone fees, never an invalid block), and it SHORT-CIRCUITS the
// 10-minute IS mining-safety hold for the locked txid itself (dashd
// IsLocked(txid) — strictly no worse than the pre-hold behaviour, which
// included EVERY young tx immediately). Honest dashd peers relay only islocks
// they themselves BLS-verified, the same SPV-style trust the tx feed already
// rides (sole-ingestion-path invariant, mempool.hpp). Full BLS verify is the
// named follow-up before islock knowledge is treated as authoritative.
BEGIN_MESSAGE(isdlock)
    MESSAGE_FIELDS
    (
        (uint8_t,                  m_version),
        (std::vector<TxPrevOut>,   m_inputs),      // COutPoint wire twin (hash+index)
        (uint256,                  m_txid),
        (uint256,                  m_cycle_hash),
        (std::vector<uint8_t>,     m_sig)
    )
    {
        READWRITE(obj.m_version);
        READWRITE(obj.m_inputs);
        READWRITE(obj.m_txid);
        READWRITE(obj.m_cycle_hash);
        READWRITE(Using<ArrayType<DefaultFormat, 96>>(obj.m_sig));
    }
END_MESSAGE()

/// The inv-announcement sourcing policy: which inv types the DASH coin-P2P
/// client answers with a getdata for the object itself.
///
/// Dash relays these objects announce-first (inv), serving the body only on
/// request, so an inv type absent from this set is an object we can NEVER
/// receive — which is exactly how the ChainLock leg stayed dark: clsig was
/// decodable and handled, but nothing ever asked for one, so the handler had
/// never once fired. Kept as a free function (rather than inline in the inv
/// handler) so the policy is unit-testable without a live socket peer.
///
///   MSG_QUORUM_FINAL_COMMITMENT = 21 — relayed DKG final commitments
///                                      (Phase-L MineableCommitmentCache)
///   MSG_CLSIG                   = 29 — ChainLocks (dashcore protocol.h:522)
///   MSG_ISDLOCK                 = 31 — InstantSend locks (protocol.h:524),
///                                      the G4 conflict-tx-lock guard's feed +
///                                      the IS mining-safety hold's IsLocked
///
/// Block invs are deliberately NOT here: they take the getheaders-then-block
/// path in the inv handler, not a bare getdata.
inline bool inv_type_is_pulled(inventory_type::inv_type t)
{
    return t == inventory_type::quorum_final_commitment
        || t == inventory_type::clsig
        || t == inventory_type::isdlock;
}

// ── Phase C-SML step 4: Simplified MN List sync messages ──────────────
// Wire commands (dashcore protocol.cpp:68-69):
//   "getmnlistd"  — request: baseBlockHash + blockHash
//   "mnlistdiff"  — reply:   full diff struct (see vendor/smldiff.hpp)
// Used to maintain a local SML for CBTX merkleRootMNList verification
// and (in later phases) ChainLock signature validation. Dashcore full
// nodes do NOT receive mnlistdiff (they Misbehaving(100) on receipt) —
// the protocol is exclusively for light clients, which c2pool-dash now
// is on the SML axis.

// ── E1 Phase-L sourcing leg: mineable quorum commitments ──────────────
// dashcore relays every VERIFIED DKG final commitment to all peers as
// inv MSG_QUORUM_FINAL_COMMITMENT (21) + "qfcommit" (llmq/blockprocessor
// .cpp ProcessMessage / AddMineableCommitment) — the exact stream its
// OWN miner sources block-N's mandatory type-6 txs from. The payload is
// a bare CFinalCommitment (already vendored). We pull the inv and feed
// the MineableCommitmentCache (dkg_commitments.hpp); template INCLUSION
// stays behind the Phase-L BLS verifier — until then the daemonless arm
// mines the consensus-valid null commitment.
BEGIN_MESSAGE(qfcommit)
    MESSAGE_FIELDS
    (
        (vendor::CFinalCommitment, m_commitment)
    )
    {
        READWRITE(obj.m_commitment);
    }
END_MESSAGE()

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

// ── DIP-0024 rotated-quorum sourcing ──────────────────────────────────────
// "getqrinfo" / "qrinfo" (dashcore llmq/snapshot.h). The rotated member set
// is NOT derivable from the single work-block snapshot getmnlistd returns —
// only qrinfo carries the quarter-rotation snapshots + cycle-base mnlistdiffs
// that ComputeQuorumMembersByQuarterRotation needs. See
// vendor/quorum_rotation_info.hpp for the wire layout (pinned from a real
// capture) and for why the reply is carried as raw bytes here.
BEGIN_MESSAGE(getqrinfo)
    MESSAGE_FIELDS
    (
        (std::vector<uint256>, m_base_block_hashes),
        (uint256,              m_block_request_hash),
        (bool,                 m_extra_share)
    )
    {
        READWRITE(obj.m_base_block_hashes,
                  obj.m_block_request_hash,
                  obj.m_extra_share);
    }
END_MESSAGE()

// The qrinfo payload is carried RAW and decoded by
// vendor::decode_quorum_rotation_info in the handler. Reason: the nested
// CSimplifiedMNListDiff reader is fail-closed (returns bool) because it must
// re-materialise the opaque quorum tail byte-exactly, and a READWRITE body has
// no way to signal "refuse this message" other than throwing. Keeping the
// decode out of the codec keeps a malformed qrinfo a LOCAL, logged refusal
// instead of a stream-level exception on the coin connection.
BEGIN_MESSAGE(qrinfo)
    MESSAGE_FIELDS
    (
        (std::vector<unsigned char>, m_raw)
    )
    {
        if constexpr (std::is_same_v<Formatter, UnserializeFormatter>) {
            size_t n = stream.cursor_size();
            obj.m_raw.resize(n);
            if (n) stream.read(std::as_writable_bytes(std::span{obj.m_raw}));
        } else {
            if (!obj.m_raw.empty()) {
                stream.write(std::as_bytes(std::span{obj.m_raw}));
            }
        }
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

// ── SPORK listener ────────────────────────────────────────────────────────
// "spork" — CSporkMessage (dashd src/spork.h SERIALIZE_METHODS): nSporkID(i32)
// + nValue(i64) + nTimeSigned(i64) + vchSig (LIMITED_VECTOR, 65-byte compact
// sig). dashd serves its FULL spork set in reply to "getsporks" (which the
// client sends once per completed handshake) and relays every new spork
// unsolicited. The signature is verified in the handler against the hardcoded
// mainnet spork key (spork.hpp) before any state is touched — an arbitrary
// peer must not be able to flip a spork by just sending the message.
BEGIN_MESSAGE(spork)
    MESSAGE_FIELDS
    (
        (int32_t,              m_spork_id),
        (int64_t,              m_value),
        (int64_t,              m_time_signed),
        (std::vector<uint8_t>, m_sig)
    )
    {
        READWRITE(obj.m_spork_id);
        READWRITE(obj.m_value);
        READWRITE(obj.m_time_signed);
        READWRITE(obj.m_sig);
    }
END_MESSAGE()

// "getsporks" — empty-payload request; dashd answers with its full spork set.
// We SEND this on every completed handshake; a peer may also send it to us
// (masternode sync does), which we acknowledge and do not serve.
BEGIN_MESSAGE(getsporks)
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
    message_sendaddrv2,
    message_addrv2,
    message_cmpctblock,
    message_getblocktxn,
    message_blocktxn,
    message_clsig,
    // ⚠ ISDLOCK lane — same registry rule as the DIP-24 pair below (#1077): a
    // handler that exists but whose message type is absent from this list can
    // never run; the payload dies on the unhandled-command path at DEBUG, and
    // the G4 islock guard + the IS mining-safety hold silently stay feed-less.
    message_isdlock,
    message_qfcommit,
    message_getmnlistd,
    message_mnlistdiff,
    // ⚠ DIP-24 ROTATED LANE — these two MUST stay in this list.
    // A message type absent here is NOT in MessageHandler::m_handlers, so
    // MessageHandler::parse() throws std::out_of_range and CoinClient::handle
    // drops the payload on the "unhandled command" path — at DEBUG level.
    // That is exactly how the rotated lane failed silently in production: the
    // getqrinfo went out, dashd answered, and the ~600 kB qrinfo was discarded
    // before ADD_P2P_HANDLER(qrinfo) — which existed, fully written, with a
    // registered consumer — could ever run. Nothing in any log said so.
    // test_dash_qrinfo_wire.cpp gates the registry membership directly.
    message_getqrinfo,
    message_qrinfo,
    message_govobj,
    message_govobjvote,
    message_govsync,
    // ⚠ SPORK lane — same registry rule as the DIP-24 pair above (#1077): a
    // handler that exists but whose message type is absent from this list can
    // never run; the payload dies on the unhandled-command path at DEBUG.
    // test_dash_spork.cpp gates the registry membership directly.
    message_spork,
    message_getsporks
>;

} // namespace p2p
} // namespace coin
} // namespace dash