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

#include <span>
#include <vector>

#include <core/hash.hpp>      // CHash256 — dstx_signature_hash (W5-B)
#include <core/pack.hpp>      // PackStream — dstx_signature_hash (W5-B)
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
// The message codec itself lives further down (BEGIN_MESSAGE(isdlock), G4
// section) — ONE definition with the MAX_ISDLOCK_INPUTS decode bound. The
// two consumer lanes' trust postures are documented there.

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
///   MSG_ISDLOCK                 = 31 — deterministic InstantSend locks
///                                      (protocol.h:524), the G4
///                                      conflict-tx-lock guard's feed +
///                                      the IS mining-safety hold's IsLocked
///
/// NOTE: this function is a TYPE predicate only. isdlock is pulled
/// unconditionally (the fee-only-safe new_islock lane rides every received
/// one); the runtime opt-in (--embedded-ingest-isdlock,
/// CoinClient::set_isdlock_pull) gates only the BLS-verified new_isdlock
/// lane at the handler in p2p_client.hpp — flag OFF means the verified
/// adoption path (maintainer BLS gate → Mempool::add_islock) stays dormant.
///
/// Block invs are deliberately NOT here: they take the getheaders-then-block
/// path in the inv handler, not a bare getdata.
///
/// govobject (17) / govobjectvote (18) ARE pull-eligible types (E-SUPERBLOCK:
/// dashcore answers a govsync with governance INVENTORY, not the objects
/// directly — CGovernanceManager::SyncObjects / SyncSingleObjVotes — so without
/// a getdata for these types the govobj / govobjvote handlers never fire and
/// the GovernanceStore stays empty, exactly the pre-fix inert leg). Unlike
/// clsig / isdlock they are RUNTIME-GATED, not unconditional: the inv handler
/// pulls them only when m_gov_pull_enabled is armed (--embedded-govsync
/// observe-only OR --embedded-superblock), the same is_dstx precedent. Keeping
/// them in this TYPE predicate documents "these are getdata-pull types"; the
/// handler decides whether to actually pull.
inline bool inv_type_is_pulled(inventory_type::inv_type t)
{
    return t == inventory_type::quorum_final_commitment
        || t == inventory_type::clsig
        || t == inventory_type::isdlock
        || t == inventory_type::govobject
        || t == inventory_type::govobjectvote;
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

// ── G4 feed: deterministic InstantSend lock (DIP-0022) ────────────────────
// "isdlock" — dashd instantsend/lock.h InstantSendLock, wire order:
//   nVersion (u8, ISDLOCK_VERSION == 1; anything else is dropped in the
//             handler, not here — an unknown version is a peer-local refusal,
//             not a stream error)
//   inputs   (CompactSize-prefixed vector<COutPoint>: 32B txid + 4B LE index,
//             the exact GovOutPoint wire)
//   txid     (uint256 — the tx these outpoints are locked TO)
//   cycleHash(uint256 — the DKG cycle-start block of the type-5 rotated
//             quorum that signed; drives the ROTATED SelectQuorumForSigning
//             arm, see islock_verify.hpp)
//   sig      (fixed 96B BLS recovered threshold signature, same decode as
//             clsig m_sig above)
//
// ACQUISITION mirrors clsig: dashd ANNOUNCES by inv (MSG_ISDLOCK = 31) and
// serves the object only on getdata; the inv hash is SerializeHash(payload),
// echo-back only. The pull is UNCONDITIONAL (inv_type_is_pulled): every
// received isdlock feeds the #1230 fee-only-safe new_islock lane (an islock
// can only EXCLUDE a conflicting tx / short-circuit the IS mining-safety
// hold — worst case forgone fees, never an invalid block; honest dashd
// peers relay only islocks they themselves BLS-verified, the same SPV-style
// trust the tx feed rides). --embedded-ingest-isdlock additionally arms the
// BLS-VERIFIED new_isdlock lane at the handler (default OFF => that lane
// never fires).
//
// ⚠ THE SIGNATURE IS NOT OPAQUE. Receiving an isdlock is NOT evidence the
// lock is real: adopting one unverified would let an arbitrary peer evict
// arbitrary mempool txs from our served templates (Mempool::add_islock's
// conflict eviction + the G4 selection guard). The 96-byte recovered
// threshold sig MUST be BLS-verified against the rotated LLMQ_60_75 quorum
// dashd's SelectQuorumForSigning designates (islock_verify.hpp +
// CoinStateMaintainer::on_new_isdlock, fail-closed without a verifier)
// before Mempool::add_islock is ever called.
//
// Decode bound: dashd InstantSendLock::TriviallyValid rejects
// inputs.size() > MaxBlockSize()/41 (instantsend/lock.h MAX_INPUTS); we
// enforce the same ceiling at decode so a hostile peer cannot make us
// buffer an absurd vector. Empty-inputs / null-txid are handler refusals.
inline constexpr size_t MAX_ISDLOCK_INPUTS = 2'000'000 / 41;   // dashd MAX_INPUTS

BEGIN_MESSAGE(isdlock)
    MESSAGE_FIELDS
    (
        (uint8_t,                    m_version),
        (std::vector<GovOutPoint>,   m_inputs),
        (uint256,                    m_txid),
        (uint256,                    m_cycle_hash),
        (std::vector<uint8_t>,       m_sig)
    )
    {
        READWRITE(obj.m_version);
        READWRITE(obj.m_inputs);
        if constexpr (std::is_same_v<Formatter, UnserializeFormatter>) {
            if (obj.m_inputs.size() > MAX_ISDLOCK_INPUTS)
                throw std::ios_base::failure(
                    "isdlock inputs over MAX_ISDLOCK_INPUTS");
        }
        READWRITE(obj.m_txid);
        READWRITE(obj.m_cycle_hash);
        READWRITE(Using<ArrayType<DefaultFormat, 96>>(obj.m_sig));
    }
END_MESSAGE()

// ── W5-B: CoinJoin broadcast tx (DSTX) ────────────────────────────────────
// "dstx" — dashd coinjoin/coinjoin.h CCoinJoinBroadcastTx, v23 wire form
// (SERIALIZE_METHODS, coinjoin.h:255-263; the legacy masternodeOutpoint arm
// is gone at proto 70230 — protxHash only):
//   tx        (full network tx serialization — Dash has no witness)
//   protxHash (uint256 — the mixing masternode's registration txid)
//   vchSig    (CompactSize-prefixed byte vector; 96-byte BLS operator sig.
//              The 96B check is a HANDLER refusal, not a codec bound —
//              mirrors isdlock's "structural refusal is peer-local" posture)
//   sigTime   (int64 LE)
//
// ACQUISITION: dashd relays a mixing tx as inv(MSG_DSTX=16) where the inv
// hash is the PLAIN TXID (net_processing.cpp:2567 — unlike isdlock/clsig,
// whose inv hash is SerializeHash(payload)), and serves the object from
// CDSTXManager::GetDSTX(txid) on getdata (:2868-2873). The pull is OPT-IN
// (--embedded-ingest-dstx, CoinClient::set_dstx_pull) and rides the SAME
// budgeted tx-pull machinery as MSG_TX (slot keyed by txid — correct here
// precisely because the DSTX inv hash IS the txid); flag OFF ⇒ no getdata
// type-16 is ever sent ⇒ zero wire and zero template change.
//
// ⚠ THE SIGNATURE IS NOT OPAQUE. A DSTX is a ZERO-FEE tx dashd admits and
// then PRIORITISES (+0.1 COIN modified fee, net_processing.cpp:3609) ONLY
// after BLS-verifying vchSig against the mixing MN's operator key
// (ValidateDSTX, :3549-3615). Adopting one unverified would let an arbitrary
// peer stuff zero-fee txs into our served templates at top priority. The
// maintainer-side gate (CoinStateMaintainer::on_new_dstx, fail-closed
// without a verifier) must BLS-verify
//     SerializeHash(tx ‖ protxHash ‖ sigTime)      (SER_GETHASH drops vchSig;
//                                                   coinjoin.cpp:68-80)
// against SML pubKeyOperator(protxHash) before Mempool::add_dstx runs.
BEGIN_MESSAGE(dstx)
    MESSAGE_FIELDS
    (
        (MutableTransaction,   m_tx),
        (uint256,              m_protx_hash),
        (std::vector<uint8_t>, m_sig),
        (int64_t,              m_sig_time)
    )
    {
        READWRITE(obj.m_tx);
        READWRITE(obj.m_protx_hash);
        READWRITE(obj.m_sig);
        READWRITE(obj.m_sig_time);
    }
END_MESSAGE()

/// dashd CCoinJoinBroadcastTx::IsValidStructure (coinjoin.cpp:83-102) — the
/// STRUCTURAL refusals a DSTX must clear before the BLS gate ever runs.
/// Mainnet constants: nPoolMinParticipants=3 / nPoolMaxParticipants=20
/// (chainparams.cpp:287-288), COINJOIN_ENTRY_MAX_SIZE=9 (coinjoin.h:47) ⇒
/// vin ∈ [3, 180]; every vout must be a standard CoinJoin denomination
/// (coinjoin/common.h:38-44) paid to P2PKH. No sigTime bound — dashd's
/// ValidateDSTX has none (the time bound is queue-only). A refusal is a
/// peer-local drop, never a ban. Free function so it is unit-testable
/// without a live socket peer (same reason as inv_type_is_pulled).
inline bool dstx_is_valid_structure(const MutableTransaction& tx,
                                    const uint256& protx_hash,
                                    size_t sig_size)
{
    static constexpr size_t kMinVin = 3;        // nPoolMinParticipants
    static constexpr size_t kMaxVin = 20 * 9;   // nPoolMaxParticipants * ENTRY_MAX
    auto is_denomination = [](int64_t v) {
        return v == 1000010000LL   // 10.00010000 DASH
            || v == 100001000LL    //  1.00001000
            || v == 10000100LL     //  0.10000100
            || v == 1000010LL      //  0.01000010
            || v == 100001LL;      //  0.00100001
    };
    auto is_p2pkh = [](const std::vector<uint8_t>& s) {
        return s.size() == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14
            && s[23] == 0x88 && s[24] == 0xac;
    };
    if (protx_hash.IsNull()) return false;
    if (tx.vin.size() != tx.vout.size()) return false;
    if (tx.vin.size() < kMinVin || tx.vin.size() > kMaxVin) return false;
    if (sig_size != 96) return false;
    for (const auto& out : tx.vout) {
        if (!is_denomination(out.value)) return false;
        if (!is_p2pkh(out.scriptPubKey.m_data)) return false;
    }
    return true;
}

/// dashd CCoinJoinBroadcastTx::GetSignatureHash() — SerializeHash(*this,
/// SER_GETHASH, PROTOCOL_VERSION) with vchSig EXCLUDED by the SER_GETHASH
/// guard in SERIALIZE_METHODS (coinjoin.h:257-262, coinjoin.cpp:68-71):
///
///     digest = SHA256d( ser(tx) ‖ protxHash[32] ‖ sigTime[8 LE] )
///
/// Full network tx serialization (Dash txs have no witness, so SER_GETHASH
/// does not alter the tx bytes; ::pack(MutableTransaction) IS the dash_txid
/// byte source), raw 32-byte protxHash, plain 8-byte LE sigTime — NO
/// CompactSize framing around the trailing fields. This is the pre-image the
/// mixing MN's BLS operator key signs; pinned by test_dash_dstx.cpp against
/// an independently hand-assembled byte stream.
inline uint256 dstx_signature_hash(const MutableTransaction& tx,
                                   const uint256& protx_hash,
                                   int64_t sig_time)
{
    ::PackStream ps;
    ps << tx;
    auto sp = ps.get_span();
    std::vector<uint8_t> pre(
        reinterpret_cast<const uint8_t*>(sp.data()),
        reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
    pre.insert(pre.end(), protx_hash.data(), protx_hash.data() + 32);
    for (int i = 0; i < 8; ++i)
        pre.push_back(static_cast<uint8_t>(
            (static_cast<uint64_t>(sig_time) >> (8 * i)) & 0xFF));
    uint256 digest;
    CHash256()
        .Write(std::span<const unsigned char>(pre.data(), pre.size()))
        .Finalize(std::span<unsigned char>(digest.data(), 32));
    return digest;
}

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
    // Membership here is UNCONDITIONAL (compile-time); the
    // --embedded-ingest-isdlock flag gates BEHAVIOUR (the BLS-verified
    // new_isdlock lane), never parsing. ONE entry only: a type listed twice
    // is a duplicate variant alternative = compile error (rebase trap,
    // #1230 x isdlock-intake). test_dash_isdlock.cpp gates the registry
    // membership directly.
    message_isdlock,
    // ⚠ DSTX lane — same registry rule as isdlock above (#1077): a handler
    // that exists but whose message type is absent from this list can never
    // run; the payload dies on the unhandled-command path at DEBUG, and the
    // CoinJoin leg silently stays feed-less. Membership here is
    // UNCONDITIONAL (compile-time); the --embedded-ingest-dstx flag gates
    // BEHAVIOUR (the getdata pull + the BLS-verified new_dstx lane), never
    // parsing. ONE entry only: a type listed twice is a duplicate variant
    // alternative = compile error (rebase trap). test_dash_dstx.cpp gates
    // the registry membership directly.
    message_dstx,
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