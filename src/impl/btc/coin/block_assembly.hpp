// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// btc::coin::assemble_won_block -- the share->block "as_block" reassembly that
// the BTC won-block reconstructor (#744 dispatch arc, slice 4/7) feeds to the
// dual-path broadcaster (P2P relay + submitblock RPC fallback).
//
// This is the BTC port of the FRAMING half of p2pool data.py
// Share.as_block(tracker, known_txs):
//
//     gentx     = self.check(tracker, known_txs)         # the coinbase tx
//     other_txs = [known_txs[h] for h in transaction_hashes]
//     return dict(header=self.header, txs=[gentx]+other_txs)
//
// It mirrors the landed DGB slice (src/impl/dgb/coin/block_assembly.hpp) but is
// deliberately NOT DGB-identical in one consensus-relevant respect -- see
// "BTC divergence" below.
//
// Two consensus-relevant facts this captures (shared with DGB):
//   1. p2pool stores only a SmallBlockHeaderType on the share (version|prev|
//      time|bits|nonce -- NO merkle_root). The full block header's merkle_root
//      is RECONSTRUCTED as check_merkle_link(gentx_hash, share merkle link),
//      exactly as verification recomputed the share's PoW root at check() time
//      (share_check.hpp:674-692 / :2500). We MUST reproduce it the same way, or
//      the block hashes to something other than the share's PoW-valid header and
//      the daemon rejects it.
//   2. Block tx order is [gentx] ++ other_txs, gentx (coinbase) always index 0,
//      other_txs in the captured template's transactions[] order (the set the
//      share committed to, replayed by template_capture.hpp -- slice 3).
//
// ---- BTC divergence from the DGB slice (the reviewer-load-bearing part) ----
// BTC commits the BIP141 witness root INSIDE the coinbase at gentx-BUILD time
// (share_check.hpp:2166 / :2296 -- generate_share_transaction). So slices 1-3
// hand this framer an ALREADY witness-committed gentx. We therefore do NOT
// re-inject a witness commitment here. Re-injecting DGB-style
// add_witness_commitment would MUTATE the coinbase, change its txid, invalidate
// the share-committed header merkle_root, and open a SECOND merkle path -- which
// the sealed BTC merkle family (#570 / #574 / #579) forbids. The DGB lane adds
// its commitment downstream only because it does not commit at gentx-time; BTC
// does, so the correct BTC action is: reuse the committed gentx verbatim. Do NOT
// "fix" this back to the DGB add_witness_commitment shape.
//
// The segwit-vs-legacy merkle-LINK SELECTION (segwit shares use
// segwit_data.txid_merkle_link, legacy shares use merkle_link -- share_check.hpp
// :674-692) stays in the CALLER (the reconstruct closure, slice 5): this framer
// takes an already-resolved MerkleLink, exactly like the DGB slice, so the
// sealed link math is reused with NO new merkle path introduced here.
//
// Body/header self-check (item 3): because BTC hands us the full template tx
// set, we can -- and do -- verify the assembled body against the share-committed
// header BEFORE emitting bytes. body_merkle_root() folds [gentx_hash] ++ the
// non-witness txids of other_txs through the sealed btc::coin::compute_merkle_root
// SSOT (template_builder.hpp); for a body that matches the merkle link the share
// committed to, this equals reconstruct_block_header()'s check_merkle_link root
// by the definition of a coinbase (leaf-0) merkle branch. assemble_won_block
// FAILS CLOSED (throws) on a mismatch rather than emit a bad-txnmrklroot block,
// consistent with the whole slice arc's "never broadcast a malformed block"
// posture (cf. gentx_unpack.hpp). This is a self-check over the EXISTING sealed
// compute_merkle_root, NOT a new merkle path or a second commitment.
//
// Interaction with template_capture.hpp (slice 3): on a capture MISS slice 3
// replays an EMPTY transactions[] -> other_txs = {}. If the won share mined a
// coinbase-only template (empty merkle link), body_root == header_root == gentx
// txid: the guard passes and the coinbase-only block broadcasts, carrying the
// full subsidy exactly as template_capture documents. If instead the share
// committed to fee txs (non-empty link), a coinbase-only body is a
// bad-txnmrklroot block the daemon would reject anyway; the guard throws so the
// reconstruct closure fails closed (announce + audit) instead of broadcasting a
// doomed block. Nothing broadcastable is lost -- the guard only tightens the
// non-empty-link miss case, which was never a valid block.
//
// Wire encoding is BlockType::Serialize -> TX_WITH_WITNESS(m_txs): the standard
// Bitcoin-Core CONDITIONAL serializer -- it emits the per-tx witness marker/flag
// iff some tx HasWitness(), legacy otherwise. The block's witness shape is thus
// governed by whether the (already-committed) gentx carries a witness, NOT an
// unconditional witness branch here. This is the identical path
// NodeRPC::submit_block uses (rpc.cpp: pack<BlockType>(block) -> submitblock), so
// the reconstructed block round-trips and the daemon accepts.
//
// Per-coin isolation: src/impl/btc/ only. p2pool-merged-v36 surface: NONE --
// block framing reuses BlockType + check_merkle_link + compute_merkle_root
// verbatim; no share format, PoW hash, coinbase commitment, or PPLNS math is
// touched.
// ---------------------------------------------------------------------------

#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>   // HexStr

#include "block.hpp"               // SmallBlockHeaderType, BlockHeaderType, BlockType
#include "transaction.hpp"         // MutableTransaction, TX_NO_WITNESS
#include "template_builder.hpp"    // btc::coin::compute_merkle_root (sealed body-root SSOT)
#include "../share_check.hpp"      // btc::check_merkle_link (SSOT merkle-branch walk)
#include "../share_types.hpp"      // btc::MerkleLink

namespace btc
{
namespace coin
{

// Reconstruct the full block header from the share's stored SmallBlockHeader
// plus the gentx txid + (already segwit-resolved) merkle link. Mirrors the
// merkle_root recomputation in share_check.hpp verification (SmallBlockHeader
// omits merkle_root); the caller passes txid_merkle_link for segwit shares and
// merkle_link for legacy ones (slice 5), so no link selection happens here.
inline BlockHeaderType
reconstruct_block_header(const SmallBlockHeaderType& small_header,
                         const uint256& gentx_hash,
                         const ::btc::MerkleLink& merkle_link)
{
    BlockHeaderType header;
    header.m_version        = small_header.m_version;
    header.m_previous_block = small_header.m_previous_block;
    header.m_timestamp      = small_header.m_timestamp;
    header.m_bits           = small_header.m_bits;
    header.m_nonce          = small_header.m_nonce;
    // SmallBlockHeader has no merkle_root -- recompute it from the coinbase
    // (gentx) txid walked up the share's merkle branch, exactly as the share's
    // PoW hash was computed at verification time.
    header.m_merkle_root    = ::btc::check_merkle_link(gentx_hash, merkle_link);
    return header;
}

// The merkle leaf (txid) of an other-tx: double-SHA256 of its NON-WITNESS
// serialization, identical to the gentx_hash derivation in gentx_unpack.hpp.
// The BTC merkle tree (header root, and the segwit txid_merkle_link) commits to
// TXIDs, never wtxids, so witness data is excluded here regardless of the tx's
// witness shape.
inline uint256 other_tx_txid(const MutableTransaction& tx)
{
    return Hash(pack(TX_NO_WITNESS(tx)).get_span());
}

// The body's merkle root: compute_merkle_root over [gentx_hash] ++ other-tx
// txids, using the sealed btc::coin::compute_merkle_root SSOT (#570/#574/#579).
// For a body that matches the merkle link the share committed to, this equals
// reconstruct_block_header()'s check_merkle_link root.
inline uint256
body_merkle_root(const uint256& gentx_hash,
                 const std::vector<MutableTransaction>& other_txs)
{
    std::vector<uint256> txids;
    txids.reserve(1 + other_txs.size());
    txids.push_back(gentx_hash);          // coinbase is leaf 0
    for (const auto& tx : other_txs)
        txids.push_back(other_tx_txid(tx));
    return compute_merkle_root(std::move(txids));
}

// Assemble the full serialized parent block for a won share.
//   small_header  : share.m_min_header (version|prev|time|bits|nonce)
//   gentx         : the reconstructed, ALREADY witness-committed coinbase (tx 0)
//   gentx_hash    : its txid (double-SHA256 of the non-witness bytes)
//   merkle_link   : the share's segwit-resolved gentx->root branch (caller-chosen)
//   other_txs     : the captured template's non-coinbase txs, in template order
// Returns {block_bytes, block_hex}: block_bytes is the blob the embedded P2P
// relay sends; block_hex is the same block for the external submitblock fallback
// (block_hex == HexStr(block_bytes)). Throws std::runtime_error if the assembled
// body's merkle root does not match the share-committed header root (fail-closed
// against a bad-txnmrklroot block -- see the header comment's template_capture
// interaction note).
inline std::pair<std::vector<unsigned char>, std::string>
assemble_won_block(const SmallBlockHeaderType& small_header,
                   const MutableTransaction& gentx,
                   const uint256& gentx_hash,
                   const ::btc::MerkleLink& merkle_link,
                   const std::vector<MutableTransaction>& other_txs)
{
    BlockType block;
    static_cast<BlockHeaderType&>(block) =
        reconstruct_block_header(small_header, gentx_hash, merkle_link);

    // Fail-closed body/header consistency guard: the share-committed header root
    // (the merkle_link walk) MUST equal the root the assembled body actually
    // hashes to, or the daemon rejects the block as bad-txnmrklroot. Reuses the
    // sealed compute_merkle_root SSOT -- NOT a new merkle path or a re-inject.
    const uint256 body_root = body_merkle_root(gentx_hash, other_txs);
    if (body_root != block.m_merkle_root)
        throw std::runtime_error(
            "assemble_won_block: assembled body merkle root " + body_root.GetHex() +
            " != share-committed header root " + block.m_merkle_root.GetHex() +
            " -- refusing to broadcast a bad-txnmrklroot block");

    // txs = [gentx] ++ other_txs (coinbase first; data.py as_block ordering).
    block.m_txs.reserve(1 + other_txs.size());
    block.m_txs.push_back(gentx);
    for (const auto& tx : other_txs)
        block.m_txs.push_back(tx);

    PackStream packed = pack<BlockType>(block);
    auto sp = packed.get_span();
    std::vector<unsigned char> bytes(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    std::string hex = HexStr(sp);
    return {std::move(bytes), std::move(hex)};
}

} // namespace coin
} // namespace btc
