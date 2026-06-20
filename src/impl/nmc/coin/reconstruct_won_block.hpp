#pragma once
// ---------------------------------------------------------------------------
// nmc::coin::reconstruct_won_block_from_template -- the won merge-mined block
// (PE-2e) reconstructor BODY: rebuild the full serialized Namecoin parent block
// for a won aux share from the CAPTURED GBT TEMPLATE the miner was handed at
// job hand-out time (work.py current_work), NOT from any share tx ref-walk.
//
// Rationale (mirrors the dgb #82/#271 block-assembly audit, work.py @42ccca53):
//     transactions       = current_work['transactions']
//     tx_map             = dict(zip(transaction_hashes, transactions))
//     other_transactions = [tx_map[h] for h in other_transaction_hashes]
//     submit txs         = [new_hexed_gentx] + [tx['data'] for tx in other_txs]
// The broadcast block's non-coinbase tx set is the GBT template snapshot the
// miner mined against, never the share.  This is why the path is version-
// AGNOSTIC.
//
// NMC is an AUX-ONLY chain merge-mined under the BTC parent: there is no NMC
// sharechain, no MerkleLink, and no transaction_hash_refs ancestry substrate
// (unlike dgb, which is a standalone parent and carries all three).  So the
// captured-template path is the ONLY faithful won-block source for NMC, and the
// merkle root is computed DIRECTLY over the full tx-id set ([gentx] ++ template
// txids) via the proven coin/template_builder.hpp compute_merkle_root SSOT --
// there is no merkle-branch to walk because the whole template is in hand.
//
// Per-coin isolation: src/impl/nmc/ only.  p2pool-merged-v36 surface: NONE --
// pure composition of the captured template txs + the proven nmc::coin::BlockType
// serializer (the live submitblock / P2P-relay codec).  No share format, PoW,
// AuxPow, coinbase commitment or PPLNS math is touched.
//
// Failure posture: a coinbase-only captured template (transactions[]==[], the
// embedded path's value until mempool tx-selection wires) yields a valid
// coinbase-only block (correct-and-empty, merkle_root == gentx_hash), never a
// throw / fail-closed -- it fills automatically as tx-selection lands with no
// change to this seam.
// ---------------------------------------------------------------------------

#include <span>
#include <string>
#include <utility>
#include <vector>

#include <core/pack.hpp>           // pack<T>, PackStream, get_span
#include <core/uint256.hpp>
#include <util/strencodings.h>     // HexStr

#include "block.hpp"               // SmallBlockHeaderType, BlockType
#include "template_builder.hpp"    // compute_merkle_root (SHA256d merkle SSOT)
#include "transaction.hpp"         // MutableTransaction

namespace nmc
{
namespace coin
{

// The reconstructed parent block, ready for the won-block dual broadcast path:
//   bytes : the blob the embedded P2P relay sends
//   hex   : the same block for the external submitblock (RPC) fallback
struct ReconstructedWonBlock
{
    std::vector<unsigned char> bytes;
    std::string hex;
};

// Reconstruct the full serialized Namecoin parent block for a won aux share
// from the captured GBT template.
//
//   small_header         : the share's stored block header fields
//                          (version|prev|time|bits|nonce -- NO merkle_root)
//   gentx                : the block's coinbase tx, already deserialized (tx 0)
//   gentx_hash           : its txid (double-SHA256) == p2pool gentx_hash
//   template_other_txs   : the captured template's non-coinbase txs, in template
//                          order (current_work transactions[]); empty today
//   template_other_txids : their txids, in the SAME order (current_work
//                          transaction_hashes[]); captured alongside the txs so
//                          the merkle root needs no per-tx re-hash here
//
// Returns {bytes, hex} with hex == HexStr(bytes).  template_other_txs and
// template_other_txids MUST be the same length (caller invariant: they come
// from the one captured template).
inline ReconstructedWonBlock
reconstruct_won_block_from_template(
    const SmallBlockHeaderType& small_header,
    const MutableTransaction& gentx,
    const uint256& gentx_hash,
    const std::vector<MutableTransaction>& template_other_txs,
    const std::vector<uint256>& template_other_txids)
{
    // 1. Merkle root over the FULL block tx set: [gentx_hash] ++ template txids.
    //    Direct compute (not a branch walk): the aux path has the whole template.
    std::vector<uint256> txids;
    txids.reserve(1 + template_other_txids.size());
    txids.push_back(gentx_hash);
    txids.insert(txids.end(), template_other_txids.begin(), template_other_txids.end());

    // 2. Frame the full block header + [gentx] ++ template_other_txs.
    BlockType block;
    block.m_version        = small_header.m_version;
    block.m_previous_block = small_header.m_previous_block;
    block.m_timestamp      = small_header.m_timestamp;
    block.m_bits           = small_header.m_bits;
    block.m_nonce          = small_header.m_nonce;
    block.m_merkle_root    = compute_merkle_root(txids);
    block.m_txs.clear();
    block.m_txs.reserve(1 + template_other_txs.size());
    block.m_txs.push_back(gentx);
    for (const auto& tx : template_other_txs)
        block.m_txs.push_back(tx);

    // 3. Serialize to {bytes, hex} via the proven BlockType codec (the same
    //    wire encoding the live submitblock / P2P-relay path uses).
    PackStream packed = pack<BlockType>(block);
    auto sp = packed.get_span();
    std::vector<unsigned char> bytes(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    std::string hex = HexStr(sp);
    return ReconstructedWonBlock{std::move(bytes), std::move(hex)};
}

} // namespace coin
} // namespace nmc
