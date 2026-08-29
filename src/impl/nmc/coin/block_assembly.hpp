// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// nmc::coin::assemble_won_block -- the won-share->parent-block "as_block"
// reassembly that the PE-2e won-block reconstructor feeds to the BTC-parent
// broadcaster (broadcast_won_block: P2P relay + submitblock RPC fallback,
// already landed as the btc broadcaster gate).
//
// Faithful C++ port of the FRAMING half of p2pool data.py Share.as_block:
//     return dict(header=self.header, txs=[gentx]+other_txs)
//
// Two facts this captures (identical to the dgb #271 SSOT it mirrors):
//   1. p2pool stores only a SmallBlockHeader on the won share (version|prev|
//      time|bits|nonce -- NO merkle_root).  The full header's merkle_root is
//      RECONSTRUCTED by walking the coinbase (gentx) hash up the share's merkle
//      branch, exactly as the share's PoW hash was computed at verification
//      time.  NMC's SSOT for that walk is coin/header_chain.hpp
//      aux_merkle_root(leaf, branch, index) -- the same Bitcoin/Namecoin
//      SHA256d merkle-branch primitive the AuxPow legs use -- so the merkle
//      link is carried here as (branch, index), NMC's native form (no separate
//      MerkleLink struct exists in the nmc tree).
//   2. Block tx order is [gentx] ++ other_txs, gentx always index 0.
//
// The gentx + other_txs are INJECTED (already-deserialized MutableTransaction
// objects) so this framing is build-verifiable and KAT-able without a live
// ShareTracker/mempool, and the proven BlockType serializer (block.hpp,
// TX_WITH_WITNESS -- the live NodeRPC::submit_block codec) does the wire
// encoding, so the reconstructed block is byte-identical to a daemon-built one.
//
// Per-coin isolation: src/impl/nmc/ only.  p2pool-merged-v36 surface: NONE --
// reuses BlockType + aux_merkle_root verbatim; no share format, PoW hash,
// coinbase commitment, or PPLNS math is touched.  NMC is the embedded aux chain
// under the BTC SHA256d parent; this frames the PARENT block a won share found.
// ---------------------------------------------------------------------------

#include <string>
#include <utility>
#include <vector>

#include <core/pack.hpp>
#include <btclibs/util/strencodings.h>

#include "block.hpp"
#include "header_chain.hpp"   // nmc::coin::aux_merkle_root (SSOT merkle-branch walk)
#include "transaction.hpp"    // nmc::coin::MutableTransaction

namespace nmc
{
namespace coin
{

// Reconstruct the full block header from the won share's stored SmallBlockHeader
// plus the gentx hash + merkle branch.  Mirrors the merkle_root recomputation in
// p2pool data.py as_block (SmallBlockHeader omits merkle_root); the branch walk
// is NMC's aux_merkle_root SSOT (Bitcoin/Namecoin SHA256d convention).
inline BlockHeaderType
reconstruct_block_header(const SmallBlockHeaderType& small_header,
                         const uint256& gentx_hash,
                         const std::vector<uint256>& merkle_branch,
                         uint32_t merkle_index)
{
    BlockHeaderType header;
    header.m_version        = small_header.m_version;
    header.m_previous_block = small_header.m_previous_block;
    header.m_timestamp      = small_header.m_timestamp;
    header.m_bits           = small_header.m_bits;
    header.m_nonce          = small_header.m_nonce;
    // SmallBlockHeader carries no merkle_root -- recompute it from the coinbase
    // (gentx) hash walked up the share's merkle branch.  Empty branch (the
    // common won-share case: coinbase is the sole leaf the share commits to)
    // yields root == gentx_hash.
    header.m_merkle_root    = aux_merkle_root(gentx_hash, merkle_branch, merkle_index);
    return header;
}

// Assemble the full serialized parent block for a won share.
//   small_header  : the won share's SmallBlockHeader (version|prev|time|bits|nonce)
//   gentx         : the reconstructed coinbase transaction (block tx 0)
//   gentx_hash    : its txid (double-SHA256), for the merkle_root walk
//   merkle_branch : the share's gentx->merkle-root sibling branch (often empty)
//   merkle_index  : branch side-selector bits (0 for the empty/leaf case)
//   other_txs     : the non-coinbase txs, in block order (the captured GBT
//                   template's transactions[]; see reconstruct_won_block.hpp)
// Returns {block_bytes, block_hex}: block_bytes is the blob the embedded P2P
// relay sends; block_hex is the same block for the submitblock RPC fallback.
inline std::pair<std::vector<unsigned char>, std::string>
assemble_won_block(const SmallBlockHeaderType& small_header,
                   const MutableTransaction& gentx,
                   const uint256& gentx_hash,
                   const std::vector<uint256>& merkle_branch,
                   uint32_t merkle_index,
                   const std::vector<MutableTransaction>& other_txs)
{
    BlockType block;
    static_cast<BlockHeaderType&>(block) =
        reconstruct_block_header(small_header, gentx_hash, merkle_branch, merkle_index);

    // txs = [gentx] ++ other_txs  (coinbase first; data.py as_block ordering).
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
} // namespace nmc