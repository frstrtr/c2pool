#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::assemble_won_block -- the share->block "as_block" reassembly that
// the won-block reconstructor (#82) feeds to broadcast_won_block.
//
// This is the faithful C++ port of the FRAMING half of p2pool data.py
// Share.as_block(tracker, known_txs):
//
//     gentx     = self.check(tracker, known_txs)         # the coinbase tx
//     other_txs = [known_txs[h] for h in transaction_hashes]
//     return dict(header=self.header, txs=[gentx]+other_txs)
//
// Two consensus-relevant facts this captures:
//   1. p2pool stores only a SmallBlockHeader on the share (version|prev|time|
//      bits|nonce -- NO merkle_root).  The full block header's merkle_root is
//      RECONSTRUCTED as check_merkle_link(gentx_hash, share.m_merkle_link).
//      as_block/get_pow both recompute it this way; we must too, or the block
//      hashes wrong and the daemon rejects it.
//   2. Block tx order is [gentx] ++ other_txs, with other_txs in the share's
//      transaction_hashes order.  gentx is always index 0 (the coinbase).
//
// The gentx bytes and the other_txs are INJECTED (already deserialized
// MutableTransaction objects): the gentx-byte build (mirroring
// generate_share_transaction's coinbase assembly -- the part that will hit the
// coinbase-byte adjudication, cf. the BCH lane) and the known_txs lookup are
// the explicitly-next reconstructor slice.  Keeping them as inputs makes this
// framing build-verifiable and KAT-testable NOW (same seam-first decomposition
// as won_block_dispatch.hpp), and lets the proven BlockType serializer (the
// live submitblock path, rpc.cpp NodeRPC::submit_block) do the wire encoding so
// the reconstructed block is byte-identical to a daemon-built one.
//
// Per-coin isolation: src/impl/dgb/ only. p2pool-merged-v36 surface: NONE --
// block framing reuses BlockType + check_merkle_link verbatim; no share format,
// PoW hash, coinbase commitment, or PPLNS math is touched.  DGB-Scrypt is a
// STANDALONE parent in the V36 default build (no merged-coinbase leg).
// ---------------------------------------------------------------------------

#include <string>
#include <utility>
#include <vector>

#include <core/pack.hpp>
#include <util/strencodings.h>

#include "block.hpp"
#include "../share_check.hpp"   // dgb::check_merkle_link (SSOT merkle-branch walk)
#include "../share_types.hpp"   // dgb::MerkleLink

namespace dgb
{
namespace coin
{

// Reconstruct the full block header from the share's stored SmallBlockHeader
// plus the gentx hash + merkle link.  Mirrors the merkle_root recomputation in
// p2pool data.py get_pow_hash / as_block (SmallBlockHeader omits merkle_root).
inline BlockHeaderType
reconstruct_block_header(const SmallBlockHeaderType& small_header,
                         const uint256& gentx_hash,
                         const ::dgb::MerkleLink& merkle_link)
{
    BlockHeaderType header;
    header.m_version        = small_header.m_version;
    header.m_previous_block = small_header.m_previous_block;
    header.m_timestamp      = small_header.m_timestamp;
    header.m_bits           = small_header.m_bits;
    header.m_nonce          = small_header.m_nonce;
    // SmallBlockHeader has no merkle_root -- recompute it from the coinbase
    // (gentx) hash walked up the share's merkle branch, exactly as the share's
    // PoW hash was computed at verification time.
    header.m_merkle_root    = ::dgb::check_merkle_link(gentx_hash, merkle_link);
    return header;
}

// Assemble the full serialized parent block for a won share.
//   small_header  : share.m_min_header (version|prev|time|bits|nonce)
//   gentx         : the reconstructed coinbase transaction (block tx 0)
//   gentx_hash    : its txid (double-SHA256), for the merkle_root walk
//   merkle_link   : share.m_merkle_link (gentx -> merkle root branch)
//   other_txs     : the share's transaction_hashes resolved to txs, in order
// Returns {block_bytes, block_hex}: block_bytes is the blob the embedded P2P
// relay sends; block_hex is the same block for the external submitblock
// fallback.  Wire encoding is BlockType::Serialize (TX_WITH_WITNESS) -- the
// identical path NodeRPC::submit_block uses, so the result round-trips and the
// daemon accepts it.
inline std::pair<std::vector<unsigned char>, std::string>
assemble_won_block(const SmallBlockHeaderType& small_header,
                   const MutableTransaction& gentx,
                   const uint256& gentx_hash,
                   const ::dgb::MerkleLink& merkle_link,
                   const std::vector<MutableTransaction>& other_txs)
{
    BlockType block;
    static_cast<BlockHeaderType&>(block) =
        reconstruct_block_header(small_header, gentx_hash, merkle_link);

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
} // namespace dgb
