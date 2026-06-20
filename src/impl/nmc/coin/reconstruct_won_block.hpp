#pragma once
// ---------------------------------------------------------------------------
// nmc::coin::reconstruct_won_block_from_template -- the CORRECT won-block
// broadcast source for the PE-2e path, mirroring the dgb #271 captured-template
// reconstructor (the p2pool-merged-v36 block-assembly audit, work.py):
//
//     transactions       = self.current_work.value['transactions']
//     tx_map             = dict(zip(transaction_hashes, transactions))
//     other_transactions = [tx_map[h] for h in other_transaction_hashes]
//     submit txs         = [new_hexed_gentx] + [tx['data'] for tx in other_txs]
//
// The broadcast block's non-coinbase tx set is the GBT TEMPLATE snapshot the
// miner was handed at job hand-out time (current_work), NOT a share ref-walk.
// The ref-walk is a share-CHAIN peer-propagation mechanism; it is never the
// block-broadcast source.  That is why this path is version-AGNOSTIC: the share
// never carried the block tx set, so pre-v34 vs v34+/v36 makes no difference --
// there is nothing to source from the share for any version.  (NMC is the
// embedded aux chain; its won-block IS a BTC SHA256d parent block, and the
// parent's tx set always comes from the captured parent GBT template.)
//
// template_other_txs : the captured template's non-coinbase txs, in template
//                      order.  Empty today -- the embedded path emits
//                      transactions[]==[] until mempool tx-selection wires --
//                      which yields a valid coinbase-only block (correct-and-
//                      empty, NOT fail-closed).  It fills automatically as
//                      tx-selection lands, with no change to this seam.
//
// Frames [gentx] ++ template_other_txs via the assemble_won_block SSOT
// (identical merkle-root math + BlockType codec the live submitblock path
// uses), so the result round-trips and the daemon accepts.
//
// Per-coin isolation: src/impl/nmc/ only.  p2pool-merged-v36 surface: NONE.
// ---------------------------------------------------------------------------

#include <string>
#include <utility>
#include <vector>

#include <core/uint256.hpp>

#include "block_assembly.hpp"   // assemble_won_block (NMC SSOT framing)
#include "block.hpp"            // SmallBlockHeaderType
#include "transaction.hpp"      // MutableTransaction

namespace nmc
{
namespace coin
{

// The reconstructed parent block, ready for broadcast_won_block's dual path:
//   bytes : the blob the embedded P2P relay sends
//   hex   : the same block for the external submitblock (RPC) fallback
struct ReconstructedWonBlock
{
    std::vector<unsigned char> bytes;
    std::string hex;
};

// Reconstruct the full serialized parent block for a won share from the
// captured GBT template tx set (the correct, version-agnostic broadcast source).
//
//   small_header       : the won share's SmallBlockHeader
//   merkle_branch      : gentx -> merkle-root sibling branch (often empty)
//   merkle_index       : branch side-selector bits (0 for the leaf case)
//   gentx              : the share's coinbase tx, already deserialized (tx 0)
//   gentx_hash         : its txid (double-SHA256), for the merkle_root walk
//   template_other_txs : captured template non-coinbase txs, in template order
//
// Returns {bytes, hex} with hex == HexStr(bytes).
inline ReconstructedWonBlock
reconstruct_won_block_from_template(
    const SmallBlockHeaderType& small_header,
    const std::vector<uint256>& merkle_branch,
    uint32_t merkle_index,
    const MutableTransaction& gentx,
    const uint256& gentx_hash,
    const std::vector<MutableTransaction>& template_other_txs)
{
    auto framed = assemble_won_block(small_header, gentx, gentx_hash,
                                     merkle_branch, merkle_index, template_other_txs);
    return ReconstructedWonBlock{std::move(framed.first), std::move(framed.second)};
}

} // namespace coin
} // namespace nmc
