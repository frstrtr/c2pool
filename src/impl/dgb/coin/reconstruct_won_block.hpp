#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::reconstruct_won_block -- the won-block reconstructor's (#82) BODY:
// the single composition that the dispatch handler (won_block_dispatch.hpp,
// make_on_block_found) injects as its WonBlockReconstructor.  It ties the three
// previously-landed sub-slices into one faithful port of p2pool data.py
// Share.as_block(tracker, known_txs):
//
//     gentx     = self.check(tracker, known_txs)                 # coinbase tx
//     other_txs = [known_txs[h]
//                  for h in self.get_other_tx_hashes(tracker)]   # ref-walk
//     return dict(header=self.header, txs=[gentx]+other_txs)
//
// Composition (each step is its own unit-tested SSOT slice):
//   1. resolve_other_tx_hashes  (other_tx_resolver.hpp, sub-slice 1 / #174)
//        share.transaction_hash_refs --ancestry walk--> ordered other_tx hashes
//   2. assemble_other_txs        (other_tx_assembler.hpp, sub-slice 2 / #176)
//        ordered hashes --known_txs lookup--> deserialized MutableTransactions
//   3. assemble_won_block        (block_assembly.hpp, as_block FRAMING / #168)
//        small_header + gentx + merkle_link + other_txs --> {bytes, hex}
//        (merkle_root recomputed from gentx_hash up the share merkle_link;
//         txs = [gentx] ++ other_txs; BlockType codec = live submitblock path)
//
// The gentx enters as an already-deserialized MutableTransaction + its txid
// (gentx_hash), exactly as block_assembly_test models it.  In the run-loop this
// binds to the SSOT gentx that generate_share_transaction exposes via its
// out_gentx parameter (#173): GentxCoinbase{bytes, txid}.  Turning those SSOT
// non-witness bytes back into a MutableTransaction is the inverse of #173's
// exposure -- a distinct param-stream codec concern with its own round-trip KAT
// (the explicitly-next slice) -- so it is kept OUT of this pure-composition body
// to keep the as_block ordering + merkle math build-verifiable and KAT-able NOW.
//
// All three tracker/mempool operations are INJECTED as callables (the same
// seam-first decomposition the sub-slices already use), so the whole
// reconstruction is unit-testable against a synthetic ancestry + known-tx set
// without standing up a live ShareTracker / mempool.  In the run-loop they bind
// to (cf. won_block_dispatch.hpp / the sub-slice run-loop notes):
//   nth_parent_fn    = chain.get_nth_parent_via_skip(h, n)
//   new_tx_hashes_fn = chain.get_share(h)->m_tx_info.m_new_transaction_hashes
//   known_txs_fn     = node known-tx store (mempool + peer-relayed tx cache)
//
// Failure posture inherited from the sub-slices: a ref that walks past the
// known sharechain, a tx_count out of range, or an unknown other_tx hash each
// throw std::out_of_range -- a partial/wrong reconstruction would hash to the
// wrong merkle root and be rejected by the daemon, so failing loudly here is
// strictly safer than broadcasting a malformed block.
//
// Per-coin isolation: src/impl/dgb/ only.  p2pool-merged-v36 surface: NONE --
// pure composition of already-validated share_info + already-relayed txs + the
// proven BlockType serializer; no share format, PoW, coinbase commitment, or
// PPLNS math is touched.  DGB-Scrypt is a STANDALONE parent in the V36 default
// build (no merged-coinbase leg).
// ---------------------------------------------------------------------------

#include <functional>
#include <string>
#include <utility>
#include <vector>

#include <core/uint256.hpp>

#include "block_assembly.hpp"      // assemble_won_block, SmallBlockHeaderType, BlockType
#include "other_tx_resolver.hpp"   // resolve_other_tx_hashes
#include "other_tx_assembler.hpp"  // assemble_other_txs
#include "transaction.hpp"         // MutableTransaction
#include "../share_types.hpp"      // TxHashRefs, MerkleLink, uint256

namespace dgb
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

// Reconstruct the full serialized parent block for a won share.
//
//   small_header     : share.m_min_header (version|prev|time|bits|nonce)
//   merkle_link      : share.m_merkle_link (gentx -> merkle root branch)
//   gentx            : the share's coinbase tx, already deserialized (block tx 0)
//   gentx_hash       : its txid (double-SHA256) == p2pool gentx_hash, for the
//                      merkle_root walk
//   won_share_hash   : hash of the share that found the block (ref-walk origin)
//   refs             : share.m_tx_info.m_transaction_hash_refs, in order
//   nth_parent_fn    : (start, n) -> hash of the n-th parent (n==0 -> start);
//                      IsNull() if the walk runs off the known sharechain
//   new_tx_hashes_fn : share_hash -> that share's new_transaction_hashes
//   known_txs_fn     : hash -> pointer to the known MutableTransaction, or
//                      nullptr if absent
//
// Returns {bytes, hex} with hex == HexStr(bytes).  Throws std::out_of_range on
// any malformed-share / incomplete-known-txs condition (see the per-step slices).
inline ReconstructedWonBlock
reconstruct_won_block(
    const SmallBlockHeaderType& small_header,
    const ::dgb::MerkleLink& merkle_link,
    const MutableTransaction& gentx,
    const uint256& gentx_hash,
    const uint256& won_share_hash,
    const std::vector<TxHashRefs>& refs,
    const std::function<uint256(const uint256&, uint64_t)>& nth_parent_fn,
    const std::function<const std::vector<uint256>&(const uint256&)>& new_tx_hashes_fn,
    const std::function<const MutableTransaction*(const uint256&)>& known_txs_fn)
{
    // 1. share.transaction_hash_refs -> ordered other_tx hashes (ancestry walk).
    const std::vector<uint256> other_tx_hashes =
        resolve_other_tx_hashes(won_share_hash, refs, nth_parent_fn, new_tx_hashes_fn);

    // 2. ordered hashes -> deserialized MutableTransactions (known_txs lookup).
    const std::vector<MutableTransaction> other_txs =
        assemble_other_txs(other_tx_hashes, known_txs_fn);

    // 3. small_header + gentx + merkle_link + other_txs -> {bytes, hex}.
    //    (merkle_root recomputed from gentx_hash up merkle_link; [gentx]++others.)
    auto framed = assemble_won_block(small_header, gentx, gentx_hash, merkle_link, other_txs);

    return ReconstructedWonBlock{std::move(framed.first), std::move(framed.second)};
}

} // namespace coin
} // namespace dgb
