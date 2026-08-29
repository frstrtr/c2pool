// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::resolve_other_tx_hashes -- the won-block reconstructor's (#82)
// connecting tissue between a share's transaction_hash_refs and the ordered
// other_tx hash list that assemble_won_block (block_assembly.hpp) needs.
//
// Faithful C++ port of the ancestry resolution inside p2pool data.py
// Tracker.get_other_tx_hashes(share):
//
//     parents_needed = max(ref_share_count for ref_share_count, _ in
//                          share.share_info['transaction_hash_refs']) ...
//     other_tx_hashes = [
//         self.items[ self.get_nth_parent_hash(share.hash, ref_share_count) ]
//             .share_info['new_transaction_hashes'][ref_tx_count]
//         for ref_share_count, ref_tx_count in
//             share.share_info['transaction_hash_refs']
//     ]
//
// A transaction_hash_ref is a (share_count, tx_count) pair: walk back
// `share_count` generations from the won share (share_count == 0 is the won
// share ITSELF, matching get_nth_parent_hash(h, 0) == h), then index `tx_count`
// into THAT ancestor's new_transaction_hashes.  The result preserves ref order,
// which is the block's other_txs order ([gentx] ++ other_txs in as_block).
//
// Why a ref-walk and NOT a flat known_txs map (integrator 2026-06-19): the
// share format stores ancestry as back-references into ancestor shares'
// new_transaction_hashes (V34+ never embeds txs), so the ONLY faithful
// resolution is to re-walk that ancestry through the tracker.  A flat
// known_txs[hash] lookup would resolve the same hashes by accident on the
// happy path but diverges the moment two ancestors announce the same txid or
// a ref points past the locally-known set -- it cannot reproduce how the
// sharechain actually addresses a tx.
//
// The two tracker operations are INJECTED as callables (same seam-first
// decomposition as won_block_dispatch.hpp / WonBlockReconstructor) so the walk
// is unit-testable against a synthetic ancestry without standing up a live
// ShareTracker.  In the run-loop these bind to:
//   nth_parent_fn   = chain.get_nth_parent_via_skip(h, n)   (shared skip list)
//   new_tx_hashes_fn= chain.get_share(h).invoke([](auto* s){
//                         return s->m_tx_info.m_new_transaction_hashes; })
//
// Per-coin isolation: src/impl/dgb/ only.  p2pool-merged-v36 surface: NONE --
// this only re-reads share_info already validated by share_check; no share
// format, PoW, coinbase commitment, or PPLNS math is touched.
// ---------------------------------------------------------------------------

#include <functional>
#include <stdexcept>
#include <vector>

#include "../share_types.hpp"   // dgb::TxHashRefs, uint256

namespace dgb
{
namespace coin
{

// Resolve a share's transaction_hash_refs to the ordered other_tx hash list.
//
//   won_share_hash  : hash of the share that found the block (walk origin)
//   refs            : share.m_tx_info.m_transaction_hash_refs, in order
//   nth_parent_fn   : (start, n) -> hash of the n-th parent of `start`
//                     (n == 0 returns `start`); IsNull() if the walk runs off
//                     the end of the known sharechain
//   new_tx_hashes_fn: share_hash -> that share's new_transaction_hashes
//
// Returns the other_tx hashes in ref order.  Throws std::out_of_range if an
// ancestor walk-back exceeds the sharechain depth or a tx_count indexes past
// an ancestor's new_transaction_hashes -- both are malformed-share conditions
// that must fail the reconstruction loudly rather than emit a wrong block.
inline std::vector<uint256>
resolve_other_tx_hashes(
    const uint256& won_share_hash,
    const std::vector<TxHashRefs>& refs,
    const std::function<uint256(const uint256&, uint64_t)>& nth_parent_fn,
    const std::function<const std::vector<uint256>&(const uint256&)>& new_tx_hashes_fn)
{
    std::vector<uint256> out;
    out.reserve(refs.size());

    for (const auto& ref : refs)
    {
        const uint256 ancestor = nth_parent_fn(won_share_hash, ref.m_share_count);
        if (ancestor.IsNull())
            throw std::out_of_range(
                "resolve_other_tx_hashes: transaction_hash_ref share_count "
                "walks past the known sharechain");

        const std::vector<uint256>& nths = new_tx_hashes_fn(ancestor);
        if (ref.m_tx_count >= nths.size())
            throw std::out_of_range(
                "resolve_other_tx_hashes: transaction_hash_ref tx_count "
                "out of range for ancestor new_transaction_hashes");

        out.push_back(nths[ref.m_tx_count]);
    }

    return out;
}

} // namespace coin
} // namespace dgb