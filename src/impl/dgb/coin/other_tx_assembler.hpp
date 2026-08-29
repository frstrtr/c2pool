// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::assemble_other_txs -- the won-block reconstructor's (#82) bridge
// between the ORDERED other_tx hash list (resolve_other_tx_hashes, sub-slice 1)
// and the deserialized MutableTransaction vector that assemble_won_block
// (block_assembly.hpp) frames as txs = [gentx] ++ other_txs.
//
// Faithful C++ port of the known_txs lookup inside p2pool data.py
// Share.as_block(tracker, known_txs):
//
//     other_txs = [known_txs[h] for h in transaction_hashes]
//
// resolve_other_tx_hashes already produced `transaction_hashes` (the ref-walk
// over ancestor new_transaction_hashes, in block other_txs order); this slice
// is the remaining `known_txs[h]` indexing.  Each hash is resolved through an
// INJECTED lookup (same seam-first decomposition as other_tx_resolver.hpp /
// won_block_dispatch.hpp), so the bridge is unit-testable against a synthetic
// known-tx set without standing up a live mempool / ShareTracker.  In the
// run-loop known_txs_fn binds to the node's known-transaction store (mempool +
// peer-relayed tx cache), the same set share verification populated.
//
// Failure mode (integrator 2026-06-19, mirroring sub-slice 1): a missing hash
// is a malformed/incomplete-reconstruction condition -- p2pool's known_txs[h]
// raises KeyError.  We throw std::out_of_range rather than skip the tx or emit
// a placeholder: a block with a dropped/wrong other_tx has the wrong merkle
// root and is rejected by the daemon, so failing loudly here is strictly safer
// than shipping a malformed block to the network.
//
// Witness framing is NOT decided here.  assemble_other_txs returns the txs
// verbatim (whatever witness stacks they carry); the block's witness SHAPE is
// governed downstream by assemble_won_block's TX_WITH_WITNESS conditional
// serializer, which emits the segwit marker/flag iff some tx HasWitness().
// DGB is segwit-active (share_types.hpp SEGWIT_ACTIVATION_VERSION, v36 >= it),
// so that path is LIVE -- a witness-bearing other_tx (or gentx) yields a
// segwit block, exactly as the daemon's submitblock codec expects.
//
// Per-coin isolation: src/impl/dgb/ only.  p2pool-merged-v36 surface: NONE --
// this only re-reads transactions already validated/relayed into known_txs; no
// share format, PoW, coinbase commitment, or PPLNS math is touched.
// ---------------------------------------------------------------------------

#include <functional>
#include <stdexcept>
#include <vector>

#include <core/uint256.hpp>

#include "transaction.hpp"   // dgb::coin::MutableTransaction

namespace dgb
{
namespace coin
{

// Resolve an ordered other_tx hash list to the deserialized transactions that
// assemble_won_block frames after the gentx.
//
//   other_tx_hashes : output of resolve_other_tx_hashes, in block other_txs
//                     order (= share transaction_hash_refs order)
//   known_txs_fn    : hash -> pointer to the known MutableTransaction, or
//                     nullptr if the hash is not in the known-tx set
//
// Returns the transactions in the SAME order as other_tx_hashes (order is
// consensus-relevant: it fixes the block merkle root).  Throws std::out_of_range
// if any hash is unknown -- a block with a missing other_tx would hash wrong and
// be rejected, so the reconstruction must fail loudly rather than emit it.
inline std::vector<MutableTransaction>
assemble_other_txs(
    const std::vector<uint256>& other_tx_hashes,
    const std::function<const MutableTransaction*(const uint256&)>& known_txs_fn)
{
    std::vector<MutableTransaction> out;
    out.reserve(other_tx_hashes.size());

    for (const auto& h : other_tx_hashes)
    {
        const MutableTransaction* tx = known_txs_fn(h);
        if (tx == nullptr)
            throw std::out_of_range(
                "assemble_other_txs: other_tx hash not present in known_txs -- "
                "cannot reconstruct a complete won block");
        out.push_back(*tx);
    }

    return out;
}

} // namespace coin
} // namespace dgb