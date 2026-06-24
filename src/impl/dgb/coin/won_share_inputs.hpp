#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::won_share_inputs -- the SHARE-SIDE half of the #82 faithful
// won-block reconstruct closure (the closure the run-loop installs as
// ShareTracker::m_on_block_found, now bound in main_dgb.cpp via
// dgb::coin::make_on_block_found -- the #82 dual-path broadcaster, no longer
// a nullopt stub). reconstruct_won_block_from_template (reconstruct_won_block.hpp)
// needs five inputs to frame a broadcastable block:
//
//     { small_header, merkle_link, gentx, gentx_hash, template_other_txs }
//
// Two of them the won share ALREADY CARRIES verbatim, version-agnostically:
//
//     small_header = share.m_min_header   (coin::SmallBlockHeaderType)
//     merkle_link  = share.m_merkle_link  (::dgb::MerkleLink)
//
// This seam pulls exactly those two. It touches no PoW, coinbase commitment,
// share format, or PPLNS math, so the p2pool-merged-v36 surface is NONE -- it
// is a pure read of already-validated share_info fields.
//
// The remaining three inputs land as their own slices and bind in the run-loop
// once they arrive:
//   * gentx + gentx_hash -- the inverse of the generate_share_transaction
//     out_gentx SSOT exposure (#173): GentxCoinbase{bytes,txid} -> a
//     MutableTransaction (the next reconstruct brick);
//   * template_other_txs -- the captured-GBT template-retention seam (#271:
//     the won block's non-coinbase set is the current_work snapshot the miner
//     was handed, NOT the share's tx_hash_refs), empty today, fills as the
//     embedded mempool tx-selection lands.
//
// Duck-typed on the share so this header stays OFF share.hpp's
// tracker/base_uint translation unit (the #143 limited-TU build trap) -- any
// type exposing m_min_header (SmallBlockHeaderType) and m_merkle_link
// (::dgb::MerkleLink) binds; in the run-loop, the live dgb::Share.
//
// Per-coin isolation: src/impl/dgb/ only.
// ---------------------------------------------------------------------------

#include "block_assembly.hpp"   // coin::SmallBlockHeaderType (re-exported)
#include "../share_types.hpp"   // ::dgb::MerkleLink

namespace dgb
{
namespace coin
{

// The two reconstruct inputs a won share carries verbatim.
struct WonShareInputs
{
    SmallBlockHeaderType small_header;   // <- share.m_min_header
    ::dgb::MerkleLink    merkle_link;    // <- share.m_merkle_link
};

// Extract them. Templated on the share to keep this off share.hpp's heavy TU;
// binds to dgb::Share in the run-loop.
template <class ShareT>
inline WonShareInputs won_share_inputs(const ShareT& share)
{
    return WonShareInputs{ share.m_min_header, share.m_merkle_link };
}

} // namespace coin
} // namespace dgb
