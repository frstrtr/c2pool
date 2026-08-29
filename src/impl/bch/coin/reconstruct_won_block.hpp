// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// bch::coin -- won-share -> parent-block RECONSTRUCTOR.
//
// The pool node holds a won share, not a block. Turning one into the other is
// three steps, and BCH previously did all three inline in the pool node with no
// gate between the last step and the wire:
//
//   1. rebuild the 80-byte header the miner actually solved. The share stores
//      only a SmallBlockHeader (version | prev | time | bits | nonce) -- NO
//      transaction root -- so the root is recomputed by walking the generation
//      transaction's txid up the share's merkle link, exactly as the share's
//      proof-of-work hash was computed at verification time;
//   2. frame `header || CompactSize(1 + n) || gentx || other_txs`; and
//   3. REFUSE to relay unless the framed bytes re-deserialize and their
//      recomputed transaction root matches the header from step 1.
//
// Step 3 is the part that was missing. See block_assembly.hpp for the G2
// zero-blocks post-mortem (155-byte body, `bad-txnmrklroot`, ~774k solutions,
// zero blocks) that motivates it.
//
// The generation transaction is supplied as the EXACT serialized buffer its
// txid was hashed from, so no second derivation path exists and the relayed
// coinbase cannot drift from the one the sharechain validated.
//
// DEGRADED PATHS are first-class here, not afterthoughts:
//   * reference hash absent  -> the header root cannot be trusted; the caller
//     must not relay. The self-check catches it as a root mismatch and names it.
//   * generation value zero / no outputs -> refused by name before it reaches
//     the wire (this is the exact G2 signature).
//
// Per-coin isolation: src/impl/bch/ ONLY. p2pool-merged-v36 SURFACE: NONE.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include "block_assembly.hpp"

namespace bch
{
namespace coin
{

/// Serialize the canonical 80-byte BCH block header. BCH did not change the
/// header layout from Bitcoin: 4-byte version | 32 prev | 32 root | 4 time |
/// 4 bits | 4 nonce. ASERT (Nov 2020) changes how `bits` is COMPUTED, not where
/// it sits. Returns an empty vector if the encoding did not come out at exactly
/// 80 bytes, which callers must treat as a hard refusal.
inline std::vector<unsigned char>
serialize_block_header80(uint32_t version,
                         const uint256& previous_block,
                         const uint256& merkle_root,
                         uint32_t timestamp,
                         uint32_t bits,
                         uint32_t nonce)
{
    PackStream s;
    s << version;
    s << previous_block;
    s << merkle_root;
    s << timestamp;
    s << bits;
    s << nonce;

    if (s.size() != 80)
        return {};

    auto sp = s.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

/// Reconstruct + self-check a won parent block from its already-resolved parts.
///
///   header80   : the 80-byte header the miner solved (serialize_block_header80)
///   gentx_bytes: the generation transaction, byte-identical to the buffer its
///                txid was hashed from
///   other_txs  : the non-coinbase transactions in block order (pointers; any
///                type PackStream `<<` accepts). CTOR ordering is the caller's
///                responsibility -- it is a property of the set, not of framing.
///
/// Returns nullopt when the block MUST NOT be relayed; `out_check.reason` names
/// why. A returned value has already round-tripped through the wire form and
/// matched its own transaction root against the solved header.
template <class OtherTxPtrRange>
inline std::optional<AssembledBlock>
reconstruct_won_block_from_parts(std::span<const unsigned char> header80,
                                 std::span<const unsigned char> gentx_bytes,
                                 const OtherTxPtrRange& other_txs,
                                 BlockSelfCheck* out_check = nullptr)
{
    BlockSelfCheck local;
    BlockSelfCheck* check = out_check ? out_check : &local;

    if (header80.size() != 80) {
        check->ok = false;
        check->reason = "header is not 80 bytes";
        return std::nullopt;
    }
    if (gentx_bytes.empty()) {
        check->ok = false;
        check->reason = "generation transaction body is empty";
        return std::nullopt;
    }

    return assemble_and_verify_won_block(header80, gentx_bytes, other_txs, check);
}

} // namespace coin
} // namespace bch
