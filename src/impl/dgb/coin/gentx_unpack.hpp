#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::unpack_gentx_coinbase -- the INVERSE of #173's GentxCoinbase
// exposure: turn the SSOT non-witness gentx bytes that
// generate_share_transaction surfaces (out_gentx, GentxCoinbase{bytes, txid})
// back into a deserialized MutableTransaction, ready to inject at block tx
// index 0 of the won-block reconstructor (reconstruct_won_block.hpp).
//
// reconstruct_won_block() takes the gentx as an already-deserialized
// MutableTransaction + its gentx_hash; in the run-loop those come from the
// share's own SSOT coinbase (gentx_coinbase.hpp assemble_gentx_coinbase, the
// single wire layout consumed by both emission and verification). This slice
// is the codec step between the two -- deliberately kept OUT of the pure
// composition body (reconstruct_won_block.hpp header note) so the as_block
// ordering + merkle math stay build-verifiable on injected inputs, while the
// byte<->object round-trip is pinned by its own KAT here.
//
// CRITICAL (integrator 2026-06-19): the gentx is a NON-WITNESS coinbase and
// MUST round-trip its non-witness bytes EXACTLY -- the txid (double-SHA256 of
// the non-witness serialization == p2pool gentx_hash) is what the merkle_root
// walk in assemble_won_block consumes, so any witness/serialization drift here
// corrupts the assembled block's merkle root and the daemon rejects it. We
// therefore unpack with TX_NO_WITNESS: the coinbase vin count is a non-zero
// 0x01 (never the 0x00 segwit dummy), so this parses the body unambiguously
// and CANNOT consume a witness marker/flag or attach a witness stack. The
// resulting MutableTransaction has empty witness stacks (HasWitness()==false),
// so re-serializing it -- even inside assemble_won_block's TX_WITH_WITNESS
// BlockType codec -- emits the identical non-witness bytes and a stable txid.
//
// Failure posture mirrors the sibling reconstructor slices: trailing bytes
// after a complete tx mean the input is not a clean gentx serialization; we
// throw std::out_of_range rather than silently accept a truncated/over-long
// blob, since a wrong coinbase hashes to the wrong merkle root.
//
// Per-coin isolation: src/impl/dgb/ only. p2pool-merged-v36 surface: NONE --
// this is the inverse of an already-oracle-pinned serializer; no share format,
// PoW, coinbase commitment, or PPLNS math is touched.
// ---------------------------------------------------------------------------

#include <stdexcept>
#include <utility>
#include <vector>

#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/uint256.hpp>

#include "transaction.hpp"   // dgb::coin::MutableTransaction, TX_NO_WITNESS

namespace dgb
{
namespace coin
{

// The deserialized gentx ready for injection at block tx index 0.
//   tx   : MutableTransaction reconstructed from the non-witness bytes
//   txid : double-SHA256(non-witness serialization) == p2pool gentx_hash
struct UnpackedGentx
{
    MutableTransaction tx;
    uint256 txid;
};

// Inverse of assemble_gentx_coinbase (#173 exposure): non-witness gentx bytes
// -> {MutableTransaction, txid}. Throws std::out_of_range if the input carries
// trailing bytes past a complete transaction (malformed gentx serialization).
inline UnpackedGentx
unpack_gentx_coinbase(const std::vector<unsigned char>& gentx_bytes)
{
    PackStream ps(gentx_bytes);

    MutableTransaction tx;
    // Non-witness parse: the coinbase vin count is 0x01 (never the segwit
    // 0x00 dummy), so this reads version|vin|vout|locktime with no witness
    // branch -- guaranteeing the empty-witness, byte-exact round-trip the
    // merkle_root walk depends on.
    UnserializeTransaction(tx, ps, TX_NO_WITNESS);

    if (!ps.empty())
        throw std::out_of_range(
            "unpack_gentx_coinbase: trailing bytes after gentx -- "
            "input is not a clean non-witness coinbase serialization");

    UnpackedGentx out;
    // txid = SHA256d of the (canonical) non-witness re-serialization; equals
    // the gentx_hash assemble_gentx_coinbase computed over the same layout.
    out.txid = Hash(pack(TX_NO_WITNESS(tx)).get_span());
    out.tx   = std::move(tx);
    return out;
}

} // namespace coin
} // namespace dgb
