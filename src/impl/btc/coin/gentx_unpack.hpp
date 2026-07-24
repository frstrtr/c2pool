// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// btc::coin::unpack_gentx_coinbase -- the codec that turns a share's SSOT
// non-witness gentx (coinbase) bytes back into a deserialized MutableTransaction
// ready to inject at block tx index 0 of the won-block reconstructor. It is the
// first landed sub-slice of the faithful share->block reassembly (p2pool data.py
// Share.as_block) that the #744 dispatch handler (won_block_dispatch.hpp) still
// carries only as an INJECTED std::function stub.
//
// In the run-loop the gentx bytes come from BTC's generate_share_transaction
// SSOT (share_check.hpp) -- the single coinbase wire layout consumed by both
// emission and verification -- and reconstruct_won_block(_from_template) injects
// the resulting {MutableTransaction, txid} at tx index 0, taking the remaining
// (non-coinbase) txs from the GBT template the miner was handed (NOT the share's
// tx_hash_refs, which v34+ shares do not carry). This slice is deliberately the
// byte<->object codec step ONLY, kept OUT of the pure composition body so the
// as_block ordering + merkle math stay build-verifiable on injected inputs while
// this round-trip is pinned by its own KAT (gentx_unpack_test.cpp).
//
// CRITICAL: the gentx is a NON-WITNESS coinbase and MUST round-trip its
// non-witness bytes EXACTLY -- the txid (double-SHA256 of the non-witness
// serialization == p2pool gentx_hash) is what the merkle_root walk in the
// won-block framing consumes, so any witness/serialization drift here corrupts
// the assembled block's merkle root and the daemon rejects it. We therefore
// unpack with TX_NO_WITNESS: the coinbase vin count is a non-zero 0x01 (never
// the 0x00 segwit dummy), so this parses version|vin|vout|locktime with no
// witness branch and CANNOT consume a witness marker/flag or attach a witness
// stack. The recovered MutableTransaction has empty witness stacks
// (HasWitness()==false), so re-serializing it -- even inside the TX_WITH_WITNESS
// BlockType codec -- emits the identical non-witness bytes and a stable txid.
//
// Failure posture mirrors the DGB sub-slice (src/impl/dgb/coin/gentx_unpack.hpp):
// trailing bytes after a complete tx mean the input is not a clean gentx
// serialization; we throw std::out_of_range rather than silently accept a
// truncated/over-long blob, since a wrong coinbase hashes to the wrong merkle
// root. The reconstruct closure catches this and fails closed (announce + audit,
// RPC submitblock fallback still attempts) rather than broadcasting a bad block.
//
// Per-coin isolation: src/impl/btc/ only. p2pool-merged-v36 surface: NONE --
// this is the inverse of an already-oracle-pinned serializer; no share format,
// PoW, coinbase commitment, or PPLNS math is touched.
// ---------------------------------------------------------------------------

#include <stdexcept>
#include <utility>
#include <vector>

#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/uint256.hpp>

#include "transaction.hpp"   // btc::coin::MutableTransaction, TX_NO_WITNESS

namespace btc
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

// Non-witness gentx bytes -> {MutableTransaction, txid}. Throws std::out_of_range
// if the input carries trailing bytes past a complete transaction (malformed
// gentx serialization).
inline UnpackedGentx
unpack_gentx_coinbase(const std::vector<unsigned char>& gentx_bytes)
{
    PackStream ps(gentx_bytes);

    MutableTransaction tx;
    // Non-witness parse: the coinbase vin count is 0x01 (never the segwit 0x00
    // dummy), so this reads version|vin|vout|locktime with no witness branch --
    // guaranteeing the empty-witness, byte-exact round-trip the merkle_root walk
    // depends on.
    UnserializeTransaction(tx, ps, TX_NO_WITNESS);

    if (!ps.empty())
        throw std::out_of_range(
            "unpack_gentx_coinbase: trailing bytes after gentx -- "
            "input is not a clean non-witness coinbase serialization");

    UnpackedGentx out;
    // txid = SHA256d of the (canonical) non-witness re-serialization; equals the
    // gentx_hash the SSOT serializer computed over the same layout.
    out.txid = Hash(pack(TX_NO_WITNESS(tx)).get_span());
    out.tx   = std::move(tx);
    return out;
}

} // namespace coin
} // namespace btc
