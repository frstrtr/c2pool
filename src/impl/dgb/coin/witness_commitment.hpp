// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::add_witness_commitment -- the BIP141 coinbase witness-commitment
// injector for the won-block reconstructor (#82, POPULATED-block slice).
//
// THE BLOCKER it closes (G3b populated-block adjudication, 2026-06-25):
// assemble_won_block (block_assembly.hpp) frames the block through the standard
// Bitcoin-Core conditional serializer (BlockType::Serialize -> TX_WITH_WITNESS),
// which emits the per-tx witness marker/flag + witness stacks iff some tx
// HasWitness().  When the replayed mempool set carries SEGWIT transactions the
// block goes out witness-shaped -- but the reconstructed coinbase carries NO
// BIP141 witness commitment, so node B rejects it `unexpected-witness`
// (CheckWitnessMalleation).  The coinbase-only path drains witness and ACCEPTs;
// the populated path did not.  This seam supplies the missing commitment.
//
// Faithful port of Bitcoin Core GenerateCoinbaseCommitment
// (validation.cpp / src/validation.cpp BIP141):
//   1. witness_root = merkle root over wtxids, where the coinbase wtxid is
//      DEFINED to be 0x00..00 (BIP141), others are SHA256d(with-witness bytes);
//   2. commitment  = SHA256d(witness_root || witness_reserved_value), with the
//      reserved value a single 32-byte item (Core defaults it to all-zero);
//   3. coinbase gains an OUTPUT  value 0, scriptPubKey =
//      OP_RETURN 0x24 0xaa21a9ed <32-byte commitment> (38 bytes); AND
//   4. the coinbase INPUT[0] witness becomes exactly that one 32-byte reserved
//      value (BIP141 requires the coinbase witness be a single 32-byte item).
//
// Trigger discipline (assemble_won_block owns it): inject ONLY when the block
// body (other_txs) carries witness data.  A coinbase-only / all-legacy body
// needs no commitment and Core accepts it without one -- so the legacy and
// coinbase-only proofs stay byte-identical (zero regression).  Injecting
// changes the coinbase txid; the caller recomputes the block merkle_root over
// the post-injection coinbase txid (build_block_merkle_root), so header and
// body stay consistent by construction.
//
// Per-coin isolation: src/impl/dgb/ only.  Consumes core/ (hash, opscript,
// uint256) + the dgb tx codec; modifies NO shared layer.  p2pool-merged-v36
// surface: NONE -- DGB-Scrypt is a STANDALONE parent; this is parent-block
// (daemon-facing) assembly, not share format / PoW / PPLNS.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <vector>

#include <core/hash.hpp>
#include <core/opscript.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include "transaction.hpp"        // MutableTransaction, TxOut, TX_WITH_WITNESS
#include "merkle_root.hpp"        // build_block_merkle_root (merkle SSOT)

namespace dgb
{
namespace coin
{

// BIP141 commitment header tag that precedes the 32-byte commitment hash in the
// coinbase OP_RETURN output (Core: HEADER_BYTES).
inline constexpr unsigned char kWitnessCommitmentHeader[4] = {0xaa, 0x21, 0xa9, 0xed};

// True iff any non-coinbase tx in the block body carries witness data -- the
// condition under which BIP141 requires a coinbase witness commitment.
inline bool body_has_witness(const std::vector<MutableTransaction>& other_txs)
{
    for (const auto& tx : other_txs)
        if (tx.HasWitness())
            return true;
    return false;
}

// wtxid = SHA256d of the WITH-witness serialization.  For a non-witness tx this
// equals its txid (the with-witness blob has no marker/flag when HasWitness()
// is false), matching Core's CTransaction::GetWitnessHash().
inline uint256 compute_wtxid(const MutableTransaction& tx)
{
    auto packed = pack(TX_WITH_WITNESS(tx));
    return Hash(packed.get_span());
}

// Witness merkle root over [coinbase wtxid == 0x00..00] ++ other-tx wtxids,
// using the standard duplicate-last block-merkle SSOT.  The coinbase wtxid is
// fixed to zero per BIP141 (it cannot commit to a hash of itself).
inline uint256 compute_witness_merkle_root(const std::vector<MutableTransaction>& other_txs)
{
    std::vector<uint256> wids;
    wids.reserve(1 + other_txs.size());
    wids.push_back(uint256());                 // coinbase wtxid := 0 (BIP141)
    for (const auto& tx : other_txs)
        wids.push_back(compute_wtxid(tx));
    return build_block_merkle_root(std::move(wids));
}

// BIP141 commitment hash = SHA256d(witness_merkle_root || witness_reserved_value).
inline uint256 compute_witness_commitment_hash(const uint256& witness_root,
                                               const uint256& reserved_value)
{
    return Hash(witness_root, reserved_value);
}

// The 38-byte commitment scriptPubKey:
//   OP_RETURN(0x6a) PUSH36(0x24) 0xaa21a9ed <32-byte commitment>.
inline std::vector<unsigned char> witness_commitment_script(const uint256& commitment)
{
    std::vector<unsigned char> s;
    s.reserve(2 + 4 + 32);
    s.push_back(0x6a);   // OP_RETURN
    s.push_back(0x24);   // direct push of the following 36 bytes
    s.insert(s.end(), std::begin(kWitnessCommitmentHeader), std::end(kWitnessCommitmentHeader));
    s.insert(s.end(), commitment.data(), commitment.data() + 32);
    return s;
}

// Inject the BIP141 witness commitment into the coinbase (mutates in place):
//   * coinbase input[0] witness  := single 32-byte reserved value, and
//   * append a value-0 OP_RETURN commitment output.
// reserved_value defaults to the all-zero value Core uses.  Mirrors
// GenerateCoinbaseCommitment; the commitment output is appended LAST so a
// highest-index scan (Core's pattern) finds it.
inline void add_witness_commitment(MutableTransaction& coinbase,
                                   const std::vector<MutableTransaction>& other_txs,
                                   const uint256& reserved_value = uint256())
{
    const uint256 wroot      = compute_witness_merkle_root(other_txs);
    const uint256 commitment = compute_witness_commitment_hash(wroot, reserved_value);

    // Coinbase witness: exactly one 32-byte stack item (the reserved value).
    if (!coinbase.vin.empty())
    {
        std::vector<unsigned char> rv(reserved_value.data(), reserved_value.data() + 32);
        coinbase.vin[0].scriptWitness.stack.assign(1, std::move(rv));
    }

    // Commitment output: value 0, scriptPubKey = OP_RETURN 0x24 aa21a9ed <hash>.
    TxOut out;
    out.value = 0;
    const auto script = witness_commitment_script(commitment);
    out.scriptPubKey = OPScript(script.data(), script.data() + script.size());
    coinbase.vout.push_back(std::move(out));
}

} // namespace coin
} // namespace dgb