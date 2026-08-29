// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dgb::coin::serialize_won_block -- the won-block wire serializer for the
// Stratum submit path (work_source.cpp mining_submit / #82 dual-path sink).
//
// THE BLOCKER it closes (G3b, bad-txnmrklroot on the empty-embedded-chain
// won block): the reconstruct path hand-rolled the block framing and could
// emit a body the ALREADY-HASHED header does not commit to.  Two divergences
// live here, both of which digibyted rejects and neither of which the header
// can be re-derived around (the miner hashed the merkle root already -- any
// post-hoc coinbase mutation invalidates the PoW binding):
//
//   1. TX-SET vs COMMITMENT.  The header merkle root is the ascent of the
//      FROZEN stratum merkle branches from the coinbase txid.  When the job
//      carried NO branches (the empty-embedded-chain case: the branch cache
//      at get_stratum_merkle_branches() is still a Stage-4c stub returning
//      {}) the committed root IS the bare coinbase txid -- i.e. the miner
//      committed to a COINBASE-ONLY block.  Appending job->tx_data anyway
//      produces a body whose recomputed root cannot match -> bad-txnmrklroot,
//      deterministically.  The only correct emission is the committed one:
//      coinbase-only.  Dropping the extra txs forfeits their fees; shipping
//      them forfeits the whole block.  We ship the block.
//
//   2. BIP144 WITNESS FORM vs BIP141 COMMITMENT.  A witness-shaped coinbase
//      is only legal when it carries the BIP141 commitment output
//      (OP_RETURN 0x24 aa21a9ed <32B>); Core's CheckWitnessMalleation rejects
//      a witness-bearing coinbase without one (unexpected-witness).  The
//      PPLNS connection coinbase only carries the commitment when the
//      producer seam populates segwit_commitment_script (gentx_coinbase.hpp)
//      -- on the empty-chain path it does not.  Emitting the marker/flag
//      regardless is therefore a second guaranteed reject.  A coinbase-only /
//      all-legacy block needs no witness at all and Core accepts the legacy
//      serialization on a segwit-active chain, so the rule is: witness form
//      IFF the coinbase actually carries the commitment.  Injecting the
//      commitment here is NOT an option -- it changes the coinbase txid and
//      breaks the header the miner already hashed.  The commitment must be
//      present at JOB-BUILD time (coinb2), which is the producer-seam slice.
//
// Pure + byte-level (no tx codec, no chain state), so it is directly KAT-able
// against hand-built vectors.  Per-coin isolation: src/impl/dgb/ only; no
// core/ or shared-layer surface.  p2pool-merged-v36 surface: NONE -- this is
// parent-block (daemon-facing) framing, not share format / PoW / PPLNS.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>
#include <vector>

namespace dgb::coin
{

// BIP141 commitment scriptPubKey prefix: OP_RETURN PUSH36 aa21a9ed.
inline constexpr uint8_t kWitnessCommitmentPrefix[6] = {0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed};

// True iff the coinbase NON-witness serialization carries a BIP141 witness
// commitment output.  Byte-scan for the 6-byte scriptPubKey prefix followed by
// the 32-byte commitment -- the same shape Core scans for in
// GetWitnessCommitmentIndex(), without pulling in the tx codec.
inline bool coinbase_has_witness_commitment(const std::vector<uint8_t>& coinbase)
{
    if (coinbase.size() < sizeof(kWitnessCommitmentPrefix) + 32)
        return false;
    const size_t last = coinbase.size() - (sizeof(kWitnessCommitmentPrefix) + 32);
    for (size_t i = 0; i <= last; ++i) {
        bool hit = true;
        for (size_t j = 0; j < sizeof(kWitnessCommitmentPrefix); ++j) {
            if (coinbase[i + j] != kWitnessCommitmentPrefix[j]) { hit = false; break; }
        }
        if (hit) return true;
    }
    return false;
}

// BIP144 reserialization of the coinbase: marker/flag after the 4-byte version
// and a single 32-byte all-zero reserved witness item before the 4-byte
// locktime.  The txid is UNCHANGED (txid is defined over the non-witness
// bytes), so the header merkle root stays valid.
inline std::vector<uint8_t> to_bip144_coinbase(const std::vector<uint8_t>& coinbase)
{
    std::vector<uint8_t> out;
    out.reserve(coinbase.size() + 36);
    out.insert(out.end(), coinbase.begin(), coinbase.begin() + 4);   // version
    out.push_back(0x00);                                             // marker
    out.push_back(0x01);                                             // flag
    out.insert(out.end(), coinbase.begin() + 4, coinbase.end() - 4); // vin/vout
    out.push_back(0x01);                                             // stack_count = 1
    out.push_back(0x20);                                             // item_len    = 32
    out.insert(out.end(), 32, 0x00);                                 // reserved value
    out.insert(out.end(), coinbase.end() - 4, coinbase.end());       // locktime
    return out;
}

struct WonBlockAssembly
{
    std::vector<uint8_t> bytes;             // full block wire bytes
    size_t tx_count{0};                     // txs actually serialized (incl. coinbase)
    bool   witness_form{false};             // coinbase emitted BIP144?
    size_t dropped_txs{0};                  // body txs the header does not commit to
    bool   witness_form_suppressed{false};  // segwit_active but no BIP141 commitment
};

// Serialize header || varint(tx_count) || coinbase[+witness] || other_txs,
// enforcing the two invariants documented at the top of this file.
//
// committed_coinbase_only == "the job carried NO merkle branches", i.e. the
// header merkle root IS the bare coinbase txid.
inline WonBlockAssembly serialize_won_block(
    const std::vector<uint8_t>& header80,
    const std::vector<uint8_t>& coinbase,
    const std::vector<std::vector<uint8_t>>& other_txs,
    bool segwit_active,
    bool committed_coinbase_only)
{
    WonBlockAssembly out;

    // (1) Emit only the tx set the frozen header actually commits to.
    const std::vector<std::vector<uint8_t>> kNone;
    const bool drop = committed_coinbase_only && !other_txs.empty();
    const std::vector<std::vector<uint8_t>>& body = drop ? kNone : other_txs;
    out.dropped_txs = drop ? other_txs.size() : 0;

    // (2) Witness form IFF the coinbase carries the BIP141 commitment.
    const bool has_commitment = coinbase_has_witness_commitment(coinbase);
    out.witness_form = segwit_active && has_commitment && coinbase.size() >= 8;
    out.witness_form_suppressed = segwit_active && !out.witness_form;

    const std::vector<uint8_t> cb =
        out.witness_form ? to_bip144_coinbase(coinbase) : coinbase;

    out.tx_count = 1 + body.size();

    size_t body_bytes = 0;
    for (const auto& tx : body) body_bytes += tx.size();
    out.bytes.reserve(header80.size() + 9 + cb.size() + body_bytes);
    out.bytes.insert(out.bytes.end(), header80.begin(), header80.end());

    // tx-count varint (Bitcoin CompactSize).
    const uint64_t n = out.tx_count;
    if (n < 0xfd) {
        out.bytes.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xffff) {
        out.bytes.push_back(0xfd);
        out.bytes.push_back(static_cast<uint8_t>(n & 0xff));
        out.bytes.push_back(static_cast<uint8_t>((n >> 8) & 0xff));
    } else {
        out.bytes.push_back(0xfe);
        for (int i = 0; i < 4; ++i)
            out.bytes.push_back(static_cast<uint8_t>((n >> (8 * i)) & 0xff));
    }

    out.bytes.insert(out.bytes.end(), cb.begin(), cb.end());
    for (const auto& tx : body)
        out.bytes.insert(out.bytes.end(), tx.begin(), tx.end());
    return out;
}

} // namespace dgb::coin
