// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-TEMPLATE step 4c: vendor compute_merkle_root_quorums.
///
/// Mirrors dashcore evo/cbtx.cpp::CalcCbTxMerkleRootQuorums. The upstream
/// function collects ::SerializeHash(commitment) for every mined+active
/// commitment (all llmqTypes, INCLUDING every ring member of rotated types),
/// then does `std::sort(vec_hashes_final)` (uint256 operator< == memcmp of the
/// internal LE bytes) and computes the standard SHA256d merkle root.
///
/// Algorithm (byte-verified against real dashd — see below):
///   1. For each active entry: leaf = SHA256d(pack(commitment))
///      (= dashcore's SerializeHash(CFinalCommitment) — NOT the wrapping
///      CFinalCommitmentTxPayload). ALL entries, no per-index dedup, no
///      mining-height ordering, no per-type grouping.
///   2. Sort the leaves lexicographically via std::memcmp on the internal
///      bytes (== dashcore's uint256 operator<).
///   3. Standard Bitcoin/Dash merkle root (duplicate-last-on-odd) over the
///      sorted leaves.
///
/// Because the sort is over the leaf HASHES, delivery order / mining height /
/// per-type grouping are IRRELEVANT to the result — only the SET of active
/// commitments matters. That set is exactly what the mnlistdiff carries
/// (base list − deletedQuorums + newQuorums), so the root is fully derivable
/// from the wire with NO block-body qc ingest.
///
/// PROVEN byte-identical to dashd: over the block-1518412 testnet mnlistdiff
/// (109 active commitments across types 1-6, incl. 32+24 rotated ring members),
/// this reproduces dashd's committed merkleRootQuorums exactly
/// (test_dash_mnlistdiff_root_parity.cpp). A prior revision dedup'd rotated
/// types by quorumIndex, dropping ring-member leaves — that diverged (bad-cbtx).

#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/log.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <span>
#include <vector>

namespace dash {
namespace coin {

inline bool llmq_uses_rotation(uint8_t llmqType)
{
    // Mainnet rotation flags: types 5 (LLMQ_60_75) and 6 (LLMQ_25_67).
    return llmqType == 5 || llmqType == 6;
}

/// SHA256d of pack(commitment). Equivalent to dashcore's
/// SerializeHash(commitment) where commitment is CFinalCommitment
/// (NOT the wrapping CFinalCommitmentTxPayload).
inline uint256 hash_commitment(const vendor::CFinalCommitment& c)
{
    auto stream = ::pack(c);
    auto sp = stream.get_span();
    uint256 h;
    CHash256()
        .Write(std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(sp.data()), sp.size()))
        .Finalize(std::span<unsigned char>(h.data(), 32));
    return h;
}

/// Standard Bitcoin/Dash SHA256d-pairwise merkle root with
/// duplicate-last-on-odd. Same as the helper inlined in
/// vendor/simplifiedmns.hpp.
inline uint256 merkle_pair_hash(const uint256& a, const uint256& b)
{
    uint256 out;
    CHash256()
        .Write(std::span<const unsigned char>(a.data(), 32))
        .Write(std::span<const unsigned char>(b.data(), 32))
        .Finalize(std::span<unsigned char>(out.data(), 32));
    return out;
}

inline uint256 compute_merkle_root_local(std::vector<uint256> hashes)
{
    if (hashes.empty()) return uint256::ZERO;
    while (hashes.size() > 1) {
        if (hashes.size() & 1u) hashes.push_back(hashes.back());
        std::vector<uint256> next;
        next.reserve(hashes.size() / 2);
        for (size_t i = 0; i < hashes.size(); i += 2) {
            next.push_back(merkle_pair_hash(hashes[i], hashes[i + 1]));
        }
        hashes = std::move(next);
    }
    return hashes[0];
}

inline uint256 compute_merkle_root_quorums(const QuorumManager& qmgr)
{
    // dashcore evo/cbtx.cpp CalcCbTxMerkleRootQuorums: collect the SerializeHash
    // of EVERY mined+active commitment (across all llmqTypes, INCLUDING all ring
    // members of rotated types — no per-index dedup), then
    //   std::sort(vec_hashes_final.begin(), vec_hashes_final.end());
    // (uint256 operator< == memcmp of the internal little-endian bytes) and take
    // the standard SHA256d merkle root. Because the final sort is over the leaf
    // HASHES, the per-type grouping / delivery order / mining-height ordering is
    // irrelevant to the result — only the SET of leaf hashes matters.
    //
    // PROVEN byte-identical to real dashd: over the block-1518412 testnet
    // mnlistdiff (109 active commitments; types 1-6, incl. 32+24 rotated ring
    // members), this yields dashd's committed merkleRootQuorums
    // (test_dash_mnlistdiff_root_parity.cpp). The earlier per-index dedup of
    // rotated types dropped ring-member leaves and diverged (bad-cbtx).
    std::vector<uint256> vec_hashes_final;
    vec_hashes_final.reserve(qmgr.active_entries().size());
    for (const auto& e : qmgr.active_entries()) {
        vec_hashes_final.push_back(hash_commitment(e.commitment));
    }

    std::sort(vec_hashes_final.begin(), vec_hashes_final.end(),
        [](const uint256& a, const uint256& b) {
            return std::memcmp(a.data(), b.data(), 32) < 0;
        });

    return compute_merkle_root_local(std::move(vec_hashes_final));
}

} // namespace coin
} // namespace dash