#pragma once

/// Phase C-TEMPLATE step 4c: vendor compute_merkle_root_quorums.
///
/// Mirrors dashcore evo/cbtx.cpp::CalcCbTxMerkleRootQuorums @ cfad414
/// using our QuorumManager state as input. Per-type ordering matches
/// dashcore's GetMinedCommitmentsUntilBlock semantics: for non-rotated
/// LLMQ types, hashes ordered NEWEST-FIRST by mining_height; for
/// rotated types, hashes per quorumIndex (latest mining_height per
/// index).
///
/// Algorithm:
///   1. Group active entries by llmqType.
///   2. Per non-rotated type: sort by mining_height DESC, take all
///      (mnlistdiff already enforced signingActiveQuorumCount cap).
///   3. Per rotated type: group by quorumIndex, take latest per index
///      by mining_height.
///   4. For each entry: hash = SHA256d(pack(commitment))
///      (= dashcore's SerializeHash(commitment) — NOT the wrapping
///      CFinalCommitmentTxPayload).
///   5. Concatenate per-type hash lists into vec_hashes_final
///      (std::map iteration = ascending llmqType, matching dashcore's
///      `for (const auto& [llmqType, vec] : qcHashes)` pattern).
///   6. Sort vec_hashes_final lexicographically using std::memcmp
///      (matches dashcore's uint256 operator< = LE-byte comparison;
///      same gotcha as Bug A in vendor/simplifiedmns.hpp's sort).
///   7. Compute Bitcoin/Dash merkle root over vec_hashes_final.
///
/// Limitations vs dashcore-bit-exact:
///   - We use OUR active set as of last applied mnlistdiff. Doesn't
///     include qfcommit additions from blocks not yet covered by
///     mnlistdiff (e.g., the current block being validated). For
///     [QUORUMS-XCHECK] log-only this means MISMATCH may fire on
///     blocks at or just past tip during catch-up.
///   - Entries with mining_height=0 (un-observed qfcommit, e.g.
///     pre-checkpoint quorums) sort to the END (oldest-equivalent).
///     If real ordering differs, MISMATCH surfaces it.
///
/// LLMQ params hardcoded for Dash mainnet (consensus/llmq.cpp):
///   type 1 LLMQ_50_60   useRotation=false signingCount=24
///   type 2 LLMQ_400_60  useRotation=false signingCount=4
///   type 3 LLMQ_400_85  useRotation=false signingCount=4
///   type 4 LLMQ_100_67  useRotation=false signingCount=24
///   type 5 LLMQ_60_75   useRotation=true  signingCount=32
///   type 6 LLMQ_25_67   useRotation=true  signingCount=24

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
    // Group entries by llmqType.
    std::map<uint8_t, std::vector<const QuorumManager::Entry*>> by_type;
    for (const auto& e : qmgr.active_entries()) {
        by_type[e.key.llmqType].push_back(&e);
    }

    std::vector<uint256> vec_hashes_final;
    vec_hashes_final.reserve(qmgr.active_entries().size());

    for (auto& [llmqType, entries] : by_type) {
        if (llmq_uses_rotation(llmqType)) {
            // Group by quorumIndex; pick latest mining_height per
            // index. dashcore iterates std::map<int, hash> = sorted
            // by quorumIndex ascending.
            std::map<int16_t, const QuorumManager::Entry*> by_index;
            for (auto* ep : entries) {
                int16_t qi = ep->commitment.quorumIndex;
                auto it = by_index.find(qi);
                if (it == by_index.end()
                    || ep->mining_height > it->second->mining_height) {
                    by_index[qi] = ep;
                }
            }
            for (auto& [_, ep] : by_index) {
                vec_hashes_final.push_back(hash_commitment(ep->commitment));
            }
        } else {
            // Non-rotated: sort by mining_height DESCENDING (newest
            // first). Tiebreak by quorumHash memcmp (deterministic
            // for entries with mining_height=0 / unknown).
            std::sort(entries.begin(), entries.end(),
                [](const QuorumManager::Entry* a,
                   const QuorumManager::Entry* b) {
                    if (a->mining_height != b->mining_height)
                        return a->mining_height > b->mining_height;
                    return std::memcmp(a->key.quorumHash.data(),
                                       b->key.quorumHash.data(), 32) < 0;
                });
            for (auto* ep : entries) {
                vec_hashes_final.push_back(hash_commitment(ep->commitment));
            }
        }
    }

    // Final sort: lexicographic by uint256 (memcmp = dashcore's
    // uint256 operator< for the `std::sort(vec_hashes_final.begin(),
    // vec_hashes_final.end())` call at cbtx.cpp:192).
    std::sort(vec_hashes_final.begin(), vec_hashes_final.end(),
        [](const uint256& a, const uint256& b) {
            return std::memcmp(a.data(), b.data(), 32) < 0;
        });

    return compute_merkle_root_local(std::move(vec_hashes_final));
}

} // namespace coin
} // namespace dash
