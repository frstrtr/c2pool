// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// E1 Phase-L — deterministic quorum MEMBER-SET computation, the last piece
/// #812's verify_final_commitment needs to serve REAL (non-null) type-6
/// commitments instead of failing closed to null-serve.
///
/// #812 cut the MemberKeysProvider seam (bls_verify.hpp): given a quorum
/// (llmqType, quorumHash) it must yield the ORDERED list of member operator
/// BLS public keys (index-aligned with the commitment's signers/validMembers
/// bitsets), each carrying the wire scheme (legacy vs basic) the key was
/// serialized under. verify_final_commitment's membersSig leg is a secure
/// aggregate over the SIGNERS' operator keys — a peer cannot forge it, so the
/// member set is what proves authenticity. This module computes that set.
///
/// REUSE-FIRST (operator mandate — vendor Dash Core, do not hand-roll):
/// this is dashcore llmq/utils.cpp ComputeQuorumMembers + dmnman
/// CDeterministicMNList::CalculateQuorum / CalculateScores, over the SML AS OF
/// the quorum base block:
///
///   * modifier   = utils::GetHashModifier. Post-V20 (the only era this module
///     serves — see kV20Floor) the non-rotated modifier is
///         SerializeHash( make_tuple(llmqType, workHeight, bestCLSignature) )
///     where workHeight = quorumBaseHeight - 8 and bestCLSignature is the
///     coinbase ChainLock of the work block (GetNonNullCoinbaseChainlock —
///     walk back to the nearest non-null). SerializeHash == SHA256d. When no
///     non-null CL exists the upstream fallback is SerializeHash(make_pair(
///     llmqType, workBlockHash)). VERIFIED byte-exact against testnet dashd
///     (llmq_50_60 @ base 1519920 -> the 50-member order dashd reports).
///   * score      = CDeterministicMNList::CalculateScores, per confirmed+valid
///     MN: sha256( sha256(proRegTxHash || confirmedHash) || modifier ), the
///     "confirmedHashWithProRegTxHash" precompute folded in. UNCONFIRMED
///     (null confirmedHash) and INVALID (PoSe-banned) MNs are excluded, exactly
///     as ForEachMN(onlyValid=true) + the confirmedHash.IsNull() skip.
///   * selection  = CalculateQuorum: sort DESCENDING by score (arith_uint256,
///     i.e. little-endian numeric on the 32 score bytes), tie-break by
///     proRegTxHash ascending, take the top llmqParams.size.
///   * keys       = each selected MN's SML pubKeyOperator (48 wire bytes) with
///     legacy_scheme = (nVersion == VER_LEGACY_BLS) — the #812 finding: the SML
///     nVersion is the ONLY unambiguous scheme signal for a mixed quorum.
///
/// ROTATED (DIP-24, llmq_60_75): ComputeQuorumMembersByQuarterRotation over
/// the cycle snapshots (qrinfo) is NOT implemented here — compute_quorum_members
/// returns std::nullopt for a rotated type, so the verifier FAILS CLOSED and
/// the rotated-window slot mines the consensus-valid null commitment (reward-
/// safe). Documented follow-up.
///
/// FAIL-CLOSED throughout: pre-V20 height, rotated type, empty/short SML, a
/// selected MN with a zero operator key, fewer confirmed+valid MNs than the
/// quorum size, or an unresolved modifier -> std::nullopt. A member set we are
/// not certain of is never handed to the verifier.

#include <impl/dash/coin/vendor/bls_verify.hpp>       // MemberOperatorKey
#include <impl/dash/coin/vendor/simplifiedmns.hpp>    // CSimplifiedMNList[Entry]

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>   // CSHA256, CHash256

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {

// ── quorum-member computation params (subset of dkg_commitments LlmqParamsView,
//    kept local so this header stays lightweight) ────────────────────────────
struct QuorumMemberParams {
    uint8_t  type{0};
    uint16_t size{0};
    bool     use_rotation{false};
};

// V20 activation floor (chainparams.cpp DEPLOYMENT_V20 nActivationHeight).
// This module ONLY serves member sets for quorums whose WORK block is post-V20
// (the modifier era it reproduces). Below it -> std::nullopt -> null-serve
// (reward-safe: the DKG-window slot mines the consensus-valid null commitment,
// or the arm falls back to dashd). RE-DIFF on a vendored-dashcore pin bump.
inline constexpr uint32_t kV20FloorMainnet = 1'987'776u;
inline constexpr uint32_t kV20FloorTestnet =   905'100u;

/// utils::GetHashModifier, post-V20 non-rotated form (SHA256d over the
/// (llmqType, workHeight, bestCLSignature) tuple). `best_cl_sig` is the
/// coinbase ChainLock of the work block (nearest non-null, per
/// GetNonNullCoinbaseChainlock). When absent, the upstream fallback hashes
/// (llmqType, workBlockHash). Byte-exact with dashcore's ::SerializeHash.
inline uint256 compute_quorum_modifier(
    uint8_t llmq_type, uint32_t work_height,
    const std::optional<std::array<uint8_t, CFinalCommitment::BLS_SIG_SIZE>>& best_cl_sig,
    const uint256& work_block_hash)
{
    ::PackStream s;
    s << llmq_type;                                  // uint8 (LLMQType)
    if (best_cl_sig) {
        // make_tuple(type, nHeight(int32 LE), CBLSSignature(96 wire bytes))
        s << static_cast<int32_t>(work_height);
        s.write(std::as_bytes(std::span{*best_cl_sig}));
    } else {
        // make_pair(type, workBlockHash) — CL-absent fallback.
        s << work_block_hash;
    }
    auto sp = s.get_span();
    uint256 h;
    CHash256()
        .Write(std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(sp.data()), sp.size()))
        .Finalize(std::span<unsigned char>(h.data(), 32));
    return h;
}

namespace detail {

// CDeterministicMNList score of one MN under a modifier:
//   sha256( sha256(proRegTxHash || confirmedHash) || modifier )   (single-SHA256
// each step — NOT double). Byte order is the raw internal LE bytes the wire /
// uint256 storage already holds (dashcore hashes over .begin()).
inline std::array<uint8_t, 32> mn_score(const CSimplifiedMNListEntry& e,
                                        const uint256& modifier)
{
    std::array<uint8_t, 32> chwp{};
    CSHA256()
        .Write(e.proRegTxHash.data(), 32)
        .Write(e.confirmedHash.data(), 32)
        .Finalize(chwp.data());
    std::array<uint8_t, 32> score{};
    CSHA256()
        .Write(chwp.data(), 32)
        .Write(modifier.data(), 32)
        .Finalize(score.data());
    return score;
}

// arith_uint256 comparison == little-endian numeric on the 32 score bytes
// (UintToArith256 loads bytes LE into limbs). Returns true iff a < b.
inline bool score_lt(const std::array<uint8_t, 32>& a,
                     const std::array<uint8_t, 32>& b)
{
    for (int i = 31; i >= 0; --i) {
        if (a[i] != b[i]) return a[i] < b[i];
    }
    return false;
}

inline bool is_all_zero(const std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>& k)
{
    for (auto x : k) if (x != 0) return false;
    return true;
}

} // namespace detail

/// dashcore ComputeQuorumMembers + CalculateQuorum for a NON-ROTATED quorum:
/// select the top `params.size` confirmed+valid MNs from `sml` by descending
/// score under `modifier`, and return their operator keys in that order.
///
/// std::nullopt when: the type is rotated (unsupported here), the SML holds
/// fewer confirmed+valid MNs than params.size (cannot form the quorum), or a
/// selected MN carries a zero operator key. The returned vector has exactly
/// params.size entries, index-aligned with the commitment's signers /
/// validMembers bitsets.
inline std::optional<std::vector<MemberOperatorKey>> compute_quorum_members(
    const QuorumMemberParams& params, const uint256& modifier,
    const CSimplifiedMNList& sml)
{
    if (params.use_rotation) return std::nullopt;   // DIP-24: qrinfo follow-up
    if (params.size == 0) return std::nullopt;

    struct Scored {
        std::array<uint8_t, 32> score;
        const CSimplifiedMNListEntry* mn;
    };
    std::vector<Scored> scored;
    scored.reserve(sml.mnList.size());
    for (const auto& e : sml.mnList) {
        if (!e.isValid) continue;                    // ForEachMN(onlyValid)
        if (e.confirmedHash.IsNull()) continue;      // unconfirmed -> skip
        scored.push_back(Scored{detail::mn_score(e, modifier), &e});
    }
    if (scored.size() < params.size) return std::nullopt;   // cannot form quorum

    // CalculateQuorum: descending by score, tie-break proRegTxHash ascending
    // (dashcore uint256 operator< == memcmp of the raw bytes).
    std::sort(scored.begin(), scored.end(),
        [](const Scored& a, const Scored& b) {
            if (a.score != b.score) return detail::score_lt(b.score, a.score);
            return std::memcmp(a.mn->proRegTxHash.data(),
                               b.mn->proRegTxHash.data(), 32) < 0;
        });

    std::vector<MemberOperatorKey> out;
    out.reserve(params.size);
    for (uint16_t i = 0; i < params.size; ++i) {
        const auto& mn = *scored[i].mn;
        if (detail::is_all_zero(mn.pubKeyOperator)) return std::nullopt;
        MemberOperatorKey k;
        k.pubKeyOperator = mn.pubKeyOperator;
        k.legacy_scheme  = (mn.nVersion == CSimplifiedMNListEntry::VER_LEGACY_BLS);
        out.push_back(k);
    }
    return out;
}

} // namespace vendor
} // namespace coin
} // namespace dash
