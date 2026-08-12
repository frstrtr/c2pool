// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Live-path deterministic-InstantSend-lock (isdlock, DIP-0022) verification —
/// the gate an isdlock MUST pass before its outpoints may enter
/// Mempool::add_islock and arm the G4 conflict-tx-lock selection guard.
///
/// WHY THIS EXISTS. Mempool::add_islock + the G4 selection guard shipped in
/// #1110 fully inert: nothing called them, because nothing acquired islocks.
/// This header is the missing verify half of the acquire->verify->use leg,
/// mirroring the #1071 ChainLock port (chainlock_verify.hpp). Adopting an
/// isdlock UNVERIFIED would let an arbitrary peer evict arbitrary mempool txs
/// from our served templates (add_islock evicts conflicts immediately and the
/// G4 guard excludes their outpoints from selection) — fee loss on demand.
/// Refusal, by contrast, costs NOTHING but parity: islock exclusion is an
/// optimization (dashd itself waives conflict-tx-lock once a block is
/// chainlocked), so every failure mode below fails CLOSED to today's
/// behaviour (empty map, unchanged selection).
///
/// REUSE-FIRST (operator mandate — mirror Dash Core, do not invent). Every
/// step is dashcore v23.1.7, cited at the line it came from, cross-checked
/// against the local checkout at tmp/dashd-src:
///
///   requestId = SerializeHash("islock"sv || inputs)
///               -- src/instantsend/lock.cpp:15-24 (GetRequestId,
///                  ISLOCK_REQUESTID_PREFIX at :15). The string_view
///                  serializes as CompactSize(6) + "islock"; inputs as
///                  CompactSize(n) + n x COutPoint (32B txid + 4B LE index).
///
///   signHeight: the isdlock's cycleHash names the DKG cycle-start block of
///               the signing quorum's cycle. dashd derives
///               nSignHeight = cycleHeight + dkgInterval - 1 when that cycle
///               is old enough, else tip (src/instantsend/
///               net_instantsend.cpp:106-118), purely so that ScanQuorums
///               snaps BACK to cycleHash's own mining window. We key the
///               candidate set on cycleHash directly (below), which is the
///               same selection whenever the cycle's commitments were mined —
///               and a fail-closed refusal when they were not.
///
///   quorum    = SelectQuorumForSigning(...), ROTATED branch
///               -- src/llmq/quorumsman.cpp:676-717. THE DIVERGENCE FROM THE
///                  #1071 PORT: llmqTypeDIP0024InstantSend is LLMQ_60_75
///                  (type 5, useRotation=true, signingActiveQuorumCount=32,
///                  dkgInterval=288 — src/llmq/params.h llmq_60_75), so
///                  selection is NOT the score-sort chainlock_verify.hpp:241
///                  implements. The rotated arm (quorumsman.cpp:694-717):
///                    n      = log2(signingActiveQuorumCount)         // = 5
///                    b      = requestId.GetUint64(3)   // last 8 bytes, LE
///                    signer = ((1 << n) - 1) & (b >> (64 - n - 1))   // >>58
///                    quorum = the scan-set entry with quorumIndex == signer
///                  ported VERBATIM below, including the (64 - n - 1) shift
///                  (which discards the top bit) — do NOT "fix" it.
///
///   scan set  : dashd's rotated ScanQuorums returns the last mined
///               commitment per quorumIndex until the snapped store block
///               (quorums.cpp ScanQuorums + blockprocessor.cpp
///               GetMinedCommitmentsIndexedUntilBlock) — for a healthy cycle,
///               exactly the 32 quorums whose commitments were mined in
///               cycleHash's own mining window. Rotated commitments satisfy
///               baseHeight % dkgInterval == quorumIndex (commitment.cpp:52),
///               i.e. baseHeight == cycleHeight + quorumIndex; we take the
///               qmgr's active type-5 entries and keep exactly those whose
///               base block sits at cycleHeight + quorumIndex. A cycle where
///               some index's DKG failed makes dashd fall back to the
///               previous cycle's commitment for that index; we cannot see
///               "mined until" from the active set, so that case fails
///               closed (unselectable => drop) instead of guessing.
///
///   signHash  = SHA256d(u8(llmqType) || quorumHash || requestId || txid)
///               -- llmq::SignHash (src/llmq/signhash.h), msgHash is the
///                  isdlock's txid (net_instantsend.cpp:128). REUSED verbatim
///                  from chainlock_verify.hpp build_sign_hash.
///
///   verify    = sig.VerifyInsecure(quorum.quorumPublicKey, signHash)
///               -- same vendor call as ChainLocks
///                  (vendor/bls_verify.cpp verify_chainlock_sig, legacy/basic
///                  scheme fallback).
///
/// FAIL-CLOSED. Every entry point returns false / nullopt when anything is
/// uncertain: unknown cycleHash, cycle not at a dkgInterval boundary, no
/// candidate at the designated quorumIndex, out-of-range signer. A refusal
/// keeps m_islock_outpoints exactly as it was; an erroneous acceptance would
/// hand a hostile peer our template's tx list.

#include <impl/dash/coin/chainlock_verify.hpp>   // sha256d_of, build_sign_hash, QuorumCandidate
#include <impl/dash/coin/dkg_commitments.hpp>    // LlmqParamsView, kLlmq60_75, LlmqNetwork

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace dash {
namespace coin {
namespace islock {

/// One candidate signing quorum for the rotated (DIP-24) lane: the base block
/// (whose hash IS the quorumHash), that block's height, the commitment's
/// quorumIndex, and the aggregate quorum public key.
struct RotatedQuorumCandidate {
    uint256                                                        quorum_hash;
    uint32_t                                                       base_height{0};
    uint16_t                                                       quorum_index{0};
    std::array<uint8_t, vendor::CFinalCommitment::BLS_PUBKEY_SIZE> quorum_public_key{};
};

/// dashcore instantsend::InstantSendLock::GetRequestId
/// (src/instantsend/lock.cpp:18-24). Preimage: CompactSize(6) || "islock" ||
/// CompactSize(n) || n x (32B txid || u32LE index), then SHA256d.
inline uint256
gen_islock_request_id(const std::vector<std::pair<uint256, uint32_t>>& inputs)
{
    static constexpr std::string_view kPrefix{"islock"};
    ::PackStream s;
    WriteCompactSize(s, kPrefix.size());
    s.write(std::as_bytes(std::span{kPrefix.data(), kPrefix.size()}));
    WriteCompactSize(s, inputs.size());
    for (const auto& in : inputs) {
        s << in.first;      // txid (raw 32 bytes)
        s << in.second;     // index (uint32, little-endian)
    }
    return chainlock::sha256d_of(s);
}

/// The rotated signer-index derivation, dashcore SelectQuorumForSigning
/// rotated arm (src/llmq/quorumsman.cpp:699-704), ported VERBATIM:
///   n      = log2(signingActiveQuorumCount)
///   b      = selectionHash.GetUint64(3)          // bytes 24..31, LE
///   signer = ((1 << n) - 1) & (b >> (64 - n - 1))
/// For LLMQ_60_75 (count 32): n = 5, shift 58, mask 0x1f — bits 58..62 of the
/// last-64-bit word; the top bit is DISCARDED by upstream's own (64 - n - 1).
/// Keep the quirk: "fixing" it selects different quorums than dashd.
inline uint64_t rotated_signer_index(const LlmqParamsView& p,
                                     const uint256& selection_hash)
{
    int n = 0;
    while ((1u << (n + 1)) <= p.signing_active_quorum_count) ++n;  // floor(log2)
    const uint64_t b = selection_hash.GetUint64(3);
    return ((1ull << n) - 1) & (b >> (64 - n - 1));
}

/// Select the rotated quorum that must have signed an isdlock: among the
/// candidates belonging to cycle `cycle_height` (base_height ==
/// cycle_height + quorum_index, the rotated-commitment invariant
/// dashcore/src/llmq/commitment.cpp:52 enforces), the one whose quorumIndex
/// equals the requestId-derived signer index. Fail-closed nullopt on: params
/// not rotated, cycle not at a dkgInterval boundary, signer index out of the
/// candidate range (upstream's own `signer > quorums.size()` guard,
/// quorumsman.cpp:706), or no candidate at that index.
inline std::optional<RotatedQuorumCandidate>
select_rotated_quorum(const LlmqParamsView& p,
                      const std::vector<RotatedQuorumCandidate>& candidates,
                      uint32_t cycle_height, const uint256& request_id)
{
    if (!p.use_rotation || p.dkg_interval == 0) return std::nullopt;
    if (cycle_height % p.dkg_interval != 0) return std::nullopt;   // not a cycle base

    // The cycle's own quorums: base block at cycleHeight + quorumIndex.
    std::vector<const RotatedQuorumCandidate*> cycle_set;
    cycle_set.reserve(p.signing_active_quorum_count);
    for (const auto& c : candidates) {
        if (c.quorum_index >= p.signing_active_quorum_count) continue;
        if (static_cast<uint64_t>(c.base_height)
                != static_cast<uint64_t>(cycle_height) + c.quorum_index) continue;
        cycle_set.push_back(&c);
    }
    if (cycle_set.empty()) return std::nullopt;

    const uint64_t signer = rotated_signer_index(p, request_id);
    // Upstream guard kept as-is (quorumsman.cpp:706-708; note `>`, not `>=` —
    // the find_if below is what actually decides membership).
    if (signer > cycle_set.size()) return std::nullopt;
    for (const auto* c : cycle_set)
        if (static_cast<uint64_t>(c->quorum_index) == signer) return *c;
    return std::nullopt;
}

/// The full pre-BLS half of dashd's isdlock verification: from the lock's
/// inputs + txid + cycle base height, pick the rotated quorum that must have
/// signed it and build the sign hash its recovered threshold signature has to
/// verify against. Returns nullopt (fail closed) when no quorum is selectable.
struct IslockSignTarget {
    RotatedQuorumCandidate quorum;
    uint256                request_id;
    uint256                sign_hash;
};

inline std::optional<IslockSignTarget>
build_islock_sign_target(const LlmqParamsView& p,
                         const std::vector<RotatedQuorumCandidate>& candidates,
                         uint32_t cycle_height,
                         const std::vector<std::pair<uint256, uint32_t>>& inputs,
                         const uint256& txid)
{
    if (inputs.empty() || txid.IsNull()) return std::nullopt;
    const uint256 request_id = gen_islock_request_id(inputs);
    auto q = select_rotated_quorum(p, candidates, cycle_height, request_id);
    if (!q) return std::nullopt;

    IslockSignTarget t;
    t.quorum     = *q;
    t.request_id = request_id;
    // msgHash is the isdlock's txid (net_instantsend.cpp:128); the hash
    // construction is llmq::SignHash, identical to the ChainLock one.
    t.sign_hash  = chainlock::build_sign_hash(p.type, q->quorum_hash,
                                              request_id, txid);
    return t;
}

/// The LLMQ type used for DIP-24 deterministic InstantSend signing:
/// llmqTypeDIP0024InstantSend = LLMQ_60_75 on BOTH mainnet and testnet
/// (dashcore src/chainparams.cpp).
inline const LlmqParamsView* islock_params(LlmqNetwork /*net*/)
{
    return &kLlmq60_75;
}

} // namespace islock
} // namespace coin
} // namespace dash
