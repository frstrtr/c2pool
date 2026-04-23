#pragma once

// Phase L step 2: ChainLock signature verification.
//
// Given an incoming clsig (height, blockHash, sig), this header
// provides the deterministic recipe for confirming the signature is a
// valid recovered threshold sig from the LLMQ that should have signed
// it. Algorithm ported from dashcore:
//
//   - chainlock/handler.cpp::VerifyChainLock
//   - chainlock/clsig.cpp::GenSigRequestId
//   - llmq/quorumsman.cpp::SelectQuorumForSigning  (non-rotation branch)
//   - llmq/quorumsman.cpp::VerifyRecoveredSig
//   - llmq/signhash.cpp::SignHash
//
// Steps (read top-to-bottom of verify_chainlock):
//   A. request_id   = SHA256d(compact_size("clsig") || int32_le(height))
//   B. signing pool = the N most-recent active quorums of llmqType
//                     LLMQ_400_60 (mainnet ChainLocks type) alive at
//                     `signHeight - signOffset` (signOffset=8 per
//                     dashcore default for ChainLocks)
//   C. signing q'm  = the pool member with the lowest
//                     SHA256d(llmqType || quorumHash || request_id)
//   D. sign_hash    = SHA256d(llmqType || quorumHash || request_id ||
//                             blockHash)
//   E. verify       = BasicSchemeMPL.Verify(q'm.pubkey, sign_hash, sig)
//
// Mainnet pinning: LLMQ_400_60 (== 2 in the LLMQType enum) is the
// `llmqTypeChainLocks` per Consensus::Params for mainnet/testnet. The
// signingActiveQuorumCount for LLMQ_400_60 is 4 (one new, one expired
// per rotation). signOffset for ChainLocks is 8 blocks.
//
// Scope caveats vs dashcore:
//   - We don't apply rotation logic (LLMQ_400_60 is non-rotation; our
//     code path takes the non-rotation branch only). LLMQ_60_75 (DIP-
//     0024 InstantSend) does use rotation; if Phase C-QUO ever ships
//     IS verification we'd add the rotation branch then.
//   - We rely on header_chain.get_header(quorumHash) to discover when
//     each candidate quorum was formed. Quorums whose formation block
//     isn't in our header chain are excluded. Steady state this should
//     never matter — quorum DKG blocks are always part of the chain
//     we sync.

#include <impl/dash/coin/bls_verify.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/header_chain.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>   // CHash256

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace dash {
namespace coin {

namespace clsig_detail {

// Per dashcore Consensus::Params for mainnet/testnet:
//   llmqTypeChainLocks = LLMQType::LLMQ_400_60 (== 2)
inline constexpr uint8_t CHAINLOCKS_LLMQ_TYPE =
    vendor::CFinalCommitment::LLMQ_400_60;

// Per dashcore LLMQParams[LLMQ_400_60].signingActiveQuorumCount.
inline constexpr size_t  CHAINLOCKS_POOL_SIZE = 4;

// Per dashcore default signOffset for ChainLocks (chainlock/handler.cpp
// VerifyRecoveredSig call leaves signOffset at its default of 8).
inline constexpr int32_t CHAINLOCKS_SIGN_OFFSET = 8;

// SHA256d helper — sha256(sha256(bytes)) into a uint256.
inline uint256 sha256d(std::span<const uint8_t> bytes)
{
    uint256 out;
    CHash256()
        .Write(std::span<const unsigned char>(bytes.data(), bytes.size()))
        .Finalize(std::span<unsigned char>(out.data(), 32));
    return out;
}

// Compute the ChainLock request id for height N.
// Wire bytes: CompactSize("clsig".size()=5) || "clsig" || int32_le(N)
//           = 0x05 'c' 'l' 's' 'i' 'g' <4 bytes height LE>  = 10 bytes
inline uint256 gen_chainlock_request_id(int32_t nHeight)
{
    std::array<uint8_t, 10> buf{};
    buf[0] = 0x05;
    buf[1] = 'c'; buf[2] = 'l'; buf[3] = 's'; buf[4] = 'i'; buf[5] = 'g';
    buf[6] = static_cast<uint8_t>( nHeight        & 0xff);
    buf[7] = static_cast<uint8_t>((nHeight >>  8) & 0xff);
    buf[8] = static_cast<uint8_t>((nHeight >> 16) & 0xff);
    buf[9] = static_cast<uint8_t>((nHeight >> 24) & 0xff);
    return sha256d(buf);
}

// Per-quorum scoring within the signing pool.
// Wire bytes: llmqType[1] || quorumHash[32] || selectionHash[32] = 65 bytes
inline uint256 quorum_signing_score(uint8_t llmqType,
                                    const uint256& quorumHash,
                                    const uint256& selectionHash)
{
    std::array<uint8_t, 1 + 32 + 32> buf{};
    buf[0] = llmqType;
    std::memcpy(buf.data() + 1,        quorumHash.data(),    32);
    std::memcpy(buf.data() + 1 + 32,   selectionHash.data(), 32);
    return sha256d(buf);
}

// SignHash — the actual message bytes the LLMQ recovered-threshold sig
// is over. Wire: llmqType[1] || quorumHash[32] || requestId[32] ||
// msgHash[32] = 97 bytes (SHA256d'd to 32 bytes).
inline uint256 build_sign_hash(uint8_t llmqType,
                               const uint256& quorumHash,
                               const uint256& requestId,
                               const uint256& msgHash)
{
    std::array<uint8_t, 1 + 32 + 32 + 32> buf{};
    buf[0] = llmqType;
    std::memcpy(buf.data() + 1,            quorumHash.data(), 32);
    std::memcpy(buf.data() + 1 + 32,       requestId.data(),  32);
    std::memcpy(buf.data() + 1 + 32 + 32,  msgHash.data(),    32);
    return sha256d(buf);
}

} // namespace clsig_detail

struct ChainLockVerifyResult
{
    enum class Status {
        VALID,           // sig verified against the selected quorum's pubkey
        INVALID_SIG,     // pool selection found a quorum but BLS verify failed
        NO_POOL,         // no active quorums of the right LLMQ type
        NO_SELECTED,     // pool exists but no quorum scored low enough (shouldn't happen)
    };
    Status   status{Status::NO_POOL};
    uint256  selected_quorum_hash;        // populated if status != NO_POOL
    uint256  sign_hash;                   // populated if status != NO_POOL
    size_t   pool_size{0};                // diagnostic: how many quorums considered
};

// Verify a ChainLock signature end-to-end. Returns a structured result
// that lets the caller log diagnostically (which quorum was selected,
// what sign_hash was computed, etc.) rather than just a bool.
//
// Pure function over (clsig, quorums snapshot, header lookup). No
// global state. Caller is expected to hold whatever locks are needed
// to make the QuorumManager and HeaderChain references stable for the
// duration of the call.
inline ChainLockVerifyResult verify_chainlock(
    int32_t                                  height,
    const uint256&                           blockHash,
    const std::array<uint8_t, 96>&           sig,
    const QuorumManager&                     quorums,
    const HeaderChain&                       header_chain,
    bool                                     fLegacyScheme = false)
{
    using namespace clsig_detail;

    ChainLockVerifyResult r;

    // ── Step A: request id ───────────────────────────────────────────
    const uint256 request_id = gen_chainlock_request_id(height);

    // ── Step B: signing pool = 4 most-recent active LLMQ_400_60
    //               quorums alive at signHeight - 8 ───────────────────
    // signHeight for ChainLocks is the clsig.height itself (signedAtHeight
    // in dashcore VerifyRecoveredSig). pindexStart is at signHeight - 8.
    const int32_t pool_anchor = height - CHAINLOCKS_SIGN_OFFSET;
    if (pool_anchor < 0) {
        r.status = ChainLockVerifyResult::Status::NO_POOL;
        return r;
    }

    // Collect candidate quorums (right type, formed at-or-before pool_anchor),
    // tagged with their formation height so we can pick the most-recent N.
    struct Candidate {
        const QuorumManager::Entry* entry;
        uint32_t                     formed_at;
    };
    std::vector<Candidate> candidates;
    candidates.reserve(16);

    // Active set on mainnet is <500 entries; linear scan is fine.
    for (const auto& entry : quorums.active_entries()) {
        if (entry.key.llmqType != CHAINLOCKS_LLMQ_TYPE) continue;
        auto hdr = header_chain.get_header(entry.key.quorumHash);
        if (!hdr) continue;
        if (static_cast<int32_t>(hdr->height) > pool_anchor) continue;
        candidates.push_back({&entry,
                              static_cast<uint32_t>(hdr->height)});
    }

    if (candidates.empty()) {
        r.status = ChainLockVerifyResult::Status::NO_POOL;
        return r;
    }

    // Sort newest-first by formation height; take top N.
    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate& a, const Candidate& b) {
                  return a.formed_at > b.formed_at;
              });
    if (candidates.size() > CHAINLOCKS_POOL_SIZE) {
        candidates.resize(CHAINLOCKS_POOL_SIZE);
    }
    r.pool_size = candidates.size();

    // ── Step C: pick lowest-score quorum ────────────────────────────
    const QuorumManager::Entry* selected = nullptr;
    uint256 best_score;
    bool first = true;
    for (const auto& c : candidates) {
        uint256 score = quorum_signing_score(
            CHAINLOCKS_LLMQ_TYPE, c.entry->key.quorumHash, request_id);
        if (first || score < best_score) {
            first = false;
            best_score = score;
            selected = c.entry;
        }
    }
    if (!selected) {
        r.status = ChainLockVerifyResult::Status::NO_SELECTED;
        return r;
    }
    r.selected_quorum_hash = selected->key.quorumHash;

    // ── Step D: sign_hash ────────────────────────────────────────────
    r.sign_hash = build_sign_hash(
        CHAINLOCKS_LLMQ_TYPE, selected->key.quorumHash, request_id, blockHash);

    // ── Step E: BLS verify ───────────────────────────────────────────
    // sign_hash is the message bytes — feed its 32 raw bytes directly.
    std::array<uint8_t, 32> msg_bytes{};
    std::memcpy(msg_bytes.data(), r.sign_hash.data(), 32);
    bool ok = fLegacyScheme
        ? verify_bls_legacy(selected->commitment.quorumPublicKey,
                            std::span<const uint8_t>(msg_bytes), sig)
        : verify_bls_basic(selected->commitment.quorumPublicKey,
                           std::span<const uint8_t>(msg_bytes), sig);

    r.status = ok
        ? ChainLockVerifyResult::Status::VALID
        : ChainLockVerifyResult::Status::INVALID_SIG;
    return r;
}

} // namespace coin
} // namespace dash
