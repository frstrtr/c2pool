// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Variant B ARM-3 — the type-9 (asset-unlock) quorum-signature verify port:
/// dashd CAssetUnlockPayload::VerifySig + the CheckAssetUnlockTx msgHash
/// derivation, cited line-by-line from dashd-src @ this pin:
///
///   requestId = ::SerializeHash(std::make_pair("plwdtx", index))
///               -- evo/assetlocktx.cpp:112 (ASSETUNLOCK_REQUESTID_PREFIX)
///                  + :147. A std::pair serializes first-then-second; the
///                  std::string as CompactSize(6) + bytes, the uint64 LE —
///                  preimage is exactly 0x06 "plwdtx" u64LE(index), 15 bytes,
///                  then SHA256d (::SerializeHash, src/hash.h).
///
///   msgHash   = GetHash() of the tx re-serialized with quorumSig = CBLSSignature{}
///               -- evo/assetlocktx.cpp:190-195 (CheckAssetUnlockTx): "Copy
///                  transaction except `quorumSig` field to calculate hash".
///                  An invalid/default CBLSSignature serializes as 96 zero
///                  bytes, so the copy carries a zeroed 96-byte sig field.
///
///   quorum activity window
///               -- evo/assetlocktx.cpp:125-132: scan the newest
///                  (signingActiveQuorumCount + 1) quorums of llmqTypePlatform
///                  ("all active + 1 the latest inactive"); the payload's
///                  quorumHash must be one of them, else
///                  bad-assetunlock-too-old-quorum.
///
///   height/expiry window
///               -- evo/assetlocktx.cpp:134-139: reject when
///                  tip < requestedHeight or tip >= requestedHeight +
///                  HEIGHT_DIFF_EXPIRING (48, assetlocktx.h:150) —
///                  bad-assetunlock-too-late. For a template at height H the
///                  tip is H-1 (pindexPrev).
///
///   signHash  = SHA256d(u8(llmqType) || quorumHash || requestId || msgHash)
///               -- llmq::SignHash, REUSED from chainlock_verify.hpp
///                  build_sign_hash (byte-identical construction, already
///                  KAT-locked against a real mainnet ChainLock).
///
///   verify    = quorumSig.VerifyInsecure(quorum->qc->quorumPublicKey, signHash)
///               -- evo/assetlocktx.cpp:149-152. REUSED via
///                  vendor::verify_chainlock_sig (bls_verify.cpp): the exact
///                  same VerifyInsecure contract — 48-byte G1 pubkey, 96-byte
///                  G2 recovered threshold sig, BASIC scheme, the 32 sign-hash
///                  bytes are the MESSAGE (no pre-hash). Fail-closed stub
///                  without C2POOL_DASH_BLS: verification is structurally
///                  impossible, so accrual is structurally OFF (predicate
///                  conjunct b).
///
///   llmqTypePlatform: mainnet LLMQ_100_67 (4), testnet LLMQ_25_67 (6)
///               -- vendor/quorum_members.hpp kLlmqTypePlatform*.
///
/// FAIL-CLOSED at every step: any parse failure, quorum-not-active, window
/// miss, missing quorum key or BLS refusal yields false, and the caller
/// (credit_pool_idx.hpp try_admit_unlocks) excludes the candidate. A wrongly
/// excluded unlock costs fee-dust; a wrongly included one costs the block.

#include <impl/dash/coin/chainlock_verify.hpp>   // build_sign_hash, QuorumCandidate, sha256d_of
#include <impl/dash/coin/vendor/assetlock.hpp>   // CAssetUnlockPayload + parser
#include <impl/dash/coin/vendor/bls_verify.hpp>  // verify_chainlock_sig (VerifyInsecure port)
#include <impl/dash/coin/dkg_commitments.hpp>    // LlmqParamsView, kLlmq100_67 / kLlmq25_67
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>       // dash_txid

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <core/log.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace dash {
namespace coin {
namespace unlockverify {

/// dashd CAssetUnlockPayload::HEIGHT_DIFF_EXPIRING (evo/assetlocktx.h:150).
inline constexpr int32_t kHeightDiffExpiring = 48;

/// dashd CAssetUnlockPayload::MAXIMUM_WITHDRAWALS (evo/assetlocktx.h:76).
inline constexpr size_t kMaximumWithdrawals = 32;

/// dashd ::SerializeHash(std::make_pair("plwdtx", index)) —
/// evo/assetlocktx.cpp:147. Preimage: CompactSize(6) || "plwdtx" || u64LE.
inline uint256 unlock_request_id(uint64_t index)
{
    static constexpr std::string_view kPrefix{"plwdtx"};
    ::PackStream s;
    WriteCompactSize(s, kPrefix.size());
    s.write(std::as_bytes(std::span{kPrefix.data(), kPrefix.size()}));
    s << index;                          // uint64, little-endian
    return chainlock::sha256d_of(s);
}

/// dashd CheckAssetUnlockTx msgHash (evo/assetlocktx.cpp:190-195): the tx's
/// hash with the payload's quorumSig zeroed. `payload` must be the tx's own
/// parsed payload (the caller already has it); the tx is copied, the payload
/// re-encoded with a zero sig, and the copy hashed with the standard Dash
/// txid rule (SHA256d over the canonical serialization incl. extra_payload).
inline uint256 unlock_msg_hash(const MutableTransaction& tx,
                               const vendor::CAssetUnlockPayload& payload)
{
    vendor::CAssetUnlockPayload zeroed = payload;
    zeroed.quorumSig.fill(0);            // CBLSSignature{} wire form: 96 zero bytes

    MutableTransaction copy = tx;
    ::PackStream ps;
    ps << zeroed;
    auto sp = ps.get_span();
    copy.extra_payload.assign(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return dash_txid(copy);
}

/// The platform-quorum LLMQ params for a network (chainparams llmqTypePlatform:
/// mainnet LLMQ_100_67, testnet LLMQ_25_67).
inline const LlmqParamsView* platform_llmq_params(LlmqNetwork net)
{
    return net == LlmqNetwork::Mainnet ? &kLlmq100_67 : &kLlmq25_67;
}

/// Full VerifySig port (evo/assetlocktx.cpp:114-157) minus the quorum-manager
/// plumbing: `candidates` is the caller-sourced set of platform-type quorums
/// with their CFinalCommitment::quorumPublicKey (sml_quorum_db 'Q' rows /
/// QuorumManager active set), any order. `tip_height` is the height of the
/// block being built ON (pindexPrev = H-1 for a template at H).
///
/// Steps, in dashd order:
///   1. take the newest (signingActiveQuorumCount + 1) candidates by base
///      height — "all active + 1 the latest inactive" (:126-128);
///   2. payload.quorumHash must be in that set (:130-132);
///   3. tip inside [requestedHeight, heightToExpiry) (:134-139);
///   4. signHash over (llmqType, quorumHash, requestId(plwdtx‖index), msgHash)
///      and VerifyInsecure against that quorum's public key (:147-152).
///
/// Returns true ONLY when all four hold and the BLS backend verified the
/// signature. Never throws.
inline bool verify_asset_unlock_sig(
    const vendor::CAssetUnlockPayload& payload,
    const uint256& msg_hash,
    int32_t tip_height,
    std::vector<chainlock::QuorumCandidate> candidates,
    const LlmqParamsView& params)
{
    // 1. Newest (signingActiveQuorumCount + 1) quorums — dashd ScanQuorums
    //    returns newest-first by mined height; base height ordering is the
    //    same ordering for a non-rotated type (fixed mining-window offset).
    const size_t quorums_to_scan =
        static_cast<size_t>(params.signing_active_quorum_count) + 1;
    std::sort(candidates.begin(), candidates.end(),
              [](const chainlock::QuorumCandidate& a,
                 const chainlock::QuorumCandidate& b) {
                  if (a.base_height != b.base_height)
                      return a.base_height > b.base_height;
                  return chainlock::score_less(a.quorum_hash, b.quorum_hash);
              });
    if (candidates.size() > quorums_to_scan) candidates.resize(quorums_to_scan);

    // 2. quorumHash must be an active (or the latest inactive) quorum.
    const chainlock::QuorumCandidate* quorum = nullptr;
    for (const auto& c : candidates) {
        if (c.quorum_hash == payload.quorumHash) { quorum = &c; break; }
    }
    if (quorum == nullptr) {
        LOG_INFO << "[UNLOCK-VERIFY] index=" << payload.index
                 << " REFUSED: bad-assetunlock-too-old-quorum (quorumHash "
                 << payload.quorumHash.GetHex().substr(0, 16)
                 << " not in the newest " << quorums_to_scan << ")";
        return false;
    }

    // 3. Height / expiry window (assetlocktx.cpp:134-139).
    if (tip_height < static_cast<int32_t>(payload.requestedHeight) ||
        tip_height >= static_cast<int32_t>(payload.requestedHeight) + kHeightDiffExpiring) {
        LOG_INFO << "[UNLOCK-VERIFY] index=" << payload.index
                 << " REFUSED: bad-assetunlock-too-late (requested="
                 << payload.requestedHeight << " tip=" << tip_height << ")";
        return false;
    }

    // 4. signHash + VerifyInsecure (fail-closed stub without C2POOL_DASH_BLS).
    const uint256 request_id = unlock_request_id(payload.index);
    const uint256 sign_hash  = chainlock::build_sign_hash(
        params.type, quorum->quorum_hash, request_id, msg_hash);
    if (!vendor::verify_chainlock_sig(quorum->quorum_public_key, sign_hash,
                                      payload.quorumSig)) {
        LOG_INFO << "[UNLOCK-VERIFY] index=" << payload.index
                 << " REFUSED: bad-assetunlock-not-verified (BLS verify failed"
                    " or backend absent — fail closed)";
        return false;
    }
    return true;
}

} // namespace unlockverify
} // namespace coin
} // namespace dash
