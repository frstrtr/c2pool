// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// E1 Phase-L — cryptographic verification of REAL (non-null) type-6 quorum
/// commitments, reusing Dash Core's own verify logic + BLS backend.
///
/// This is the piece the MineableCommitmentCache::set_bls_verify_fn seam
/// (dkg_commitments.hpp) was cut for. Without it every DKG-window slot mines
/// the consensus-valid NULL commitment (dashd's own behaviour when it holds no
/// verified DKG result); with it, a peer-relayed commitment that PASSES
/// dashcore's CFinalCommitment::Verify may be INCLUDED in the template, so a
/// mainnet DKG-window block carries the same REAL commitment dashd's block
/// carries (null-serve would diverge → bad-qc reject on a successful DKG).
///
/// REUSE-FIRST (operator mandate — vendor Dash Core, do not hand-roll):
///
///   * build_commitment_hash  == dashcore llmq/commitment.cpp BuildCommitmentHash
///     (the signed preimage; byte-exact, locked by a from-wire KAT).
///   * verify_final_commitment == dashcore CFinalCommitment::VerifySignatureAsync
///     (checkSigs path): membersSig = VerifySecureAggregated over the signers'
///     pubKeyOperator, quorumSig = VerifyInsecure against quorumPublicKey, both
///     over the commitment hash. Post-V19 BASIC scheme (the serve floor in
///     dkg_commitments.hpp guarantees post-V19).
///   * The BLS math is dashpay/bls-signatures ("dashbls", relic-backed,
///     Apache-2.0 — the SAME library dashd wraps in src/bls/bls.h) — linked
///     only when C2POOL_DASH_BLS is defined (see src/impl/dash/CMakeLists.txt).
///
/// FAIL-CLOSED (reward-critical embedded consensus): when the BLS backend is
/// not compiled in, OR the member operator key set cannot be sourced, OR any
/// size is wrong, OR the BLS verify FAILS, every entry point returns false and
/// the caller (MineableCommitmentCache::verified_for) yields nullopt → the
/// provider mines the always-valid NULL commitment (or falls back to dashd).
/// An unverified/forged relayed commitment is NEVER served.
///
/// WHY membersSig IS MANDATORY (not quorumSig alone): the commitment hash binds
/// quorumPublicKey, and quorumSig is a self-signature by that key — a malicious
/// peer can mint its own (sk, pk) and produce a valid quorumSig. Only membersSig
/// (an aggregate over the ACTUAL quorum members' operator keys, which the peer
/// does not control) proves authenticity. So Phase-L REQUIRES the real member
/// operator key set; without it we fail closed.

#include <impl/dash/coin/vendor/llmq_commitment.hpp>

#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {

/// One quorum member's BLS operator public key, carrying the wire scheme the
/// key was serialized under. The SML (E3, CSimplifiedMNListEntry) records this
/// per entry via nVersion (VER_LEGACY_BLS == 1 → legacy, VER_BASIC_BLS == 2 →
/// basic), so production sourcing is UNAMBIGUOUS — unlike a bare RPC hex string
/// (a mixed quorum has keys valid under BOTH encodings; only the SML nVersion
/// disambiguates). legacy_scheme MUST reflect that flag.
struct MemberOperatorKey {
    std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE> pubKeyOperator{};
    bool legacy_scheme{false};
};

/// dashcore llmq/commitment.cpp BuildCommitmentHash (@ v23.1.x, verbatim
/// preimage): CHashWriter(SER_GETHASH) << llmqType << quorumHash
/// << DYNBITSET(validMembers) << quorumPublicKey << quorumVvecHash, then
/// SHA256d. No BLS dependency — usable + testable regardless of C2POOL_DASH_BLS.
uint256 build_commitment_hash(uint8_t llmq_type, const uint256& quorum_hash,
                              const std::vector<bool>& valid_members,
                              const std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>& quorum_public_key,
                              const uint256& quorum_vvec_hash);

/// True iff the dashbls backend is compiled in (C2POOL_DASH_BLS). When false,
/// verify_final_commitment / the produced verifier fn always return false and
/// the serve path fails closed — a build without BLS keeps the pre-Phase-L
/// null-serve posture exactly.
bool bls_backend_available();

/// Verify one commitment's crypto EXACTLY as dashcore CFinalCommitment::Verify
/// (checkSigs) does, post-V19 basic scheme. `members` MUST be the full ordered
/// quorum member set (index-aligned with c.signers; members.size() ==
/// c.signers.size() == params.size). Returns true only when BOTH the aggregate
/// membersSig and the quorumSig verify. Fail-closed (false) on: backend absent,
/// size mismatch, empty signer set, or any BLS verify failure. Never throws.
bool verify_final_commitment(const CFinalCommitment& c,
                             const std::vector<MemberOperatorKey>& members);

/// Sources the ordered member operator key set for a (llmqType, quorumHash).
/// Returns std::nullopt when the set cannot be established with certainty
/// (member selection not resolvable, SML gap, historical base list unavailable)
/// — in which case the verifier fails closed. The keys MUST be index-aligned
/// with the commitment's signers/validMembers bitsets.
using MemberKeysProvider =
    std::function<std::optional<std::vector<MemberOperatorKey>>(
        uint8_t llmq_type, const uint256& quorum_hash)>;

/// Build the MineableCommitmentCache::BlsVerifyFn (std::function<bool(const
/// CFinalCommitment&)>) main_dash installs via set_bls_verify_fn. It sources
/// the member set via `provider`, then runs verify_final_commitment. When the
/// BLS backend is absent OR the provider yields nullopt, the returned fn is
/// fail-closed (always false). `provider` may be null (always fail closed).
std::function<bool(const CFinalCommitment&)>
make_commitment_bls_verifier(MemberKeysProvider provider);

// ── R3: governance-vote operator-key signature verify ───────────────────────
//
// Daemonless superblock serving (E-SUPERBLOCK) needs to VERIFY that a relayed
// TRIGGER funding vote was really signed by the voting masternode — else the
// GovernanceStore tally counts nothing (fail closed) and every superblock
// height falls back to dashd. This is the SINGLE-signature analogue of the
// aggregate quorum-commitment verify above: one sig, one operator key, no
// aggregation.
//
// Contract (dashcore CGovernanceVote::CheckSignature(const CBLSPublicKey&)):
//   CBLSSignature sig; sig.SetByteVector(vchSig, legacy);
//   sig.VerifyInsecure(pubKeyOperator, GetSignatureHash(), legacy);
// i.e. VerifyInsecure == scheme.Verify(pubKeyOperator_G1, digest_bytes,
// vchSig_G2). TRIGGER funding votes are signed by the MN's OPERATOR key (NOT
// the ECDSA voting key — that path is PROPOSAL-funding-only). `digest` is the
// govvote_signature_hash preimage (governance_object.hpp), i.e. dashcore
// GetSignatureHash(). `key_legacy_scheme` reflects the operator key's declared
// wire scheme (MNState nVersion: LEGACY_BLS => true, BASIC_BLS => false).
// IMPORTANT (pinned against a real from-wire testnet vote): the key's
// wire-encoding and the SIGNING scheme are INDEPENDENT — a LEGACY_BLS-registered
// MN keeps a legacy-encoded pubkey but post-V19 signs under the BASIC scheme
// (basic-encoded sig + basic DST). The implementation therefore varies the two
// axes independently (network sig-scheme BASIC-first for sig-encoding+DST; the
// key's declared scheme first for the pubkey encoding). A forged/tampered sig or
// wrong key verifies under NO combination — this only broadens which LEGITIMATE
// encodings are accepted, never what is cryptographically valid.
//
// FAIL-CLOSED (reward-critical): returns false when the BLS backend is absent,
// vch_sig is not 96 bytes, either point fails to deserialize, or the BLS verify
// fails — so an unverified vote is NEVER tallied. Never throws.
bool verify_govvote_operator_sig(
    const std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>& pubkey_operator,
    bool key_legacy_scheme,
    const uint256& digest,
    const std::vector<uint8_t>& vch_sig);

} // namespace vendor
} // namespace coin
} // namespace dash
