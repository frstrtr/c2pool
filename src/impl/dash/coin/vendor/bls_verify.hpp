// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// E1 Phase-L — cryptographic verification of REAL (non-null) type-6 quorum
/// commitments, reusing Dash Core's own verify logic + BLS backend.
///
/// This is the piece the MineableCommitmentCache::set_bls_verify_fn seam
/// (dkg_commitments.hpp) was cut for. Without it no DKG-window slot can ever
/// be satisfied, so every DKG-window height fails closed to the dashd fallback
/// — c2pool does NOT take dashd's "mine the null commitment" arm (null-serving
/// a SUCCEEDED DKG diverged merkleRootQuorums at block 1520106; see
/// dkg_commitments.hpp HEIGHT COMPLETENESS). With it, a peer-relayed commitment
/// that PASSES dashcore's CFinalCommitment::Verify may be INCLUDED in the
/// template, so a mainnet DKG-window block carries the same REAL commitment
/// dashd's block carries.
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
#include <algorithm>

#ifdef C2POOL_DASH_BLS
// Pulled ONLY under the BLS backend (which already links dashbls): the opkey
// scheme helpers below are inline so a BLS-OFF translation unit that includes
// this header (e.g. the fold/replay test targets, which do not link
// dash_bls_verify) resolves them via the byte-fallback path with no new link
// dependency — while the real crypto is exercised in every BLS-ON build.
#include <dashbls/bls.hpp>
#include <dashbls/schemes.hpp>
#include <dashbls/elements.hpp>
#endif

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
/// posture exactly: every DKG-window height refuses and falls back to dashd
/// (it does NOT null-serve).
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

// ── ChainLock recovered-threshold-signature verify ──────────────────────────
//
// dashcore llmq::VerifyRecoveredSig's final step (src/llmq/quorumsman.cpp:749-751):
//     SignHash signHash{llmqType, quorum->qc->quorumHash, id, msgHash};
//     sig.VerifyInsecure(quorum->qc->quorumPublicKey, signHash.Get());
// and VerifyInsecure (src/bls/bls.cpp:294-310) is
//     Scheme(legacy)->Verify(pubKey.impl, bls::Bytes(hash.begin(), 32), impl)
// i.e. the 32 sign-hash bytes are the MESSAGE handed to the scheme, which
// applies its own hash-to-curve — do NOT pre-hash them again here.
//
// SCHEME IS HARD-PINNED TO BASIC (fLegacy=false), for BOTH the 96-byte
// signature wire decode and the verify DST, and for the 48-byte G1 quorum
// public key. dashcore flips bls::bls_legacy_scheme to false at V19 activation
// (src/evo/specialtxman.cpp) and every live ChainLock we can act on is
// post-V19. Unlike the govvote path there is NO pubkey-encoding fallback: the
// quorumPublicKey reaches us from a mnlistdiff-sourced CFinalCommitment whose
// wire encoding is basic post-V19, and a legacy retry here would only ever
// broaden what we accept on a consensus-critical adoption.
//
// The caller (chainlock_verify.hpp) is responsible for having selected the
// CORRECT signing quorum — this function only answers "did THIS key sign THIS
// hash". Passing the wrong quorum's key yields false (fail closed).
//
// FAIL-CLOSED: returns false when the BLS backend is absent, either point
// fails to deserialize, or the verify fails. Never throws.
bool verify_chainlock_sig(
    const std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>& quorum_public_key,
    const uint256& sign_hash,
    const std::array<uint8_t, CFinalCommitment::BLS_SIG_SIZE>& sig);


// Scheme-FAITHFUL operator-pubkey point equality — the 1:1 port of dashd's
// operator-key reset gate compare (specialtxman.cpp:388
// `newState->pubKeyOperator != opt_proTx->pubKeyOperator`, a CBLSPublicKey
// operator== / bls.h:512 POINT compare). Each side is decoded under EXACTLY
// its declared scheme with NO fallback to the other scheme: `a` under
// a_legacy, `b` under b_legacy. Returns true iff BOTH decode (validly) under
// their declared scheme AND encode the SAME underlying G1 point.
//
// WHY (h=1874081 divergence): the DML store canonicalizes every operator key to
// BASIC (opkey_to_basic), so the STORED side is basic (a_legacy=false). A
// ProUpRegTx serializes its operator key in the scheme its payload nVersion
// dictates (legacy iff nVersion < BASIC_BLS, providertx.h:221), so the WIRE side
// MUST be decoded under that scheme. When a v1 (legacy) wire key is BYTE-IDENTICAL
// to a stored basic key but is a DIFFERENT point, dashd resets — a dual-scheme
// intersection read of the wire under BASIC would find the stored point and
// falsely report "same" (no reset). This helper reads the wire ONLY under its
// declared scheme so the points differ and the reset fires, exactly as dashd
// does. Fail-closed (NOT-EQUAL) when either side fails to decode under its
// declared scheme. Without a BLS backend, falls back to byte-equality only when
// the declared schemes match.
//
// Defined inline (not in bls_verify.cpp) so a BLS-OFF test target that folds a
// TU which ODR-uses these (the fold/replay suite computes SML roots via
// to_sml_entry → opkey_for_leaf) links via the fallback path without pulling
// dash_bls_verify.
inline bool opkey_point_eq(const std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>& a, bool a_legacy,
                           const std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>& b, bool b_legacy)
{
#ifndef C2POOL_DASH_BLS
    // No BLS backend: bytes are only comparable as points when serialized under
    // the SAME scheme; differing schemes are unresolvable → conservatively false.
    return a_legacy == b_legacy && a == b;
#else
    bls::G1Element pa, pb;
    try {
        // DECLARED scheme only — a v1 wire key read under basic would decode to a
        // DIFFERENT point and mask a real key change (the h=1874081 bug).
        pa = bls::G1Element::FromBytes(bls::Bytes(a.data(), a.size()), a_legacy);
        pb = bls::G1Element::FromBytes(bls::Bytes(b.data(), b.size()), b_legacy);
    } catch (...) {
        return false;   // either side undecodable under its declared scheme
    }
    if (!pa.IsValid() || !pb.IsValid()) return false;
    return pa == pb;    // G1Element::operator== — scheme-insensitive point compare
#endif
}


// --- opkey scheme normalization (dashd stores a POINT and serializes per the
// entry nVersion; we store raw bytes, so we must convert explicitly). A same
// G1 point encodes differently under the LEGACY (pre-v19) and BASIC (v19+)
// schemes; a basic key even mis-parses under legacy to a DIFFERENT valid point.
// We canonicalize every STORED opkey to BASIC (opkey_to_basic) so the store is
// scheme-unambiguous, then emit each SML leaf in the scheme its nVersion dictates
// (opkey_for_leaf: legacy iff nVersion < BASIC_BLS). Both no-op the a==b path and
// fall back to the input on decode failure.
inline std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>
opkey_to_basic(const std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>& wire, bool wire_legacy)
{
#ifndef C2POOL_DASH_BLS
    (void)wire_legacy;
    return wire;
#else
    const bls::Bytes bb(wire.data(), wire.size());
    // Decode with the declared wire scheme first (a v1 tx carries legacy, a v2 tx
    // basic); fall back to the other scheme, then to the raw bytes.
    for (bool legacy : { wire_legacy, !wire_legacy }) {
        try {
            bls::G1Element e = bls::G1Element::FromBytes(bb, legacy);
            if (e.IsValid()) {
                const std::vector<uint8_t> v = e.Serialize(false); // basic
                std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE> out{};
                std::copy_n(v.begin(), std::min(v.size(), out.size()), out.begin());
                return out;
            }
        } catch (...) { /* try the other scheme */ }
    }
    return wire;
#endif
}

inline std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>
opkey_for_leaf(const std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>& stored_basic, bool want_legacy)
{
#ifndef C2POOL_DASH_BLS
    (void)want_legacy;
    return stored_basic;
#else
    const bls::Bytes bb(stored_basic.data(), stored_basic.size());
    // The store is canonical BASIC; decode basic first, fall back to legacy, then raw.
    for (bool legacy : { false, true }) {
        try {
            bls::G1Element e = bls::G1Element::FromBytes(bb, legacy);
            if (e.IsValid()) {
                const std::vector<uint8_t> v = e.Serialize(want_legacy);
                std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE> out{};
                std::copy_n(v.begin(), std::min(v.size(), out.size()), out.begin());
                return out;
            }
        } catch (...) { /* try the other scheme */ }
    }
    return stored_basic;
#endif
}

} // namespace vendor
} // namespace coin
} // namespace dash
