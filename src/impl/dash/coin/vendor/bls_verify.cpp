// SPDX-License-Identifier: AGPL-3.0-or-later
//
// E1 Phase-L BLS verification of type-6 quorum commitments. See bls_verify.hpp.
//
// This TU is compiled UNCONDITIONALLY (so the seam symbols always resolve), but
// the BLS backend is linked + used only when C2POOL_DASH_BLS is defined. Without
// it, verify_final_commitment() / the produced verifier are fail-closed stubs
// (always false) and the serve path keeps the pre-Phase-L null-commitment
// posture — no dashbls dependency leaks into a build (e.g. the Windows main_ltc
// launcher, which never defines C2POOL_DASH_BLS).

#include <impl/dash/coin/vendor/bls_verify.hpp>

#include <core/pack.hpp>       // PackStream, WriteCompactSize
#include <core/hash.hpp>       // CHash256

#include <cstring>
#include <span>

#ifdef C2POOL_DASH_BLS
// dashpay/bls-signatures ("dashbls") — the exact library dashd wraps in
// src/bls/bls.h. bls.hpp pulls in the relic-backed G1/G2 element + scheme API.
#include <dashbls/bls.hpp>
#include <dashbls/schemes.hpp>
#include <dashbls/elements.hpp>
#endif

namespace dash {
namespace coin {
namespace vendor {

// ── BuildCommitmentHash (dashcore llmq/commitment.cpp, byte-exact) ──────────

uint256 build_commitment_hash(
    uint8_t llmq_type, const uint256& quorum_hash,
    const std::vector<bool>& valid_members,
    const std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>& quorum_public_key,
    const uint256& quorum_vvec_hash)
{
    // CHashWriter(SER_GETHASH, 0) << llmqType << blockHash
    //   << DYNBITSET(validMembers) << pubKey << vvecHash
    // then GetHash() == SHA256d. We build the identical preimage with a
    // PackStream (little-endian integrals; uint256 raw 32 LE bytes; the
    // vendored DynBitSetFormat is wire-identical to dashcore's
    // DynamicBitSetFormatter; the BLS pubkey is the opaque 48 wire bytes) and
    // hash it with core CHash256 — the same primitive quorum_root.hpp uses.
    ::PackStream s;
    s << llmq_type;                                   // 1 byte
    s << quorum_hash;                                 // 32 bytes (uint256, LE)
    DynBitSetFormat::Write(s, valid_members);         // CompactSize + ceil(n/8)
    s.write(std::as_bytes(std::span{quorum_public_key}));  // 48 raw wire bytes
    s << quorum_vvec_hash;                            // 32 bytes (uint256, LE)

    auto sp = s.get_span();
    uint256 h;
    CHash256()
        .Write(std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(sp.data()), sp.size()))
        .Finalize(std::span<unsigned char>(h.data(), 32));
    return h;
}

// ── BLS backend ─────────────────────────────────────────────────────────────

bool bls_backend_available()
{
#ifdef C2POOL_DASH_BLS
    return true;
#else
    return false;
#endif
}

#ifdef C2POOL_DASH_BLS
namespace {

// Robust G1 (public-key) deserialization mirroring dashcore CBLSWrapper::
// SetBytes: try the entry's declared scheme, and if the point is invalid fall
// back to the other scheme (a pre-V19 key relayed after the fork, or an SML
// nVersion mismatch). Returns false when neither yields a valid point.
bool deser_g1(const std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>& bytes,
              bool prefer_legacy, bls::G1Element& out)
{
    const bls::Bytes b(bytes.data(), bytes.size());
    for (bool legacy : {prefer_legacy, !prefer_legacy}) {
        try {
            bls::G1Element e = bls::G1Element::FromBytes(b, legacy);
            if (e.IsValid()) { out = e; return true; }
        } catch (...) { /* try the other scheme */ }
    }
    return false;
}

// Post-V19 signatures are BASIC scheme (fLegacy = false) — the serve floor in
// dkg_commitments.hpp guarantees post-V19, and the commitment we admit is the
// basic-scheme wire object.
bool deser_g2_basic(const std::array<uint8_t, CFinalCommitment::BLS_SIG_SIZE>& bytes,
                    bls::G2Element& out)
{
    try {
        out = bls::G2Element::FromBytes(bls::Bytes(bytes.data(), bytes.size()),
                                        /*fLegacy=*/false);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace
#endif // C2POOL_DASH_BLS

bool verify_final_commitment(const CFinalCommitment& c,
                             const std::vector<MemberOperatorKey>& members)
{
#ifndef C2POOL_DASH_BLS
    (void)c;
    (void)members;
    return false;   // no BLS backend → fail closed (serve null / dashd)
#else
    // ── structural guards (dashcore CFinalCommitment::Verify prelude) ───────
    if (members.empty()) return false;
    if (c.signers.size() != members.size()) return false;
    if (c.validMembers.size() != members.size()) return false;

    const uint256 commitment_hash = build_commitment_hash(
        c.llmqType, c.quorumHash, c.validMembers, c.quorumPublicKey,
        c.quorumVvecHash);
    const bls::Bytes msg(commitment_hash.data(), 32);
    bls::BasicSchemeMPL scheme;   // post-V19

    try {
        // ── membersSig: aggregate over the SIGNERS' operator keys ───────────
        bls::G2Element members_sig;
        if (!deser_g2_basic(c.membersSig, members_sig)) return false;

        std::vector<bls::G1Element> signer_pubkeys;
        signer_pubkeys.reserve(members.size());
        for (size_t i = 0; i < members.size(); ++i) {
            if (!c.signers[i]) continue;
            bls::G1Element pk;
            if (!deser_g1(members[i].pubKeyOperator,
                          members[i].legacy_scheme, pk))
                return false;   // a signer key we cannot decode → fail closed
            signer_pubkeys.push_back(pk);
        }
        if (signer_pubkeys.empty()) return false;

        // dashcore CFinalCommitment::Verify secure-aggregates the members' sig
        // for EVERY enabled LLMQ type. The plain-Verify shortcut is keyed
        // upstream on is_single_member() (llmq_params.size == 1), which NO
        // enabled type is — NOT on the signer COUNT (a count-based shortcut
        // diverges from dashbls VerifySecure, which has no n==1 special case).
        // So always VerifySecure; the minSize floor keeps signer_pubkeys well
        // above 1 for any admitted commitment.
        if (!scheme.VerifySecure(signer_pubkeys, members_sig, msg))
            return false;

        // ── quorumSig: threshold sig against quorumPublicKey ────────────────
        bls::G1Element quorum_pubkey =
            bls::G1Element::FromBytes(
                bls::Bytes(c.quorumPublicKey.data(), c.quorumPublicKey.size()),
                /*fLegacy=*/false);
        if (!quorum_pubkey.IsValid()) return false;
        bls::G2Element quorum_sig;
        if (!deser_g2_basic(c.quorumSig, quorum_sig)) return false;
        if (!scheme.Verify(quorum_pubkey, msg, quorum_sig)) return false;
    } catch (...) {
        return false;   // any relic/dashbls throw → fail closed
    }
    return true;
#endif // C2POOL_DASH_BLS
}

// ── R3: governance-vote operator-key single-sig verify ──────────────────────

bool verify_govvote_operator_sig(
    const std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>& pubkey_operator,
    bool key_legacy_scheme, const uint256& digest,
    const std::vector<uint8_t>& vch_sig)
{
#ifndef C2POOL_DASH_BLS
    (void)pubkey_operator;
    (void)key_legacy_scheme;
    (void)digest;
    (void)vch_sig;
    return false;   // no BLS backend → fail closed (vote never tallied → dashd)
#else
    // dashcore CGovernanceVote::CheckSignature: a BLS signature is 96 bytes.
    if (vch_sig.size() != CFinalCommitment::BLS_SIG_SIZE) return false;

    const bls::Bytes msg(digest.data(), 32);   // GetSignatureHash() digest bytes

    try {
        // The SIGNING scheme (signature wire-encoding + verify DST) and the
        // OPERATOR KEY's wire-encoding are INDEPENDENT, and dashcore treats them
        // so: a masternode registered under LEGACY_BLS (nVersion 1) keeps a
        // legacy-encoded pubKeyOperator forever, yet post-V19 it signs its
        // governance votes under the CURRENT (BASIC) scheme — a basic-encoded
        // signature verified with the basic DST. (Pinned against the real
        // from-wire testnet vote: legacy-encoded pubkey + basic-encoded sig +
        // basic DST verifies; every other combination fails.) So we vary the
        // two axes independently: the network signing scheme (BASIC first,
        // post-V19) drives sig-encoding + DST together; the key's declared
        // scheme drives the pubkey encoding, other as fallback. A forged/
        // tampered sig or wrong key verifies under NO combination — this only
        // widens which LEGITIMATE encodings are accepted, never what is
        // cryptographically valid.
        for (bool net_legacy : {false, true}) {   // BASIC (post-V19) first
            bls::G2Element sig;
            try {
                sig = bls::G2Element::FromBytes(
                    bls::Bytes(vch_sig.data(), vch_sig.size()), net_legacy);
            } catch (...) { continue; }

            for (bool pk_legacy : {key_legacy_scheme, !key_legacy_scheme}) {
                bls::G1Element pk;
                try {
                    pk = bls::G1Element::FromBytes(
                        bls::Bytes(pubkey_operator.data(), pubkey_operator.size()),
                        pk_legacy);
                } catch (...) { continue; }
                if (!pk.IsValid()) continue;

                const bool ok = net_legacy
                    ? bls::LegacySchemeMPL().Verify(pk, msg, sig)
                    : bls::BasicSchemeMPL().Verify(pk, msg, sig);
                if (ok) return true;
            }
        }
        return false;
    } catch (...) {
        return false;   // any relic/dashbls throw → fail closed
    }
#endif // C2POOL_DASH_BLS
}

// ── seam factory ────────────────────────────────────────────────────────────

std::function<bool(const CFinalCommitment&)>
make_commitment_bls_verifier(MemberKeysProvider provider)
{
    if (!bls_backend_available() || !provider) {
        // Fail-closed: verified_for() will never yield a real commitment; the
        // provider mines the null commitment (or dashd fallback) exactly as
        // pre-Phase-L.
        return [](const CFinalCommitment&) { return false; };
    }
    return [provider = std::move(provider)](const CFinalCommitment& c) -> bool {
        auto members = provider(c.llmqType, c.quorumHash);
        if (!members) return false;   // member set uncertain → fail closed
        return verify_final_commitment(c, *members);
    };
}

} // namespace vendor
} // namespace coin
} // namespace dash
