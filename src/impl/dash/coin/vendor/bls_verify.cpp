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
#include <algorithm>

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
        // ── SIGNATURE axis: HARD-PINNED to the BASIC scheme ─────────────────
        // dashcore v23.1.7 governance/vote.cpp CGovernanceVote::CheckSignature
        // (const CBLSPublicKey&):
        //     CBLSSignature sig;
        //     sig.SetBytes(vchSig, false);                       // BASIC decode
        //     sig.VerifyInsecure(pubKey, GetSignatureHash(), false);  // BASIC DST
        // Both the sig wire-decode AND the verify DST are hard-pinned false
        // (basic). SetBytes has NO legacy retry — the CheckMalleable/legacy
        // fallback exists only in the stream Unserialize path, which this
        // verify never takes. So post-V19 dashd REJECTS a legacy-scheme-signed
        // governance vote outright, and so must we: a legacy-sig fallback here
        // would accept votes dashd neither tallies nor relays — a hostile
        // registered MN could legacy-sign a YES on a near-threshold trigger
        // and feed it ONLY to c2pool, inflating our tally vs the network's
        // (wrong trigger wins => wrong superblock payees => lost block).
        // Pre-V19 heights would be legacy-scheme, but this tally only ever
        // runs post-V19 (triggers are cycle-ephemeral and the serve floor is
        // post-V19); if that ever changes, gate the scheme on the V19 fork
        // height exactly as dashcore does — never fall back per-vote.
        bls::G2Element sig;
        try {
            sig = bls::G2Element::FromBytes(
                bls::Bytes(vch_sig.data(), vch_sig.size()), /*fLegacy=*/false);
        } catch (...) {
            return false;   // not a basic-encoded G2 point => dashd rejects too
        }

        // ── PUBKEY-encoding axis: declared scheme first, other as fallback ──
        // Independent of the signature axis, and the fallback here is KEPT: a
        // masternode registered under LEGACY_BLS (ProRegTx nVersion 1) keeps a
        // legacy-ENCODED pubKeyOperator forever, and dashcore's
        // CBLSLazyPublicKey ingest decodes it per that registration version
        // BEFORE CheckSignature ever sees it (pubKeyOperator.Get() hands over
        // the decoded element — the key's encoding never reaches the verify).
        // We decode from the raw wire bytes ourselves, so we mirror that
        // ingest: the key's declared scheme first, the other encoding as
        // fallback. (Pinned against the real from-wire testnet vote:
        // legacy-encoded pubkey + basic-encoded sig + basic DST verifies; a
        // forged/tampered sig or wrong key verifies under NO pubkey encoding.)
        for (bool pk_legacy : {key_legacy_scheme, !key_legacy_scheme}) {
            bls::G1Element pk;
            try {
                pk = bls::G1Element::FromBytes(
                    bls::Bytes(pubkey_operator.data(), pubkey_operator.size()),
                    pk_legacy);
            } catch (...) { continue; }
            if (!pk.IsValid()) continue;

            if (bls::BasicSchemeMPL().Verify(pk, msg, sig)) return true;
        }
        return false;
    } catch (...) {
        return false;   // any relic/dashbls throw → fail closed
    }
#endif // C2POOL_DASH_BLS
}

// ── ChainLock recovered-threshold-signature verify ──────────────────────────

bool verify_chainlock_sig(
    const std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>& quorum_public_key,
    const uint256& sign_hash,
    const std::array<uint8_t, CFinalCommitment::BLS_SIG_SIZE>& sig)
{
#ifndef C2POOL_DASH_BLS
    (void)quorum_public_key;
    (void)sign_hash;
    (void)sig;
    return false;   // no BLS backend → fail closed (ChainLock never adopted)
#else
    try {
        // Quorum public key: G1, basic scheme (post-V19 wire encoding).
        bls::G1Element pk;
        try {
            pk = bls::G1Element::FromBytes(
                bls::Bytes(quorum_public_key.data(), quorum_public_key.size()),
                /*fLegacy=*/false);
        } catch (...) {
            return false;
        }
        if (!pk.IsValid()) return false;

        // Recovered threshold signature: G2, basic scheme.
        bls::G2Element s;
        try {
            s = bls::G2Element::FromBytes(bls::Bytes(sig.data(), sig.size()),
                                          /*fLegacy=*/false);
        } catch (...) {
            return false;   // not a basic-encoded G2 point → dashd rejects too
        }

        // The 32 sign-hash bytes are the message; BasicSchemeMPL applies the
        // DST "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_" hash-to-curve.
        return bls::BasicSchemeMPL().Verify(
            pk, bls::Bytes(sign_hash.data(), 32), s);
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


// See bls_verify.hpp. Self-contained (does not depend on the anon-namespace
// deser_g1): robust dual-scheme G1 deserialize, compare canonical basic bytes.
bool opkey_same_g1(const std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>& a,
                   const std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>& b)
{
    if (a == b) return true;
#ifndef C2POOL_DASH_BLS
    return false;   // no BLS backend: fall back to byte-equality (already != here)
#else
    // A same G1 point can be encoded under either the LEGACY or the BASIC scheme,
    // and a BASIC-scheme key can silently DESERIALIZE (without throwing) under the
    // legacy convention as a DIFFERENT valid point. So "first scheme that decodes
    // wins" is unsafe: it may canonicalize the two sides via different points and
    // report a spurious difference (proven at h=1900676: wire 93d0.. mis-parses as
    // b3d0.. under legacy). Instead collect EVERY canonical (basic-serialized) form
    // each side can decode to, under BOTH schemes, and treat the keys as equal iff
    // those form-sets intersect.
    auto canon_set = [](const std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>& k,
                        std::vector<std::vector<uint8_t>>& out) {
        const bls::Bytes bb(k.data(), k.size());
        for (bool legacy : {true, false}) {
            try {
                bls::G1Element e = bls::G1Element::FromBytes(bb, legacy);
                if (e.IsValid()) out.push_back(e.Serialize(false));
            } catch (...) { /* try the other scheme */ }
        }
    };
    std::vector<std::vector<uint8_t>> sa, sb;
    canon_set(a, sa);
    canon_set(b, sb);
    for (const auto& x : sa)
        for (const auto& y : sb)
            if (x == y) return true;
    return false;
#endif
}


// See bls_verify.hpp. Faithful port of dashd's reset-gate point compare
// (specialtxman.cpp:388 CBLSPublicKey operator== / bls.h:512): decode EACH side
// under EXACTLY its declared scheme (NO cross-scheme fallback) and compare the
// two G1 points. Equal iff both decode validly AND are the same point.
bool opkey_point_eq(const std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>& a, bool a_legacy,
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


std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>
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

std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE>
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
