// SPDX-License-Identifier: AGPL-3.0-or-later
//
// E1 Phase-L KATs: BLS12-381 verification of type-6 quorum commitments.
//
// Two independent anchors:
//
//   1. BuildCommitmentHash byte-exactness (ALWAYS runs, no BLS backend needed):
//      the signed preimage of a REAL from-wire testnet commitment hashes to the
//      value dashd itself signed. This is the hardest-to-get-right piece and is
//      locked regardless of whether dashbls is linked.
//
//   2. BLS crypto (gated on C2POOL_DASH_BLS): the real from-wire quorumSig
//      verifies against the real quorumPublicKey over that hash (ACCEPT), and
//      tampering REJECTS; plus a fully synthetic round-trip that exercises the
//      complete verify_final_commitment() path (membersSig aggregate + quorumSig)
//      deterministically, and the fail-closed guards.
//
// The real vector was captured read-only from the testnet dashd (block 1519931,
// llmq_50_60 quorum 0000001badbdd0…5c928798) — a successful DKG whose canonical
// block carries the REAL (non-null) commitment, the exact mainnet case null-serve
// would diverge on.

#include <gtest/gtest.h>

#include <impl/dash/coin/vendor/bls_verify.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#ifdef C2POOL_DASH_BLS
#include <dashbls/bls.hpp>
#include <dashbls/schemes.hpp>
#include <dashbls/elements.hpp>
#endif

using namespace dash::coin::vendor;

namespace {

std::vector<uint8_t> unhex(const std::string& s)
{
    std::vector<uint8_t> o;
    o.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        o.push_back(static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
    return o;
}

template <size_t N>
std::array<uint8_t, N> to_array(const std::vector<uint8_t>& v)
{
    std::array<uint8_t, N> a{};
    EXPECT_EQ(v.size(), N);
    for (size_t i = 0; i < N && i < v.size(); ++i) a[i] = v[i];
    return a;
}

// uint256 from raw little-endian wire bytes (as they appear on the wire).
uint256 u256_le(const std::string& le_hex)
{
    return uint256(unhex(le_hex));
}

// ── real from-wire testnet vector (llmq_50_60 @ block 1519931) ──────────────
constexpr uint8_t kLlmqType = 1;
const char* kQuorumHashLe =
    "9887925c4fe116e798cb79d54f3614baf73349e85c0bf66ce9d0bdad1b000000";
const char* kQuorumPubKey =
    "a51db3577089e74a6aa0b3ed0e8b8697e56f43b330be3c34e88fe7d4d1e3889e"
    "781fea3c5aa385edcbca6540ddd49fa1";
const char* kQuorumVvecHash =
    "77a703f2ee5498e7b79df11f8fbbd40ab5c26e660c0a8fe67443dc083e3e4524";
const char* kQuorumSig =
    "93a37bd57ef329e8953deb448a0348124cafa52df0e5b7ca1076fc57e9a801ae"
    "fd445c259b1a65e43472959a3b16e3f901aa42b7e830706b5525841e3c7b388b"
    "94be4a72da1776f52b1f90e73d8dff21831fc90332634c88311b7f7ac6aa166b";
// SHA256d of the BuildCommitmentHash preimage, as computed against dashd's
// signed value (independently derived from the wire, matches the quorumSig).
const char* kExpectedCommitmentHash =
    "fda5e2b76b8d83aa328b694b0f827b0d589babb656d81fb8b92f3b193ed86594";

} // namespace

// ── anchor 1: BuildCommitmentHash byte-exactness (no backend needed) ────────
TEST(DashBlsVerify, BuildCommitmentHashRealVector)
{
    std::vector<bool> valid_members(50, true);   // all 50 valid on this quorum
    uint256 h = build_commitment_hash(
        kLlmqType, u256_le(kQuorumHashLe), valid_members,
        to_array<48>(unhex(kQuorumPubKey)), u256_le(kQuorumVvecHash));

    // h is SHA256d output stored LE; compare against the LE-hex we captured.
    std::vector<uint8_t> got(h.data(), h.data() + 32);
    std::vector<uint8_t> want = unhex(kExpectedCommitmentHash);
    EXPECT_EQ(got, want)
        << "BuildCommitmentHash preimage drifted from dashd (bad-qc risk)";
}

// ── fail-closed without a backend / provider (always meaningful) ────────────
TEST(DashBlsVerify, FailClosedNoMembers)
{
    CFinalCommitment c;
    c.llmqType = kLlmqType;
    c.signers.assign(50, true);
    c.validMembers.assign(50, true);
    // Empty member set → cannot verify membersSig → false, regardless of backend.
    EXPECT_FALSE(verify_final_commitment(c, {}));
    // Size-mismatched member set → false.
    std::vector<MemberOperatorKey> two(2);
    EXPECT_FALSE(verify_final_commitment(c, two));
}

TEST(DashBlsVerify, MakeVerifierNullProviderFailsClosed)
{
    auto fn = make_commitment_bls_verifier(nullptr);
    ASSERT_TRUE(static_cast<bool>(fn));
    CFinalCommitment c;
    c.llmqType = kLlmqType;
    c.signers.assign(50, true);
    c.validMembers.assign(50, true);
    EXPECT_FALSE(fn(c));   // null provider → never serves a real commitment
}

#ifdef C2POOL_DASH_BLS

// ── anchor 2a: real quorumSig verifies over the real commitment hash ────────
TEST(DashBlsVerify, RealQuorumSigAcceptsAndTamperRejects)
{
    ASSERT_TRUE(bls_backend_available());
    std::vector<bool> valid_members(50, true);
    uint256 h = build_commitment_hash(
        kLlmqType, u256_le(kQuorumHashLe), valid_members,
        to_array<48>(unhex(kQuorumPubKey)), u256_le(kQuorumVvecHash));

    auto pk = unhex(kQuorumPubKey);
    auto sig = unhex(kQuorumSig);
    bls::G1Element qpk =
        bls::G1Element::FromBytes(bls::Bytes(pk.data(), pk.size()), false);
    bls::G2Element qs =
        bls::G2Element::FromBytes(bls::Bytes(sig.data(), sig.size()), false);
    bls::BasicSchemeMPL scheme;

    // real quorumSig over the real commitment hash → ACCEPT.
    EXPECT_TRUE(scheme.Verify(qpk, bls::Bytes(h.data(), 32), qs));

    // flip one bit of the hash → REJECT.
    std::vector<uint8_t> bad(h.data(), h.data() + 32);
    bad[7] ^= 0x01;
    EXPECT_FALSE(scheme.Verify(qpk, bls::Bytes(bad.data(), bad.size()), qs));

    // flip one byte of the signature → REJECT (or fails to deserialize).
    auto badsig = sig;
    badsig[20] ^= 0x01;
    bool ok_badsig = false;
    try {
        bls::G2Element qsb = bls::G2Element::FromBytes(
            bls::Bytes(badsig.data(), badsig.size()), false);
        ok_badsig = scheme.Verify(qpk, bls::Bytes(h.data(), 32), qsb);
    } catch (...) { ok_badsig = false; }
    EXPECT_FALSE(ok_badsig);
}

// ── BLS smoke KAT: a self-generated keypair round-trips ─────────────────────
TEST(DashBlsVerify, BlsSmokeSignVerify)
{
    bls::BasicSchemeMPL scheme;
    std::vector<uint8_t> seed(32, 0x11);
    bls::PrivateKey sk = scheme.KeyGen(seed);
    bls::G1Element pk = sk.GetG1Element();
    std::vector<uint8_t> msg = {'c', '2', 'p', 'o', 'o', 'l'};
    bls::G2Element sig = scheme.Sign(sk, msg);
    EXPECT_TRUE(scheme.Verify(pk, bls::Bytes(msg.data(), msg.size()), sig));
    std::vector<uint8_t> other = {'x'};
    EXPECT_FALSE(scheme.Verify(pk, bls::Bytes(other.data(), other.size()), sig));
}

// ── anchor 2b: full verify_final_commitment round-trip (synthetic) ──────────
//
// Deterministically construct a VALID commitment (real member + quorum BLS
// keys we generate here), then assert verify_final_commitment ACCEPTS it and
// every single-byte tamper REJECTS — exercising the complete production path
// (BuildCommitmentHash + membersSig VerifySecure + quorumSig Verify) without the
// scheme-ambiguity of RPC-sourced member keys.
TEST(DashBlsVerify, VerifyFinalCommitmentSyntheticRoundTrip)
{
    const size_t kSize = 5;
    bls::BasicSchemeMPL scheme;

    CFinalCommitment c;
    c.nVersion = CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
    c.llmqType = kLlmqType;
    c.quorumHash = u256_le(kQuorumHashLe);
    c.quorumVvecHash = u256_le(kQuorumVvecHash);
    c.signers.assign(kSize, true);
    c.validMembers.assign(kSize, true);

    // member operator keys
    std::vector<MemberOperatorKey> members(kSize);
    std::vector<bls::PrivateKey> member_sks;
    std::vector<bls::G1Element> member_pks;
    for (size_t i = 0; i < kSize; ++i) {
        std::vector<uint8_t> seed(32, static_cast<uint8_t>(0x40 + i));
        bls::PrivateKey sk = scheme.KeyGen(seed);
        bls::G1Element pk = sk.GetG1Element();
        member_sks.push_back(sk);
        member_pks.push_back(pk);
        auto raw = pk.Serialize(false);   // basic scheme wire bytes
        for (size_t j = 0; j < 48; ++j) members[i].pubKeyOperator[j] = raw[j];
        members[i].legacy_scheme = false;
    }
    // quorum threshold key
    std::vector<uint8_t> qseed(32, 0xAB);
    bls::PrivateKey qsk = scheme.KeyGen(qseed);
    bls::G1Element qpk = qsk.GetG1Element();
    {
        auto raw = qpk.Serialize(false);
        for (size_t j = 0; j < 48; ++j) c.quorumPublicKey[j] = raw[j];
    }

    // the commitment hash the signatures must cover
    uint256 h = build_commitment_hash(
        c.llmqType, c.quorumHash, c.validMembers, c.quorumPublicKey,
        c.quorumVvecHash);
    bls::Bytes msg(h.data(), 32);

    // membersSig = secure aggregate of each member's signature over h
    std::vector<bls::G2Element> member_sigs;
    for (auto& sk : member_sks) member_sigs.push_back(scheme.Sign(sk, msg));
    bls::G2Element members_sig = scheme.AggregateSecure(member_pks, member_sigs, msg);
    {
        auto raw = members_sig.Serialize(false);
        for (size_t j = 0; j < 96; ++j) c.membersSig[j] = raw[j];
    }
    // quorumSig = the threshold key's signature over h
    bls::G2Element quorum_sig = scheme.Sign(qsk, msg);
    {
        auto raw = quorum_sig.Serialize(false);
        for (size_t j = 0; j < 96; ++j) c.quorumSig[j] = raw[j];
    }

    // ACCEPT.
    EXPECT_TRUE(verify_final_commitment(c, members));

    // tamper membersSig → REJECT.
    {
        CFinalCommitment t = c;
        t.membersSig[10] ^= 0x01;
        EXPECT_FALSE(verify_final_commitment(t, members));
    }
    // tamper quorumSig → REJECT.
    {
        CFinalCommitment t = c;
        t.quorumSig[10] ^= 0x01;
        EXPECT_FALSE(verify_final_commitment(t, members));
    }
    // tamper quorumPublicKey → REJECT (changes the hash AND the key).
    {
        CFinalCommitment t = c;
        t.quorumPublicKey[10] ^= 0x01;
        EXPECT_FALSE(verify_final_commitment(t, members));
    }
    // drop a signer's key (wrong member set) → REJECT.
    {
        auto bad_members = members;
        bad_members[0].pubKeyOperator[5] ^= 0x01;
        EXPECT_FALSE(verify_final_commitment(c, bad_members));
    }
}

// ── task #154 KAT (c): operator-key POINT compare (opkey_point_eq) ───────────
//
// The DML fold's ProUpRegTx reset gate (replay_fold_engine.hpp fold_proupreg)
// resets+bans a masternode iff the operator key POINT changed, a 1:1 port of
// dashd specialtxman.cpp:388 (CBLSPublicKey operator== / bls.h:512). The store
// is canonical BASIC; the wire key is serialized in the scheme its ProUpRegTx
// nVersion dictates (legacy iff nVersion < BasicBLS). A same G1 point encodes
// to DIFFERENT bytes under legacy vs basic, and legacy bytes read under basic
// decode to a DIFFERENT point. A naive byte compare therefore OVER-resets a
// legacy-wire/same-point update, and a dual-scheme intersection UNDER-resets it
// — the h=1874081/@1899899 derive walls. opkey_point_eq decodes each side under
// EXACTLY its declared scheme and compares points, matching dashd byte-for-byte.
TEST(DashBlsVerify, OpkeyPointEqIsSchemeFaithful)
{
    auto to_arr = [](const std::vector<uint8_t>& v) {
        std::array<uint8_t, CFinalCommitment::BLS_PUBKEY_SIZE> a{};
        for (size_t i = 0; i < a.size() && i < v.size(); ++i) a[i] = v[i];
        return a;
    };

    bls::BasicSchemeMPL scheme;
    // Key P and a DISTINCT key Q.
    bls::G1Element P = scheme.KeyGen(std::vector<uint8_t>(32, 0x51)).GetG1Element();
    bls::G1Element Q = scheme.KeyGen(std::vector<uint8_t>(32, 0x77)).GetG1Element();

    const auto p_basic  = to_arr(P.Serialize(false)); // basic (v19+) encoding of P
    const auto p_legacy = to_arr(P.Serialize(true));  // legacy (pre-v19) encoding of P
    const auto q_basic  = to_arr(Q.Serialize(false));

    // The two encodings of the SAME point are DIFFERENT bytes — a naive byte
    // compare would (wrongly) treat a legacy-wire update as a key change.
    EXPECT_NE(p_basic, p_legacy)
        << "basic and legacy encodings of one point must differ (else the KAT is vacuous)";

    // Stored BASIC vs wire LEGACY, each read under its DECLARED scheme => SAME
    // point => EQUAL => the reset does NOT fire (no over-reset). This is the
    // h=1874081 case dashd does not reset on.
    EXPECT_TRUE(opkey_point_eq(p_basic, /*a_legacy=*/false,
                               p_legacy, /*b_legacy=*/true));

    // Same legacy bytes MIS-declared as basic => decode to a different/invalid
    // point => NOT-EQUAL. (Shows the declared scheme is load-bearing.)
    EXPECT_FALSE(opkey_point_eq(p_basic, /*a_legacy=*/false,
                                p_legacy, /*b_legacy=*/false));

    // A REAL operator-key change => NOT-EQUAL => the reset+ban fires.
    EXPECT_FALSE(opkey_point_eq(p_basic, /*a_legacy=*/false,
                                q_basic, /*b_legacy=*/false));

    // Scheme normalization round-trips: a legacy wire key canonicalizes to the
    // stored basic bytes, and a stored basic key re-emits the legacy leaf bytes.
    EXPECT_EQ(opkey_to_basic(p_legacy, /*wire_legacy=*/true), p_basic);
    EXPECT_EQ(opkey_for_leaf(p_basic, /*want_legacy=*/true),  p_legacy);
    EXPECT_EQ(opkey_for_leaf(p_basic, /*want_legacy=*/false), p_basic);
}

#endif // C2POOL_DASH_BLS
