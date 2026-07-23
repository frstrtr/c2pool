// SPDX-License-Identifier: AGPL-3.0-or-later
//
// E1 Phase-L KATs: deterministic quorum MEMBER-SET computation (the piece that
// lets #812's verify_final_commitment ACCEPT a real relayed commitment instead
// of failing closed to null-serve).
//
// Anchors (all against REAL from-wire testnet vectors, captured read-only from
// the testnet dashd — llmq_50_60 quorum 0000001badbdd0…5c928798, base block
// height 1519920, commitment mined in block 1519931):
//
//   1. compute_quorum_members reproduces dashd's EXACT ordered 50-member set +
//      each member's operator key + the legacy/basic scheme flag (fails BEFORE
//      this module: the provider returned nullopt). Runs in EVERY build (no BLS
//      backend needed — pure selection).
//   2. (C2POOL_DASH_BLS) the computed member set makes verify_final_commitment
//      ACCEPT the REAL mined commitment (real signers bitset + real membersSig
//      aggregate over the members' operator keys) — the end-to-end proof that
//      Phase-L now serves a REAL commitment. Byte-flip the member set -> REJECT.
//   3. (C2POOL_DASH_BLS) partial signers/validMembers KAT (review gap): a
//      commitment whose validMembers is NOT all-ones, membersSig aggregated over
//      a signer SUBSET, verifies correctly (subset selection + the validMembers
//      bitset folded into the hash) and tampers reject.
//   4. fail-closed: rotated type, SML gap / too-small SML, zero operator key.

#include <gtest/gtest.h>

#include <impl/dash/coin/vendor/quorum_members.hpp>
#include <impl/dash/coin/vendor/bls_verify.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <core/uint256.hpp>

#include "data/dash_quorum_members_kat.hpp"

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
std::array<uint8_t, N> arr(const std::vector<uint8_t>& v)
{
    std::array<uint8_t, N> a{};
    EXPECT_EQ(v.size(), N);
    for (size_t i = 0; i < N && i < v.size(); ++i) a[i] = v[i];
    return a;
}

// uint256 from RPC DISPLAY hex (big-endian) -> raw internal LE wire bytes.
uint256 u256_disp(const std::string& disp_hex)
{
    auto b = unhex(disp_hex);
    std::reverse(b.begin(), b.end());
    return uint256(b);
}

// Expand a DYNBITSET body (LSB-first packed bytes) to a length-n bool vector.
std::vector<bool> bitset_of(const std::string& hex, size_t n)
{
    auto bytes = unhex(hex);
    std::vector<bool> v(n, false);
    for (size_t p = 0; p < n; ++p)
        v[p] = (bytes[p / 8] >> (p % 8)) & 1u;
    return v;
}

CSimplifiedMNList build_kat_sml()
{
    std::vector<CSimplifiedMNListEntry> entries;
    entries.reserve(dash_qmk::kSml.size());
    for (const auto& e : dash_qmk::kSml) {
        CSimplifiedMNListEntry m;
        m.nVersion       = e.nVersion;
        m.proRegTxHash   = u256_disp(e.proReg);
        m.confirmedHash  = u256_disp(e.confirmed);
        m.pubKeyOperator = arr<48>(unhex(e.pubkeyOp));
        m.isValid        = e.isValid;
        entries.push_back(m);
    }
    return CSimplifiedMNList(std::move(entries));
}

QuorumMemberParams params_50_60() { return QuorumMemberParams{1, 50, false}; }

uint256 kat_modifier()
{
    std::array<uint8_t, 96> cl = arr<96>(unhex(dash_qmk::kWorkClSig));
    return compute_quorum_modifier(
        dash_qmk::kLlmqType, dash_qmk::kWorkHeight,
        std::optional<std::array<uint8_t, 96>>(cl),
        u256_disp(dash_qmk::kWorkBlockHashDisp));
}

} // namespace

// ── anchor 1: exact ordered member set + keys + scheme (no backend needed) ──
TEST(DashQuorumMembers, ReproducesDashdMemberSet)
{
    CSimplifiedMNList sml = build_kat_sml();
    auto members = compute_quorum_members(params_50_60(), kat_modifier(), sml);

    ASSERT_TRUE(members.has_value())
        << "member selection failed on a real full SML — provider would null-serve";
    ASSERT_EQ(members->size(), dash_qmk::kExpectedMembers.size());

    for (size_t i = 0; i < members->size(); ++i) {
        const auto& got  = (*members)[i];
        const auto& want = dash_qmk::kExpectedMembers[i];
        auto want_key = arr<48>(unhex(want.pubkeyOp));
        EXPECT_EQ(got.pubKeyOperator, want_key)
            << "operator key mismatch at member index " << i
            << " (member ORDER drifted from dashd -> membersSig would fail)";
        EXPECT_EQ(got.legacy_scheme, want.legacy)
            << "scheme flag mismatch at index " << i
            << " (SML nVersion plumb-through — a mixed quorum would mis-decode)";
    }
}

// ── fail-closed surfaces (no backend needed) ────────────────────────────────
TEST(DashQuorumMembers, FailClosedSurfaces)
{
    CSimplifiedMNList sml = build_kat_sml();
    const uint256 mod = kat_modifier();

    // rotated type -> nullopt (DIP-24 quarter rotation is the qrinfo follow-up).
    EXPECT_FALSE(compute_quorum_members(
        QuorumMemberParams{5, 60, /*use_rotation=*/true}, mod, sml).has_value());

    // empty SML -> nullopt (cannot form the quorum).
    EXPECT_FALSE(compute_quorum_members(
        params_50_60(), mod, CSimplifiedMNList{}).has_value());

    // SML with fewer confirmed+valid MNs than params.size -> nullopt.
    {
        std::vector<CSimplifiedMNListEntry> few;
        for (size_t i = 0; i < 10 && i < dash_qmk::kSml.size(); ++i) {
            CSimplifiedMNListEntry m;
            m.nVersion      = dash_qmk::kSml[i].nVersion;
            m.proRegTxHash  = u256_disp(dash_qmk::kSml[i].proReg);
            m.confirmedHash = u256_disp(dash_qmk::kSml[i].confirmed);
            m.pubKeyOperator = arr<48>(unhex(dash_qmk::kSml[i].pubkeyOp));
            m.isValid       = true;
            few.push_back(m);
        }
        EXPECT_FALSE(compute_quorum_members(
            params_50_60(), mod, CSimplifiedMNList(std::move(few))).has_value());
    }
}

// ── modifier fail-closed / fallback shape (no backend needed) ───────────────
TEST(DashQuorumMembers, ModifierClAbsentFallbackDiffers)
{
    // With vs without a coinbase ChainLock the modifier MUST differ (tuple vs
    // pair preimage) — a silent collapse would mis-select every post-V20 quorum.
    std::array<uint8_t, 96> cl = arr<96>(unhex(dash_qmk::kWorkClSig));
    uint256 with_cl = compute_quorum_modifier(
        dash_qmk::kLlmqType, dash_qmk::kWorkHeight,
        std::optional<std::array<uint8_t, 96>>(cl),
        u256_disp(dash_qmk::kWorkBlockHashDisp));
    uint256 no_cl = compute_quorum_modifier(
        dash_qmk::kLlmqType, dash_qmk::kWorkHeight, std::nullopt,
        u256_disp(dash_qmk::kWorkBlockHashDisp));
    EXPECT_NE(with_cl, no_cl);
}

#ifdef C2POOL_DASH_BLS

// ── anchor 2: computed member set makes the REAL commitment VERIFY ──────────
TEST(DashQuorumMembers, RealCommitmentVerifiesWithComputedMembers)
{
    ASSERT_TRUE(bls_backend_available());

    CSimplifiedMNList sml = build_kat_sml();
    auto members = compute_quorum_members(params_50_60(), kat_modifier(), sml);
    ASSERT_TRUE(members.has_value());
    ASSERT_EQ(members->size(), 50u);

    // Reconstruct the REAL mined commitment from the captured wire fields.
    CFinalCommitment c;
    c.nVersion       = dash_qmk::kCommVersion;   // 3 = basic non-indexed
    c.llmqType       = dash_qmk::kLlmqType;
    c.quorumHash     = u256_disp(dash_qmk::kQuorumHashDisp);
    c.signers        = bitset_of(dash_qmk::kCommSigners, 50);
    c.validMembers   = bitset_of(dash_qmk::kCommValidMembers, 50);
    c.quorumPublicKey = arr<48>(unhex(dash_qmk::kCommQuorumPubKey));
    c.quorumVvecHash = u256_disp(dash_qmk::kCommVvecHash);
    c.quorumSig      = arr<96>(unhex(dash_qmk::kCommQuorumSig));
    c.membersSig     = arr<96>(unhex(dash_qmk::kCommMembersSig));

    // THE Phase-L acceptance: a REAL relayed commitment now verifies.
    EXPECT_TRUE(verify_final_commitment(c, *members))
        << "real commitment REJECTED — Phase-L would stay null-serve";

    // Corrupt one member's operator key -> membersSig aggregate breaks -> REJECT.
    {
        auto bad = *members;
        bad[0].pubKeyOperator[5] ^= 0x01;
        EXPECT_FALSE(verify_final_commitment(c, bad));
    }
    // Substitute a member key with a foreign one -> the signer SET changes ->
    // secure aggregate REJECT. (Swapping two ALL-signers members would NOT
    // reject — the signer pubkey SET is unchanged and VerifySecure is
    // set-based, exactly like dashcore; member-ORDER vs the signers BITSET is
    // exercised by PartialSignersAndValidMembers below.)
    {
        auto bad = *members;
        bad[0].pubKeyOperator[0] ^= 0x02;   // no longer a real member key
        EXPECT_FALSE(verify_final_commitment(c, bad));
    }
}

// ── anchor 3: partial signers/validMembers (review KAT gap) ─────────────────
TEST(DashQuorumMembers, PartialSignersAndValidMembers)
{
    const size_t kSize = 6;
    bls::BasicSchemeMPL scheme;

    CFinalCommitment c;
    c.nVersion       = CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
    c.llmqType       = dash_qmk::kLlmqType;
    c.quorumHash     = u256_disp(dash_qmk::kQuorumHashDisp);
    c.quorumVvecHash = u256_disp(dash_qmk::kCommVvecHash);

    // NON-full bitsets, and validMembers != signers (both folded distinctly:
    // validMembers into the commitment hash, signers into the aggregate set).
    std::vector<bool> signers      = {true, true, false, true, true, false};
    std::vector<bool> validMembers = {true, true, true,  false, true, true};
    c.signers = signers;
    c.validMembers = validMembers;

    // member operator keys (index-aligned with the bitsets).
    std::vector<MemberOperatorKey> members(kSize);
    std::vector<bls::PrivateKey> sks;
    std::vector<bls::G1Element> signer_pks;
    std::vector<bls::G2Element> signer_sigs;

    uint256 h;   // built below once quorumPublicKey is set
    // quorum threshold key first (it feeds the hash).
    std::vector<uint8_t> qseed(32, 0xCD);
    bls::PrivateKey qsk = scheme.KeyGen(qseed);
    {
        auto raw = qsk.GetG1Element().Serialize(false);
        for (size_t j = 0; j < 48; ++j) c.quorumPublicKey[j] = raw[j];
    }
    h = build_commitment_hash(c.llmqType, c.quorumHash, c.validMembers,
                              c.quorumPublicKey, c.quorumVvecHash);
    bls::Bytes msg(h.data(), 32);

    for (size_t i = 0; i < kSize; ++i) {
        std::vector<uint8_t> seed(32, static_cast<uint8_t>(0x70 + i));
        bls::PrivateKey sk = scheme.KeyGen(seed);
        auto raw = sk.GetG1Element().Serialize(false);
        for (size_t j = 0; j < 48; ++j) members[i].pubKeyOperator[j] = raw[j];
        members[i].legacy_scheme = false;
        if (signers[i]) {
            signer_pks.push_back(sk.GetG1Element());
            signer_sigs.push_back(scheme.Sign(sk, msg));
        }
    }
    // membersSig = secure aggregate over ONLY the signer subset.
    bls::G2Element magg = scheme.AggregateSecure(signer_pks, signer_sigs, msg);
    { auto raw = magg.Serialize(false); for (size_t j = 0; j < 96; ++j) c.membersSig[j] = raw[j]; }
    { auto raw = scheme.Sign(qsk, msg).Serialize(false); for (size_t j = 0; j < 96; ++j) c.quorumSig[j] = raw[j]; }

    EXPECT_TRUE(verify_final_commitment(c, members))
        << "partial-bitset commitment failed to verify";

    // Flip a validMembers bit -> commitment hash changes -> REJECT.
    {
        CFinalCommitment t = c;
        t.validMembers[2] = false;
        EXPECT_FALSE(verify_final_commitment(t, members));
    }
    // Flip a signers bit (claims a non-signer signed) -> aggregate set wrong -> REJECT.
    {
        CFinalCommitment t = c;
        t.signers[2] = true;
        EXPECT_FALSE(verify_final_commitment(t, members));
    }
}

#endif // C2POOL_DASH_BLS
