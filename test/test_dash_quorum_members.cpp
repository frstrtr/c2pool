// SPDX-License-Identifier: AGPL-3.0-or-later
//
// E1 Phase-L KATs: deterministic quorum MEMBER-SET computation (the piece that
// lets #812's verify_final_commitment ACCEPT a real relayed commitment instead
// of failing closed to null-serve).
//
// Anchors (all against REAL from-wire testnet vectors, captured read-only from
// the testnet dashd — quorum base block height 1519920, WORK block 1519912 =
// base - WORK_DIFF_DEPTH(8), commitments mined in block 1519931; the KAT data
// header documents the exact RPC provenance):
//
//   1. compute_quorum_members over the SML AS OF THE WORK BLOCK (#814 review
//      R2 — the list v23.1.7 GetAllQuorumMembers actually selects from)
//      reproduces dashd's EXACT ordered 50-member llmq_50_60 set + each
//      member's operator key + the legacy/basic scheme flag. Runs in EVERY
//      build (no BLS backend needed — pure selection).
//   1b. llmq_25_67 (testnet llmqTypePlatform) with the Evo-only filter (#814
//      review R4) reproduces dashd's EXACT ordered 25-member all-Evo set at
//      the SAME base block; without the filter the set is WRONG.
//   1c. the full-field SML's CalcMerkleRoot() equals the work-block cbTx's
//      merkleRootMNList, and the cbTxMerkleTree proves that cbTx into the
//      work-block header — the DIP-4 authentication legs (#814 review R3)
//      against real wire data; tampered variants REJECT.
//   2. (C2POOL_DASH_BLS) the computed member set makes verify_final_commitment
//      ACCEPT the REAL mined commitment (real signers bitset + real membersSig
//      aggregate over the members' operator keys) — the end-to-end proof that
//      Phase-L now serves a REAL commitment. Byte-flip the member set -> REJECT.
//      Same for the REAL llmq_25_67 platform commitment over the Evo-only set.
//   3. (C2POOL_DASH_BLS) partial signers/validMembers KAT (review gap): a
//      commitment whose validMembers is NOT all-ones, membersSig aggregated over
//      a signer SUBSET, verifies correctly (subset selection + the validMembers
//      bitset folded into the hash) and tampers reject.
//   4. fail-closed: rotated type, SML gap / too-small SML, zero operator key,
//      platform type without enough Evo nodes.

#include <gtest/gtest.h>

#include <impl/dash/coin/vendor/quorum_members.hpp>
#include <impl/dash/coin/vendor/bls_verify.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/dash/coin/vendor/smldiff.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>   // dash_txid
#include <impl/dash/coin/block.hpp>          // BlockHeaderType
#include <core/uint256.hpp>
#include <core/pack.hpp>

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

// uint160 from RAW wire-order hex (20 bytes as they sit on the wire).
uint160 u160_raw(const std::string& raw_hex)
{
    auto b = unhex(raw_hex);
    EXPECT_EQ(b.size(), 20u);
    return uint160(b);
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

CSimplifiedMNListEntry kat_entry(const dash_qmk::SmlEntry& e)
{
    CSimplifiedMNListEntry m;
    m.nVersion         = e.nVersion;
    m.proRegTxHash     = u256_disp(e.proReg);
    m.confirmedHash    = u256_disp(e.confirmed);
    m.netAddress       = arr<16>(unhex(e.ip));
    m.netPort          = e.port;
    m.pubKeyOperator   = arr<48>(unhex(e.pubkeyOp));
    m.keyIDVoting      = u160_raw(e.votingKeyId);
    m.isValid          = e.isValid;
    m.nType            = e.nType;
    m.platformHTTPPort = e.platformHTTPPort;
    if (e.platformNodeId[0] != '\0')
        m.platformNodeID = u160_raw(e.platformNodeId);
    return m;
}

CSimplifiedMNList build_kat_sml()
{
    std::vector<CSimplifiedMNListEntry> entries;
    entries.reserve(dash_qmk::kSml.size());
    for (const auto& e : dash_qmk::kSml) entries.push_back(kat_entry(e));
    return CSimplifiedMNList(std::move(entries));
}

QuorumMemberParams params_50_60() { return QuorumMemberParams{1, 50, false, false}; }
QuorumMemberParams params_25_67_platform()
{
    // testnet llmqTypePlatform = LLMQ_25_67 (type 6) => EvoOnly (review R4).
    return QuorumMemberParams{dash_qmk::kLlmqTypePlatform, 25, false, true};
}

uint256 kat_modifier(uint8_t llmq_type)
{
    std::array<uint8_t, 96> cl = arr<96>(unhex(dash_qmk::kWorkClSig));
    return compute_quorum_modifier(
        llmq_type, dash_qmk::kWorkHeight,
        std::optional<std::array<uint8_t, 96>>(cl),
        u256_disp(dash_qmk::kWorkBlockHashDisp));
}

} // namespace

// ── anchor 1: exact ordered member set + keys + scheme (no backend needed) ──
TEST(DashQuorumMembers, ReproducesDashdMemberSet)
{
    CSimplifiedMNList sml = build_kat_sml();
    auto members = compute_quorum_members(
        params_50_60(), kat_modifier(dash_qmk::kLlmqType), sml);

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

// ── anchor 1b (review R4): platform type => Evo-only member selection ───────
TEST(DashQuorumMembers, PlatformTypeEvoOnlyReproducesDashdMemberSet)
{
    CSimplifiedMNList sml = build_kat_sml();
    const uint256 mod = kat_modifier(dash_qmk::kLlmqTypePlatform);

    auto members = compute_quorum_members(params_25_67_platform(), mod, sml);
    ASSERT_TRUE(members.has_value())
        << "Evo-only selection failed on a real full SML";
    ASSERT_EQ(members->size(), dash_qmk::kExpectedMembers25.size());
    for (size_t i = 0; i < members->size(); ++i) {
        auto want_key = arr<48>(unhex(dash_qmk::kExpectedMembers25[i].pubkeyOp));
        EXPECT_EQ((*members)[i].pubKeyOperator, want_key)
            << "Evo-only member mismatch at index " << i;
    }

    // WITHOUT the Evo-only filter the platform member set is WRONG (this is
    // exactly the pre-R4 bug: permanent silent null-serve for the type).
    auto unfiltered = compute_quorum_members(
        QuorumMemberParams{dash_qmk::kLlmqTypePlatform, 25, false, false}, mod, sml);
    ASSERT_TRUE(unfiltered.has_value());
    bool same = true;
    for (size_t i = 0; i < unfiltered->size(); ++i) {
        if ((*unfiltered)[i].pubKeyOperator != (*members)[i].pubKeyOperator) {
            same = false;
            break;
        }
    }
    EXPECT_FALSE(same) << "filter made no difference — vector cannot attest R4";
}

// ── anchor 1c (review R3): DIP-4 authentication legs against real wire data ──
TEST(DashQuorumMembers, Dip4SmlRootMatchesWorkBlockCbTx)
{
    // (c) full-field SML root == cbTx.merkleRootMNList.
    CSimplifiedMNList sml = build_kat_sml();
    EXPECT_EQ(sml.CalcMerkleRoot(), u256_disp(dash_qmk::kMerkleRootMNListDisp))
        << "computed SML merkle root != real cbTx.merkleRootMNList — the "
           "DIP-4 root check would reject a GENUINE snapshot (feature inert)";

    // Tampered snapshot (one member's operator key flipped) -> root mismatch.
    {
        CSimplifiedMNList bad = sml;
        bad.mnList.at(0).pubKeyOperator[7] ^= 0x01;
        EXPECT_NE(bad.CalcMerkleRoot(), u256_disp(dash_qmk::kMerkleRootMNListDisp))
            << "tampered member set NOT caught by the SML root";
    }
}

TEST(DashQuorumMembers, Dip4CbTxMerkleProofVerifiesAgainstHeader)
{
    // Parse the real work-block header; its m_merkle_root is the trust anchor.
    dash::coin::BlockHeaderType header;
    {
        auto raw = unhex(dash_qmk::kWorkHeaderHex);
        ASSERT_EQ(raw.size(), 80u);
        PackStream s(raw);
        s >> header;
    }

    // Parse the real cbTxMerkleTree and the real cbTx.
    CPartialMerkleTreeStub pmt;
    {
        auto raw = unhex(dash_qmk::kWorkCbTxMerkleTreeHex);
        PackStream s(raw);
        s >> pmt;
    }
    dash::coin::MutableTransaction cbtx;
    {
        auto raw = unhex(dash_qmk::kWorkCbTxHex);
        PackStream s(raw);
        s >> cbtx;
    }
    ASSERT_EQ(cbtx.type, 5);

    // (b) proof root == header merkle root, single match = the cbTx at index 0.
    std::vector<uint256> matches;
    std::vector<unsigned int> idx;
    const uint256 root = pmt.ExtractMatches(matches, idx);
    EXPECT_EQ(root, header.m_merkle_root);
    ASSERT_EQ(matches.size(), 1u);
    ASSERT_EQ(idx.size(), 1u);
    EXPECT_EQ(idx[0], 0u);
    EXPECT_EQ(matches[0], dash::coin::dash_txid(cbtx));

    // (a) the cbTx payload parses and carries the expected height + the CL.
    CCbTx payload;
    ASSERT_TRUE(parse_cbtx(cbtx.extra_payload, payload));
    EXPECT_EQ(payload.nHeight, static_cast<int32_t>(dash_qmk::kWorkHeight));
    EXPECT_TRUE(payload.has_best_cl_signature());
    EXPECT_EQ(payload.bestCLSignature, arr<96>(unhex(dash_qmk::kWorkClSig)));
    EXPECT_EQ(payload.merkleRootMNList, u256_disp(dash_qmk::kMerkleRootMNListDisp));

    // Tampered proof (flip a byte of the proven hash) -> root mismatch/null.
    {
        CPartialMerkleTreeStub bad = pmt;
        ASSERT_FALSE(bad.vHash.empty());
        bad.vHash[0].data()[3] ^= 0x01;
        std::vector<uint256> m2;
        std::vector<unsigned int> i2;
        const uint256 r2 = bad.ExtractMatches(m2, i2);
        EXPECT_NE(r2, header.m_merkle_root);
    }
    // Malformed proof (truncated bits) -> ZERO (fail closed).
    {
        CPartialMerkleTreeStub bad = pmt;
        bad.vBitsBytes.clear();
        std::vector<uint256> m2;
        std::vector<unsigned int> i2;
        EXPECT_TRUE(bad.ExtractMatches(m2, i2).IsNull());
    }
}

// ── fail-closed surfaces (no backend needed) ────────────────────────────────
TEST(DashQuorumMembers, FailClosedSurfaces)
{
    CSimplifiedMNList sml = build_kat_sml();
    const uint256 mod = kat_modifier(dash_qmk::kLlmqType);

    // rotated type -> nullopt (DIP-24 quarter rotation is the qrinfo follow-up).
    EXPECT_FALSE(compute_quorum_members(
        QuorumMemberParams{5, 60, /*use_rotation=*/true, false}, mod, sml).has_value());

    // empty SML -> nullopt (cannot form the quorum).
    EXPECT_FALSE(compute_quorum_members(
        params_50_60(), mod, CSimplifiedMNList{}).has_value());

    // SML with fewer confirmed+valid MNs than params.size -> nullopt.
    {
        std::vector<CSimplifiedMNListEntry> few;
        for (size_t i = 0; i < 10 && i < dash_qmk::kSml.size(); ++i) {
            auto m = kat_entry(dash_qmk::kSml[i]);
            m.isValid = true;
            few.push_back(m);
        }
        EXPECT_FALSE(compute_quorum_members(
            params_50_60(), mod, CSimplifiedMNList(std::move(few))).has_value());
    }

    // Evo-only with too few Evo nodes -> nullopt (platform quorum cannot form).
    {
        std::vector<CSimplifiedMNListEntry> entries;
        for (const auto& e : dash_qmk::kSml) {
            auto m = kat_entry(e);
            if (m.nType == CSimplifiedMNListEntry::TYPE_EVO) continue;  // strip Evo
            entries.push_back(m);
        }
        EXPECT_FALSE(compute_quorum_members(
            params_25_67_platform(), mod,
            CSimplifiedMNList(std::move(entries))).has_value())
            << "platform selection over a no-Evo list must fail closed";
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
    auto members = compute_quorum_members(
        params_50_60(), kat_modifier(dash_qmk::kLlmqType), sml);
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

// ── anchor 2b (review R4): REAL platform (Evo-only) commitment verifies ─────
TEST(DashQuorumMembers, RealPlatformCommitmentVerifiesWithEvoOnlyMembers)
{
    ASSERT_TRUE(bls_backend_available());

    CSimplifiedMNList sml = build_kat_sml();
    const uint256 mod = kat_modifier(dash_qmk::kLlmqTypePlatform);
    auto members = compute_quorum_members(params_25_67_platform(), mod, sml);
    ASSERT_TRUE(members.has_value());
    ASSERT_EQ(members->size(), 25u);

    CFinalCommitment c;
    c.nVersion       = dash_qmk::kComm25Version;
    c.llmqType       = dash_qmk::kLlmqTypePlatform;
    c.quorumHash     = u256_disp(dash_qmk::kQuorumHashDisp);
    c.signers        = bitset_of(dash_qmk::kComm25Signers, 25);
    c.validMembers   = bitset_of(dash_qmk::kComm25ValidMembers, 25);
    c.quorumPublicKey = arr<48>(unhex(dash_qmk::kComm25QuorumPubKey));
    c.quorumVvecHash = u256_disp(dash_qmk::kComm25VvecHash);
    c.quorumSig      = arr<96>(unhex(dash_qmk::kComm25QuorumSig));
    c.membersSig     = arr<96>(unhex(dash_qmk::kComm25MembersSig));

    EXPECT_TRUE(verify_final_commitment(c, *members))
        << "REAL llmq_25_67 (platform) commitment rejected over the Evo-only "
           "member set — R4 filter not upstream-exact";

    // The unfiltered (pre-R4) member set must REJECT the real commitment —
    // demonstrating the exact silent null-serve the review flagged.
    auto unfiltered = compute_quorum_members(
        QuorumMemberParams{dash_qmk::kLlmqTypePlatform, 25, false, false}, mod, sml);
    ASSERT_TRUE(unfiltered.has_value());
    EXPECT_FALSE(verify_final_commitment(c, *unfiltered));
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
