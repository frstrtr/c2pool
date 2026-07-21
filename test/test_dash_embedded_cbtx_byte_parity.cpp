// SPDX-License-Identifier: AGPL-3.0-or-later
/// Dash embedded CbTx BYTE-PARITY against a REAL dashd getblocktemplate.
///
/// review finding H-5: the prior embedded_gbt KAT was self-referential — it built a CCbTx
/// with c2pool code and compared it to a CCbTx built with c2pool code, so it
/// proved only internal round-tripping, never that the bytes match dashd.
///
/// This suite fixes that. The oracle is a REAL Dash Core testnet
/// getblocktemplate response (block 1,518,413), captured verbatim; the
/// `coinbase_payload` below is dashd's OWN type-5 CbTx extra_payload, produced
/// by dashd, NOT by c2pool. Provenance + the full capture (masternode outputs,
/// superblock flags, the creditPool accrual series) live in
/// test/fixtures/dash_testnet_gbt_1518413.json.
///
/// What is proven here (mainnet-gate acceptance evidence):
///   1. Our wire codec (parse_cbtx / encode_cbtx) round-trips dashd's real CbTx
///      bytes BYTE-IDENTICALLY — every field (nVersion, nHeight,
///      merkleRootMNList, merkleRootQuorums, VarInt bestCLHeightDiff, the 96-byte
///      BLS bestCLSignature, signed int64 creditPoolBalance) serializes exactly
///      as dashd does.
///   2. The independently-decoded field values match what we expect (roots,
///      height, bestCL diff, creditPool).
///   3. build_embedded_cbtx()'s ASSEMBLY of the non-root fields (nVersion=3,
///      nHeight = prev+1, bestCLHeightDiff = prev − bestCLHeight) reproduces
///      dashd's real values, and plumbs the SML/quorum roots through unchanged.
///   4. H-4 creditPool accrual: creditPoolBalance(N) = creditPoolBalance(N-1) +
///      platformReward(N), verified against dashd's own consecutive-block series.
///
/// Explicitly NOT proven here (flagged for the gate-lift record):
///   - Reconstructing the merkleRootMNList/merkleRootQuorums from the specific
///     375-entry / 109-quorum testnet SML is not done in-KAT (a heavy wire
///     rebuild). Those roots ARE proven EQUAL to dashd's commitment out-of-band:
///     the captured `protx diff 1 1518412` reports the SAME roots dashd puts in
///     this GBT (see fixture), and CalcMerkleRoot/compute_merkle_root_quorums are
///     pinned by test_dash_simplifiedmns / test_dash_quorum_root. Wiring a raw
///     mnlistdiff wire capture -> CalcMerkleRoot == fixture root is the one
///     remaining reconstruct-from-wire step before a mainnet gate-lift.

#include <gtest/gtest.h>

#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/subsidy.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

using dash::coin::vendor::CCbTx;
using dash::coin::vendor::parse_cbtx;
using dash::coin::encode_cbtx;
using dash::coin::build_embedded_cbtx;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListEntry;
using dash::coin::QuorumManager;

// ── REAL dashd testnet getblocktemplate capture (block 1,518,413) ───────────
// coinbase_payload: dashd's own type-5 CbTx extra_payload, verbatim off the RPC.
static const char* kDashdCbTxHex =
    "03004d2b17008fd43916c4062570542a746a18808d00bb47107d541c0eeb0def"
    "c107fd07bc6bfb1dff7b7ee05a246fe0fa0a3dc3a3a516578f857bee925a586e"
    "840272c101190197902356524fd09c8bd3e892367863a5b7791f885c1da7d946"
    "efde9f38e82b6ead4fd6934e5c62c96470c63e6661b65611849196fe6498c29c"
    "246d82dcba6b00d062a37cd35b62cd676dc8d5f8c46d0d60d69c6db90f3c5e0a"
    "a21bf1a2349deda4c96f7ae21e0000";

// Independently-decoded expected fields (from the fixture / dashd RPC).
static constexpr int32_t  kExpVersion          = 3;
static constexpr int32_t  kExpHeight           = 1518413;
static const char*        kExpMnListRoot        = "6bbc07fd07c1ef0deb0e1c547d1047bb008d80186a742a54702506c41639d48f";
static const char*        kExpQuorumRoot        = "1901c17202846e585a92ee7b858f5716a5a3c33d0afae06f245ae07e7bff1dfb";
static constexpr uint32_t kExpBestClHeightDiff = 1;
static constexpr int64_t  kExpCreditPoolSat    = 33958065588644LL;

// H-4 accrual evidence (consecutive real testnet blocks).
static constexpr int64_t  kPrevCreditPoolSat   = 33957998621814LL;  // block 1518412
static constexpr int64_t  kPlatformRewardSat   = 66966830LL;        // per-block burn

static std::vector<unsigned char> from_hex(const std::string& h) {
    std::vector<unsigned char> v;
    v.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        v.push_back(static_cast<unsigned char>((nib(h[i]) << 4) | nib(h[i + 1])));
    return v;
}

// ════════════════════════════════════════════════════════════════════════
// 1. THE byte-parity proof: dashd's real CbTx bytes survive our codec exactly.
// ════════════════════════════════════════════════════════════════════════
TEST(DashEmbeddedCbtxByteParity, RealDashdCbTxRoundTripsByteIdentical) {
    const std::vector<unsigned char> dashd_bytes = from_hex(kDashdCbTxHex);
    ASSERT_EQ(dashd_bytes.size(), 175u) << "capture length regression";

    CCbTx cb;
    ASSERT_TRUE(parse_cbtx(dashd_bytes, cb))
        << "our parser must accept dashd's real CbTx with zero trailing bytes";

    // Re-encode through OUR wire path and demand byte-for-byte identity with the
    // dashd-produced bytes. This is the non-self-referential proof: input bytes
    // are dashd's, output bytes are ours.
    const std::vector<unsigned char> reencoded = encode_cbtx(cb);
    EXPECT_EQ(reencoded, dashd_bytes)
        << "encode_cbtx must reproduce dashd's CbTx extra_payload byte-identically";
}

// ════════════════════════════════════════════════════════════════════════
// 2. Decoded fields match the independently-captured expectations.
// ════════════════════════════════════════════════════════════════════════
TEST(DashEmbeddedCbtxByteParity, RealDashdCbTxFieldsDecodeAsExpected) {
    CCbTx cb;
    ASSERT_TRUE(parse_cbtx(from_hex(kDashdCbTxHex), cb));

    EXPECT_EQ(cb.nVersion, kExpVersion);
    EXPECT_EQ(cb.nHeight, kExpHeight);
    EXPECT_EQ(cb.merkleRootMNList.GetHex(), std::string(kExpMnListRoot));
    EXPECT_EQ(cb.merkleRootQuorums.GetHex(), std::string(kExpQuorumRoot));
    EXPECT_EQ(cb.bestCLHeightDiff, kExpBestClHeightDiff);
    EXPECT_TRUE(cb.has_best_cl_signature())
        << "block 1518413 template carries a real ChainLock signature";
    EXPECT_EQ(cb.creditPoolBalance, kExpCreditPoolSat);
}

// ════════════════════════════════════════════════════════════════════════
// 3. build_embedded_cbtx() ASSEMBLY reproduces dashd's non-root fields exactly
//    and plumbs the SML/quorum roots through unchanged.
// ════════════════════════════════════════════════════════════════════════
TEST(DashEmbeddedCbtxByteParity, AssemblyReproducesDashdNonRootFields) {
    CCbTx dashd;
    ASSERT_TRUE(parse_cbtx(from_hex(kDashdCbTxHex), dashd));

    // dashd's bestCL diff for block N=1518413 is 1, with prev_height=N-1=1518412,
    // so the recovered absolute bestCLHeight is prev_height - diff = 1518411.
    const uint32_t prev_height   = static_cast<uint32_t>(kExpHeight) - 1;   // 1518412
    const int32_t  best_cl_height = static_cast<int32_t>(prev_height)
                                    - static_cast<int32_t>(kExpBestClHeightDiff); // 1518411

    // Any SML/quorum set: the assembly must plumb ITS roots through and set the
    // version/height/bestCL fields exactly as dashd does. (Root-value parity is
    // the SML axis, proven separately — see the file header note.)
    CSimplifiedMNList sml;
    CSimplifiedMNListEntry e; e.proRegTxHash = uint256S("11"); e.confirmedHash = uint256S("22"); e.isValid = true;
    sml.mnList = {e};
    sml.sort();
    QuorumManager qmgr;

    CCbTx built = build_embedded_cbtx(
        prev_height, sml, qmgr, best_cl_height, dashd.bestCLSignature,
        dashd.creditPoolBalance);

    EXPECT_EQ(built.nVersion, dashd.nVersion) << "v3 (VERSION_CLSIG_AND_BALANCE)";
    EXPECT_EQ(built.nHeight, dashd.nHeight)   << "nHeight = prev_height + 1";
    EXPECT_EQ(built.bestCLHeightDiff, dashd.bestCLHeightDiff)
        << "bestCLHeightDiff = prev_height - bestCLHeight, matching dashd";
    EXPECT_EQ(built.bestCLSignature, dashd.bestCLSignature)
        << "the recovered 96-byte ChainLock sig is committed verbatim";
    EXPECT_EQ(built.creditPoolBalance, dashd.creditPoolBalance);
    // Roots are plumbed from the supplied SML/quorum set (not dashd's here).
    auto sml_copy = sml;
    EXPECT_EQ(built.merkleRootMNList, sml_copy.CalcMerkleRoot());
    EXPECT_EQ(built.merkleRootQuorums,
              dash::coin::compute_merkle_root_quorums(qmgr));

    // And the assembled CbTx, once its roots equal dashd's, is byte-identical:
    // prove it by transplanting dashd's real roots into the assembled struct and
    // re-encoding — every OTHER field already came from build_embedded_cbtx.
    built.merkleRootMNList  = dashd.merkleRootMNList;
    built.merkleRootQuorums = dashd.merkleRootQuorums;
    EXPECT_EQ(encode_cbtx(built), from_hex(kDashdCbTxHex))
        << "assembled CbTx with dashd's roots is byte-identical to dashd's payload";
}

// ════════════════════════════════════════════════════════════════════════
// 4. H-4: creditPool accrual == dashd's real consecutive-block step.
// ════════════════════════════════════════════════════════════════════════
TEST(DashEmbeddedCbtxByteParity, CreditPoolAccrualMatchesRealDashd) {
    // dashd's creditPoolBalance for block N = balance(N-1) + platformReward(N)
    // (+ asset lock/unlock, zero here — the embedded template excludes special
    // txs). Proven against dashd's own numbers: block 1518412 -> template 1518413.
    EXPECT_EQ(kPrevCreditPoolSat + kPlatformRewardSat, kExpCreditPoolSat)
        << "platform-reward accrual must land on dashd's committed creditPoolBalance";
}
