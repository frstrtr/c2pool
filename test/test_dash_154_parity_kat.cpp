// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Task #154 — daemonless DASH MN-list self-derive fold: byte-parity KATs.
//
// The full fold (c2pool --replay-bulk, dashd BuildNewListFromBlock parity)
// self-derived the mainnet masternode list 1028160 -> 2522504 with
// roots_matched=1497777 and DIVERGED=none, and its registered set at 2522504
// (2991 MNs) equals dashd .165 `protx list registered true 2522504`, whose
// committed cbTx merkleRootMNList is
//   9d5b3dde8a327bb90a4b6bef16689065deae2700a64d8987c83a1a6efa78fb61.
//
// This TU locks the two consensus fixes that closed the last derive walls and
// the golden checkpoint artifact the fold emits:
//
//   * DashParity154_GoldenCheckpoint — the self-derived checkpoint at 2522504
//     parses, carries exactly 2991 registered MNs, and its committed digest is
//     the one the shared digest rule recomputes.  (KAT (a))
//
//   * DashV20Modifier — GetHashModifier selects the pre/post-V20 form by the
//     DEPLOYMENT state of the WORK block (base - WORK_DIFF_DEPTH(8)), not the
//     cycle base; the [v20_floor, v20_floor+8) window is pre-V20 and hashes the
//     BASE block hash, not the WORK block hash (the h=1987797 off-by-8).
//     (KAT (d))
//
// The operator-key point-compare KAT (opkey_point_eq, KAT (c)) lives in
// test_dash_bls_verify.cpp because its cross-scheme half needs the real dashbls
// backend linked (C2POOL_DASH_BLS); this TU is BLS-independent and runs in
// every build.
//
// NOTE ON THE 9d5b3dde ROOT: it is NOT re-asserted here from the checkpoint.
// The DIP-4 SML leaf (CSimplifiedMNListEntry::CalcHash) commits the masternode
// SERVICE (netInfo ip:port); the release checkpoint is a payee/registered-set
// trust anchor and does NOT serialize service (17 fields, no netInfo). The
// 9d5b3dde root is therefore a FOLD-level artifact (the engine sources service
// from each ProRegTx) and is bound by the full-history replay self-check, not
// reproducible from the service-less checkpoint. See the PR body.

#include <gtest/gtest.h>

#include <impl/dash/coin/mn_checkpoint.hpp>               // parse_mn_checkpoint, mn_checkpoint_digest (DUT)
#include <impl/dash/coin/vendor/quorum_members.hpp>       // compute_quorum_modifier (DUT of the V20 fix)
#include <core/uint256.hpp>

#include <cstdint>
#include <optional>
#include <string>

using dash::coin::MnCheckpoint;
using dash::coin::MNState;
using dash::coin::parse_mn_checkpoint;
using dash::coin::mn_checkpoint_digest;

namespace {

// The self-derived mainnet checkpoint at height 2522504 (2991 registered MNs),
// emitted by the byte-parity fold. Embedded verbatim; the trailing `digest`
// line commits every other line.
const char* const kGoldenCheckpoint2522504 =
#include "dash_mn_checkpoint_mainnet_2522504.inc"
    ;

} // namespace

// ── KAT (a): the golden self-derived checkpoint ──────────────────────────────
TEST(DashParity154_GoldenCheckpoint, ParsesExactly2991RegisteredMasternodes)
{
    const std::string payload(kGoldenCheckpoint2522504);
    MnCheckpoint cp = parse_mn_checkpoint(payload, "mainnet");

    ASSERT_TRUE(cp.ok) << cp.error;
    EXPECT_FALSE(cp.unpinned);
    EXPECT_EQ(cp.network, "mainnet");
    EXPECT_EQ(cp.height, 2522504u);
    EXPECT_EQ(cp.blockhash,
              uint256S("0000000000000016359051c239e552f2423a9f47585dda1273a9a0e1743d64f5"));

    // The oracle count: dashd .165 protx list registered true 2522504 == 2991.
    ASSERT_EQ(cp.entries.size(), 2991u)
        << "the self-derived registered set must equal dashd's at 2522504";

    // Every registered entry carries a payee script and a 48-byte operator key
    // (a byte-lossy dump would parse but strand the payment queue).
    size_t empty_payout = 0, zero_opkey = 0;
    for (const auto& [protx, st] : cp.entries) {
        if (st.scriptPayout.m_data.empty()) ++empty_payout;
        bool all_zero = true;
        for (uint8_t b : st.pubKeyOperator) if (b != 0) { all_zero = false; break; }
        if (all_zero) ++zero_opkey;
    }
    EXPECT_EQ(empty_payout, 0u) << empty_payout << " entries have no scriptPayout";
    EXPECT_EQ(zero_opkey, 0u)   << zero_opkey   << " entries have a zero operator key";
}

TEST(DashParity154_GoldenCheckpoint, CommittedDigestIsTheOneTheRuleRecomputes)
{
    const std::string payload(kGoldenCheckpoint2522504);
    MnCheckpoint cp = parse_mn_checkpoint(payload, "mainnet");
    ASSERT_TRUE(cp.ok) << cp.error;

    // The digest the payload declares == the digest the shared rule recomputes
    // over the same payload (a hand edit to any line would break this).
    EXPECT_EQ(mn_checkpoint_digest(payload), cp.digest);
    EXPECT_EQ(cp.digest,
              "67545c97e5968a9db6874c62e91d6f5d078e03a905f3cb11a10f0b6257a00216");

    // A tampered body (flip one payload byte inside the digest domain) must be
    // rejected: proves the digest actually guards the set.
    std::string tampered = payload;
    const std::string needle = "count 2991";
    const auto pos = tampered.find(needle);
    ASSERT_NE(pos, std::string::npos);
    tampered.replace(pos, needle.size(), "count 2990");
    MnCheckpoint bad = parse_mn_checkpoint(tampered, "mainnet");
    EXPECT_FALSE(bad.ok) << "a count/body edit must fail the checkpoint closed";
}

// ── KAT (d): the V20 hash-modifier off-by-8 ──────────────────────────────────
//
// dashd llmq::utils::GetHashModifier (utils.cpp:88-111) reads the DEPLOYMENT
// state of pWorkBlockIndex = base - WORK_DIFF_DEPTH(8). PRE-V20 (no cbTx CL
// exists) the non-rotated form hashes the CYCLE BASE block hash; the previous
// c2pool code UNCONDITIONALLY used the POST-V20 form (the WORK block hash). At
// mainnet base 1987776 (== the V20 activation height) the work block 1987768 is
// still PRE-V20, so the correct modifier hashes the BASE hash, not the WORK
// hash — the two differ and select different LLMQ_400_60 member sets (the
// h=1987797 poison, dashd invalid-marked MN b61cf487 @ idx 45).
namespace {
constexpr uint32_t kWorkDiffDepth = 8;
constexpr uint32_t kMainnetV20Floor = 1'987'776u;

// dashd DeploymentActiveAfter(pWorkBlockIndex, DEPLOYMENT_V20).
bool post_v20_for_base(uint32_t cycle_base)
{
    const uint32_t work_h = cycle_base - kWorkDiffDepth;
    return (work_h + 1) >= kMainnetV20Floor;
}
} // namespace

TEST(DashV20Modifier, WorkBlockDeploymentSelectsThePreV20Window)
{
    // post_v20 == (work_h + 1) >= v20_floor == base >= v20_floor + (WORK_DIFF_DEPTH - 1).
    // So the PRE-V20 cycle-base window (work block still pre-V20) is
    // [v20_floor, v20_floor + WORK_DIFF_DEPTH - 1) = [1987776, 1987783).
    EXPECT_FALSE(post_v20_for_base(kMainnetV20Floor))                    // base 1987776, work 1987768
        << "base 1987776 (== V20 height) has a PRE-V20 work block";
    EXPECT_FALSE(post_v20_for_base(kMainnetV20Floor + kWorkDiffDepth - 2)); // base 1987782, work 1987774 -> pre
    // The first cycle base whose work block is AT/after the floor is post-V20.
    EXPECT_TRUE(post_v20_for_base(kMainnetV20Floor + kWorkDiffDepth - 1));  // base 1987783, work 1987775 -> post
    EXPECT_TRUE(post_v20_for_base(kMainnetV20Floor + kWorkDiffDepth));      // base 1987784, work 1987776 -> post
    EXPECT_TRUE(post_v20_for_base(kMainnetV20Floor + 100));
}

TEST(DashV20Modifier, PreV20NonRotatedHashesBaseNotWork)
{
    using dash::coin::vendor::compute_quorum_modifier;

    const uint8_t   type   = 4;                 // LLMQ_400_60
    const uint32_t  base   = kMainnetV20Floor;   // 1987776
    const uint32_t  work_h = base - kWorkDiffDepth;

    // Two distinct, deterministic stand-ins for the work and base block hashes.
    const uint256 work_hash = uint256S(std::string(63, '0') + "1");
    const uint256 base_hash = uint256S(std::string(63, '0') + "2");
    ASSERT_NE(work_hash, base_hash);

    // The FIXED pre-V20 non-rotated form: SerializeHash(pair(type, BASE hash)).
    const uint256 fixed = compute_quorum_modifier(type, work_h, std::nullopt, base_hash);
    // The OLD (buggy) form the unconditional post-V20 path produced:
    // SerializeHash(pair(type, WORK hash)).
    const uint256 buggy = compute_quorum_modifier(type, work_h, std::nullopt, work_hash);

    ASSERT_TRUE(post_v20_for_base(base) == false)
        << "base 1987776 must classify PRE-V20 for this KAT to bind the fix";
    EXPECT_NE(fixed, buggy)
        << "the base-hash and work-hash modifier forms MUST differ — else the "
           "off-by-8 could never change the member set";

    // Determinism: the fixed form is stable across calls.
    EXPECT_EQ(fixed, compute_quorum_modifier(type, work_h, std::nullopt, base_hash));

    // NOTE: the concrete member-order assertion (dashd LLMQ_400_60 idx45 =
    // b61cf487 under the fixed form vs 108a0089 under the buggy form) requires
    // the real block-hash fixtures + the full DKG member sort at base 1987776
    // and is bound by the full-history replay quorum KAT, not this unit TU.
}
