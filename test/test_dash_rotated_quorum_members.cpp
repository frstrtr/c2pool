// SPDX-License-Identifier: AGPL-3.0-or-later
//
// DIP-0024 rotated-quorum member-set computation (items 3+4): the ORDER gate.
//
// WHY ORDER IS THE GATE
// ---------------------
// A member's INDEX in the returned vector selects its slot in the
// commitment's signers/validMembers bitsets and in the membersSig aggregate.
// A member set that is correct as a SET but wrong as a SEQUENCE verifies
// nothing and, served, produces a bad-qc block. So every assertion below that
// matters compares the ORDERED key sequence, and there is an explicit
// permutation control proving the comparison is order-sensitive.
//
// GROUND TRUTH
// ------------
// test/data/dash_rotated_quorum_members_kat.hpp — dashd's own ordered 60-member
// llmq_60_75 set for quorumIndex 0 at cycle base 1520064 (testnet), captured
// read-only via `quorum info 5 <quorumHash> false`. All 60 operator keys in it
// are DISTINCT, so equality of the key sequence IS equality of the member
// sequence. The inputs come from the same real 602'189-byte qrinfo fixture the
// item-1/2 suite pins (test/fixtures/dash_testnet_qrinfo_1520064.bin), through
// the same DIP-4 authentication.
//
// WHAT THIS SUITE DOES *NOT* ESTABLISH
// ------------------------------------
// At cycle 1520064 the testnet MN list is 371 entries of which only 85 are
// PoSe-valid, and ALL 85 are marked active in every one of the three cycle
// snapshots. The "unused MNs first, then already-used MNs" concatenation in
// GetQuorumQuarterMembersBySnapshot / BuildNewQuorumQuarterMembers is therefore
// DEGENERATE on this vector — swapping the two halves changes nothing, on any
// of the 32 slots. That leg is pinned separately below by a synthetic
// non-degenerate case (UsedMasternodesSortToTheEnd), which is derived from the
// upstream algorithm, not from this implementation. It is called out here
// because a reader could otherwise assume the real vector covers it.

#include <gtest/gtest.h>

#include <impl/dash/coin/quorum_member_source.hpp>
#include <impl/dash/coin/vendor/quorum_members_rotated.hpp>
#include <impl/dash/coin/vendor/quorum_rotation_info.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/smldiff.hpp>

#include "data/dash_rotated_quorum_members_kat.hpp"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <vector>

using dash::coin::QuorumMemberSource;
using dash::coin::LlmqNetwork;
using dash::coin::vendor::CQuorumRotationInfo;
using dash::coin::vendor::CQuorumSnapshot;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListEntry;
using dash::coin::vendor::CSimplifiedMNListDiff;
using dash::coin::vendor::MemberOperatorKey;
using dash::coin::vendor::RotatedCycleInput;
using dash::coin::vendor::RotatedQuorumParams;
using dash::coin::vendor::compute_quorum_members_by_quarter_rotation;
using dash::coin::vendor::decode_quorum_rotation_info;

namespace {

constexpr uint32_t kCycleBase = 1520064;   // llmq_60_75 cycle base
constexpr uint32_t kWorkDepth = 8;
constexpr uint32_t kC         = 288;       // llmq_60_75 dkgInterval
constexpr uint8_t  kType      = 5;         // LLMQ_60_75
constexpr size_t   kNQuorums  = 32;        // signingActiveQuorumCount
constexpr size_t   kQuorumSz  = 60;

std::string hex48(const std::array<uint8_t, 48>& k)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(96);
    for (uint8_t b : k) { s.push_back(d[b >> 4]); s.push_back(d[b & 0xf]); }
    return s;
}

std::vector<unsigned char> read_fixture()
{
    const std::string path =
        std::string(DASH_FIXTURE_DIR) + "/dash_testnet_qrinfo_1520064.bin";
    std::ifstream f(path, std::ios::binary);
    EXPECT_TRUE(f.good()) << "cannot open fixture: " << path;
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(f),
                                      std::istreambuf_iterator<char>());
}

/// The real cycle inputs, built the way quorum_member_source does: the four
/// authenticated cycle SMLs plus the modifier each cycle base implies (post-V20
/// SHA256d over (type, workHeight, bestCLSignature) from that work block's OWN
/// cbTx). Kept in one struct so the SMLs outlive the pointers into them.
struct RealInputs {
    CQuorumRotationInfo               info;
    std::array<CSimplifiedMNList, 4>  smls;
    std::array<RotatedCycleInput, 4>  cycles;
    std::array<const CQuorumSnapshot*, 3> snaps{};

    bool load()
    {
        auto bytes = read_fixture();
        if (!decode_quorum_rotation_info(bytes, info)) return false;
        const CSimplifiedMNListDiff* diffs[4] = {
            &info.mnListDiffH, &info.mnListDiffAtHMinusC,
            &info.mnListDiffAtHMinus2C, &info.mnListDiffAtHMinus3C};
        for (size_t i = 0; i < 4; ++i) {
            dash::coin::vendor::apply_diff(smls[i], *diffs[i]);
            dash::coin::vendor::CCbTx cb;
            if (!dash::coin::vendor::parse_cbtx(diffs[i]->cbTx.extra_payload, cb))
                return false;
            // The SML we just rebuilt must be the list that block committed to
            // — the same leg (c) the authentication path checks.
            if (smls[i].CalcMerkleRoot() != cb.merkleRootMNList) return false;
            std::optional<std::array<
                uint8_t, dash::coin::vendor::CFinalCommitment::BLS_SIG_SIZE>> cl;
            if (cb.nVersion >= dash::coin::vendor::CCbTx::VERSION_CLSIG_AND_BALANCE
                && cb.has_best_cl_signature()) {
                cl = cb.bestCLSignature;
            }
            cycles[i].sml      = &smls[i];
            cycles[i].modifier = dash::coin::vendor::compute_quorum_modifier(
                kType, static_cast<uint32_t>(cb.nHeight), cl, diffs[i]->blockHash);
        }
        snaps = {&info.quorumSnapshotAtHMinusC,
                 &info.quorumSnapshotAtHMinus2C,
                 &info.quorumSnapshotAtHMinus3C};
        return true;
    }
};

std::vector<std::string> kat_key_sequence()
{
    std::vector<std::string> v;
    for (const auto& m : dash::coin::testdata::rotated_6075_members())
        v.emplace_back(m.pub_key_operator);
    return v;
}

std::vector<std::string> key_sequence(const std::vector<MemberOperatorKey>& v)
{
    std::vector<std::string> out;
    out.reserve(v.size());
    for (const auto& k : v) out.push_back(hex48(k.pubKeyOperator));
    return out;
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// THE ORDERING GATE
// ═══════════════════════════════════════════════════════════════════════════

// dashd's exact ordered 60-member vector for llmq_60_75 quorumIndex 0 at cycle
// base 1520064, reproduced from qrinfo alone. Index-by-index, not as a set.
TEST(DashRotatedQuorumMembers, ReproducesDashdMemberORDERForQuorumIndexZero)
{
    RealInputs in;
    ASSERT_TRUE(in.load()) << "fixture must decode and authenticate";

    RotatedQuorumParams p{kType, kQuorumSz, kNQuorums};
    auto sets = compute_quorum_members_by_quarter_rotation(p, in.cycles, in.snaps);
    ASSERT_TRUE(sets.has_value())
        << "the quarter rotation must not fail closed on a genuine cycle";
    ASSERT_EQ(sets->size(), kNQuorums);

    const auto want = kat_key_sequence();
    ASSERT_EQ(want.size(), dash::coin::testdata::kRot6075_MemberCount);
    const auto got = key_sequence((*sets)[dash::coin::testdata::kRot6075_QuorumIndex]);
    ASSERT_EQ(got.size(), want.size());

    // Index-by-index so a failure names the slot that diverged.
    for (size_t i = 0; i < want.size(); ++i) {
        EXPECT_EQ(got[i], want[i])
            << "member INDEX " << i << " diverges from dashd; member index is "
               "the signers/validMembers bitset slot, so this is consensus";
    }
    EXPECT_EQ(got, want);
}

// The control that makes the assertion above a real ORDER gate: the SAME set
// in a different order must NOT compare equal. Without this, a set-equality
// bug in the test itself would go unnoticed.
TEST(DashRotatedQuorumMembers, TheOrderAssertionRejectsAPermutationOfTheSameSet)
{
    RealInputs in;
    ASSERT_TRUE(in.load());
    RotatedQuorumParams p{kType, kQuorumSz, kNQuorums};
    auto sets = compute_quorum_members_by_quarter_rotation(p, in.cycles, in.snaps);
    ASSERT_TRUE(sets.has_value());

    const auto want = kat_key_sequence();
    auto permuted = key_sequence((*sets)[0]);
    ASSERT_EQ(permuted, want);

    // Same multiset, different sequence.
    std::swap(permuted[0], permuted[1]);
    EXPECT_NE(permuted, want) << "a swap of two members must RED the gate";

    std::vector<std::string> a = permuted, b = want;
    std::sort(a.begin(), a.end());
    std::sort(b.begin(), b.end());
    EXPECT_EQ(a, b) << "…while remaining the identical SET — which is exactly "
                       "what a membership-only test would have accepted";

    // Reversal is the strongest permutation control.
    auto reversed = key_sequence((*sets)[0]);
    std::reverse(reversed.begin(), reversed.end());
    EXPECT_NE(reversed, want);
}

// All 60 KAT keys are distinct, so key-sequence equality IS member-sequence
// equality. Asserted rather than assumed.
TEST(DashRotatedQuorumMembers, KatKeysAreDistinctSoKeyOrderIsMemberOrder)
{
    const auto want = kat_key_sequence();
    std::set<std::string> uniq(want.begin(), want.end());
    EXPECT_EQ(uniq.size(), want.size());

    std::set<std::string> protx;
    for (const auto& m : dash::coin::testdata::rotated_6075_members())
        protx.insert(m.pro_tx_hash);
    EXPECT_EQ(protx.size(), want.size());
}

// One qrinfo yields the WHOLE cycle: 32 slots, each exactly quorum size.
TEST(DashRotatedQuorumMembers, AllThirtyTwoRotatedSlotsAreFullWidth)
{
    RealInputs in;
    ASSERT_TRUE(in.load());
    RotatedQuorumParams p{kType, kQuorumSz, kNQuorums};
    auto sets = compute_quorum_members_by_quarter_rotation(p, in.cycles, in.snaps);
    ASSERT_TRUE(sets.has_value());
    ASSERT_EQ(sets->size(), kNQuorums);
    for (size_t i = 0; i < sets->size(); ++i) {
        EXPECT_EQ((*sets)[i].size(), kQuorumSz) << "slot " << i;
        for (const auto& k : (*sets)[i]) {
            bool all_zero = true;
            for (uint8_t b : k.pubKeyOperator) if (b) { all_zero = false; break; }
            EXPECT_FALSE(all_zero) << "slot " << i << " carries a zero key";
        }
    }
}

// The quarter geometry is observable in the output: members 0..14 come from the
// H-3C cycle, 15..29 from H-2C, 30..44 from H-C, 45..59 are new at H. Pinning
// the boundary catches a quarter-order regression even without the KAT.
TEST(DashRotatedQuorumMembers, QuarterBoundariesMatchTheOldestFirstAssembly)
{
    RealInputs in;
    ASSERT_TRUE(in.load());
    RotatedQuorumParams p{kType, kQuorumSz, kNQuorums};
    auto sets = compute_quorum_members_by_quarter_rotation(p, in.cycles, in.snaps);
    ASSERT_TRUE(sets.has_value());

    const size_t quarter = kQuorumSz / 4;
    // Recompute the OLDEST quarter on its own and require it to be the HEAD of
    // the assembled quorum (upstream iterates the previous cycles reversed).
    auto oldest = dash::coin::vendor::detail::get_quorum_quarter_members_by_snapshot(
        kNQuorums, quarter, *in.cycles[3].sml, in.cycles[3].modifier, *in.snaps[2]);
    ASSERT_TRUE(oldest.has_value());
    ASSERT_EQ((*oldest)[0].size(), quarter);
    for (size_t i = 0; i < quarter; ++i) {
        EXPECT_EQ(hex48((*sets)[0][i].pubKeyOperator),
                  hex48((*oldest)[0][i]->pubKeyOperator))
            << "member " << i << " must come from the H-3C quarter";
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FAIL-CLOSED
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashRotatedQuorumMembers, ShortSnapshotBitsetFailsClosed)
{
    RealInputs in;
    ASSERT_TRUE(in.load());
    // A peer trimming the bitset would make upstream read out of bounds; here
    // it must simply refuse.
    CQuorumSnapshot trimmed = in.info.quorumSnapshotAtHMinusC;
    trimmed.activeQuorumMembers.resize(10);
    std::array<const CQuorumSnapshot*, 3> snaps = in.snaps;
    snaps[0] = &trimmed;

    RotatedQuorumParams p{kType, kQuorumSz, kNQuorums};
    EXPECT_FALSE(compute_quorum_members_by_quarter_rotation(p, in.cycles, snaps)
                     .has_value());
}

TEST(DashRotatedQuorumMembers, AllSkippedSnapshotYieldsAShortQuorumAndFailsClosed)
{
    RealInputs in;
    ASSERT_TRUE(in.load());
    CQuorumSnapshot allskip = in.info.quorumSnapshotAtHMinus2C;
    allskip.mnSkipListMode = CQuorumSnapshot::MODE_ALL_SKIPPED;
    std::array<const CQuorumSnapshot*, 3> snaps = in.snaps;
    snaps[1] = &allskip;

    RotatedQuorumParams p{kType, kQuorumSz, kNQuorums};
    EXPECT_FALSE(compute_quorum_members_by_quarter_rotation(p, in.cycles, snaps)
                     .has_value())
        << "a quarter we cannot reconstruct must never be served short";
}

TEST(DashRotatedQuorumMembers, MissingCycleInputFailsClosed)
{
    RealInputs in;
    ASSERT_TRUE(in.load());
    auto cycles = in.cycles;
    cycles[2].sml = nullptr;
    RotatedQuorumParams p{kType, kQuorumSz, kNQuorums};
    EXPECT_FALSE(compute_quorum_members_by_quarter_rotation(p, cycles, in.snaps)
                     .has_value());
}

TEST(DashRotatedQuorumMembers, WrongModifierProducesADifferentOrderNotASilentPass)
{
    RealInputs in;
    ASSERT_TRUE(in.load());
    auto cycles = in.cycles;
    // Reuse cycle 0's modifier for every cycle — the mistake a port that
    // forgot GetHashModifier is per-cycle-base would make.
    for (auto& c : cycles) c.modifier = in.cycles[0].modifier;
    RotatedQuorumParams p{kType, kQuorumSz, kNQuorums};
    auto sets = compute_quorum_members_by_quarter_rotation(p, cycles, in.snaps);
    ASSERT_TRUE(sets.has_value());
    EXPECT_NE(key_sequence((*sets)[0]), kat_key_sequence())
        << "the per-cycle modifier must be load-bearing";
}

// Upstream breaks a score tie by collateralOutpoint, which an SML cannot carry.
// Two MNs with identical (proRegTxHash, confirmedHash) score identically, and
// the sort order between them is then not reproducible — refuse.
TEST(DashRotatedQuorumMembers, ScoreTieFailsClosed)
{
    CSimplifiedMNListEntry a;
    a.nVersion = CSimplifiedMNListEntry::VER_BASIC_BLS;
    a.proRegTxHash.SetHex(
        "1111111111111111111111111111111111111111111111111111111111111111");
    a.confirmedHash.SetHex(
        "2222222222222222222222222222222222222222222222222222222222222222");
    a.isValid = true;
    a.pubKeyOperator[0] = 0xaa;
    CSimplifiedMNListEntry b = a;
    b.pubKeyOperator[0] = 0xbb;   // same score inputs, different key

    std::vector<const CSimplifiedMNListEntry*> cands{&a, &b};
    uint256 modifier;
    modifier.SetHex(
        "3333333333333333333333333333333333333333333333333333333333333333");
    EXPECT_FALSE(
        dash::coin::vendor::detail::calculate_quorum_all(cands, modifier)
            .has_value());
}

// ═══════════════════════════════════════════════════════════════════════════
// The leg the real vector CANNOT discriminate (see the header note): the
// snapshot replay must place ALREADY-USED masternodes at the END of the
// combined list, after every unused one, whatever their score.
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashRotatedQuorumMembers, UsedMasternodesSortToTheEnd)
{
    // 8 synthetic MNs, all eligible, all distinct.
    const size_t kN = 8;
    std::vector<CSimplifiedMNListEntry> entries(kN);
    for (size_t i = 0; i < kN; ++i) {
        auto& e = entries[i];
        e.nVersion = CSimplifiedMNListEntry::VER_BASIC_BLS;
        std::string h(64, '0');
        h[63] = static_cast<char>('1' + i);
        e.proRegTxHash.SetHex(h);
        h[62] = '7';
        e.confirmedHash.SetHex(h);
        e.isValid = true;
        e.pubKeyOperator[0] = static_cast<uint8_t>(0x10 + i);
    }
    CSimplifiedMNList sml(std::move(entries));
    ASSERT_EQ(sml.mnList.size(), kN);

    uint256 modifier;
    modifier.SetHex(
        "4444444444444444444444444444444444444444444444444444444444444444");

    // The score-sorted list, with nothing marked used, is the control.
    CQuorumSnapshot none;
    none.mnSkipListMode = CQuorumSnapshot::MODE_NO_SKIPPING;
    none.activeQuorumMembers.assign(kN, false);
    auto ctrl = dash::coin::vendor::detail::get_quorum_quarter_members_by_snapshot(
        /*num_quorums=*/1, /*quarter_size=*/kN, sml, modifier, none);
    ASSERT_TRUE(ctrl.has_value());
    ASSERT_EQ((*ctrl)[0].size(), kN);

    // For EVERY choice of a single already-used MN, that MN must land LAST —
    // regardless of where its score would otherwise have put it. This is the
    // upstream rule ("the list begins with all the unused MNs", then the used
    // ones are appended), asserted without reference to this implementation's
    // own ordering.
    for (size_t used = 0; used < kN; ++used) {
        // Which sorted position does this MN occupy in the control?
        size_t ctrl_pos = kN;
        for (size_t j = 0; j < kN; ++j)
            if ((*ctrl)[0][j] == &sml.mnList[used]) { ctrl_pos = j; break; }
        ASSERT_LT(ctrl_pos, kN);

        CQuorumSnapshot snap;
        snap.mnSkipListMode = CQuorumSnapshot::MODE_NO_SKIPPING;
        snap.activeQuorumMembers.assign(kN, false);
        // activeQuorumMembers is indexed over the SCORE-SORTED list, not the
        // SML order — that indexing is itself part of the contract.
        snap.activeQuorumMembers[ctrl_pos] = true;

        auto q = dash::coin::vendor::detail::get_quorum_quarter_members_by_snapshot(
            1, kN, sml, modifier, snap);
        ASSERT_TRUE(q.has_value()) << "used=" << used;
        ASSERT_EQ((*q)[0].size(), kN);
        EXPECT_EQ((*q)[0][kN - 1], &sml.mnList[used])
            << "an already-used MN must be appended AFTER every unused one "
               "(used=" << used << ", control position " << ctrl_pos << ")";
        // …and the unused ones keep their relative score order.
        size_t k = 0;
        for (size_t j = 0; j < kN; ++j) {
            if ((*ctrl)[0][j] == &sml.mnList[used]) continue;
            EXPECT_EQ((*q)[0][k], (*ctrl)[0][j]) << "used=" << used << " j=" << j;
            ++k;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ITEM 4 — end to end through QuorumMemberSource: an authenticated qrinfo makes
// lookup() serve the rotated quorum, in dashd's order.
// ═══════════════════════════════════════════════════════════════════════════

namespace {

uint256 slot_hash(uint32_t qi)
{
    // Synthetic per-index base-block hashes. The fixture cannot carry them
    // (they are the blocks at cycleBase+1..+31), and only index 0's hash is
    // consensus-known here — it is the cycle base itself.
    uint256 h;
    std::string s(64, '0');
    s[0] = 'e'; s[1] = 'e';
    s[62] = "0123456789abcdef"[(qi >> 4) & 0xf];
    s[63] = "0123456789abcdef"[qi & 0xf];
    h.SetHex(s);
    return h;
}

struct SourceHarness {
    CQuorumRotationInfo info;
    std::map<uint256, uint256> roots;
    std::map<uint32_t, uint256> by_height;
    int sends{0};

    void load()
    {
        auto bytes = read_fixture();
        ASSERT_TRUE(decode_quorum_rotation_info(bytes, info));
        for (const CSimplifiedMNListDiff* d :
             {&info.mnListDiffH, &info.mnListDiffAtHMinusC,
              &info.mnListDiffAtHMinus2C, &info.mnListDiffAtHMinus3C}) {
            std::vector<uint256>      m;
            std::vector<unsigned int> idx;
            roots[d->blockHash] = d->cbTxMerkleTree.ExtractMatches(m, idx);
        }
        uint256 cycle;
        cycle.SetHex(dash::coin::testdata::kRot6075_QuorumHash);
        by_height[kCycleBase] = cycle;              // quorumIndex 0
        for (uint32_t qi = 1; qi < kNQuorums; ++qi)
            by_height[kCycleBase + qi] = slot_hash(qi);
    }

    QuorumMemberSource make()
    {
        QuorumMemberSource src(
            LlmqNetwork::Testnet,
            [this](uint32_t h) -> std::optional<uint256> {
                auto it = by_height.find(h);
                if (it == by_height.end()) return std::nullopt;
                return it->second;
            },
            [this](const uint256& qh) -> std::optional<uint32_t> {
                for (const auto& [h, hash] : by_height)
                    if (hash == qh) return h;
                return std::nullopt;
            },
            [this](const uint256& h) -> std::optional<uint256> {
                auto it = roots.find(h);
                if (it == roots.end()) return std::nullopt;
                return it->second;
            },
            [](const uint256&, const uint256&) {});
        src.set_send_getqrinfo(
            [this](const std::vector<uint256>&, const uint256&, bool) { ++sends; });
        return src;
    }
};

} // namespace

TEST(DashRotatedQuorumMembers, LookupServesTheRotatedQuorumInDashdOrder)
{
    SourceHarness h;
    h.load();
    auto src = h.make();

    uint256 cycle;
    cycle.SetHex(dash::coin::testdata::kRot6075_QuorumHash);
    ASSERT_TRUE(src.request_rotated(kType, cycle));
    ASSERT_EQ(h.sends, 1);

    ASSERT_TRUE(src.on_qrinfo(h.info).has_value());
    EXPECT_EQ(src.rotated_pending_count(), 0u);
    // One reply, the whole cycle.
    EXPECT_EQ(src.ready_count(), kNQuorums);

    auto members = src.lookup(kType, cycle);
    ASSERT_TRUE(members.has_value())
        << "item 4: an authenticated qrinfo must make the rotated quorum "
           "serveable";
    EXPECT_EQ(key_sequence(*members), kat_key_sequence());

    // Every other slot of the cycle is served too, at full width.
    for (uint32_t qi = 1; qi < kNQuorums; ++qi) {
        auto m = src.lookup(kType, slot_hash(qi));
        ASSERT_TRUE(m.has_value()) << "slot " << qi;
        EXPECT_EQ(m->size(), kQuorumSz) << "slot " << qi;
    }
}

// request() is the entry point the qfcommit feed calls, with the quorum's OWN
// hash — NOT the cycle base. It must derive the cycle (quorumIndex = height %
// dkgInterval) and emit exactly one getqrinfo for the whole cycle.
TEST(DashRotatedQuorumMembers, RequestDerivesTheCycleBaseAndDedupesAcrossSlots)
{
    SourceHarness h;
    h.load();
    auto src = h.make();

    // Ask for a MID-CYCLE slot first.
    src.request(kType, slot_hash(7));
    EXPECT_EQ(h.sends, 1) << "a rotated request must now actually emit a getqrinfo";
    EXPECT_EQ(src.rotated_pending_count(), 1u);

    // Every other slot of the same cycle rides the outstanding request.
    for (uint32_t qi = 0; qi < kNQuorums; ++qi) {
        uint256 qh = (qi == 0) ? h.by_height[kCycleBase] : slot_hash(qi);
        src.request(kType, qh);
    }
    EXPECT_EQ(h.sends, 1) << "32 slots must share ONE 600 kB qrinfo, not 32";
    EXPECT_EQ(src.rotated_pending_count(), 1u);

    ASSERT_TRUE(src.on_qrinfo(h.info).has_value());
    EXPECT_EQ(src.ready_count(), kNQuorums);

    // A ready cycle is not re-requested.
    src.request(kType, slot_hash(7));
    EXPECT_EQ(h.sends, 1);
}

// Without a send seam wired there is no rotated traffic at all and every slot
// stays null-serve — the pre-item-4 posture, still reachable.
TEST(DashRotatedQuorumMembers, NoSendSeamMeansNoTrafficAndNullServe)
{
    SourceHarness h;
    h.load();
    QuorumMemberSource src(
        LlmqNetwork::Testnet,
        [&h](uint32_t hh) -> std::optional<uint256> {
            auto it = h.by_height.find(hh);
            if (it == h.by_height.end()) return std::nullopt;
            return it->second;
        },
        [&h](const uint256& qh) -> std::optional<uint32_t> {
            for (const auto& [hh, hash] : h.by_height)
                if (hash == qh) return hh;
            return std::nullopt;
        },
        [](const uint256&) -> std::optional<uint256> { return std::nullopt; },
        [](const uint256&, const uint256&) {});
    // no set_send_getqrinfo
    src.request(kType, slot_hash(3));
    EXPECT_EQ(src.rotated_pending_count(), 0u);
    EXPECT_EQ(src.ready_count(), 0u);
    EXPECT_FALSE(src.lookup(kType, slot_hash(3)).has_value());
}

// A quorumIndex at or beyond signingActiveQuorumCount does not exist (upstream
// GetAllQuorumMembers returns {}), so it must not even source.
TEST(DashRotatedQuorumMembers, IndexBeyondSigningActiveCountIsRefused)
{
    SourceHarness h;
    h.load();
    auto src = h.make();
    uint256 far;
    far.SetHex("00000000000000000000000000000000000000000000000000000000000000ff");
    h.by_height[kCycleBase + 200] = far;   // 200 >= 32
    src.request(kType, far);
    EXPECT_EQ(h.sends, 0);
    EXPECT_EQ(src.rotated_pending_count(), 0u);
}

// A tampered operator key breaks the SML root, so the WHOLE cycle fails closed
// and nothing reaches m_ready — the serve-a-bad-member-set gate, now at the
// point where a member set actually would have been served.
TEST(DashRotatedQuorumMembers, TamperedKeyKeepsTheWholeCycleNullServe)
{
    SourceHarness h;
    h.load();
    auto src = h.make();
    uint256 cycle;
    cycle.SetHex(dash::coin::testdata::kRot6075_QuorumHash);
    ASSERT_TRUE(src.request_rotated(kType, cycle));

    CQuorumRotationInfo tampered = h.info;
    ASSERT_FALSE(tampered.mnListDiffAtHMinus2C.mnList.empty());
    tampered.mnListDiffAtHMinus2C.mnList[0].pubKeyOperator[0] ^= 0xff;

    EXPECT_FALSE(src.on_qrinfo(tampered).has_value());
    EXPECT_EQ(src.ready_count(), 0u);
    EXPECT_FALSE(src.lookup(kType, cycle).has_value());
}
