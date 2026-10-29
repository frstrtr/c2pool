// SPDX-License-Identifier: AGPL-3.0-or-later
/// Serve-time PoSe pass (sml_pose_fold.hpp) — dashd's DecreaseScores ->
/// HandleQuorumCommitment -> PoSePunish leg of the list rebuild, folded into
/// the merkleRootMNList a template commits, decided on penalty-oracle bounds.
///
/// THE INCIDENT PINNED HERE (h=2561514, 2026-10-26): both hotel nodes refused
/// to serve for 360 s because the pre-emit gate refused any real commitment
/// with a clear validMembers bit for a listed member. dashd only changes the
/// SML when a punishment crosses the ban threshold; at 2561514 five
/// commitments punished five members and NO MN was banned
/// (merkleRootMNList byte-identical at 2561513/14/15, 3012 MNs).
///
/// Oracle discipline: every reference root below is rebuilt INDEPENDENTLY —
/// a hand-copied list with the expected leaf flipped, hashed through the
/// vendored CalcMerkleRoot — never via the pass under test. The threshold
/// arithmetic is restated from dashd v23.1.7 (deterministicmns.cpp:292-332,
/// specialtxman.cpp:159-174, :229), not from pose_penalty.hpp.

#include <gtest/gtest.h>

#include <impl/dash/coin/sml_pose_fold.hpp>
#include <impl/dash/coin/pose_penalty.hpp>
#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/dkg_commitments.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/dash/coin/vendor/quorum_members.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>   // ParseHex

#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace {

using dash::coin::DashWorkData;
using dash::coin::DeclineReport;
using dash::coin::MNState;
using dash::coin::MnStateMachine;
using dash::coin::MutableTransaction;
using dash::coin::NodeCoinState;
using dash::coin::PoSeOracle;
using dash::coin::PoSePenaltyView;
using dash::coin::QcBlockPlan;
using dash::coin::QcMembersFn;
using dash::coin::QcPoseDecision;
using dash::coin::QcPoseStage;
using dash::coin::WorkSelection;
using dash::coin::WorkSource;
using dash::coin::decide_qc_pose;
using dash::coin::fold_qc_pose;
using dash::coin::vendor::CCbTx;
using dash::coin::vendor::CFinalCommitment;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListEntry;

constexpr uint8_t kPubkeyVer = 76;   // Dash mainnet base58 versions
constexpr uint8_t kP2shVer   = 16;

// The incident tip: block 2561513 is the prev of the refused height.
constexpr uint32_t kPrevH = 2'561'513;

// A distinct, deterministic 256-bit value per (tag, n). Byte 31 carries the
// tag so the families never collide.
uint256 hval(uint8_t tag, uint32_t n)
{
    uint256 h;
    std::array<uint8_t, 32> b{};
    std::memcpy(b.data(), &n, sizeof(n));
    b[8]  = 0x5A;
    b[31] = tag;
    std::memcpy(h.data(), b.data(), 32);
    return h;
}
uint256 mn(uint32_t i)    { return hval(0x11, i); }   // MN proRegTxHash
uint256 qhash(uint32_t i) { return hval(0x22, i); }   // quorum hash
const uint256 kPrevHash = hval(0x33, 1);

CSimplifiedMNListEntry entry(const uint256& pro, bool valid = true)
{
    CSimplifiedMNListEntry e;
    e.nVersion      = CSimplifiedMNListEntry::VER_BASIC_BLS;
    e.proRegTxHash  = pro;
    e.confirmedHash = hval(0x44, 7);       // confirmed long ago
    e.netPort       = 9999;
    e.isValid       = valid;
    return e;
}

// N entries mn(0..N-1), all valid.
CSimplifiedMNList list_of(size_t n)
{
    std::vector<CSimplifiedMNListEntry> v;
    v.reserve(n);
    for (size_t i = 0; i < n; ++i) v.push_back(entry(mn(static_cast<uint32_t>(i))));
    return CSimplifiedMNList(std::move(v));
}

// INDEPENDENT reference root: a hand copy with the named leaves flipped.
uint256 root_with_invalid(CSimplifiedMNList l, const std::set<uint256>& banned)
{
    for (auto& e : l.mnList)
        if (banned.count(e.proRegTxHash)) e.isValid = false;
    return l.CalcMerkleRoot();
}

// A structurally real (non-null) commitment, every member valid.
CFinalCommitment real_qc(uint8_t type, const uint256& qh, size_t size,
                         int16_t qi = 0)
{
    CFinalCommitment c;
    c.nVersion    = CFinalCommitment::BASIC_BLS_INDEXED_QUORUM_VERSION;
    c.llmqType    = type;
    c.quorumHash  = qh;
    c.quorumIndex = qi;
    c.signers.assign(size, true);
    c.validMembers.assign(size, true);
    c.quorumPublicKey.fill(0x11);
    c.quorumVvecHash = hval(0x55, 1);
    c.quorumSig.fill(0x33);
    c.membersSig.fill(0x44);
    return c;
}

// members(type, qh) from a fixed table.
QcMembersFn members_table(std::map<uint256, std::vector<uint256>> t)
{
    return [t](uint8_t, const uint256& qh) -> std::optional<std::vector<uint256>> {
        auto it = t.find(qh);
        if (it == t.end()) return std::nullopt;
        return it->second;
    };
}

// `size` members starting at mn(first).
std::vector<uint256> member_run(uint32_t first, size_t size)
{
    std::vector<uint256> v;
    for (size_t k = 0; k < size; ++k) v.push_back(mn(first + static_cast<uint32_t>(k)));
    return v;
}

// An oracle AT THE TIP (cursor == (kPrevH, kPrevHash)) answering `view` for
// every MN, or per-MN from `table` when given.
PoSeOracle oracle_all(PoSePenaltyView view)
{
    PoSeOracle o;
    o.penalty = [view](const uint256&) -> std::optional<PoSePenaltyView> { return view; };
    o.cursor  = [] { return std::optional<std::pair<uint32_t, uint256>>{{kPrevH, kPrevHash}}; };
    return o;
}
PoSeOracle oracle_table(std::map<uint256, PoSePenaltyView> t)
{
    PoSeOracle o;
    o.penalty = [t](const uint256& p) -> std::optional<PoSePenaltyView> {
        auto it = t.find(p);
        if (it == t.end()) return std::nullopt;
        return it->second;
    };
    o.cursor  = [] { return std::optional<std::pair<uint32_t, uint256>>{{kPrevH, kPrevHash}}; };
    return o;
}

QcPoseDecision decide(const CSimplifiedMNList& base,
                      const std::vector<CFinalCommitment>& plan,
                      const QcMembersFn& members, const PoSeOracle* oracle)
{
    return decide_qc_pose(base, plan, members, oracle, kPrevH, kPrevHash);
}

// The PRE-FIX serve predicate, VERBATIM from origin/master
// dkg_commitments.hpp (qc_pose_pass_provably_noop) — the reference model for
// the fail-closed equivalence proof below. Not production code any more.
bool master_qc_pose_pass_provably_noop(const CFinalCommitment& c,
                                       size_t member_count)
{
    if (dash::coin::qc_commitment_is_null(c)) return true;
    if (member_count == 0 || member_count > c.validMembers.size())
        return false;
    for (size_t i = 0; i < member_count; ++i)
        if (!c.validMembers[i]) return false;
    return true;
}

} // namespace

// ════════════════════════════════════════════════════════════════════════
// dashd's arithmetic, restated at the incident's numbers.
// ════════════════════════════════════════════════════════════════════════

TEST(DashSmlPoseFold, PenaltyArithmeticAtTheIncidentListSize)
{
    // CalcMaxPoSePenalty = max(100, total MN count) (deterministicmns.cpp:
    // 292-298); CalcPenalty(66) = max*66/100, integer (:300-304).
    EXPECT_EQ(dash::coin::pose::calc_max_pose_penalty(3012), 3012);
    EXPECT_EQ(dash::coin::pose::calc_penalty(3012, 66), 1987);   // 198792/100
    EXPECT_EQ(dash::coin::pose::calc_max_pose_penalty(2), 100);   // floor of 100
    EXPECT_EQ(dash::coin::pose::calc_penalty(100, 66), 66);
}

// ════════════════════════════════════════════════════════════════════════
// KAT 1 — one punishment from zero is a byte no-op for the root.
// ════════════════════════════════════════════════════════════════════════
TEST(DashSmlPoseFold, OnePunishFromZeroIsRootNoop)
{
    const CSimplifiedMNList base = list_of(3012);
    // Slot 0 of block 2561514: validMembers fffffffffbffff0f -> member 34
    // invalid (byte 4 = 0xfb, bit 2), 60 members.
    auto c = real_qc(5, qhash(0), 60);
    c.validMembers[34] = false;
    const auto members = members_table({{qhash(0), member_run(0, 60)}});
    const PoSeOracle o = oracle_all({0, 0, false});

    const auto f = fold_qc_pose(base, {c}, members, &o, kPrevH, kPrevHash);
    ASSERT_TRUE(f.ok()) << dash::coin::qc_pose_stage_name(f.decision.stage);
    EXPECT_EQ(f.decision.punished, 1u);
    EXPECT_TRUE(f.decision.bans.empty());
    // 0 -> decay 0 -> +1987 = 1987 < 3012: punished, not banned. nPoSePenalty
    // is not a leaf field (simplifiedmns.h:35), so the root is unchanged.
    EXPECT_EQ(f.sml.CalcMerkleRoot(), base.CalcMerkleRoot());
}

// ════════════════════════════════════════════════════════════════════════
// KAT 2 — the 2561514 shape: the five REAL punishing commitments of that
// block (wire payloads from insight, type-6 txs at vtx 1/2/13/22/27 = slots
// 0/1/12/21/26), over synthetic disjoint 60-member sets in a 3012-MN list,
// every oracle penalty 0 -> committed root unchanged, exactly as the network
// committed it. (Byte-exact variant needs a capture of SML@2561513 and the
// five member sets — design §5 Q4.)
// ════════════════════════════════════════════════════════════════════════
namespace {

struct RealQc { int slot; size_t invalid_index; const char* payload_hex; };

// CFinalCommitmentTxPayload bytes, verbatim from the block (extraPayload).
const RealQc kBlock2561514Punishing[] = {
    {0, 34, "0100ea15270004000598b17fc74d3b94ff139bc09e9541d95275413abcd92b424b110000000000000000003cfffffffffbffff0f3cfffffffffbffff0fa11324029127024de4d1269a8fcf7626202676578130da0727b42c8914617add99c0baa5d8a404c5a971b70304e56b6cb044e3aea98b8a6af4532ba79a818e588f773fc26d232b8b071a688ef351273c8ad42f4c6adf15c13e4cf39262dc8b0852cc05f1ccba5bdc759dddccc6e1317e66ae30b106764dd076fb92d9e460e5be17717f651446d772e7e28cb27cace2d01ff27066ce32833efaef3cad4626cdaab279341873d4e8c8491a080fc8b67740a090be78af051e3308f2c00319d8fc6975d64bed33f97a9fae79304ff2ebd8be79d261f7d43235054ac3e87f763f91a708a41a20b453d47b4e26c39e892eebc3919ff41cf541e8622386462850686c075908063e2ce990ce6c1aa46573c033ad"},
    {1, 22, "0100ea152700040005f22b0ef748dba5db8db3b1bfbd3fc62fc70f0ceced3716171e0000000000000001003cfffffffffffeff0f3cffffbfffffffff0f92321c1eda5a2ff8d30da2d534e618daf12d5a7e304c9b92165cee42587fbcf295fd7006170e48532d2d3328ee0b9f47787ef79d5119a07824ecf14815b4f8d526190b920c7059b01921a7ce34856e67aea43d0370eb0d8c3c56426daac80af799a05af41bc2f3e40ca9c9af14b5aa8de742f411e4097fba363bbb5b0cb472740fd8c855fc6942f23983876bf9aab3a6b24966c62f69fb4b8078a37509df7155e4d7f8eb5df664adc6634563b1c12784b0fa5571cedb142e539b1d5f542d6471877f124b5596847ac715f3cd2c4a8b7140a5765fd438f9316c1b1a13f88ed2560f5727412d1a06a05b5ebfad50d651c7a242b12044c6b6b9fe3082692642e5e846c8fc594f682906006ca03ffa70896d"},
    {12, 57, "0100ea15270004000502d301634e8272a08a40ea7bb61f1d24fd75ddc10e41de3310000000000000000c003cfffffedfffffff0d3cffffffffffffff0da3e0107bcf9f8a4b8e23417bfeafe86793e2ed2c3dafd9e0eaa0dddb2f11439f227b69678f64d0426ed3ccb16755865dff47c15c77cd48a750afe06e23f8c1cea6eeb2edee93d24a7756d50efe9cbe3fb5cfde862311118f0c5863fc5ca228a222efa45e37adab8bc4d325d8d38ef1396cf17d4779d3ea4bfa61a1b0765a04a712d4409841ea07aa3aa0109c46e1bc4c376680d14745c2d03ba41df3f82054c0ffbd3125b2be5c481bd9292e5e932da6b030e4af2fe72f340c7180446ed92ac1b6ada1b742a392ef74c53388a11111b1878afddc3235e546fd7a7b7450b7efd50e253a9fc13c81fb427bf97692f7edb4e906fd7204be4e38095a25754305a0b065875cffb390363c8e4652bfd16bd0b9"},
    {21, 9, "0100ea152700040005d2418edd555c000614130ae7db6eaef0b0930ae203148eb7170000000000000015003cfffdffffffffff0f3cfffdffffffffff0f870149e6a6b359ec4438e6e537ff018249705fbb2f5cd818c228381d84916f781d193cc1a5ab6ca592cc8e86d33f144fd9f6dbd05e3157c93ea7cb635ed16af38700d3916ef34db2e03b9aa6881785b3a635b12efb6a8ba9a4a5b923b5af330657d8dd051af2ef4e43d601b2b9eb4a92dcf0d3948968085bd68147374528657d09ba11b056520e94683cc1b71b2f322711524516fd6373b3b671175aa8b8d28e92a7cdb7eae34b2d3ab993cd5ae0f3c4b1cf6f1fc46aca0104180ed383d901006a8fbef3535f6d04fa3b1c2b46c2dc460069231962d49cb3d4d9dabf02d3c00b0d8a806c847f99bfb1a2a9d60d33ae25c749a990422698f7939d2bd3ad5c4999f830e59d6268bc329d8c02ee63243008"},
    {26, 31, "0100ea152700040005477d9fd941bd90e21d2200ca97aceb4b8d0c0cda4683b9b511000000000000001a003cdffffffdfffffd0f3cffffff7fffffff0f85c5ff191fec0841e5ec952d79b034a065150b73760e3f7fe3e6801efe79881d1c06b182340cd58e0c6090da1b38e6cf0b477bd577ab7dade080ab8e6395cae01e2c541885902da21738721b14725ec0b42b2298893b4b2bd899bb164ffb7bb1796e944eae8a7e4062b8f09e621624ac1706bdcc7487fa59128e7487558ecba307aee5294f18ebe2a7a7599924f8df9dd9b2e75dafa97faa70d2eca2a9f480101911462cf3bc22386988ec17c189ae3496fb7d4daffd142f85ad9a41b71c4182d4adce9fd8c547db86ca45fe2d42f60af04f6379b1d0de745b7f826dddcf56b605599bc79b4bc8d5538158d18be810e4da1c320fb0cdf8d3ac618f03ccd1406dd5a51ae152a82bb1cef3f6146fb42762"},
};

// Parse the five real commitments and their synthetic disjoint member sets
// (slot s -> mn(s*60 .. s*60+59)).
struct Block2561514 {
    std::vector<CFinalCommitment> plan;
    std::map<uint256, std::vector<uint256>> members;
    std::vector<uint256> punished_pro;   // the member each one marks invalid
};

Block2561514 load_block_2561514()
{
    Block2561514 b;
    for (const auto& q : kBlock2561514Punishing) {
        dash::coin::vendor::CFinalCommitmentTxPayload pl;
        const auto bytes = ParseHex(q.payload_hex);
        EXPECT_TRUE(dash::coin::vendor::parse_qfcommit_payload(bytes, pl))
            << "slot " << q.slot;
        EXPECT_EQ(pl.nHeight, 2'561'514u);
        EXPECT_EQ(pl.commitment.llmqType, 5);              // LLMQ_60_75
        EXPECT_EQ(pl.commitment.quorumIndex, q.slot);
        EXPECT_EQ(pl.commitment.validMembers.size(), 60u);
        EXPECT_FALSE(dash::coin::qc_commitment_is_null(pl.commitment));
        // Exactly the one invalid member read off the insight bitset.
        size_t clear = 0;
        for (size_t i = 0; i < pl.commitment.validMembers.size(); ++i)
            if (!pl.commitment.validMembers[i]) {
                ++clear;
                EXPECT_EQ(i, q.invalid_index) << "slot " << q.slot;
            }
        EXPECT_EQ(clear, 1u) << "slot " << q.slot;
        const uint32_t first = static_cast<uint32_t>(q.slot) * 60u;
        b.members[pl.commitment.quorumHash] = member_run(first, 60);
        b.punished_pro.push_back(mn(first + static_cast<uint32_t>(q.invalid_index)));
        b.plan.push_back(pl.commitment);
    }
    return b;
}

} // namespace

TEST(DashSmlPoseFold, Block2561514ShapeIsRootNoop)
{
    const CSimplifiedMNList base = list_of(3012);
    const auto blk = load_block_2561514();
    ASSERT_EQ(blk.plan.size(), 5u);
    const QcMembersFn members = members_table(blk.members);

    // Oracle 0 for every MN: five punishments, no ban, root unchanged — the
    // network's own outcome (merkleRootMNList 28a48e2f... at 2561513/14/15).
    const PoSeOracle zero = oracle_all({0, 0, false});
    const auto f = fold_qc_pose(base, blk.plan, members, &zero, kPrevH, kPrevHash);
    ASSERT_TRUE(f.ok()) << dash::coin::qc_pose_stage_name(f.decision.stage);
    EXPECT_EQ(f.decision.punished, 5u);
    EXPECT_EQ(f.decision.absent, 0u);
    EXPECT_EQ(f.decision.already_banned, 0u);
    EXPECT_TRUE(f.decision.bans.empty());
    EXPECT_EQ(f.sml.CalcMerkleRoot(), base.CalcMerkleRoot());

    // WITHOUT an oracle (PR-A as shipped) the height still refuses at the
    // first punishing commitment, naming it — the fail-closed posture.
    const auto none = decide(base, blk.plan, members, nullptr);
    EXPECT_EQ(none.stage, QcPoseStage::PenaltyUnknown);
    EXPECT_EQ(none.qc_index, 0u);
    EXPECT_EQ(none.quorum_index, 0);
    EXPECT_EQ(none.pro_tx_hash, blk.punished_pro[0]);

    // And the shape IS sensitive: had slot 21's member carried a prior
    // punishment >= 1026 (one within the previous ~961 blocks), dashd bans it
    // and the committed root must change by exactly that leaf.
    std::map<uint256, PoSePenaltyView> t;
    for (const auto& p : blk.punished_pro) t[p] = PoSePenaltyView{0, 0, false};
    t[blk.punished_pro[3]] = PoSePenaltyView{1026, 1026, false};
    const PoSeOracle primed = oracle_table(t);
    const auto g = fold_qc_pose(base, blk.plan, members, &primed, kPrevH, kPrevHash);
    ASSERT_TRUE(g.ok());
    ASSERT_EQ(g.decision.bans.size(), 1u);
    EXPECT_EQ(g.decision.bans[0], blk.punished_pro[3]);
    EXPECT_EQ(g.sml.CalcMerkleRoot(),
              root_with_invalid(base, {blk.punished_pro[3]}));
    EXPECT_NE(g.sml.CalcMerkleRoot(), base.CalcMerkleRoot());
}

// ════════════════════════════════════════════════════════════════════════
// KAT 3 — the threshold, dashd-exact, with decay FIRST.
// N=3012: max=3012, P=1987. Pre-block 1026 -> decay 1025 -> 1025+1987=3012
// >= max -> ban. Pre-block 1025 -> 1024+1987=3011 -> no ban.
// Mutations: `>=` -> `>` flips the 1026 case; dropping the decay flips 1025.
// ════════════════════════════════════════════════════════════════════════
TEST(DashSmlPoseFold, ThresholdArithmeticIsDashdExact)
{
    const CSimplifiedMNList base = list_of(3012);
    auto c = real_qc(5, qhash(0), 60);
    c.validMembers[34] = false;
    const auto members = members_table({{qhash(0), member_run(0, 60)}});
    const uint256 victim = mn(34);

    {
        const PoSeOracle o = oracle_all({1026, 1026, false});
        const auto f = fold_qc_pose(base, {c}, members, &o, kPrevH, kPrevHash);
        ASSERT_TRUE(f.ok());
        ASSERT_EQ(f.decision.bans.size(), 1u)
            << "1026 -> decay 1025 -> +1987 = 3012 >= max 3012: dashd BANS";
        EXPECT_EQ(f.decision.bans[0], victim);
        EXPECT_EQ(f.sml.CalcMerkleRoot(), root_with_invalid(base, {victim}));
    }
    {
        const PoSeOracle o = oracle_all({1025, 1025, false});
        const auto f = fold_qc_pose(base, {c}, members, &o, kPrevH, kPrevHash);
        ASSERT_TRUE(f.ok());
        EXPECT_TRUE(f.decision.bans.empty())
            << "1025 -> decay 1024 -> +1987 = 3011 < 3012: no ban";
        EXPECT_EQ(f.sml.CalcMerkleRoot(), base.CalcMerkleRoot());
    }
}

// ════════════════════════════════════════════════════════════════════════
// KAT 4 — two commitments punishing the same MN in one block (types 1 and 4
// share the h%24 in [10,18] window) ban from zero: 2P = 3974 >= 3012.
// ════════════════════════════════════════════════════════════════════════
TEST(DashSmlPoseFold, SameBlockDoublePunishBansFromZero)
{
    const CSimplifiedMNList base = list_of(3012);
    const uint256 victim = mn(100);
    auto c1 = real_qc(1, qhash(1), 50);    // LLMQ_50_60
    auto c4 = real_qc(4, qhash(4), 100);   // LLMQ_100_67
    std::vector<uint256> m1 = member_run(0, 50);
    std::vector<uint256> m4 = member_run(500, 100);
    m1[3]  = victim; c1.validMembers[3]  = false;
    m4[77] = victim; c4.validMembers[77] = false;
    const auto members = members_table({{qhash(1), m1}, {qhash(4), m4}});
    const PoSeOracle o = oracle_all({0, 0, false});

    const auto f = fold_qc_pose(base, {c1, c4}, members, &o, kPrevH, kPrevHash);
    ASSERT_TRUE(f.ok());
    EXPECT_EQ(f.decision.punished, 2u);
    ASSERT_EQ(f.decision.bans.size(), 1u)
        << "0 + 1987 + 1987 = 3974 -> clamp 3012 >= max: banned in-block";
    EXPECT_EQ(f.decision.bans[0], victim);
    EXPECT_EQ(f.sml.CalcMerkleRoot(), root_with_invalid(base, {victim}));

    // Each commitment alone is a no-op — the ban is the accumulation.
    EXPECT_TRUE(decide(base, {c1}, members, &o).bans.empty());
    EXPECT_TRUE(decide(base, {c4}, members, &o).bans.empty());
}

// ════════════════════════════════════════════════════════════════════════
// KAT 5 — the free exact sub-proofs and the structural edges.
// ════════════════════════════════════════════════════════════════════════
TEST(DashSmlPoseFold, AlreadyBannedMemberIsNoop)
{
    CSimplifiedMNList base = list_of(200);
    for (auto& e : base.mnList)
        if (e.proRegTxHash == mn(7)) e.isValid = false;   // PoSe-banned at tip
    auto c = real_qc(1, qhash(1), 50);
    c.validMembers[7] = false;
    const auto members = members_table({{qhash(1), member_run(0, 50)}});

    // NO oracle: PoSePunish's ban branch is guarded by !IsBanned()
    // (deterministicmns.cpp:319), so no penalty can change the leaf.
    const auto f = fold_qc_pose(base, {c}, members, nullptr, kPrevH, kPrevHash);
    ASSERT_TRUE(f.ok()) << dash::coin::qc_pose_stage_name(f.decision.stage);
    EXPECT_EQ(f.decision.punished, 1u);
    EXPECT_EQ(f.decision.already_banned, 1u);
    EXPECT_TRUE(f.decision.bans.empty());
    EXPECT_EQ(f.sml.CalcMerkleRoot(), base.CalcMerkleRoot());
}

TEST(DashSmlPoseFold, AbsentMemberIsSkipped)
{
    const CSimplifiedMNList base = list_of(200);
    auto c = real_qc(1, qhash(1), 50);
    std::vector<uint256> m = member_run(0, 50);
    m[7] = hval(0x66, 1);              // not in the list (collateral spent since)
    c.validMembers[7] = false;
    const auto members = members_table({{qhash(1), m}});

    // dashd: if (!mnList.HasMN(members[i]->proTxHash)) continue; (:162-164)
    const auto f = fold_qc_pose(base, {c}, members, nullptr, kPrevH, kPrevHash);
    ASSERT_TRUE(f.ok()) << dash::coin::qc_pose_stage_name(f.decision.stage);
    EXPECT_EQ(f.decision.absent, 1u);
    EXPECT_EQ(f.decision.punished, 0u);
    EXPECT_EQ(f.sml.CalcMerkleRoot(), base.CalcMerkleRoot());
}

TEST(DashSmlPoseFold, PaddingBitsIgnored)
{
    // A non-full quorum: 40 members on a size-50 type. Bits [40,50) are DKG
    // padding (dashd's Verify requires them unset) and the punish loop runs
    // over members.size() only (:161) — nothing is punished.
    const CSimplifiedMNList base = list_of(200);
    auto c = real_qc(1, qhash(1), 50);
    for (size_t i = 40; i < 50; ++i) { c.signers[i] = false; c.validMembers[i] = false; }
    const auto f = fold_qc_pose(base, {c},
                                members_table({{qhash(1), member_run(0, 40)}}),
                                nullptr, kPrevH, kPrevHash);
    ASSERT_TRUE(f.ok()) << dash::coin::qc_pose_stage_name(f.decision.stage);
    EXPECT_EQ(f.decision.punished, 0u);

    // The SAME bitset against a 50-member list reads [40,50) as punished
    // listed members -> needs penalties -> refuses without an oracle.
    const auto g = decide(base, {c}, members_table({{qhash(1), member_run(0, 50)}}),
                          nullptr);
    EXPECT_EQ(g.stage, QcPoseStage::PenaltyUnknown);
}

TEST(DashSmlPoseFold, MemberSetOverrunRefuses)
{
    const CSimplifiedMNList base = list_of(200);
    const auto c = real_qc(1, qhash(1), 50);   // every member valid
    const PoSeOracle o = oracle_all({0, 0, false});
    // 51 members cannot index a 50-bit bitset — never a guess.
    const auto f = decide(base, {c}, members_table({{qhash(1), member_run(0, 51)}}), &o);
    EXPECT_EQ(f.stage, QcPoseStage::MembersOverrun);
    // Unsourced and empty sets refuse too, even for an all-valid commitment
    // (the pre-fix predicate refused member_count 0 the same way).
    EXPECT_EQ(decide(base, {c}, members_table({}), &o).stage,
              QcPoseStage::MembersMissing);
    EXPECT_EQ(decide(base, {c}, members_table({{qhash(1), {}}}), &o).stage,
              QcPoseStage::MembersMissing);
    EXPECT_EQ(decide(base, {c}, QcMembersFn{}, &o).stage,
              QcPoseStage::MembersMissing);
    // A punished member with no identity would read as "absent" — refuse.
    auto p = real_qc(1, qhash(1), 50);
    p.validMembers[7] = false;
    auto m = member_run(0, 50);
    m[7] = uint256();
    EXPECT_EQ(decide(base, {p}, members_table({{qhash(1), m}}), &o).stage,
              QcPoseStage::MembersMissing);
}

TEST(DashSmlPoseFold, NullCommitmentUntouched)
{
    const CSimplifiedMNList base = list_of(200);
    const auto n = dash::coin::build_null_commitment(dash::coin::kLlmq50_60,
                                                     qhash(1), 0);
    // IsNull() (specialtxman.cpp:432): no member set, no oracle consulted.
    const auto f = fold_qc_pose(base, {n}, QcMembersFn{}, nullptr, kPrevH, kPrevHash);
    ASSERT_TRUE(f.ok());
    EXPECT_EQ(f.decision.punished, 0u);
    EXPECT_EQ(f.sml.CalcMerkleRoot(), base.CalcMerkleRoot());
}

// ════════════════════════════════════════════════════════════════════════
// KAT 6 — inexact bounds refuse ONLY when they straddle the threshold.
// N=3012 (max 3012, P 1987):
//   lo=0,   hi=6024 -> [1987, 3012]  straddles      -> REFUSE
//   lo=0,   hi=900  -> [1987, 2886]  hi-1+P < max   -> serve, no ban
//   lo=1100,hi=6024 -> [3012, 3012]  lo-1+P >= max  -> serve, ban
// Mutation lo<->hi (no-ban proved on lo) makes case 1 serve -> red.
// ════════════════════════════════════════════════════════════════════════
TEST(DashSmlPoseFold, InexactPenaltyRefusesOnlyWhenItMatters)
{
    const CSimplifiedMNList base = list_of(3012);
    auto c = real_qc(5, qhash(0), 60);
    c.validMembers[34] = false;
    const auto members = members_table({{qhash(0), member_run(0, 60)}});
    const uint256 victim = mn(34);

    {
        const PoSeOracle o = oracle_all({0, 6024, false});
        const auto d = decide(base, {c}, members, &o);
        EXPECT_EQ(d.stage, QcPoseStage::PenaltyInexact);
        EXPECT_EQ(d.pro_tx_hash, victim);
        EXPECT_TRUE(d.bans.empty());
    }
    {
        const PoSeOracle o = oracle_all({0, 900, false});
        const auto f = fold_qc_pose(base, {c}, members, &o, kPrevH, kPrevHash);
        ASSERT_TRUE(f.ok());
        EXPECT_TRUE(f.decision.bans.empty());
        EXPECT_EQ(f.sml.CalcMerkleRoot(), base.CalcMerkleRoot());
    }
    {
        const PoSeOracle o = oracle_all({1100, 6024, false});
        const auto f = fold_qc_pose(base, {c}, members, &o, kPrevH, kPrevHash);
        ASSERT_TRUE(f.ok());
        ASSERT_EQ(f.decision.bans.size(), 1u);
        EXPECT_EQ(f.sml.CalcMerkleRoot(), root_with_invalid(base, {victim}));
    }
    {
        // An oracle UPPER bound at the int32 ceiling is clamped, never
        // overflowed (PoSePunish: min(max, p + penalty)).
        const PoSeOracle o = oracle_all({1100, 2147483647, false});
        const auto f = fold_qc_pose(base, {c}, members, &o, kPrevH, kPrevHash);
        ASSERT_TRUE(f.ok());
        EXPECT_EQ(f.decision.bans.size(), 1u);
    }
}

// ════════════════════════════════════════════════════════════════════════
// KAT 7a — the oracle must be present, at THIS tip, and well-formed.
// ════════════════════════════════════════════════════════════════════════
TEST(DashSmlPoseFold, OracleUnknownRefuses)
{
    const CSimplifiedMNList base = list_of(200);
    auto c = real_qc(1, qhash(1), 50, /*qi=*/0);
    c.validMembers[7] = false;
    const auto members = members_table({{qhash(1), member_run(0, 50)}});

    // No oracle at all (PR-A production posture).
    EXPECT_EQ(decide(base, {c}, members, nullptr).stage, QcPoseStage::PenaltyUnknown);
    const PoSeOracle unwired;
    EXPECT_EQ(decide(base, {c}, members, &unwired).stage, QcPoseStage::PenaltyUnknown);
    // Wired, but no answer for this MN.
    {
        const PoSeOracle o = oracle_table({});
        const auto d = decide(base, {c}, members, &o);
        EXPECT_EQ(d.stage, QcPoseStage::PenaltyUnknown);
        EXPECT_EQ(d.pro_tx_hash, mn(7));
    }
    // Malformed bounds.
    {
        const PoSeOracle o = oracle_all({5, 4, false});
        EXPECT_EQ(decide(base, {c}, members, &o).stage, QcPoseStage::PenaltyUnknown);
        const PoSeOracle n = oracle_all({-1, 4, false});
        EXPECT_EQ(decide(base, {c}, members, &n).stage, QcPoseStage::PenaltyUnknown);
    }
    // Cursor one block behind / on a sibling block.
    {
        PoSeOracle o = oracle_all({0, 0, false});
        o.cursor = [] { return std::optional<std::pair<uint32_t, uint256>>{{kPrevH - 1, kPrevHash}}; };
        EXPECT_EQ(decide(base, {c}, members, &o).stage, QcPoseStage::OracleNotAtTip);
        o.cursor = [] { return std::optional<std::pair<uint32_t, uint256>>{{kPrevH, hval(0x33, 2)}}; };
        EXPECT_EQ(decide(base, {c}, members, &o).stage, QcPoseStage::OracleNotAtTip);
        o.cursor = [] { return std::optional<std::pair<uint32_t, uint256>>{}; };
        EXPECT_EQ(decide(base, {c}, members, &o).stage, QcPoseStage::OracleNotAtTip);
    }
    // The oracle holds the MN banned while the tip SML says valid: it is not
    // describing this tip.
    {
        const PoSeOracle o = oracle_all({3012, 3012, true});
        EXPECT_EQ(decide(base, {c}, members, &o).stage, QcPoseStage::OracleNotAtTip);
    }
    // An oracle WITHOUT a cursor is trusted to gate itself (nullopt when not
    // at the tip); with an answer it decides.
    {
        PoSeOracle o = oracle_all({0, 0, false});
        o.cursor = nullptr;
        EXPECT_TRUE(decide(base, {c}, members, &o).ok());
    }
}

// ════════════════════════════════════════════════════════════════════════
// FAIL-CLOSED PROOF (done criterion 3): with NO oracle wired, every case the
// pre-fix predicate refused is still refused, EXCEPT the two exact sub-proofs
// (every punished listed member absent from the list or already banned) —
// and every case it served is still served. Every refusal names its stage.
// Exhaustive over member-source shape x bitset shape x punished-member state.
// ════════════════════════════════════════════════════════════════════════
TEST(DashSmlPoseFold, NoOracleRefusesEverythingTheOldPredicateRefused)
{
    CSimplifiedMNList base = list_of(200);
    for (auto& e : base.mnList)
        if (e.proRegTxHash == mn(150)) e.isValid = false;   // a banned MN
    const uint256 absent = hval(0x66, 9);

    enum class Src { Unset, Nullopt, Empty, Overrun, Full, Short };
    enum class Pun { None, Valid, Banned, Absent, ValidAndBanned, BannedAndAbsent, Padding };
    const Src srcs[] = {Src::Unset, Src::Nullopt, Src::Empty, Src::Overrun,
                        Src::Full, Src::Short};
    const Pun puns[] = {Pun::None, Pun::Valid, Pun::Banned, Pun::Absent,
                        Pun::ValidAndBanned, Pun::BannedAndAbsent, Pun::Padding};
    size_t cases = 0, sub_proof_serves = 0;
    for (bool null_commitment : {false, true})
    for (Src src : srcs)
    for (Pun pun : puns) {
        CFinalCommitment c = null_commitment
            ? dash::coin::build_null_commitment(dash::coin::kLlmq50_60, qhash(1), 0)
            : real_qc(1, qhash(1), 50);
        std::vector<uint256> m = member_run(0, 50);
        // Who sits at the punished indices.
        if (pun == Pun::Banned || pun == Pun::ValidAndBanned || pun == Pun::BannedAndAbsent)
            m[10] = mn(150);
        if (pun == Pun::Absent || pun == Pun::BannedAndAbsent) m[11] = absent;
        if (!null_commitment) {
            switch (pun) {
            case Pun::None: break;
            case Pun::Valid: c.validMembers[3] = false; break;
            case Pun::Banned: c.validMembers[10] = false; break;
            case Pun::Absent: c.validMembers[11] = false; break;
            case Pun::ValidAndBanned:
                c.validMembers[3] = false; c.validMembers[10] = false; break;
            case Pun::BannedAndAbsent:
                c.validMembers[10] = false; c.validMembers[11] = false; break;
            case Pun::Padding:
                for (size_t i = 45; i < 50; ++i) { c.signers[i] = false; c.validMembers[i] = false; }
                break;
            }
        }
        std::optional<std::vector<uint256>> set;
        switch (src) {
        case Src::Unset: case Src::Nullopt: break;
        case Src::Empty: set = std::vector<uint256>{}; break;
        case Src::Overrun: { auto o = m; o.push_back(mn(199)); set = o; break; }
        case Src::Full: set = m; break;
        case Src::Short: set = std::vector<uint256>(m.begin(), m.begin() + 45); break;
        }
        QcMembersFn fn;
        if (src != Src::Unset)
            fn = [set](uint8_t, const uint256&) { return set; };

        // The old predicate's verdict, exactly as the old gate formed it:
        // capability absent / member set unsourced => refuse (n/a).
        const bool old_serves =
            dash::coin::qc_commitment_is_null(c)
            || (set.has_value()
                && master_qc_pose_pass_provably_noop(c, set->size()));
        const QcPoseDecision d = decide(base, {c}, fn, nullptr);
        ++cases;

        // The ONLY new serves: a sourced, in-bounds member set whose every
        // punished listed member is absent or already banned.
        bool sub_proof = false;
        if (!old_serves && set && !set->empty() && set->size() <= c.validMembers.size()) {
            bool any_punished = false, all_free = true;
            for (size_t k = 0; k < set->size(); ++k) {
                if (c.validMembers[k]) continue;
                any_punished = true;
                const uint256& p = (*set)[k];
                const bool is_absent = (p == absent);
                const bool is_banned = (p == mn(150));
                if (!is_absent && !is_banned) all_free = false;
            }
            sub_proof = any_punished && all_free;
        }
        const std::string tag = "null=" + std::to_string(null_commitment)
            + " src=" + std::to_string(static_cast<int>(src))
            + " pun=" + std::to_string(static_cast<int>(pun));
        if (old_serves) {
            EXPECT_TRUE(d.ok()) << "a case the old gate SERVED now refuses: " << tag
                                << " stage=" << dash::coin::qc_pose_stage_name(d.stage);
        } else if (sub_proof) {
            EXPECT_TRUE(d.ok()) << "an exact sub-proof must serve: " << tag;
            ++sub_proof_serves;
        } else {
            EXPECT_FALSE(d.ok()) << "FAIL-OPEN: the old gate refused this and the "
                                    "pass served it with no oracle: " << tag;
            EXPECT_NE(d.stage, QcPoseStage::Ok);
            EXPECT_STRNE(dash::coin::qc_pose_stage_name(d.stage), "ok") << tag;
            EXPECT_TRUE(d.bans.empty()) << tag;
        }
        if (!d.ok())
            EXPECT_NE(NodeCoinState::qc_pose_value(d).find(
                          std::string("stage=") + dash::coin::qc_pose_stage_name(d.stage)),
                      std::string::npos) << tag;
    }
    EXPECT_EQ(cases, 2u * 6u * 7u);
    EXPECT_GT(sub_proof_serves, 0u) << "the enumeration must reach the sub-proofs";
}

// ════════════════════════════════════════════════════════════════════════
// Member identity: the published member set carries each member's
// proRegTxHash, index-aligned with the bitset (the key it already carried).
// ════════════════════════════════════════════════════════════════════════
TEST(DashSmlPoseFold, ComputedMemberSetCarriesIndexAlignedProTxHash)
{
    std::vector<CSimplifiedMNListEntry> v;
    for (uint32_t i = 0; i < 80; ++i) {
        auto e = entry(mn(i));
        e.confirmedHash = hval(0x44, 1000 + i);
        for (size_t b = 0; b < e.pubKeyOperator.size(); ++b)
            e.pubKeyOperator[b] = static_cast<uint8_t>(i + 1 + b);
        v.push_back(e);
    }
    const CSimplifiedMNList sml(std::move(v));
    const auto members = dash::coin::vendor::compute_quorum_members(
        dash::coin::vendor::QuorumMemberParams{1, 50, false, false},
        hval(0x77, 1), sml);
    ASSERT_TRUE(members.has_value());
    ASSERT_EQ(members->size(), 50u);
    std::set<uint256> seen;
    for (size_t k = 0; k < members->size(); ++k) {
        const auto& m = (*members)[k];
        ASSERT_FALSE(m.proTxHash.IsNull()) << "member " << k << " has no identity";
        const CSimplifiedMNListEntry* e = nullptr;
        for (const auto& x : sml.mnList)
            if (x.proRegTxHash == m.proTxHash) e = &x;
        ASSERT_NE(e, nullptr) << "member " << k << " proTxHash not in the list";
        EXPECT_EQ(e->pubKeyOperator, m.pubKeyOperator)
            << "member " << k << ": identity and key name different MNs";
        seen.insert(m.proTxHash);
    }
    EXPECT_EQ(seen.size(), 50u);
}

// ════════════════════════════════════════════════════════════════════════
// BUILDER x GATE (KAT 7b ordering, KAT 12 parity) through NodeCoinState:
// select_work runs the builder, embedded_template_emit_ok the gate — two
// independent derivations of the same root.
// ════════════════════════════════════════════════════════════════════════
namespace {

std::vector<unsigned char> p2pkh(uint8_t seed)
{
    std::vector<unsigned char> s{0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(static_cast<unsigned char>(seed + i));
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

// A healthy DKG-window serving posture at the incident tip with ONE real
// commitment in the plan and an MN list of `n` entries.
void seed_gate(NodeCoinState& st, const CSimplifiedMNList& sml,
               const CFinalCommitment& qc)
{
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2'300'000;
    s.scriptPayout.m_data = p2pkh(0x30);
    s.payoutSplitProvenance = MNState::SPLIT_KNOWN;
    st.mnstates().load(std::vector<std::pair<uint256, MNState>>{{mn(0), s}});
    st.sml() = sml;
    st.set_have_sml(true);
    st.set_require_sml(true);
    st.set_sml_current_hash(kPrevHash);
    QcBlockPlan plan;
    plan.commitments = {qc};
    plan.merkle_root_quorums = hval(0x77, 7);
    st.set_qc_plan_fn([plan](uint32_t) { return std::optional<QcBlockPlan>{plan}; });
    st.set_tip(kPrevH, kPrevHash, 0x1b104be3u, 1'700'000'000u,
               kPubkeyVer, kP2shVer, 1'700'000'123u, 0x20000000u);
}

uint256 committed_mn_root(const DashWorkData& w)
{
    CCbTx cb;
    EXPECT_TRUE(dash::coin::vendor::parse_cbtx(w.m_coinbase_payload, cb));
    return cb.merkleRootMNList;
}

} // namespace

// KAT 12: a proven ban reaches the committed root, and the gate re-derives
// the same root independently. Mutation: remove the builder's pass call ->
// the committed root is the unfolded one and the gate refuses (root drift).
TEST(DashSmlPoseFoldGate, BuilderAndGateAgreeOnTheFoldedRoot)
{
    const CSimplifiedMNList sml = list_of(10);   // max 100, P 66
    auto qc = real_qc(1, qhash(1), 8);
    qc.validMembers[5] = false;                  // punishes mn(5)
    NodeCoinState st;
    seed_gate(st, sml, qc);
    // lo=hi=50 -> decay 49 -> +66 = 115 -> clamp 100 >= 100: banned.
    st.set_qc_pose_fold_inputs(
        members_table({{qhash(1), member_run(0, 8)}}),
        [](const uint256&) { return std::optional<PoSePenaltyView>{{50, 50, false}}; },
        [] { return std::optional<std::pair<uint32_t, uint256>>{{kPrevH, kPrevHash}}; });

    ASSERT_TRUE(st.describe_decline().viable) << st.describe_decline().one_line();
    WorkSelection sel = st.select_work([] { return DashWorkData{}; });
    ASSERT_EQ(sel.source, WorkSource::Embedded);
    EXPECT_EQ(committed_mn_root(sel.work), root_with_invalid(sml, {mn(5)}))
        << "the builder must commit the post-ban list (BanIfNotBanned -> "
           "isValid=false, deterministicmns.cpp:319-321)";
    DeclineReport why;
    EXPECT_TRUE(st.embedded_template_emit_ok(sel.work, &why)) << why.one_line();

    // A template committing the UNFOLDED root (what master's builder
    // committed) is refused by the gate.
    DashWorkData stale = sel.work;
    {
        CCbTx cb;
        ASSERT_TRUE(dash::coin::vendor::parse_cbtx(stale.m_coinbase_payload, cb));
        cb.merkleRootMNList = sml.CalcMerkleRoot();
        stale.m_coinbase_payload = dash::coin::encode_cbtx(cb);
    }
    DeclineReport why2;
    EXPECT_FALSE(st.embedded_template_emit_ok(stale, &why2));
    EXPECT_EQ(why2.cause, "emit-mnlist-root-drift");
}

// KAT 7b: dashd applies the block's txs in order, and the type-6 txs lead
// the body — so a PoSe ban by a commitment is followed by a ProUpServTx
// REVIVE in the same body: the MN ends VALID with its new service.
// Mutation: fold the provider txs before the PoSe pass -> the ban lands
// last, isValid=false, root differs -> red.
TEST(DashSmlPoseFoldGate, RevivingProUpServAfterQcBanOrdersLikeDashd)
{
    namespace v = dash::coin::vendor;
    const CSimplifiedMNList sml = list_of(10);
    auto qc = real_qc(1, qhash(1), 8);
    qc.validMembers[5] = false;
    NodeCoinState st;
    seed_gate(st, sml, qc);
    st.set_include_mn_special_txs(true);
    st.set_serve_mempool_txs(true);
    st.set_qc_pose_fold_inputs(
        members_table({{qhash(1), member_run(0, 8)}}),
        [](const uint256&) { return std::optional<PoSePenaltyView>{{50, 50, false}}; },
        [] { return std::optional<std::pair<uint32_t, uint256>>{{kPrevH, kPrevHash}}; });

    // A fee-paying ProUpServTx for mn(5) with a new service.
    ::core::coin::UTXOViewCache utxo(nullptr);
    v::CProUpServTx ups;
    ups.nVersion  = v::ProTxVersion::BASIC_BLS;
    ups.nType     = v::MnType::REGULAR;
    ups.proTxHash = mn(5);
    for (size_t b = 0; b < ups.netInfo.ip.size(); ++b)
        ups.netInfo.ip[b] = static_cast<uint8_t>(0x20 + b);
    ups.netInfo.port_be = 0x1027;
    ups.inputsHash = hval(0x88, 1);
    MutableTransaction tx;
    tx.version = 3; tx.type = 2;
    {
        const uint256 pv = hval(0x99, 1);
        utxo.add_coin(::core::coin::Outpoint(pv, 0),
                      ::core::coin::Coin(100'000, {}, 1, false));
        ::bitcoin_family::coin::TxIn in; in.prevout.hash = pv; in.prevout.index = 0;
        in.sequence = 0xffffffffu;
        tx.vin.push_back(in);
        ::bitcoin_family::coin::TxOut o; o.value = 90'000; o.scriptPubKey.m_data = p2pkh(0x33);
        tx.vout.push_back(o);
        auto ps = ::pack(ups); auto sp = ps.get_span();
        tx.extra_payload.assign(reinterpret_cast<const unsigned char*>(sp.data()),
                                reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    }
    st.mempool().set_utxo(&utxo);
    ASSERT_TRUE(st.mempool().add_tx(tx));

    WorkSelection sel = st.select_work([] { return DashWorkData{}; });
    ASSERT_EQ(sel.source, WorkSource::Embedded) << sel.decline.one_line();
    bool rode = false;
    for (const auto& h : sel.work.m_tx_hashes)
        if (h == dash::coin::dash_txid(tx)) rode = true;
    ASSERT_TRUE(rode) << "the ProUpServTx must ride the body for this KAT";

    // Independent reference: ban (pose) THEN revive + new service (ProUpServ).
    CSimplifiedMNList ref = sml;
    for (auto& e : ref.mnList)
        if (e.proRegTxHash == mn(5)) {
            e.netAddress = ups.netInfo.ip;
            e.netPort    = ups.netInfo.port_be;
            e.isValid    = true;
        }
    EXPECT_EQ(committed_mn_root(sel.work), ref.CalcMerkleRoot())
        << "ban-then-revive: the MN must end VALID (type-6 precedes type-2)";
    DeclineReport why;
    EXPECT_TRUE(st.embedded_template_emit_ok(sel.work, &why)) << why.one_line();
}
