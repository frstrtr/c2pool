// SPDX-License-Identifier: AGPL-3.0-or-later
///
/// THE SEAM — W4's derived quorum membership feeding W1's DML fold
/// (src/impl/dash/coin/replay_quorum_bridge.hpp).
///
/// The first live daemonless replay (2026-08-05, LAN archival peer VM210)
/// folded 129 consecutive byte-exact merkleRootMNList checks from anchor
/// h=2513000 and then failed closed at **h=2513130** — the first mainnet
/// block in that window whose mined qfcommits actually mark members invalid
/// (four llmq_60_75 commitments, quorumIndex 2/7/10/13, one invalid member
/// each) — because main_dash had no quorum-member resolver wired. These KATs
/// pin the closure of exactly that seam, against real mainnet bytes:
///
///  KAT-1  the pre-anchor snapshot seed parses, and its guard REFUSES any
///         cycle the replay could itself produce (anchor + 3·dkgInterval) —
///         a seed must never be able to stand in for a derivation.
///  KAT-2  the pre-anchor work-block list seed parses (four real work blocks
///         of mainnet llmq_60_75 cycle base 2513088) and refuses to seed a
///         height the replay folds itself.
///  KAT-3  DERIVATION: the 32 member lists of cycle base 2513088 computed by
///         the quarter-rotation port from those four replayed lists + the
///         three prior-cycle snapshots, matched proTxHash-for-proTxHash, IN
///         ORDER, against dashd's own `quorum info 5 <hash>` for the quorum
///         h=2513130's punishing commitment names (quorumIndex 2, quorumHash
///         = block 2513090).
///  KAT-4  THE SEAM HEIGHT: block 2513130 folded over the full-state prestate
///         at 2513129.
///           (a) with NO resolver → fails closed with the live run's exact
///               blocking condition;
///           (b) with the DERIVED lists from KAT-3 → folds, punishes 4, and
///               reproduces the block's own committed cbTx merkleRootMNList
///               byte-exact.
///         (a) also pins the "resolver demanded only when a member is
///         actually marked invalid" fix: the fold must reach tx[3] (the
///         FIRST punishing commitment), having folded the two all-valid
///         commitments in tx[1]/tx[2] with no member set at all.
///  KAT-5  the member-set size check is a BOUND, not an equality: a member
///         list shorter than the validMembers bitset (what dashd's own
///         GetAllQuorumMembers can return on a thin list) still folds to the
///         same committed root.
///  KAT-6  the bridge installs BOTH directions: with it in place the fold's
///         refusal changes from "no resolver installed" to "resolver has no
///         member set" (i.e. the MembersFn IS wired), the miss is named, and
///         the replayed list handed to the quorum lane carries the collateral
///         outpoint that makes the upstream score tiebreak decidable.
///
/// Fixture provenance (captured 2026-08-05 from the LAN archival mainnet
/// node VM210, Dash Core v23.1.7, read-only):
///   dash_replay_prestate_2513129.inc        protx list + protx diff @2513129
///   dash_replay_block_2513130.inc           getblock <hash> 0
///   dash_replay_quorum_2513090_idx2.inc     quorum info 5 <quorumHash idx 2>
///   dash_replay_seam_qsnap_2513088.inc      quorum rotationinfo <hash 2513088>
///   dash_replay_seam_workblocks_2513088.inc protx diff 1 H + getblock H 2,
///                                           H ∈ {2513080, 2512792, 2512504,
///                                                2512216}

#include <gtest/gtest.h>

#include <impl/dash/coin/replay_quorum_bridge.hpp>
#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/replay_prestate.hpp>
#include <impl/dash/coin/replay_quorum_engine.hpp>
#include <impl/dash/coin/dkg_commitments.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/block.hpp>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "data/dash_replay_prestate_2513129.inc"
#include "data/dash_replay_block_2513130.inc"
#include "data/dash_replay_quorum_2513090_idx2.inc"
#include "data/dash_replay_seam_qsnap_2513088.inc"
#include "data/dash_replay_seam_workblocks_2513088.inc"

using dash::coin::BlockType;
using dash::coin::kLlmq60_75;
using dash::coin::LlmqNetwork;
using dash::coin::replay::DmlFoldEngine;
using dash::coin::replay::FoldConfig;
using dash::coin::replay::QSnapshotSeed;
using dash::coin::replay::QuorumBridgeConfig;
using dash::coin::replay::QuorumMnEntry;
using dash::coin::replay::QuorumReplayConfig;
using dash::coin::replay::QuorumReplayEngine;
using dash::coin::replay::ReplayQuorumBridge;
using dash::coin::replay::RotationCycleInput;
using dash::coin::replay::WorkListSeed;
using dash::coin::replay::compute_rotation_cycle;
using dash::coin::replay::kWorkDiffDepth;
using dash::coin::replay::load_qsnapshot_seed_file;      // (unused ODR anchor)
using dash::coin::replay::parse_prestate_text;
using dash::coin::replay::parse_qsnapshot_seed_text;
using dash::coin::replay::parse_work_list_seed_text;
using dash::coin::replay::seed_engine_from_prestate;
using dash::coin::vendor::CFinalCommitmentTxPayload;
using dash::coin::vendor::CQuorumSnapshot;
using dash::coin::vendor::parse_qfcommit_payload;

namespace {

constexpr uint32_t kAnchor      = 2'513'129;  // prestate height
constexpr uint32_t kSeamHeight  = 2'513'130;  // where the live run stopped
constexpr uint32_t kCycleBase   = 2'513'088;  // llmq_60_75 cycle of that batch
constexpr uint32_t kC           = 288;        // llmq_60_75 dkgInterval
constexpr uint8_t  kType6075    = 5;
constexpr int16_t  kPunishIndex = 2;          // first punishing quorumIndex
/// Block 2513130's own committed cbTx merkleRootMNList.
constexpr const char* kRoot2513130 =
    "2315e6dfcd7e3256288d73aa8a2022395561f7625da2b20d0eedde22622d120b";

std::vector<std::string> split_ws(const std::string& line)
{
    std::vector<std::string> out;
    std::istringstream is(line);
    std::string tok;
    while (is >> tok) out.push_back(tok);
    return out;
}

bool hex_to_bytes(const std::string& h, std::vector<uint8_t>& out)
{
    if (h.size() % 2 != 0) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    out.reserve(h.size() / 2);
    for (size_t i = 0; i < h.size(); i += 2) {
        const int hi = nib(h[i]), lo = nib(h[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

uint256 u256_wire(const std::string& hex)
{
    uint256 v;
    std::vector<uint8_t> b;
    EXPECT_TRUE(hex_to_bytes(hex, b));
    EXPECT_EQ(b.size(), 32u);
    if (b.size() == 32) std::memcpy(v.data(), b.data(), 32);
    return v;
}

uint256 from_display(const char* hex)
{
    uint256 v;
    v.SetHex(hex);
    return v;
}

BlockType parse_block(const char* hex_text)
{
    std::string hex;
    for (const char* p = hex_text; *p; ++p)
        if (*p != '\n' && *p != '\r') hex.push_back(*p);
    std::vector<uint8_t> bytes;
    EXPECT_TRUE(hex_to_bytes(hex, bytes));
    BlockType b;
    ::PackStream s(bytes);
    s >> b;
    EXPECT_TRUE(s.empty()) << "trailing bytes after block";
    return b;
}

/// Seed the mainnet anchor's FULL active set (h=2513685, 88 commitments —
/// 24+32+4+4+24) into a quorum engine. Same fixture the W4 engine KAT uses;
/// columns are `type qidx base_height quorumHash commitment_hex`. This is the
/// state that makes active_sets_complete() true, i.e. the exact precondition
/// the removed auto-arm keyed on.
size_t seed_anchor_active_set(QuorumReplayEngine& eng)
{
    const std::string path = std::string(DASH_FIXTURE_DIR)
                           + "/dash_mainnet_active_quorums_2513685.txt";
    std::ifstream f(path);
    EXPECT_TRUE(f.good()) << "cannot open fixture: " << path;
    std::string line;
    size_t n = 0;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto fl = split_ws(line);
        EXPECT_EQ(fl.size(), 5u) << line.substr(0, 80);
        if (fl.size() != 5) continue;
        std::vector<uint8_t> bytes;
        EXPECT_TRUE(hex_to_bytes(fl[4], bytes));
        dash::coin::vendor::CFinalCommitment c;
        ::PackStream s(bytes);
        s >> c;
        EXPECT_EQ(s.cursor_size(), 0u) << "commitment slice must parse exact";
        std::string err;
        EXPECT_TRUE(eng.seed_commitment(
            static_cast<uint32_t>(std::stoul(fl[2])), c, err)) << err;
        ++n;
    }
    return n;
}

/// dashd `quorum info` member order IS the DKG order the validMembers bitset
/// indexes (fixture format `c2pool-dash-replay-quorum/1`).
struct QuorumInfoFixture {
    uint8_t              llmq_type{0};
    std::string          quorum_hash_display;
    std::vector<uint256> members;
};

QuorumInfoFixture parse_quorum_info(const char* text)
{
    QuorumInfoFixture fx;
    std::istringstream is(text);
    std::string line;
    EXPECT_TRUE(std::getline(is, line));
    EXPECT_EQ(line, "c2pool-dash-replay-quorum/1");
    while (std::getline(is, line)) {
        auto f = split_ws(line);
        if (f.empty()) continue;
        if (f[0] == "llmqType") {
            fx.llmq_type = static_cast<uint8_t>(std::stoul(f[1]));
        } else if (f[0] == "quorumHash") {
            fx.quorum_hash_display = f[1];
        } else if (f[0] == "member") {
            fx.members.push_back(u256_wire(f[1]));
        }
    }
    return fx;
}

DmlFoldEngine seed_engine_at_2513129()
{
    FoldConfig cfg;
    cfg.enabled = true;
    DmlFoldEngine eng(cfg);
    auto ps = parse_prestate_text(kDashReplayPrestate2513129);
    EXPECT_TRUE(ps.ok) << ps.error;
    const std::string err = seed_engine_from_prestate(eng, ps);
    EXPECT_TRUE(err.empty()) << err;
    EXPECT_EQ(eng.height(), kAnchor);
    return eng;
}

/// Every type-6 payload of block 2513130, in tx order (tx index kept: the
/// fold names it in its refusal, and KAT-4a asserts WHICH one it reaches).
struct BlockCommitments {
    std::vector<std::pair<size_t, CFinalCommitmentTxPayload>> items;
};

BlockCommitments commitments_of(const BlockType& b)
{
    BlockCommitments out;
    for (size_t i = 1; i < b.m_txs.size(); ++i) {
        const auto& tx = b.m_txs[i];
        if (tx.version != 3 || tx.type != 6) continue;
        CFinalCommitmentTxPayload qc;
        EXPECT_TRUE(parse_qfcommit_payload(tx.extra_payload, qc));
        out.items.emplace_back(i, std::move(qc));
    }
    return out;
}

/// The four work-block lists of cycle 2513088, as the derivation consumes
/// them, keyed by CYCLE BASE (base − 8 is the work height in the fixture).
struct SeamInputs {
    WorkListSeed  works;
    QSnapshotSeed snaps;
};

SeamInputs load_seam_inputs()
{
    SeamInputs in;
    in.works = parse_work_list_seed_text(kDashReplaySeamWorkBlocks2513088);
    EXPECT_TRUE(in.works.ok) << in.works.error;
    in.snaps = parse_qsnapshot_seed_text(kDashReplaySeamQSnapshots2513088);
    EXPECT_TRUE(in.snaps.ok) << in.snaps.error;
    return in;
}

const dash::coin::replay::WorkListSeedEntry* work_for(const WorkListSeed& s,
                                                      uint32_t cycle_base)
{
    for (const auto& w : s.works)
        if (w.cycle_base == cycle_base) return &w;
    return nullptr;
}

const CQuorumSnapshot* snap_for(const QSnapshotSeed& s, uint32_t cycle_base)
{
    for (const auto& e : s.entries)
        if (e.cycle_base == cycle_base) return &e.snapshot;
    return nullptr;
}

/// Run the DIP-0024 quarter rotation for cycle base 2513088 from the real
/// captured inputs. Returns the 32 ordered member lists.
std::vector<std::vector<uint256>> derive_cycle_2513088(const SeamInputs& in)
{
    std::array<const dash::coin::replay::WorkListSeedEntry*, 4> w{
        work_for(in.works, kCycleBase),
        work_for(in.works, kCycleBase - kC),
        work_for(in.works, kCycleBase - 2 * kC),
        work_for(in.works, kCycleBase - 3 * kC)};
    std::array<const CQuorumSnapshot*, 3> snaps{
        snap_for(in.snaps, kCycleBase - kC),
        snap_for(in.snaps, kCycleBase - 2 * kC),
        snap_for(in.snaps, kCycleBase - 3 * kC)};
    for (size_t i = 0; i < w.size(); ++i)
        EXPECT_NE(w[i], nullptr) << "missing work list " << i;
    for (size_t i = 0; i < snaps.size(); ++i)
        EXPECT_NE(snaps[i], nullptr) << "missing snapshot " << i;
    if (!w[0] || !w[1] || !w[2] || !w[3] || !snaps[0] || !snaps[1] || !snaps[2])
        return {};

    std::array<RotationCycleInput, 4> cycles;
    for (size_t i = 0; i < 4; ++i) {
        std::optional<std::array<uint8_t,
            dash::coin::vendor::CCbTx::BLS_SIG_SIZE>> cl;
        if (w[i]->has_cl) cl = w[i]->cl_sig;
        cycles[i].mn_list  = &w[i]->entries;
        cycles[i].modifier = dash::coin::vendor::compute_quorum_modifier(
            kType6075, w[i]->work_height, cl, w[i]->block_hash);
    }
    std::string err;
    auto out = compute_rotation_cycle(kLlmq60_75, cycles, snaps, &err);
    EXPECT_TRUE(out.has_value()) << err;
    if (!out) return {};
    return out->member_protx;
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// KAT-1 — the snapshot seed and its "never stand in for a derivation" guard
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashReplayQuorumSeam, QSnapshotSeedParsesRealRotationInfoCapture)
{
    auto seed = parse_qsnapshot_seed_text(kDashReplaySeamQSnapshots2513088);
    ASSERT_TRUE(seed.ok) << seed.error;
    EXPECT_EQ(seed.network, "mainnet");
    ASSERT_EQ(seed.entries.size(), 3u);
    // rotationinfo at cycle base 2513088 carries H−C / H−2C / H−3C.
    EXPECT_EQ(seed.entries[0].cycle_base, kCycleBase - kC);
    EXPECT_EQ(seed.entries[1].cycle_base, kCycleBase - 2 * kC);
    EXPECT_EQ(seed.entries[2].cycle_base, kCycleBase - 3 * kC);
    for (const auto& e : seed.entries) {
        EXPECT_EQ(e.llmq_type, kType6075);
        EXPECT_TRUE(e.snapshot.sane());
        // A real mainnet cycle bitset is one bit per MN in the work list.
        EXPECT_GT(e.snapshot.activeQuorumMembers.size(), 2000u);
    }
}

TEST(DashReplayQuorumSeam, QSnapshotSeedRefusesMalformedInput)
{
    EXPECT_FALSE(parse_qsnapshot_seed_text("").ok);
    EXPECT_FALSE(parse_qsnapshot_seed_text("wrong-tag\n").ok);
    auto bad_bits = parse_qsnapshot_seed_text(
        "c2pool-dash-replay-qsnapshot/1\nsnapshot 5 100 0 0102 0\n");
    EXPECT_FALSE(bad_bits.ok);
    EXPECT_NE(bad_bits.error.find("activeQuorumMembers"), std::string::npos)
        << bad_bits.error;
    auto short_skips = parse_qsnapshot_seed_text(
        "c2pool-dash-replay-qsnapshot/1\nsnapshot 5 100 1 0101 3 7\n");
    EXPECT_FALSE(short_skips.ok);
    EXPECT_NE(short_skips.error.find("skip"), std::string::npos)
        << short_skips.error;
}

TEST(DashReplayQuorumSeam, QSnapshotSeedRefusesCyclesTheReplayCouldProduce)
{
    auto seed = parse_qsnapshot_seed_text(kDashReplaySeamQSnapshots2513088);
    ASSERT_TRUE(seed.ok) << seed.error;

    FoldConfig fcfg; fcfg.enabled = true;
    DmlFoldEngine dml(fcfg);
    QuorumReplayConfig qcfg; qcfg.enabled = true;
    QuorumReplayEngine quorum(qcfg);
    ReplayQuorumBridge bridge(dml, quorum);

    // Anchor 2512200: every seeded base is below anchor + 3·288 = 2513064,
    // so the replay genuinely cannot produce them — accepted.
    std::string err;
    EXPECT_TRUE(bridge.seed_snapshots(seed, 2'512'200u, err)) << err;
    EXPECT_EQ(bridge.seeded_snapshot_count(), 3u);
    // …and that is exactly the anchor from which cycle 2513088 — the cycle
    // h=2513130's punishing commitments belong to — is the replay's own.
    EXPECT_EQ(bridge.self_contained_from(kType6075, 2'512'200u), kCycleBase);

    // Anchor 2510000: 2510000 + 864 = 2510864 ≤ every seeded base, so all
    // three are the replay's to PRODUCE and seeding them is refused by name.
    DmlFoldEngine dml2(fcfg);
    QuorumReplayEngine quorum2(qcfg);
    ReplayQuorumBridge bridge2(dml2, quorum2);
    std::string err2;
    EXPECT_FALSE(bridge2.seed_snapshots(seed, 2'510'000u, err2));
    EXPECT_NE(err2.find("PRODUCE"), std::string::npos) << err2;
    EXPECT_EQ(bridge2.seeded_snapshot_count(), 0u);
}

TEST(DashReplayQuorumSeam, QSnapshotSeedRefusesNonRotatedTypes)
{
    // llmq_100_67 (type 4) is not rotated: its membership is computed from
    // the replayed list alone and a snapshot could only mislead.
    auto seed = parse_qsnapshot_seed_text(
        "c2pool-dash-replay-qsnapshot/1\nsnapshot 4 2512224 0 0101 0\n");
    ASSERT_TRUE(seed.ok) << seed.error;
    FoldConfig fcfg; fcfg.enabled = true;
    DmlFoldEngine dml(fcfg);
    QuorumReplayConfig qcfg; qcfg.enabled = true;
    QuorumReplayEngine quorum(qcfg);
    ReplayQuorumBridge bridge(dml, quorum);
    std::string err;
    EXPECT_FALSE(bridge.seed_snapshots(seed, 2'512'200u, err));
    EXPECT_NE(err.find("NOT rotated"), std::string::npos) << err;
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT-2 — the pre-anchor work-block list seed
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashReplayQuorumSeam, WorkListSeedParsesFourRealWorkBlocks)
{
    auto s = parse_work_list_seed_text(kDashReplaySeamWorkBlocks2513088);
    ASSERT_TRUE(s.ok) << s.error;
    EXPECT_EQ(s.llmq_type, kType6075);
    EXPECT_EQ(s.cycle_base, kCycleBase);
    EXPECT_EQ(s.interval, kC);
    ASSERT_EQ(s.works.size(), 4u);
    for (const auto& w : s.works) {
        EXPECT_EQ(w.work_height + kWorkDiffDepth, w.cycle_base);
        EXPECT_TRUE(w.has_cl) << "post-V20 work block must carry a cbTx CL";
        EXPECT_GT(w.entries.size(), 2000u);
        // SML-fed: no collateral, so an upstream score TIE fails closed
        // rather than being guessed.
        EXPECT_FALSE(w.entries.front().has_collateral);
    }
    EXPECT_FALSE(parse_work_list_seed_text("nope\n").ok);
}

TEST(DashReplayQuorumSeam, WorkListSeedRefusesHeightsTheReplayFoldsItself)
{
    auto s = parse_work_list_seed_text(kDashReplaySeamWorkBlocks2513088);
    ASSERT_TRUE(s.ok) << s.error;

    FoldConfig fcfg; fcfg.enabled = true;
    DmlFoldEngine dml(fcfg);
    QuorumReplayConfig qcfg; qcfg.enabled = true;
    QuorumReplayEngine quorum(qcfg);
    ReplayQuorumBridge bridge(dml, quorum);

    // Anchor below every work height: nothing is pre-anchor, so the seed is
    // refused outright rather than silently overriding the replay's own fold.
    std::string err;
    EXPECT_FALSE(bridge.seed_work_lists(s, 2'512'200u, err));
    EXPECT_NE(err.find("PRE-anchor"), std::string::npos) << err;
    EXPECT_EQ(bridge.seeded_work_list_count(), 0u);

    // Anchor AT 2513080: the three older work blocks are pre-anchor and are
    // seeded; 2513080 is at the anchor, i.e. the replay's own, and is left
    // alone (the seed file legitimately carries the whole cycle set).
    ReplayQuorumBridge bridge2(dml, quorum);
    std::string err2;
    EXPECT_TRUE(bridge2.seed_work_lists(s, 2'513'080u, err2)) << err2;
    EXPECT_EQ(bridge2.seeded_work_list_count(), 3u);
    EXPECT_TRUE(bridge2.mn_list_at(2'512'792u).has_value());
    EXPECT_FALSE(bridge2.mn_list_at(2'513'080u).has_value());
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT-3 — DERIVATION: cycle 2513088 members vs dashd's own `quorum info`
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashReplayQuorumSeam, DerivesCycle2513088MembersMatchingDashd)
{
    auto in = load_seam_inputs();
    auto derived = derive_cycle_2513088(in);
    ASSERT_EQ(derived.size(),
              static_cast<size_t>(kLlmq60_75.signing_active_quorum_count));

    auto want = parse_quorum_info(kDashReplayQuorumMembers2513090Idx2);
    EXPECT_EQ(want.llmq_type, kType6075);
    ASSERT_EQ(want.members.size(), static_cast<size_t>(kLlmq60_75.size));

    // quorumIndex 2 of cycle base 2513088 ⇒ quorum base block 2513090, which
    // is the quorumHash h=2513130's first punishing commitment names.
    const auto& got = derived[static_cast<size_t>(kPunishIndex)];
    ASSERT_EQ(got.size(), want.members.size());
    for (size_t i = 0; i < want.members.size(); ++i)
        EXPECT_EQ(got[i].GetHex(), want.members[i].GetHex())
            << "member #" << i << " of llmq_60_75 cycle 2513088 index 2";
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT-4 — h=2513130, the height the live run stopped at
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashReplayQuorumSeam, Height2513130FailsClosedWithoutAResolver)
{
    auto eng = seed_engine_at_2513129();
    auto blk = parse_block(kDashReplayBlock2513130);
    auto cmts = commitments_of(blk);
    ASSERT_EQ(cmts.items.size(), 32u) << "the whole llmq_60_75 batch";

    // The FIRST commitment that marks a member invalid — the fold must reach
    // it, not stop at the all-valid ones before it. (On a fold that demands a
    // resolver for every non-null commitment this is tx[1], quorumIndex 0.)
    size_t first_punishing_tx = 0;
    for (const auto& [tx_i, qc] : cmts.items) {
        if (qc.commitment.CountValidMembers()
                != qc.commitment.validMembers.size()) {
            first_punishing_tx = tx_i;
            break;
        }
    }
    ASSERT_EQ(first_punishing_tx, 3u)
        << "quorumIndex 2 is the first punishing commitment in this block";

    auto r = eng.fold_block(blk, kSeamHeight);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.error.find("no quorum-member resolver is installed"),
              std::string::npos) << r.error;
    // 470 of 595 non-null commitments in the 2513001..2516851 window mark
    // nobody invalid; demanding membership there would have stalled the live
    // run at h=2513003 instead of h=2513130.
    EXPECT_NE(r.error.find("tx[3]"), std::string::npos)
        << "the fold must have folded tx[1] and tx[2] (all-valid, dashd's "
           "punish loop is a provable no-op there) with no member set: "
        << r.error;
    EXPECT_NE(r.error.find("llmqType=5"), std::string::npos) << r.error;
}

TEST(DashReplayQuorumSeam, Height2513130FoldsThroughDerivedMembership)
{
    auto in = load_seam_inputs();
    auto derived = derive_cycle_2513088(in);
    ASSERT_EQ(derived.size(),
              static_cast<size_t>(kLlmq60_75.signing_active_quorum_count));

    auto eng = seed_engine_at_2513129();
    auto blk = parse_block(kDashReplayBlock2513130);
    auto cmts = commitments_of(blk);

    // quorumHash → quorumIndex, taken from the block's own commitments; the
    // index is the offset from the cycle base, which KAT-3 pinned against
    // dashd for index 2.
    std::map<std::string, int16_t> index_of;
    size_t punishing = 0;
    for (const auto& [tx_i, qc] : cmts.items) {
        (void)tx_i;
        index_of[qc.commitment.quorumHash.GetHex()] = qc.commitment.quorumIndex;
        if (qc.commitment.CountValidMembers()
                != qc.commitment.validMembers.size())
            ++punishing;
    }
    ASSERT_EQ(punishing, 4u) << "quorumIndex 2/7/10/13 each mark one member "
                                "invalid at h=2513130";

    size_t answered = 0;
    eng.set_members_fn([&](uint8_t type, const uint256& qh)
                           -> std::optional<std::vector<uint256>> {
        if (type != kType6075) return std::nullopt;
        auto it = index_of.find(qh.GetHex());
        if (it == index_of.end()) return std::nullopt;
        const size_t idx = static_cast<size_t>(it->second);
        if (idx >= derived.size()) return std::nullopt;
        ++answered;
        return derived[idx];   // DERIVED, not captured
    });

    auto r = eng.fold_block(blk, kSeamHeight);
    ASSERT_TRUE(r.ok) << r.error;
    // THE assertion: the block's own committed answer key.
    EXPECT_EQ(r.committed_root.GetHex(), kRoot2513130);
    EXPECT_EQ(r.computed_root.GetHex(), kRoot2513130);
    EXPECT_EQ(r.punished, punishing);
    EXPECT_EQ(answered, punishing)
        << "the resolver must be consulted exactly for the commitments that "
           "mark a member invalid";
    EXPECT_EQ(eng.height(), kSeamHeight);
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT-5 — the member-set size check is a BOUND, not an equality
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashReplayQuorumSeam, ShorterMemberListThanBitsetStillFolds)
{
    auto in = load_seam_inputs();
    auto derived = derive_cycle_2513088(in);
    ASSERT_FALSE(derived.empty());

    auto eng = seed_engine_at_2513129();
    auto blk = parse_block(kDashReplayBlock2513130);
    auto cmts = commitments_of(blk);

    // dashd HandleQuorumCommitment iterates members.size() and indexes
    // validMembers[i]; GetAllQuorumMembers may return FEWER than params.size
    // on a thin list. Truncate every derived list to just past the LAST
    // invalid-marked index — no punish dashd applies can be lost, so the
    // committed root must still reproduce byte-exact.
    size_t keep = 1;
    std::map<std::string, int16_t> index_of;
    for (const auto& [tx_i, qc] : cmts.items) {
        (void)tx_i;
        index_of[qc.commitment.quorumHash.GetHex()] = qc.commitment.quorumIndex;
        for (size_t i = 0; i < qc.commitment.validMembers.size(); ++i)
            if (!qc.commitment.validMembers[i]) keep = std::max(keep, i + 1);
    }
    ASSERT_LT(keep, static_cast<size_t>(kLlmq60_75.size))
        << "this KAT needs a strictly shorter list to be meaningful";

    eng.set_members_fn([&](uint8_t type, const uint256& qh)
                           -> std::optional<std::vector<uint256>> {
        if (type != kType6075) return std::nullopt;
        auto it = index_of.find(qh.GetHex());
        if (it == index_of.end()) return std::nullopt;
        auto v = derived[static_cast<size_t>(it->second)];
        v.resize(keep);
        return v;
    });

    auto r = eng.fold_block(blk, kSeamHeight);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.computed_root.GetHex(), kRoot2513130);
    EXPECT_EQ(r.punished, 4u);
}

TEST(DashReplayQuorumSeam, MemberListOverrunningTheBitsetIsStillRefused)
{
    auto eng = seed_engine_at_2513129();
    auto blk = parse_block(kDashReplayBlock2513130);
    eng.set_members_fn([](uint8_t, const uint256&)
                           -> std::optional<std::vector<uint256>> {
        return std::vector<uint256>(500);   // longer than any bitset
    });
    auto r = eng.fold_block(blk, kSeamHeight);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.error.find("OVERRUNS"), std::string::npos) << r.error;
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT-6 — the bridge installs BOTH directions
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashReplayQuorumSeam, BridgeInstallsTheResolverAndNamesAMiss)
{
    FoldConfig fcfg; fcfg.enabled = true;
    DmlFoldEngine dml(fcfg);
    auto ps = parse_prestate_text(kDashReplayPrestate2513129);
    ASSERT_TRUE(ps.ok) << ps.error;
    ASSERT_TRUE(seed_engine_from_prestate(dml, ps).empty());

    QuorumReplayConfig qcfg;
    qcfg.enabled = true;
    QuorumReplayEngine quorum(qcfg);
    QuorumBridgeConfig bcfg;
    bcfg.network = LlmqNetwork::Mainnet;
    ReplayQuorumBridge bridge(dml, quorum, bcfg);

    // Direction 1: the fold now HAS a resolver — the refusal changes from
    // "no resolver installed" (the live run's stop at h=2513130) to a named
    // derivation miss. That difference is the whole seam.
    auto r = dml.fold_block(parse_block(kDashReplayBlock2513130), kSeamHeight);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.error.find("no quorum-member resolver is installed"),
              std::string::npos) << r.error;
    EXPECT_NE(r.error.find("resolver has no member set"), std::string::npos)
        << r.error;
    EXPECT_EQ(bridge.stats().members_missing, 1u);
    EXPECT_NE(bridge.stats().first_member_miss.find("llmqType=5"),
              std::string::npos) << bridge.stats().first_member_miss;

    // Direction 2: the quorum lane's MN-list source is the REPLAYED list —
    // and it carries the collateral outpoint, so the upstream score tiebreak
    // is decidable (an SML-fed list cannot do this).
    bridge.prime_at_anchor();
    auto list = bridge.mn_list_at(kAnchor);
    ASSERT_TRUE(list.has_value());
    EXPECT_EQ(list->size(), dml.entries().size());
    EXPECT_TRUE(list->front().has_collateral);
    bool any_confirmed = false;
    for (const auto& e : *list)
        if (!e.confirmedHash.IsNull()) { any_confirmed = true; break; }
    EXPECT_TRUE(any_confirmed);
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT-7 — ISSUE #90: the bridge NEVER arms the root self-check by itself.
//
// One revision of replay_quorum_bridge.hpp armed QuorumReplayEngine's root
// self-check from inside observe(), the moment active_sets_complete() went
// true. That was the only change in PR-2 not behind
// --replay-mined-commitment-index: it rides the PRE-EXISTING
// --replay-fold-quorums. And arming is not a diagnostic — once armed, a
// merkleRootQuorums differ POISONS the engine (observe_block's m_self_check
// branch), a poisoned engine answers no member sets, the fold stops, the
// replay payee publisher stops publishing and the node STOPS SERVING. It was
// argued inert on mainnet because type 1 is short by 24 forever, which is a
// fact about the chain, not about this code.
//
// So the arming half now belongs to #90's own PR, behind its own default-OFF
// flag. THIS KAT holds the line: a COMPLETE active set — the trigger — must
// not arm anything, and neither must an observation the engine refused (the
// removed code sat BEFORE `if (!r.ok) return r.error;`, so it armed on a
// refusal too).
//
// RED: put back
//     if (!m_quorum.self_check_armed() && m_quorum.active_sets_complete())
//         m_quorum.arm_self_check();
// anywhere in ReplayQuorumBridge::observe.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashReplayQuorumSeam, BridgeNeverArmsTheRootSelfCheckByItself)
{
    FoldConfig fcfg; fcfg.enabled = true;
    DmlFoldEngine dml(fcfg);
    auto ps = parse_prestate_text(kDashReplayPrestate2513129);
    ASSERT_TRUE(ps.ok) << ps.error;
    ASSERT_TRUE(seed_engine_from_prestate(dml, ps).empty());

    QuorumReplayConfig qcfg;
    qcfg.enabled = true;
    qcfg.network = LlmqNetwork::Mainnet;
    QuorumReplayEngine quorum(qcfg);
    QuorumBridgeConfig bcfg;
    bcfg.network = LlmqNetwork::Mainnet;
    ReplayQuorumBridge bridge(dml, quorum, bcfg);

    // THE TRIGGER, present and true: every chainparams type at its full
    // active quota. Nothing weaker than this ever armed the old code.
    ASSERT_EQ(seed_anchor_active_set(quorum), 88u);
    ASSERT_TRUE(quorum.active_sets_complete())
        << "shortfall: " << quorum.active_set_shortfall_text();
    EXPECT_EQ(bridge.active_set_shortfall_text(), "complete");
    ASSERT_FALSE(bridge.self_check_armed());

    const auto blk = parse_block(kDashReplayBlock2513130);
    // Window key only; nothing under test reads it.
    const uint256 observed_hash =
        from_display("0000000000000000000000000000000000000000000000000000000000513130");

    // ── Arm 1: an observation the ENGINE REFUSES (no seeded cursor). The
    //    removed auto-arm ran before the !r.ok return, so this refused block
    //    armed the consensus check anyway.
    const std::string refused = bridge.observe(kSeamHeight, observed_hash, blk);
    ASSERT_FALSE(refused.empty())
        << "precondition: an unseeded engine must refuse this observation";
    EXPECT_FALSE(bridge.self_check_armed())
        << "a REFUSED observation must not arm the root self-check: " << refused;

    // ── Arm 2: a real observation, cursor seeded, the fold actually runs.
    quorum.seed_cursor(kAnchor, from_display(ps.blockhash_display.c_str()));
    bridge.observe(kSeamHeight, observed_hash, blk);
    EXPECT_FALSE(bridge.self_check_armed())
        << "observing a block with a COMPLETE active set must not arm the "
           "root self-check — arming can stop serving and belongs behind its "
           "own flag (issue #90)";
    EXPECT_FALSE(quorum.self_check_armed());

    // ── Anti-vacuity: the flag IS reachable, and only an explicit caller
    //    reaches it. Without this the EXPECT_FALSEs above could be measuring
    //    an observable that is never true for unrelated reasons.
    quorum.arm_self_check();
    EXPECT_TRUE(bridge.self_check_armed())
        << "arm_self_check() is the ONLY door, and it must still work";
}
