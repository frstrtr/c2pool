// SPDX-License-Identifier: AGPL-3.0-or-later
//
// W4 of the DASH FULL-HISTORY REPLAY mode — the quorum lane
// (src/impl/dash/coin/replay_quorum_engine.hpp): reconstruct quorum state
// purely from replayed mined qfcommits, no qrinfo P2P dependency.
//
// THE THREE MAINNET KATS (all against REAL chain-committed bytes)
// ---------------------------------------------------------------
// KAT-A  merkleRootQuorums replay: seed the engine with the 88-commitment
//        active set at h=2513685 (captured via a genesis-based mnlistdiff
//        from a mainnet dashd; includes the 24 FROZEN LLMQ_50_60
//        commitments from the 1738xxx DIP0024 era — they never leave the
//        committed root), then replay 3101 consecutive mainnet blocks
//        (2513686..2516786, 702 type-6 payloads) and byte-match the folded
//        merkleRootQuorums against EVERY block's committed cbTx root. 3101
//        consecutive equalities cover both active-set selection rules and
//        every in-block fold rule (rotated index-replace, non-rotated
//        oldest-eviction, null skip) across ~340 commitment-carrying
//        blocks.
// KAT-B  rotated (DIP-0024 llmq_60_75) membership: compute all 32 member
//        lists for real cycle base 2516544 from replay-shaped inputs (SMLs
//        at the work blocks + prior-cycle snapshots + V20 CL modifiers) and
//        match dashd's own ordered member lists (`quorum info`, captured
//        for every quorumIndex) — proTxHash by proTxHash, in order.
// KAT-C  the snapshot PRODUCER (the piece that replaces the qrinfo port):
//        produce the CQuorumSnapshot for cycle base 2516256 from the three
//        cycles before it and byte-match dashd's own served snapshot for
//        that cycle (skip mode + active bitset + skip list) — then feed OUR
//        produced snapshot back into the member computation for 2516544 and
//        reproduce dashd's members again (the self-sustaining recurrence
//        that makes the qrinfo dependency unnecessary).
//
// Fixture provenance (captured 2026-08-05 from a mainnet Dash Core v23
// node, read-only):
//   dash_mainnet_active_quorums_2513685.txt   — mnlistdiff(genesis→2513685)
//       newQuorums: "type qidx base_height quorumHash commitment_hex", the
//       commitment hex being the BYTE-EXACT wire slice; base heights
//       RPC-resolved (getblockheader)
//   dash_mainnet_quorum_scan_2513685_2516786.txt — per block:
//       "height blockHash merkleRootQuorums bestCLSignature|- qcPayloads|-"
//   dash_mainnet_qrinfo_2516785.bin           — getqrinfo(extraShare=true)
//       at block 2516785 (cycle base 2516544), decoded by the PRODUCTION
//       decoder and DIP-4-authenticated below
//   dash_mainnet_quorum_members_60_75_2516544.txt — `quorum info 5 <hash>`:
//       "quorumIndex height quorumHash protx0 .. protx59" for all 32 slots

#include <gtest/gtest.h>

#include <impl/dash/coin/replay_quorum_engine.hpp>
#include <impl/dash/coin/dkg_commitments.hpp>
#include <impl/dash/coin/quorum_root.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/vendor/quorum_rotation_info.hpp>
#include <impl/dash/coin/vendor/smldiff.hpp>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <array>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

using dash::coin::LlmqNetwork;
using dash::coin::LlmqParamsView;
using dash::coin::kLlmq50_60;
using dash::coin::kLlmq60_75;
using dash::coin::hash_commitment;
using dash::coin::compute_merkle_root_local;
using dash::coin::vendor::CFinalCommitment;
using dash::coin::vendor::CFinalCommitmentTxPayload;
using dash::coin::vendor::CQuorumRotationInfo;
using dash::coin::vendor::CQuorumSnapshot;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListDiff;
using dash::coin::vendor::CSimplifiedMNListEntry;
using dash::coin::vendor::decode_quorum_rotation_info;
using dash::coin::replay::QuorumBlockInput;
using dash::coin::replay::QuorumMnEntry;
using dash::coin::replay::QuorumObserveResult;
using dash::coin::replay::QuorumReplayConfig;
using dash::coin::replay::QuorumReplayEngine;
using dash::coin::replay::RotationCycleInput;
using dash::coin::replay::RotationCycleOutput;
using dash::coin::replay::compute_rotation_cycle;
using dash::coin::replay::kWorkDiffDepth;

namespace {

constexpr uint32_t kSeedHeight = 2513685;   // KAT-A anchor
constexpr uint32_t kCycleBase  = 2516544;   // KAT-B llmq_60_75 cycle base
constexpr uint32_t kC          = 288;       // llmq_60_75 dkgInterval
constexpr uint8_t  kType6075   = 5;

std::vector<uint8_t> from_hex(const std::string& h)
{
    std::vector<uint8_t> out;
    out.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        int hi = nib(h[i]), lo = nib(h[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::optional<CFinalCommitment> parse_commitment_hex(const std::string& hex)
{
    auto bytes = from_hex(hex);
    if (bytes.empty()) return std::nullopt;
    try {
        ::PackStream s(bytes);
        CFinalCommitment c;
        s >> c;
        if (s.cursor_size() != 0) return std::nullopt;
        return c;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<CFinalCommitmentTxPayload> parse_qc_payload_hex(const std::string& hex)
{
    auto bytes = from_hex(hex);
    if (bytes.empty()) return std::nullopt;
    CFinalCommitmentTxPayload qc;
    std::vector<unsigned char> b(bytes.begin(), bytes.end());
    if (!dash::coin::vendor::parse_qfcommit_payload(b, qc)) return std::nullopt;
    return qc;
}

std::vector<std::string> read_lines(const std::string& name)
{
    const std::string path = std::string(DASH_FIXTURE_DIR) + "/" + name;
    std::ifstream f(path);
    EXPECT_TRUE(f.good()) << "cannot open fixture: " << path;
    std::vector<std::string> lines;
    std::string l;
    while (std::getline(f, l))
        if (!l.empty() && l[0] != '#') lines.push_back(l);
    return lines;
}

std::vector<std::string> split_ws(const std::string& l)
{
    std::istringstream ss(l);
    std::vector<std::string> f;
    std::string t;
    while (ss >> t) f.push_back(t);
    return f;
}

/// Anchor-seed an engine from the h=2513685 active-set fixture.
/// Columns: type qidx base_height quorumHash commitment_hex.
size_t seed_engine_from_anchor(QuorumReplayEngine& eng)
{
    size_t n = 0;
    for (const auto& l : read_lines("dash_mainnet_active_quorums_2513685.txt")) {
        auto f = split_ws(l);
        EXPECT_EQ(f.size(), 5u) << l.substr(0, 80);
        if (f.size() != 5) continue;
        auto c = parse_commitment_hex(f[4]);
        EXPECT_TRUE(c.has_value()) << "commitment slice must parse byte-exact";
        if (!c) continue;
        EXPECT_EQ(int(c->llmqType), std::stoi(f[0]));
        uint256 qh;
        qh.SetHex(f[3]);
        EXPECT_EQ(qh.GetHex(), c->quorumHash.GetHex())
            << "fixture quorumHash column must match the parsed commitment";
        const uint32_t base = static_cast<uint32_t>(std::stoul(f[2]));
        std::string err;
        EXPECT_TRUE(eng.seed_commitment(base, *c, err)) << err;
        ++n;
    }
    return n;
}

/// The anchor sits MID-CYCLE (2513685; the surrounding cycle base is
/// 2513664), so commitments mined in the first observed mining window name
/// quorum-base blocks BELOW the seed cursor. In integration those resolve
/// via the replay header chain (W0); the KAT seeds the 21 pre-window
/// hashes 2513664..2513684 the same way an anchor state would.
void seed_prewindow_hashes(QuorumReplayEngine& eng)
{
    for (const auto& l :
         read_lines("dash_mainnet_block_hashes_2513664_2513684.txt")) {
        auto f = split_ws(l);
        ASSERT_EQ(f.size(), 2u);
        uint256 bh;
        bh.SetHex(f[1]);
        eng.seed_block_hash(static_cast<uint32_t>(std::stoul(f[0])), bh);
    }
}

struct ScanBlock {
    uint32_t height{0};
    uint256  block_hash;
    uint256  mrq;
    std::optional<std::array<uint8_t, 96>> cl;
    std::vector<std::string> qc_hex;
};

std::vector<ScanBlock> load_scan()
{
    std::vector<ScanBlock> out;
    for (const auto& l :
         read_lines("dash_mainnet_quorum_scan_2513685_2516786.txt")) {
        auto f = split_ws(l);
        EXPECT_EQ(f.size(), 5u) << l.substr(0, 80);
        if (f.size() != 5) continue;
        ScanBlock b;
        b.height = static_cast<uint32_t>(std::stoul(f[0]));
        b.block_hash.SetHex(f[1]);
        b.mrq.SetHex(f[2]);
        if (f[3] != "-" && f[3] != "null") {
            auto bytes = from_hex(f[3]);
            EXPECT_EQ(bytes.size(), 96u);
            if (bytes.size() == 96) {
                std::array<uint8_t, 96> sig{};
                std::copy(bytes.begin(), bytes.end(), sig.begin());
                bool any = false;
                for (auto x : sig) if (x) { any = true; break; }
                // All-zero == "no chainlock in this cbTx" == absent for the
                // modifier (GetNonNullCoinbaseChainlock nullopt path).
                if (any) b.cl = sig;
            }
        }
        if (f[4] != "-") {
            std::stringstream ss(f[4]);
            std::string item;
            while (std::getline(ss, item, ',')) b.qc_hex.push_back(item);
        }
        out.push_back(std::move(b));
    }
    return out;
}

QuorumBlockInput input_from_scan(const ScanBlock& b)
{
    QuorumBlockInput in;
    in.height     = b.height;
    in.block_hash = b.block_hash;
    in.committed_merkle_root_quorums = b.mrq;
    in.best_cl_sig = b.cl;
    for (const auto& hex : b.qc_hex) {
        auto qc = parse_qc_payload_hex(hex);
        EXPECT_TRUE(qc.has_value()) << "h=" << b.height
                                    << " qfcommit payload must parse";
        if (qc) in.commitments.push_back(std::move(*qc));
    }
    return in;
}

QuorumReplayConfig mainnet_cfg()
{
    QuorumReplayConfig cfg;
    cfg.enabled = true;
    cfg.network = LlmqNetwork::Mainnet;
    return cfg;
}

// ── qrinfo-derived rotation inputs (KAT-B/C) ───────────────────────────────

std::vector<QuorumMnEntry> sml_to_entries(const CSimplifiedMNList& sml)
{
    std::vector<QuorumMnEntry> out;
    out.reserve(sml.mnList.size());
    for (const auto& e : sml.mnList) {
        QuorumMnEntry q;
        q.proTxHash        = e.proRegTxHash;
        q.confirmedHash    = e.confirmedHash;
        q.is_valid         = e.isValid;
        q.n_type           = e.nType;
        q.pub_key_operator = e.pubKeyOperator;
        q.has_collateral   = false;   // an SML cannot carry the collateral
        out.push_back(std::move(q));
    }
    return out;
}

/// The five authenticated cycles of the mainnet qrinfo: index 0 = H
/// (2516544), 1 = H-C, 2 = H-2C, 3 = H-3C, 4 = H-4C (extraShare). Each
/// cycle carries the work-block MN list (rebuilt from the genesis-based
/// diff and checked against the work block's OWN committed
/// merkleRootMNList) and the V20 hash modifier for its cycle base (CL from
/// the work block's cbTx).
struct QrinfoCycles {
    CQuorumRotationInfo info;
    std::array<std::vector<QuorumMnEntry>, 5> lists;
    std::array<uint256, 5>                    modifiers;
    std::array<const CQuorumSnapshot*, 4>     snaps{};   // H-C..H-4C

    bool load()
    {
        const std::string path =
            std::string(DASH_FIXTURE_DIR) + "/dash_mainnet_qrinfo_2516785.bin";
        std::ifstream f(path, std::ios::binary);
        if (!f.good()) return false;
        std::vector<unsigned char> bytes(
            (std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        if (!decode_quorum_rotation_info(bytes, info)) return false;
        if (!info.extraShare || !info.quorumSnapshotAtHMinus4C
            || !info.mnListDiffAtHMinus4C)
            return false;

        const CSimplifiedMNListDiff* diffs[5] = {
            &info.mnListDiffH, &info.mnListDiffAtHMinusC,
            &info.mnListDiffAtHMinus2C, &info.mnListDiffAtHMinus3C,
            &*info.mnListDiffAtHMinus4C};
        for (size_t i = 0; i < 5; ++i) {
            CSimplifiedMNList sml;
            dash::coin::vendor::apply_diff(sml, *diffs[i]);
            dash::coin::vendor::CCbTx cb;
            if (!dash::coin::vendor::parse_cbtx(diffs[i]->cbTx.extra_payload, cb))
                return false;
            // DIP-4 authentication: the rebuilt list must be the one the
            // work block committed to.
            if (sml.CalcMerkleRoot() != cb.merkleRootMNList) return false;
            // The diff targets the WORK block of its cycle base.
            const uint32_t expect_work =
                kCycleBase - static_cast<uint32_t>(i) * kC - kWorkDiffDepth;
            if (static_cast<uint32_t>(cb.nHeight) != expect_work) return false;
            std::optional<std::array<uint8_t, CFinalCommitment::BLS_SIG_SIZE>> cl;
            if (cb.nVersion >= dash::coin::vendor::CCbTx::VERSION_CLSIG_AND_BALANCE
                && cb.has_best_cl_signature())
                cl = cb.bestCLSignature;
            modifiers[i] = dash::coin::vendor::compute_quorum_modifier(
                kType6075, static_cast<uint32_t>(cb.nHeight), cl,
                diffs[i]->blockHash);
            lists[i] = sml_to_entries(sml);
        }
        snaps = {&info.quorumSnapshotAtHMinusC, &info.quorumSnapshotAtHMinus2C,
                 &info.quorumSnapshotAtHMinus3C, &*info.quorumSnapshotAtHMinus4C};
        return true;
    }
};

struct KatMemberRow {
    uint32_t index{0};
    uint32_t height{0};
    std::vector<std::string> protx;   // display hex, dashd's order
};

std::vector<KatMemberRow> load_member_kat()
{
    std::vector<KatMemberRow> rows;
    for (const auto& l :
         read_lines("dash_mainnet_quorum_members_60_75_2516544.txt")) {
        auto f = split_ws(l);
        EXPECT_GE(f.size(), 3u);
        if (f.size() < 3) continue;
        KatMemberRow r;
        r.index  = static_cast<uint32_t>(std::stoul(f[0]));
        r.height = static_cast<uint32_t>(std::stoul(f[1]));
        for (size_t i = 3; i < f.size(); ++i) r.protx.push_back(f[i]);
        rows.push_back(std::move(r));
    }
    return rows;
}

std::vector<std::string> protx_hex(const std::vector<uint256>& v)
{
    std::vector<std::string> out;
    out.reserve(v.size());
    for (const auto& h : v) out.push_back(h.GetHex());
    return out;
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// KAT-A — merkleRootQuorums, 3101 consecutive mainnet blocks, byte-exact
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashReplayQuorumEngine, KatA_MerkleRootQuorums_3101ConsecutiveMainnetBlocks)
{
    auto scan = load_scan();
    ASSERT_GE(scan.size(), 3000u);
    ASSERT_EQ(scan.front().height, kSeedHeight);

    QuorumReplayEngine eng(mainnet_cfg());
    eng.seed_cursor(kSeedHeight, scan.front().block_hash);
    seed_prewindow_hashes(eng);
    ASSERT_EQ(seed_engine_from_anchor(eng), 88u)
        << "the anchor active set is 24+4+4+24+32 commitments";
    // The seed IS the full active set at the anchor — the self-check is
    // armed from the very first replayed block (a wrong seed must desync at
    // anchor+1, not be masked by a warm-up).
    ASSERT_TRUE(eng.active_sets_complete());
    eng.arm_self_check();

    size_t blocks = 0, with_qcs = 0, ingested = 0, nulls = 0;
    for (size_t i = 1; i < scan.size(); ++i) {
        auto in = input_from_scan(scan[i]);
        auto r  = eng.observe_block(in);
        ASSERT_TRUE(r.ok) << "h=" << scan[i].height << ": " << r.error;
        ASSERT_TRUE(r.self_checked);
        ASSERT_EQ(r.computed_root.GetHex(), scan[i].mrq.GetHex())
            << "h=" << scan[i].height;
        ++blocks;
        if (!in.commitments.empty()) ++with_qcs;
        ingested += r.commitments_ingested;
        nulls    += r.commitments_null;
    }
    EXPECT_EQ(blocks, scan.size() - 1);
    // The window genuinely exercises the fold: hundreds of commitment
    // blocks, both real and null commitments, every enabled type.
    EXPECT_GE(with_qcs, 300u);
    EXPECT_GE(ingested, 200u);
    EXPECT_GE(nulls, 1u);
    EXPECT_TRUE(eng.active_sets_complete());
    EXPECT_FALSE(eng.poisoned());
}

// A single flipped byte in one active commitment must desync the root at
// the NEXT block and poison the engine — the anchor-trust bound (§4.5): a
// wrong seed is caught in ONE block, never served.
TEST(DashReplayQuorumEngine, KatA_TamperedSeedDesyncsAtAnchorPlusOne)
{
    auto scan = load_scan();
    ASSERT_GE(scan.size(), 2u);

    QuorumReplayEngine eng(mainnet_cfg());
    eng.seed_cursor(kSeedHeight, scan.front().block_hash);

    size_t n = 0;
    for (const auto& l : read_lines("dash_mainnet_active_quorums_2513685.txt")) {
        auto f = split_ws(l);
        ASSERT_EQ(f.size(), 5u);
        auto c = parse_commitment_hex(f[4]);
        ASSERT_TRUE(c.has_value());
        if (n == 40) c->quorumVvecHash.data()[0] ^= 0xff;   // one tampered leaf
        std::string err;
        ASSERT_TRUE(eng.seed_commitment(
            static_cast<uint32_t>(std::stoul(f[2])), *c, err)) << err;
        ++n;
    }
    eng.arm_self_check();

    auto r = eng.observe_block(input_from_scan(scan[1]));
    EXPECT_FALSE(r.ok);
    EXPECT_TRUE(eng.poisoned());
    EXPECT_NE(r.error.find("QUORUM ROOT MISMATCH"), std::string::npos) << r.error;

    // Poison is sticky: the next block refuses too.
    auto r2 = eng.observe_block(input_from_scan(scan[2]));
    EXPECT_FALSE(r2.ok);
    EXPECT_NE(r2.error.find("POISONED"), std::string::npos) << r2.error;
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT-B — rotated membership for real cycle 2516544, all 32 slots, in order
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashReplayQuorumEngine, KatB_RotationMembersMatchDashdForAll32Slots)
{
    QrinfoCycles q;
    ASSERT_TRUE(q.load()) << "mainnet qrinfo must decode + authenticate";

    std::array<RotationCycleInput, 4> cycles{};
    for (size_t i = 0; i < 4; ++i) {
        cycles[i].mn_list  = &q.lists[i];
        cycles[i].modifier = q.modifiers[i];
    }
    std::array<const CQuorumSnapshot*, 3> snaps{q.snaps[0], q.snaps[1],
                                                q.snaps[2]};
    std::string err;
    auto out = compute_rotation_cycle(kLlmq60_75, cycles, snaps, &err);
    ASSERT_TRUE(out.has_value()) << err;
    ASSERT_EQ(out->member_protx.size(), 32u);

    auto kat = load_member_kat();
    ASSERT_EQ(kat.size(), 32u);
    for (const auto& row : kat) {
        ASSERT_LT(row.index, 32u);
        ASSERT_EQ(row.height, kCycleBase + row.index)
            << "the captured ring is the 2516544 cycle";
        ASSERT_EQ(row.protx.size(), 60u);
        const auto got = protx_hex(out->member_protx[row.index]);
        ASSERT_EQ(got.size(), row.protx.size()) << "quorumIndex " << row.index;
        for (size_t i = 0; i < got.size(); ++i) {
            EXPECT_EQ(got[i], row.protx[i])
                << "quorumIndex " << row.index << " member INDEX " << i
                << " diverges from dashd; member index is the signers/"
                   "validMembers bitset slot, so this is consensus";
        }
    }
}

// Order-sensitivity control: the same member SET in a different order must
// not compare equal (guards the KAT itself against a set-only comparison).
TEST(DashReplayQuorumEngine, KatB_OrderAssertionRejectsPermutation)
{
    QrinfoCycles q;
    ASSERT_TRUE(q.load());
    std::array<RotationCycleInput, 4> cycles{};
    for (size_t i = 0; i < 4; ++i) {
        cycles[i].mn_list  = &q.lists[i];
        cycles[i].modifier = q.modifiers[i];
    }
    std::array<const CQuorumSnapshot*, 3> snaps{q.snaps[0], q.snaps[1],
                                                q.snaps[2]};
    auto out = compute_rotation_cycle(kLlmq60_75, cycles, snaps);
    ASSERT_TRUE(out.has_value());

    auto kat = load_member_kat();
    auto got = protx_hex(out->member_protx[kat[0].index]);
    ASSERT_EQ(got, kat[0].protx);
    std::swap(got[0], got[1]);
    EXPECT_NE(got, kat[0].protx);
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT-C — the snapshot PRODUCER matches dashd's own served snapshot bytes
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashReplayQuorumEngine, KatC_ProducedSnapshotMatchesDashdServedSnapshot)
{
    QrinfoCycles q;
    ASSERT_TRUE(q.load());

    // Produce cycle H-C (2516256) from the three cycles before it.
    std::array<RotationCycleInput, 4> cycles{};
    for (size_t i = 0; i < 4; ++i) {
        cycles[i].mn_list  = &q.lists[i + 1];   // H-C, H-2C, H-3C, H-4C
        cycles[i].modifier = q.modifiers[i + 1];
    }
    std::array<const CQuorumSnapshot*, 3> snaps{q.snaps[1], q.snaps[2],
                                                q.snaps[3]};
    std::string err;
    auto out = compute_rotation_cycle(kLlmq60_75, cycles, snaps, &err);
    ASSERT_TRUE(out.has_value()) << err;

    const CQuorumSnapshot& want = *q.snaps[0];   // dashd's snapshot for H-C
    const CQuorumSnapshot& got  = out->snapshot_at_h;
    EXPECT_EQ(got.mnSkipListMode, want.mnSkipListMode);
    ASSERT_EQ(got.activeQuorumMembers.size(), want.activeQuorumMembers.size());
    for (size_t i = 0; i < want.activeQuorumMembers.size(); ++i) {
        EXPECT_EQ(got.activeQuorumMembers[i], want.activeQuorumMembers[i])
            << "active bit " << i;
    }
    ASSERT_EQ(got.mnSkipList.size(), want.mnSkipList.size());
    for (size_t i = 0; i < want.mnSkipList.size(); ++i) {
        EXPECT_EQ(got.mnSkipList[i], want.mnSkipList[i]) << "skip entry " << i;
    }
}

// The recurrence: OUR produced snapshot for H-C, consumed in place of the
// served one, reproduces dashd's members for cycle H — replay is
// self-sustaining, qrinfo retired.
TEST(DashReplayQuorumEngine, KatC_OwnSnapshotFeedsTheNextCycleIdentically)
{
    QrinfoCycles q;
    ASSERT_TRUE(q.load());

    // Produce snapshot @ H-C.
    std::array<RotationCycleInput, 4> prev_cycles{};
    for (size_t i = 0; i < 4; ++i) {
        prev_cycles[i].mn_list  = &q.lists[i + 1];
        prev_cycles[i].modifier = q.modifiers[i + 1];
    }
    std::array<const CQuorumSnapshot*, 3> prev_snaps{q.snaps[1], q.snaps[2],
                                                     q.snaps[3]};
    auto produced = compute_rotation_cycle(kLlmq60_75, prev_cycles, prev_snaps);
    ASSERT_TRUE(produced.has_value());

    // Members @ H with the served snapshot vs with OURS.
    std::array<RotationCycleInput, 4> cycles{};
    for (size_t i = 0; i < 4; ++i) {
        cycles[i].mn_list  = &q.lists[i];
        cycles[i].modifier = q.modifiers[i];
    }
    std::array<const CQuorumSnapshot*, 3> served{q.snaps[0], q.snaps[1],
                                                 q.snaps[2]};
    std::array<const CQuorumSnapshot*, 3> ours{&produced->snapshot_at_h,
                                               q.snaps[1], q.snaps[2]};
    auto a = compute_rotation_cycle(kLlmq60_75, cycles, served);
    auto b = compute_rotation_cycle(kLlmq60_75, cycles, ours);
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());
    for (size_t i = 0; i < 32; ++i) {
        EXPECT_EQ(protx_hex(a->member_protx[i]), protx_hex(b->member_protx[i]))
            << "quorumIndex " << i;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT-D — the STORE-ENGINE straddle bootstrap: derive_members_for_cycle()
// ASSEMBLES the rotated cycle's 32 ordered member sets from the SEEDED
// quarters (getqrinfo straddle seed) and KEYS them by (llmqType,
// cycle_base+quorumIndex), so fold_qfcommit's m_members_fn(type, quorumHash)
// lookup resolves — the fix for the store capping at cycle_base +
// mining_window_start. KAT-B proved compute_rotation_cycle's math is
// dashd-exact; this proves the ENGINE WRAPPER that drives it from the seed
// and the members_for KEYING the fold consumes.
//
//  RED (drop a seeded quarter, or revert the wiring): derive returns ok=false
//      with a NAMED skip, members_for() is nullopt, the fold fails closed.
//  GREEN: 32/32 sets registered, each == dashd's golden order (KAT-B
//      goldens), resolvable through members_for by the per-index quorum base
//      hash exactly as fold_qfcommit resolves a commitment quorumHash.
//  REWARD-SAFE: a TAMPERED quarter still runs the math but the assembled set
//      DIFFERS from dashd's — the divergence the writer's per-row
//      merkleRootMNList self-check catches, so the store fails closed and
//      callers fall through to the network path (never a bad mint).
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashReplayQuorumEngine, KatD_DeriveMembersForCycleAssemblesAndKeysStraddleCycle)
{
    QrinfoCycles q;
    ASSERT_TRUE(q.load()) << "mainnet qrinfo must decode + authenticate";
    auto kat = load_member_kat();
    ASSERT_EQ(kat.size(), 32u);

    // The cycle-H work block's own hash + CL — chain data the store OBSERVES
    // forward before the hold; derive recomputes the H modifier from these
    // (it does NOT read a seeded H modifier), so it must reproduce
    // q.modifiers[0] for the members to match the goldens.
    const uint32_t workH = kCycleBase - kWorkDiffDepth;
    const uint256  workH_hash = q.info.mnListDiffH.blockHash;
    std::optional<std::array<uint8_t, CFinalCommitment::BLS_SIG_SIZE>> workH_cl;
    {
        dash::coin::vendor::CCbTx cb;
        ASSERT_TRUE(dash::coin::vendor::parse_cbtx(
            q.info.mnListDiffH.cbTx.extra_payload, cb));
        if (cb.nVersion >= dash::coin::vendor::CCbTx::VERSION_CLSIG_AND_BALANCE
            && cb.has_best_cl_signature())
            workH_cl = cb.bestCLSignature;
    }

    // Seed an engine to the same state the store-engine bridge holds when the
    // getqrinfo straddle seed lands: the three previous-quarter snapshots +
    // modifiers + work-lists, and the cycle-H work block chain fields.
    auto seed_engine = [&](QuorumReplayEngine& eng, bool seed_hminusC) {
        std::map<uint32_t, std::vector<QuorumMnEntry>> lists_by_h;
        lists_by_h[kCycleBase - kWorkDiffDepth]              = q.lists[0];
        lists_by_h[kCycleBase - 1u * kC - kWorkDiffDepth]    = q.lists[1];
        lists_by_h[kCycleBase - 2u * kC - kWorkDiffDepth]    = q.lists[2];
        lists_by_h[kCycleBase - 3u * kC - kWorkDiffDepth]    = q.lists[3];
        eng.set_mn_list_at_fn(
            [lists_by_h](uint32_t h)
                -> std::optional<std::vector<QuorumMnEntry>> {
                auto it = lists_by_h.find(h);
                if (it == lists_by_h.end()) return std::nullopt;
                return it->second;
            });
        eng.seed_block_hash(workH, workH_hash);
        eng.seed_work_block_cl(workH, workH_cl);
        for (size_t i = 1; i <= 3; ++i) {
            if (i == 1 && !seed_hminusC) continue;   // RED: drop the H-C quarter
            const uint32_t base = kCycleBase - static_cast<uint32_t>(i) * kC;
            eng.seed_snapshot(kType6075, base, *q.snaps[i - 1]);
            eng.seed_modifier(kType6075, base, q.modifiers[i]);
        }
    };

    // Per-index quorum base hashes, so members_for() resolves the way
    // fold_qfcommit does: quorumHash -> height (cycle_base+index) -> members.
    auto seed_index_hashes = [&](QuorumReplayEngine& eng, char tag,
                                 std::array<uint256, 32>& qhash) {
        for (uint32_t idx = 0; idx < 32; ++idx) {
            std::string h(64, '0');
            h[0]  = tag;
            h[58] = "0123456789abcdef"[(idx >> 8) & 0xf];
            h[59] = "0123456789abcdef"[(idx >> 4) & 0xf];
            h[60] = "0123456789abcdef"[idx & 0xf];
            qhash[idx].SetHex(h);
            eng.seed_block_hash(kCycleBase + idx, qhash[idx]);
        }
    };

    // ── GREEN: assembled + keyed, dashd-exact, resolvable ─────────────────
    {
        QuorumReplayEngine eng(mainnet_cfg());
        seed_engine(eng, /*seed_hminusC=*/true);
        std::array<uint256, 32> qhash;
        seed_index_hashes(eng, 'e', qhash);

        auto dr = eng.derive_members_for_cycle(kType6075, kCycleBase);
        ASSERT_TRUE(dr.ok) << dr.skip_reason;
        EXPECT_EQ(dr.member_sets, 32u);
        EXPECT_EQ(dr.expected_sets, 32u);
        EXPECT_EQ(dr.quorum_size, 60u);

        for (const auto& row : kat) {
            ASSERT_LT(row.index, 32u);
            auto m = eng.members_for(kType6075, qhash[row.index]);
            ASSERT_TRUE(m.has_value())
                << "quorumIndex " << row.index << " must resolve after derive";
            auto got = protx_hex(*m);
            ASSERT_EQ(got.size(), row.protx.size())
                << "quorumIndex " << row.index;
            for (size_t i = 0; i < got.size(); ++i)
                EXPECT_EQ(got[i], row.protx[i])
                    << "quorumIndex " << row.index << " member INDEX " << i
                    << " diverges from dashd (this is the validMembers slot — "
                       "consensus)";
        }
    }

    // ── RED: a missing quarter → named skip, no member set, fail-closed ────
    {
        QuorumReplayEngine eng(mainnet_cfg());
        seed_engine(eng, /*seed_hminusC=*/false);
        uint256 qh0;
        qh0.SetHex(
            "0000000000000000000000000000000000000000000000000000000000000e00");
        eng.seed_block_hash(kCycleBase, qh0);

        auto dr = eng.derive_members_for_cycle(kType6075, kCycleBase);
        EXPECT_FALSE(dr.ok);
        EXPECT_LT(dr.member_sets, 32u);
        EXPECT_FALSE(dr.skip_reason.empty()) << "the miss must be NAMED";
        EXPECT_FALSE(eng.members_for(kType6075, qh0).has_value())
            << "a missing quarter must leave the fold with NO member set "
               "(fail-closed), never a guessed one";
    }

    // ── REWARD-SAFE: a tampered quarter assembles a DETECTABLY WRONG set ───
    {
        QuorumReplayEngine eng(mainnet_cfg());
        seed_engine(eng, /*seed_hminusC=*/true);
        CQuorumSnapshot bad = *q.snaps[0];   // H-C quarter
        ASSERT_FALSE(bad.activeQuorumMembers.empty());
        bad.activeQuorumMembers[0] = !bad.activeQuorumMembers[0];
        eng.seed_snapshot(kType6075, kCycleBase - kC, bad);
        std::array<uint256, 32> qhash;
        seed_index_hashes(eng, 'f', qhash);

        (void)eng.derive_members_for_cycle(kType6075, kCycleBase);
        bool any_diff = false;
        for (const auto& row : kat) {
            auto m = eng.members_for(kType6075, qhash[row.index]);
            if (!m) { any_diff = true; break; }
            if (protx_hex(*m) != row.protx) { any_diff = true; break; }
        }
        EXPECT_TRUE(any_diff)
            << "a tampered quarter must NOT reproduce dashd's members — that "
               "divergence is exactly what the writer's per-row "
               "merkleRootMNList self-check catches (reward-safe fail-closed)";
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Engine discipline (synthetic)
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashReplayQuorumEngine, FeatureFlagOffRefusesEverything)
{
    QuorumReplayConfig cfg;   // enabled defaults to false
    QuorumReplayEngine eng(cfg);
    eng.seed_cursor(2'500'000, uint256::ZERO);
    QuorumBlockInput in;
    in.height = 2'500'001;
    auto r = eng.observe_block(in);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.error.find("not enabled"), std::string::npos) << r.error;
}

TEST(DashReplayQuorumEngine, CursorIsForwardContiguous)
{
    QuorumReplayEngine eng(mainnet_cfg());
    eng.seed_cursor(2'500'000, uint256::ZERO);

    QuorumBlockInput gap;
    gap.height = 2'500'002;   // skips 2'500'001
    auto r = eng.observe_block(gap);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.error.find("forward-contiguous"), std::string::npos) << r.error;

    QuorumBlockInput dup;
    dup.height = 2'500'000;
    EXPECT_FALSE(eng.observe_block(dup).ok);
    EXPECT_FALSE(eng.poisoned()) << "cursor refusals are not poison";
}

TEST(DashReplayQuorumEngine, BelowV20FloorRefusesNamed)
{
    QuorumReplayEngine eng(mainnet_cfg());
    eng.seed_cursor(1'900'000, uint256::ZERO);
    QuorumBlockInput in;
    in.height = 1'900'001;
    auto r = eng.observe_block(in);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.error.find("V20 floor"), std::string::npos) << r.error;
}

TEST(DashReplayQuorumEngine, UnseededEngineRefuses)
{
    QuorumReplayEngine eng(mainnet_cfg());
    QuorumBlockInput in;
    in.height = 1;
    auto r = eng.observe_block(in);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.error.find("no seeded cursor"), std::string::npos) << r.error;
}

TEST(DashReplayQuorumEngine, ArmedSelfCheckRequiresACommittedRoot)
{
    QuorumReplayEngine eng(mainnet_cfg());
    eng.seed_cursor(2'500'000, uint256::ZERO);
    eng.arm_self_check();
    QuorumBlockInput in;
    in.height = 2'500'001;
    // no committed_merkle_root_quorums
    auto r = eng.observe_block(in);
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.error.find("no "), std::string::npos) << r.error;
    EXPECT_TRUE(eng.poisoned())
        << "an armed self-check with no answer key must fail closed loudly";
}

// The in-block fold rules on a synthetic non-rotated type: sub-capacity
// append, capacity eviction of the OLDEST, and the root recomputed from the
// exact expected leaf set at every step.
TEST(DashReplayQuorumEngine, NonRotatedFoldEvictsOldestAtCapacity)
{
    // Build 6 synthetic 400_60 commitments (capacity 4) on distinct bases.
    auto make_qc = [](uint32_t base_height, uint8_t tag) {
        CFinalCommitment c;
        c.nVersion = CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
        c.llmqType = 2;   // LLMQ_400_60
        std::string h(64, '0');
        h[0] = 'a';
        h[62] = "0123456789abcdef"[(tag >> 4) & 0xf];
        h[63] = "0123456789abcdef"[tag & 0xf];
        c.quorumHash.SetHex(h);
        c.signers.assign(400, false);
        c.validMembers.assign(400, false);
        c.signers[0] = c.validMembers[0] = true;   // non-null
        c.quorumPublicKey[0] = tag;
        c.quorumVvecHash.SetHex(h);
        (void)base_height;
        return c;
    };

    QuorumReplayEngine eng(mainnet_cfg());
    const uint32_t H0 = 2'500'000;
    eng.seed_cursor(H0, uint256::ZERO);

    // Seed 3 (below capacity), bases 100/200/300.
    std::vector<CFinalCommitment> seeds;
    for (uint8_t i = 0; i < 3; ++i) {
        auto c = make_qc(0, i + 1);
        std::string err;
        ASSERT_TRUE(eng.seed_commitment(2'400'000u + 100u * (i + 1), c, err))
            << err;
        seeds.push_back(c);
    }
    EXPECT_EQ(eng.active_count(2), 3u);

    auto expected_root = [&](const std::vector<CFinalCommitment>& active) {
        std::vector<uint256> leaves;
        for (const auto& c : active) leaves.push_back(hash_commitment(c));
        std::sort(leaves.begin(), leaves.end(),
                  [](const uint256& a, const uint256& b) {
                      return std::memcmp(a.data(), b.data(), 32) < 0;
                  });
        return compute_merkle_root_local(std::move(leaves));
    };

    // Block 1: a 4th commitment — append, no eviction.
    auto c4 = make_qc(0, 4);
    {
        QuorumBlockInput in;
        in.height = H0 + 1;
        in.block_hash.SetHex(
            "00000000000000000000000000000000000000000000000000000000000000b1");
        eng.seed_block_hash(H0 - 5, c4.quorumHash);   // resolvable base
        CFinalCommitmentTxPayload p;
        p.nHeight = in.height;
        p.commitment = c4;
        in.commitments.push_back(p);
        auto want = expected_root({seeds[0], seeds[1], seeds[2], c4});
        auto r = eng.observe_block(in);
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(r.computed_root.GetHex(), want.GetHex());
        EXPECT_EQ(eng.active_count(2), 4u);
    }

    // Block 2: a 5th — the OLDEST (base 2'400'100, seeds[0]) is evicted.
    auto c5 = make_qc(0, 5);
    {
        QuorumBlockInput in;
        in.height = H0 + 2;
        in.block_hash.SetHex(
            "00000000000000000000000000000000000000000000000000000000000000b2");
        eng.seed_block_hash(H0 - 3, c5.quorumHash);
        CFinalCommitmentTxPayload p;
        p.nHeight = in.height;
        p.commitment = c5;
        in.commitments.push_back(p);
        auto want = expected_root({seeds[1], seeds[2], c4, c5});
        auto r = eng.observe_block(in);
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(r.computed_root.GetHex(), want.GetHex())
            << "capacity eviction must drop the OLDEST-mined leaf";
        EXPECT_EQ(eng.active_count(2), 4u);
    }

    // Block 3: a null commitment — skipped entirely, root unchanged.
    {
        QuorumBlockInput in;
        in.height = H0 + 3;
        in.block_hash.SetHex(
            "00000000000000000000000000000000000000000000000000000000000000b3");
        CFinalCommitment null_c;
        null_c.nVersion = CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
        null_c.llmqType = 2;
        null_c.signers.assign(400, false);
        null_c.validMembers.assign(400, false);
        CFinalCommitmentTxPayload p;
        p.nHeight = in.height;
        p.commitment = null_c;
        in.commitments.push_back(p);
        auto want = expected_root({seeds[1], seeds[2], c4, c5});
        auto r = eng.observe_block(in);
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(r.commitments_null, 1u);
        EXPECT_EQ(r.commitments_ingested, 0u);
        EXPECT_EQ(r.computed_root.GetHex(), want.GetHex());
    }
}

TEST(DashReplayQuorumEngine, RotatedFoldReplacesTheSameQuorumIndex)
{
    auto make_rot = [](int16_t index, uint8_t tag) {
        CFinalCommitment c;
        c.nVersion = CFinalCommitment::BASIC_BLS_INDEXED_QUORUM_VERSION;
        c.llmqType = 5;   // LLMQ_60_75
        c.quorumIndex = index;
        std::string h(64, '0');
        h[0] = 'c';
        h[63] = "0123456789abcdef"[tag & 0xf];
        c.quorumHash.SetHex(h);
        c.signers.assign(60, false);
        c.validMembers.assign(60, false);
        c.signers[0] = c.validMembers[0] = true;
        c.quorumPublicKey[0] = tag;
        c.quorumVvecHash.SetHex(h);
        return c;
    };

    QuorumReplayEngine eng(mainnet_cfg());
    const uint32_t H0 = 2'500'000;
    eng.seed_cursor(H0, uint256::ZERO);
    auto old0 = make_rot(0, 1);
    auto old1 = make_rot(1, 2);
    std::string err;
    ASSERT_TRUE(eng.seed_commitment(2'499'000, old0, err)) << err;
    ASSERT_TRUE(eng.seed_commitment(2'499'001, old1, err)) << err;
    EXPECT_EQ(eng.active_count(5), 2u);

    // A new index-0 commitment REPLACES old0; old1 stays.
    auto new0 = make_rot(0, 9);
    QuorumBlockInput in;
    in.height = H0 + 1;
    in.block_hash.SetHex(
        "00000000000000000000000000000000000000000000000000000000000000c9");
    eng.seed_block_hash(H0 - 7, new0.quorumHash);
    CFinalCommitmentTxPayload p;
    p.nHeight = in.height;
    p.commitment = new0;
    in.commitments.push_back(p);

    std::vector<uint256> leaves{hash_commitment(new0), hash_commitment(old1)};
    std::sort(leaves.begin(), leaves.end(),
              [](const uint256& a, const uint256& b) {
                  return std::memcmp(a.data(), b.data(), 32) < 0;
              });
    auto want = compute_merkle_root_local(std::move(leaves));

    auto r = eng.observe_block(in);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.computed_root.GetHex(), want.GetHex());
    EXPECT_EQ(eng.active_count(5), 2u) << "replace, not append";
}

TEST(DashReplayQuorumEngine, UnresolvableQuorumBasePoisons)
{
    QuorumReplayEngine eng(mainnet_cfg());
    eng.seed_cursor(2'500'000, uint256::ZERO);
    CFinalCommitment c;
    c.nVersion = CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
    c.llmqType = 2;
    c.quorumHash.SetHex(
        "00000000000000000000000000000000000000000000000000000000deadbeef");
    c.signers.assign(400, false);
    c.validMembers.assign(400, false);
    c.signers[0] = c.validMembers[0] = true;
    c.quorumPublicKey[0] = 1;

    QuorumBlockInput in;
    in.height = 2'500'001;
    CFinalCommitmentTxPayload p;
    p.nHeight = in.height;
    p.commitment = c;
    in.commitments.push_back(p);
    auto r = eng.observe_block(in);
    EXPECT_FALSE(r.ok);
    EXPECT_TRUE(eng.poisoned());
    EXPECT_NE(r.error.find("no known block height"), std::string::npos)
        << r.error;
}

// ═══════════════════════════════════════════════════════════════════════════
// Producer↔consumer round trip on a synthetic, NON-degenerate set — the
// invariant the live recurrence rests on: the snapshot produced at cycle H
// replays, through the consumer leg, into exactly the new quarter built at
// H. (KAT-C proves the same against real dashd bytes; this pins it where
// every branch — used/unused split, skip list — is exercised by
// construction and the failure is debuggable.)
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashReplayQuorumEngine, ProducedSnapshotReplaysIntoTheSameNewQuarter)
{
    // 12 MNs, all eligible; small rotated params: size 8 (quarter 2),
    // 2 quorums per cycle.
    LlmqParamsView params = kLlmq60_75;   // copy, then shrink
    params.size = 8;
    params.signing_active_quorum_count = 2;

    std::vector<QuorumMnEntry> list(12);
    for (size_t i = 0; i < list.size(); ++i) {
        auto& e = list[i];
        std::string h(64, '0');
        h[63] = "0123456789abcdef"[(i + 1) & 0xf];
        e.proTxHash.SetHex(h);
        h[0] = '9';
        e.confirmedHash.SetHex(h);
        e.is_valid = true;
        e.pub_key_operator[0] = static_cast<uint8_t>(0x20 + i);
    }
    uint256 mod_prev, mod_h;
    mod_prev.SetHex(
        "5555555555555555555555555555555555555555555555555555555555555555");
    mod_h.SetHex(
        "6666666666666666666666666666666666666666666666666666666666666666");

    // Three previous cycles with all-false snapshots (nothing marked used):
    // the quarters then fill round-robin from the score-sorted list — a
    // real, non-empty previous-quarter population.
    CQuorumSnapshot none;
    none.mnSkipListMode = CQuorumSnapshot::MODE_NO_SKIPPING;
    none.activeQuorumMembers.assign(list.size(), false);

    std::array<RotationCycleInput, 4> cycles{};
    for (auto& c : cycles) c.mn_list = &list;
    cycles[0].modifier = mod_h;
    for (size_t i = 1; i < 4; ++i) cycles[i].modifier = mod_prev;
    std::array<const CQuorumSnapshot*, 3> snaps{&none, &none, &none};

    std::string err;
    auto out = compute_rotation_cycle(params, cycles, snaps, &err);
    ASSERT_TRUE(out.has_value()) << err;
    ASSERT_EQ(out->member_protx.size(), 2u);
    for (const auto& q : out->member_protx) ASSERT_EQ(q.size(), 8u);
    // With every MN used by the previous quarters, the produced snapshot
    // must mark bits and (in general) carry a skip list.
    size_t marked = 0;
    for (bool b : out->snapshot_at_h.activeQuorumMembers) marked += b;
    EXPECT_GT(marked, 0u);

    // Consumer leg over OUR snapshot at H replays the NEW quarter exactly.
    auto replayed = dash::coin::replay::rotdetail::get_quarter_members_by_snapshot(
        2, 2, list, mod_h, out->snapshot_at_h);
    ASSERT_TRUE(replayed.has_value());
    for (size_t qi = 0; qi < 2; ++qi) {
        ASSERT_EQ((*replayed)[qi].size(), 2u);
        for (size_t m = 0; m < 2; ++m) {
            // new quarter = members [6..8) of the assembled quorum
            EXPECT_EQ((*replayed)[qi][m]->proTxHash.GetHex(),
                      out->member_protx[qi][6 + m].GetHex())
                << "qi=" << qi << " m=" << m;
        }
    }
}

// Score ties: unresolvable without collateral, resolved EXACTLY like dashd
// (descending outpoint on the descending-score sort) with it.
TEST(DashReplayQuorumEngine, ScoreTieNeedsCollateralToResolve)
{
    QuorumMnEntry a, b;
    a.proTxHash.SetHex(
        "1111111111111111111111111111111111111111111111111111111111111111");
    a.confirmedHash.SetHex(
        "2222222222222222222222222222222222222222222222222222222222222222");
    a.is_valid = true;
    b = a;   // identical score inputs
    uint256 modifier;
    modifier.SetHex(
        "3333333333333333333333333333333333333333333333333333333333333333");

    std::vector<const QuorumMnEntry*> cands{&a, &b};
    EXPECT_FALSE(dash::coin::replay::rotdetail::calculate_quorum_all(
                     cands, modifier)
                     .has_value())
        << "a tie without collateral info cannot reproduce upstream order";

    a.has_collateral = b.has_collateral = true;
    a.collateral_hash.SetHex(
        "00000000000000000000000000000000000000000000000000000000000000aa");
    b.collateral_hash.SetHex(
        "00000000000000000000000000000000000000000000000000000000000000bb");
    auto sorted = dash::coin::replay::rotdetail::calculate_quorum_all(
        cands, modifier);
    ASSERT_TRUE(sorted.has_value());
    ASSERT_EQ(sorted->size(), 2u);
    // Upstream: sort(rbegin, rend, {score asc, tie collateral asc}) — the
    // final descending sequence puts the LARGER collateral first.
    EXPECT_EQ((*sorted)[0], &b);
    EXPECT_EQ((*sorted)[1], &a);
}

// The parsed-block adapter (W1's consumer shape): cbTx fields + type-6
// payloads lifted from a synthetic block; unparseable payloads fail closed.
TEST(DashReplayQuorumEngine, InputFromBlockAdapterLiftsCbTxAndCommitments)
{
    dash::coin::BlockType block;

    // Coinbase with a v3 cbTx payload.
    dash::coin::vendor::CCbTx cb;
    cb.nVersion = dash::coin::vendor::CCbTx::VERSION_CLSIG_AND_BALANCE;
    cb.nHeight  = 2'500'001;
    cb.merkleRootMNList.SetHex(
        "1111111111111111111111111111111111111111111111111111111111111111");
    cb.merkleRootQuorums.SetHex(
        "2222222222222222222222222222222222222222222222222222222222222222");
    cb.bestCLSignature[0] = 0x77;
    dash::coin::MutableTransaction cbtx;
    cbtx.version = 3;
    cbtx.type    = 5;
    {
        auto s  = ::pack(cb);
        auto sp = s.get_span();
        cbtx.extra_payload.assign(
            reinterpret_cast<const unsigned char*>(sp.data()),
            reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    }
    block.m_txs.push_back(cbtx);

    // One type-6 tx via the production builder.
    auto null_c = dash::coin::build_null_commitment(
        kLlmq50_60, uint256::ZERO, 0);
    block.m_txs.push_back(dash::coin::build_qc_tx(2'500'001, null_c));

    uint256 bh;
    bh.SetHex("00000000000000000000000000000000000000000000000000000000000000e1");
    std::string err;
    auto in = QuorumReplayEngine::input_from_block(block, 2'500'001, bh, &err);
    ASSERT_TRUE(in.has_value()) << err;
    ASSERT_TRUE(in->committed_merkle_root_quorums.has_value());
    EXPECT_EQ(in->committed_merkle_root_quorums->GetHex(),
              cb.merkleRootQuorums.GetHex());
    ASSERT_TRUE(in->best_cl_sig.has_value());
    EXPECT_EQ((*in->best_cl_sig)[0], 0x77);
    ASSERT_EQ(in->commitments.size(), 1u);
    EXPECT_EQ(int(in->commitments[0].commitment.llmqType), 1);

    // A corrupt qfcommit payload fails the whole adapter closed.
    block.m_txs.back().extra_payload.resize(3);
    EXPECT_FALSE(QuorumReplayEngine::input_from_block(block, 2'500'001, bh, &err)
                     .has_value());
    EXPECT_NE(err.find("unparseable qfcommit"), std::string::npos) << err;
}

// members_for(): the W1 DmlFoldEngine::MembersFn contract, end to end
// through observe_block on a testnet-configured engine (LLMQ_50_60 is
// enabled and non-rotated there, interval 24).
TEST(DashReplayQuorumEngine, MembersForResolvesAfterACycleBaseObservation)
{
    QuorumReplayConfig cfg;
    cfg.enabled  = true;
    cfg.network  = LlmqNetwork::Testnet;
    cfg.v20_floor = 905'100;
    QuorumReplayEngine eng(cfg);

    // 60 eligible MNs so every testnet type (max size 60 among 24-interval
    // types… 50_60 needs 50) can form members.
    std::vector<QuorumMnEntry> list(60);
    for (size_t i = 0; i < list.size(); ++i) {
        auto& e = list[i];
        std::string h(64, '0');
        h[60] = "0123456789abcdef"[(i >> 4) & 0xf];
        h[61] = "0123456789abcdef"[i & 0xf];
        h[63] = '7';
        e.proTxHash.SetHex(h);
        h[0] = '8';
        e.confirmedHash.SetHex(h);
        e.is_valid = true;
        e.n_type   = 1;   // Evo — also satisfies the platform filter
        e.pub_key_operator[0] = static_cast<uint8_t>(1 + i);
    }
    eng.set_mn_list_at_fn([&](uint32_t) { return list; });

    // Cycle base 905'160 (% 24 == 0); observe 905'153..905'160. The work
    // block 905'152 (% 24 == 16) is BEFORE our window, so seed its hash +
    // CL observability via seed_block_hash… it must be OBSERVED, so start
    // the cursor at 905'151 and walk through it.
    const uint32_t base = 905'160;
    uint256 prev_hash;
    prev_hash.SetHex(
        "0000000000000000000000000000000000000000000000000000000000000aaa");
    eng.seed_cursor(base - 9, prev_hash);
    uint256 base_hash;
    for (uint32_t h = base - 8; h <= base; ++h) {
        QuorumBlockInput in;
        in.height = h;
        std::string hh(64, '0');
        hh[0] = 'd';
        hh[58] = "0123456789abcdef"[(h >> 8) & 0xf];
        hh[59] = "0123456789abcdef"[(h >> 4) & 0xf];
        hh[60] = "0123456789abcdef"[h & 0xf];
        in.block_hash.SetHex(hh);
        if (h == base) base_hash = in.block_hash;
        // Work block carries a (synthetic) CL — exercises the CL-present
        // modifier arm.
        if (h % 24 == 16) {
            std::array<uint8_t, 96> cl{};
            cl[0] = 0x99;
            in.best_cl_sig = cl;
        }
        auto r = eng.observe_block(in);
        ASSERT_TRUE(r.ok) << "h=" << h << ": " << r.error;
        if (h == base) {
            EXPECT_GE(r.member_cycles_derived, 1u)
                << "the 24-interval types must derive members at their base";
        }
    }

    // 50_60 (type 1, non-rotated, size 50): members resolvable by the
    // quorum base hash — the exact (llmqType, quorumHash) contract W1's
    // qfcommit punish pass consumes.
    auto members = eng.members_for(1, base_hash);
    ASSERT_TRUE(members.has_value());
    EXPECT_EQ(members->size(), 50u);
    // And a never-observed hash resolves to nothing (fail closed).
    uint256 unknown;
    unknown.SetHex(
        "00000000000000000000000000000000000000000000000000000000000ffff1");
    EXPECT_FALSE(eng.members_for(1, unknown).has_value());
}

// ═══════════════════════════════════════════════════════════════════════════
// ISSUE #90 — active_set_shortfall() NAMES the blocking type, exactly, and
// closes only when the last missing commitment arrives.
//
// active_sets_complete() is the criterion any future self-check arming will
// key on (the arming itself is NOT in this PR — see
// DashReplayQuorumSeam.BridgeNeverArmsTheRootSelfCheckByItself and the
// ISSUE #90 note in ReplayQuorumBridge::observe). A bare bool cannot say WHY
// a run never completes, which is how the fold_root_vs_committed line came to
// print `0/4684` with no blocking condition named. The shortfall is the
// missing half and it must be EXACT: the right type, the right count, and
// "complete" only when nothing is short.
//
// This engine-level KAT is what the MinedCommitmentIndex KAT-G does NOT
// cover: MinedCommitmentIndex::active_set_shortfall and
// QuorumReplayEngine::active_set_shortfall are two different functions on two
// different stores, and only the latter feeds the bridge's reporting surface.
//
// RED: make QuorumReplayEngine::active_set_shortfall() return {}, or make
//      active_set_shortfall_text() return "complete".
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashReplayQuorumEngine, ActiveSetShortfallNamesTheTypeAndClosesExactly)
{
    // Seed the anchor fixture MINUS one llmq type / minus one row, so the
    // shortfall has a known, checkable value.
    auto seed_except = [](QuorumReplayEngine& eng, int skip_type,
                          int skip_nth_of_type) {
        size_t seeded = 0, skipped = 0;
        std::map<int, int> seen_of_type;
        for (const auto& l :
             read_lines("dash_mainnet_active_quorums_2513685.txt")) {
            auto f = split_ws(l);
            EXPECT_EQ(f.size(), 5u);
            if (f.size() != 5) continue;
            const int type = std::stoi(f[0]);
            const int nth  = seen_of_type[type]++;
            if (type == skip_type
                && (skip_nth_of_type < 0 || nth == skip_nth_of_type)) {
                ++skipped;
                continue;
            }
            auto c = parse_commitment_hex(f[4]);
            EXPECT_TRUE(c.has_value());
            if (!c) continue;
            std::string err;
            EXPECT_TRUE(eng.seed_commitment(
                static_cast<uint32_t>(std::stoul(f[2])), *c, err)) << err;
            ++seeded;
        }
        EXPECT_GT(skipped, 0u) << "the skip must actually skip something";
        return seeded;
    };

    // ── (1) The mainnet reality: type 1 (LLMQ_50_60) entirely absent, which
    //        is what a forward replay from a modern anchor produces — its 24
    //        commitments were mined before DIP0024 and can never be observed.
    {
        QuorumReplayEngine eng(mainnet_cfg());
        seed_except(eng, /*skip_type=*/1, /*skip_nth_of_type=*/-1);
        EXPECT_FALSE(eng.active_sets_complete());
        const auto miss = eng.active_set_shortfall();
        ASSERT_EQ(miss.size(), 1u) << eng.active_set_shortfall_text();
        EXPECT_EQ(int(miss[0].first), 1);
        EXPECT_EQ(miss[0].second, 24u);
        EXPECT_EQ(eng.active_set_shortfall_text(), "type1:short24");
    }

    // ── (2) ONE commitment short of complete is still SHORT, and says so by
    //        name. This is the precision an arming criterion needs: it must
    //        not round 3-of-4 up to "the reconstructed set IS dashd's set".
    {
        QuorumReplayEngine eng(mainnet_cfg());
        seed_except(eng, /*skip_type=*/2, /*skip_nth_of_type=*/0);
        EXPECT_FALSE(eng.active_sets_complete())
            << "one type-2 commitment short must NOT read as complete";
        const auto miss = eng.active_set_shortfall();
        ASSERT_EQ(miss.size(), 1u) << eng.active_set_shortfall_text();
        EXPECT_EQ(int(miss[0].first), 2);
        EXPECT_EQ(miss[0].second, 1u);
        EXPECT_EQ(eng.active_set_shortfall_text(), "type2:short1");
    }

    // ── (3) The full 88-commitment anchor closes it, and the text says so —
    //        so "complete" is a reachable value, not a branch nothing hits.
    {
        QuorumReplayEngine eng(mainnet_cfg());
        ASSERT_EQ(seed_engine_from_anchor(eng), 88u);
        EXPECT_TRUE(eng.active_sets_complete());
        EXPECT_TRUE(eng.active_set_shortfall().empty());
        EXPECT_EQ(eng.active_set_shortfall_text(), "complete");
    }
}
