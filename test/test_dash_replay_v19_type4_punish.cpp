/// ─────────────────────────────────────────────────────────────────────────
/// h=1516043 divergence class: the pre-v19 PLATFORM-quorum PoSe double-punish.
///
/// The full-history replay fold reproduced every committed merkleRootMNList
/// from DIP0003 activation to h=1516042 byte-for-byte, then DIVERGED at
/// h=1516043:  computed ecced0a4… vs committed 028ef00b….  Block 1516043 has
/// no ProReg/ProUpServ/ProUpReg/ProUpRevoke — only two qfcommits: the first
/// LLMQ_50_60 (type 1) commitment marking member idx 33 invalid, and the
/// FIRST-EVER LLMQ_100_67 (type 4, the mainnet PLATFORM quorum, DIP0020
/// activated at 1516032) marking member idx 26 invalid.  The SAME masternode
/// 86f863af… is that invalid member in BOTH quorums; dashd applies
/// CalcPenalty(66)=3072 per commitment, 3072+3072=6144 ≥ CalcMaxPoSePenalty
/// 4656 → instant PoSe-ban → its SML isValid flips 1→0 → committed root
/// 028ef00b….
///
/// The bug: QuorumReplayEngine::produce_early_nonrotated_members computed the
/// platform quorum's members with evo_only UNCONDITIONALLY true.  Pre-v19 NO
/// EvoNodes exist (they arrive at h≈1899072), so the type-4 member set folded
/// EMPTY, its PoSe punish was silently skipped, 86f863af never crossed the ban
/// threshold, isValid stayed 1 and the folded root stuck at ecced0a4 — the
/// list unchanged from 1516042.  dashd restricts the platform quorum to Evo
/// members only from v19 on (llmq/utils.cpp GetAllQuorumMembers:
/// EvoOnly = isPlatform && IsV19Active(baseIndex)); the fix gates evo_only on
/// v19_activation exactly the same way.
///
/// GOLDEN: the committed cbTx merkleRootMNList of mainnet block 1516043,
///         028ef00b1ba952c9aaf0fb2b4d2d220602f19ba55bb75e538c5144ce0cc4dd02.
///
/// Fixture provenance: dash_mainnet_mnlistdiff_1516032.bin is the full
/// `mnlistdiff` (null base → 1516032) captured from an archival mainnet dashd
/// (85.209.241.13:9999, proto 70230).  apply_diff → the 4656-entry SML whose
/// CalcMerkleRoot == the block-1516032 committed root ecced0a4… (asserted
/// below as the seed sanity check).
///
/// Author: frstrtr.
/// ─────────────────────────────────────────────────────────────────────────

#include <gtest/gtest.h>

#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/replay_quorum_engine.hpp>
#include <impl/dash/coin/vendor/smldiff.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/block.hpp>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using dash::coin::BlockType;
using dash::coin::MutableTransaction;
using dash::coin::LlmqNetwork;
using dash::coin::vendor::apply_diff;
using dash::coin::vendor::CCbTx;
using dash::coin::vendor::CFinalCommitment;
using dash::coin::vendor::CFinalCommitmentTxPayload;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListDiff;
using dash::coin::replay::DmlFoldEngine;
using dash::coin::replay::FoldConfig;
using dash::coin::replay::QuorumMnEntry;
using dash::coin::replay::QuorumReplayConfig;
using dash::coin::replay::QuorumReplayEngine;
using dash::coin::replay::ReplayMNState;

namespace {

constexpr uint8_t  kType1        = 1;         // LLMQ_50_60
constexpr uint8_t  kType4        = 4;         // LLMQ_100_67 (mainnet platform)
constexpr uint32_t kBaseHeight   = 1516032;   // the type-1/type-4 DKG base
constexpr uint32_t kDivergeHeight = 1516043;  // the qfcommit-carrying block
constexpr size_t   kType1Size    = 50;
constexpr size_t   kType4Size    = 100;
// The invalid-marked member index in each of block 1516043's two commitments
// (dashd-committed validMembers bitsets: type1 49/50 invalid [33],
// type4 99/100 invalid [26]).
constexpr size_t   kType1InvalidIdx = 33;
constexpr size_t   kType4InvalidIdx = 26;

const char* kBannedDisplay =
    "86f863af002b6c167fa0b219d7f04793827c46dd9bb39459d29b0f02fa90c9c9";
// Committed cbTx merkleRootMNList @1516032 == the engine's STUCK root @1516043
// (list unchanged 1516032..1516042; on master the type-4 punish is dropped so
// the fold produces exactly this — the divergence).
const char* kRootAt1516032 =
    "ecced0a44ba8f31fa31a49bdf4fb40ea0b60d2da1d492c4afb2b340ff82a3364";
// Committed cbTx merkleRootMNList @1516043 (golden): 86f863af isValid 1→0.
const char* kRootAt1516043 =
    "028ef00b1ba952c9aaf0fb2b4d2d220602f19ba55bb75e538c5144ce0cc4dd02";

std::vector<unsigned char> read_fixture() {
    const std::string path =
        std::string(DASH_FIXTURE_DIR) + "/dash_mainnet_mnlistdiff_1516032.bin";
    std::ifstream f(path, std::ios::binary);
    EXPECT_TRUE(f.good()) << "cannot open fixture: " << path;
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(f),
                                      std::istreambuf_iterator<char>());
}

CSimplifiedMNList load_sml_1516032(uint256& base_hash_out) {
    auto bytes = read_fixture();
    ::PackStream in(bytes);
    CSimplifiedMNListDiff diff;
    in >> diff;
    EXPECT_EQ(in.cursor_size(), 0u) << "trailing bytes after mnlistdiff parse";
    EXPECT_EQ(diff.baseBlockHash, uint256::ZERO) << "capture must be a full snapshot";
    base_hash_out = diff.blockHash;
    CSimplifiedMNList sml;
    apply_diff(sml, diff);
    return sml;
}

// The SML carries exactly the fields to_sml_entry re-emits, so the seeded
// ReplayMNState list round-trips through compute_sml_root() to the committed
// 1516032 root byte-for-byte (asserted in the fold test).
std::vector<std::pair<uint256, ReplayMNState>>
fold_entries_from_sml(const CSimplifiedMNList& sml) {
    std::vector<std::pair<uint256, ReplayMNState>> out;
    out.reserve(sml.size());
    for (const auto& e : sml.mnList) {
        ReplayMNState st;
        st.nVersion         = e.nVersion;
        st.confirmedHash    = e.confirmedHash;
        st.netInfo.ip       = e.netAddress;
        st.netInfo.port_be  = e.netPort;
        st.pubKeyOperator   = e.pubKeyOperator;
        st.keyIDVoting      = e.keyIDVoting;
        st.nType            = e.nType;
        st.platformHTTPPort = e.platformHTTPPort;
        st.platformNodeID   = e.platformNodeID;
        if (!e.isValid) st.nPoSeBanHeight = 1;  // isValid == !IsBanned()
        // Any MN whose confirmedHash is still null must NOT re-confirm at the
        // fold height (the committed root is unchanged 1516032..1516043 except
        // for the single ban); seed nRegisteredHeight at H-1 so pass-1's
        // confs==0 keeps it null. Already-confirmed MNs short-circuit pass-1
        // on !IsNull() and ignore this value.
        st.nRegisteredHeight = static_cast<int32_t>(kDivergeHeight) - 1;
        out.emplace_back(e.proRegTxHash, std::move(st));
    }
    return out;
}

std::vector<QuorumMnEntry>
quorum_entries_from_sml(const CSimplifiedMNList& sml) {
    std::vector<QuorumMnEntry> out;
    out.reserve(sml.size());
    for (const auto& e : sml.mnList) {
        QuorumMnEntry q;
        q.proTxHash        = e.proRegTxHash;
        q.confirmedHash    = e.confirmedHash;
        q.is_valid         = e.isValid;
        q.n_type           = e.nType;
        q.pub_key_operator = e.pubKeyOperator;
        q.has_collateral   = false;  // SML-fed: score tiebreak fails closed (no live tie)
        out.push_back(std::move(q));
    }
    return out;
}

// A type-3/type-6 qfcommit tx: a CFinalCommitment for `llmq_type` at the base
// quorum hash, every member valid except `invalid_idx`. Only llmqType /
// quorumHash / validMembers are consulted by the fold.
MutableTransaction make_qfcommit(uint8_t llmq_type, const uint256& quorum_hash,
                                 size_t n_members, size_t invalid_idx) {
    CFinalCommitment c;
    c.nVersion   = CFinalCommitment::LEGACY_BLS_NON_INDEXED_QUORUM_VERSION;
    c.llmqType   = llmq_type;
    c.quorumHash = quorum_hash;
    c.signers.assign(n_members, true);
    c.validMembers.assign(n_members, true);
    c.validMembers[invalid_idx] = false;
    CFinalCommitmentTxPayload pl;
    pl.nVersion   = CFinalCommitmentTxPayload::CURRENT_VERSION;
    pl.nHeight    = kDivergeHeight;
    pl.commitment = std::move(c);
    MutableTransaction tx;
    tx.version = 3;
    tx.type    = CFinalCommitmentTxPayload::SPECIALTX_TYPE;  // 6
    ::PackStream s;
    s << pl;
    auto sp = s.get_span();
    tx.extra_payload.assign(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return tx;
}

MutableTransaction make_coinbase(const uint256& mnlist_root) {
    CCbTx cb;
    cb.nVersion          = CCbTx::VERSION_MERKLE_ROOT_QUORUMS;  // 2 (no CL/balance tail)
    cb.nHeight           = static_cast<int32_t>(kDivergeHeight);
    cb.merkleRootMNList  = mnlist_root;
    cb.merkleRootQuorums = uint256::ZERO;
    MutableTransaction tx;
    tx.version = 3;
    tx.type    = 5;  // TRANSACTION_COINBASE
    ::PackStream s;
    s << cb;
    auto sp = s.get_span();
    tx.extra_payload.assign(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return tx;
}

size_t index_of(const std::vector<uint256>& v, const uint256& x) {
    for (size_t i = 0; i < v.size(); ++i)
        if (v[i] == x) return i;
    return v.size();  // == not found
}

QuorumReplayEngine make_early_engine() {
    QuorumReplayConfig qcfg;
    qcfg.enabled = true;
    qcfg.network = LlmqNetwork::Mainnet;   // v20_floor 1987776, v19_activation 1899072
    return QuorumReplayEngine(qcfg);
}

}  // namespace

// ════════════════════════════════════════════════════════════════════════
// SEAM: the ported gate. Pre-v19 the platform quorum (type 4) draws its
// members from ALL confirmed+valid MNs, and the banned MN is member 26 of it
// (and member 33 of the type-1 quorum). RED on master: the type-4 set is
// EMPTY (evo_only unconditional, no Evo MNs exist pre-v19).
// ════════════════════════════════════════════════════════════════════════
TEST(DashReplayV19Type4Punish, EarlyPlatformQuorumMemberSetIsFullAndHoldsBannedMN) {
    uint256 base_hash;
    const CSimplifiedMNList sml = load_sml_1516032(base_hash);
    ASSERT_EQ(sml.CalcMerkleRoot().GetHex(), std::string(kRootAt1516032));

    QuorumReplayEngine eng = make_early_engine();
    eng.produce_early_nonrotated_members(
        kBaseHeight, base_hash, quorum_entries_from_sml(sml));

    auto t1 = eng.members_for(kType1, base_hash);
    auto t4 = eng.members_for(kType4, base_hash);
    ASSERT_TRUE(t1.has_value());
    ASSERT_TRUE(t4.has_value());
    EXPECT_EQ(t1->size(), kType1Size);
    // The whole fix in one assertion: pre-v19 the platform quorum is a FULL
    // 100-member set, not the empty evo-only set master produced.
    EXPECT_EQ(t4->size(), kType4Size)
        << "pre-v19 LLMQ_100_67 must draw from ALL confirmed+valid MNs; an "
           "empty set here is the h=1516043 divergence (evo_only ungated)";

    uint256 banned;
    banned.SetHex(kBannedDisplay);
    const size_t i1 = index_of(*t1, banned);
    const size_t i4 = index_of(*t4, banned);
    ASSERT_LT(i1, t1->size()) << "86f863af must be a type-1 member";
    ASSERT_LT(i4, t4->size()) << "86f863af must be a type-4 member (dropped on master)";
    // dashd-committed invalid indices for block 1516043's two commitments.
    EXPECT_EQ(i1, kType1InvalidIdx);
    EXPECT_EQ(i4, kType4InvalidIdx);
}

// ════════════════════════════════════════════════════════════════════════
// THE GOLDEN: fold block 1516043 over the real 1516032 list through the
// engine-derived member sets and reproduce the committed root 028ef00b….
// RED on master: type-4 members empty → only the type-1 punish → 86f863af
// stays valid → folded root sticks at ecced0a4… ≠ committed → HARD-STOP
// poison (the exact live divergence). GREEN: the double punish bans it.
// ════════════════════════════════════════════════════════════════════════
TEST(DashReplayV19Type4Punish, FoldReproducesCommittedRootAt1516043) {
    uint256 base_hash;
    const CSimplifiedMNList sml = load_sml_1516032(base_hash);
    ASSERT_EQ(sml.size(), 4656u);
    ASSERT_EQ(sml.CalcMerkleRoot().GetHex(), std::string(kRootAt1516032))
        << "SML from wire must equal dashd's committed 1516032 root";

    // W4 quorum engine: the derived member sets for the two commitments.
    QuorumReplayEngine qeng = make_early_engine();
    qeng.produce_early_nonrotated_members(
        kBaseHeight, base_hash, quorum_entries_from_sml(sml));

    // W1 fold engine, seeded at 1516042 (== 1516032 list; unchanged through
    // 1516042), members resolved from the quorum engine.
    FoldConfig fcfg;
    fcfg.enabled = true;
    DmlFoldEngine feng(fcfg);
    feng.set_members_fn(
        [&qeng](uint8_t t, const uint256& qh) { return qeng.members_for(t, qh); });
    feng.seed(fold_entries_from_sml(sml), sml.size(),
              kDivergeHeight - 1, base_hash, "mainnet");

    // The ReplayMNState seed reproduces the committed 1516032 root byte-exact.
    ASSERT_EQ(feng.compute_sml_root().GetHex(), std::string(kRootAt1516032))
        << "seed round-trip through ReplayMNState::to_sml_entry drifted";

    // Block 1516043: coinbase (answer key 028ef00b) + the two qfcommits.
    BlockType block;
    block.m_txs.push_back(make_coinbase([]{ uint256 r; r.SetHex(kRootAt1516043); return r; }()));
    block.m_txs.push_back(make_qfcommit(kType1, base_hash, kType1Size, kType1InvalidIdx));
    block.m_txs.push_back(make_qfcommit(kType4, base_hash, kType4Size, kType4InvalidIdx));

    const auto r = feng.fold_block(block, kDivergeHeight);

    EXPECT_EQ(r.computed_root.GetHex(), std::string(kRootAt1516043))
        << "folded merkleRootMNList must equal dashd's committed 1516043 root";
    EXPECT_TRUE(r.ok) << r.error;
    EXPECT_FALSE(feng.poisoned()) << feng.poison_reason();
    EXPECT_EQ(r.banned, 1u) << "exactly the double-punished MN 86f863af is banned";
    EXPECT_EQ(feng.compute_sml_root().GetHex(), std::string(kRootAt1516043));
}

// ════════════════════════════════════════════════════════════════════════
// The gate BOTH directions, on a synthetic all-regular list (no fixture):
// below v19 the platform quorum is full; at/after v19 it is evo-only (and so
// empty when no Evo MNs exist). The non-platform type-1 quorum is full in
// both regimes — the fix touches only the platform type.
// ════════════════════════════════════════════════════════════════════════
TEST(DashReplayV19Type4Punish, PlatformEvoOnlyGateFollowsV19BothDirections) {
    // 120 regular (non-Evo) MNs, all confirmed+valid.
    std::vector<QuorumMnEntry> list;
    for (uint32_t i = 0; i < 120; ++i) {
        QuorumMnEntry q;
        uint256 protx, conf;
        std::memset(protx.data(), 0, 32);
        std::memset(conf.data(), 0, 32);
        protx.data()[0] = static_cast<uint8_t>(i);
        protx.data()[1] = 0xa1;
        conf.data()[0]  = static_cast<uint8_t>(i);
        conf.data()[1]  = 0xc2;
        q.proTxHash     = protx;
        q.confirmedHash = conf;
        q.is_valid      = true;
        q.n_type        = 0;  // regular, NOT Evo
        list.push_back(std::move(q));
    }

    uint256 base_hash;
    std::memset(base_hash.data(), 0x7e, 32);

    // Below v19 (default mainnet v19_activation 1899072) → platform quorum full.
    {
        QuorumReplayEngine eng = make_early_engine();
        eng.produce_early_nonrotated_members(1516032u, base_hash, list);
        auto t1 = eng.members_for(kType1, base_hash);
        auto t4 = eng.members_for(kType4, base_hash);
        ASSERT_TRUE(t4.has_value());
        EXPECT_EQ(t4->size(), kType4Size)
            << "pre-v19 platform quorum must draw from all 120 MNs";
        ASSERT_TRUE(t1.has_value());
        EXPECT_EQ(t1->size(), kType1Size);
    }
    // At/after v19 (still below v20_floor 1987776) → platform quorum evo-only
    // → EMPTY (no Evo MNs), while type-1 stays full.
    {
        uint256 bh2;
        std::memset(bh2.data(), 0x5c, 32);
        QuorumReplayEngine eng = make_early_engine();
        eng.produce_early_nonrotated_members(1920000u, bh2, list);
        auto t1 = eng.members_for(kType1, bh2);
        auto t4 = eng.members_for(kType4, bh2);
        ASSERT_TRUE(t4.has_value());
        EXPECT_EQ(t4->size(), 0u)
            << "post-v19 platform quorum is Evo-only; no Evo MNs → empty (dashd-faithful)";
        ASSERT_TRUE(t1.has_value());
        EXPECT_EQ(t1->size(), kType1Size)
            << "the non-platform type-1 quorum is unaffected by the v19 gate";
    }
}
