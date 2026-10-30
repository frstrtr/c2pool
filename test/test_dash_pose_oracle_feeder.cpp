// SPDX-License-Identifier: AGPL-3.0-or-later
/// PoSe PENALTY ORACLE, LIVE (design PR-B §4.2) — the feeder that drives the
/// bridge DML fold engine to the tip and keeps it there
/// (src/impl/dash/coin/pose_oracle_feeder.hpp), and the bridge seams it uses
/// (src/impl/dash/coin/replay_quorum_bridge.hpp).
///
///  1. members_for FALLBACK + request-on-miss (§4.2 item 1): a set the
///     quorum lane cannot derive is answered by the member source; a miss
///     kicks the source and is reported by the pre-fold probe.
///  2. DEFERRED STRADDLE BOOTSTRAP on REAL mainnet bytes (§4.2 item 2): the
///     engine stands at cursor 2513129; block 2513130 carries four punishing
///     llmq_60_75 commitments of cycle 2513088, whose base AND three
///     predecessors predate the cursor. Before the pre-cursor inputs land the
///     block is UNRESOLVED (the feeder holds it — never a fail-closed
///     poison); once the qrinfo-shaped inputs are seeded, the engine's OWN
///     quarter rotation derives the cycle at the cursor and the block folds
///     to its committed merkleRootMNList. Members match dashd's quorum info.
///  3. FEEDER mechanics (synthetic chain): contiguous folding off
///     block_connected with an out-of-order buffer and fork-body rejection;
///     the HOLD on an unresolved member set (released when the source
///     answers, the engine never poisoned); v4 persist + resume only when the
///     snapshot's block is on our header chain; reorg rollback from the
///     in-memory ring; the oracle answering only at the template's tip; the
///     straddle plan at the release anchor 2549400.

#include <gtest/gtest.h>

#include <impl/dash/coin/pose_oracle_feeder.hpp>
#include <impl/dash/coin/sml_pose_fold.hpp>
#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/replay_prestate.hpp>
#include <impl/dash/coin/replay_quorum_bridge.hpp>
#include <impl/dash/coin/replay_quorum_engine.hpp>
#include <impl/dash/coin/dkg_commitments.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/dash/coin/vendor/quorum_members.hpp>
#include <impl/dash/coin/block.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <unistd.h>

#include "data/dash_replay_prestate_2513129.inc"
#include "data/dash_replay_block_2513130.inc"
#include "data/dash_replay_quorum_2513090_idx2.inc"
#include "data/dash_replay_seam_qsnap_2513088.inc"
#include "data/dash_replay_seam_workblocks_2513088.inc"
#include "data/dash_quorum_members_kat.hpp"   // dashd golden: non-rotated member sets

namespace rp = dash::coin::replay;
using dash::coin::BlockType;
using dash::coin::LlmqNetwork;
using dash::coin::MutableTransaction;
using dash::coin::vendor::CCbTx;
using dash::coin::vendor::CFinalCommitment;
using dash::coin::vendor::CFinalCommitmentTxPayload;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListEntry;
namespace ProTxVersion = dash::coin::vendor::ProTxVersion;
namespace MnType = dash::coin::vendor::MnType;

namespace {

// ─── small helpers ──────────────────────────────────────────────────────────

bool hex_to_bytes(const std::string& hex, std::vector<uint8_t>& out)
{
    if (hex.size() % 2) return false;
    out.clear();
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

uint256 raw256(uint8_t base)
{
    uint256 h;
    for (size_t i = 0; i < 32; ++i) h.data()[i] = static_cast<uint8_t>(base + i);
    return h;
}
uint160 raw160(uint8_t base)
{
    uint160 h;
    for (size_t i = 0; i < 20; ++i) h.data()[i] = static_cast<uint8_t>(base + i);
    return h;
}
template <size_t N>
std::array<uint8_t, N> seq_array(uint8_t base)
{
    std::array<uint8_t, N> a{};
    for (size_t i = 0; i < N; ++i) a[i] = static_cast<uint8_t>(base + i);
    return a;
}
// A distinct synthetic "block hash" per height (only identity matters).
uint256 synth_hash(uint32_t h, uint8_t salt = 0)
{
    uint256 v;
    std::memset(v.data(), salt, 32);
    std::memcpy(v.data(), &h, 4);
    v.data()[31] = 0xA5;
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
    return b;
}

std::vector<std::string> split_ws(const std::string& line)
{
    std::vector<std::string> out;
    std::istringstream ls(line);
    std::string t;
    while (ls >> t) out.push_back(t);
    return out;
}

// ─── synthetic chain (the replay_fold KAT conventions) ──────────────────────

rp::FoldConfig synth_cfg()
{
    rp::FoldConfig cfg;
    cfg.enabled = true;
    cfg.gates.dip0003_height = 1;
    cfg.gates.dip0003_enforcement_height = 1;
    cfg.gates.v19_height = 1;
    cfg.gates.mn_rr_height = 1;
    return cfg;
}

rp::ReplayMNState synth_state(uint8_t tag)
{
    rp::ReplayMNState st;
    st.nVersion = ProTxVersion::BASIC_BLS;
    st.nType = MnType::REGULAR;
    st.internalId = tag;
    st.collateralOutpoint.hash  = raw256(static_cast<uint8_t>(0x40 + tag));
    st.collateralOutpoint.index = 1;
    st.netInfo.ip      = seq_array<16>(static_cast<uint8_t>(0x10 + tag));
    st.netInfo.port_be = 9999;
    st.keyIDOwner      = raw160(static_cast<uint8_t>(0x20 + tag));
    st.pubKeyOperator  = seq_array<48>(static_cast<uint8_t>(0x30 + tag));
    st.keyIDVoting     = raw160(static_cast<uint8_t>(0x50 + tag));
    std::vector<unsigned char> sp(25);
    for (size_t i = 0; i < sp.size(); ++i) sp[i] = static_cast<unsigned char>(0x60 + tag + i);
    st.scriptPayout.m_data = sp;
    st.nRegisteredHeight = 1;
    st.confirmedHash = raw256(static_cast<uint8_t>(0x70 + tag));
    return st;
}

CSimplifiedMNListEntry synth_entry(const uint256& protx, const rp::ReplayMNState& st,
                                   bool valid)
{
    CSimplifiedMNListEntry e;
    e.nVersion = st.nVersion;
    e.proRegTxHash = protx;
    e.confirmedHash = st.confirmedHash;
    e.netAddress = st.netInfo.ip;
    e.netPort = st.netInfo.port_be;
    e.pubKeyOperator = st.pubKeyOperator;
    e.keyIDVoting = st.keyIDVoting;
    e.isValid = valid;
    e.nType = st.nType;
    return e;
}

template <typename Payload>
MutableTransaction special_tx(uint16_t type, const Payload& p, uint8_t tag)
{
    MutableTransaction tx;
    tx.version = 3;
    tx.type = type;
    bitcoin_family::coin::TxIn in;
    in.prevout.hash = raw256(static_cast<uint8_t>(0xA0 + tag));
    in.prevout.index = tag;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    auto ps = ::pack(p);
    auto sp = ps.get_span();
    tx.extra_payload.assign(reinterpret_cast<const unsigned char*>(sp.data()),
                            reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return tx;
}

/// A 3-MN chain (a, b, c) with a quorum Q = (a, b, c), fed through a feeder
/// over fake I/O. hash_at() is the "header chain"; blocks are delivered by
/// the test through on_block().
struct SynthChain
{
    rp::DmlFoldEngine eng{synth_cfg()};
    rp::QuorumReplayEngine qeng{[] {
        rp::QuorumReplayConfig c;
        c.enabled = true;
        return c;
    }()};
    rp::ReplayQuorumBridge br{eng, qeng};
    uint256 a{raw256(0xE1)}, b{raw256(0xE2)}, c{raw256(0xE3)};
    std::map<uint256, rp::ReplayMNState> st;
    uint256 quorum{raw256(0xC0)};
    uint8_t tag{10};

    std::map<uint32_t, uint256> chain;      // best-chain header hashes
    std::map<uint32_t, BlockType> bodies;   // the blocks "the network" has
    std::vector<uint256> requested;
    std::vector<std::pair<uint8_t, uint256>> kicked;
    std::optional<std::vector<uint256>> source_answer;   // fallback member source
    uint64_t clock{1000};
    std::string snap_path;

    std::unique_ptr<rp::PoseOracleFeeder> feeder;

    explicit SynthChain(const std::string& snap = "")
        : snap_path(snap)
    {
        st[a] = synth_state(1);
        st[b] = synth_state(2);
        st[c] = synth_state(3);
        chain[100] = raw256(9);
        br.set_members_fallback(
            [this](uint8_t, const uint256& qh) -> std::optional<std::vector<uint256>> {
                if (qh == quorum && source_answer) return source_answer;
                return std::nullopt;
            },
            [this](uint8_t t, const uint256& qh) { kicked.emplace_back(t, qh); });
        make_feeder();
    }

    void make_feeder()
    {
        rp::PoseOracleConfig cfg;
        cfg.net_name = "mainnet";
        cfg.anchor_height = 100;
        cfg.anchor_hash = raw256(9);
        cfg.snapshot_path = snap_path;
        cfg.straddle_bootstrap = false;     // synthetic heights: below every LLMQ floor
        cfg.persist_every_tip = 1;
        rp::PoseOracleIo io;
        io.hash_at = [this](uint32_t h) -> std::optional<uint256> {
            auto it = chain.find(h);
            if (it == chain.end()) return std::nullopt;
            return it->second;
        };
        io.tip_height = [this]() { return chain.empty() ? 0u : chain.rbegin()->first; };
        io.merkle_root_of = [](const uint256&) -> std::optional<uint256> { return std::nullopt; };
        io.request_block = [this](const uint256& h) { requested.push_back(h); return true; };
        io.send_getmnlistd = [](const uint256&, const uint256&) {};
        io.send_getqrinfo = [](const uint256&) {};
        io.now_ms = [this]() { return clock; };
        io.anchor_entries = [this](const CSimplifiedMNList&, size_t& w, size_t& wo) {
            w = 3; wo = 0;
            std::vector<std::pair<uint256, rp::ReplayMNState>> v;
            for (auto& [p, s] : st) v.emplace_back(p, s);
            return v;
        };
        feeder = std::make_unique<rp::PoseOracleFeeder>(eng, qeng, br, cfg, std::move(io));
    }

    uint256 root(const std::set<uint256>& banned = {}) const
    {
        std::vector<CSimplifiedMNListEntry> v;
        for (const auto& [p, s] : st) v.push_back(synth_entry(p, s, !banned.count(p)));
        CSimplifiedMNList sml(std::move(v));
        return sml.CalcMerkleRoot();
    }

    // The anchor seed the lane would deliver (its root is what matters).
    CSimplifiedMNList anchor_sml() const
    {
        std::vector<CSimplifiedMNListEntry> v;
        for (const auto& [p, s] : st) v.push_back(synth_entry(p, s, true));
        return CSimplifiedMNList(std::move(v));
    }

    MutableTransaction qc_marking(const uint256& who)
    {
        CFinalCommitmentTxPayload qc;
        qc.nVersion = 1;
        qc.commitment.nVersion = CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
        qc.commitment.llmqType = CFinalCommitment::LLMQ_100_67;
        qc.commitment.quorumHash = quorum;
        std::vector<bool> valid{who != a, who != b, who != c};
        qc.commitment.signers = valid;
        qc.commitment.validMembers = valid;
        qc.commitment.quorumPublicKey = seq_array<48>(0xD0);
        qc.commitment.quorumVvecHash = raw256(0xD1);
        qc.commitment.quorumSig = seq_array<96>(0xD2);
        qc.commitment.membersSig = seq_array<96>(0xD3);
        return special_tx(6, qc, ++tag);
    }

    /// Build block h on top of the CURRENT chain (payee projected from a
    /// shadow engine that mirrors what dashd folds), register its hash.
    BlockType make(uint32_t h, std::vector<MutableTransaction> txs,
                   const rp::DmlFoldEngine& payee_from,
                   const std::set<uint256>& banned = {}, uint8_t salt = 0)
    {
        BlockType blk;
        blk.m_version = 536870912;
        blk.m_previous_block = chain.count(h - 1) ? chain[h - 1] : uint256();
        blk.m_timestamp = 1700000000 + h + salt;
        blk.m_bits = 0x1e0fffff;
        blk.m_nonce = h * 7 + salt;
        CCbTx cb;
        cb.nVersion = CCbTx::VERSION_MERKLE_ROOT_QUORUMS;
        cb.nHeight = static_cast<int32_t>(h);
        cb.merkleRootMNList = root(banned);
        MutableTransaction cbtx;
        cbtx.version = 3;
        cbtx.type = 5;
        bitcoin_family::coin::TxIn in;
        in.prevout.hash.SetNull();
        in.prevout.index = 0xffffffff;
        cbtx.vin.push_back(in);
        auto ps = ::pack(cb);
        auto sp = ps.get_span();
        cbtx.extra_payload.assign(reinterpret_cast<const unsigned char*>(sp.data()),
                                  reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
        if (auto p = payee_from.project_payee(static_cast<int32_t>(h))) {
            bitcoin_family::coin::TxOut out;
            out.value = 1;
            out.scriptPubKey.m_data = payee_from.find(*p)->scriptPayout.m_data;
            cbtx.vout.push_back(out);
        }
        blk.m_txs.push_back(std::move(cbtx));
        for (auto& t : txs) blk.m_txs.push_back(std::move(t));
        chain[h] = rp::DmlFoldEngine::block_header_hash(blk);
        bodies[h] = blk;
        return blk;
    }

    void seed_via_lane() { feeder->on_anchor_sml(anchor_sml()); }
};

/// A shadow engine that folds the same synthetic blocks (to project the
/// payee each block's coinbase must pay).
struct Shadow
{
    rp::DmlFoldEngine eng{synth_cfg()};
    explicit Shadow(SynthChain& ch)
    {
        std::vector<std::pair<uint256, rp::ReplayMNState>> v;
        for (auto& [p, s] : ch.st) v.emplace_back(p, s);
        eng.seed(std::move(v), 3, 100, raw256(9));
        eng.set_members_fn([&ch](uint8_t, const uint256&) -> std::optional<std::vector<uint256>> {
            return std::vector<uint256>{ch.a, ch.b, ch.c};
        });
    }
    void fold(const BlockType& b, uint32_t h) { ASSERT_TRUE(eng.fold_block(b, h).ok); }
};

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// 1. members_for fallback + request-on-miss (bridge)
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashPoseOracleBridge, MembersForFallsBackToTheSourceAndKicksOnMiss)
{
    SynthChain ch;
    // Nothing derived by the quorum lane; the source does not know Q yet.
    EXPECT_FALSE(ch.br.members_for(4, ch.quorum).has_value());
    ASSERT_EQ(ch.kicked.size(), 1u);
    EXPECT_EQ(ch.kicked[0].second, ch.quorum);
    EXPECT_EQ(ch.br.stats().members_missing, 1u);

    // The source answers: the bridge returns ITS set (index-aligned).
    ch.source_answer = std::vector<uint256>{ch.a, ch.b, ch.c};
    auto m = ch.br.members_for(4, ch.quorum);
    ASSERT_TRUE(m.has_value());
    EXPECT_EQ((*m)[1], ch.b);
    EXPECT_EQ(ch.br.stats().members_from_fallback, 1u);

    // The pre-fold probe: a punishing commitment whose set is unresolvable is
    // reported (and kicked); all-valid / resolvable ones are not.
    Shadow sh(ch);
    ch.source_answer.reset();
    auto blk = ch.make(101, {ch.qc_marking(ch.a)}, sh.eng);
    const size_t kicks_before = ch.kicked.size();
    auto miss = ch.br.unresolved_member_sets(blk);
    ASSERT_EQ(miss.size(), 1u);
    EXPECT_EQ(miss[0].first, CFinalCommitment::LLMQ_100_67);
    EXPECT_EQ(ch.kicked.size(), kicks_before + 1);
    ch.source_answer = std::vector<uint256>{ch.a, ch.b, ch.c};
    EXPECT_TRUE(ch.br.unresolved_member_sets(blk).empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. DEFERRED STRADDLE BOOTSTRAP on real mainnet bytes (cycle 2513088)
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashPoseOracleStraddle, DeferredBootstrapDerivesCycle2513088AtTheCursorThenFolds2513130)
{
    constexpr uint32_t kS  = 2'513'129;
    constexpr uint32_t kB0 = 2'513'088;
    constexpr uint32_t kC  = 288;
    constexpr uint8_t  kT  = 5;

    rp::FoldConfig fcfg;
    fcfg.enabled = true;
    rp::DmlFoldEngine eng(fcfg);
    auto ps = rp::parse_prestate_text(kDashReplayPrestate2513129);
    ASSERT_TRUE(ps.ok) << ps.error;
    ASSERT_TRUE(rp::seed_engine_from_prestate(eng, ps).empty());
    rp::QuorumReplayConfig qcfg;
    qcfg.enabled = true;
    rp::QuorumReplayEngine q(qcfg);
    q.seed_cursor(kS, eng.block_hash());
    rp::ReplayQuorumBridge br(eng, q);
    br.prime_at_anchor();

    const BlockType blk = parse_block(kDashReplayBlock2513130);

    // BEFORE the bootstrap: the four punishing llmq_60_75 commitments have no
    // member set (cycle base AND predecessors predate the cursor). The feeder
    // HOLDS such a block; folding it now is the production cap (a poison).
    auto miss = br.unresolved_member_sets(blk, /*kick=*/false);
    ASSERT_EQ(miss.size(), 4u);
    for (const auto& [t, qh] : miss) EXPECT_EQ(t, kT);
    {
        rp::DmlFoldEngine probe(fcfg);
        ASSERT_TRUE(rp::seed_engine_from_prestate(probe, ps).empty());
        rp::QuorumReplayEngine q2(qcfg);
        q2.seed_cursor(kS, probe.block_hash());
        rp::ReplayQuorumBridge br2(probe, q2);
        auto r = probe.fold_block(blk, kS + 1);
        EXPECT_FALSE(r.ok);
        EXPECT_TRUE(probe.poisoned()) << "folding unresolved = the old cap";
    }

    // Pre-cursor block hashes of the cycle's quorum bases (the header chain,
    // here taken from the block's own commitments: quorumHash <-> cyc0 + qi).
    std::map<uint32_t, uint256> hashes;
    for (size_t i = 1; i < blk.m_txs.size(); ++i) {
        const auto& tx = blk.m_txs[i];
        if (tx.version != 3 || tx.type != 6) continue;
        CFinalCommitmentTxPayload qc;
        ASSERT_TRUE(dash::coin::vendor::parse_qfcommit_payload(tx.extra_payload, qc));
        hashes[kB0 + static_cast<uint32_t>(qc.commitment.quorumIndex)] = qc.commitment.quorumHash;
    }
    EXPECT_EQ(br.seed_block_hashes(kB0, kS, [&](uint32_t h) -> std::optional<uint256> {
        auto it = hashes.find(h);
        if (it == hashes.end()) return std::nullopt;
        return it->second;
    }), 32u);

    // The qrinfo(cyc0)-shaped inputs, exactly as land_qrinfo_b0 seeds them:
    // three predecessor snapshots, three predecessor work lists (+ hash, CL,
    // modifier), and cyc0's own work list (the H leg).
    auto snaps = rp::parse_qsnapshot_seed_text(kDashReplaySeamQSnapshots2513088);
    ASSERT_TRUE(snaps.ok) << snaps.error;
    std::string err;
    ASSERT_TRUE(br.seed_snapshots(snaps, kS, err)) << err;
    auto works = rp::parse_work_list_seed_text(kDashReplaySeamWorkBlocks2513088);
    ASSERT_TRUE(works.ok) << works.error;
    rp::WorkListSeed prev = works;
    prev.works.clear();
    const rp::WorkListSeedEntry* hleg = nullptr;
    for (const auto& w : works.works) {
        if (w.cycle_base == kB0) hleg = &w;
        else prev.works.push_back(w);
    }
    ASSERT_NE(hleg, nullptr);
    ASSERT_EQ(prev.works.size(), 3u);
    ASSERT_TRUE(br.seed_work_lists(prev, kS, err)) << err;
    std::optional<std::array<uint8_t, CCbTx::BLS_SIG_SIZE>> cl;
    if (hleg->has_cl) cl = hleg->cl_sig;
    ASSERT_TRUE(br.seed_pre_cursor_work_list(kB0 - 8, hleg->block_hash, cl,
                                             hleg->entries, kS, err)) << err;
    // A height after the cursor is never seedable.
    EXPECT_FALSE(br.seed_pre_cursor_work_list(kS + 1, hleg->block_hash, cl,
                                              hleg->entries, kS, err));

    // The engine's OWN quarter rotation, out of band, at the cursor.
    auto dr = br.derive_at(kB0);
    EXPECT_GE(dr.derived, 1u);
    for (uint32_t i = 0; i < 32; ++i)
        EXPECT_TRUE(q.has_members_at(kT, kB0 + i)) << "qi=" << i;
    // ...and it PRODUCED cyc0's snapshot, which cyc0+C's derivation will read.
    EXPECT_TRUE(q.snapshot_for(kT, kB0).has_value());
    (void)kC;

    // Members of quorumIndex 2 == dashd's own `quorum info`.
    {
        std::istringstream is(kDashReplayQuorumMembers2513090Idx2);
        std::string line;
        std::vector<uint256> want;
        while (std::getline(is, line)) {
            auto f = split_ws(line);
            if (f.size() >= 2 && f[0] == "member") {
                std::vector<uint8_t> bb;
                ASSERT_TRUE(hex_to_bytes(f[1], bb));
                uint256 v;
                std::memcpy(v.data(), bb.data(), 32);
                want.push_back(v);
            }
        }
        auto got = q.members_for(kT, hashes.at(kB0 + 2));
        ASSERT_TRUE(got.has_value());
        ASSERT_EQ(got->size(), want.size());
        for (size_t i = 0; i < want.size(); ++i) EXPECT_EQ((*got)[i], want[i]) << i;
    }

    // NOW the block is resolvable and folds to its own committed root.
    EXPECT_TRUE(br.unresolved_member_sets(blk, false).empty());
    const uint256 bh = rp::DmlFoldEngine::block_header_hash(blk);
    br.observe(kS + 1, bh, blk);
    auto r = eng.fold_block(blk, kS + 1);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.computed_root.GetHex(),
              "2315e6dfcd7e3256288d73aa8a2022395561f7625da2b20d0eedde22622d120b");
    EXPECT_EQ(r.punished, 4u);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. FEEDER mechanics
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashPoseOracleFeeder, FoldsContiguouslyBuffersOutOfOrderAndDropsForkBodies)
{
    SynthChain ch;
    Shadow sh(ch);
    ch.seed_via_lane();
    ASSERT_TRUE(ch.feeder->seeded());
    EXPECT_EQ(ch.feeder->stats().seed_source, "anchor");
    EXPECT_EQ(ch.eng.find(ch.a)->nPoSePenaltyHi, 200);   // unknown-penalty seed

    std::vector<BlockType> blks;
    for (uint32_t h = 101; h <= 104; ++h) {
        blks.push_back(ch.make(h, {}, sh.eng));
        sh.fold(blks.back(), h);
    }
    // A fork body at 102 (not the best-chain header) is dropped.
    BlockType fork = blks[1];
    fork.m_nonce ^= 0x5555;
    ch.feeder->on_block(fork, 102);
    EXPECT_EQ(ch.feeder->stats().dropped_fork_bodies, 1u);
    // Out of order: 103, 104 buffer; 101 releases 101; 102 releases the rest.
    ch.feeder->on_block(blks[2], 103);
    ch.feeder->on_block(blks[3], 104);
    EXPECT_EQ(ch.eng.height(), 100u);
    ch.feeder->on_block(blks[0], 101);
    EXPECT_EQ(ch.eng.height(), 101u);
    EXPECT_EQ(ch.feeder->buffered(), 2u);
    ch.feeder->on_block(blks[1], 102);
    EXPECT_EQ(ch.eng.height(), 104u);
    EXPECT_EQ(ch.feeder->stats().folded, 4u);
    EXPECT_EQ(ch.eng.find(ch.a)->nPoSePenaltyHi, 196);
    // Nothing was fetched: every height arrived on block_connected.
    // (Missing heights are requested — next test.)
}

// The quorum lane's cursor is forward-contiguous like the fold's: a body the
// fold refuses with its state unchanged (a tx dashd's
// ContextualCheckTransaction rejects) must never reach it, or the lane sits
// one block ahead and refuses the valid sibling at that height.
TEST(DashPoseOracleFeeder, RefusedBodyNeverReachesTheQuorumLane)
{
    SynthChain ch;
    Shadow sh(ch);
    ch.seed_via_lane();
    ASSERT_TRUE(ch.feeder->seeded());
    const uint64_t observed0 = ch.br.stats().blocks_observed;
    const uint32_t qh0 = ch.qeng.height();

    MutableTransaction neg;           // nVersion -1: v23.1.9 bad-txns-version
    neg.version = 0xFFFF;
    bitcoin_family::coin::TxIn in;
    in.prevout.hash = raw256(0xA9);
    in.prevout.index = 3;
    in.sequence = 0xffffffff;
    neg.vin.push_back(in);
    bitcoin_family::coin::TxOut out;
    out.value = 5;
    neg.vout.push_back(out);
    const BlockType bad = ch.make(101, {neg}, sh.eng);
    ch.feeder->on_block(bad, 101);
    EXPECT_EQ(ch.eng.height(), 100u);
    EXPECT_FALSE(ch.eng.poisoned());
    EXPECT_EQ(ch.feeder->stats().refused_unchanged, 1u);
    EXPECT_EQ(ch.br.stats().blocks_observed, observed0)
        << "the refused body reached the quorum lane";
    EXPECT_EQ(ch.qeng.height(), qh0);

    // The best chain moves to the valid sibling: it folds, and the quorum
    // lane observes exactly that block.
    const BlockType good = ch.make(101, {}, sh.eng, {}, /*salt=*/1);
    sh.fold(good, 101);
    ch.feeder->on_block(good, 101);
    EXPECT_EQ(ch.eng.height(), 101u);
    EXPECT_EQ(ch.feeder->stats().folded, 1u);
    EXPECT_EQ(ch.br.stats().blocks_observed, observed0 + 1);
    EXPECT_EQ(ch.qeng.height(), qh0 + 1);
}

TEST(DashPoseOracleFeeder, RequestsHeightsNobodyDeliversAndRefetchesOnTimeout)
{
    SynthChain ch;
    Shadow sh(ch);
    ch.seed_via_lane();
    for (uint32_t h = 101; h <= 103; ++h) sh.fold(ch.make(h, {}, sh.eng), h);
    ch.feeder->on_tick();
    ASSERT_EQ(ch.requested.size(), 3u);
    EXPECT_EQ(ch.requested[0], ch.chain[101]);
    ch.feeder->on_tick();                       // within refetch_ms: no re-ask
    EXPECT_EQ(ch.requested.size(), 3u);
    ch.clock += 31000;
    ch.feeder->on_tick();
    EXPECT_EQ(ch.requested.size(), 6u);
    ch.feeder->on_block(ch.bodies[101], 101);
    ch.feeder->on_block(ch.bodies[102], 102);
    ch.feeder->on_block(ch.bodies[103], 103);
    EXPECT_EQ(ch.eng.height(), 103u);
}

TEST(DashPoseOracleFeeder, HoldsAPunishingBlockUntilTheMemberSourceAnswersNeverPoisons)
{
    SynthChain ch;
    Shadow sh(ch);
    ch.seed_via_lane();
    auto b101 = ch.make(101, {ch.qc_marking(ch.a)}, sh.eng);
    sh.fold(b101, 101);
    auto b102 = ch.make(102, {}, sh.eng);
    sh.fold(b102, 102);

    ch.feeder->on_block(b101, 101);
    ch.feeder->on_block(b102, 102);
    // HELD, not folded, not poisoned; the source was asked.
    EXPECT_EQ(ch.eng.height(), 100u);
    EXPECT_FALSE(ch.eng.poisoned());
    EXPECT_EQ(ch.feeder->stats().holds, 1u);
    EXPECT_FALSE(ch.kicked.empty());
    EXPECT_FALSE(ch.feeder->oracle_bounds(101, ch.chain[101], ch.a).has_value());

    // The member source answers: the held block (and the next) fold.
    ch.source_answer = std::vector<uint256>{ch.a, ch.b, ch.c};
    ch.feeder->on_tick();
    EXPECT_EQ(ch.eng.height(), 102u);
    EXPECT_FALSE(ch.eng.poisoned());
    auto v = ch.feeder->oracle_bounds(102, ch.chain[102], ch.a);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(v->lo, 65);    // 0 -> +66 at 101 -> decay at 102
    EXPECT_EQ(v->hi, 99);    // 200 -> 199 -> +66 -> clamp 100 -> 99
}

TEST(DashPoseOracleFeeder, OracleAnswersOnlyAtTheTemplateTip)
{
    SynthChain ch;
    Shadow sh(ch);
    ch.seed_via_lane();
    auto b101 = ch.make(101, {}, sh.eng);
    sh.fold(b101, 101);
    ch.feeder->on_block(b101, 101);
    ASSERT_TRUE(ch.feeder->cursor().has_value());
    EXPECT_EQ(ch.feeder->cursor()->first, 101u);
    EXPECT_TRUE(ch.feeder->oracle_bounds(101, ch.chain[101], ch.b).has_value());
    EXPECT_FALSE(ch.feeder->oracle_bounds(100, ch.chain[100], ch.b).has_value());
    EXPECT_FALSE(ch.feeder->oracle_bounds(101, raw256(0x77), ch.b).has_value());
    // The tip moved on but its body has not arrived: not at tip.
    auto b102 = ch.make(102, {}, sh.eng);
    EXPECT_FALSE(ch.feeder->oracle_bounds(102, ch.chain[102], ch.b).has_value());
}

TEST(DashPoseOracleFeeder, PersistsV4AndResumesOnlyWhenTheBlockIsOnOurHeaderChain)
{
    const std::string path =
        (std::filesystem::temp_directory_path()
         / ("pose_oracle_kat_" + std::to_string(::getpid()) + ".snap")).string();
    std::remove(path.c_str());
    std::map<uint32_t, uint256> chain_copy;
    std::map<uint32_t, BlockType> bodies_copy;
    {
        SynthChain ch(path);
        Shadow sh(ch);
        ch.seed_via_lane();
        auto b101 = ch.make(101, {ch.qc_marking(ch.a)}, sh.eng);
        sh.fold(b101, 101);
        ch.source_answer = std::vector<uint256>{ch.a, ch.b, ch.c};
        ch.feeder->on_block(b101, 101);
        ASSERT_EQ(ch.eng.height(), 101u);
        // persist_every_tip = 1 -> written at 101.
        EXPECT_GE(ch.feeder->stats().persisted, 1u);
        chain_copy = ch.chain;
        bodies_copy = ch.bodies;
    }
    {
        // Same chain: RESUMES (no anchor seed needed), bounds intact.
        SynthChain ch(path);
        ch.chain = chain_copy;
        ch.feeder->on_tick();
        ASSERT_TRUE(ch.feeder->seeded());
        EXPECT_EQ(ch.feeder->stats().seed_source, "snapshot");
        EXPECT_EQ(ch.eng.height(), 101u);
        EXPECT_EQ(ch.eng.loaded_snapshot_version(), 4u);
        EXPECT_EQ(ch.eng.find(ch.a)->nPoSePenalty, 66);
        EXPECT_EQ(ch.eng.find(ch.a)->nPoSePenaltyHi, 100);
        EXPECT_EQ(ch.eng.find(ch.b)->nPoSePenaltyHi, 199);
        // and it keeps folding from there
        Shadow sh(ch);
        sh.eng.set_members_fn([&](uint8_t, const uint256&) -> std::optional<std::vector<uint256>> {
            return std::vector<uint256>{ch.a, ch.b, ch.c};
        });
        sh.fold(bodies_copy[101], 101);
        auto b102 = ch.make(102, {}, sh.eng);
        ch.feeder->on_block(b102, 102);
        EXPECT_EQ(ch.eng.height(), 102u);
    }
    {
        // A different chain at 101: the snapshot is DISCARDED, never loaded.
        SynthChain ch(path);
        ch.chain = chain_copy;
        ch.chain[101] = raw256(0x55);
        ch.chain[102] = raw256(0x56);
        ch.feeder->on_tick();
        EXPECT_FALSE(ch.feeder->seeded());
        ch.seed_via_lane();
        EXPECT_EQ(ch.feeder->stats().seed_source, "anchor");
        EXPECT_EQ(ch.eng.height(), 100u);
    }
    std::remove(path.c_str());
}

TEST(DashPoseOracleFeeder, RollsBackOnReorgFromTheInMemoryRing)
{
    SynthChain ch;
    Shadow sh(ch);
    ch.seed_via_lane();
    std::vector<BlockType> main;
    for (uint32_t h = 101; h <= 103; ++h) {
        main.push_back(ch.make(h, {}, sh.eng));
        sh.fold(main.back(), h);
        ch.feeder->on_block(main.back(), h);
    }
    ASSERT_EQ(ch.eng.height(), 103u);
    const uint256 old103 = ch.chain[103];

    // A competing 103' wins (ChainLock): the header chain now says 103'.
    Shadow sh2(ch);
    sh2.fold(main[0], 101);
    sh2.fold(main[1], 102);
    auto alt = ch.make(103, {}, sh2.eng, {}, /*salt=*/9);
    ASSERT_NE(ch.chain[103], old103);
    ch.feeder->on_tick();
    EXPECT_EQ(ch.feeder->stats().rollbacks, 1u);
    EXPECT_EQ(ch.eng.height(), 102u);
    EXPECT_EQ(ch.eng.block_hash(), ch.chain[102]);
    ch.feeder->on_block(alt, 103);
    EXPECT_EQ(ch.eng.height(), 103u);
    EXPECT_EQ(ch.eng.block_hash(), ch.chain[103]);
}

// The straddle plan at the release anchor (2549400): rotated cyc0 = 2549376
// (window 2549418..2549426 is after the anchor) and cyc1 = 2549664; the only
// non-rotated base needing a pre-anchor work list is type 4 @ 2549400
// (work 2549392) — types 2/3 @ 2549376 share cyc0's work block (qrinfo H leg).
// cyc0's header is below the fast-start anchor, so the first request is
// getqrinfo(cyc1) (whose H-4C leg is the backfill locator).
TEST(DashPoseOracleFeeder, StraddlePlanAtTheReleaseAnchor2549400)
{
    rp::DmlFoldEngine eng(synth_cfg());
    rp::QuorumReplayConfig qc;
    qc.enabled = true;
    rp::QuorumReplayEngine q(qc);
    rp::ReplayQuorumBridge br(eng, q);
    constexpr uint32_t kA = 2'549'400;
    std::map<uint32_t, uint256> chain;
    for (uint32_t h = kA; h <= kA + 400; ++h) chain[h] = synth_hash(h);
    std::vector<uint256> qrinfo_asked;
    rp::PoseOracleConfig cfg;
    cfg.anchor_height = kA;
    cfg.anchor_hash = chain[kA];
    rp::PoseOracleIo io;
    io.hash_at = [&](uint32_t h) -> std::optional<uint256> {
        auto it = chain.find(h);
        if (it == chain.end()) return std::nullopt;
        return it->second;
    };
    io.tip_height = [&]() { return chain.rbegin()->first; };
    io.merkle_root_of = [](const uint256&) -> std::optional<uint256> { return std::nullopt; };
    io.send_getmnlistd = [](const uint256&, const uint256&) {};
    io.send_getqrinfo = [&](const uint256& h) { qrinfo_asked.push_back(h); };
    io.now_ms = []() -> uint64_t { return 5000; };
    rp::PoseOracleFeeder f(eng, q, br, cfg, std::move(io));
    auto s1 = synth_state(1);
    eng.seed({{raw256(0xE1), s1}}, 1, kA, chain[kA]);
    f.adopt_current_state("test");
    auto p = f.boot_plan();
    EXPECT_EQ(p.cursor, kA);
    EXPECT_EQ(p.cyc0, 2'549'376u);
    EXPECT_EQ(p.cyc1, 2'549'664u);
    EXPECT_EQ(p.work_heights, (std::vector<uint32_t>{2'549'392u}));
    EXPECT_EQ(p.derive_bases, (std::vector<uint32_t>{2'549'376u, 2'549'400u}));
    EXPECT_FALSE(p.hashes_ready);   // pre-anchor headers not held yet
    ASSERT_EQ(qrinfo_asked.size(), 1u);
    EXPECT_EQ(qrinfo_asked[0], chain[2'549'664]);
    // Nothing folds until the pre-cursor hashes exist (quorum ingest).
    EXPECT_FALSE(f.cursor() && f.boot_plan().complete);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. END TO END: the feeder's oracle consumed by PR-A's serve-time PoSe pass
//    (sml_pose_fold.hpp decide_qc_pose), exactly as main_dash wires it.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashPoseOracleFeeder, OracleDrivesThePoSePassProvenNoBanProvenBanAndOffTipRefusal)
{
    SynthChain ch;
    Shadow sh(ch);
    ch.source_answer = std::vector<uint256>{ch.a, ch.b, ch.c};
    ch.seed_via_lane();
    // 170 clean blocks: every MN's bound converges to [0, 30].
    for (uint32_t h = 101; h <= 270; ++h) {
        auto blk = ch.make(h, {}, sh.eng);
        sh.fold(blk, h);
        ch.feeder->on_block(blk, h);
    }
    ASSERT_EQ(ch.eng.height(), 270u);
    EXPECT_EQ(ch.eng.find(ch.b)->nPoSePenaltyHi, 30);

    dash::coin::PoSeOracle oracle;
    oracle.penalty = [&](const uint256& pro) -> std::optional<dash::coin::PoSePenaltyView> {
        auto cur = ch.feeder->cursor();
        if (!cur) return std::nullopt;
        auto v = ch.feeder->oracle_bounds(cur->first, cur->second, pro);
        if (!v) return std::nullopt;
        return dash::coin::PoSePenaltyView{v->lo, v->hi, v->banned};
    };
    oracle.cursor = [&]() { return ch.feeder->cursor(); };
    dash::coin::QcMembersFn members = [&](uint8_t, const uint256&)
        -> std::optional<std::vector<uint256>> {
        return std::vector<uint256>{ch.a, ch.b, ch.c};
    };
    auto commitment_marking = [&](const uint256& who) {
        CFinalCommitment c;
        c.nVersion = CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
        c.llmqType = CFinalCommitment::LLMQ_100_67;
        c.quorumHash = ch.quorum;
        std::vector<bool> valid{who != ch.a, who != ch.b, who != ch.c};
        c.signers = valid;
        c.validMembers = valid;
        c.quorumPublicKey = seq_array<48>(0xD0);
        c.quorumVvecHash = raw256(0xD1);
        c.quorumSig = seq_array<96>(0xD2);
        c.membersSig = seq_array<96>(0xD3);
        return c;
    };
    const CSimplifiedMNList tip_sml = ch.anchor_sml();   // all valid

    // PROVEN NO-BAN: b in [0,30] -> decay [0,29] -> +66 -> hi 95 < max 100.
    auto d = dash::coin::decide_qc_pose(tip_sml, {commitment_marking(ch.b)}, members,
                                        &oracle, 270, ch.chain[270]);
    EXPECT_TRUE(d.ok()) << dash::coin::qc_pose_stage_name(d.stage);
    EXPECT_EQ(d.punished, 1u);
    EXPECT_TRUE(d.bans.empty());

    // OFF TIP: a template on 269 must not read the 270 state.
    d = dash::coin::decide_qc_pose(tip_sml, {commitment_marking(ch.b)}, members,
                                   &oracle, 269, ch.chain[269]);
    EXPECT_EQ(d.stage, dash::coin::QcPoseStage::OracleNotAtTip);

    // A real punish of `a` at 271 (dashd: no ban) leaves a at [66, 95].
    auto b271 = ch.make(271, {ch.qc_marking(ch.a)}, sh.eng);
    sh.fold(b271, 271);
    ch.feeder->on_block(b271, 271);
    ASSERT_EQ(ch.eng.height(), 271u);
    EXPECT_EQ(ch.eng.find(ch.a)->nPoSePenalty, 66);
    EXPECT_EQ(ch.eng.find(ch.a)->nPoSePenaltyHi, 95);

    // PROVEN BAN: a [66,95] -> decay [65,94] -> +66 -> both clamp to 100.
    d = dash::coin::decide_qc_pose(tip_sml, {commitment_marking(ch.a)}, members,
                                   &oracle, 271, ch.chain[271]);
    ASSERT_TRUE(d.ok()) << dash::coin::qc_pose_stage_name(d.stage);
    ASSERT_EQ(d.bans.size(), 1u);
    EXPECT_EQ(d.bans[0], ch.a);

    // UNPROVEN: right after the seed (b at [0,200]) the same pass refuses.
    SynthChain fresh;
    fresh.seed_via_lane();
    dash::coin::PoSeOracle o2;
    o2.penalty = [&](const uint256& pro) -> std::optional<dash::coin::PoSePenaltyView> {
        auto v = fresh.feeder->oracle_bounds(100, fresh.chain[100], pro);
        if (!v) return std::nullopt;
        return dash::coin::PoSePenaltyView{v->lo, v->hi, v->banned};
    };
    o2.cursor = [&]() { return fresh.feeder->cursor(); };
    d = dash::coin::decide_qc_pose(fresh.anchor_sml(), {commitment_marking(fresh.b)},
                                   members, &o2, 100, fresh.chain[100]);
    EXPECT_EQ(d.stage, dash::coin::QcPoseStage::PenaltyInexact);
}


// ═══════════════════════════════════════════════════════════════════════════
// 5. NON-ROTATED MEMBER ATTRIBUTION vs dashd (PR-B verify, must-fix 1)
//
// The fold engine derives non-rotated member sets with ITS OWN CalculateQuorum
// port (replay_quorum_engine.hpp mn_score / calculate_quorum_all /
// compute_nonrotated_members), not the vendored compute_quorum_members the
// serve path uses. A wrong order there mis-attributes PoSe punishes: lo moves
// on the wrong MN and hi stays too low on the right one, the per-block root
// check stays green (no ban moved), and ~1000 blocks later the pass would
// serve a "provable" decision dashd disagrees with. Pin it to dashd's own
// `quorum info` (test/data/dash_quorum_members_kat.hpp, testnet base 1519920,
// work block 1519912): llmq_50_60 (regular + Evo) and llmq_25_67 (the testnet
// platform type => Evo-only, the same code path as mainnet type 4, the type of
// the 2561514 incident). Driven THROUGH the engine (derive_at over a seeded
// work list + work-block hash + cbTx CL, members_for by quorum hash), and
// cross-checked index by index against the vendored port on the same input.
// ═══════════════════════════════════════════════════════════════════════════
namespace golden_nonrot {

std::vector<uint8_t> unhex(const std::string& s)
{
    std::vector<uint8_t> o;
    o.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        o.push_back(static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
    return o;
}
uint256 u256_disp(const std::string& disp)
{
    auto b = unhex(disp);
    std::reverse(b.begin(), b.end());
    return uint256(b);
}
template <size_t N>
std::array<uint8_t, N> arr(const std::vector<uint8_t>& v)
{
    std::array<uint8_t, N> a{};
    for (size_t i = 0; i < N && i < v.size(); ++i) a[i] = v[i];
    return a;
}

CSimplifiedMNList golden_sml()
{
    std::vector<CSimplifiedMNListEntry> es;
    for (const auto& g : dash_qmk::kSml) {
        CSimplifiedMNListEntry m;
        m.nVersion       = g.nVersion;
        m.proRegTxHash   = u256_disp(g.proReg);
        m.confirmedHash  = u256_disp(g.confirmed);
        m.netAddress     = arr<16>(unhex(g.ip));
        m.netPort        = g.port;
        m.pubKeyOperator = arr<48>(unhex(g.pubkeyOp));
        m.keyIDVoting    = uint160(unhex(g.votingKeyId));
        m.isValid        = g.isValid;
        m.nType          = g.nType;
        m.platformHTTPPort = g.platformHTTPPort;
        if (g.platformNodeId[0] != '\0')
            m.platformNodeID = uint160(unhex(g.platformNodeId));
        es.push_back(m);
    }
    return CSimplifiedMNList(std::move(es));
}

// The engine's work-list entry form, exactly as the feeder builds it from an
// authenticated historical SML (no collateral on an SML: a tie fails closed).
std::vector<rp::QuorumMnEntry> engine_list(const CSimplifiedMNList& sml)
{
    std::vector<rp::QuorumMnEntry> v;
    for (const auto& e : sml.mnList) {
        rp::QuorumMnEntry q;
        q.proTxHash      = e.proRegTxHash;
        q.confirmedHash  = e.confirmedHash;
        q.is_valid       = e.isValid;
        q.n_type         = e.nType;
        q.has_collateral = false;
        v.push_back(q);
    }
    return v;
}

std::vector<uint256> expected(const std::vector<dash_qmk::ExpMember>& want)
{
    std::vector<uint256> v;
    for (const auto& m : want) v.push_back(u256_disp(m.proReg));
    return v;
}

} // namespace golden_nonrot

TEST(DashPoseOracleNonRotated, EngineDerivationReproducesDashdMemberSets)
{
    using namespace golden_nonrot;
    const CSimplifiedMNList sml = golden_sml();
    const auto list = engine_list(sml);
    const uint256 work_hash  = u256_disp(dash_qmk::kWorkBlockHashDisp);
    const uint256 quorum     = u256_disp(dash_qmk::kQuorumHashDisp);
    const auto    cl         = arr<96>(unhex(dash_qmk::kWorkClSig));

    rp::QuorumReplayConfig qc;
    qc.enabled   = true;
    qc.network   = LlmqNetwork::Testnet;
    qc.v20_floor = 905'100u;                       // testnet V20 (main_dash)
    rp::QuorumReplayEngine q(qc);
    q.set_mn_list_at_fn([&](uint32_t h) -> std::optional<std::vector<rp::QuorumMnEntry>> {
        if (h == dash_qmk::kWorkHeight) return list;
        return std::nullopt;
    });
    q.seed_block_hash(dash_qmk::kWorkHeight, work_hash);
    q.seed_work_block_cl(dash_qmk::kWorkHeight, cl);
    q.seed_block_hash(dash_qmk::kBaseHeight, quorum);

    auto dr = q.derive_at(dash_qmk::kBaseHeight);
    ASSERT_TRUE(q.has_members_at(dash_qmk::kLlmqType, dash_qmk::kBaseHeight))
        << (dr.reasons.empty() ? std::string("no reason") : dr.reasons.back());
    ASSERT_TRUE(q.has_members_at(dash_qmk::kLlmqTypePlatform, dash_qmk::kBaseHeight))
        << (dr.reasons.empty() ? std::string("no reason") : dr.reasons.back());

    struct Case {
        uint8_t type;
        uint16_t size;
        bool evo_only;
        const std::vector<dash_qmk::ExpMember>* want;
    };
    const Case cases[] = {
        {dash_qmk::kLlmqType, dash_qmk::kQuorumSize, false, &dash_qmk::kExpectedMembers},
        {dash_qmk::kLlmqTypePlatform, dash_qmk::kQuorumSize25, true,
         &dash_qmk::kExpectedMembers25},
    };
    for (const auto& c : cases) {
        SCOPED_TRACE("llmqType=" + std::to_string(int(c.type)));
        const auto want = expected(*c.want);
        auto got = q.members_for(c.type, quorum);
        ASSERT_TRUE(got.has_value());
        ASSERT_EQ(got->size(), want.size());
        for (size_t i = 0; i < want.size(); ++i)
            EXPECT_EQ((*got)[i], want[i]) << "engine member #" << i
                << " differs from dashd `quorum info " << int(c.type) << "`";

        // The two ports agree index by index on the same input.
        const uint256 mod = dash::coin::vendor::compute_quorum_modifier(
            c.type, dash_qmk::kWorkHeight,
            std::optional<std::array<uint8_t, 96>>(cl), work_hash);
        auto vendor = dash::coin::vendor::compute_quorum_members(
            dash::coin::vendor::QuorumMemberParams{c.type, c.size, false, c.evo_only},
            mod, sml);
        ASSERT_TRUE(vendor.has_value());
        ASSERT_EQ(vendor->size(), got->size());
        for (size_t i = 0; i < got->size(); ++i)
            EXPECT_EQ((*vendor)[i].proTxHash, (*got)[i]) << "port drift at #" << i;
    }

    // The Evo-only filter is load-bearing: without it the platform set differs.
    auto unfiltered = rp::compute_nonrotated_members(
        dash::coin::kLlmq25_67, /*evo_only=*/false, list,
        dash::coin::vendor::compute_quorum_modifier(
            dash_qmk::kLlmqTypePlatform, dash_qmk::kWorkHeight,
            std::optional<std::array<uint8_t, 96>>(cl), work_hash));
    ASSERT_TRUE(unfiltered.has_value());
    EXPECT_NE(*unfiltered, expected(dash_qmk::kExpectedMembers25));
}
