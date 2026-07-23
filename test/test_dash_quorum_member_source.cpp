// SPDX-License-Identifier: AGPL-3.0-or-later
//
// E1 Phase-L KATs: QuorumMemberSource — the SOURCING PLUMBING that feeds the
// (separately KAT'd, #812-proven) member-selection + BLS verify. Covers the
// #814 re-review findings:
//
//   R1 — shared quorum bases: multiple (type, quorumHash) requests sharing one
//        WORK block ride a SINGLE outstanding getmnlistd (dedup BY HASH, not
//        by (type,hash)) — no duplicate request, so no second reply to leak
//        past the demux into the tip-SML maintainer. Strict consume: only a
//        full snapshot (base=ZERO) at an awaited hash matches.
//   R2 — the SML is sourced at the WORK block (base - 8), never the base
//        block (v23.1.7 GetAllQuorumMembers), proven both with the REAL
//        testnet snapshot (end-to-end vs dashd's member set) and with a
//        synthetic churn-in-(base-8, base] vector where the base-block list
//        would yield a DIFFERENT member set.
//   R3 — DIP-4 authentication: a tampered snapshot (wrong member keys ->
//        SML root != cbTx.merkleRootMNList; wrong merkle proof; wrong cbTx
//        height) is REJECTED — consumed but never served (fail closed).
//   R4 — the platform type sources with the Evo-only filter (real 25_67
//        vector, same base as the 50_60 quorum — also the R1 shared-base
//        end-to-end proof).
//   R5 — a null-CL work-block cbTx finalizes IMMEDIATELY with the upstream
//        fallback modifier: no walk-back, no extra requests.
//   nits — base % dkgInterval != 0 refused; rotated refused; pending reap cap.

#include <gtest/gtest.h>

#include <impl/dash/coin/quorum_member_source.hpp>
#include <impl/dash/coin/embedded_gbt.hpp>          // encode_cbtx
#include <impl/dash/coin/vendor/quorum_members.hpp>
#include <impl/dash/coin/vendor/smldiff.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>          // dash_txid
#include <impl/dash/coin/block.hpp>
#include <core/uint256.hpp>
#include <core/pack.hpp>

#include "data/dash_quorum_members_kat.hpp"

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

using dash::coin::QuorumMemberSource;
using dash::coin::LlmqNetwork;
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

uint256 u256_disp(const std::string& disp_hex)
{
    auto b = unhex(disp_hex);
    std::reverse(b.begin(), b.end());
    return uint256(b);
}

uint160 u160_raw(const std::string& raw_hex)
{
    auto b = unhex(raw_hex);
    return uint160(b);
}

uint256 raw256(uint8_t seed)
{
    uint256 h;
    for (int i = 0; i < 32; ++i) h.data()[i] = static_cast<uint8_t>(seed + i);
    return h;
}

// ── the REAL captured work-block snapshot, reassembled as a wire diff ───────

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

CSimplifiedMNListDiff real_snapshot_diff()
{
    CSimplifiedMNListDiff d;
    d.baseBlockHash = uint256::ZERO;
    d.blockHash     = u256_disp(dash_qmk::kWorkBlockHashDisp);
    {
        auto raw = unhex(dash_qmk::kWorkCbTxMerkleTreeHex);
        PackStream s(raw);
        s >> d.cbTxMerkleTree;
    }
    {
        auto raw = unhex(dash_qmk::kWorkCbTxHex);
        PackStream s(raw);
        s >> d.cbTx;
    }
    for (const auto& e : dash_qmk::kSml) d.mnList.push_back(kat_entry(e));
    return d;
}

uint256 real_work_header_root()
{
    dash::coin::BlockHeaderType header;
    auto raw = unhex(dash_qmk::kWorkHeaderHex);
    PackStream s(raw);
    s >> header;
    return header.m_merkle_root;
}

// ── harness: a source wired to recording callbacks ──────────────────────────

struct Harness {
    // height -> hash and back (the "header chain")
    std::map<uint32_t, uint256> by_height;
    std::map<uint256, uint32_t> by_hash;
    std::map<uint256, uint256>  merkle_root;   // block hash -> header merkle root
    std::vector<std::pair<uint256, uint256>> sends;   // (base, target)

    std::unique_ptr<QuorumMemberSource> src;

    explicit Harness(LlmqNetwork net = LlmqNetwork::Testnet)
    {
        src = std::make_unique<QuorumMemberSource>(
            net,
            [this](uint32_t h) -> std::optional<uint256> {
                auto it = by_height.find(h);
                if (it == by_height.end()) return std::nullopt;
                return it->second;
            },
            [this](const uint256& bh) -> std::optional<uint32_t> {
                auto it = by_hash.find(bh);
                if (it == by_hash.end()) return std::nullopt;
                return it->second;
            },
            [this](const uint256& bh) -> std::optional<uint256> {
                auto it = merkle_root.find(bh);
                if (it == merkle_root.end()) return std::nullopt;
                return it->second;
            },
            [this](const uint256& base, const uint256& tgt) {
                sends.emplace_back(base, tgt);
            });
    }

    void add_block(uint32_t h, const uint256& hash)
    {
        by_height[h] = hash;
        by_hash[hash] = h;
    }
};

// The real vectors' heights/hashes.
struct RealChain {
    uint256 base_hash = u256_disp(dash_qmk::kQuorumHashDisp);
    uint256 work_hash = u256_disp(dash_qmk::kWorkBlockHashDisp);
    void wire(Harness& h) const
    {
        h.add_block(dash_qmk::kBaseHeight, base_hash);
        h.add_block(dash_qmk::kWorkHeight, work_hash);
        h.merkle_root[work_hash] = real_work_header_root();
    }
};

// ── synthetic authenticated snapshots (for the churn / tamper / null-CL KATs)

struct SynthSnapshot {
    CSimplifiedMNListDiff diff;
    uint256 header_root;   // what the "verified header" reports
};

CSimplifiedMNListEntry synth_entry(uint8_t seed, bool evo = false)
{
    CSimplifiedMNListEntry e;
    e.nVersion      = 2;
    e.proRegTxHash  = raw256(seed);
    e.confirmedHash = raw256(static_cast<uint8_t>(seed + 0x40));
    e.pubKeyOperator[0] = 0x80;   // plausible compressed-point prefix
    e.pubKeyOperator[1] = seed;
    e.isValid = true;
    e.nType = evo ? CSimplifiedMNListEntry::TYPE_EVO
                  : CSimplifiedMNListEntry::TYPE_REGULAR;
    return e;
}

// Build a snapshot at block `block_hash` (height `h`) over `entries` whose
// cbTx commits to the entries' SML root; the single-tx merkle proof makes the
// header root == the cbTx txid.
SynthSnapshot synth_snapshot(const uint256& block_hash, uint32_t h,
                             std::vector<CSimplifiedMNListEntry> entries,
                             bool with_clsig = true)
{
    SynthSnapshot out;
    out.diff.baseBlockHash = uint256::ZERO;
    out.diff.blockHash     = block_hash;
    out.diff.mnList        = std::move(entries);

    CSimplifiedMNList sml;
    apply_diff(sml, out.diff);

    CCbTx cb;
    cb.nVersion = CCbTx::VERSION_CLSIG_AND_BALANCE;
    cb.nHeight  = static_cast<int32_t>(h);
    cb.merkleRootMNList = sml.CalcMerkleRoot();
    if (with_clsig) cb.bestCLSignature.fill(0x5A);  // non-null CL

    out.diff.cbTx.version = 3;
    out.diff.cbTx.type    = 5;
    out.diff.cbTx.extra_payload = dash::coin::encode_cbtx(cb);

    const uint256 txid = dash::coin::dash_txid(out.diff.cbTx);
    out.diff.cbTxMerkleTree.nTransactions = 1;
    out.diff.cbTxMerkleTree.vHash = {txid};
    out.diff.cbTxMerkleTree.vBitsBytes = {0x01};
    out.header_root = txid;   // single-tx block: root == coinbase txid
    return out;
}

} // namespace

// ── R2 + R3 (positive) + R4 + R1 end-to-end with the REAL testnet vectors ───
//
// TWO types sharing ONE cycle base (llmq_50_60 + llmq_25_67 platform) issue
// exactly ONE getmnlistd(ZERO, WORK-block) — never the base block — and the
// single authenticated reply readies BOTH member sets, byte-equal to dashd's.
TEST(DashQuorumMemberSource, RealSnapshotEndToEndSharedBaseSingleRequest)
{
    Harness h;
    RealChain chain;
    chain.wire(h);

    h.src->request(dash_qmk::kLlmqType, chain.base_hash);
    h.src->request(dash_qmk::kLlmqTypePlatform, chain.base_hash);

    // R1: ONE send despite two (type, hash) keys; R2: target is the WORK block.
    ASSERT_EQ(h.sends.size(), 1u)
        << "shared-base types must ride ONE outstanding getmnlistd (R1)";
    EXPECT_TRUE(h.sends[0].first.IsNull());
    EXPECT_EQ(h.sends[0].second, chain.work_hash)
        << "must fetch the WORK block (base-8), not the base block (R2)";
    EXPECT_TRUE(h.src->awaiting(chain.work_hash));
    EXPECT_EQ(h.src->pending_count(), 2u);

    // Single authenticated reply readies BOTH types.
    ASSERT_TRUE(h.src->on_mnlistdiff(real_snapshot_diff()));
    EXPECT_EQ(h.src->pending_count(), 0u);
    EXPECT_FALSE(h.src->awaiting(chain.work_hash));

    auto m1 = h.src->lookup(dash_qmk::kLlmqType, chain.base_hash);
    ASSERT_TRUE(m1.has_value()) << "llmq_50_60 not ready off the real snapshot";
    ASSERT_EQ(m1->size(), dash_qmk::kExpectedMembers.size());
    for (size_t i = 0; i < m1->size(); ++i) {
        EXPECT_EQ((*m1)[i].pubKeyOperator,
                  arr<48>(unhex(dash_qmk::kExpectedMembers[i].pubkeyOp)))
            << "member order/key drift vs dashd at index " << i;
    }

    // R4: the platform type is Evo-only-selected and matches dashd exactly.
    auto m6 = h.src->lookup(dash_qmk::kLlmqTypePlatform, chain.base_hash);
    ASSERT_TRUE(m6.has_value()) << "platform type not ready (R4)";
    ASSERT_EQ(m6->size(), dash_qmk::kExpectedMembers25.size());
    for (size_t i = 0; i < m6->size(); ++i) {
        EXPECT_EQ((*m6)[i].pubKeyOperator,
                  arr<48>(unhex(dash_qmk::kExpectedMembers25[i].pubkeyOp)))
            << "Evo-only member drift vs dashd at index " << i;
    }

    // A DUPLICATE reply no longer matches any await -> NOT consumed (returns
    // false; the tip maintainer's own R1 stale-snapshot guard is the second
    // fence, KAT'd in test_dash_coin_state_maintainer.cpp).
    EXPECT_FALSE(h.src->on_mnlistdiff(real_snapshot_diff()));
}

// ── R1 strict consume: non-ZERO-base / unknown-hash replies are not ours ────
TEST(DashQuorumMemberSource, StrictConsumeOnlyFullSnapshotsAtAwaitedHash)
{
    Harness h;
    RealChain chain;
    chain.wire(h);
    h.src->request(dash_qmk::kLlmqType, chain.base_hash);
    ASSERT_EQ(h.sends.size(), 1u);

    // An INCREMENTAL diff (base != ZERO) at the awaited hash: NOT a full
    // snapshot -> must not match (it would be mis-applied as one).
    {
        auto d = real_snapshot_diff();
        d.baseBlockHash = raw256(0x77);
        EXPECT_FALSE(h.src->on_mnlistdiff(d));
        EXPECT_TRUE(h.src->awaiting(chain.work_hash)) << "await must survive";
    }
    // A full snapshot at an UNRELATED hash: not ours.
    {
        auto d = real_snapshot_diff();
        d.blockHash = raw256(0x99);
        EXPECT_FALSE(h.src->on_mnlistdiff(d));
    }
    // The genuine reply still lands afterwards.
    EXPECT_TRUE(h.src->on_mnlistdiff(real_snapshot_diff()));
    EXPECT_TRUE(h.src->lookup(dash_qmk::kLlmqType, chain.base_hash).has_value());
}

// ── R3: tampered snapshots are consumed but NEVER served (fail closed) ──────
TEST(DashQuorumMemberSource, TamperedSnapshotRejectedNoServe)
{
    RealChain chain;

    // (a) wrong member key -> SML root != cbTx.merkleRootMNList.
    {
        Harness h;
        chain.wire(h);
        h.src->request(dash_qmk::kLlmqType, chain.base_hash);
        auto d = real_snapshot_diff();
        d.mnList.at(0).pubKeyOperator[9] ^= 0x01;   // attacker key
        EXPECT_TRUE(h.src->on_mnlistdiff(d))
            << "tampered reply must still be consumed (demux) — never leak to tip";
        EXPECT_FALSE(h.src->lookup(dash_qmk::kLlmqType, chain.base_hash).has_value())
            << "TAMPERED SNAPSHOT SERVED — the R3 block-losing path";
        EXPECT_EQ(h.src->pending_count(), 0u) << "failed pendings must clear";
    }
    // (b) merkle proof does not bind to the verified header.
    {
        Harness h;
        chain.wire(h);
        h.merkle_root[chain.work_hash] = raw256(0x13);   // header says otherwise
        h.src->request(dash_qmk::kLlmqType, chain.base_hash);
        EXPECT_TRUE(h.src->on_mnlistdiff(real_snapshot_diff()));
        EXPECT_FALSE(h.src->lookup(dash_qmk::kLlmqType, chain.base_hash).has_value());
    }
    // (c) header not held at all -> cannot authenticate -> fail closed.
    {
        Harness h;
        chain.wire(h);
        h.merkle_root.erase(chain.work_hash);
        h.src->request(dash_qmk::kLlmqType, chain.base_hash);
        EXPECT_TRUE(h.src->on_mnlistdiff(real_snapshot_diff()));
        EXPECT_FALSE(h.src->lookup(dash_qmk::kLlmqType, chain.base_hash).has_value());
    }
    // (d) cbTx height != the requested work height (a genuine but WRONG
    // block's snapshot must not satisfy the await).
    {
        Harness h;
        chain.wire(h);
        h.src->request(dash_qmk::kLlmqType, chain.base_hash);
        auto d = real_snapshot_diff();
        // Re-point the await'd hash at a snapshot whose cbTx says another
        // height: rebuild a synthetic snapshot AT the awaited hash but with a
        // shifted height.
        std::vector<CSimplifiedMNListEntry> entries;
        for (const auto& e : dash_qmk::kSml) entries.push_back(kat_entry(e));
        auto ss = synth_snapshot(chain.work_hash, dash_qmk::kWorkHeight - 1,
                                 std::move(entries));
        h.merkle_root[chain.work_hash] = ss.header_root;  // proof itself is fine
        EXPECT_TRUE(h.src->on_mnlistdiff(ss.diff));
        EXPECT_FALSE(h.src->lookup(dash_qmk::kLlmqType, chain.base_hash).has_value())
            << "height-mismatched snapshot must fail closed";
    }
}

// ── R2: churn inside (base-8, base] — the WORK-block list decides ───────────
TEST(DashQuorumMemberSource, ChurnInWindowUsesWorkBlockList)
{
    // Synthetic chain: base at 1519920-like alignment (dkgInterval 24).
    const uint32_t base_h = 1'519'920;   // % 24 == 0
    const uint32_t work_h = base_h - 8;
    const uint256 base_hash = raw256(0xB1);
    const uint256 work_hash = raw256(0xC2);

    // WORK-block list: 60 regular MNs. "Base-block" list (churn in the
    // window): entry 0 rotated its operator key. Selection input keys differ,
    // so the computed member sets differ — the KAT the review said the
    // single-height vector could not provide.
    std::vector<CSimplifiedMNListEntry> work_list, base_list;
    for (uint8_t i = 0; i < 60; ++i) {
        auto e = synth_entry(i);
        work_list.push_back(e);
        if (i == 0) e.pubKeyOperator[2] ^= 0xFF;   // churned key at the base
        base_list.push_back(e);
    }

    Harness h;
    h.add_block(base_h, base_hash);
    h.add_block(work_h, work_hash);
    auto ss = synth_snapshot(work_hash, work_h, work_list);
    h.merkle_root[work_hash] = ss.header_root;

    h.src->request(/*llmq_50_60*/ 1, base_hash);
    ASSERT_EQ(h.sends.size(), 1u);
    EXPECT_EQ(h.sends[0].second, work_hash)
        << "requested the base block — R2 regression";

    ASSERT_TRUE(h.src->on_mnlistdiff(ss.diff));
    auto got = h.src->lookup(1, base_hash);
    ASSERT_TRUE(got.has_value());

    // Expected = compute over the WORK list with the snapshot's CL modifier.
    std::array<uint8_t, 96> cl{};
    cl.fill(0x5A);
    const uint256 modifier = compute_quorum_modifier(
        1, work_h, std::optional<std::array<uint8_t, 96>>(cl), work_hash);
    auto want_work = compute_quorum_members(
        QuorumMemberParams{1, 50, false, false}, modifier,
        CSimplifiedMNList{std::vector<CSimplifiedMNListEntry>(work_list)});
    auto want_base = compute_quorum_members(
        QuorumMemberParams{1, 50, false, false}, modifier,
        CSimplifiedMNList{std::vector<CSimplifiedMNListEntry>(base_list)});
    ASSERT_TRUE(want_work.has_value());
    ASSERT_TRUE(want_base.has_value());

    bool matches_work = true, matches_base = true;
    for (size_t i = 0; i < got->size(); ++i) {
        if ((*got)[i].pubKeyOperator != (*want_work)[i].pubKeyOperator)
            matches_work = false;
        if ((*got)[i].pubKeyOperator != (*want_base)[i].pubKeyOperator)
            matches_base = false;
    }
    EXPECT_TRUE(matches_work) << "member set != work-block list computation";
    EXPECT_FALSE(matches_base)
        << "churn vector inert — base list selects identically (fix the vector)";
}

// ── R5: null-CL work block -> fallback modifier, immediately, no re-request ──
TEST(DashQuorumMemberSource, NullClFallbackModifierNoWalkback)
{
    const uint32_t base_h = 1'519'920;
    const uint32_t work_h = base_h - 8;
    const uint256 base_hash = raw256(0xB1);
    const uint256 work_hash = raw256(0xC2);

    std::vector<CSimplifiedMNListEntry> list;
    for (uint8_t i = 0; i < 60; ++i) list.push_back(synth_entry(i));

    Harness h;
    h.add_block(base_h, base_hash);
    h.add_block(work_h, work_hash);
    auto ss = synth_snapshot(work_hash, work_h, list, /*with_clsig=*/false);
    h.merkle_root[work_hash] = ss.header_root;

    h.src->request(1, base_hash);
    ASSERT_EQ(h.sends.size(), 1u);
    ASSERT_TRUE(h.src->on_mnlistdiff(ss.diff));

    // v23.1.7 GetNonNullCoinbaseChainlock does NOT walk back: the null-CL
    // work block finalizes with SerializeHash((type, workBlockHash)) — and no
    // further getmnlistd is issued.
    EXPECT_EQ(h.sends.size(), 1u) << "walk-back re-request observed (R5)";
    auto got = h.src->lookup(1, base_hash);
    ASSERT_TRUE(got.has_value())
        << "null-CL work block failed closed — upstream serves via fallback";

    const uint256 fb_modifier = compute_quorum_modifier(
        1, work_h, std::nullopt, work_hash);
    auto want = compute_quorum_members(
        QuorumMemberParams{1, 50, false, false}, fb_modifier,
        CSimplifiedMNList{std::vector<CSimplifiedMNListEntry>(list)});
    ASSERT_TRUE(want.has_value());
    for (size_t i = 0; i < got->size(); ++i) {
        EXPECT_EQ((*got)[i].pubKeyOperator, (*want)[i].pubKeyOperator)
            << "fallback-modifier member mismatch at index " << i;
    }
}

// ── request guards + reap ───────────────────────────────────────────────────
TEST(DashQuorumMemberSource, RequestGuardsAndPendingReap)
{
    Harness h;

    // base not on a dkgInterval boundary -> refused (upstream ASSERT posture +
    // request-amplification bound).
    const uint256 off_base = raw256(0xD0);
    h.add_block(1'519'921, off_base);       // % 24 != 0
    h.add_block(1'519'913, raw256(0xD1));
    h.src->request(1, off_base);
    EXPECT_TRUE(h.sends.empty());
    EXPECT_EQ(h.src->pending_count(), 0u);

    // rotated type -> refused (qrinfo follow-up).
    const uint256 rot_base = raw256(0xE0);
    h.add_block(1'520'064, rot_base);       // 1520064 % 288 == 0
    h.add_block(1'520'056, raw256(0xE1));
    h.src->request(/*llmq_60_75*/ 5, rot_base);
    EXPECT_TRUE(h.sends.empty());

    // pending reap: > kPendingCap outstanding requests evict the oldest
    // rather than growing without bound (dead-peer hygiene).
    uint32_t base = 1'600'800;              // % 24 == 0
    for (size_t i = 0; i < QuorumMemberSource::kPendingCap + 8; ++i) {
        const uint256 bh = raw256(static_cast<uint8_t>(i));
        uint256 bh2 = bh;
        bh2.data()[31] = 0xAB;              // distinct namespace vs work hashes
        const uint256 wh = raw256(static_cast<uint8_t>(i));
        uint256 wh2 = wh;
        wh2.data()[31] = 0xCD;
        h.add_block(base, bh2);
        h.add_block(base - 8, wh2);
        h.src->request(1, bh2);
        base += 24;
    }
    EXPECT_LE(h.src->pending_count(), QuorumMemberSource::kPendingCap);
}
