// SPDX-License-Identifier: AGPL-3.0-or-later
/// E1 — daemonless type-6 quorum-commitment sourcing at DKG-window heights
/// (dkg_commitments.hpp). Compiled into the CI-allowlisted
/// test_dash_embedded_gbt executable.
///
/// Axes:
///   * mandatory-slot math (dashcore GetNumCommitmentsRequired parity:
///     windows, rotation fan-out, already-mined suppression, AddLLMQ order);
///   * fail-closed surfaces (header gap, below-V19-floor => PHASE-1 refusal);
///   * null-commitment + qc-tx byte KATs (dashcore CFinalCommitment(params,
///     quorumHash) / GetMineableCommitmentsTx shapes);
///   * FROM-WIRE window-height byte parity: the captured testnet mnlistdiff
///     (block 1518412) -> QuorumManager -> daemonless plan at the WINDOW
///     height 1518420 -> merkleRootQuorums == the root a real dashd
///     committed (all-null plan folds nothing, so the with-block root must
///     equal the PROVEN active-set root byte-for-byte);
///   * with-block root fold for REAL commitments (Phase-L path): non-rotated
///     oldest-eviction at capacity + rotated per-index replacement;
///   * MineableCommitmentCache structural admission + the BLS-verifier gate
///     (verified_for is nullopt until Phase L installs a verifier);
///   * build_embedded_workdata integration: qc txs first, zero-fee, hex body
///     filled, CbTx commits the override root.

#include <gtest/gtest.h>

#include <impl/dash/coin/dkg_commitments.hpp>
#include <impl/dash/coin/dkg_window.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/quorum_root.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/vendor/quorum_tail.hpp>
#include <impl/dash/coin/vendor/smldiff.hpp>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <vector>

using namespace dash::coin;
using dash::coin::vendor::CFinalCommitment;
using dash::coin::vendor::CFinalCommitmentTxPayload;

namespace {

uint256 h256(uint8_t fill)
{
    uint256 u;
    std::memset(u.data(), fill, 32);
    return u;
}

// hash_at_height stub: deterministic per-height pseudo hash.
std::optional<uint256> fake_hash_at(uint32_t h)
{
    uint256 u;
    std::memset(u.data(), 0xAB, 32);
    std::memcpy(u.data(), &h, 4);
    return u;
}

bool never_mined(uint8_t, const uint256&) { return false; }

} // namespace

// ── mandatory-slot math ────────────────────────────────────────────────────

TEST(DashDkgCommitments, MainnetInterval24WindowYieldsOneSlotPerType)
{
    // 1900800 % 24 == 0 and >= the mainnet V19 serve floor (1899072).
    const uint32_t h = 1'900'800u + 12;   // phase 12 in [10,18]
    auto slots = compute_required_qc_slots(
        LlmqNetwork::Mainnet, h, fake_hash_at, never_mined);
    ASSERT_TRUE(slots.has_value());
    // Interval-24 mainnet types in AddLLMQ order: LLMQ_50_60 (1), LLMQ_100_67
    // (4). 288/576-interval types are at phase 12, outside their windows.
    ASSERT_EQ(slots->size(), 2u);
    EXPECT_EQ((*slots)[0].params.type, 1);
    EXPECT_EQ((*slots)[1].params.type, 4);
    for (const auto& s : *slots) {
        EXPECT_EQ(s.quorum_index, 0);
        EXPECT_EQ(s.quorum_hash, *fake_hash_at(1'900'800u));
    }
}

TEST(DashDkgCommitments, RotatedWindowFansOutPerQuorumIndexInAddLlmqOrder)
{
    // 1900800 is 0 mod 24/288/576, so at phase 42: LLMQ_60_75's window start
    // ([42,50], 32 rotated slots), LLMQ_400_85's window ([20,48], 1 slot),
    // AND the last interval-24 window height (42 % 24 == 18) — the slot list
    // interleaves per AddLLMQ order: [50_60, 60_75 x32, 400_85, 100_67].
    const uint32_t h = 1'900'800u + 42;
    auto slots = compute_required_qc_slots(
        LlmqNetwork::Mainnet, h, fake_hash_at, never_mined);
    ASSERT_TRUE(slots.has_value());
    ASSERT_EQ(slots->size(), 1u + 32u + 1u + 1u);
    EXPECT_EQ((*slots)[0].params.type, 1);
    for (int i = 0; i < 32; ++i) {
        const auto& s = (*slots)[1 + static_cast<size_t>(i)];
        EXPECT_EQ(s.params.type, 5);
        EXPECT_EQ(s.quorum_index, i);
        // Rotated base blocks: cycleStart + quorumIndex — DISTINCT hashes.
        EXPECT_EQ(s.quorum_hash, *fake_hash_at(1'900'800u + static_cast<uint32_t>(i)));
    }
    EXPECT_EQ((*slots)[33].params.type, 3);
    EXPECT_EQ(slots->back().params.type, 4);
}

TEST(DashDkgCommitments, AlreadyMinedCommitmentSuppressesItsSlot)
{
    const uint32_t h = 1'900'800u + 12;
    auto mined_type1 = [](uint8_t t, const uint256&) { return t == 1; };
    auto slots = compute_required_qc_slots(
        LlmqNetwork::Mainnet, h, fake_hash_at, mined_type1);
    ASSERT_TRUE(slots.has_value());
    ASSERT_EQ(slots->size(), 1u);
    EXPECT_EQ((*slots)[0].params.type, 4);
}

TEST(DashDkgCommitments, NonWindowHeightYieldsEmptySet)
{
    const uint32_t h = 1'900'800u + 4;    // phase 4 — outside every window
    auto slots = compute_required_qc_slots(
        LlmqNetwork::Mainnet, h, fake_hash_at, never_mined);
    ASSERT_TRUE(slots.has_value());
    EXPECT_TRUE(slots->empty());
}

TEST(DashDkgCommitments, HeaderGapFailsClosed)
{
    const uint32_t h = 1'900'800u + 12;
    auto no_headers = [](uint32_t) -> std::optional<uint256> {
        return std::nullopt;
    };
    EXPECT_FALSE(compute_required_qc_slots(
        LlmqNetwork::Mainnet, h, no_headers, never_mined).has_value());
}

TEST(DashDkgCommitments, BelowServeFloorPreservesPhase1RefusalExactly)
{
    // Below the V19 floor: refuse (nullopt) INSIDE any window, serve-empty
    // outside — i.e. byte-identical routing to the dkg_window.hpp guard.
    for (uint32_t h = 100'000; h < 100'000 + 600; ++h) {
        auto slots = compute_required_qc_slots(
            LlmqNetwork::Mainnet, h, fake_hash_at, never_mined);
        if (is_dkg_commitment_window(h)) {
            EXPECT_FALSE(slots.has_value()) << "h=" << h;
        } else {
            ASSERT_TRUE(slots.has_value()) << "h=" << h;
            EXPECT_TRUE(slots->empty()) << "h=" << h;
        }
    }
}

TEST(DashDkgCommitments, EverySlotHeightIsInsideTheCoarseWindowUnion)
{
    // The served set is a REFINEMENT of the coarse dkg_window union: any
    // height with a non-empty mandatory set must be flagged by the old guard
    // (the reverse is not true — that over-refusal is what E1 removes).
    for (uint32_t h = 1'900'800u; h < 1'900'800u + 1152; ++h) {
        auto slots = compute_required_qc_slots(
            LlmqNetwork::Mainnet, h, fake_hash_at, never_mined);
        ASSERT_TRUE(slots.has_value());
        if (!slots->empty())
            EXPECT_TRUE(is_dkg_commitment_window(h)) << "h=" << h;
    }
}

// ── null commitment + qc tx byte KATs ──────────────────────────────────────

TEST(DashDkgCommitments, NullCommitmentByteShape)
{
    const uint256 qh = h256(0x42);
    auto c = build_null_commitment(kLlmq50_60, qh, 0);
    EXPECT_EQ(c.nVersion, CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION);
    EXPECT_EQ(c.llmqType, 1);
    EXPECT_EQ(c.CountSigners(), 0);
    EXPECT_EQ(c.CountValidMembers(), 0);
    EXPECT_EQ(c.signers.size(), 50u);
    EXPECT_EQ(c.validMembers.size(), 50u);
    // Wire: u16 ver + u8 type + 32B hash + 2 x (CompactSize(50) + 7B bitset)
    //       + 48B pk + 32B vvec + 96B qsig + 96B msig = 323 bytes.
    auto bytes = ::pack(c);
    EXPECT_EQ(bytes.get_span().size(), 323u);

    // Rotated (indexed) variant: +2B quorumIndex, 60-bit bitsets (8B each).
    auto cr = build_null_commitment(kLlmq60_75, qh, 7);
    EXPECT_EQ(cr.nVersion, CFinalCommitment::BASIC_BLS_INDEXED_QUORUM_VERSION);
    EXPECT_EQ(cr.quorumIndex, 7);
    auto rbytes = ::pack(cr);
    EXPECT_EQ(rbytes.get_span().size(), 2u + 1 + 32 + 2 + 2 * (1 + 8) + 48 + 32 + 96 + 96);
}

TEST(DashDkgCommitments, QcTxShapeAndPayloadRoundTrip)
{
    const uint32_t height = 1'900'812u;
    const uint256 qh = h256(0x42);
    auto c = build_null_commitment(kLlmq50_60, qh, 0);
    auto tx = build_qc_tx(height, c);
    EXPECT_EQ(tx.version, 3);
    EXPECT_EQ(tx.type, 6);
    EXPECT_TRUE(tx.vin.empty());
    EXPECT_TRUE(tx.vout.empty());
    EXPECT_EQ(tx.locktime, 0u);
    // Payload: u16 ver(1) + u32 height + commitment(323) = 329 bytes,
    // parseable by the vendored strict-tail parser and field-faithful.
    ASSERT_EQ(tx.extra_payload.size(), 329u);
    CFinalCommitmentTxPayload back;
    ASSERT_TRUE(vendor::parse_qfcommit_payload(tx.extra_payload, back));
    EXPECT_EQ(back.nVersion, 1);
    EXPECT_EQ(back.nHeight, height);
    EXPECT_EQ(back.commitment.quorumHash, qh);
    EXPECT_EQ(::pack(back.commitment).get_span().size(),
              ::pack(c).get_span().size());
    // Full tx wire: 4B version|type + 1B vin cnt + 1B vout cnt + 4B locktime
    //               + CompactSize(329)=3B + 329B payload = 342 bytes.
    auto wire = ::pack(tx);
    ASSERT_EQ(wire.get_span().size(), 342u);
    // version|type dword: 3 | (6 << 16) => LE bytes 03 00 06 00.
    auto sp = wire.get_span();
    const auto* b = reinterpret_cast<const unsigned char*>(sp.data());
    EXPECT_EQ(b[0], 0x03); EXPECT_EQ(b[1], 0x00);
    EXPECT_EQ(b[2], 0x06); EXPECT_EQ(b[3], 0x00);
}

// ── FROM-WIRE window-height byte parity ────────────────────────────────────

namespace {

std::vector<unsigned char> read_mnlistdiff_fixture()
{
    const std::string path =
        std::string(DASH_FIXTURE_DIR) + "/dash_testnet_mnlistdiff_1518412.bin";
    std::ifstream f(path, std::ios::binary);
    EXPECT_TRUE(f.good()) << "cannot open fixture: " << path;
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(f),
                                      std::istreambuf_iterator<char>());
}

// dashd's committed merkleRootQuorums for block 1518413 (same anchor as
// test_dash_mnlistdiff_root_parity.cpp).
const char* kExpQuorumRoot =
    "1901c17202846e585a92ee7b858f5716a5a3c33d0afae06f245ae07e7bff1dfb";

} // namespace

TEST(DashDkgCommitments, FromWireWindowHeightPlanMatchesDashdQuorumRoot)
{
    // Wire -> QuorumManager (the same path the live maintainer runs).
    auto bytes = read_mnlistdiff_fixture();
    ::PackStream in(bytes);
    vendor::CSimplifiedMNListDiff diff;
    in >> diff;
    ASSERT_EQ(in.cursor_size(), 0u);
    vendor::QuorumTail tail;
    ASSERT_TRUE(vendor::parse_quorum_tail(diff.quorum_tail, tail));
    QuorumManager qmgr;
    qmgr.apply(tail);
    ASSERT_GT(qmgr.active_count(), 0u);

    // 1518420 is a DKG mining-window height on testnet (phase 12 of the
    // 24-block cycle => LLMQ_50_60 / LLMQ_100_67 / LLMQ_25_67 windows; the
    // 288/576-cycle types are at phase 84, off-window). Cycle start 1518408.
    const uint32_t next_h = 1'518'420u;
    ASSERT_TRUE(is_dkg_commitment_window(next_h));  // PHASE-1 refused here

    auto height_of = [](const uint256&) -> std::optional<uint32_t> {
        ADD_FAILURE() << "eviction ordering must not be needed for an "
                         "all-null plan";
        return std::nullopt;
    };
    auto plan = build_daemonless_qc_plan(
        LlmqNetwork::Testnet, next_h, qmgr, fake_hash_at, height_of);
    ASSERT_TRUE(plan.has_value());

    // The current cycle's quorums cannot be in the (older) fixture set, so
    // all three interval-24 testnet types need a commitment — served as the
    // consensus-valid nulls dashd itself mines without a DKG result.
    ASSERT_EQ(plan->commitments.size(), 3u);
    EXPECT_EQ(plan->commitments[0].llmqType, 1);
    EXPECT_EQ(plan->commitments[1].llmqType, 4);
    EXPECT_EQ(plan->commitments[2].llmqType, 6);
    for (const auto& c : plan->commitments) {
        EXPECT_EQ(c.CountSigners(), 0);
        EXPECT_EQ(c.CountValidMembers(), 0);
        EXPECT_EQ(c.quorumHash, *fake_hash_at(1'518'408u));
    }

    // BYTE PARITY: null commitments fold nothing, so the with-block root the
    // CbTx commits at this WINDOW height must equal the root a real dashd
    // committed over the same wire-fed active set.
    EXPECT_EQ(plan->merkle_root_quorums.GetHex(), kExpQuorumRoot);
    EXPECT_EQ(plan->merkle_root_quorums, compute_merkle_root_quorums(qmgr));
}

// ── with-block fold: real commitments (Phase-L path) ───────────────────────

namespace {

CFinalCommitment real_commitment(const LlmqParamsView& p, const uint256& qh,
                                 int16_t qi, uint8_t seed)
{
    CFinalCommitment c;
    c.nVersion = p.use_rotation
        ? CFinalCommitment::BASIC_BLS_INDEXED_QUORUM_VERSION
        : CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
    c.llmqType    = p.type;
    c.quorumHash  = qh;
    c.quorumIndex = qi;
    c.signers.assign(p.size, true);
    c.validMembers.assign(p.size, true);
    c.quorumPublicKey.fill(seed);
    c.quorumVvecHash = h256(seed);
    c.quorumSig.fill(seed);
    c.membersSig.fill(seed);
    return c;
}

} // namespace

TEST(DashDkgCommitments, WithBlockFoldEvictsOldestNonRotatedAtCapacity)
{
    // LLMQ_400_60 (type 2): signingActiveQuorumCount = 4. Fill to capacity,
    // fold one real commitment: the LOWEST-base-height leaf must drop.
    QuorumManager qmgr;
    vendor::QuorumTail tail;
    std::vector<uint256> hashes;
    for (uint8_t i = 0; i < 4; ++i) {
        const uint256 qh = h256(static_cast<uint8_t>(0x10 + i));
        hashes.push_back(qh);
        tail.newQuorums.push_back(real_commitment(kLlmq400_60, qh, 0,
                                                  static_cast<uint8_t>(i + 1)));
    }
    qmgr.apply(tail);
    ASSERT_EQ(qmgr.active_count(), 4u);
    auto height_of = [&](const uint256& qh) -> std::optional<uint32_t> {
        for (size_t i = 0; i < hashes.size(); ++i)
            if (hashes[i] == qh) return 1000u + 288u * static_cast<uint32_t>(i);
        return std::nullopt;
    };
    auto newc = real_commitment(kLlmq400_60, h256(0x99), 0, 0x77);
    auto root = compute_merkle_root_quorums_with_block(
        LlmqNetwork::Mainnet, qmgr, {newc}, height_of);
    ASSERT_TRUE(root.has_value());

    // Expected: leaves of entries 1..3 (entry 0 = lowest height, evicted)
    // + the new commitment, sorted, merkled — via the PROVEN primitives.
    std::vector<uint256> leaves;
    for (size_t i = 1; i < 4; ++i)
        leaves.push_back(hash_commitment(*qmgr.find(2, hashes[i])));
    leaves.push_back(hash_commitment(newc));
    std::sort(leaves.begin(), leaves.end(),
        [](const uint256& a, const uint256& b) {
            return std::memcmp(a.data(), b.data(), 32) < 0;
        });
    EXPECT_EQ(*root, compute_merkle_root_local(leaves));

    // And an unknown base height while eviction is needed => fail closed.
    auto unknown = [](const uint256&) -> std::optional<uint32_t> {
        return std::nullopt;
    };
    EXPECT_FALSE(compute_merkle_root_quorums_with_block(
        LlmqNetwork::Mainnet, qmgr, {newc}, unknown).has_value());
}

TEST(DashDkgCommitments, WithBlockFoldReplacesRotatedSameIndexAndSkipsNulls)
{
    QuorumManager qmgr;
    vendor::QuorumTail tail;
    tail.newQuorums.push_back(real_commitment(kLlmq60_75, h256(0x20), 0, 0x01));
    tail.newQuorums.push_back(real_commitment(kLlmq60_75, h256(0x21), 1, 0x02));
    qmgr.apply(tail);
    ASSERT_EQ(qmgr.active_count(), 2u);
    auto no_heights = [](const uint256&) -> std::optional<uint32_t> {
        return std::nullopt;   // must never be needed for rotated replacement
    };

    // Replace index 1; also carry a NULL commitment — folded root must skip it.
    auto repl = real_commitment(kLlmq60_75, h256(0x31), 1, 0x03);
    auto nullc = build_null_commitment(kLlmq50_60, h256(0x40), 0);
    auto root = compute_merkle_root_quorums_with_block(
        LlmqNetwork::Mainnet, qmgr, {repl, nullc}, no_heights);
    ASSERT_TRUE(root.has_value());

    std::vector<uint256> leaves{
        hash_commitment(*qmgr.find(5, h256(0x20))),
        hash_commitment(repl)};
    std::sort(leaves.begin(), leaves.end(),
        [](const uint256& a, const uint256& b) {
            return std::memcmp(a.data(), b.data(), 32) < 0;
        });
    EXPECT_EQ(*root, compute_merkle_root_local(leaves));

    // All-null fold == the plain PROVEN root (the E1 steady-state identity).
    auto null_only = compute_merkle_root_quorums_with_block(
        LlmqNetwork::Mainnet, qmgr, {nullc}, no_heights);
    ASSERT_TRUE(null_only.has_value());
    EXPECT_EQ(*null_only, compute_merkle_root_quorums(qmgr));
}

// ── MineableCommitmentCache: the Phase-L line ──────────────────────────────

TEST(DashDkgCommitments, MineableCacheStructuralAdmissionAndBlsGate)
{
    MineableCommitmentCache cache;
    const uint256 qh = h256(0x55);
    auto good = real_commitment(kLlmq50_60, qh, 0, 0x11);

    // Structural rejects: wrong version / short bitsets / below threshold /
    // null crypto fields.
    {
        auto bad = good; bad.nVersion = CFinalCommitment::LEGACY_BLS_NON_INDEXED_QUORUM_VERSION;
        EXPECT_FALSE(cache.ingest(LlmqNetwork::Mainnet, bad));
    }
    {
        auto bad = good; bad.signers.assign(10, true);
        EXPECT_FALSE(cache.ingest(LlmqNetwork::Mainnet, bad));
    }
    {
        auto bad = good;
        bad.signers.assign(50, false);
        for (int i = 0; i < 29; ++i) bad.signers[static_cast<size_t>(i)] = true;  // threshold is 30
        EXPECT_FALSE(cache.ingest(LlmqNetwork::Mainnet, bad));
    }
    {
        auto bad = good; bad.quorumSig.fill(0);
        EXPECT_FALSE(cache.ingest(LlmqNetwork::Mainnet, bad));
    }
    EXPECT_EQ(cache.size(), 0u);

    ASSERT_TRUE(cache.ingest(LlmqNetwork::Mainnet, good));
    EXPECT_EQ(cache.size(), 1u);

    // THE Phase-L line: without a BLS verifier the cache NEVER serves — the
    // provider must mine the consensus-valid null commitment instead.
    EXPECT_FALSE(cache.has_bls_verifier());
    EXPECT_FALSE(cache.verified_for(1, qh).has_value());
    auto plan_commitments = daemonless_qc_commitments(
        LlmqNetwork::Mainnet, 1'900'812u, fake_hash_at, never_mined, &cache);
    ASSERT_TRUE(plan_commitments.has_value());
    for (const auto& c : *plan_commitments)
        EXPECT_EQ(c.CountSigners(), 0) << "unverified commitment served";

    // With a (stub) verifier installed the cached commitment is served.
    cache.set_bls_verify_fn([](const CFinalCommitment&) { return true; });
    auto served = cache.verified_for(1, qh);
    ASSERT_TRUE(served.has_value());
    EXPECT_EQ(::pack(*served).get_span().size(), ::pack(good).get_span().size());
    // And a failing verifier withholds it again.
    cache.set_bls_verify_fn([](const CFinalCommitment&) { return false; });
    EXPECT_FALSE(cache.verified_for(1, qh).has_value());
}

// ── template integration ───────────────────────────────────────────────────

#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/mempool.hpp>

TEST(DashDkgCommitments, EmbeddedWorkdataCarriesQcTxsFirstAndOverrideRoot)
{
    MnStateMachine mnstates;
    Mempool mempool;
    vendor::CSimplifiedMNList sml;   // empty — root ZERO, irrelevant here
    QuorumManager qmgr;

    const uint32_t prev_h = 1'900'811u;
    std::vector<CFinalCommitment> qcs{
        build_null_commitment(kLlmq50_60, h256(0x42), 0),
        build_null_commitment(kLlmq100_67, h256(0x42), 0)};
    const uint256 override_root = h256(0x66);

    auto w = build_embedded_workdata(
        prev_h, h256(0x01), mnstates, mempool,
        /*bits*/ 0x1a012345u, /*mtp*/ 1000u, /*addr_ver*/ 76, /*p2sh*/ 16,
        /*curtime*/ 1234u, /*version*/ 0x20000000u,
        /*underfill*/ nullptr, &sml, &qmgr,
        /*best_cl_height*/ 0, k_zero_cl_sig, /*credit_pool*/ 0,
        &qcs, &override_root);

    // qc txs first, zero-fee, body hex filled for submit-time assembly.
    ASSERT_EQ(w.m_txs.size(), 2u);
    ASSERT_EQ(w.m_tx_hashes.size(), 2u);
    ASSERT_EQ(w.m_tx_fees.size(), 2u);
    ASSERT_EQ(w.m_tx_data_hex.size(), 2u);
    for (size_t i = 0; i < 2; ++i) {
        EXPECT_EQ(w.m_txs[i].type, 6);
        EXPECT_EQ(w.m_tx_fees[i], 0u);
        MutableTransaction expect = build_qc_tx(prev_h + 1, qcs[i]);
        EXPECT_EQ(w.m_txs[i].extra_payload, expect.extra_payload);
        EXPECT_EQ(w.m_tx_hashes[i], dash_txid(expect));
        EXPECT_FALSE(w.m_tx_data_hex[i].empty());
    }

    // The CbTx commits the override (with-block) quorum root.
    vendor::CCbTx cb;
    ASSERT_TRUE(vendor::parse_cbtx(w.m_coinbase_payload, cb));
    EXPECT_EQ(cb.merkleRootQuorums, override_root);

    // Without the qc seams the very same call is byte-identical to pre-E1:
    // no txs, plain (empty-set => ZERO) root.
    auto w0 = build_embedded_workdata(
        prev_h, h256(0x01), mnstates, mempool,
        0x1a012345u, 1000u, 76, 16, 1234u, 0x20000000u,
        nullptr, &sml, &qmgr, 0, k_zero_cl_sig, 0);
    EXPECT_TRUE(w0.m_txs.empty());
    vendor::CCbTx cb0;
    ASSERT_TRUE(vendor::parse_cbtx(w0.m_coinbase_payload, cb0));
    EXPECT_EQ(cb0.merkleRootQuorums, uint256::ZERO);
}
