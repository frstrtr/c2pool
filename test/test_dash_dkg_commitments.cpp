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
#include <impl/dash/coin/llmq_type_reconciler.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/quorum_root.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/vendor/quorum_tail.hpp>
#include <impl/dash/coin/vendor/smldiff.hpp>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <span>
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
    // The ONLY interval-24 type enabled on mainnet is LLMQ_100_67 (4).
    // LLMQ_50_60 (1) is in mainnet chainparams but dashd's runtime
    // IsQuorumTypeEnabled disables it at every height >= DIP0024QuorumsHeight
    // (1738698) — far below this serve floor — so it is NOT required and
    // must NOT appear here. 288/576-interval types are at phase 12, outside
    // their windows.
    ASSERT_EQ(slots->size(), 1u);
    EXPECT_EQ((*slots)[0].params.type, 4);
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
    // interleaves per enabled-set order: [60_75 x32, 400_85, 100_67].
    // LLMQ_50_60 is runtime-disabled on mainnet and contributes nothing.
    const uint32_t h = 1'900'800u + 42;
    auto slots = compute_required_qc_slots(
        LlmqNetwork::Mainnet, h, fake_hash_at, never_mined);
    ASSERT_TRUE(slots.has_value());
    ASSERT_EQ(slots->size(), 32u + 1u + 1u);
    for (int i = 0; i < 32; ++i) {
        const auto& s = (*slots)[static_cast<size_t>(i)];
        EXPECT_EQ(s.params.type, 5);
        EXPECT_EQ(s.quorum_index, i);
        // Rotated base blocks: cycleStart + quorumIndex — DISTINCT hashes.
        EXPECT_EQ(s.quorum_hash, *fake_hash_at(1'900'800u + static_cast<uint32_t>(i)));
    }
    EXPECT_EQ((*slots)[32].params.type, 3);
    EXPECT_EQ(slots->back().params.type, 4);
}

TEST(DashDkgCommitments, AlreadyMinedCommitmentSuppressesItsSlot)
{
    const uint32_t h = 1'900'800u + 12;
    // Mainnet's only interval-24 type is 4; mining it empties the set.
    auto mined_type4 = [](uint8_t t, const uint256&) { return t == 4; };
    auto slots = compute_required_qc_slots(
        LlmqNetwork::Mainnet, h, fake_hash_at, mined_type4);
    ASSERT_TRUE(slots.has_value());
    EXPECT_TRUE(slots->empty());
    // Testnet at the same phase keeps types 1 and 6 outstanding — the
    // suppression is per (type, quorumHash), not blanket.
    auto tslots = compute_required_qc_slots(
        LlmqNetwork::Testnet, h, fake_hash_at, mined_type4);
    ASSERT_TRUE(tslots.has_value());
    ASSERT_EQ(tslots->size(), 2u);
    EXPECT_EQ((*tslots)[0].params.type, 1);
    EXPECT_EQ((*tslots)[1].params.type, 6);
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

    // COMPLETENESS GATE (block-1520106 fix): without positive failed-DKG
    // evidence for the three mandatory slots, null is not provably canonical
    // and the WHOLE height must fail closed — never served with unattested
    // nulls (the old per-slot behaviour is exactly what diverged the root).
    EXPECT_FALSE(build_daemonless_qc_plan(
        LlmqNetwork::Testnet, next_h, qmgr, fake_hash_at, height_of)
            .has_value())
        << "unattested null slots must fail the whole height closed";

    // With attested failed-DKG evidence for every slot, the plan serves and
    // the byte-parity claim below holds.
    auto plan = build_daemonless_qc_plan(
        LlmqNetwork::Testnet, next_h, qmgr, fake_hash_at, height_of,
        /*cache=*/nullptr,
        /*null_evidence=*/[](uint8_t, const uint256&) { return true; });
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
    // NETWORK: testnet. LLMQ_50_60 (type 1) is enabled on testnet FOREVER
    // (dashd IsQuorumTypeEnabled has an unconditional `network == testnet`
    // disjunct) and is DISABLED on mainnet from DIP0024QuorumsHeight. This
    // test is about admission mechanics at the 50/40/30 size/minSize/threshold
    // shape, so it runs where that shape is real.
    MineableCommitmentCache cache;
    const uint256 qh = h256(0x55);
    auto good = real_commitment(kLlmq50_60, qh, 0, 0x11);

    // Structural rejects: wrong version / short bitsets / below threshold /
    // null crypto fields.
    {
        auto bad = good; bad.nVersion = CFinalCommitment::LEGACY_BLS_NON_INDEXED_QUORUM_VERSION;
        EXPECT_FALSE(cache.ingest(LlmqNetwork::Testnet, bad));
    }
    {
        auto bad = good; bad.signers.assign(10, true);
        EXPECT_FALSE(cache.ingest(LlmqNetwork::Testnet, bad));
    }
    {
        auto bad = good;
        bad.signers.assign(50, false);
        for (int i = 0; i < 29; ++i) bad.signers[static_cast<size_t>(i)] = true;  // below threshold (30)
        EXPECT_FALSE(cache.ingest(LlmqNetwork::Testnet, bad));
    }
    {
        // must-fix: >= threshold (30) but < minSize (40) — cryptographically
        // valid yet bad-qc-invalid to every dashd. MUST reject (else, once
        // member sourcing serves it, the block is lost).
        auto bad = good;
        bad.signers.assign(50, false);
        for (int i = 0; i < 35; ++i) bad.signers[static_cast<size_t>(i)] = true;
        EXPECT_FALSE(cache.ingest(LlmqNetwork::Testnet, bad))
            << "admitted a >=threshold but <minSize commitment (block-losing)";
        auto bad2 = good;
        bad2.validMembers.assign(50, false);
        for (int i = 0; i < 35; ++i) bad2.validMembers[static_cast<size_t>(i)] = true;
        EXPECT_FALSE(cache.ingest(LlmqNetwork::Testnet, bad2));
    }
    {
        auto bad = good; bad.quorumSig.fill(0);
        EXPECT_FALSE(cache.ingest(LlmqNetwork::Testnet, bad));
    }
    EXPECT_EQ(cache.size(), 0u);

    ASSERT_TRUE(cache.ingest(LlmqNetwork::Testnet, good));
    EXPECT_EQ(cache.size(), 1u);

    // THE Phase-L line: without a BLS verifier the cache NEVER serves. Under
    // the completeness gate an unverified mandatory slot with no failed-DKG
    // evidence fails the WHOLE height closed (block-1520106 fix)...
    EXPECT_FALSE(cache.has_bls_verifier());
    EXPECT_FALSE(cache.verified_for(1, qh).has_value());
    EXPECT_FALSE(daemonless_qc_commitments(
        LlmqNetwork::Testnet, 1'900'812u, fake_hash_at, never_mined, &cache)
            .has_value())
        << "unverifiable mandatory slots must fail the whole height closed";
    // ...and with attested failed-DKG evidence the consensus-valid nulls are
    // mined (the only case where null is canonical).
    auto plan_commitments = daemonless_qc_commitments(
        LlmqNetwork::Testnet, 1'900'812u, fake_hash_at, never_mined, &cache,
        [](uint8_t, const uint256&) { return true; });
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

// ── block 1520106: HEIGHT-COMPLETENESS KATs (real from-wire vectors) ───────
//
// The definitive-soak bad-cbtx: 1520106 is the FIRST height of the rotated
// LLMQ_60_75 (type 5, DIP-24) mining window (phase 42 of the 288-cycle) AND
// phase 18 of the 24-cycle (types 1/4/6 already mined) AND phase 42 of the
// 576-cycle (type 3 window). dashd mined 33 mandatory qc txs: 29 REAL
// rotated type-5 (idx 0..31 minus {2,3,31}), 3 null type-5 (idx 2/3/31,
// failed DKGs) and 1 null type-3. Pre-fix Phase-L null-served all 33 slots
// (rotated member sourcing unsupported => BLS verify fail-closed), folded
// NOTHING, and committed block 1520105's root verbatim — diverging from
// dashd's with-block root = FAIL_BAD_CBTX.

#include "data/dash_qc_1520106_kat.hpp"

namespace {

CFinalCommitment parse_commitment_hex(const std::string& hex)
{
    ::PackStream s;
    s.from_hex(hex);
    CFinalCommitment c;
    s >> c;
    EXPECT_EQ(s.cursor_size(), 0u) << "trailing bytes in commitment fixture";
    return c;
}

uint256 disp_to_u256(const std::string& disp)
{
    uint256 u;
    u.SetHex(disp);
    return u;
}

std::string span_hex(std::span<const std::byte> sp)
{
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(sp.size() * 2);
    for (auto b : sp) {
        const auto v = std::to_integer<uint8_t>(b);
        out.push_back(d[v >> 4]);
        out.push_back(d[v & 0xf]);
    }
    return out;
}

QuorumManager make_qmgr_1520105()
{
    vendor::QuorumTail tail;
    for (const auto& hex : dash_qc1520106::kActiveCommitmentHex)
        tail.newQuorums.push_back(parse_commitment_hex(hex));
    QuorumManager qmgr;
    qmgr.apply(tail);
    EXPECT_EQ(qmgr.active_count(), 109u);
    return qmgr;
}

std::optional<uint256> hash_at_1520106(uint32_t h)
{
    if (h >= dash_qc1520106::kRotatedCycleBase
        && h < dash_qc1520106::kRotatedCycleBase + 32)
        return disp_to_u256(dash_qc1520106::kBaseHashDisp
                                [h - dash_qc1520106::kRotatedCycleBase]);
    return std::nullopt;   // any other lookup would itself fail closed
}

// The four genuinely-failed DKG slots dashd mined NULL commitments for.
bool failed_dkg_1520106(uint8_t type, const uint256& qh)
{
    using namespace dash_qc1520106;
    if (type == 3) return qh == disp_to_u256(kBaseHashDisp[0]);
    if (type != 5) return false;
    return qh == disp_to_u256(kBaseHashDisp[2])
        || qh == disp_to_u256(kBaseHashDisp[3])
        || qh == disp_to_u256(kBaseHashDisp[31]);
}

} // namespace

TEST(DashDkgCommitments, Block1520106MandatorySlotSetMatchesDashd)
{
    auto qmgr = make_qmgr_1520105();
    auto has_mined = [&qmgr](uint8_t t, const uint256& qh) {
        return qmgr.find(t, qh).has_value();
    };
    // The interval-24 types (1/4/6, cycle base 1520088 = rotated base idx
    // 24) were mined at phase 10 and must be IN the active set — that is
    // what suppresses their slots at phase 18.
    const uint256 base24 = disp_to_u256(dash_qc1520106::kBaseHashDisp[24]);
    for (uint8_t t : {1, 4, 6})
        ASSERT_TRUE(has_mined(t, base24)) << "type " << int(t);

    auto slots = compute_required_qc_slots(
        LlmqNetwork::Testnet, dash_qc1520106::kHeight,
        hash_at_1520106, has_mined);
    ASSERT_TRUE(slots.has_value());
    // Exactly dashd's mined set: 32 rotated type-5 slots then the type-3
    // slot (AddLLMQ order == the block's qc tx order).
    ASSERT_EQ(slots->size(), 33u);
    for (int i = 0; i < 32; ++i) {
        EXPECT_EQ((*slots)[static_cast<size_t>(i)].params.type, 5);
        EXPECT_EQ((*slots)[static_cast<size_t>(i)].quorum_index, i);
        EXPECT_EQ((*slots)[static_cast<size_t>(i)].quorum_hash,
                  disp_to_u256(dash_qc1520106::kBaseHashDisp
                                   [static_cast<size_t>(i)]));
    }
    EXPECT_EQ(slots->back().params.type, 3);
    EXPECT_EQ(slots->back().quorum_index, 0);
    EXPECT_EQ(slots->back().quorum_hash,
              disp_to_u256(dash_qc1520106::kBaseHashDisp[0]));
}

TEST(DashDkgCommitments, Block1520106WithBlockFoldReproducesDashdRoot)
{
    auto qmgr = make_qmgr_1520105();

    // The active-set root IS the root the soak build served at 1520106 —
    // the completeness-gap signature (it folded nothing).
    EXPECT_EQ(compute_merkle_root_quorums(qmgr).GetHex(),
              dash_qc1520106::kQuorumRootActive1520105Disp);

    std::vector<CFinalCommitment> block_qcs;
    for (const auto& hex : dash_qc1520106::kBlockCommitmentHex)
        block_qcs.push_back(parse_commitment_hex(hex));
    ASSERT_EQ(block_qcs.size(), 33u);

    auto height_of = [](const uint256&) -> std::optional<uint32_t> {
        ADD_FAILURE() << "eviction ordering must not be needed (rotated "
                         "replacement + skipped nulls only)";
        return std::nullopt;
    };
    auto root = compute_merkle_root_quorums_with_block(
        LlmqNetwork::Testnet, qmgr, block_qcs, height_of);
    ASSERT_TRUE(root.has_value());
    // BYTE PARITY with the root dashd mined in block 1520106's cbTx.
    EXPECT_EQ(root->GetHex(), dash_qc1520106::kQuorumRootMined1520106Disp);
}

TEST(DashDkgCommitments, Block1520106CompletenessGateFailsClosedThenServes)
{
    auto qmgr = make_qmgr_1520105();
    auto height_of = [](const uint256&) -> std::optional<uint32_t> {
        return std::nullopt;   // must not be needed on any served path here
    };

    // (1) THE SOAK REALITY (fail-before/pass-after): rotated member sourcing
    // unsupported => cache empty/unverifiable => pre-fix the plan null-served
    // all 33 slots and committed the 1520105 root (bad-cbtx). Post-fix the
    // WHOLE height must fail closed — no plan, arm=dashd-fallback.
    RequiredQcSlot gap{};
    EXPECT_FALSE(build_daemonless_qc_plan(
        LlmqNetwork::Testnet, dash_qc1520106::kHeight, qmgr,
        hash_at_1520106, height_of,
        /*cache=*/nullptr, /*null_evidence=*/nullptr, &gap).has_value())
        << "unsourceable rotated slots must fail the whole height closed";
    EXPECT_EQ(gap.params.type, 5);
    EXPECT_EQ(gap.quorum_index, 0);   // first unsatisfiable mandatory slot

    // (2) PARTIAL sourcing: all 29 real rotated commitments BLS-verified,
    // but no failed-DKG evidence for the 4 null slots => still the whole
    // height (null-where-dashd-null cannot be assumed from absence).
    MineableCommitmentCache cache;
    std::vector<CFinalCommitment> block_qcs;
    for (const auto& hex : dash_qc1520106::kBlockCommitmentHex)
        block_qcs.push_back(parse_commitment_hex(hex));
    for (const auto& c : block_qcs)
        if (c.CountSigners() > 0)
            ASSERT_TRUE(cache.ingest(LlmqNetwork::Testnet, c));
    EXPECT_EQ(cache.size(), 29u);
    cache.set_bls_verify_fn([](const CFinalCommitment&) { return true; });
    EXPECT_FALSE(build_daemonless_qc_plan(
        LlmqNetwork::Testnet, dash_qc1520106::kHeight, qmgr,
        hash_at_1520106, height_of, &cache,
        /*null_evidence=*/nullptr, &gap).has_value())
        << "an unattested null slot must fail the whole height closed";
    EXPECT_EQ(gap.params.type, 5);
    EXPECT_EQ(gap.quorum_index, 2);   // idx 2 = the first failed-DKG slot

    // (3) COMPLETE sourcing: 29 verified reals + positive failed-DKG
    // evidence for exactly the 4 slots dashd mined null => the height
    // serves, every commitment byte-matches dashd's mined qc tx (including
    // the legitimately-null ones), and the committed root is dashd's.
    auto plan = build_daemonless_qc_plan(
        LlmqNetwork::Testnet, dash_qc1520106::kHeight, qmgr,
        hash_at_1520106, height_of, &cache, failed_dkg_1520106);
    ASSERT_TRUE(plan.has_value());
    ASSERT_EQ(plan->commitments.size(), 33u);
    for (size_t i = 0; i < 33; ++i) {
        auto packed = ::pack(plan->commitments[i]);
        EXPECT_EQ(span_hex(packed.get_span()),
                  dash_qc1520106::kBlockCommitmentHex[i])
            << "commitment " << i << " must byte-match dashd's mined qc";
    }
    EXPECT_EQ(plan->merkle_root_quorums.GetHex(),
              dash_qc1520106::kQuorumRootMined1520106Disp);
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

// ── COLD-START HOLE: classified + bounded refusal (mainnet 2026-08-03) ─────
//
// THE INCIDENT, replayed as a KAT. Daemonless mainnet node, binary
// 0.2.4-237-gdf160971, uptime 75 min, ONE qfcommit seen on the wire since
// start (type=4). At next_height 2515381 the type-1 (LLMQ_50_60) mandatory
// slot's commitment had been relayed BEFORE the process connected, so it was
// not in the MineableCommitmentCache; with no attested-null evidence source
// the WHOLE height failed closed and — the fallback arm being unarmed on a
// daemonless node — the stratum surface served an empty h=0 template for 11
// minutes / 14 serves (heights 2515381..2515384), self-healing at 2515385
// when another miner mined the commitment.
//
// PRIOR ART (dashpay/dash v21.1.0, verified): that commitment CANNOT be
// pulled. AddMineableCommitment announces it ONCE by inv at DKG finalize and
// GetMineableCommitmentByHash serves it BY COMMITMENT HASH only — there is
// no (llmqType, quorumHash)-keyed request, and mnlistdiff/qrinfo carry MINED
// commitments only. dashd has the same hole and mines NULL through it; we
// must not (block 1520106). So these KATs pin the two things we DO owe:
//   1. the gate still fails closed on EVERY unsatisfiable shape (no
//      weakening — each case below asserts nullopt), and
//   2. the refusal NAMES which of the five distinct causes fired, carries
//      the measured signer count (n/a, never 0, when nothing is held), and
//      BOUNDS the wait with the DKG mining window.
namespace {

// The incident's real coordinates.
constexpr uint32_t kIncidentHeight    = 2'515'381u;
constexpr uint32_t kIncidentCycleBase = 2'515'368u;   // 2515381 - 2515381%24

// NETWORK NOTE. The incident was LOGGED on mainnet as "type=1 qi=0", but
// type 1 was never actually required there — that report WAS the LLMQ_50_60
// defect (dashd's IsQuorumTypeEnabled disables LLMQ_50_60 on mainnet from
// DIP0024QuorumsHeight=1738698, so the slot could never be satisfied by
// anything). The mainnet coordinates are therefore now a REGRESSION vector
// (see IncidentHeightNoLongerRequiresTheDisabledType), while the cold-start
// NAMING mechanics — which are network-independent and still matter — are
// exercised on TESTNET, where type 1 genuinely is enabled forever.
//
// At kIncidentHeight the interval-24 types are all in phase 13 of [10,18]:
// mainnet has {4}, testnet has {1, 4, 6}. Pin every type EXCEPT 1 as
// already-mined so the type-1 slot is the whole story — exactly the shape
// the incident logged (first gap = type 1, qi 0).
QuorumManager qmgr_with_others_mined()
{
    vendor::QuorumTail tail;
    tail.newQuorums.push_back(
        real_commitment(kLlmq100_67, *fake_hash_at(kIncidentCycleBase), 0, 0x44));
    tail.newQuorums.push_back(
        real_commitment(kLlmq25_67, *fake_hash_at(kIncidentCycleBase), 0, 0x66));
    QuorumManager q;
    q.apply(tail);
    EXPECT_TRUE(q.find(4, *fake_hash_at(kIncidentCycleBase)).has_value());
    EXPECT_TRUE(q.find(6, *fake_hash_at(kIncidentCycleBase)).has_value());
    return q;
}

std::optional<QcBlockPlan> incident_plan(const QuorumManager& qmgr,
                                         const MineableCommitmentCache* cache,
                                         RequiredQcSlot* gap,
                                         LlmqNetwork net = LlmqNetwork::Testnet)
{
    return build_daemonless_qc_plan(
        net, kIncidentHeight, qmgr, fake_hash_at,
        [](const uint256&) -> std::optional<uint32_t> { return std::nullopt; },
        cache, /*null_evidence=*/nullptr, gap);
}

} // namespace

TEST(DashDkgColdStart, WindowBoundIsTheRefusalsUpperBound)
{
    // The measured bound the incident log now prints: LLMQ_50_60 window is
    // [cycleStart+10, cycleStart+18] = [2515378, 2515386].
    auto wb = qc_window_bound(kLlmq50_60, kIncidentHeight);
    EXPECT_EQ(wb.cycle_start, kIncidentCycleBase);
    EXPECT_EQ(wb.first_height, 2'515'378u);
    EXPECT_EQ(wb.last_height, 2'515'386u);
    EXPECT_EQ(wb.heights_remaining, 6u);   // 2515381..2515386 inclusive

    // NEGATIVE TWIN: past the window the slot is not required at all, so the
    // bound must collapse to zero rather than keep counting down forever.
    auto after = qc_window_bound(kLlmq50_60, 2'515'387u);
    EXPECT_EQ(after.heights_remaining, 0u);
    EXPECT_FALSE(is_mining_phase(kLlmq50_60, 2'515'387u));
    EXPECT_TRUE(is_mining_phase(kLlmq50_60, kIncidentHeight));

    // And the window the bound reports is the one the slot actually lives in:
    // every height in [first,last] is a mining phase, the flanks are not.
    for (uint32_t h = wb.first_height; h <= wb.last_height; ++h)
        EXPECT_TRUE(is_mining_phase(kLlmq50_60, h)) << "h=" << h;
    EXPECT_FALSE(is_mining_phase(kLlmq50_60, wb.first_height - 1));
    EXPECT_FALSE(is_mining_phase(kLlmq50_60, wb.last_height + 1));
}

// THE REGRESSION PROOF for the LLMQ_50_60 fix. This test FAILS on the old
// table (which required type 1 on mainnet -> one unsatisfiable slot -> the
// whole height fails closed) and passes on the corrected one.
TEST(DashDkgColdStart, IncidentHeightNoLongerRequiresTheDisabledType)
{
    auto qmgr = qmgr_with_others_mined();
    auto mined = [&qmgr](uint8_t t, const uint256& qh) {
        return qmgr.find(t, qh).has_value();
    };

    // MAINNET at the incident height: phase 13 is inside the interval-24
    // window [10,18], and the ONLY interval-24 type mainnet enables is 4,
    // which is already mined here. So there is no mandatory slot at all...
    auto slots = compute_required_qc_slots(
        LlmqNetwork::Mainnet, kIncidentHeight, fake_hash_at, mined);
    ASSERT_TRUE(slots.has_value());
    EXPECT_TRUE(slots->empty())
        << "mainnet must not require a runtime-disabled llmqType";
    for (const auto& sl : *slots)
        EXPECT_NE(sl.params.type, 1)
            << "LLMQ_50_60 is disabled on mainnet from DIP0024QuorumsHeight";

    // ...and the height SERVES rather than failing closed. This is the
    // 9-in-24 structural outage, gone.
    RequiredQcSlot gap{};
    MineableCommitmentCache empty_cache;
    auto plan = incident_plan(qmgr, &empty_cache, &gap, LlmqNetwork::Mainnet);
    ASSERT_TRUE(plan.has_value())
        << "the mainnet incident height must no longer fail closed";
    EXPECT_TRUE(plan->commitments.empty());

    // NEGATIVE TWIN — this test can still fail for the right reason: with the
    // one genuinely-required mainnet type NOT mined, the height must still
    // fail closed (the completeness gate is untouched by the type fix).
    QuorumManager nothing_mined;
    RequiredQcSlot gap2{};
    EXPECT_FALSE(incident_plan(nothing_mined, &empty_cache, &gap2,
                               LlmqNetwork::Mainnet).has_value());
    EXPECT_EQ(gap2.params.type, 4);
}

TEST(DashDkgColdStart, IncidentReplayFailsClosedNamingTheColdStartCause)
{
    // TESTNET — where type 1 is genuinely required forever, so the cold-start
    // naming mechanics the incident exercised remain covered.
    auto qmgr = qmgr_with_others_mined();

    // Only the type-1 slot is outstanding — the incident's exact shape.
    auto slots = compute_required_qc_slots(
        LlmqNetwork::Testnet, kIncidentHeight, fake_hash_at,
        [&qmgr](uint8_t t, const uint256& qh) {
            return qmgr.find(t, qh).has_value();
        });
    ASSERT_TRUE(slots.has_value());
    ASSERT_EQ(slots->size(), 1u);
    EXPECT_EQ((*slots)[0].params.type, 1);
    EXPECT_EQ((*slots)[0].quorum_index, 0);
    EXPECT_EQ((*slots)[0].quorum_hash, *fake_hash_at(kIncidentCycleBase));
    // A slot handed back in the mandatory set is NOT a gap — its diagnosis
    // fields must read unevaluated, never a fabricated cause or a zero.
    EXPECT_EQ((*slots)[0].gap, QcSlotGap::Unevaluated);
    EXPECT_EQ((*slots)[0].cached_signers, -1);

    // THE COLD START: the commitment predates the process, so the cache is
    // empty for it. FAIL CLOSED — unchanged behaviour — but now named.
    MineableCommitmentCache cache;
    RequiredQcSlot gap{};
    EXPECT_FALSE(incident_plan(qmgr, &cache, &gap).has_value())
        << "a mandatory slot with no commitment must fail the WHOLE height";
    EXPECT_EQ(gap.params.type, 1);
    EXPECT_EQ(gap.quorum_index, 0);
    EXPECT_EQ(gap.gap, QcSlotGap::NoCommitmentCached);
    EXPECT_STREQ(qc_slot_gap_name(gap.gap), "no-commitment-cached");
    // n/a, NOT 0: nothing was held, so no signer count was ever measured.
    EXPECT_EQ(gap.cached_signers, -1);
    EXPECT_EQ(cache.cached_signers(1, *fake_hash_at(kIncidentCycleBase)), -1);
    EXPECT_FALSE(cache.has_commitment(1, *fake_hash_at(kIncidentCycleBase)));

    // No cache wired at all reads the same way (nothing is held either way).
    RequiredQcSlot gap_nocache{};
    EXPECT_FALSE(incident_plan(qmgr, nullptr, &gap_nocache).has_value());
    EXPECT_EQ(gap_nocache.gap, QcSlotGap::NoCommitmentCached);
    EXPECT_EQ(gap_nocache.cached_signers, -1);
}

TEST(DashDkgColdStart, BackFilledCommitmentServesAndItsRemovalFailsClosed)
{
    // THE POSITIVE: whatever fills the cache for a slot whose commitment
    // predates startup — today only live relay; no P2P back-fill exists —
    // the height must serve the moment it is BLS-verifiable, with dashd's
    // real commitment in the plan rather than a null.
    auto qmgr = qmgr_with_others_mined();
    const uint256 qh = *fake_hash_at(kIncidentCycleBase);
    auto real = real_commitment(kLlmq50_60, qh, /*quorumIndex=*/0, 0x11);

    MineableCommitmentCache cache;
    ASSERT_TRUE(cache.ingest(LlmqNetwork::Testnet, real));
    cache.set_bls_verify_fn([](const CFinalCommitment&) { return true; });
    cache.set_members_ready_fn([](uint8_t, const uint256&) { return true; });

    RequiredQcSlot gap{};
    auto plan = incident_plan(qmgr, &cache, &gap);
    ASSERT_TRUE(plan.has_value()) << "a verifiable commitment must SERVE";
    ASSERT_EQ(plan->commitments.size(), 1u);
    EXPECT_EQ(plan->commitments[0].llmqType, 1);
    EXPECT_EQ(plan->commitments[0].quorumHash, qh);
    // A REAL commitment, not the null dashd would have mined here.
    EXPECT_EQ(plan->commitments[0].CountSigners(), 50);
    EXPECT_GT(plan->commitments[0].CountSigners(), 0);
    // Measured, not guessed.
    EXPECT_EQ(cache.cached_signers(1, qh), 50);

    // THE NEGATIVE TWIN — the back-fill removed: same qmgr, same height,
    // same verifier, cache emptied. Must fail closed.
    cache.clear();
    RequiredQcSlot gap2{};
    EXPECT_FALSE(incident_plan(qmgr, &cache, &gap2).has_value())
        << "without the commitment the WHOLE height must fail closed";
    EXPECT_EQ(gap2.gap, QcSlotGap::NoCommitmentCached);
    EXPECT_EQ(gap2.cached_signers, -1);
}

TEST(DashDkgColdStart, EveryUnsatisfiableShapeFailsClosedWithItsOwnName)
{
    auto qmgr = qmgr_with_others_mined();
    const uint256 qh = *fake_hash_at(kIncidentCycleBase);
    auto real = real_commitment(kLlmq50_60, qh, 0, 0x11);

    // (1) cached, but NO BLS verifier installed => bls-verifier-absent.
    {
        MineableCommitmentCache cache;
        ASSERT_TRUE(cache.ingest(LlmqNetwork::Testnet, real));
        EXPECT_FALSE(cache.has_bls_verifier());
        RequiredQcSlot gap{};
        EXPECT_FALSE(incident_plan(qmgr, &cache, &gap).has_value());
        EXPECT_EQ(gap.gap, QcSlotGap::VerifierAbsent);
        EXPECT_STREQ(qc_slot_gap_name(gap.gap), "bls-verifier-absent");
        // The signer count IS measured here — something is held.
        EXPECT_EQ(gap.cached_signers, 50);
        // No member probe installed => the readiness axis is n/a, not "no".
        EXPECT_FALSE(cache.members_ready(1, qh).has_value());
    }

    // (2) cached + verifier, member set still in flight => member-set-unsourced.
    {
        MineableCommitmentCache cache;
        ASSERT_TRUE(cache.ingest(LlmqNetwork::Testnet, real));
        cache.set_bls_verify_fn([](const CFinalCommitment&) { return false; });
        cache.set_members_ready_fn([](uint8_t, const uint256&) { return false; });
        RequiredQcSlot gap{};
        EXPECT_FALSE(incident_plan(qmgr, &cache, &gap).has_value());
        EXPECT_EQ(gap.gap, QcSlotGap::MemberSetUnsourced);
        ASSERT_TRUE(cache.members_ready(1, qh).has_value());
        EXPECT_FALSE(*cache.members_ready(1, qh));
    }

    // (3) cached + verifier + members READY, signature rejected => the
    //     hostile/corrupt-peer case, which must read differently from (2).
    {
        MineableCommitmentCache cache;
        ASSERT_TRUE(cache.ingest(LlmqNetwork::Testnet, real));
        cache.set_bls_verify_fn([](const CFinalCommitment&) { return false; });
        cache.set_members_ready_fn([](uint8_t, const uint256&) { return true; });
        RequiredQcSlot gap{};
        EXPECT_FALSE(incident_plan(qmgr, &cache, &gap).has_value());
        EXPECT_EQ(gap.gap, QcSlotGap::BlsVerifyFailed);
        EXPECT_STREQ(qc_slot_gap_name(gap.gap), "bls-verify-failed");
    }

    // (4) verified, but the relayed copy carries a flipped quorumIndex —
    //     serving it is bad-qc-invalid, so the slot stays unsatisfiable and
    //     must NOT be reported as a relay gap.
    {
        MineableCommitmentCache cache;
        auto flipped = real;
        flipped.quorumIndex = 7;    // slot's index is 0
        ASSERT_TRUE(cache.ingest(LlmqNetwork::Testnet, flipped));
        cache.set_bls_verify_fn([](const CFinalCommitment&) { return true; });
        cache.set_members_ready_fn([](uint8_t, const uint256&) { return true; });
        RequiredQcSlot gap{};
        EXPECT_FALSE(incident_plan(qmgr, &cache, &gap).has_value());
        EXPECT_EQ(gap.gap, QcSlotGap::QuorumIndexMismatch);
        EXPECT_STREQ(qc_slot_gap_name(gap.gap), "quorum-index-mismatch");
    }

    // (5) THE ONE SERVING SHAPE, for contrast: all four defects absent.
    {
        MineableCommitmentCache cache;
        ASSERT_TRUE(cache.ingest(LlmqNetwork::Testnet, real));
        cache.set_bls_verify_fn([](const CFinalCommitment&) { return true; });
        cache.set_members_ready_fn([](uint8_t, const uint256&) { return true; });
        RequiredQcSlot gap{};
        EXPECT_TRUE(incident_plan(qmgr, &cache, &gap).has_value());
        EXPECT_TRUE(cache.verified_for(1, qh).has_value());
        // A served height leaves the gap code UNTOUCHED. There is no "none"
        // code to assert here on purpose: success is reported by the plan
        // existing, never by a status word that could read as "fine" when it
        // was in fact never measured.
        EXPECT_EQ(gap.gap, QcSlotGap::Unevaluated);
        EXPECT_STREQ(qc_slot_gap_name(gap.gap), "n/a");
    }
}

TEST(DashDkgColdStart, DiagnosisNeverInfluencesTheServeDecision)
{
    // The gate must key off verified_for ALONE. A members_ready probe that
    // lies in either direction changes the NAME on the refusal and nothing
    // else — belt-and-braces against the diagnosis seam becoming a bypass.
    auto qmgr = qmgr_with_others_mined();
    const uint256 qh = *fake_hash_at(kIncidentCycleBase);
    auto real = real_commitment(kLlmq50_60, qh, 0, 0x11);

    // Probe says "ready" while the verifier rejects: still fails closed.
    MineableCommitmentCache lying_ready;
    ASSERT_TRUE(lying_ready.ingest(LlmqNetwork::Testnet, real));
    lying_ready.set_bls_verify_fn([](const CFinalCommitment&) { return false; });
    lying_ready.set_members_ready_fn([](uint8_t, const uint256&) { return true; });
    EXPECT_FALSE(incident_plan(qmgr, &lying_ready, nullptr).has_value());

    // Probe says "not ready" while the verifier accepts: still SERVES (the
    // probe is observability, it can never withhold a valid commitment).
    MineableCommitmentCache lying_unready;
    ASSERT_TRUE(lying_unready.ingest(LlmqNetwork::Testnet, real));
    lying_unready.set_bls_verify_fn([](const CFinalCommitment&) { return true; });
    lying_unready.set_members_ready_fn([](uint8_t, const uint256&) { return false; });
    EXPECT_TRUE(incident_plan(qmgr, &lying_unready, nullptr).has_value());
}

TEST(DashDkgColdStart, EveryAdmissionRejectionHasItsOwnName)
{
    // A relayed qfcommit that structural admission drops must SAY SO. Before
    // this, ingest returned bare false and only the accept path logged — so a
    // later "no-commitment-cached" refusal could not be told apart from "the
    // commitment never reached us on the wire". Opposite diagnoses.
    using Adm = MineableCommitmentCache::Admission;
    const uint256 qh = h256(0x55);
    auto good = real_commitment(kLlmq50_60, qh, 0, 0x11);

    MineableCommitmentCache cache;
    // POSITIVE: the good one is accepted and says so.
    EXPECT_EQ(cache.ingest_ex(LlmqNetwork::Testnet, good), Adm::Accepted);
    EXPECT_STREQ(MineableCommitmentCache::admission_name(Adm::Accepted),
                 "accepted");
    EXPECT_EQ(cache.cached_signers(1, qh), 50);

    // NEGATIVE TWINS: one per rejection branch, each named distinctly.
    {
        auto bad = good; bad.llmqType = 99;
        MineableCommitmentCache c2;
        EXPECT_EQ(c2.ingest_ex(LlmqNetwork::Testnet, bad), Adm::UnknownType);
    }
    {
        auto bad = good;
        bad.nVersion = CFinalCommitment::LEGACY_BLS_NON_INDEXED_QUORUM_VERSION;
        MineableCommitmentCache c2;
        EXPECT_EQ(c2.ingest_ex(LlmqNetwork::Testnet, bad), Adm::WrongVersion);
    }
    {
        auto bad = good; bad.signers.assign(10, true);
        MineableCommitmentCache c2;
        EXPECT_EQ(c2.ingest_ex(LlmqNetwork::Testnet, bad),
                  Adm::BitsetSizeMismatch);
    }
    {
        auto bad = good;
        bad.validMembers.assign(50, false);
        for (int i = 0; i < 35; ++i) bad.validMembers[static_cast<size_t>(i)] = true;
        MineableCommitmentCache c2;
        EXPECT_EQ(c2.ingest_ex(LlmqNetwork::Testnet, bad),
                  Adm::ValidMembersBelowMin);
    }
    {
        auto bad = good;
        bad.signers.assign(50, false);
        for (int i = 0; i < 35; ++i) bad.signers[static_cast<size_t>(i)] = true;
        MineableCommitmentCache c2;
        EXPECT_EQ(c2.ingest_ex(LlmqNetwork::Testnet, bad), Adm::SignersBelowMin);
    }
    {
        auto bad = good; bad.membersSig.fill(0);
        MineableCommitmentCache c2;
        EXPECT_EQ(c2.ingest_ex(LlmqNetwork::Testnet, bad),
                  Adm::NullCryptoFields);
    }
    // Keep-best-by-CountSigners: a re-relay of the SAME commitment is not a
    // defect and must not read like one.
    EXPECT_EQ(cache.ingest_ex(LlmqNetwork::Testnet, good),
              Adm::NotBetterThanCached);
    EXPECT_EQ(cache.size(), 1u);

    // Every name is distinct — a shared string would re-collapse the causes.
    const Adm all[] = {Adm::Accepted, Adm::UnknownType, Adm::WrongVersion,
                       Adm::BitsetSizeMismatch, Adm::ValidMembersBelowMin,
                       Adm::SignersBelowMin, Adm::NullCryptoFields,
                       Adm::NotBetterThanCached};
    std::vector<std::string> names;
    for (auto a : all) names.emplace_back(MineableCommitmentCache::admission_name(a));
    std::sort(names.begin(), names.end());
    EXPECT_EQ(std::adjacent_find(names.begin(), names.end()), names.end())
        << "two admission outcomes share a name";

    // And the legacy bool wrapper still means exactly "accepted".
    MineableCommitmentCache c3;
    EXPECT_TRUE(c3.ingest(LlmqNetwork::Testnet, good));
    EXPECT_FALSE(c3.ingest(LlmqNetwork::Testnet, good));
}

// ── enabled-set parity + the LLMQ_50_60 fix ────────────────────────────────
//
// NOTE FOR REVIEWERS: several open PRs append test sections to the END of this
// file. If this block conflicts, it is a pure append-vs-append conflict — take
// both sides.
//
// GROUND TRUTH used below (all re-derivable, none of it guessed):
//   * dashpay/dash v23.1.7 validation.cpp ChainstateManager::IsQuorumTypeEnabled
//     — the RUNTIME predicate CQuorumBlockProcessor::ProcessBlock filters the
//     chainparams AddLLMQ list through (via GetEnabledQuorumParams). LLMQ_50_60:
//       !fDIP0024IsActive || !fHaveDIP0024Quorums || testnet || devnet
//   * chainparams.cpp v23.1.7: mainnet DIP0024QuorumsHeight 1738698,
//     V19Height 1899072; testnet 770730 / 850100, LLMQ_25_67 from 847000.
//   * A live Dash Core 23.1.7 mainnet node at height 2515629: `quorum list`
//     returns exactly {llmq_60_75, llmq_400_60, llmq_400_85, llmq_100_67}, in
//     that order, and nothing else.

TEST(DashLlmqEnabledSet, MainnetMatchesDashdQuorumListExactlyAndInOrder)
{
    // CLAIM: mainnet's enabled set == the four types a live mainnet dashd
    // reports, in dashd's own enumeration order.
    const auto& m = enabled_llmqs(LlmqNetwork::Mainnet);
    ASSERT_EQ(m.size(), 4u);
    EXPECT_EQ(m[0].type, 5);    // llmq_60_75
    EXPECT_EQ(m[1].type, 2);    // llmq_400_60
    EXPECT_EQ(m[2].type, 3);    // llmq_400_85
    EXPECT_EQ(m[3].type, 4);    // llmq_100_67

    // THE DEFECT, named: LLMQ_50_60 is in mainnet CHAINPARAMS but is disabled
    // by the runtime predicate at every height >= 1738698 — 160374 blocks
    // below our serve floor. It must never be required on mainnet.
    for (const auto& p : m)
        EXPECT_NE(p.type, 1)
            << "LLMQ_50_60 is runtime-disabled on mainnet; requiring it emits a"
               " mandatory slot nothing can ever satisfy";
    // ...nor LLMQ_25_67, which is testnet-only.
    for (const auto& p : m) EXPECT_NE(p.type, 6);
}

TEST(DashLlmqEnabledSet, TestnetKeepsLlmq50_60Deliberately)
{
    // CLAIM: the mainnet fix is NOT mirrored to testnet, and that is correct
    // rather than an oversight. IsQuorumTypeEnabled's third disjunct
    // (`NetworkIDString() == TESTNET`) is unconditional and height-independent,
    // so LLMQ_50_60 is enabled on testnet forever — it is also testnet's
    // llmqTypeChainLocks and llmqTypeMnhf. Deleting it here would be a NEW
    // defect wearing the shape of a symmetry fix.
    const auto& t = enabled_llmqs(LlmqNetwork::Testnet);
    ASSERT_EQ(t.size(), 6u);
    EXPECT_EQ(t[0].type, 1);    // llmq_50_60 — STAYS
    EXPECT_EQ(t[1].type, 5);
    EXPECT_EQ(t[2].type, 2);
    EXPECT_EQ(t[3].type, 3);
    EXPECT_EQ(t[4].type, 4);
    EXPECT_EQ(t[5].type, 6);    // llmq_25_67, enabled from testnet h=847000
                                // < the testnet serve floor 850100
    // The two networks genuinely differ — this is not a copy-paste artefact.
    EXPECT_NE(enabled_llmqs(LlmqNetwork::Mainnet).size(), t.size());
}

TEST(DashLlmqEnabledSet, NoMainnetWindowHeightEverRequiresADisabledType)
{
    // CLAIM: the fix holds across the whole height domain, not at one lucky
    // height. Sweep a full 576-block superperiod (lcm of 24/288/576) above the
    // mainnet serve floor: every mandatory slot must name a type the live
    // mainnet node actually reports.
    const std::set<uint8_t> dashd_types{5, 2, 3, 4};
    size_t window_heights = 0, band_24_heights = 0;
    for (uint32_t h = 1'900'800u; h < 1'900'800u + 576u; ++h) {
        auto slots = compute_required_qc_slots(
            LlmqNetwork::Mainnet, h, fake_hash_at, never_mined);
        ASSERT_TRUE(slots.has_value()) << "h=" << h;
        if (!slots->empty()) ++window_heights;
        for (const auto& s : *slots) {
            EXPECT_TRUE(dashd_types.count(s.params.type) != 0)
                << "h=" << h << " requires type "
                << static_cast<int>(s.params.type)
                << " which mainnet dashd does not enable";
            EXPECT_NE(s.params.type, 1) << "h=" << h;
        }
        // The interval-24 band [10,18] is the one the defect blanked: it is
        // still a window band, but now every slot in it is type 4 — a type
        // that IS mined, so the height is satisfiable rather than dead.
        if (h % 24u >= 10u && h % 24u <= 18u) {
            ++band_24_heights;
            bool has24 = false;
            for (const auto& s : *slots)
                if (s.params.type == 4) has24 = true;
            EXPECT_TRUE(has24) << "h=" << h;
        }
    }
    EXPECT_EQ(band_24_heights, 9u * 24u);   // 9 of every 24 heights
    EXPECT_GT(window_heights, 0u);
}

// ── LlmqTypeReconciler: the negative-capable backstop ──────────────────────

namespace {

// A mined-type stream shaped like a healthy chain: every required type shows
// up in the active set at every tip.
std::vector<uint8_t> healthy_types(LlmqNetwork net)
{
    std::vector<uint8_t> v;
    for (const auto& p : enabled_llmqs(net)) v.push_back(p.type);
    return v;
}

std::optional<LlmqTypeFinding> finding_for(
    const std::vector<LlmqTypeFinding>& fs, uint8_t type)
{
    for (const auto& f : fs) if (f.llmq_type == type) return f;
    return std::nullopt;
}

} // namespace

TEST(DashLlmqTypeReconciler, NamesARequiredTypeThatIsNeverMined)
{
    // CLAIM (the guard's whole reason to exist): a type we REQUIRE but that
    // the chain never mines is named LOUDLY, while "not yet arrived" is not.
    // This is the exact pre-fix mainnet shape, reproduced against the REAL
    // table by starving one genuinely-required testnet type (6 / llmq_25_67).
    LlmqTypeReconciler r(LlmqNetwork::Testnet);
    auto stream = healthy_types(LlmqNetwork::Testnet);
    stream.erase(std::remove(stream.begin(), stream.end(), uint8_t{6}),
                 stream.end());
    for (uint32_t h = 850'200u; h <= 850'200u + 48u; ++h)
        r.observe(h, stream);

    auto d = r.defects();
    ASSERT_EQ(d.size(), 1u) << "exactly the starved type must be indicted";
    EXPECT_EQ(d[0].llmq_type, 6);
    EXPECT_EQ(d[0].verdict, LlmqTypeVerdict::NeverObserved);
    EXPECT_TRUE(d[0].required);
    EXPECT_EQ(d[0].sightings, 0u);
    EXPECT_STREQ(llmq_type_verdict_name(d[0].verdict),
                 "REQUIRED-BUT-NEVER-OBSERVED");

    // The rendering must NAME the type — an operator must not have to open a
    // debugger to learn which one.
    const auto said = r.format_defects();
    EXPECT_NE(said.find("type=6"), std::string::npos) << said;
    EXPECT_NE(said.find("REQUIRED-BUT-NEVER-OBSERVED"), std::string::npos)
        << said;

    // Every OTHER required type reads Observed, not "unevaluated" — the check
    // discriminates, it does not merely shrug at everything.
    auto all = r.reconcile();
    for (const auto& p : enabled_llmqs(LlmqNetwork::Testnet)) {
        auto f = finding_for(all, p.type);
        ASSERT_TRUE(f.has_value());
        EXPECT_EQ(f->verdict, p.type == 6 ? LlmqTypeVerdict::NeverObserved
                                          : LlmqTypeVerdict::Observed)
            << "type " << static_cast<int>(p.type);
    }
}

TEST(DashLlmqTypeReconciler, SaysNothingOnAHealthyChain)
{
    // THE NEGATIVE CONTROL. A check that always fires is as useless as one
    // that never can: on a chain that mines every required type, the guard
    // must be SILENT — and format_defects() must return the empty string so
    // no caller is tempted to log a reassuring "ok" it did not earn.
    for (auto net : {LlmqNetwork::Mainnet, LlmqNetwork::Testnet}) {
        LlmqTypeReconciler r(net);
        for (uint32_t h = 1'900'800u; h <= 1'900'800u + 600u; ++h)
            r.observe(h, healthy_types(net));
        EXPECT_TRUE(r.defects().empty());
        EXPECT_TRUE(r.format_defects().empty());
        for (const auto& f : r.reconcile()) {
            EXPECT_EQ(f.verdict, LlmqTypeVerdict::Observed);
            EXPECT_FALSE(is_llmq_type_defect(f.verdict));
        }
    }
}

TEST(DashLlmqTypeReconciler, RefusesToIndictWhenTheChannelItselfIsSilent)
{
    // FALSE-POSITIVE DISCIPLINE. A bootstrapping / drained QuorumManager
    // reports nothing for ANY type. Absence is only evidence when presence was
    // demonstrable on the same channel, so the honest verdict here is
    // Unevaluated for every type — never a blanket indictment of all of them.
    LlmqTypeReconciler r(LlmqNetwork::Mainnet);
    for (uint32_t h = 1'900'800u; h <= 1'900'800u + 600u; ++h)
        r.observe(h, std::vector<uint8_t>{});
    EXPECT_TRUE(r.defects().empty());
    for (const auto& f : r.reconcile()) {
        EXPECT_EQ(f.verdict, LlmqTypeVerdict::Unevaluated);
        EXPECT_STREQ(f.pending_reason, "no-required-type-observed-anywhere");
    }

    // ...and the moment ONE required type is corroborated, the same silence
    // about the others becomes a real finding. The rule buys discrimination,
    // it does not disable the check.
    for (uint32_t h = 1'901'401u; h <= 1'901'401u + 48u; ++h)
        r.observe(h, std::vector<uint8_t>{4});
    auto d = r.defects();
    EXPECT_EQ(d.size(), 3u);   // types 5, 2, 3 — required, still never seen
    for (const auto& f : d)
        EXPECT_EQ(f.verdict, LlmqTypeVerdict::NeverObserved);
}

TEST(DashLlmqTypeReconciler, WaitsForAFullDkgCycleAndSaysWhyItIsWaiting)
{
    // A verdict must not outrun its evidence. Before one full DKG cycle of the
    // starved type has elapsed under observation, the verdict is Unevaluated
    // WITH A NAMED REASON — never a fabricated pass and never a premature
    // indictment.
    LlmqTypeReconciler r(LlmqNetwork::Testnet);
    auto stream = healthy_types(LlmqNetwork::Testnet);
    stream.erase(std::remove(stream.begin(), stream.end(), uint8_t{3}),
                 stream.end());
    // Too few observations first.
    for (uint32_t h = 850'200u; h < 850'200u + 4u; ++h) r.observe(h, stream);
    {
        auto f = finding_for(r.reconcile(), 3);
        ASSERT_TRUE(f.has_value());
        EXPECT_EQ(f->verdict, LlmqTypeVerdict::Unevaluated);
        EXPECT_STREQ(f->pending_reason, "too-few-observations");
    }
    // Enough observations, but LLMQ_400_85's dkgInterval is 576 and the span
    // is far shorter — still not a completed experiment.
    for (uint32_t h = 850'204u; h < 850'204u + 100u; ++h) r.observe(h, stream);
    {
        auto f = finding_for(r.reconcile(), 3);
        ASSERT_TRUE(f.has_value());
        EXPECT_EQ(f->verdict, LlmqTypeVerdict::Unevaluated);
        EXPECT_STREQ(f->pending_reason, "span-shorter-than-one-dkg-cycle");
        EXPECT_TRUE(r.defects().empty());
    }
    // A full 576-block cycle later it IS a completed experiment, and the
    // guard commits to the negative.
    for (uint32_t h = 850'304u; h <= 850'304u + 600u; ++h) r.observe(h, stream);
    {
        auto f = finding_for(r.reconcile(), 3);
        ASSERT_TRUE(f.has_value());
        EXPECT_EQ(f->verdict, LlmqTypeVerdict::NeverObserved);
        EXPECT_STREQ(f->pending_reason, "n/a");
    }
}

TEST(DashLlmqTypeReconciler, NamesAMinedTypeWeDoNotRequire)
{
    // THE OTHER DIRECTION — the half a one-directional check would miss, and
    // the one that makes this survive a future Dash consensus change. If
    // upstream ADDS or RE-ENABLES a type, our blocks silently omit a mandatory
    // commitment (bad-qc-missing) with no local symptom at all. Seeing a mined
    // type we do not require is that symptom.
    LlmqTypeReconciler r(LlmqNetwork::Mainnet);
    auto stream = healthy_types(LlmqNetwork::Mainnet);
    stream.push_back(7);            // a type upstream mines and we do not model
    for (uint32_t h = 1'900'800u; h <= 1'900'800u + 600u; ++h)
        r.observe(h, stream);

    auto d = r.defects();
    ASSERT_EQ(d.size(), 1u);
    EXPECT_EQ(d[0].llmq_type, 7);
    EXPECT_EQ(d[0].verdict, LlmqTypeVerdict::UnexpectedType);
    EXPECT_FALSE(d[0].required);
    EXPECT_GT(d[0].sightings, 0u);
    const auto said = r.format_defects();
    EXPECT_NE(said.find("type=7"), std::string::npos) << said;
    EXPECT_NE(said.find("MINED-BUT-NOT-REQUIRED"), std::string::npos) << said;
}

TEST(DashLlmqTypeReconciler, ReadsTheProductionQuorumManagerSource)
{
    // The production overload must observe the SAME thing the hand-fed one
    // does — otherwise the guard tested here is not the guard that ships.
    // The mnlistdiff-fed active set IS dashd's mined-and-active commitment
    // set (dkg_commitments.hpp header note), so it is the mined-type source.
    QuorumManager qmgr;
    vendor::QuorumTail tail;
    tail.newQuorums.push_back(real_commitment(kLlmq400_60, h256(0x21), 0, 0x01));
    tail.newQuorums.push_back(real_commitment(kLlmq400_85, h256(0x22), 0, 0x02));
    tail.newQuorums.push_back(real_commitment(kLlmq100_67, h256(0x23), 0, 0x03));
    qmgr.apply(tail);

    LlmqTypeReconciler r(LlmqNetwork::Mainnet);
    for (uint32_t h = 1'900'800u; h <= 1'900'800u + 600u; ++h)
        r.observe(h, qmgr);
    EXPECT_EQ(r.observations(), 601u);

    // Types 2/3/4 are in the active set; type 5 (rotated llmq_60_75) is not,
    // and IS required — so it is correctly indicted rather than ignored.
    auto d = r.defects();
    ASSERT_EQ(d.size(), 1u);
    EXPECT_EQ(d[0].llmq_type, 5);
    EXPECT_EQ(d[0].verdict, LlmqTypeVerdict::NeverObserved);
}

namespace {

// One entry per required mainnet type, so every reconciler test below is
// corroborated and no REQUIRED-type finding contaminates the axis under
// test (the MINED-BUT-NOT-REQUIRED side).
void add_required_mainnet_entries(QuorumManager& qmgr, uint8_t seed)
{
    vendor::QuorumTail tail;
    tail.newQuorums.push_back(
        real_commitment(kLlmq60_75,  h256(seed + 0), 0, seed + 0));
    tail.newQuorums.push_back(
        real_commitment(kLlmq400_60, h256(seed + 1), 0, seed + 1));
    tail.newQuorums.push_back(
        real_commitment(kLlmq400_85, h256(seed + 2), 0, seed + 2));
    tail.newQuorums.push_back(
        real_commitment(kLlmq100_67, h256(seed + 3), 0, seed + 3));
    qmgr.apply(tail);
}

} // namespace

TEST(DashLlmqTypeReconciler, ZeroWidthWindowCannotIndictAMinedButNotRequiredType)
{
    // kMinObservations observe() calls accumulate at a SINGLE tip in
    // production (one call per template build, many builds per block), so the
    // observation-count gate alone is satisfiable before any observation
    // window exists. A zero-width window proves nothing about any type: the
    // unexpected side must demand the same thing the required side always
    // has — a window at least one DKG cycle wide — before it indicts.
    LlmqTypeReconciler r(LlmqNetwork::Mainnet);
    auto stream = healthy_types(LlmqNetwork::Mainnet);
    stream.push_back(7);            // a type we do not require
    for (uint32_t i = 0; i < LlmqTypeReconciler::kMinObservations + 4u; ++i)
        r.observe(1'950'000u, stream);          // SAME tip every time: span 0

    EXPECT_EQ(r.span_heights(), 0u);
    EXPECT_TRUE(r.defects().empty())
        << "zero-width window must not indict: " << r.format_defects();
    auto f = finding_for(r.reconcile(), 7);
    ASSERT_TRUE(f.has_value());
    EXPECT_EQ(f->verdict, LlmqTypeVerdict::Unevaluated);
    EXPECT_STREQ(f->pending_reason, "span-shorter-than-one-dkg-cycle");
    EXPECT_EQ(r.format_defects().find("MINED-BUT-NOT-REQUIRED"),
              std::string::npos);

    // The gate DELAYS the verdict, it does not destroy it: once a real
    // window exists (>= one cycle; type 7 is unknown to the params table so
    // the conservative largest-known cycle, 576, applies) the same evidence
    // convicts.
    for (uint32_t h = 1'950'001u; h <= 1'950'000u + 600u; ++h)
        r.observe(h, stream);
    auto d = r.defects();
    ASSERT_EQ(d.size(), 1u);
    EXPECT_EQ(d[0].llmq_type, 7);
    EXPECT_EQ(d[0].verdict, LlmqTypeVerdict::UnexpectedType);
}

TEST(DashLlmqTypeReconciler, StaleDatedEntryIsNeverSightedAtAll)
{
    // The 2026-08-04 soak defect, DATABLE variant. A local active-set entry
    // whose quorum was mined far outside its type's retention window
    // (dkgInterval x signingActiveQuorumCount — the span the chain itself
    // keeps a quorum active) cannot be a currently-active quorum. Observing
    // it must register NOTHING: the defect was stamping such an entry with
    // the CURRENT TIP at every sample, which made one stale entry ring
    // MINED-BUT-NOT-REQUIRED forever with sightings == observations.
    constexpr uint32_t kT0 = 1'950'000u;
    QuorumManager qmgr;
    add_required_mainnet_entries(qmgr, 0x40);
    qmgr.find_mutable(5, h256(0x40))->mining_height = kT0;   // llmq_60_75
    qmgr.find_mutable(2, h256(0x41))->mining_height = kT0;   // llmq_400_60
    qmgr.find_mutable(3, h256(0x42))->mining_height = kT0;   // llmq_400_85
    qmgr.find_mutable(4, h256(0x43))->mining_height = kT0;   // llmq_100_67
    // The stale entry: type 1 (LLMQ_50_60 — mainnet cannot even mine it),
    // dated 2000 blocks before our window; retention for type 1 is
    // 24 x 24 = 576.
    vendor::QuorumTail tail;
    tail.newQuorums.push_back(real_commitment(kLlmq50_60, h256(0x51), 0, 0x51));
    qmgr.apply(tail);
    qmgr.find_mutable(1, h256(0x51))->mining_height = kT0 - 2'000u;

    LlmqTypeReconciler r(LlmqNetwork::Mainnet);
    for (uint32_t h = kT0; h <= kT0 + 700u; ++h) r.observe(h, qmgr);

    // The stale entry never registers a sighting, so type 1 produces no
    // finding at all — and in particular no defect.
    EXPECT_TRUE(r.defects().empty()) << r.format_defects();
    auto f = finding_for(r.reconcile(), 1);
    EXPECT_FALSE(f.has_value())
        << "a stale entry must not manufacture sightings; got sightings="
        << (f ? f->sightings : 0u) << " of " << r.observations()
        << " observations";
}

TEST(DashLlmqTypeReconciler, UndatableStaleEntryAgesOutAndTheAlarmClears)
{
    // The 2026-08-04 soak defect, EXACT measured shape. The stale type-1
    // entry has mining_height 0 (the [QC-MINED] scanner never saw a type-1
    // qfcommit — none exists), so it cannot be dated better than "when WE
    // first saw it". Both soaks measured sightings == observations EXACTLY
    // (1408==1408, 895==895) over ~12 h with zero type-1 qfcommits on chain:
    // the entry re-registered as fresh at every sample, so the alarm could
    // never decay and carried no information. Post-fix the entry dates from
    // first sight, ages out of retention (576 blocks for type 1), sightings
    // FREEZE, and one DKG cycle later the verdict decays to the named
    // non-defect StaleSightings — the alarm CLEARS.
    constexpr uint32_t kT0 = 1'950'000u;
    QuorumManager qmgr;
    add_required_mainnet_entries(qmgr, 0x60);   // mining_height 0: undatable
    vendor::QuorumTail tail;
    tail.newQuorums.push_back(real_commitment(kLlmq50_60, h256(0x71), 0, 0x71));
    qmgr.apply(tail);                            // mining_height stays 0

    LlmqTypeReconciler r(LlmqNetwork::Mainnet);
    for (uint32_t h = kT0; h <= kT0 + 300u; ++h) r.observe(h, qmgr);

    // SEMANTICS SHARPENED for issue #1164 (mode 3): while the undatable entry
    // is inside the retention window it is served but the [QC-MINED] scanner
    // has never dated ANY commitment of its type — delivery is not mining, so
    // the honest verdict is now Unevaluated with the reason named, NOT the
    // alarm. (The old in-retention alarm survived every RESTART indefinitely
    // in production, because first-seen dating is in-memory — see the
    // RestartCannotResurrect test below.)
    {
        auto f = finding_for(r.reconcile(), 1);
        ASSERT_TRUE(f.has_value());
        EXPECT_EQ(f->verdict, LlmqTypeVerdict::Unevaluated);
        EXPECT_STREQ(f->pending_reason, "delivered-but-never-scanner-dated");
        EXPECT_TRUE(r.defects().empty()) << r.format_defects();
    }

    // ...but past first-sight + retention the entry ages out: sightings stop.
    for (uint32_t h = kT0 + 301u; h <= kT0 + 601u; ++h) r.observe(h, qmgr);
    auto f = finding_for(r.reconcile(), 1);
    ASSERT_TRUE(f.has_value());
    EXPECT_EQ(f->verdict, LlmqTypeVerdict::StaleSightings);
    EXPECT_STREQ(llmq_type_verdict_name(f->verdict),
                 "stale-sightings-aged-out");
    EXPECT_FALSE(is_llmq_type_defect(f->verdict));
    EXPECT_TRUE(r.defects().empty())
        << "the alarm must CLEAR once every sighting aged out: "
        << r.format_defects();
    // The measured self-refresh signature — sightings == observations — is
    // structurally impossible now: sightings froze at first-sight+retention.
    EXPECT_LT(f->sightings, r.observations());
    EXPECT_EQ(f->sightings, 577u);              // kT0 .. kT0+576 inclusive
    EXPECT_EQ(f->last_height, kT0 + 576u);
}

TEST(DashLlmqTypeReconciler, RestartCannotResurrectAnUndatedEntryAlarm)
{
    // MODE 3 — the shape MEASURED on the hotel reserve node (issue #1164).
    // The reconciler is in-memory: a restart empties first-seen dating, so a
    // never-mined entry that mnlistdiff keeps delivering was re-dated fresh
    // by every NEW process and rang MINED-BUT-NOT-REQUIRED for a whole
    // retention window after EVERY restart — the alarm survived restarts
    // indefinitely while a full-span chain sweep showed ZERO commitments of
    // the type on-chain. With the scanner-confirmation gate the indictment
    // needs at least one scanner-dated entry, which a never-mined type can
    // never produce — in the first process, or any process after it.
    constexpr uint32_t kT0 = 1'950'000u;
    QuorumManager qmgr;
    add_required_mainnet_entries(qmgr, 0x60);   // undated (mining_height 0)
    vendor::QuorumTail tail;
    tail.newQuorums.push_back(real_commitment(kLlmq50_60, h256(0x91), 0, 0x91));
    qmgr.apply(tail);                            // type 1, never scanner-dated

    // Process 1: a full retention window of observation. No defect, and the
    // reason is named rather than silently fine.
    {
        LlmqTypeReconciler r(LlmqNetwork::Mainnet);
        for (uint32_t h = kT0; h <= kT0 + 600u; ++h) r.observe(h, qmgr);
        EXPECT_TRUE(r.defects().empty()) << r.format_defects();
    }

    // "Restart": a fresh reconciler over the SAME still-served entry, at the
    // heights where the next process would resume. Pre-fix this rang for
    // another 576 blocks; now it must stay silent, with the same named
    // reason, for as many restarts as ever happen.
    LlmqTypeReconciler r2(LlmqNetwork::Mainnet);
    for (uint32_t h = kT0 + 601u; h <= kT0 + 1'200u; ++h) r2.observe(h, qmgr);
    EXPECT_TRUE(r2.defects().empty())
        << "restart resurrected the undated-entry alarm: "
        << r2.format_defects();
    auto f = finding_for(r2.reconcile(), 1);
    ASSERT_TRUE(f.has_value());
    EXPECT_EQ(f->verdict, LlmqTypeVerdict::Unevaluated);
    EXPECT_STREQ(f->pending_reason, "delivered-but-never-scanner-dated");
}

TEST(DashLlmqTypeReconciler, GenuinelyMinedUnexpectedTypeStillAlarms)
{
    // THE BACKSTOP MUST KEEP WORKING — a fix that silences the stale echo by
    // silencing the alarm would trade a false positive for a false negative,
    // and the false negative is worse (bad-qc-missing loses blocks). A type
    // upstream genuinely mines keeps producing NEW quorums with current
    // mined heights; those entries are always inside retention, sightings
    // ride the tip, and the indictment must stand. Same zero-width
    // discipline applies first: no verdict from a one-tip pileup.
    constexpr uint32_t kT0 = 1'950'000u;
    QuorumManager qmgr;
    add_required_mainnet_entries(qmgr, 0x20);
    const LlmqParamsView fake7{7, 50, 40, 30, 24, 10, 18, 24, false};

    LlmqTypeReconciler r(LlmqNetwork::Mainnet);
    // A template-build pileup at one tip: enough CALLS, zero-width WINDOW.
    {
        vendor::QuorumTail tail;
        tail.newQuorums.push_back(real_commitment(fake7, h256(0x80), 0, 0x80));
        qmgr.apply(tail);
        qmgr.find_mutable(7, h256(0x80))->mining_height = kT0;
    }
    for (uint32_t i = 0; i < LlmqTypeReconciler::kMinObservations + 4u; ++i)
        r.observe(kT0, qmgr);
    EXPECT_TRUE(r.defects().empty()) << r.format_defects();

    // The chain keeps mining the type: a new quorum every 24 blocks, each
    // stamped with ITS OWN mined height.
    uint8_t fill = 0x81;
    for (uint32_t h = kT0 + 1u; h <= kT0 + 600u; ++h) {
        if (h % 24u == 0u) {
            vendor::QuorumTail tail;
            tail.newQuorums.push_back(
                real_commitment(fake7, h256(fill), 0, fill));
            qmgr.apply(tail);
            qmgr.find_mutable(7, h256(fill))->mining_height = h;
            ++fill;
        }
        r.observe(h, qmgr);
    }

    auto d = r.defects();
    ASSERT_EQ(d.size(), 1u);
    EXPECT_EQ(d[0].llmq_type, 7);
    EXPECT_EQ(d[0].verdict, LlmqTypeVerdict::UnexpectedType);
    const auto said = r.format_defects();
    EXPECT_NE(said.find("type=7"), std::string::npos) << said;
    EXPECT_NE(said.find("MINED-BUT-NOT-REQUIRED"), std::string::npos) << said;
}

// ── qc_pose_pass_provably_noop: the interim PoSe serve predicate ───────────
//
// dashd PoSe-punishes every member a NON-NULL in-block commitment marks
// invalid (specialtxman.cpp:159-174 HandleQuorumCommitment ->
// PoSePunish(CalcPenalty(66))), mutating the SAME block's merkleRootMNList
// when a punishment crosses the ban threshold; null commitments are exempt
// (specialtxman.cpp:427-432 IsNull() guard). c2pool folds no PoSe pass, so a
// real commitment is servable ONLY when that pass is provably a no-op: every
// LISTED member (index < member_count of the deterministic member list dashd
// indexes validMembers with) marked valid. These KATs pin the predicate's
// fail-closed edges.

TEST(DashQcPoseNoopPredicate, NullCommitmentIsExemptByConstruction)
{
    // The arm-synthesized null (all-false bitsets, zero crypto) takes the
    // IsNull() exempt path in every verifier — provably a no-op regardless
    // of member count, even an unknowable one (0).
    const auto null_c = build_null_commitment(kLlmq50_60, h256(0x31), 0);
    EXPECT_TRUE(qc_commitment_is_null(null_c));
    EXPECT_TRUE(qc_pose_pass_provably_noop(null_c, 0));
    EXPECT_TRUE(qc_pose_pass_provably_noop(null_c, 50));
}

TEST(DashQcPoseNoopPredicate, AllListedMembersValidIsProvableNoop)
{
    // The common case: a full quorum, every listed member valid — the PoSe
    // punish loop touches nothing, serving stays unblocked.
    const auto c = real_commitment(kLlmq50_60, h256(0x32), 0, 0x01);
    EXPECT_FALSE(qc_commitment_is_null(c));
    EXPECT_TRUE(qc_pose_pass_provably_noop(c, 50));
}

TEST(DashQcPoseNoopPredicate, PaddingBitsBeyondMemberCountProveNothingBad)
{
    // A NON-FULL quorum: 40 members on a size-50 type. dashcore's own Verify
    // requires bits at index >= members.size() unset, so a fully-valid
    // commitment there has false bits [40,50) — DKG padding, not punished
    // members. The predicate must NOT read padding as a punishment (that
    // would refuse every non-full quorum forever).
    auto c = real_commitment(kLlmq50_60, h256(0x33), 0, 0x02);
    for (size_t i = 40; i < 50; ++i) {
        c.signers[i]      = false;
        c.validMembers[i] = false;
    }
    EXPECT_TRUE(qc_pose_pass_provably_noop(c, 40));
    // The SAME bitset judged against a 50-member list reads indices [40,50)
    // as punished listed members — refused. member_count is load-bearing.
    EXPECT_FALSE(qc_pose_pass_provably_noop(c, 50));
}

TEST(DashQcPoseNoopPredicate, OnePunishedListedMemberRefuses)
{
    // THE LANDMINE INPUT: a verified real commitment carrying
    // !validMembers[i] for a listed member — dashd would PoSePunish
    // members[7] in the block's own MN list. Never provably a no-op.
    auto c = real_commitment(kLlmq50_60, h256(0x34), 0, 0x03);
    c.validMembers[7] = false;
    EXPECT_FALSE(qc_pose_pass_provably_noop(c, 50));
    // Punished member visible even at the smallest count that lists it.
    EXPECT_FALSE(qc_pose_pass_provably_noop(c, 8));
    // A count that does NOT list index 7 cannot see a punishment there.
    EXPECT_TRUE(qc_pose_pass_provably_noop(c, 7));
}

TEST(DashQcPoseNoopPredicate, UnprovableMemberCountsFailClosed)
{
    // No member list (count 0) or a count exceeding the bitset: the punish
    // loop cannot be modeled, so the answer is REFUSE, never a guess.
    const auto c = real_commitment(kLlmq50_60, h256(0x35), 0, 0x04);
    EXPECT_FALSE(qc_pose_pass_provably_noop(c, 0));
    EXPECT_FALSE(qc_pose_pass_provably_noop(c, 51));
}
