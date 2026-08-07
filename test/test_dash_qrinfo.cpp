// SPDX-License-Identifier: AGPL-3.0-or-later
//
// DIP-0024 rotated-quorum sourcing, items 1+2: the getqrinfo/qrinfo WIRE and
// the AUTHENTICATED decode. Real-vector gated.
//
// THE VECTOR
// ----------
// test/fixtures/dash_testnet_qrinfo_1520064.bin is a real 602'189-byte qrinfo
// captured read-only from a testnet dashd (protocol 70237) by sending exactly
// the request these tests reconstruct: empty baseBlockHashes, blockRequestHash
// = the llmq_60_75 cycle-base block 1520064, extraShare = false. Everything
// below is pinned against those bytes.
//
// WHAT THIS SUITE GATES
// ---------------------
//   * the decode consumes the payload EXACTLY (zero trailing bytes) — which is
//     what proves the nested-CSimplifiedMNListDiff reader is byte-correct,
//     since a single mis-sized field would desynchronise everything after it;
//   * the CQuorumSnapshot field order (mnSkipListMode FIRST — the one place
//     the wire disagrees with the upstream member-declaration order); a
//     mutation swapping it back RED-s the decode;
//   * cycle geometry: H = base-8 and the -C/-2C/-3C spacing at dkgInterval 288;
//   * the 32 mandatory rotated slots (llmq_60_75 signingActiveQuorumCount) come
//     back as lastCommitmentPerIndex with quorumIndex 0..31 IN ORDER;
//   * per-cycle-diff DIP-4 height BINDING: a peer answering with another
//     block's genuine snapshot, or with an INCREMENTAL diff, fails closed;
//   * the request bytes we emit are byte-identical to the request a real dashd
//     answered with this fixture.
//
// WHAT THIS SUITE DOES *NOT* ESTABLISH
// ------------------------------------
// Member ORDER. This suite gates the WIRE and the AUTHENTICATION only; what it
// proves about test/data/dash_rotated_quorum_members_kat.hpp is the NECESSARY
// CONDITION — every one of the 60 ground-truth members is present in each
// authenticated cycle SML with a byte-identical operator key, so the sourced
// inputs are sufficient. The ORDERING gate against that KAT lives in
// test_dash_rotated_quorum_members.cpp (same executable), which pins
// ComputeQuorumMembersByQuarterRotation index-by-index. Do not mistake the
// membership check below for the ordering gate.
//
// Merkle-proof leg note: leg (b) of authenticate_historical_snapshot (cbTx
// proven into the PoW-VERIFIED header) is the same shared function the
// non-rotated KATs already gate, and needs the four cycle block headers, which
// this fixture does not carry. These tests therefore supply the header root
// from each diff's own proof and gate the legs that are NEW here: the height
// binding, the full-snapshot requirement, and the header-gap refusal.

#include <gtest/gtest.h>

#include <impl/dash/coin/quorum_member_source.hpp>
#include <impl/dash/coin/vendor/quorum_rotation_info.hpp>
#include <impl/dash/coin/vendor/quorum_tail.hpp>
#include <impl/dash/coin/p2p_messages.hpp>
#include <core/pack.hpp>

#include "data/dash_rotated_quorum_members_kat.hpp"

#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <vector>

using dash::coin::QuorumMemberSource;
using dash::coin::LlmqNetwork;
using dash::coin::vendor::CQuorumRotationInfo;
using dash::coin::vendor::CQuorumSnapshot;
using dash::coin::vendor::CSimplifiedMNListDiff;
using dash::coin::vendor::decode_quorum_rotation_info;

namespace {

constexpr size_t kFixtureBytes   = 602189;
constexpr uint32_t kCycleBaseH   = 1520064;   // llmq_60_75 cycle base
constexpr uint32_t kWorkDepth    = 8;
constexpr uint32_t kC            = 288;       // llmq_60_75 dkgInterval

std::vector<unsigned char> read_qrinfo_fixture()
{
    const std::string path =
        std::string(DASH_FIXTURE_DIR) + "/dash_testnet_qrinfo_1520064.bin";
    std::ifstream f(path, std::ios::binary);
    EXPECT_TRUE(f.good()) << "cannot open fixture: " << path;
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(f),
                                      std::istreambuf_iterator<char>());
}

uint32_t cbtx_height(const CSimplifiedMNListDiff& d)
{
    dash::coin::vendor::CCbTx cb;
    EXPECT_EQ(d.cbTx.type, 5);
    EXPECT_TRUE(dash::coin::vendor::parse_cbtx(d.cbTx.extra_payload, cb));
    return static_cast<uint32_t>(cb.nHeight);
}

// The header merkle root implied by a diff's OWN cbTx proof — see the header
// note on the merkle-proof leg.
uint256 implied_header_root(const CSimplifiedMNListDiff& d)
{
    std::vector<uint256>      matches;
    std::vector<unsigned int> idx;
    return d.cbTxMerkleTree.ExtractMatches(matches, idx);
}

} // namespace

// ── the decode consumes the real payload exactly ──────────────────────────

TEST(DashQrInfo, RealVectorDecodesWithZeroTrailingBytes)
{
    auto bytes = read_qrinfo_fixture();
    ASSERT_EQ(bytes.size(), kFixtureBytes) << "fixture length regression";

    CQuorumRotationInfo info;
    // decode_quorum_rotation_info returns false on ANY trailing byte, so a
    // true here IS the "consumed exactly" assertion.
    ASSERT_TRUE(decode_quorum_rotation_info(bytes, info));
    EXPECT_FALSE(info.extraShare);
    EXPECT_FALSE(info.quorumSnapshotAtHMinus4C.has_value());
    EXPECT_FALSE(info.mnListDiffAtHMinus4C.has_value());
}

TEST(DashQrInfo, RealVectorCycleGeometry)
{
    auto bytes = read_qrinfo_fixture();
    CQuorumRotationInfo info;
    ASSERT_TRUE(decode_quorum_rotation_info(bytes, info));

    // H is the WORK block of the cycle base, and the cycle diffs step by C.
    EXPECT_EQ(cbtx_height(info.mnListDiffH),          kCycleBaseH - kWorkDepth);
    EXPECT_EQ(cbtx_height(info.mnListDiffAtHMinusC),  kCycleBaseH - kWorkDepth - kC);
    EXPECT_EQ(cbtx_height(info.mnListDiffAtHMinus2C), kCycleBaseH - kWorkDepth - 2 * kC);
    EXPECT_EQ(cbtx_height(info.mnListDiffAtHMinus3C), kCycleBaseH - kWorkDepth - 3 * kC);

    // Every cycle diff is a FULL list. NOTE the difference from the getmnlistd
    // path: a qrinfo answered with EMPTY baseBlockHashes comes back based on
    // GENESIS, not on ZERO — so "full" is read off deletedMNs being empty, and
    // the real guarantee is the SML-root leg of the authentication.
    uint256 genesis;
    genesis.SetHex("00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c");
    for (const CSimplifiedMNListDiff* d :
         {&info.mnListDiffH, &info.mnListDiffAtHMinusC,
          &info.mnListDiffAtHMinus2C, &info.mnListDiffAtHMinus3C}) {
        EXPECT_FALSE(d->baseBlockHash.IsNull())
            << "regression guard: qrinfo full diffs are genesis-based, not ZERO-based";
        EXPECT_EQ(d->baseBlockHash, genesis);
        EXPECT_TRUE(d->deletedMNs.empty());
    }

    EXPECT_EQ(info.mnListDiffH.mnList.size(), 371u);
    EXPECT_EQ(info.mnListDiffAtHMinus3C.mnList.size(), 371u);
}

TEST(DashQrInfo, RealVectorSnapshotsPinned)
{
    auto bytes = read_qrinfo_fixture();
    CQuorumRotationInfo info;
    ASSERT_TRUE(decode_quorum_rotation_info(bytes, info));

    const CQuorumSnapshot* snaps[3] = {&info.quorumSnapshotAtHMinusC,
                                       &info.quorumSnapshotAtHMinus2C,
                                       &info.quorumSnapshotAtHMinus3C};
    const size_t expect_skip[3] = {523, 514, 564};
    for (size_t i = 0; i < 3; ++i) {
        EXPECT_EQ(snaps[i]->mnSkipListMode, CQuorumSnapshot::MODE_SKIPPING_ENTRIES) << i;
        EXPECT_EQ(snaps[i]->activeQuorumMembers.size(), 371u) << i;
        EXPECT_EQ(std::count(snaps[i]->activeQuorumMembers.begin(),
                             snaps[i]->activeQuorumMembers.end(), true), 85) << i;
        EXPECT_EQ(snaps[i]->mnSkipList.size(), expect_skip[i]) << i;
        EXPECT_TRUE(snaps[i]->sane()) << i;
    }
}

// The 32 mandatory rotated slots — the whole reason the h%288 in [42,50] window
// fails closed today. ORDER of the index sequence is asserted explicitly.
TEST(DashQrInfo, RealVectorCarriesThirtyTwoRotatedSlotsInIndexOrder)
{
    auto bytes = read_qrinfo_fixture();
    CQuorumRotationInfo info;
    ASSERT_TRUE(decode_quorum_rotation_info(bytes, info));

    ASSERT_EQ(info.lastCommitmentPerIndex.size(), 32u);
    for (size_t i = 0; i < info.lastCommitmentPerIndex.size(); ++i) {
        const auto& c = info.lastCommitmentPerIndex[i];
        EXPECT_EQ(c.llmqType, 5) << "slot " << i;
        EXPECT_EQ(c.quorumIndex, static_cast<uint16_t>(i))
            << "lastCommitmentPerIndex must be in quorumIndex order";
        // The BITSET is quorum-size wide (60) for every slot; the number of
        // members actually valid is NOT uniformly 60 in real data (slot 18 in
        // this capture carries 59), it only has to clear llmq_60_75 minSize=50.
        EXPECT_EQ(c.validMembers.size(), 60u) << "slot " << i;
        EXPECT_EQ(c.signers.size(), 60u) << "slot " << i;
        EXPECT_GE(c.CountValidMembers(), 50) << "slot " << i;
    }
}

// ── the nested-diff tail is re-materialised byte-exactly ──────────────────

TEST(DashQrInfo, NestedDiffQuorumTailRoundTripsThroughTheOpaqueField)
{
    auto bytes = read_qrinfo_fixture();
    CQuorumRotationInfo info;
    ASSERT_TRUE(decode_quorum_rotation_info(bytes, info));

    // Every existing consumer reads the OPAQUE quorum_tail. A nested diff must
    // therefore behave exactly like a standalone one.
    const CSimplifiedMNListDiff* diffs[5] = {
        &info.mnListDiffTip, &info.mnListDiffH, &info.mnListDiffAtHMinusC,
        &info.mnListDiffAtHMinus2C, &info.mnListDiffAtHMinus3C};
    for (size_t i = 0; i < 5; ++i) {
        EXPECT_FALSE(diffs[i]->quorum_tail.empty()) << "diff " << i;
        dash::coin::vendor::QuorumTail tail;
        ASSERT_TRUE(dash::coin::vendor::parse_quorum_tail(diffs[i]->quorum_tail, tail))
            << "re-materialised tail must parse with the EXISTING parser, diff " << i;
        EXPECT_EQ(tail.newQuorums.size(), 109u) << "diff " << i;
    }
}

// ── request bytes match what a real dashd answered ────────────────────────

TEST(DashQrInfo, GetQrInfoRequestBytesMatchTheCapturedRequest)
{
    // The exact request the fixture was captured with: empty baseBlockHashes,
    // blockRequestHash = the llmq_60_75 cycle-base block, extraShare = false.
    uint256 req;
    req.SetHex(dash::coin::testdata::kRot6075_QuorumHash);

    ::PackStream out;
    std::vector<uint256> bases;
    bool extra = false;
    out << bases;
    out << req;
    out << extra;

    std::vector<unsigned char> got(
        reinterpret_cast<const unsigned char*>(out.data()),
        reinterpret_cast<const unsigned char*>(out.data()) + out.cursor_size());

    // compactsize(0) | 32-byte hash in internal (LE) order | 0x00
    std::vector<unsigned char> want;
    want.push_back(0x00);
    want.insert(want.end(), req.data(), req.data() + 32);
    want.push_back(0x00);

    EXPECT_EQ(got, want);
    EXPECT_EQ(got.size(), 34u);
}

// ── mutations: each must RED the decode ───────────────────────────────────

// THE field-order mutation. Re-encode the first snapshot bitset-first (the
// order the upstream member declaration suggests) and confirm the decode
// refuses — this is what makes the "mode first" pin a gate rather than a
// comment.
TEST(DashQrInfo, MutationSnapshotFieldOrderSwappedIsRejected)
{
    auto bytes = read_qrinfo_fixture();
    CQuorumRotationInfo control;
    ASSERT_TRUE(decode_quorum_rotation_info(bytes, control));

    // Real head: [int32 mode][compactsize nbits][47 bitset bytes]...
    // 371 bits -> compactsize is 3 bytes (0xfd 0x73 0x01), bitset is 47 bytes.
    const size_t mode_len = 4, cs_len = 3, bits_len = 47;
    ASSERT_GT(bytes.size(), mode_len + cs_len + bits_len);

    std::vector<unsigned char> swapped;
    // bitset first ...
    swapped.insert(swapped.end(), bytes.begin() + mode_len,
                   bytes.begin() + mode_len + cs_len + bits_len);
    // ... then the mode ...
    swapped.insert(swapped.end(), bytes.begin(), bytes.begin() + mode_len);
    // ... then the untouched remainder.
    swapped.insert(swapped.end(), bytes.begin() + mode_len + cs_len + bits_len,
                   bytes.end());
    ASSERT_EQ(swapped.size(), bytes.size());
    ASSERT_NE(swapped, bytes);

    CQuorumRotationInfo info;
    EXPECT_FALSE(decode_quorum_rotation_info(swapped, info))
        << "bitset-first snapshot ordering must NOT decode";
}

TEST(DashQrInfo, MutationTrailingByteIsRejected)
{
    auto bytes = read_qrinfo_fixture();
    bytes.push_back(0x00);
    CQuorumRotationInfo info;
    EXPECT_FALSE(decode_quorum_rotation_info(bytes, info))
        << "a peer must not be able to smuggle unread bytes past the decode";
}

TEST(DashQrInfo, MutationTruncatedPayloadIsRejected)
{
    auto bytes = read_qrinfo_fixture();
    bytes.resize(bytes.size() - 1);
    CQuorumRotationInfo info;
    EXPECT_FALSE(decode_quorum_rotation_info(bytes, info));
}

// A corrupted LENGTH desynchronises the stream and must be refused. (Note the
// honest limit of a wire codec: corrupting an OPAQUE payload byte — a BLS key
// or signature — changes no length and is NOT detectable here by design. That
// class of tampering is what the DIP-4 authentication below catches, and the
// OnQrInfoRejectsTamperedMemberKey test is the gate for it.)
TEST(DashQrInfo, MutationCorruptedLengthPrefixIsRejected)
{
    auto bytes = read_qrinfo_fixture();
    // Snapshot 1 head is [int32 mode][compactsize 0xfd 0x73 0x01][47 bytes].
    ASSERT_EQ(bytes[4], 0xfd);
    bytes[5] ^= 0x40;               // 371 bits -> a different, wrong width
    CQuorumRotationInfo info;
    EXPECT_FALSE(decode_quorum_rotation_info(bytes, info));
}

// ── QuorumMemberSource: authenticated consumption + fail-closed ───────────

namespace {

struct Harness {
    CQuorumRotationInfo info;
    std::map<uint256, uint256> roots;     // blockHash -> header merkle root
    std::vector<uint256> sent_bases;
    uint256 sent_request;
    int     sends{0};

    QuorumMemberSource make(bool with_headers = true)
    {
        QuorumMemberSource src(
            LlmqNetwork::Testnet,
            /*hash_at_height=*/[](uint32_t) -> std::optional<uint256> { return std::nullopt; },
            /*height_of_hash=*/[](const uint256&) -> std::optional<uint32_t> {
                return kCycleBaseH;
            },
            /*merkle_root_of_hash=*/[this, with_headers](const uint256& h)
                -> std::optional<uint256> {
                if (!with_headers) return std::nullopt;
                auto it = roots.find(h);
                if (it == roots.end()) return std::nullopt;
                return it->second;
            },
            /*send=*/[](const uint256&, const uint256&) {});
        src.set_send_getqrinfo([this](const std::vector<uint256>& b,
                                      const uint256& r, bool) {
            sent_bases = b;
            sent_request = r;
            ++sends;
        });
        return src;
    }

    void load()
    {
        auto bytes = read_qrinfo_fixture();
        ASSERT_TRUE(decode_quorum_rotation_info(bytes, info));
        for (const CSimplifiedMNListDiff* d :
             {&info.mnListDiffH, &info.mnListDiffAtHMinusC,
              &info.mnListDiffAtHMinus2C, &info.mnListDiffAtHMinus3C}) {
            roots[d->blockHash] = implied_header_root(*d);
        }
    }
};

} // namespace

// ── #108 QC-PREFETCH: ask early, but never before the slot headers exist ────
//
// The prefetch asks for a DKG cycle's member sets at the cycle boundary rather
// than at the first qfcommit that needs them — 48 qc-plan-underivable declines
// on the daemonless soak were exactly that round trip, paid late.
//
// The ROTATED lane must NOT be asked at the boundary. A rotated reply keys one
// member set per slot on the header at cycleBase + quorumIndex; at the boundary
// only cycleBase exists, so 31 of 32 slots would be skipped for want of a
// header — and the one slot that publishes is index 0, whose key IS the cycle
// key, after which request_rotated short-circuits "already ready" forever.
// These KATs pin BOTH halves of that contract.
namespace {

struct PrefetchHarness {
    std::map<uint32_t, uint256> by_height;
    std::map<uint256, uint32_t> by_hash;
    std::vector<std::pair<uint256, uint256>> sends;      // non-rotated getmnlistd
    int qrinfo_sends{0};                                  // rotated getqrinfo

    std::unique_ptr<QuorumMemberSource> src;

    explicit PrefetchHarness(LlmqNetwork net = LlmqNetwork::Mainnet)
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
            [](const uint256&) -> std::optional<uint256> { return std::nullopt; },
            [this](const uint256& base, const uint256& tgt) {
                sends.emplace_back(base, tgt);
            });
        src->set_send_getqrinfo(
            [this](const std::vector<uint256>&, const uint256&, bool) {
                ++qrinfo_sends;
            });
    }

    void add(uint32_t h)
    {
        uint256 hash;
        hash.begin()[0] = static_cast<unsigned char>(h & 0xff);
        hash.begin()[1] = static_cast<unsigned char>((h >> 8) & 0xff);
        hash.begin()[2] = static_cast<unsigned char>((h >> 16) & 0xff);
        by_height[h] = hash;
        by_hash[hash] = h;
    }
    void add_range(uint32_t from, uint32_t to) { for (uint32_t h = from; h <= to; ++h) add(h); }
};

} // namespace

// A tip that CROSSES a cycle boundary asks for the non-rotated cycle
// immediately — before any qfcommit for that cycle can have arrived.
TEST(DashQcPrefetch, BoundaryTipAsksForTheNonRotatedCycle)
{
    PrefetchHarness h;
    // LLMQ_100_67 on mainnet: dkg_interval 24. Give the chain the cycle base
    // and its work block (base - 8).
    const uint32_t cycle_base = 2517600;      // 2517600 % 24 == 0
    h.add_range(cycle_base - 8, cycle_base);

    EXPECT_TRUE(h.sends.empty()) << "nothing asked before the tip advances";
    h.src->prefetch_cycle(cycle_base);
    EXPECT_FALSE(h.sends.empty())
        << "the boundary tip must have asked for at least one non-rotated cycle";
}

// The SAME cycle asked twice must not draw a second request — the memo and the
// pending/ready dedupe both have to hold.
TEST(DashQcPrefetch, RepeatedTipsInsideOneCycleDoNotReAsk)
{
    PrefetchHarness h;
    const uint32_t cycle_base = 2517600;
    h.add_range(cycle_base - 8, cycle_base + 5);

    h.src->prefetch_cycle(cycle_base);
    const size_t after_first = h.sends.size();
    ASSERT_GT(after_first, 0u);

    h.src->prefetch_cycle(cycle_base + 1);
    h.src->prefetch_cycle(cycle_base + 2);
    EXPECT_EQ(h.sends.size(), after_first)
        << "tips inside the same cycle must not re-walk the request path";
}

// THE REGRESSION GUARD. At the cycle boundary the rotated slot headers
// (cycleBase+1 .. cycleBase+31) do not exist yet. Asking then would publish
// 1/32 slots and latch the cycle ready forever, so the prefetch must stay
// silent on the rotated lane until the last slot header is in the chain.
TEST(DashQcPrefetch, RotatedCycleIsNotAskedBeforeItsSlotHeadersExist)
{
    PrefetchHarness h;
    // LLMQ_60_75 on mainnet: dkg_interval 288, 32 signing-active slots.
    // 2517408 = 288 * 8741, so it IS a cycle base. (An unaligned height would
    // make prefetch_cycle derive a DIFFERENT base whose header we never added,
    // and the test would pass for the wrong reason — it did, once.)
    const uint32_t cycle_base = 2517408;
    static_assert(2517408u % 288u == 0u, "cycle_base must be dkgInterval-aligned");
    h.add_range(cycle_base - 8, cycle_base);  // ONLY the base exists

    h.src->prefetch_cycle(cycle_base);
    EXPECT_EQ(h.qrinfo_sends, 0)
        << "a rotated cycle must not be requested while 31 of its 32 slot "
           "headers are missing — that publishes 1/32 and latches the cycle";

    // Once the whole slot range is in the chain the same cycle IS asked: the
    // skip must be a deferral, not a permanent memo burn.
    h.add_range(cycle_base + 1, cycle_base + 31);
    h.src->prefetch_cycle(cycle_base + 31);
    EXPECT_GT(h.qrinfo_sends, 0)
        << "after the slot headers arrive the rotated cycle must be prefetched";
}


// CATCH-UP GATE (Fable review, 2026-08-07): the tip callback fires once per
// headers MESSAGE and add_headers coalesces up to 2000 headers, so a cold
// start delivers tips ~2000 apart. Every such call would be a memo miss for
// every type and would ask for cycles whose mining windows are long past —
// measured shape ~215 requests / ~100 MB of full MN snapshots down the single
// ordered stream the cold-start path depends on. Prefetch is for the LIVE tip.
TEST(DashQcPrefetch, CatchUpTipJumpsAskNothing)
{
    PrefetchHarness h;
    const uint32_t base = 2517600;                 // 2517600 % 24 == 0
    h.add_range(base - 8, base + 4100);            // headers present either way

    h.src->prefetch_cycle(base);                   // first call primes the tip
    const size_t after_first = h.sends.size();
    ASSERT_GT(after_first, 0u) << "a live tip must still prefetch";

    // Two coalesced headers batches: +2000 each. Both must be refused.
    h.src->prefetch_cycle(base + 2000);
    h.src->prefetch_cycle(base + 4000);
    EXPECT_EQ(h.sends.size(), after_first)
        << "a tip jump larger than the biggest dkgInterval means we are still "
           "catching up — prefetch must stay silent";

    // Back to live cadence (+1): asking resumes.
    h.src->prefetch_cycle(base + 4001);
    EXPECT_GT(h.sends.size(), after_first)
        << "the gate must be a deferral for catch-up, not a permanent stop";
}

// A header gap must NOT burn the cycle's single prefetch: the lookup happens
// BEFORE the memo insert, so the next tip retries.
TEST(DashQcPrefetch, HeaderGapDoesNotBurnTheMemo)
{
    PrefetchHarness h;
    const uint32_t base = 2517600;
    // Deliberately withhold the cycle base header; give only the work block.
    h.add_range(base - 8, base - 1);

    h.src->prefetch_cycle(base);
    EXPECT_TRUE(h.sends.empty()) << "no header, nothing to ask with";

    // Header arrives; the SAME cycle must now be asked for.
    h.add(base);
    h.src->prefetch_cycle(base);
    EXPECT_FALSE(h.sends.empty())
        << "a header gap is a 'not yet', not a spent prefetch";
}


TEST(DashQrInfo, RequestRotatedEmitsAnEmptyBaseFullSnapshotRequest)
{
    Harness h;
    h.load();
    auto src = h.make();

    uint256 qh;
    qh.SetHex(dash::coin::testdata::kRot6075_QuorumHash);
    ASSERT_TRUE(src.request_rotated(dash::coin::testdata::kRot6075_LlmqType, qh));
    EXPECT_EQ(h.sends, 1);
    EXPECT_TRUE(h.sent_bases.empty())
        << "baseBlockHashes MUST be empty: only a FULL diff is self-authenticating";
    EXPECT_EQ(h.sent_request, qh);
    EXPECT_EQ(src.rotated_pending_count(), 1u);
}

TEST(DashQrInfo, RequestRotatedRefusesNonRotatedType)
{
    Harness h;
    h.load();
    auto src = h.make();
    uint256 qh;
    qh.SetHex(dash::coin::testdata::kRot6075_QuorumHash);
    EXPECT_FALSE(src.request_rotated(/*llmq_50_60=*/1, qh));
    EXPECT_EQ(h.sends, 0);
}

TEST(DashQrInfo, OnQrInfoAuthenticatesAllFourCycleDiffs)
{
    Harness h;
    h.load();
    auto src = h.make();

    uint256 qh;
    qh.SetHex(dash::coin::testdata::kRot6075_QuorumHash);
    ASSERT_TRUE(src.request_rotated(dash::coin::testdata::kRot6075_LlmqType, qh));

    auto got = src.on_qrinfo(h.info);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->cycle_base_height, kCycleBaseH);
    EXPECT_EQ(got->heights[0], kCycleBaseH - kWorkDepth);
    EXPECT_EQ(got->heights[1], kCycleBaseH - kWorkDepth - kC);
    EXPECT_EQ(got->heights[2], kCycleBaseH - kWorkDepth - 2 * kC);
    EXPECT_EQ(got->heights[3], kCycleBaseH - kWorkDepth - 3 * kC);
    for (int i = 0; i < 4; ++i)
        EXPECT_EQ(got->smls[i].mnList.size(), 371u) << "cycle SML " << i;
    EXPECT_EQ(got->last_commitment_per_index.size(), 32u);
    // consumed
    EXPECT_EQ(src.rotated_pending_count(), 0u);

    // NECESSARY CONDITION for the (not-yet-ported) ordering KAT: the
    // authenticated cycle SMLs contain every ground-truth member with a
    // byte-identical operator key. This is NOT the ordering assertion.
    const auto& kat = dash::coin::testdata::rotated_6075_members();
    ASSERT_EQ(kat.size(), dash::coin::testdata::kRot6075_MemberCount);
    for (int c = 0; c < 4; ++c) {
        std::map<std::string, std::string> by_pro;
        for (const auto& e : got->smls[c].mnList) {
            std::string key_hex;
            for (uint8_t b : e.pubKeyOperator) {
                static const char* hexd = "0123456789abcdef";
                key_hex.push_back(hexd[b >> 4]);
                key_hex.push_back(hexd[b & 0xf]);
            }
            by_pro[e.proRegTxHash.GetHex()] = key_hex;
        }
        for (const auto& m : kat) {
            auto it = by_pro.find(m.pro_tx_hash);
            ASSERT_NE(it, by_pro.end())
                << "KAT member missing from cycle SML " << c << ": " << m.pro_tx_hash;
            EXPECT_EQ(it->second, std::string(m.pub_key_operator))
                << "operator key mismatch for " << m.pro_tx_hash;
        }
    }
}

// The substitution attack the height binding exists to stop: a peer answers
// with genuine, internally-consistent snapshots — for the WRONG cycle.
TEST(DashQrInfo, OnQrInfoRejectsCycleDiffAtTheWrongHeight)
{
    Harness h;
    h.load();
    auto src = h.make();

    uint256 qh;
    qh.SetHex(dash::coin::testdata::kRot6075_QuorumHash);
    ASSERT_TRUE(src.request_rotated(dash::coin::testdata::kRot6075_LlmqType, qh));

    // Swap H-C and H-2C: both are genuine, authenticated-in-isolation
    // snapshots; only the position binding catches it.
    CQuorumRotationInfo tampered = h.info;
    std::swap(tampered.mnListDiffAtHMinusC, tampered.mnListDiffAtHMinus2C);

    EXPECT_FALSE(src.on_qrinfo(tampered).has_value())
        << "a genuine snapshot at the WRONG cycle position must fail closed";
    EXPECT_EQ(src.rotated_pending_count(), 0u) << "pending must be cleared, not leaked";
}

// THE serve-a-bad-member-set attack: a peer swaps in its own operator key.
// The SML root then no longer matches the block's committed
// cbTx.merkleRootMNList, so the whole reply must fail closed.
TEST(DashQrInfo, OnQrInfoRejectsTamperedMemberKey)
{
    Harness h;
    h.load();
    auto src = h.make();
    uint256 qh;
    qh.SetHex(dash::coin::testdata::kRot6075_QuorumHash);
    ASSERT_TRUE(src.request_rotated(dash::coin::testdata::kRot6075_LlmqType, qh));

    CQuorumRotationInfo tampered = h.info;
    ASSERT_FALSE(tampered.mnListDiffAtHMinus2C.mnList.empty());
    tampered.mnListDiffAtHMinus2C.mnList[0].pubKeyOperator[0] ^= 0xff;

    EXPECT_FALSE(src.on_qrinfo(tampered).has_value())
        << "a substituted operator key must not be believed";
}

// A diff that DELETES entries is not a full list, so applying it onto an empty
// list would authenticate something other than the list at that height.
TEST(DashQrInfo, OnQrInfoRejectsNonFullCycleDiff)
{
    Harness h;
    h.load();
    auto src = h.make();
    uint256 qh;
    qh.SetHex(dash::coin::testdata::kRot6075_QuorumHash);
    ASSERT_TRUE(src.request_rotated(dash::coin::testdata::kRot6075_LlmqType, qh));

    CQuorumRotationInfo tampered = h.info;
    tampered.mnListDiffAtHMinus2C.deletedMNs.push_back(
        tampered.mnListDiffH.blockHash);
    EXPECT_FALSE(src.on_qrinfo(tampered).has_value());
}

TEST(DashQrInfo, OnQrInfoFailsClosedWhenTheHeaderIsNotHeld)
{
    Harness h;
    h.load();
    auto src = h.make(/*with_headers=*/false);
    uint256 qh;
    qh.SetHex(dash::coin::testdata::kRot6075_QuorumHash);
    ASSERT_TRUE(src.request_rotated(dash::coin::testdata::kRot6075_LlmqType, qh));
    EXPECT_FALSE(src.on_qrinfo(h.info).has_value());
}

TEST(DashQrInfo, OnQrInfoDropsAnUnsolicitedReply)
{
    Harness h;
    h.load();
    auto src = h.make();
    // No request_rotated() call => nothing outstanding.
    EXPECT_FALSE(src.on_qrinfo(h.info).has_value());
}

// A cycle whose per-index BASE BLOCK HASHES are not held cannot be published:
// each rotated quorum is keyed by the hash of the block at cycleBase +
// quorumIndex, and this Harness deliberately holds no height index at all. The
// member set is computed, has nowhere to go, and the quorum stays null-serve.
// The POSITIVE path — a header index present, lookup() serving dashd's exact
// order — is gated in test_dash_rotated_quorum_members.cpp.
TEST(DashQrInfo, RotatedCycleWithoutAHeightIndexPublishesNothing)
{
    Harness h;
    h.load();
    auto src = h.make();   // hash_at_height() returns nullopt for every height
    uint256 qh;
    qh.SetHex(dash::coin::testdata::kRot6075_QuorumHash);
    ASSERT_TRUE(src.request_rotated(dash::coin::testdata::kRot6075_LlmqType, qh));
    ASSERT_TRUE(src.on_qrinfo(h.info).has_value());

    EXPECT_FALSE(src.lookup(dash::coin::testdata::kRot6075_LlmqType, qh).has_value())
        << "no held header for the slot base block => nothing to key on => "
           "null-serve";
    EXPECT_EQ(src.ready_count(), 0u);
}
