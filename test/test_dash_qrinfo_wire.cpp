// SPDX-License-Identifier: AGPL-3.0-or-later
//
// DIP-0024 rotated quorums: the WIRE-TO-READY gate, and the "every outcome
// names itself" gate.
//
// WHY THIS FILE EXISTS
// --------------------
// Three live soaks cached 32 type-5 (LLMQ_60_75) qfcommits and produced ZERO
// "[QC-MEMBERS] READY type=5". The decode, the DIP-4 authentication and the
// quarter-rotation member computation were all correct and all covered — by
// test_dash_qrinfo.cpp and test_dash_rotated_quorum_members.cpp, which hand a
// DECODED CQuorumRotationInfo straight to QuorumMemberSource::on_qrinfo().
//
// That is exactly the seam the defect lived in. `message_qrinfo` was never
// added to the p2p::Handler type list, so MessageHandler::parse() threw
// std::out_of_range on every reply and CoinClient::handle dropped it on the
// "unhandled command" path — at DEBUG level. ADD_P2P_HANDLER(qrinfo) existed,
// fully written, with a registered consumer, and could never run. Every
// existing test passed, because every existing test started AFTER the drop.
//
// So the tests below start at the RAW BYTES, the way a peer delivers them:
//
//     602'189 fixture bytes
//        -> RawMessage{"qrinfo", ...}
//        -> p2p::Handler::parse()          <- WHERE IT BROKE
//        -> message_qrinfo::m_raw
//        -> decode_quorum_rotation_info()
//        -> QuorumMemberSource::on_qrinfo()
//        -> lookup() serves the rotated quorum
//
// VERIFIED TO FAIL ON THE PRE-FIX TREE: with message_qrinfo removed from the
// p2p::Handler list in p2p_messages.hpp (i.e. master as of this branch point),
// HandlerRegistryDispatchesQrInfo and WireToReadyEndToEnd both RED with
// "MessageHandler not contain qrinfo" thrown out of parse(). A happy-path test
// that began at on_qrinfo() would have stayed GREEN through the whole outage —
// and did.
//
// The second half of the file gates the OTHER half of the defect: the rotated
// lane could fail without saying why. Every refusal must now name itself, and
// an unanswered getqrinfo must TIME OUT by name rather than wedge its cycle
// forever.

#include <gtest/gtest.h>

#include <impl/dash/coin/p2p_messages.hpp>
#include <impl/dash/coin/quorum_member_source.hpp>
#include <impl/dash/coin/vendor/quorum_rotation_info.hpp>
#include <core/message.hpp>
#include <core/pack.hpp>

#include "data/dash_rotated_quorum_members_kat.hpp"

#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

using dash::coin::LlmqNetwork;
using dash::coin::QuorumMemberSource;
using dash::coin::RotatedOutcome;
using dash::coin::rotated_outcome_name;
using dash::coin::vendor::CQuorumRotationInfo;
using dash::coin::vendor::CSimplifiedMNListDiff;
using dash::coin::vendor::decode_quorum_rotation_info;

namespace {

constexpr uint32_t kCycleBase = 1520064;   // llmq_60_75 cycle base
constexpr uint8_t  kType      = 5;         // LLMQ_60_75 (rotated)
constexpr size_t   kNQuorums  = 32;        // signingActiveQuorumCount
constexpr size_t   kFixtureBytes = 602189;

std::vector<unsigned char> read_fixture()
{
    const std::string path =
        std::string(DASH_FIXTURE_DIR) + "/dash_testnet_qrinfo_1520064.bin";
    std::ifstream f(path, std::ios::binary);
    EXPECT_TRUE(f.good()) << "cannot open fixture: " << path;
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(f),
                                      std::istreambuf_iterator<char>());
}

/// Deliver `payload` to the coin p2p Handler exactly as the socket read loop
/// does: as a RawMessage carrying only a command string and opaque bytes.
/// Throws whatever parse() throws — which is the point.
dash::coin::p2p::Handler::result_t deliver(const std::string& command,
                                           const std::vector<unsigned char>& payload)
{
    auto raw = std::make_unique<RawMessage>(command, PackStream(payload));
    dash::coin::p2p::Handler handler;
    return handler.parse(raw);
}

// ⚠ These two accessors use std::visit + `requires`, NOT std::get_if<T>.
// std::get_if<message_qrinfo> against a variant that does not list that
// alternative is a COMPILE error — which would turn a removed registry entry
// into a build break instead of a legible RED test. Visiting keeps this file
// compilable on a tree WITHOUT qrinfo registered, so the failure lands where
// it belongs: parse() throwing "MessageHandler not contain qrinfo".

/// The command string of whatever alternative the variant now holds.
std::string parsed_command(const dash::coin::p2p::Handler::result_t& r)
{
    return std::visit([](const auto& m) {
        return m ? m->m_command : std::string{};
    }, r);
}

/// The opaque payload of a message that carries one (qrinfo does).
std::optional<std::vector<unsigned char>>
parsed_raw(const dash::coin::p2p::Handler::result_t& r)
{
    return std::visit([](const auto& m)
        -> std::optional<std::vector<unsigned char>> {
        if constexpr (requires { m->m_raw; }) {
            if (m) return m->m_raw;
        }
        return std::nullopt;
    }, r);
}

/// The block-request hash of a message that carries one (getqrinfo does).
std::optional<uint256>
parsed_block_request_hash(const dash::coin::p2p::Handler::result_t& r)
{
    return std::visit([](const auto& m) -> std::optional<uint256> {
        if constexpr (requires { m->m_block_request_hash; }) {
            if (m) return m->m_block_request_hash;
        }
        return std::nullopt;
    }, r);
}

uint256 slot_hash(uint32_t qi)
{
    uint256 h;
    std::string s(64, '0');
    s[0] = 'e'; s[1] = 'e';
    s[62] = "0123456789abcdef"[(qi >> 4) & 0xf];
    s[63] = "0123456789abcdef"[qi & 0xf];
    h.SetHex(s);
    return h;
}

/// A QuorumMemberSource wired against the real fixture's headers, with an
/// injectable clock so the timeout path is testable without sleeping.
struct SourceHarness {
    CQuorumRotationInfo         info;
    std::map<uint256, uint256>  roots;      // blockHash -> header merkle root
    std::map<uint32_t, uint256> by_height;
    int      sends{0};
    int64_t  now{1000};

    void load()
    {
        auto bytes = read_fixture();
        ASSERT_EQ(bytes.size(), kFixtureBytes) << "fixture length regression";
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
        by_height[kCycleBase] = cycle;                 // quorumIndex 0
        for (uint32_t qi = 1; qi < kNQuorums; ++qi)
            by_height[kCycleBase + qi] = slot_hash(qi);
    }

    QuorumMemberSource make(bool with_send_seam = true)
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
        src.set_clock([this] { return now; });
        if (with_send_seam) {
            src.set_send_getqrinfo(
                [this](const std::vector<uint256>&, const uint256&, bool) { ++sends; });
        }
        return src;
    }

    uint256 cycle_hash() const
    {
        uint256 c;
        c.SetHex(dash::coin::testdata::kRot6075_QuorumHash);
        return c;
    }
};

} // namespace

// ═══ 1. THE REGISTRY GATE — the exact defect ═══════════════════════════════
//
// A message type absent from p2p::Handler is not merely unhandled, it is
// UNROUTABLE: parse() throws and the payload dies in a catch block. These two
// tests assert the qrinfo pair is routable at all, which is a property no
// decode-level test can see.

TEST(DashQrInfoWire, HandlerRegistryDispatchesQrInfo)
{
    auto bytes = read_fixture();
    dash::coin::p2p::Handler::result_t res;
    ASSERT_NO_THROW(res = deliver("qrinfo", bytes))
        << "qrinfo is missing from the p2p::Handler type list — every reply "
           "from dashd is dropped before ADD_P2P_HANDLER(qrinfo) can run, and "
           "the ONLY trace is a debug-level 'unhandled command' line";

    EXPECT_EQ(parsed_command(res), "qrinfo") << "parsed to the wrong message type";
    // The codec hands the payload through untouched; the decode is the
    // handler's job, deliberately (see p2p_messages.hpp).
    auto raw = parsed_raw(res);
    ASSERT_TRUE(raw.has_value());
    EXPECT_EQ(raw->size(), kFixtureBytes);
    EXPECT_EQ(*raw, bytes);
}

TEST(DashQrInfoWire, HandlerRegistryDispatchesGetQrInfo)
{
    // The inbound side has a handler too (we refuse to serve rotation info).
    // Absent from the registry it is equally dead, and a peer's getqrinfo
    // would be an unexplained drop rather than an explicit refusal.
    std::vector<uint256> bases;
    uint256 req;
    req.SetHex(dash::coin::testdata::kRot6075_QuorumHash);
    auto raw = dash::coin::p2p::message_getqrinfo::make_raw(bases, req, false);
    std::vector<unsigned char> payload(
        reinterpret_cast<unsigned char*>(raw->m_data.data()),
        reinterpret_cast<unsigned char*>(raw->m_data.data()) + raw->m_data.size());

    dash::coin::p2p::Handler::result_t res;
    ASSERT_NO_THROW(res = deliver("getqrinfo", payload));
    EXPECT_EQ(parsed_command(res), "getqrinfo");
    auto got = parsed_block_request_hash(res);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, req);
}

// An unregistered command still throws out_of_range — this pins that the drop
// path we hardened is the one that was actually swallowing qrinfo, and that
// the registry is a whitelist rather than a fallthrough.
TEST(DashQrInfoWire, AnUnregisteredCommandStillThrowsOutOfRange)
{
    EXPECT_THROW(deliver("qsendrecsigs", {}), std::out_of_range);
}

// ═══ 2. WIRE TO READY — the end-to-end property ════════════════════════════

TEST(DashQrInfoWire, WireToReadyEndToEnd)
{
    SourceHarness h;
    h.load();
    auto src = h.make();

    const uint256 cycle = h.cycle_hash();
    ASSERT_TRUE(src.request_rotated(kType, cycle));
    EXPECT_EQ(h.sends, 1);
    EXPECT_EQ(src.last_rotated_outcome(), RotatedOutcome::kRequestSent);

    // ── the reply comes back the way a peer actually delivers it ──
    auto bytes = read_fixture();
    dash::coin::p2p::Handler::result_t res;
    ASSERT_NO_THROW(res = deliver("qrinfo", bytes))
        << "the reply never reaches ADD_P2P_HANDLER(qrinfo) at all";
    auto raw = parsed_raw(res);
    ASSERT_TRUE(raw.has_value());

    // ── what ADD_P2P_HANDLER(qrinfo) then does ──
    CQuorumRotationInfo info;
    ASSERT_TRUE(decode_quorum_rotation_info(*raw, info));
    ASSERT_TRUE(src.on_qrinfo(info).has_value());

    // THE PROPERTY: a rotated type reaches member-set-ready given a valid
    // qrinfo reply. In the soaks this never happened even once.
    EXPECT_EQ(src.last_rotated_outcome(), RotatedOutcome::kReady);
    EXPECT_EQ(src.rotated_pending_count(), 0u);
    EXPECT_EQ(src.ready_count(), kNQuorums);
    auto members = src.lookup(kType, cycle);
    ASSERT_TRUE(members.has_value());
    EXPECT_EQ(members->size(), 60u);
    for (uint32_t qi = 1; qi < kNQuorums; ++qi)
        EXPECT_TRUE(src.lookup(kType, slot_hash(qi)).has_value()) << "slot " << qi;
}

// ═══ 3. EVERY OUTCOME NAMES ITSELF ═════════════════════════════════════════
//
// The other half of the defect: the rotated lane could not report why it
// failed. These gate that each distinct failure is DISTINGUISHABLE, which is
// what "impossible to look at a log and not know which happened" reduces to.

TEST(DashQrInfoWire, EveryRotatedOutcomeHasAUniqueName)
{
    const RotatedOutcome all[] = {
        RotatedOutcome::kNone,
        RotatedOutcome::kRequestSent,
        RotatedOutcome::kRequestDeduped,
        RotatedOutcome::kRequestAlreadyReady,
        RotatedOutcome::kRefusedUnknownType,
        RotatedOutcome::kRefusedNotRotated,
        RotatedOutcome::kRefusedNoSendSeam,
        RotatedOutcome::kRefusedIntervalZero,
        RotatedOutcome::kRefusedBaseHeaderMissing,
        RotatedOutcome::kRefusedIndexOutOfRange,
        RotatedOutcome::kRefusedCycleHeaderGap,
        RotatedOutcome::kRefusedBaseUnaligned,
        RotatedOutcome::kRefusedCycleSpanTooShallow,
        RotatedOutcome::kRefusedPreV20,
        RotatedOutcome::kReplyNoCbTx,
        RotatedOutcome::kReplyUnsolicited,
        RotatedOutcome::kReplyTypeVanished,
        RotatedOutcome::kReplyNotFullList,
        RotatedOutcome::kReplyAuthFailed,
        RotatedOutcome::kComputeAmbiguous,
        RotatedOutcome::kNoSlotHeaders,
        RotatedOutcome::kReady,
        RotatedOutcome::kTimedOut,
    };
    std::set<std::string> seen;
    for (RotatedOutcome o : all) {
        const std::string n = rotated_outcome_name(o);
        EXPECT_NE(n, "unnamed") << "a rotated outcome with no name is the bug "
                                   "this whole file exists to prevent";
        EXPECT_FALSE(n.empty());
        EXPECT_TRUE(seen.insert(n).second) << "duplicate outcome name: " << n;
    }
}

// The send-seam-not-wired refusal. In production this is the difference
// between "the peer is broken" and "we never asked" — the two states the
// soaks could not tell apart.
TEST(DashQrInfoWire, MissingSendSeamNamesItself)
{
    SourceHarness h;
    h.load();
    auto src = h.make(/*with_send_seam=*/false);
    EXPECT_FALSE(src.request_rotated(kType, h.cycle_hash()));
    EXPECT_EQ(src.last_rotated_outcome(), RotatedOutcome::kRefusedNoSendSeam);
    EXPECT_EQ(h.sends, 0);
}

TEST(DashQrInfoWire, NonRotatedTypeRefusalNamesItself)
{
    SourceHarness h;
    h.load();
    auto src = h.make();
    EXPECT_FALSE(src.request_rotated(/*llmq_50_60=*/1, h.cycle_hash()));
    EXPECT_EQ(src.last_rotated_outcome(), RotatedOutcome::kRefusedNotRotated);
}

TEST(DashQrInfoWire, UnknownTypeRefusalNamesItself)
{
    SourceHarness h;
    h.load();
    auto src = h.make();
    EXPECT_FALSE(src.request_rotated(/*not an enabled llmq type=*/200, h.cycle_hash()));
    EXPECT_EQ(src.last_rotated_outcome(), RotatedOutcome::kRefusedUnknownType);
}

TEST(DashQrInfoWire, UnalignedCycleBaseRefusalNamesItself)
{
    SourceHarness h;
    h.load();
    // Point the height index at a base that is NOT on the 288 boundary.
    uint256 unaligned = slot_hash(7);        // sits at kCycleBase + 7
    auto src = h.make();
    EXPECT_FALSE(src.request_rotated(kType, unaligned));
    EXPECT_EQ(src.last_rotated_outcome(), RotatedOutcome::kRefusedBaseUnaligned);
}

TEST(DashQrInfoWire, UnheldBaseHeaderRefusalNamesItself)
{
    SourceHarness h;
    h.load();
    auto src = h.make();
    uint256 stranger;
    stranger.SetHex(std::string(63, '0') + "1");
    EXPECT_FALSE(src.request_rotated(kType, stranger));
    EXPECT_EQ(src.last_rotated_outcome(), RotatedOutcome::kRefusedBaseHeaderMissing);
}

TEST(DashQrInfoWire, UnsolicitedReplyNamesItself)
{
    SourceHarness h;
    h.load();
    auto src = h.make();                 // nothing requested
    EXPECT_FALSE(src.on_qrinfo(h.info).has_value());
    EXPECT_EQ(src.last_rotated_outcome(), RotatedOutcome::kReplyUnsolicited);
}

TEST(DashQrInfoWire, AuthFailureNamesItself)
{
    SourceHarness h;
    h.load();
    auto src = h.make();
    ASSERT_TRUE(src.request_rotated(kType, h.cycle_hash()));

    CQuorumRotationInfo tampered = h.info;
    ASSERT_FALSE(tampered.mnListDiffAtHMinus2C.mnList.empty());
    tampered.mnListDiffAtHMinus2C.mnList[0].pubKeyOperator[0] ^= 0xff;

    EXPECT_FALSE(src.on_qrinfo(tampered).has_value());
    EXPECT_EQ(src.last_rotated_outcome(), RotatedOutcome::kReplyAuthFailed)
        << "a rejected reply must say WHY it was rejected, not just fail";
}

TEST(DashQrInfoWire, NonFullCycleDiffNamesItself)
{
    SourceHarness h;
    h.load();
    auto src = h.make();
    ASSERT_TRUE(src.request_rotated(kType, h.cycle_hash()));

    CQuorumRotationInfo tampered = h.info;
    tampered.mnListDiffAtHMinus2C.deletedMNs.push_back(
        tampered.mnListDiffH.blockHash);
    EXPECT_FALSE(src.on_qrinfo(tampered).has_value());
    EXPECT_EQ(src.last_rotated_outcome(), RotatedOutcome::kReplyNotFullList);
}

// ═══ 4. THE WEDGE — an unanswered request must expire, by name ═════════════
//
// This is the liveness half of the dropped-reply defect. One lost qrinfo left
// m_rotated_pending occupied forever; every later slot of that cycle then took
// the dedup branch and sent nothing. The cycle could never recover, and no log
// line said so. Both halves are gated here.

TEST(DashQrInfoWire, UnansweredRequestTimesOutWithANamedCause)
{
    SourceHarness h;
    h.load();
    auto src = h.make();

    ASSERT_TRUE(src.request_rotated(kType, h.cycle_hash()));
    ASSERT_EQ(src.rotated_pending_count(), 1u);

    // Just inside the window: still outstanding, nothing claimed.
    h.now += 119;
    EXPECT_EQ(src.expire_rotated_requests(), 0u);
    EXPECT_EQ(src.rotated_pending_count(), 1u);

    // Past it: the failure is named and the slot is freed.
    h.now += 2;
    EXPECT_EQ(src.expire_rotated_requests(), 1u);
    EXPECT_EQ(src.last_rotated_outcome(), RotatedOutcome::kTimedOut);
    EXPECT_EQ(src.rotated_pending_count(), 0u);
}

TEST(DashQrInfoWire, ATimedOutCycleCanBeReRequested)
{
    SourceHarness h;
    h.load();
    auto src = h.make();

    ASSERT_TRUE(src.request_rotated(kType, h.cycle_hash()));
    ASSERT_EQ(h.sends, 1);

    // Before expiry the dedup is correct and must hold.
    ASSERT_TRUE(src.request_rotated(kType, h.cycle_hash()));
    EXPECT_EQ(h.sends, 1);
    EXPECT_EQ(src.last_rotated_outcome(), RotatedOutcome::kRequestDeduped);

    h.now += 121;
    ASSERT_EQ(src.expire_rotated_requests(), 1u);

    // After expiry the cycle is live again — this is what stops ONE lost
    // reply from wedging a cycle permanently.
    ASSERT_TRUE(src.request_rotated(kType, h.cycle_hash()));
    EXPECT_EQ(h.sends, 2);
    EXPECT_EQ(src.last_rotated_outcome(), RotatedOutcome::kRequestSent);
}

// request() is the qfcommit kick, and the only heartbeat this class has. It
// must drive expiry, or the timeout above never fires in production.
TEST(DashQrInfoWire, RequestDrivesExpiry)
{
    SourceHarness h;
    h.load();
    auto src = h.make();

    ASSERT_TRUE(src.request_rotated(kType, h.cycle_hash()));
    ASSERT_EQ(src.rotated_pending_count(), 1u);

    h.now += 121;
    // A qfcommit for slot 3 arrives. Before the fix this would have deduped
    // against the wedged pending and sent nothing, forever.
    src.request(kType, slot_hash(3));
    EXPECT_EQ(src.rotated_pending_count(), 1u) << "expired, then re-requested";
    EXPECT_EQ(h.sends, 2);
    EXPECT_EQ(src.last_rotated_outcome(), RotatedOutcome::kRequestSent);
}

// A ready cycle must not be re-requested when a later slot's qfcommit lands.
TEST(DashQrInfoWire, AReadyCycleIssuesNoFurtherTraffic)
{
    SourceHarness h;
    h.load();
    auto src = h.make();

    ASSERT_TRUE(src.request_rotated(kType, h.cycle_hash()));
    ASSERT_TRUE(src.on_qrinfo(h.info).has_value());
    ASSERT_EQ(h.sends, 1);

    h.now += 100000;                       // long past any timeout
    src.request(kType, slot_hash(9));
    EXPECT_EQ(h.sends, 1) << "a served cycle must generate no getqrinfo";
}
