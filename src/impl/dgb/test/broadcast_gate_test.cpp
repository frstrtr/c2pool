// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// F3 tx-completeness broadcast gate + broadcast marking discipline — DGB KATs.
//
// READ FIRST — DGB REACHABILITY. DGB is NOT symmetric with btc/bch here, and
// these KATs are deliberately scoped to the path production actually takes:
//
//   main_dgb.cpp binds NO create/mint-share fn, so dgb::NodeImpl::broadcast_share
//   and notify_local_share have ZERO callers repo-wide — DGB never mints a local
//   share today (tracked as #884). The LIVE DGB path into send_shares is
//   readvertise_best_share() (ROOT-2 re-advert, fired on best-change and on a
//   timer), which re-pushes PEER-RECEIVED shares and deliberately bypasses the
//   broadcast de-dup set.
//
//   LIVE on DGB:      partition_backable()     (send_shares, via readvertise)
//                     readvertise_and_record() (readvertise_best_share)
//   PRE-WIRED, dead:  broadcast_and_mark()     (broadcast_share; #884)
//
// So the reward-critical assertions below drive readvertise_and_record, NOT
// broadcast_and_mark. A DGB test that proved the gate by broadcasting a locally
// minted share would be exercising a path production never takes — the exact
// shape of the LTC #873 miss, where both the test AND its negative control
// passed against an unreachable function.
//
// The pre-wired broadcast_and_mark coverage is kept but named
// DgbBroadcastMarkingPrewired_NotReachedToday so a reader cannot mistake it for
// live protection; it exists so the seam is correct on the day #884 lands.
//
// Rides the already-allowlisted dgb_share_test executable — no build.yml
// --target allowlist change, no NOT_BUILT sentinel risk.
// Consensus surface: NONE. These primitives decide only WHETHER a share is put
// on the wire; share bytes, minting and payout are untouched.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <map>
#include <set>
#include <vector>

#include <core/uint256.hpp>
#include <impl/dgb/known_txs_retention.hpp>
#include <impl/dgb/share.hpp>                     // real dgb share variants + ShareType
#include <impl/dgb/coin/share_tx_relay_refs.hpp>  // dgb::append_share_tx_refs SSOT (#905/#914)

// ---------------------------------------------------------------------------
// #880 COMPILE-TIME PIN of the send-side probe topology.
//
// The F3 gate is only as good as the member probe that feeds it. The historical
// defect was a probe on a member name NO share variant declares: `if constexpr`
// on a false `requires` is discarded silently — no warning, no error, no
// counter — so the gate collected an empty ref list for every share, every share
// was vacuously backable, and the gate no-op'd while every test stayed green.
//
// dgb::append_share_tx_refs guards on m_tx_info and reads the NESTED list. These
// static_asserts hold that topology down: if a variant ever moves or renames the
// list, the build breaks HERE instead of the gate going quietly inert.
// ---------------------------------------------------------------------------
namespace {
template <typename S>
inline constexpr bool has_flat_new_tx_hashes =
    requires(S* o) { o->m_new_transaction_hashes; };
template <typename S>
inline constexpr bool has_nested_new_tx_hashes =
    requires(S* o) { o->m_tx_info.m_new_transaction_hashes; };
} // namespace

// The FLAT spelling the dead probe assumed is absent on EVERY variant — that is
// exactly why the old gate probe was always false.
static_assert(!has_flat_new_tx_hashes<dgb::Share>,              "v17 must NOT expose a flat new-tx list");
static_assert(!has_flat_new_tx_hashes<dgb::NewShare>,           "v33 must NOT expose a flat new-tx list");
static_assert(!has_flat_new_tx_hashes<dgb::SegwitMiningShare>,  "v34 must NOT expose a flat new-tx list");
static_assert(!has_flat_new_tx_hashes<dgb::PaddingBugfixShare>, "v35 must NOT expose a flat new-tx list");
static_assert(!has_flat_new_tx_hashes<dgb::MergedMiningShare>,  "v36 must NOT expose a flat new-tx list");

// The NESTED spelling the SSOT reads is present exactly on v17/v33.
static_assert(has_nested_new_tx_hashes<dgb::Share>,               "v17 must nest the list in m_tx_info");
static_assert(has_nested_new_tx_hashes<dgb::NewShare>,            "v33 must nest the list in m_tx_info");
static_assert(!has_nested_new_tx_hashes<dgb::SegwitMiningShare>,  "v34 carries no new-tx list");
static_assert(!has_nested_new_tx_hashes<dgb::PaddingBugfixShare>, "v35 carries no new-tx list");
static_assert(!has_nested_new_tx_hashes<dgb::MergedMiningShare>,  "v36 carries no new-tx list");

namespace {

uint256 h(const char* hex) { uint256 v; v.SetHex(hex); return v; }

// Share hashes S1..S3 and tx hashes TA..TC.
const uint256 S1 = h("11"), S2 = h("22"), S3 = h("33");
const uint256 TA = h("aa"), TB = h("bb"), TC = h("cc");

// Stand-in for a share on the broadcast path: its hash plus the new-tx hashes
// it references. The gate is agnostic to everything else in a share.
struct FakeShare {
    uint256 hash;
    std::vector<uint256> new_txs;
};

std::vector<uint256> refs_of(FakeShare& s) { return s.new_txs; }

// A peer that accepts exactly the hashes send_shares would have written to it.
struct FakePeer { std::set<uint256> accepts; };

// The readvertise_best_share tip walk, verbatim in its essentials: it does NOT
// consult the de-dup set, but it DOES skip every peer-rejected hash — and that
// skip is permanent, which is what makes the recording rule reward-critical.
std::vector<uint256> readvertise_walk(const std::vector<uint256>& chain_tip_first,
                                      const std::set<uint256>& rejected)
{
    std::vector<uint256> to_send;
    for (const auto& hash : chain_tip_first) {
        if (rejected.count(hash))
            continue;
        to_send.push_back(hash);
    }
    return to_send;
}

// The EXACT refs_of that src/impl/dgb/node.cpp installs on partition_backable:
// route the variant through the dgb::append_share_tx_refs SSOT. Kept verbatim so
// the cases below drive the production probe rather than a stand-in.
std::vector<uint256> production_refs_of(dgb::ShareType& share)
{
    std::vector<uint256> hashes;
    share.invoke([&](auto* obj) { dgb::append_share_tx_refs(obj, hashes); });
    return hashes;
}

// Heap-allocated real v17 share wrapped in the production variant. ShareVariants
// is non-owning (see sharechain/share.hpp destroy()), so callers free the raws.
dgb::ShareType make_v17(std::vector<uint256> refs, std::vector<dgb::Share*>& owned)
{
    auto* raw = new dgb::Share();
    raw->m_tx_info.m_new_transaction_hashes = std::move(refs);
    owned.push_back(raw);
    dgb::ShareType sv;
    sv = raw;
    return sv;
}

} // namespace

// =========================== LIVE PATH: F3 gate =============================
// Reached in production via readvertise_best_share -> send_shares.

// A share referencing a tx whose bytes we do not hold is removed from the
// outgoing batch; the backable ones survive, in order.
TEST(DgbBroadcastGate, GateWithholdsUnbackedShare)
{
    const std::set<uint256> held{TA, TB};  // TC bytes NOT held

    std::vector<FakeShare> batch{
        {S1, {TA}},
        {S2, {TC}},        // references an unheld tx -> must be withheld
        {S3, {TA, TB}},
    };

    const std::size_t skipped = dgb::partition_backable(batch, held, refs_of);

    EXPECT_EQ(skipped, 1u);
    ASSERT_EQ(batch.size(), 2u);
    EXPECT_EQ(batch[0].hash, S1);
    EXPECT_EQ(batch[1].hash, S3);   // order preserved
}

// A share referencing no new txs is trivially backable (the common case for an
// empty-template share) — the gate must not withhold it.
TEST(DgbBroadcastGate, ShareWithNoTxRefsIsAlwaysSendable)
{
    const std::set<uint256> held;   // hold nothing at all
    std::vector<FakeShare> batch{{S1, {}}};

    EXPECT_EQ(dgb::partition_backable(batch, held, refs_of), 0u);
    ASSERT_EQ(batch.size(), 1u);
    EXPECT_EQ(batch[0].hash, S1);
}

// When every share is unbacked the batch empties, so send_shares reports nothing
// written — which is what keeps the readvertise record empty below.
TEST(DgbBroadcastGate, WholeBatchUnbackedEmptiesTheSend)
{
    const std::set<uint256> held;
    std::vector<FakeShare> batch{{S1, {TA}}, {S2, {TB}}};

    EXPECT_EQ(dgb::partition_backable(batch, held, refs_of), 2u);
    EXPECT_TRUE(batch.empty());
}

// ================= LIVE PATH: readvertise recording discipline ==============
// Reached in production via readvertise_best_share (best-change + timer).

// The DGB regression. readvertise offers three shares; the F3 gate withholds S2
// because we lack its tx bytes. The per-peer record must contain ONLY what was
// written, because that record is what a peer disconnect within 10s converts
// into m_rejected_share_hashes — and the readvertise walk skips rejected hashes
// PERMANENTLY. Recording the offered batch would blame S2 for someone else's
// drop and exclude it from every future re-advert.
TEST(DgbReadvertiseRecording, WithheldShareIsNeverBlamedForAPeerDrop)
{
    const std::vector<uint256> offered{S1, S2, S3};
    // The peer receives the gated batch: S2 was withheld by partition_backable.
    std::map<uint64_t, FakePeer> peers{{1, {{S1, S3}}}};

    std::vector<uint256> recorded;
    bool recorded_any = false;
    const std::size_t reached = dgb::readvertise_and_record(
        peers, offered,
        [](FakePeer& p) {
            return std::vector<uint256>(p.accepts.begin(), p.accepts.end());
        },
        [&](FakePeer&, const std::vector<uint256>& sent) {
            recorded = sent;
            recorded_any = true;
        });

    EXPECT_EQ(reached, 1u);
    ASSERT_TRUE(recorded_any);
    const std::set<uint256> rec(recorded.begin(), recorded.end());
    EXPECT_TRUE(rec.count(S1));
    EXPECT_TRUE(rec.count(S3));
    EXPECT_FALSE(rec.count(S2)) << "withheld share must not be in the record";

    // The peer now drops inside the 10s window: everything recorded for it is
    // marked rejected. S2 must survive that, and stay eligible for re-advert.
    const auto retry = readvertise_walk({S3, S2, S1}, rec);
    ASSERT_EQ(retry.size(), 1u);
    EXPECT_EQ(retry[0], S2) << "S2 must still be re-advertisable after the drop";
}

// A peer that received NOTHING gets no record at all, so a later drop has
// nothing to blame — the whole batch stays eligible for the next re-advert.
TEST(DgbReadvertiseRecording, PeerThatReceivedNothingIsNotRecorded)
{
    const std::vector<uint256> offered{S1, S2};
    std::map<uint64_t, FakePeer> peers{{1, {}}, {2, {}}};

    std::size_t records = 0;
    const std::size_t reached = dgb::readvertise_and_record(
        peers, offered,
        [](FakePeer&) { return std::vector<uint256>{}; },
        [&](FakePeer&, const std::vector<uint256>&) { ++records; });

    EXPECT_EQ(reached, 0u);
    EXPECT_EQ(records, 0u);

    // Nothing rejected -> the next walk still offers the whole batch.
    EXPECT_EQ(readvertise_walk({S2, S1}, /*rejected=*/{}).size(), 2u);
}

// With zero peers connected nothing is sent and nothing is recorded.
TEST(DgbReadvertiseRecording, ZeroPeersRecordsNothing)
{
    std::map<uint64_t, FakePeer> peers;
    std::size_t records = 0;
    EXPECT_EQ(dgb::readvertise_and_record(
                  peers, std::vector<uint256>{S1},
                  [](FakePeer&) { return std::vector<uint256>{}; },
                  [&](FakePeer&, const std::vector<uint256>&) { ++records; }),
              0u);
    EXPECT_EQ(records, 0u);
}

// An empty offer is a no-op: readvertise_best_share returns before the peer loop.
TEST(DgbReadvertiseRecording, EmptyOfferIsANoOp)
{
    std::map<uint64_t, FakePeer> peers{{1, {{S1}}}};
    std::size_t sends = 0, records = 0;
    EXPECT_EQ(dgb::readvertise_and_record(
                  peers, std::vector<uint256>{},
                  [&](FakePeer&) { ++sends; return std::vector<uint256>{S1}; },
                  [&](FakePeer&, const std::vector<uint256>&) { ++records; }),
              0u);
    EXPECT_EQ(sends, 0u);
    EXPECT_EQ(records, 0u);
}

// ============ LIVE PATH: F3 gate driven by the PRODUCTION probe =============
//
// The DgbBroadcastGate cases above exercise partition_backable's MECHANICS
// through FakeShare, which declares its ref list as a TOP-LEVEL member and hands
// it over via a bespoke refs_of. That is precisely the shape that let the real
// bug hide: production probed `requires { obj->m_new_transaction_hashes; }`,
// which is FALSE for every DGB variant (v17/v33 nest the list inside m_tx_info,
// v34+ carry none), so the gate saw empty refs, every share was vacuously
// backable, and the gate withheld nothing — while a FakeShare KAT and its
// negative control both stayed green.
//
// The cases below build REAL dgb share variants and drive them through the SAME
// dgb::append_share_tx_refs SSOT that node.cpp's partition_backable refs_of
// uses. FAILS-BEFORE: revert append_share_tx_refs to the flat probe (or drop the
// SSOT from node.cpp's refs_of) and the skip counts collapse to 0.

// Accessor SSOT: a REAL v17 share nests its hashes in m_tx_info and the
// production probe must surface them. The dead flat probe yielded nothing here,
// which is what emptied the gate.
TEST(DgbBroadcastGate, RealV17ShareRefsResolvedViaSsot)
{
    dgb::Share s;
    s.m_tx_info.m_new_transaction_hashes = {TA, TC};

    std::vector<uint256> refs;
    dgb::append_share_tx_refs(&s, refs);

    ASSERT_EQ(refs.size(), 2u);        // dead flat probe -> 0
    EXPECT_EQ(refs[0], TA);
    EXPECT_EQ(refs[1], TC);
}

// v33 uses the same nested carrier.
TEST(DgbBroadcastGate, RealV33ShareRefsResolvedViaSsot)
{
    dgb::NewShare s;
    s.m_tx_info.m_new_transaction_hashes = {TC};

    std::vector<uint256> refs;
    dgb::append_share_tx_refs(&s, refs);

    ASSERT_EQ(refs.size(), 1u);
    EXPECT_EQ(refs[0], TC);
}

// v34/v35/v36 carry no m_tx_info -> probe compiled out, vacuously empty. Dormant
// by construction, never silently dead.
TEST(DgbBroadcastGate, SegwitAndMergedVariantsHaveNoRefs)
{
    dgb::SegwitMiningShare  v34;
    dgb::PaddingBugfixShare v35;
    dgb::MergedMiningShare  v36;

    std::vector<uint256> refs;
    dgb::append_share_tx_refs(&v34, refs);
    dgb::append_share_tx_refs(&v35, refs);
    dgb::append_share_tx_refs(&v36, refs);

    EXPECT_TRUE(refs.empty());
}

// The gate end-to-end on REAL share variants: a v17 share referencing a tx whose
// bytes we do NOT hold must be withheld, and the backable ones must survive in
// order. This is the assertion the dead probe made impossible — pre-fix, skipped
// was pinned at 0 forever.
TEST(DgbBroadcastGate, RealShareTxInfoRefsWithheld)
{
    std::vector<dgb::Share*> owned;
    const std::set<uint256> held{TA, TB};   // TC bytes NOT held

    std::vector<dgb::ShareType> batch;
    batch.push_back(make_v17({TA}, owned));       // backable
    batch.push_back(make_v17({TC}, owned));       // unheld TC -> withheld
    batch.push_back(make_v17({TA, TB}, owned));   // backable

    const std::size_t skipped =
        dgb::partition_backable(batch, held, production_refs_of);

    EXPECT_EQ(skipped, 1u);            // dead-probe regression -> 0
    ASSERT_EQ(batch.size(), 2u);
    EXPECT_EQ(production_refs_of(batch[0]).size(), 1u);   // order preserved
    EXPECT_EQ(production_refs_of(batch[1]).size(), 2u);

    for (auto* raw : owned)
        delete raw;
}

// A wholly-unbacked REAL batch empties, so send_shares reports nothing sent and
// readvertise_best_share records nothing against the peer.
TEST(DgbBroadcastGate, WhollyUnbackedRealBatchEmpties)
{
    std::vector<dgb::Share*> owned;
    const std::set<uint256> held{TA};   // TB/TC bytes NOT held

    std::vector<dgb::ShareType> batch;
    batch.push_back(make_v17({TB}, owned));
    batch.push_back(make_v17({TC}, owned));

    EXPECT_EQ(dgb::partition_backable(batch, held, production_refs_of), 2u);
    EXPECT_TRUE(batch.empty());

    for (auto* raw : owned)
        delete raw;
}

// ============ PRE-WIRED (NOT REACHED ON DGB TODAY — see #884) ===============
// broadcast_and_mark backs dgb::NodeImpl::broadcast_share, which has zero
// callers because main_dgb.cpp binds no mint seam. These KATs pin the seam so it
// is correct the day #884 binds it; they assert NOTHING about DGB today. The
// live equivalents are the DgbReadvertiseRecording cases above.

TEST(DgbBroadcastMarkingPrewired_NotReachedToday, NothingMarkedWhenNoPeerAccepted)
{
    std::set<uint256> marked;
    std::map<uint64_t, FakePeer> peers{{1, {}}, {2, {}}};

    const std::size_t n = dgb::broadcast_and_mark(
        marked, peers, std::vector<uint256>{S1, S2},
        [](FakePeer&) { return std::vector<uint256>{}; });

    EXPECT_EQ(n, 0u);
    EXPECT_TRUE(marked.empty());
}

TEST(DgbBroadcastMarkingPrewired_NotReachedToday, OnlyAcceptedHashesAreMarked)
{
    std::set<uint256> marked;
    std::map<uint64_t, FakePeer> peers{{1, {{S1}}}, {2, {{S1, S3}}}};

    const std::size_t n = dgb::broadcast_and_mark(
        marked, peers, std::vector<uint256>{S1, S2, S3}, [](FakePeer& p) {
            return std::vector<uint256>(p.accepts.begin(), p.accepts.end());
        });

    EXPECT_EQ(n, 2u);
    EXPECT_TRUE(marked.count(S1));
    EXPECT_TRUE(marked.count(S3));
    EXPECT_FALSE(marked.count(S2));   // withheld by the gate -> retryable
}
