// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// F3 tx-completeness broadcast gate + F2 mark-only-what-was-sent — BTC KATs.
//
// Both primitives are the ones send_shares()/broadcast_share() in
// src/impl/btc/node.cpp actually call, so these KATs pin the shipped policy:
//
//   partition_backable()  — F3. send_shares must NOT write a share whose
//     referenced new-tx BYTES we do not hold: canonical p2pool disconnects on
//     "referenced unknown transaction" (p2p.py), which isolates us from the
//     sharechain and orphans our shares. Pre-fix, send_shares looked the tx up
//     and simply omitted it when absent (`if (it != m_known_txs.end())` with no
//     else), sending the share anyway.
//
//   broadcast_and_mark()  — F2. broadcast_share may add a hash to
//     m_shared_share_hashes only AFTER a peer accepted it. Pre-fix it marked the
//     whole chain-walk up front, so a batch that send_shares then abandoned (F3
//     skip, tracker try_to_lock miss, zero peers) was withheld FOREVER: the next
//     walk breaks on the first marked hash and nothing ever re-pushes it.
//
// Red-able: WalkStrandedWhenMarkedBeforeSend reproduces the pre-fix marking
// order side by side with the shipped one and asserts they differ — restoring
// mark-before-send makes the shipped half fail. GateWithholdsUnbackedShare
// asserts a skip count of 1; deleting the gate flips it red.
//
// Rides the already-allowlisted btc_share_test executable — no build.yml
// --target allowlist change, no NOT_BUILT sentinel risk.
// Consensus surface: NONE. These primitives decide only WHETHER a share is put
// on the wire; share bytes, minting and payout are untouched.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <map>
#include <set>
#include <utility>
#include <vector>

#include <core/uint256.hpp>
#include <impl/btc/known_txs_retention.hpp>
#include <impl/btc/share.hpp>          // real btc share variants + ShareType
#include <impl/btc/share_tx_refs.hpp>  // btc::new_tx_hashes SSOT (#880)

// ---------------------------------------------------------------------------
// #880 COMPILE-TIME PIN of the send-side probe topology.
//
// btc/share_tx_refs.hpp declares has_flat_new_tx_hashes / has_nested_new_tx_hashes
// specifically so the topology can be held down at compile time; without a
// static_assert somewhere those traits are themselves inert. A runtime KAT
// catches the flat-probe reversion, but only these catch a share variant moving
// or renaming the list — the build breaks HERE instead of the gate going
// quietly inert.
// ---------------------------------------------------------------------------
static_assert(!btc::has_flat_new_tx_hashes<btc::Share>,              "v17 must NOT expose a flat new-tx list");
static_assert(!btc::has_flat_new_tx_hashes<btc::NewShare>,           "v33 must NOT expose a flat new-tx list");
static_assert(!btc::has_flat_new_tx_hashes<btc::SegwitMiningShare>,  "v34 must NOT expose a flat new-tx list");
static_assert(!btc::has_flat_new_tx_hashes<btc::PaddingBugfixShare>, "v35 must NOT expose a flat new-tx list");
static_assert(!btc::has_flat_new_tx_hashes<btc::MergedMiningShare>,  "v36 must NOT expose a flat new-tx list");

static_assert(btc::has_nested_new_tx_hashes<btc::Share>,               "v17 must nest the list in m_tx_info");
static_assert(btc::has_nested_new_tx_hashes<btc::NewShare>,            "v33 must nest the list in m_tx_info");
static_assert(!btc::has_nested_new_tx_hashes<btc::SegwitMiningShare>,  "v34 carries no new-tx list");
static_assert(!btc::has_nested_new_tx_hashes<btc::PaddingBugfixShare>, "v35 carries no new-tx list");
static_assert(!btc::has_nested_new_tx_hashes<btc::MergedMiningShare>,  "v36 carries no new-tx list");

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

} // namespace

// F3: a share referencing a tx whose bytes we do not hold is removed from the
// outgoing batch; the backable ones survive, in order.
TEST(BtcBroadcastGate, GateWithholdsUnbackedShare)
{
    const std::set<uint256> held{TA, TB};  // TC bytes NOT held

    std::vector<FakeShare> batch{
        {S1, {TA}},
        {S2, {TC}},        // references an unheld tx -> must be withheld
        {S3, {TA, TB}},
    };

    const std::size_t skipped = btc::partition_backable(batch, held, refs_of);

    EXPECT_EQ(skipped, 1u);
    ASSERT_EQ(batch.size(), 2u);
    EXPECT_EQ(batch[0].hash, S1);
    EXPECT_EQ(batch[1].hash, S3);   // order preserved
}

// F3: a share referencing no new txs is trivially backable (the common case for
// an empty-template share) — the gate must not withhold it.
TEST(BtcBroadcastGate, ShareWithNoTxRefsIsAlwaysSendable)
{
    const std::set<uint256> held;   // hold nothing at all
    std::vector<FakeShare> batch{{S1, {}}};

    EXPECT_EQ(btc::partition_backable(batch, held, refs_of), 0u);
    ASSERT_EQ(batch.size(), 1u);
    EXPECT_EQ(batch[0].hash, S1);
}

// F3: when every share is unbacked the batch empties, and send_shares reports
// nothing sent (which is what keeps F2 from marking them).
TEST(BtcBroadcastGate, WholeBatchUnbackedEmptiesTheSend)
{
    const std::set<uint256> held;
    std::vector<FakeShare> batch{{S1, {TA}}, {S2, {TB}}};

    EXPECT_EQ(btc::partition_backable(batch, held, refs_of), 2u);
    EXPECT_TRUE(batch.empty());
}

// F2: a batch no peer accepted must leave the de-dup set untouched, so the next
// broadcast walk re-offers it.
TEST(BtcBroadcastMarking, NothingMarkedWhenNoPeerAccepted)
{
    std::set<uint256> marked;
    std::map<uint64_t, FakePeer> peers{{1, {}}, {2, {}}};

    const std::size_t n = btc::broadcast_and_mark(
        marked, peers, std::vector<uint256>{S1, S2},
        [](FakePeer&) { return std::vector<uint256>{}; });

    EXPECT_EQ(n, 0u);
    EXPECT_TRUE(marked.empty());
}

// F2: with zero peers connected nothing is sent, therefore nothing is marked.
TEST(BtcBroadcastMarking, NothingMarkedWithZeroPeers)
{
    std::set<uint256> marked;
    std::map<uint64_t, FakePeer> peers;

    EXPECT_EQ(btc::broadcast_and_mark(marked, peers, std::vector<uint256>{S1, S2},
                                      [](FakePeer&) { return std::vector<uint256>{}; }),
              0u);
    EXPECT_TRUE(marked.empty());
}

// F2: exactly the union of what the peers accepted gets marked — no more.
TEST(BtcBroadcastMarking, OnlyAcceptedHashesAreMarked)
{
    std::set<uint256> marked;
    std::map<uint64_t, FakePeer> peers{{1, {{S1}}}, {2, {{S1, S3}}}};

    const std::size_t n = btc::broadcast_and_mark(
        marked, peers, std::vector<uint256>{S1, S2, S3}, [](FakePeer& p) {
            return std::vector<uint256>(p.accepts.begin(), p.accepts.end());
        });

    EXPECT_EQ(n, 2u);
    EXPECT_TRUE(marked.count(S1));
    EXPECT_TRUE(marked.count(S3));
    EXPECT_FALSE(marked.count(S2));   // withheld by the gate -> retryable
}

// The regression itself. broadcast_share walks back from the tip and BREAKS on
// the first already-marked hash. Round 1: TB is missing so S2 is withheld and no
// peer accepts anything. Pre-fix (mark first) the walk is stranded forever;
// shipped (mark after send) it re-offers the batch in round 2, when TB arrives.
TEST(BtcBroadcastMarking, WalkStrandedWhenMarkedBeforeSend)
{
    // The tip-first walk broadcast_share performs, verbatim in its essentials.
    auto walk = [](const std::vector<uint256>& chain_tip_first,
                   const std::set<uint256>& marked) {
        std::vector<uint256> to_send;
        for (const auto& hash : chain_tip_first) {
            if (marked.count(hash))
                break;
            to_send.push_back(hash);
        }
        return to_send;
    };

    const std::vector<uint256> chain{S2, S1};   // S2 is the tip
    std::map<uint64_t, FakePeer> one_peer{{1, {}}};

    // ---- pre-fix ordering: mark the walk, THEN discover nothing was sent ----
    {
        std::set<uint256> marked;
        auto to_send = walk(chain, marked);
        ASSERT_EQ(to_send.size(), 2u);
        for (const auto& hash : to_send) marked.insert(hash);   // the bug
        btc::broadcast_and_mark(marked, one_peer, to_send,
                                [](FakePeer&) { return std::vector<uint256>{}; });

        // Round 2, TB has since arrived and S2 is backable — but the walk is
        // dead: the tip is marked, so nothing is ever re-pushed. Silent,
        // permanent share loss with no retry path.
        EXPECT_TRUE(walk(chain, marked).empty());
    }

    // ---- shipped ordering: mark only what a peer accepted --------------------
    {
        std::set<uint256> marked;
        auto to_send = walk(chain, marked);
        ASSERT_EQ(to_send.size(), 2u);
        btc::broadcast_and_mark(marked, one_peer, to_send,
                                [](FakePeer&) { return std::vector<uint256>{}; });
        EXPECT_TRUE(marked.empty());

        // Round 2: the walk still yields the full batch, so the share is retried.
        auto retry = walk(chain, marked);
        ASSERT_EQ(retry.size(), 2u);
        EXPECT_EQ(retry[0], S2);

        // ...and once a peer accepts them they are marked exactly once.
        std::map<uint64_t, FakePeer> live{{1, {{S1, S2}}}};
        btc::broadcast_and_mark(marked, live, retry, [](FakePeer& p) {
            return std::vector<uint256>(p.accepts.begin(), p.accepts.end());
        });
        EXPECT_EQ(marked.size(), 2u);
        EXPECT_TRUE(walk(chain, marked).empty());   // now correctly de-duped
    }
}


// ---------------------------------------------------------------------------
// #880 REGRESSION: the F3 gate above must be driven by the PRODUCTION probe,
// not a hand-rolled stand-in. The FakeShare KATs exercise partition_backable's
// MECHANICS with a top-level new_txs member and a bespoke refs_of -- exactly
// the shape that let the real bug hide. In production send_shares probed
// `requires { obj->m_new_transaction_hashes; }`, which is FALSE for every BTC
// share variant (the list is nested in m_tx_info), so the gate collected empty
// refs, every share was vacuously backable, and the gate silently no-op'd for
// ALL versions -- a share referencing a tx the peer lacked was broadcast anyway
// and tripped the canonical "referenced unknown transaction" disconnect.
//
// These KATs build REAL btc share types and drive them through the SAME
// btc::new_tx_hashes SSOT that node.cpp's partition_backable refs_of now uses.
// FAILS-BEFORE: revert btc::new_tx_hashes (or the gate) to the flat probe and
// the v17/v33 expectations collapse -- the unbacked share is no longer withheld.
// ---------------------------------------------------------------------------
namespace {

// The exact refs_of node.cpp installs on partition_backable: route the variant
// through the btc::new_tx_hashes SSOT.
std::vector<uint256> production_refs_of(btc::ShareType& share)
{
    std::vector<uint256> hashes;
    share.invoke([&](auto* obj) {
        if (const auto* new_txs = btc::new_tx_hashes(obj))
            hashes.assign(new_txs->begin(), new_txs->end());
    });
    return hashes;
}

} // namespace

// Accessor SSOT: a REAL v17 share nests its new-tx hashes in m_tx_info; the
// production probe must surface them (the dead flat probe returned nullptr).
TEST(BtcBroadcastGate, RealV17ShareRefsResolvedViaSsot)
{
    btc::Share s;
    s.m_tx_info.m_new_transaction_hashes = {TA, TC};

    const auto* refs = btc::new_tx_hashes(&s);
    ASSERT_NE(refs, nullptr);
    ASSERT_EQ(refs->size(), 2u);          // dead flat probe -> nullptr
    EXPECT_EQ((*refs)[0], TA);
    EXPECT_EQ((*refs)[1], TC);
}

// Accessor SSOT: v33 uses the same nested carrier.
TEST(BtcBroadcastGate, RealV33ShareRefsResolvedViaSsot)
{
    btc::NewShare s;
    s.m_tx_info.m_new_transaction_hashes = {TC};

    const auto* refs = btc::new_tx_hashes(&s);
    ASSERT_NE(refs, nullptr);
    ASSERT_EQ(refs->size(), 1u);
    EXPECT_EQ((*refs)[0], TC);
}

// Accessor SSOT: v34/v35/v36 carry no m_tx_info -> nullptr, compiled out.
TEST(BtcBroadcastGate, SegwitAndMergedVariantsHaveNoRefs)
{
    btc::SegwitMiningShare v34;
    btc::PaddingBugfixShare v35;
    btc::MergedMiningShare v36;
    EXPECT_EQ(btc::new_tx_hashes(&v34), nullptr);
    EXPECT_EQ(btc::new_tx_hashes(&v35), nullptr);
    EXPECT_EQ(btc::new_tx_hashes(&v36), nullptr);
}

// The gate end-to-end: REAL share variants + the production refs_of through
// btc::partition_backable. A v17 share referencing a tx whose bytes we do NOT
// hold must be withheld; the backable ones survive, in order. Pre-fix the dead
// probe made every share vacuously backable -> skipped==0, nothing withheld.
TEST(BtcBroadcastGate, RealShareTxInfoRefsWithheld)
{
    std::vector<btc::Share*> raws;   // own the heap shares for cleanup
    auto v17 = [&](std::vector<uint256> refs) {
        auto* raw = new btc::Share();
        raw->m_tx_info.m_new_transaction_hashes = std::move(refs);
        raws.push_back(raw);
        btc::ShareType sv; sv = raw; return sv;
    };

    const std::set<uint256> held{TA, TB};   // TC bytes NOT held

    std::vector<btc::ShareType> batch;
    batch.push_back(v17({TA}));        // backable
    batch.push_back(v17({TC}));        // references unheld TC -> withheld
    batch.push_back(v17({TA, TB}));    // backable

    const std::size_t skipped =
        btc::partition_backable(batch, held, production_refs_of);

    EXPECT_EQ(skipped, 1u);            // dead-probe regression -> 0
    ASSERT_EQ(batch.size(), 2u);
    EXPECT_EQ(production_refs_of(batch[0]).front(), TA);   // order preserved
    EXPECT_EQ(production_refs_of(batch[1]).front(), TA);

    for (auto* raw : raws) delete raw;
}
