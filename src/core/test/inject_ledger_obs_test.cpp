// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT for the S4 read-only per-inject ledger mirror and the best-ChainLock
// mirror (core::obs::InjectLedger / BestChainLockObs, inject_ledger_obs.hpp),
// the stores the loopback GET /api/tx-inject/ledger endpoint reads. Folded into
// the existing core_test target, never a standalone add_executable (the #769
// "Not Run" trap).
//
// Covers the invariants the endpoint depends on:
//   1. the ledger is bounded at kMaxEntries: an upsert past it is dropped and
//      counted, never grown;
//   2. retain() erases everything not tracked (the reconcile self-heal);
//   3. set_last_build on an absent txid is a no-op (no entry is created);
//   4. a replace keeps the last build verdict unless it carries one;
//   5. the ChainLock mirror is nullopt before any publish and round-trips.
//
// Fresh instances are used so the process-global stores stay untouched.

#include <gtest/gtest.h>

#include <core/inject_ledger_obs.hpp>

#include <cstdint>
#include <cstring>
#include <vector>

using namespace core::obs;

namespace {

uint256 ledger_id(uint32_t i) {
    uint256 h;
    std::memset(h.begin(), 0x47, 32);
    std::memcpy(h.begin(), &i, sizeof(i));
    return h;
}

InjectLedgerEntry entry(uint32_t i) {
    InjectLedgerEntry e;
    e.txid = ledger_id(i);
    e.submit_time = 1'762'000'000 + i;
    e.byte_size = 200 + i;
    return e;
}

} // namespace

TEST(InjectLedgerObs, FreshLedgerIsUnpublished)
{
    InjectLedger l;
    EXPECT_TRUE(l.snapshot().empty());
    EXPECT_EQ(l.updated_at(), 0) << "0 => the endpoint renders \"wired\": false";
    EXPECT_EQ(l.overflow_dropped(), 0u);
    EXPECT_EQ(l.tip(), 0u);
}

TEST(InjectLedgerObs, BoundedAtMaxEntriesAndOverflowCounted)
{
    InjectLedger l;
    for (uint32_t i = 0; i < InjectLedger::kMaxEntries + 1; ++i) l.upsert(entry(i));
    EXPECT_EQ(l.snapshot().size(), InjectLedger::kMaxEntries);
    EXPECT_EQ(l.overflow_dropped(), 1u);
    EXPECT_NE(l.updated_at(), 0);
    // A replace of a tracked txid at the bound is not an overflow.
    l.upsert(entry(0));
    EXPECT_EQ(l.overflow_dropped(), 1u);
    EXPECT_EQ(l.snapshot().size(), InjectLedger::kMaxEntries);

    l.retain({});
    EXPECT_TRUE(l.snapshot().empty()) << "retain of nothing tracked empties the mirror";
}

TEST(InjectLedgerObs, RetainKeepsOnlyTracked)
{
    InjectLedger l;
    for (uint32_t i = 0; i < 5; ++i) l.upsert(entry(i));
    l.retain({ledger_id(1), ledger_id(3), ledger_id(99)});
    const auto s = l.snapshot();
    ASSERT_EQ(s.size(), 2u);
    EXPECT_TRUE((s[0].txid == ledger_id(1) && s[1].txid == ledger_id(3)) ||
                (s[0].txid == ledger_id(3) && s[1].txid == ledger_id(1)));
    l.erase(ledger_id(1));
    ASSERT_EQ(l.snapshot().size(), 1u);
    EXPECT_EQ(l.snapshot()[0].txid, ledger_id(3));
}

TEST(InjectLedgerObs, SetLastBuildIsANoOpForAnAbsentTxid)
{
    InjectLedger l;
    InjectLedgerBuild b;
    b.height = 10; b.rides = false; b.cause = "not-selected";
    l.set_last_build(ledger_id(7), b);
    EXPECT_TRUE(l.snapshot().empty()) << "no entry is created for an untracked txid";

    l.upsert(entry(7));
    l.set_last_build(ledger_id(7), b);
    auto s = l.snapshot();
    ASSERT_EQ(s.size(), 1u);
    ASSERT_TRUE(s[0].last_build.has_value());
    EXPECT_EQ(*s[0].last_build, b);

    // A replace without a verdict keeps the stored one; with one, replaces it.
    InjectLedgerEntry e = entry(7);
    e.expiry_height = 42;
    l.upsert(e);
    s = l.snapshot();
    ASSERT_TRUE(s[0].last_build.has_value());
    EXPECT_EQ(*s[0].last_build, b);
    EXPECT_EQ(s[0].expiry_height, 42);
    InjectLedgerBuild r;
    r.height = 11; r.rides = true; r.cause = "ok"; r.vin = 1;
    e.last_build = r;
    l.upsert(e);
    EXPECT_EQ(*l.snapshot()[0].last_build, r);

    l.set_tip(2565261);
    EXPECT_EQ(l.tip(), 2565261u);
}

TEST(InjectLedgerObs, BestChainLockRoundTrip)
{
    BestChainLockObs o;
    EXPECT_FALSE(o.snapshot().has_value()) << "nullopt before any publish";
    BestChainLock cl;
    cl.height = 2565260;
    std::memset(cl.blockhash.begin(), 0x21, 32);
    cl.provenance = "bls-verified";
    cl.updated_at = 1'762'069'990;
    o.publish(cl);
    const auto s = o.snapshot();
    ASSERT_TRUE(s.has_value());
    EXPECT_EQ(s->height, 2565260);
    EXPECT_EQ(s->blockhash, cl.blockhash);
    EXPECT_EQ(s->provenance, "bls-verified");
    EXPECT_EQ(s->updated_at, 1'762'069'990);
    o.reset();
    EXPECT_FALSE(o.snapshot().has_value());
}
