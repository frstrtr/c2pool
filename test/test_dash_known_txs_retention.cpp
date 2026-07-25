// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for the known-transaction retention that backs share broadcast
// (dash::retain_template_txs / all_txs_backable — src/impl/dash/
// known_txs_retention.hpp), i.e. the semantics of register_template_txs.
//
// This is the empirical gate we CAN run for the tx-forwarding fix (the
// deterministic 2-dashd testbed is infra-blocked). It pins:
//   (1) rolling-window retention across DISTINCT templates;
//   (2) eviction ONLY after a tx has fallen out of EVERY retained set;
//   (3) code review F1 — template-identity dedup: N payout-script re-
//       registrations of ONE template consume ONE slot, not N (else the window
//       collapses to a single template on a ~50-script cluster tip);
//   (4) recency refresh — re-touching a retained template moves it to the back
//       so it is not the next evicted;
//   (5) the F3/F2 broadcast gate — a share is backable only when we hold every
//       referenced tx; an unbackable share is therefore not sent (F2: not
//       marked "shared", so it is retried, never silently withheld).

#include <gtest/gtest.h>

#include <deque>
#include <map>
#include <set>
#include <vector>

#include <impl/dash/known_txs_retention.hpp>

namespace {

using dash::retain_template_txs;
using dash::all_txs_backable;

using KnownTxs = std::map<uint256, int>;              // hash -> stand-in "bytes"
using Window   = std::deque<std::set<uint256>>;

// Build a distinct 256-bit hash from a small integer.
uint256 H(uint64_t n) { return uint256(n); }

// A template = a set of tx hashes + parallel "bytes" (== the int id here).
void reg(Window& w, KnownTxs& k, const std::vector<uint64_t>& ids,
         std::size_t cap)
{
    std::vector<uint256> hashes;
    std::vector<int> txs;
    for (auto id : ids) { hashes.push_back(H(id)); txs.push_back(int(id)); }
    retain_template_txs(w, k, hashes, txs, cap);
}

bool held(const KnownTxs& k, uint64_t id) { return k.count(H(id)) != 0; }

// ── (1) rolling window retains txs of every DISTINCT template ────────────────
TEST(DashKnownTxsRetention, RollingWindowRetainsDistinctTemplates)
{
    Window w; KnownTxs k;
    reg(w, k, {1, 2}, /*cap*/ 8);
    reg(w, k, {3},    8);
    reg(w, k, {4, 5}, 8);
    EXPECT_EQ(w.size(), 3u);
    for (uint64_t id : {1, 2, 3, 4, 5}) EXPECT_TRUE(held(k, id)) << id;
}

// ── (2) eviction past cap drops the oldest template's EXCLUSIVE txs ──────────
TEST(DashKnownTxsRetention, EvictionDropsOldestExclusiveTxs)
{
    Window w; KnownTxs k;
    reg(w, k, {1, 2}, /*cap*/ 2);
    reg(w, k, {3, 4}, 2);
    reg(w, k, {5, 6}, 2);   // pushes {1,2} out
    EXPECT_EQ(w.size(), 2u);
    EXPECT_FALSE(held(k, 1));
    EXPECT_FALSE(held(k, 2));
    for (uint64_t id : {3, 4, 5, 6}) EXPECT_TRUE(held(k, id)) << id;
}

// ── (3) a tx shared by two templates survives until BOTH are evicted ────────
TEST(DashKnownTxsRetention, EvictOnlyAfterFallsOutOfAllSets)
{
    Window w; KnownTxs k;
    reg(w, k, {1, 2}, /*cap*/ 2);   // A = {1,2}
    reg(w, k, {2, 3}, 2);           // B = {2,3}  (tx 2 shared by A and B)
    reg(w, k, {4},    2);           // evicts A; tx 2 still in B -> retained
    EXPECT_FALSE(held(k, 1));       // A-exclusive -> gone
    EXPECT_TRUE(held(k, 2));        // still in B
    EXPECT_TRUE(held(k, 3));
    EXPECT_TRUE(held(k, 4));
    reg(w, k, {5}, 2);              // evicts B; tx 2 now in no set -> erased
    EXPECT_FALSE(held(k, 2));
    EXPECT_FALSE(held(k, 3));
    EXPECT_TRUE(held(k, 4));
    EXPECT_TRUE(held(k, 5));
}

// ── (4) F1: N re-registrations of ONE template consume ONE slot ─────────────
TEST(DashKnownTxsRetention, F1_DedupSameTemplateConsumesOneSlot)
{
    Window w; KnownTxs k;
    const std::size_t cap = 8;
    // ~50 payout scripts re-register the SAME template on one tip.
    for (int i = 0; i < 50; ++i) reg(w, k, {1, 2, 3}, cap);
    EXPECT_EQ(w.size(), 1u) << "dedup failed: window collapsed to N copies";
    for (uint64_t id : {1, 2, 3}) EXPECT_TRUE(held(k, id)) << id;

    // 7 further DISTINCT templates coexist with the deduped one (8 slots).
    for (uint64_t id : {10, 11, 12, 13, 14, 15, 16}) reg(w, k, {id}, cap);
    EXPECT_EQ(w.size(), 8u);
    for (uint64_t id : {1, 2, 3, 10, 11, 12, 13, 14, 15, 16})
        EXPECT_TRUE(held(k, id)) << id;

    // The 8th DISTINCT template evicts the OLDEST distinct one (the {1,2,3}
    // slot), proving the window holds 8 DISTINCT templates — NOT 50 copies.
    reg(w, k, {17}, cap);
    EXPECT_EQ(w.size(), 8u);
    for (uint64_t id : {1, 2, 3}) EXPECT_FALSE(held(k, id)) << id;
    for (uint64_t id : {10, 11, 12, 13, 14, 15, 16, 17})
        EXPECT_TRUE(held(k, id)) << id;
}

// ── (4b) recency refresh: re-touching a template moves it to the back ───────
TEST(DashKnownTxsRetention, DedupRefreshesRecency)
{
    Window w; KnownTxs k;
    const std::size_t cap = 3;
    reg(w, k, {1}, cap);   // oldest
    reg(w, k, {2}, cap);
    reg(w, k, {3}, cap);   // window: [1][2][3]
    reg(w, k, {1}, cap);   // re-touch {1} -> refresh to back: [2][3][1]
    EXPECT_EQ(w.size(), 3u);
    reg(w, k, {4}, cap);   // evicts the NEW oldest {2}, not {1}
    EXPECT_FALSE(held(k, 2));
    for (uint64_t id : {1, 3, 4}) EXPECT_TRUE(held(k, id)) << id;
}

// ── (5) F3/F2 broadcast gate: backable iff we hold every referenced tx ──────
TEST(DashKnownTxsRetention, BroadcastGateRequiresHeldBytes)
{
    KnownTxs k;
    {
        Window w;
        reg(w, k, {1, 2, 3}, 8);
    }
    // fully-held share -> backable -> sent -> marked
    EXPECT_TRUE(all_txs_backable(std::vector<uint256>{H(1), H(2)}, k));
    // one referenced tx not held -> NOT backable -> NOT sent (F2: NOT marked,
    // so broadcast_share retries it rather than silently withholding).
    EXPECT_FALSE(all_txs_backable(std::vector<uint256>{H(1), H(9)}, k));
    // empty new-tx list is trivially backable.
    EXPECT_TRUE(all_txs_backable(std::vector<uint256>{}, k));
}

} // namespace
