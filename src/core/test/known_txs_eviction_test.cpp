// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <deque>
#include <map>

#include <core/known_txs_eviction.hpp>
#include <core/uint256.hpp>

// KATs for core::evict_known_txs_to_cap — the recency-preserving bounded
// eviction that replaces the wholesale m_known_txs.clear() in the LTC/DGB/BCH/BTC
// node relay path (tx-forwarding robustness; no consensus state). The map stands
// in for m_known_txs (value type is irrelevant to eviction, so int here), and
// the deque is the insertion-order recency sidecar the protocol handlers push to.

using core::evict_known_txs_to_cap;

namespace {

// Distinct uint256 tx-hash stand-ins (uint256(uint64_t) ctor).
uint256 H(uint64_t i) { return uint256(i); }

// Insert like a remember_tx handler would: new key -> map + order sidecar.
void insert_known(std::map<uint256, int>& m, std::deque<uint256>& order,
                  const uint256& h, int v)
{
    if (!m.contains(h)) {
        m.emplace(h, v);
        order.push_back(h);
    }
}

} // namespace

// Over-cap insert evicts oldest-first; only the most-recent `cap` survive, and
// the survivors are exactly the last `cap` inserted (recency preserved).
TEST(KnownTxsEviction, EvictsOldestKeepsMostRecent)
{
    std::map<uint256, int> m;
    std::deque<uint256> order;
    constexpr size_t cap = 4;

    for (uint64_t i = 1; i <= 10; ++i)
        insert_known(m, order, H(i), static_cast<int>(i));

    evict_known_txs_to_cap(m, order, cap);

    ASSERT_EQ(m.size(), cap);
    // Oldest (1..6) gone, most-recent (7..10) retained.
    for (uint64_t i = 1; i <= 6; ++i)
        EXPECT_FALSE(m.contains(H(i))) << "stale tx " << i << " should be evicted";
    for (uint64_t i = 7; i <= 10; ++i)
        EXPECT_TRUE(m.contains(H(i))) << "recent tx " << i << " should survive";
    // Order deque tracks exactly the live survivors, oldest-first.
    ASSERT_EQ(order.size(), cap);
    EXPECT_EQ(order.front(), H(7));
    EXPECT_EQ(order.back(), H(10));
}

// Under cap: no eviction, nothing touched.
TEST(KnownTxsEviction, NoOpWhenUnderCap)
{
    std::map<uint256, int> m;
    std::deque<uint256> order;
    for (uint64_t i = 1; i <= 3; ++i)
        insert_known(m, order, H(i), static_cast<int>(i));

    evict_known_txs_to_cap(m, order, /*cap=*/8);

    EXPECT_EQ(m.size(), 3u);
    EXPECT_EQ(order.size(), 3u);
    for (uint64_t i = 1; i <= 3; ++i)
        EXPECT_TRUE(m.contains(H(i)));
}

// Desync tolerance: a key erased from the map by some other path leaves a stale
// entry in the order deque. Eviction must skip it as a no-op (never crash),
// never let the map exceed cap, and must not evict a live key on its behalf.
TEST(KnownTxsEviction, ToleratesStaleOrderEntries)
{
    std::map<uint256, int> m;
    std::deque<uint256> order;
    for (uint64_t i = 1; i <= 6; ++i)
        insert_known(m, order, H(i), static_cast<int>(i));

    // Externally erase two entries WITHOUT touching the order deque (simulated
    // desync): H(2) is in the middle, H(1) is the oldest/front.
    m.erase(H(1));
    m.erase(H(2));
    ASSERT_EQ(m.size(), 4u);
    ASSERT_EQ(order.size(), 6u); // deque still holds the tombstones

    evict_known_txs_to_cap(m, order, /*cap=*/3);

    // Map is brought to cap using live entries; a stale front erase is a no-op
    // that still advances the deque, so exactly one live key (H(3)) is dropped.
    EXPECT_EQ(m.size(), 3u);
    EXPECT_FALSE(m.contains(H(3)));
    for (uint64_t i = 4; i <= 6; ++i)
        EXPECT_TRUE(m.contains(H(i)));
    // Deque no longer holds keys absent from the map (front pruned of tombstones).
    for (const auto& h : order)
        EXPECT_TRUE(m.contains(h)) << "order deque must not retain tombstones";
    EXPECT_EQ(order.size(), m.size());
}

// Leading tombstones are pruned even when the map is already under cap, so the
// order deque cannot accrete unbounded relative to the live map.
TEST(KnownTxsEviction, PrunesLeadingTombstonesUnderCap)
{
    std::map<uint256, int> m;
    std::deque<uint256> order;
    for (uint64_t i = 1; i <= 3; ++i)
        insert_known(m, order, H(i), static_cast<int>(i));
    m.erase(H(1)); // front tombstone; map now under any reasonable cap

    evict_known_txs_to_cap(m, order, /*cap=*/8);

    EXPECT_EQ(m.size(), 2u);
    EXPECT_EQ(order.size(), 2u);
    EXPECT_EQ(order.front(), H(2));
}

// cap == 0 degenerates to the old wholesale-empty semantics (never a foot-gun).
TEST(KnownTxsEviction, ZeroCapEmpties)
{
    std::map<uint256, int> m;
    std::deque<uint256> order;
    for (uint64_t i = 1; i <= 5; ++i)
        insert_known(m, order, H(i), static_cast<int>(i));

    evict_known_txs_to_cap(m, order, /*cap=*/0);

    EXPECT_TRUE(m.empty());
    EXPECT_TRUE(order.empty());
}
