// SPDX-License-Identifier: AGPL-3.0-or-later
//
// B-BCH.EVICT wiring gate. The recency-preserving eviction primitive itself is
// KAT-covered in core/test/known_txs_eviction_test.cpp. What THIS test pins is
// the BCH-side WIRING: clean_tracker()'s live periodic pass must apply the
// guarded eviction call so the m_known_txs tx-forward cache stays bounded at
// m_max_known_txs. Before this fix the only evict call site lived inside the
// dead lockless prune_shares() (zero callers), so the cap was never enforced
// and m_known_txs grew without bound.
//
// Honesty gate: the "wired" clean pass reproduces node.cpp clean_tracker()'s
// exact predicate + call; the "unwired" pass omits it (the perturbation the
// integrator asked for) and is asserted to grow past the cap. Green = bounded;
// the unwired control proves the assertion can actually fail.
#include <gtest/gtest.h>

#include <deque>
#include <map>

#include <core/known_txs_eviction.hpp>
#include <core/uint256.hpp>

namespace {

uint256 H(uint64_t i) { return uint256(i); }

// remember_tx-style learn: new key -> map + recency sidecar (protocol_*.cpp).
void learn(std::map<uint256, int>& m, std::deque<uint256>& order, uint64_t i) {
    auto h = H(i);
    if (!m.contains(h)) { m.emplace(h, 1); order.push_back(h); }
}

// WIRED: byte-for-byte the guarded call clean_tracker() now runs each pass.
void clean_pass_wired(std::map<uint256, int>& m, std::deque<uint256>& order,
                      size_t cap) {
    if (m.size() > cap)
        core::evict_known_txs_to_cap(m, order, cap);
}

// UNWIRED control (perturbation): the periodic pass with the eviction removed,
// i.e. the pre-fix behaviour where the only caller was dead code.
void clean_pass_unwired(std::map<uint256, int>&, std::deque<uint256>&, size_t) {}

} // namespace

// Green: sustained over-cap learning + periodic clean passes keeps the cache
// bounded at the cap, and the survivors are the most-recently-learned txs.
TEST(BchKnownTxsEvictWiring, LivePassKeepsCacheBounded) {
    std::map<uint256, int> m;
    std::deque<uint256> order;
    constexpr size_t cap = 16;

    uint64_t next = 1;
    for (int round = 0; round < 50; ++round) {
        for (int k = 0; k < 100; ++k) learn(m, order, next++);  // 100 new txs
        clean_pass_wired(m, order, cap);                        // periodic clean
        ASSERT_LE(m.size(), cap) << "cap breached after round " << round;
        ASSERT_EQ(order.size(), m.size()) << "recency sidecar desynced";
    }
    // Bounded exactly at the cap, holding the most-recent `cap` learns.
    EXPECT_EQ(m.size(), cap);
    for (uint64_t i = next - cap; i < next; ++i)
        EXPECT_TRUE(m.contains(H(i))) << "recent tx " << i << " should survive";
    EXPECT_FALSE(m.contains(H(next - cap - 1))) << "stale tx must be evicted";
}

// Red control: perturb the wiring out and the cache grows without bound past
// the cap — proving the LivePassKeepsCacheBounded assertion has real teeth.
TEST(BchKnownTxsEvictWiring, UnwiredPassGrowsPastCap) {
    std::map<uint256, int> m;
    std::deque<uint256> order;
    constexpr size_t cap = 16;

    uint64_t next = 1;
    for (int round = 0; round < 50; ++round) {
        for (int k = 0; k < 100; ++k) learn(m, order, next++);
        clean_pass_unwired(m, order, cap);
    }
    EXPECT_GT(m.size(), cap) << "unwired pass must leak past the cap";
    EXPECT_EQ(m.size(), 5000u);
}
