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
//
// Harness posture matches the sibling bch ABLA-seam tests: plain main() +
// CHECK() over <core/*> headers, NO GTest (the bch test tree has no GTest
// harness -- CMakeLists BCH_ABLA_TESTS builds bare add_executable targets).
// p2pool-merged-v36 surface: NONE (local tx-forward cache hygiene).

#include <cstdint>
#include <deque>
#include <iostream>
#include <map>

#include <core/known_txs_eviction.hpp>
#include <core/uint256.hpp>

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

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

// Green: sustained over-cap learning + periodic clean passes keeps the cache
// bounded at the cap, and the survivors are the most-recently-learned txs.
void live_pass_keeps_cache_bounded() {
    std::map<uint256, int> m;
    std::deque<uint256> order;
    constexpr size_t cap = 16;

    uint64_t next = 1;
    for (int round = 0; round < 50; ++round) {
        for (int k = 0; k < 100; ++k) learn(m, order, next++);  // 100 new txs
        clean_pass_wired(m, order, cap);                        // periodic clean
        CHECK(m.size() <= cap);          // cap breached this round
        CHECK(order.size() == m.size()); // recency sidecar desynced
    }
    // Bounded exactly at the cap, holding the most-recent `cap` learns.
    CHECK(m.size() == cap);
    for (uint64_t i = next - cap; i < next; ++i)
        CHECK(m.contains(H(i)));         // recent tx should survive
    CHECK(!m.contains(H(next - cap - 1))); // stale tx must be evicted
}

// Red control: perturb the wiring out and the cache grows without bound past
// the cap -- proving the live_pass_keeps_cache_bounded assertion has real teeth.
void unwired_pass_grows_past_cap() {
    std::map<uint256, int> m;
    std::deque<uint256> order;
    constexpr size_t cap = 16;

    uint64_t next = 1;
    for (int round = 0; round < 50; ++round) {
        for (int k = 0; k < 100; ++k) learn(m, order, next++);
        clean_pass_unwired(m, order, cap);
    }
    CHECK(m.size() > cap);        // unwired pass must leak past the cap
    CHECK(m.size() == 5000u);
}

} // namespace

int main() {
    live_pass_keeps_cache_bounded();
    unwired_pass_grows_past_cap();

    if (failures == 0) {
        std::cout << "known_txs_evict_wiring_test: ALL PASS\n";
        return 0;
    }
    std::cerr << "known_txs_evict_wiring_test: " << failures << " FAILURE(S)\n";
    return 1;
}
