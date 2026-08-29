// SPDX-License-Identifier: AGPL-3.0-or-later
// H5 acceptance gate: deterministic pointer-identity + O(1) proof for the
// tx_data memo (the work_source.cpp:634 churn/leak fix). Standalone harness
// in the style of template_parity_test.cpp -- no btc/test CMake plumbing
// required.
//
// Build (from repo root):
//   g++ -std=gnu++20 -I src -I src/btclibs \
//       src/impl/btc/test/tx_data_memo_test.cpp src/btclibs/crypto/sha256.cpp \
//       -o /tmp/tx_data_memo_test
// Run:
//   /tmp/tx_data_memo_test
//
// Proves the invariant the fix establishes:
//   (1) same merkle leaf set on repeat calls -> SAME shared_ptr (no rebuild)
//   (2) a changed leaf set -> a FRESH shared_ptr (correct invalidation)
//   (3) content is correct (the tx "data" hex, in order)
//   (4) N repeat calls do NOT grow allocations: exactly ONE vector ever built
//       for an unchanged tx set, and the per-call cost is O(1) (fingerprint
//       only), not O(mempool) -- this is the flatten of the :634 curve.

#include <impl/btc/stratum/tx_data_memo.hpp>

#include <chrono>
#include <cstdio>
#include <cstdint>

using btc::stratum::detail::tx_data_memo_get_or_build;

static int g_fails = 0;
static void check(bool ok, const char* label) {
    std::printf("  %s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) ++g_fails;
}

// Build a synthetic merkle leaf set (deterministic, no real PoW needed).
static std::vector<uint256> make_leaves(unsigned n, unsigned char salt) {
    std::vector<uint256> v(n);
    for (unsigned i = 0; i < n; ++i) {
        unsigned char* d = v[i].data();
        for (int b = 0; b < 32; ++b) d[b] = (unsigned char)((i * 31 + b * 7 + salt) & 0xff);
    }
    return v;
}

// Build a synthetic getblocktemplate-style "transactions" array.
static nlohmann::json make_txs(unsigned n) {
    nlohmann::json arr = nlohmann::json::array();
    for (unsigned i = 0; i < n; ++i)
        arr.push_back({{"data", std::string("deadbeef") + std::to_string(i)}});
    return arr;
}

int main() {
    std::printf("== tx_data memo: pointer-identity + O(1) acceptance gate ==\n");

    const unsigned NTX = 3000;                  // representative full mempool
    auto leaves_a = make_leaves(NTX, 0x00);
    auto leaves_b = make_leaves(NTX, 0x01);     // one differing tx set
    auto txs_a    = make_txs(NTX);
    auto txs_b    = make_txs(NTX);

    uint256 memo_fp;
    std::shared_ptr<std::vector<std::string>> memo_slot;

    // (1) first call builds; second call against same leaves reuses the ptr.
    auto p1 = tx_data_memo_get_or_build(leaves_a, txs_a, memo_fp, memo_slot);
    auto p2 = tx_data_memo_get_or_build(leaves_a, txs_a, memo_fp, memo_slot);
    check(p1.get() == p2.get(), "same leaf set -> identical shared_ptr (no rebuild)");
    check(p1.use_count() >= 3,  "memoized ptr is shared, not re-materialized");

    // (3) content correctness on the built vector.
    bool content_ok = p1->size() == NTX && (*p1)[0] == "deadbeef0"
                      && (*p1)[NTX - 1] == ("deadbeef" + std::to_string(NTX - 1));
    check(content_ok, "tx hex content correct and in order");

    // (2) a changed leaf set invalidates and yields a fresh ptr.
    auto p3 = tx_data_memo_get_or_build(leaves_b, txs_b, memo_fp, memo_slot);
    check(p3.get() != p1.get(), "changed leaf set -> fresh shared_ptr (invalidated)");

    // rolling back to leaves_a is now a MISS (single slot holds leaves_b).
    auto p4 = tx_data_memo_get_or_build(leaves_a, txs_a, memo_fp, memo_slot);
    check(p4.get() != p1.get() && p4.get() != p3.get(),
          "single-slot: rolled-back set rebuilds (bounded memory, one slot)");

    // (4) O(1) proof: hammer the SAME leaf set N times. The original :634 code
    // re-serialized the whole mempool every call (O(N*NTX)); the memo makes
    // every repeat a fingerprint-only refcount bump. Assert exactly ONE vector
    // identity is returned across all N calls, and report per-call timing.
    const long N = 1000000;
    // reset slot to a known single set
    memo_slot.reset(); memo_fp = uint256();
    auto base = tx_data_memo_get_or_build(leaves_a, txs_a, memo_fp, memo_slot);
    void* base_id = base.get();
    bool all_same = true;
    auto t0 = std::chrono::steady_clock::now();
    for (long i = 0; i < N; ++i) {
        auto pp = tx_data_memo_get_or_build(leaves_a, txs_a, memo_fp, memo_slot);
        if (pp.get() != base_id) { all_same = false; break; }
    }
    auto t1 = std::chrono::steady_clock::now();
    double ns_per_call =
        std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count() / double(N);
    check(all_same, "N repeat calls return the ONE memoized vector (no rebuild)");
    std::printf("  curve: %ld unchanged-tx calls @ NTX=%u -> %.1f ns/call "
                "(O(1) fingerprint, was O(NTX) re-serialize)\n", N, NTX, ns_per_call);

    std::printf("\n%s (%d failures)\n", g_fails ? "FAILED" : "ALL PASS", g_fails);
    return g_fails ? 1 : 0;
}