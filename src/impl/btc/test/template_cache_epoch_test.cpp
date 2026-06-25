// Value-invariance gate for the BTC stratum work-template cache (heap opt).
//
// work_source.cpp build_connection_coinbase / get_current_work_template /
// get_stratum_merkle_branches rebuilt the FULL getblocktemplate (mempool
// walk + merkle + tx serialization) on EVERY mining.notify -- the dominant
// per-notify allocation behind the .53 RSS regression (v5 heaptrack: 2.5x
// heap, 449M peak vs the 182M Phase-1D budget). The fix caches the built
// WorkData and reuses it while the cache key (work_generation_, mempool
// tx-set epoch) is unchanged; curtime is re-stamped fresh by each caller so
// the reuse is value-invariant.
//
// The cache is only SAFE if Mempool::epoch() is itself value-invariant:
// it must change IFF the selected tx set could change, and must NOT change
// on any pure read -- otherwise the cache either serves a stale template
// (missed bump) or thrashes pointlessly (spurious bump). This harness locks
// exactly that invariant on the real Mempool.
//
// Standalone (no btc/test CMake plumbing), in the style of
// tx_data_memo_test.cpp / template_parity_test.cpp.

#include <impl/btc/coin/mempool.hpp>

#include <cstdio>
#include <cstdint>

using btc::coin::Mempool;
using btc::coin::MutableTransaction;

static int g_fails = 0;
static void check(bool ok, const char* label) {
    std::printf("  %s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) ++g_fails;
}

// Distinct, deterministic tx: locktime varies the txid (no UTXO/PoW needed).
static MutableTransaction make_tx(uint32_t lt) {
    MutableTransaction tx;
    tx.version  = 1;
    tx.locktime = lt;
    return tx;
}

int main() {
    std::printf("== Mempool::epoch() value-invariance (work-template cache key) ==\n");

    Mempool mp;  // default LTC_LIMITS; nullptr UTXO -> fee_known=false path

    // (1) fresh pool: epoch starts at a fixed baseline.
    const uint64_t e0 = mp.epoch();
    check(e0 == 0, "fresh mempool epoch == 0");

    // (2) a successful add bumps the epoch (tx set changed).
    check(mp.add_tx(make_tx(1)), "first add_tx succeeds");
    const uint64_t e1 = mp.epoch();
    check(e1 > e0, "successful add_tx bumps epoch");

    // (3) a duplicate add (returns false) must NOT bump -- tx set unchanged.
    check(!mp.add_tx(make_tx(1)), "duplicate add_tx rejected");
    check(mp.epoch() == e1, "rejected duplicate add_tx does NOT bump epoch");

    // a second distinct add bumps again.
    check(mp.add_tx(make_tx(2)), "second distinct add_tx succeeds");
    const uint64_t e2 = mp.epoch();
    check(e2 > e1, "second add_tx bumps epoch");

    // (4) pure reads must NEVER bump -- this is what makes the cache a HIT
    //     across repeated mining.notify against an unchanged mempool.
    (void)mp.size();
    (void)mp.all_txids();
    (void)mp.get_sorted_txs(4'000'000);
    (void)mp.get_sorted_txs_with_fees(4'000'000);
    (void)mp.get_entry(btc::coin::compute_txid(make_tx(2)));
    check(mp.epoch() == e2, "pure reads do NOT bump epoch (no false cache miss)");

    // (5) removing a tx bumps -- the cache must not serve a template whose
    //     tx is gone.
    mp.remove_tx(btc::coin::compute_txid(make_tx(1)));
    const uint64_t e3 = mp.epoch();
    check(e3 > e2, "remove_tx bumps epoch");

    // (6) clear bumps.
    mp.clear();
    const uint64_t e4 = mp.epoch();
    check(e4 > e3, "clear bumps epoch");
    check(mp.size() == 0, "clear empties the pool");

    // (7) monotonic across the whole sequence (never decreases).
    check(e0 <= e1 && e1 <= e2 && e2 <= e3 && e3 <= e4,
          "epoch is monotonic non-decreasing throughout");

    std::printf("== %s (%d failure%s) ==\n",
                g_fails ? "FAIL" : "ALL PASS", g_fails, g_fails == 1 ? "" : "s");
    return g_fails ? 1 : 0;
}
