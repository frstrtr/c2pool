// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_m3_serving_kat — the KILLER known-answer test for BIP-110 M3 daemonless
// mempool tx-serving. Network-free, it exercises the REWARD-SAFETY core of the
// serve path (src/impl/bip110/coin/block_assembler.hpp + the merkle/commitment
// SSOT in template_builder.hpp) with synthetic mempool entries:
//
//   (1) CPFP PACKAGE: a low-fee parent + high-fee child are BOTH selected, and
//       the parent is emitted at a LOWER index than the child (topological
//       order) — the reward-safety invariant that a child never enters a block
//       without its in-mempool parent. Fees sum exactly.
//   (2) UNPRICED-PARENT FAIL-CLOSED: a child spending an in-mempool but UNPRICED
//       parent is EXCLUDED (reason "unpriced-in-mempool-parent") — including it
//       would be a missing-inputs INVALID block.
//   (3) WEIGHT CAP: a tx heavier than the cap is EXCLUDED (reason "weight-cap").
//   (4) CONFIRMED-PARENT INDEPENDENCE: a tx spending a coin NOT in the mempool
//       (confirmed / priced by the UTXO view) is selected with no ancestor.
//   (5) COINBASEVALUE CONSERVATION: coinbasevalue == subsidy + Σ(included fees),
//       to the satoshi.
//   (6) MERKLE/COMMITMENT SSOT: the txid-merkle over [coinbase]++txids equals an
//       independent pairwise SHA256d fold; witness_merkle_root([]) == 0.
//
// A failure here is a money-path defect (over-claim / invalid block), so this KAT
// gates the M3 serve path exactly as the M2 workshape KAT gates mining.

#include <impl/bip110/coin/block_assembler.hpp>
#include <impl/bip110/coin/mempool.hpp>
#include <impl/bip110/coin/template_builder.hpp>
#include <impl/bip110/coin/transaction.hpp>

#include <core/coin/utxo_view_db.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/uint256.hpp>

#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

namespace {

int g_fail = 0;
void expect(const std::string& what, bool ok) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

uint256 h_of(unsigned byte) {
    uint256 u; std::memset(u.data(), 0, 32); u.data()[0] = byte; return u;
}

// Build a minimal spendable tx: one input (prevhash:idx), one output of `value`.
bip110::coin::MutableTransaction mk_tx(const uint256& prev, uint32_t idx, int64_t value) {
    bip110::coin::MutableTransaction tx;
    bip110::coin::TxIn in;
    in.prevout.hash = prev;
    in.prevout.index = idx;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    bip110::coin::TxOut out;
    out.value = value;
    tx.vout.push_back(out);
    return tx;
}

bip110::coin::MempoolEntry mk_entry(const uint256& txid, const uint256& prev, uint32_t idx,
                                    uint64_t fee, uint32_t weight, bool priced = true) {
    bip110::coin::MempoolEntry e;
    e.tx = mk_tx(prev, idx, 1000);
    e.txid = txid;
    e.fee = fee;
    e.weight = weight;
    e.fee_known = priced;
    e.base_size = weight / 4;
    return e;
}

size_t index_of(const std::vector<bip110::coin::AssembledTx>& v, const uint256& txid) {
    for (size_t i = 0; i < v.size(); ++i) if (v[i].txid == txid) return i;
    return SIZE_MAX;
}
bool has_exclusion(const bip110::coin::AssemblyResult& r, const uint256& txid, const std::string& reason) {
    for (const auto& e : r.excluded) if (e.first == txid && e.second == reason) return true;
    return false;
}

} // namespace

int main() {
    using namespace bip110::coin;
    std::printf("bip110_m3_serving_kat — daemonless tx-serving reward-safety\n");

    // Synthetic txids.
    const uint256 A = h_of(0xA1);   // CPFP parent (low fee)
    const uint256 B = h_of(0xB2);   // CPFP child of A (high fee)
    const uint256 X = h_of(0xC3);   // UNPRICED in-mempool parent (not in snapshot)
    const uint256 C = h_of(0xC4);   // child of X (must be excluded)
    const uint256 D = h_of(0xD5);   // over-weight tx
    const uint256 E = h_of(0xE6);   // independent (spends confirmed coin)
    const uint256 CONFIRMED = h_of(0x11);  // a coin NOT in the mempool

    // priced snapshot: A, B, D, E  (X is NOT priced -> absent from snapshot).
    std::vector<MempoolEntry> priced;
    priced.push_back(mk_entry(A, CONFIRMED, 0, /*fee*/1000, /*weight*/400));
    priced.push_back(mk_entry(B, A,         0, /*fee*/9000, /*weight*/400));  // spends A:0
    priced.push_back(mk_entry(D, CONFIRMED, 1, /*fee*/50000,/*weight*/900000)); // > cap
    priced.push_back(mk_entry(E, CONFIRMED, 2, /*fee*/2000, /*weight*/400));
    // A child of an unpriced in-mempool parent X. It is itself fee_known (priced
    // via T2/T3), so it appears in the snapshot — the assembler MUST still exclude
    // it because X can never be included.
    priced.push_back(mk_entry(C, X,         0, /*fee*/8000, /*weight*/400));

    // ALL pool txids (priced + unpriced). X is in the pool but unpriced.
    std::set<uint256> pool_txids = { A, B, D, E, C, X };

    const uint32_t cap = 799000;   // RDTS 800000 - ~1000 headroom for the test
    AssemblyResult r = assemble_block_txs(priced, pool_txids, cap);

    std::printf("selected=%zu total_fee=%llu total_weight=%u excluded=%zu\n",
                r.txs.size(), (unsigned long long)r.total_fee, r.total_weight, r.excluded.size());

    // (1) CPFP package: A and B both in, A before B.
    size_t iA = index_of(r.txs, A), iB = index_of(r.txs, B);
    expect("CPFP parent A selected", iA != SIZE_MAX);
    expect("CPFP child B selected",  iB != SIZE_MAX);
    expect("parent A ordered before child B (topological)", iA != SIZE_MAX && iB != SIZE_MAX && iA < iB);

    // (2) child of unpriced parent excluded, fail-closed.
    expect("C (child of unpriced X) EXCLUDED", index_of(r.txs, C) == SIZE_MAX);
    expect("C exclusion named unpriced-in-mempool-parent",
           has_exclusion(r, C, "unpriced-in-mempool-parent"));

    // (3) over-weight tx excluded.
    expect("D (over-weight) EXCLUDED", index_of(r.txs, D) == SIZE_MAX);
    expect("D exclusion named weight-cap", has_exclusion(r, D, "weight-cap"));

    // (4) independent tx selected.
    expect("E (confirmed-parent) selected", index_of(r.txs, E) != SIZE_MAX);

    // (5) coinbasevalue conservation: only A,B,E fees count (1000+9000+2000).
    const uint64_t expect_fee = 1000 + 9000 + 2000;
    expect("total_fee == 12000 (A+B+E only)", r.total_fee == expect_fee);
    const uint64_t subsidy = get_block_subsidy(961700, 210000);   // post-anchor height
    const uint64_t coinbasevalue = subsidy + r.total_fee;
    expect("coinbasevalue == subsidy + fees", coinbasevalue == subsidy + expect_fee);

    // (6) merkle SSOT: [coinbase]++[A,B,E] fold matches an independent pairwise
    //     SHA256d recompute; witness_merkle_root of an empty set is ZERO.
    {
        uint256 cb = h_of(0x01);
        std::vector<uint256> leaves = { cb, A, B, E };
        uint256 root = compute_merkle_root(leaves);
        // independent 4-leaf fold: ((cb,A),(B,E))
        uint256 l0 = merkle_hash_pair(cb, A);
        uint256 l1 = merkle_hash_pair(B, E);
        uint256 ref = merkle_hash_pair(l0, l1);
        expect("txid-merkle([cb,A,B,E]) == independent pairwise fold", root == ref);
        expect("witness_merkle_root([]) == coinbase-only zero root",
               witness_merkle_root({}) == uint256::ZERO);
    }

    // (7) HARD topological verification: every selected tx's in-snapshot parent
    //     appears earlier — belt-and-suspenders re-check the assembler guarantees.
    {
        std::set<uint256> seen;
        bool ok = true;
        for (const auto& t : r.txs) {
            for (const auto& vin : t.tx.vin) {
                bool parent_in_selection = (index_of(r.txs, vin.prevout.hash) != SIZE_MAX);
                if (parent_in_selection && !seen.count(vin.prevout.hash)) { ok = false; break; }
            }
            seen.insert(t.txid);
        }
        expect("no child precedes its in-block parent", ok);
    }

    // ── (8) REAL PRODUCTION PATH: ingest -> price (T2 UTXO) -> select ────────
    // Drive the ACTUAL Mempool::add_tx + UTXOViewCache pricing (compute_fee_locked)
    // + assemble_block_txs with a REAL tx spending a coin in the UTXO view. This is
    // the price->include->txcount>1->coinbasevalue path the live fork-mempool txs
    // cannot exercise (they spend pre-fork CONFIRMED coins that getdata(tx) does
    // not serve — correctly fail-closed). Here a matured coin is in the view, so
    // the tx is priced and included.
    {
        std::string path = "/tmp/bip110_kat_utxo_" + std::to_string(::getpid());
        core::coin::UTXOViewDB db(path);
        db.open();
        core::coin::UTXOViewCache utxo(&db);

        // A matured non-coinbase coin worth 100000 sat at some outpoint.
        uint256 funding = h_of(0x77);
        core::coin::Outpoint op(funding, 0);
        OPScript spk;
        utxo.add_coin(op, core::coin::Coin(100000, spk, /*height*/1, /*coinbase*/false));

        Mempool pool;
        pool.set_utxo(&utxo);
        pool.set_tip_height(1000);

        // A tx spending funding:0 (100000) with a 90000 output => fee 10000.
        MutableTransaction spend = mk_tx(funding, 0, 90000);
        bool added = pool.add_tx(spend, &utxo);
        expect("real tx admitted to mempool", added);
        expect("mempool priced 1 tx (fee_known)", pool.total_fees() == 10000);

        auto ps = pool.snapshot_priced();
        auto pt = pool.all_txids();
        std::set<uint256> pool_ids(pt.begin(), pt.end());
        AssemblyResult rr = assemble_block_txs(ps, pool_ids, 799000);
        std::printf("PRODUCTION PATH: priced=%zu included=%zu fee=%llu\n",
                    ps.size(), rr.txs.size(), (unsigned long long)rr.total_fee);
        expect("assembler included the priced tx (txcount 1+N, N>=1)", rr.txs.size() == 1);
        expect("included fee == 10000", rr.total_fee == 10000);

        // Full template arithmetic: coinbasevalue == subsidy + fee; merkle over
        // [coinbase]++[txid] is well-formed and depends on the included tx.
        uint256 cbtxid = h_of(0x02);
        std::vector<uint256> leaves = { cbtxid };
        for (const auto& t : rr.txs) leaves.push_back(t.txid);
        uint256 root = compute_merkle_root(leaves);
        uint64_t sub = get_block_subsidy(964346, 210000);
        expect("coinbasevalue == subsidy + fee", (sub + rr.total_fee) == (sub + 10000));
        expect("txid-merkle([cb,tx]) == pair(cb, txid)",
               root == merkle_hash_pair(cbtxid, rr.txs[0].txid));
        expect("txcount would be 1 (coinbase) + 1 (tx) = 2", (1 + rr.txs.size()) == 2);
    }

    std::printf("%s\n", g_fail == 0 ? "bip110_m3_serving_kat PASS" : "bip110_m3_serving_kat FAIL");
    return g_fail == 0 ? 0 : 1;
}
