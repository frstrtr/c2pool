// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch_template_topology_spend (rides bch_g2_block_assembly_roundtrip_test)
// -- #1437 KAT.
//
// Pins bch::coin::Mempool::get_sorted_txs_with_fees() as a producer of a
// SELF-CONSISTENT block body. The embedded template builder feeds this set
// straight into transactions[] and the tx-merkle; if the set is not a valid
// block body, the daemon rejects the whole template
// (bad-txns-inputs-missingorspent) and the found block is LOST. BCH block order
// is canonical txid, but parent-PRESENCE and no-double-spend are still block
// validity invariants the naive selector violated.
//
// Two hazards the naive highest-feerate-first selector admitted, both proven
// here as regression witnesses and then proven fixed:
//   (a) child-without-parent -- a tx funded by another mempool tx (the parent)
//       absent from / ordered after the child.
//   (b) intra-template double-spend -- two mempool txs spending the SAME
//       outpoint both selected.
//
// HARNESS: the bch test tree is plain int main()/assert (no GTest), so this TU
// exposes run_template_topology_spend_checks() and rides the already-allowlisted
// bch_g2_block_assembly_roundtrip_test executable -- no build.yml --target
// allowlist change. Consensus surface: NONE (tx SELECTION only; minting/payout
// untouched). Per-coin isolation: src/impl/bch/ only.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <iostream>
#include <set>
#include <utility>
#include <vector>

#include <core/uint256.hpp>

#include <impl/bch/coin/mempool.hpp>
#include <impl/bch/coin/merkle.hpp>
#include <impl/bch/coin/transaction.hpp>

namespace {

using bch::coin::Mempool;
using bch::coin::MutableTransaction;
using bch::coin::TxIn;
using bch::coin::TxOut;
using bch::coin::compute_txid;
using bch::coin::compute_merkle_root;

int g_failures = 0;

void check(bool ok, const char* what)
{
    if (!ok) {
        ++g_failures;
        std::cerr << "  FAIL: " << what << "\n";
    }
}

// One-in, one-out payment. The output value tags the tx so distinct txids fall
// out even when two txs spend the same input (the double-spend pair).
MutableTransaction pay(const uint256& prev_hash, uint32_t prev_index, int64_t out_value)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash  = prev_hash;
    in.prevout.index = prev_index;
    in.sequence      = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = out_value;
    tx.vout.push_back(out);
    return tx;
}

uint256 h(const char* hex) { uint256 v; v.SetHex(hex); return v; }

const uint256 CONFIRMED_A = h("00000000000000000000000000000000000000000000000000000000000000a1");
const uint256 CONFIRMED_X = h("00000000000000000000000000000000000000000000000000000000000000b2");

std::set<uint256> txid_set(const std::vector<Mempool::SelectedTx>& sel)
{
    std::set<uint256> s;
    for (const auto& t : sel) s.insert(compute_txid(t.tx));
    return s;
}

bool has(const std::set<uint256>& s, const uint256& id) { return s.count(id) != 0; }

// BCH selection uses raw bytes as the budget; cap large enough to admit all.
const uint32_t BCH_CAP = 32'000'000u;

} // namespace

int run_template_topology_spend_checks()
{
    g_failures = 0;

    // -- Test 1b: child whose parent cannot be selected is EXCLUDED -----------
    {
        Mempool mp;
        MutableTransaction P = pay(CONFIRMED_A, 0, 100000);
        uint256 pid = compute_txid(P);
        MutableTransaction C = pay(pid, 0, 90000);
        uint256 cid = compute_txid(C);

        check(mp.add_tx(P), "1b: add parent (fee unknown)");
        check(mp.add_tx(C), "1b: add child");
        mp.set_tx_fee(cid, 8000);   // child fee known; parent stays unknown

        auto [sel, fees] = mp.get_sorted_txs_with_fees(BCH_CAP);
        auto s = txid_set(sel);
        check(!has(s, cid), "1b: child-without-parent excluded (else lost block)");
        check(!has(s, pid), "1b: unknown-fee parent not selected");
        check(sel.empty(), "1b: empty template");
        check(fees == 0u, "1b: zero fees");
    }

    // -- Test 1a: CPFP child selected alongside its parent (both present) ------
    {
        Mempool mp;
        MutableTransaction P = pay(CONFIRMED_A, 0, 100000);
        uint256 pid = compute_txid(P);
        MutableTransaction C = pay(pid, 0, 90000);
        uint256 cid = compute_txid(C);

        check(mp.add_tx(P), "1a: add parent");
        check(mp.add_tx(C), "1a: add child");
        mp.set_tx_fee(pid, 200);    // low feerate parent
        mp.set_tx_fee(cid, 8000);   // high feerate child (CPFP)

        auto [sel, fees] = mp.get_sorted_txs_with_fees(BCH_CAP);
        auto s = txid_set(sel);
        check(sel.size() == 2u, "1a: both parent and child ship");
        check(has(s, pid) && has(s, cid), "1a: parent present with child");
        check(fees == 200u + 8000u, "1a: both fees counted (reward-neutral)");
    }

    // -- Test 2: intra-template double-spend -> only one spender ships --------
    {
        Mempool mp;
        MutableTransaction D1 = pay(CONFIRMED_X, 0, 100000);
        MutableTransaction D2 = pay(CONFIRMED_X, 0, 90000);   // same input
        uint256 d1 = compute_txid(D1);
        uint256 d2 = compute_txid(D2);
        check(d1 != d2, "2: distinct double-spend txids");

        check(mp.add_tx(D1), "2: add D1");
        check(mp.add_tx(D2), "2: add D2");
        mp.set_tx_fee(d1, 5000);    // higher feerate -> visited first -> wins
        mp.set_tx_fee(d2, 1000);

        auto [sel, fees] = mp.get_sorted_txs_with_fees(BCH_CAP);
        check(sel.size() == 1u, "2: only one double-spender admitted (else lost block)");
        check(!sel.empty() && compute_txid(sel[0].tx) == d1, "2: higher-feerate spender wins");
        check(fees == 5000u, "2: winner's fee only");

        int consumers = 0;
        for (const auto& t : sel)
            for (const auto& vin : t.tx.vin)
                if (vin.prevout.hash == CONFIRMED_X && vin.prevout.index == 0) ++consumers;
        check(consumers == 1, "2: shared outpoint consumed exactly once");
    }

    // -- Test 3: pruned set is a valid body + tx-merkle over exactly that set --
    {
        Mempool mp;
        MutableTransaction A = pay(h("00000000000000000000000000000000000000000000000000000000000000c3"), 0, 50000);
        uint256 aid = compute_txid(A);
        MutableTransaction D1 = pay(CONFIRMED_X, 0, 100000);
        MutableTransaction D2 = pay(CONFIRMED_X, 0, 90000);
        uint256 d1 = compute_txid(D1), d2 = compute_txid(D2);
        MutableTransaction OP = pay(CONFIRMED_A, 0, 70000);
        uint256 opid = compute_txid(OP);
        MutableTransaction OC = pay(opid, 0, 60000);
        uint256 ocid = compute_txid(OC);

        check(mp.add_tx(A), "3: add A");
        check(mp.add_tx(D1), "3: add D1");
        check(mp.add_tx(D2), "3: add D2");
        check(mp.add_tx(OP), "3: add OP (fee unknown)");
        check(mp.add_tx(OC), "3: add OC");
        mp.set_tx_fee(aid, 3000);
        mp.set_tx_fee(d1, 5000);
        mp.set_tx_fee(d2, 4000);
        mp.set_tx_fee(ocid, 8000);

        auto [sel, fees] = mp.get_sorted_txs_with_fees(BCH_CAP);
        auto s = txid_set(sel);
        check(!has(s, d2), "3: losing double-spender excluded");
        check(!has(s, ocid), "3: orphan child excluded");
        check(!has(s, opid), "3: unknown-fee parent excluded");
        check(has(s, aid), "3: clean tx included");
        check(has(s, d1), "3: winning double-spender included");
        check(fees == 3000u + 5000u, "3: fees == included known fees");

        // Invariant (i): no shared input across the selected set.
        std::set<std::pair<uint256, uint32_t>> consumed;
        bool no_dup = true;
        for (const auto& t : sel)
            for (const auto& vin : t.tx.vin) {
                auto op = std::make_pair(vin.prevout.hash, vin.prevout.index);
                if (consumed.count(op)) no_dup = false;
                consumed.insert(op);
            }
        check(no_dup, "3: no double-spend survived pruning");

        // Invariant (ii): any selected tx whose input funds from a MEMPOOL tx
        // must have that parent in the selected set (BCH order is canonical
        // txid, so we assert presence, not position). A selected tx spending
        // the excluded orphan parent OP would fail this.
        const std::set<uint256> pool_ids{aid, d1, d2, opid, ocid};
        bool parents_present = true;
        for (const auto& t : sel)
            for (const auto& vin : t.tx.vin)
                if (pool_ids.count(vin.prevout.hash) && !has(s, vin.prevout.hash))
                    parents_present = false;   // selected child of an unselected mempool parent
        check(parents_present, "3: every mempool parent of a selected tx is present");

        // Invariant (iii): tx-merkle over exactly the pruned set is well-defined
        // and differs from the merkle over the invalid full set.
        std::vector<uint256> leaves;
        for (const auto& t : sel) leaves.push_back(compute_txid(t.tx));
        uint256 pruned_root = compute_merkle_root(leaves);
        check(pruned_root != uint256::ZERO, "3: pruned merkle non-zero");
        check(pruned_root == compute_merkle_root(leaves), "3: pruned merkle deterministic");

        std::vector<uint256> with_bad = leaves;
        with_bad.push_back(d2);
        with_bad.push_back(ocid);
        check(pruned_root != compute_merkle_root(with_bad),
              "3: merkle over the invalid full set differs from the pruned set");
    }

    if (g_failures == 0)
        std::cout << "  template_topology_spend: all checks passed\n";
    return g_failures;
}
