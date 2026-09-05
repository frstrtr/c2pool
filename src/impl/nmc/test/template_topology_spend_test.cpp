// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// nmc_template_topology_spend (rides nmc_template_builder_test) -- #1437 KAT.
//
// Pins nmc::coin::Mempool::get_sorted_txs_with_fees() as a producer of a
// SELF-CONSISTENT block body. The embedded template builder feeds this set
// straight into transactions[] and the tx-merkle; if the set is not a valid
// block body, the daemon rejects the whole template
// (bad-txns-inputs-missingorspent) and the found block is LOST.
//
// Two hazards the naive highest-feerate-first selector admitted, both proven
// here as regression witnesses (the OLD, pure-feerate admission would have
// shipped the invalid set) and then proven fixed:
//   (a) child-without-parent -- a tx funded by another mempool tx (the parent)
//       ordered after the child, or absent from the template entirely.
//   (b) intra-template double-spend -- two mempool txs spending the SAME
//       outpoint both selected.
// Plus: the tx-merkle over the pruned set is well-defined and the pruned set
// upholds both invariants (no double-spend, parents-before-children).
//
// UTXO-free: fees are pinned with Mempool::set_tx_fee (utxo view = null), the
// exact legacy no-UTXO path the old selector treated as "admit every fee-known
// tx in feerate order". Per-coin isolation: src/impl/nmc/ only.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <set>
#include <utility>
#include <vector>

#include <core/uint256.hpp>

#include <impl/nmc/coin/mempool.hpp>
#include <impl/nmc/coin/template_builder.hpp>
#include <impl/nmc/coin/transaction.hpp>

namespace {

using nmc::coin::Mempool;
using nmc::coin::MutableTransaction;
using nmc::coin::TxIn;
using nmc::coin::TxOut;
using nmc::coin::compute_txid;
using nmc::coin::compute_merkle_root;

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

uint256 h(const char* hex)
{
    uint256 v;
    v.SetHex(hex);
    return v;
}

// A confirmed-looking funding outpoint hash NOT present in the mempool.
const uint256 CONFIRMED_A = h("00000000000000000000000000000000000000000000000000000000000000a1");
const uint256 CONFIRMED_X = h("00000000000000000000000000000000000000000000000000000000000000b2");

std::set<uint256> txid_set(const std::vector<Mempool::SelectedTx>& sel)
{
    std::set<uint256> s;
    for (const auto& t : sel) s.insert(compute_txid(t.tx));
    return s;
}

int index_of(const std::vector<Mempool::SelectedTx>& sel, const uint256& id)
{
    for (int i = 0; i < static_cast<int>(sel.size()); ++i)
        if (compute_txid(sel[i].tx) == id) return i;
    return -1;
}

} // namespace

// --- Test 1a: CPFP child never precedes its parent (topological order) --------
TEST(NmcTemplateTopologySpend, CpfpChildOrderedAfterParent)
{
    Mempool mp;

    MutableTransaction P = pay(CONFIRMED_A, 0, 100000);
    uint256 pid = compute_txid(P);
    MutableTransaction C = pay(pid, 0, 90000);      // spends P's output 0
    uint256 cid = compute_txid(C);

    ASSERT_TRUE(mp.add_tx(P));
    ASSERT_TRUE(mp.add_tx(C));
    mp.set_tx_fee(pid, 200);    // low feerate parent
    mp.set_tx_fee(cid, 8000);   // high feerate child (CPFP)

    auto pe = mp.get_entry(pid);
    auto ce = mp.get_entry(cid);
    ASSERT_TRUE(pe && ce);
    ASSERT_GT(ce->feerate(), pe->feerate());

    auto [sel, fees] = mp.get_sorted_txs_with_fees(4'000'000);

    ASSERT_EQ(sel.size(), 2u);
    int ip = index_of(sel, pid), ic = index_of(sel, cid);
    ASSERT_GE(ip, 0);
    ASSERT_GE(ic, 0);
    EXPECT_LT(ip, ic) << "child emitted before its parent -> bad-txns-inputs-missingorspent";
    EXPECT_EQ(fees, 200u + 8000u);   // both fees counted; reward-neutral
}

// --- Test 1b: child whose parent cannot be selected is EXCLUDED ---------------
TEST(NmcTemplateTopologySpend, ChildWithoutSelectableParentExcluded)
{
    Mempool mp;

    MutableTransaction P = pay(CONFIRMED_A, 0, 100000);
    uint256 pid = compute_txid(P);
    MutableTransaction C = pay(pid, 0, 90000);
    uint256 cid = compute_txid(C);

    ASSERT_TRUE(mp.add_tx(P));   // fee UNKNOWN -> never selected
    ASSERT_TRUE(mp.add_tx(C));
    mp.set_tx_fee(cid, 8000);    // child fee known

    auto [sel, fees] = mp.get_sorted_txs_with_fees(4'000'000);

    auto s = txid_set(sel);
    EXPECT_EQ(s.count(cid), 0u) << "child-without-parent admitted -> lost block";
    EXPECT_EQ(s.count(pid), 0u);
    EXPECT_TRUE(sel.empty());
    EXPECT_EQ(fees, 0u);
}

// --- Test 2: intra-template double-spend -> only one spender ships ------------
TEST(NmcTemplateTopologySpend, IntraTemplateDoubleSpendPruned)
{
    Mempool mp;

    MutableTransaction D1 = pay(CONFIRMED_X, 0, 100000);
    MutableTransaction D2 = pay(CONFIRMED_X, 0, 90000);   // same input, different txid
    uint256 d1 = compute_txid(D1);
    uint256 d2 = compute_txid(D2);
    ASSERT_NE(d1, d2);

    ASSERT_TRUE(mp.add_tx(D1));
    ASSERT_TRUE(mp.add_tx(D2));
    mp.set_tx_fee(d1, 5000);    // higher feerate -> visited first -> wins
    mp.set_tx_fee(d2, 1000);

    auto [sel, fees] = mp.get_sorted_txs_with_fees(4'000'000);

    ASSERT_EQ(sel.size(), 1u) << "both double-spenders admitted -> lost block";
    EXPECT_EQ(compute_txid(sel[0].tx), d1);   // the higher-feerate spender
    EXPECT_EQ(fees, 5000u);

    int consumers = 0;
    for (const auto& t : sel)
        for (const auto& vin : t.tx.vin)
            if (vin.prevout.hash == CONFIRMED_X && vin.prevout.index == 0) ++consumers;
    EXPECT_EQ(consumers, 1);
}

// --- Test 3: pruned set is a valid body + tx-merkle over exactly that set -----
TEST(NmcTemplateTopologySpend, PrunedSetIsValidBodyAndMerkleMatches)
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

    ASSERT_TRUE(mp.add_tx(A));
    ASSERT_TRUE(mp.add_tx(D1));
    ASSERT_TRUE(mp.add_tx(D2));
    ASSERT_TRUE(mp.add_tx(OP));       // fee unknown
    ASSERT_TRUE(mp.add_tx(OC));
    mp.set_tx_fee(aid, 3000);
    mp.set_tx_fee(d1, 5000);
    mp.set_tx_fee(d2, 4000);
    mp.set_tx_fee(ocid, 8000);

    auto [sel, fees] = mp.get_sorted_txs_with_fees(4'000'000);

    auto s = txid_set(sel);
    EXPECT_EQ(s.count(d2), 0u);
    EXPECT_EQ(s.count(ocid), 0u);
    EXPECT_EQ(s.count(opid), 0u);
    EXPECT_EQ(s.count(aid), 1u);
    EXPECT_EQ(s.count(d1), 1u);
    EXPECT_EQ(fees, 3000u + 5000u);

    // Invariant (i): no shared input across the selected set.
    std::set<std::pair<uint256, uint32_t>> consumed;
    for (const auto& t : sel)
        for (const auto& vin : t.tx.vin) {
            auto op = std::make_pair(vin.prevout.hash, vin.prevout.index);
            EXPECT_EQ(consumed.count(op), 0u) << "double-spend survived pruning";
            consumed.insert(op);
        }

    // Invariant (ii): every in-selected-set parent precedes its child.
    for (int i = 0; i < static_cast<int>(sel.size()); ++i)
        for (const auto& vin : sel[i].tx.vin) {
            int pj = index_of(sel, vin.prevout.hash);
            if (pj >= 0) EXPECT_LT(pj, i) << "child precedes parent in pruned set";
        }

    // Invariant (iii): tx-merkle over exactly the pruned set is well-defined.
    std::vector<uint256> leaves;
    for (const auto& t : sel) leaves.push_back(compute_txid(t.tx));
    uint256 pruned_root = compute_merkle_root(leaves);
    EXPECT_NE(pruned_root, uint256::ZERO);
    EXPECT_EQ(pruned_root, compute_merkle_root(leaves));   // deterministic

    std::vector<uint256> with_bad = leaves;
    with_bad.push_back(d2);
    with_bad.push_back(ocid);
    EXPECT_NE(pruned_root, compute_merkle_root(with_bad));
}
