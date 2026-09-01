// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// bip110::coin::block_assembler — daemonless Bitcoin-native tx selection.
//
// BIP-110 is a Bitcoin fork (src/impl/bip110/ cloned from src/impl/btc/), so
// the tx/fee/weight/merkle model is IDENTICAL to Bitcoin and the selector is
// Bitcoin-Core's BlockAssembler::addPackageTxs (node/miner.cpp): ancestor
// fee-rate ordering with CPFP, under the block-weight cap. Because BIP-110 has
// NO coin daemon there is no getblocktemplate to hand us an ordered tx list —
// we build it ourselves from the embedded mempool.
//
// REWARD-SAFETY (money path): the cloned flat-feerate selector
// (mempool.hpp get_sorted_txs_with_fees) admits a CPFP child whose in-mempool
// parent is merely "present" without requiring the parent to be SELECTED AND
// ORDERED FIRST — a high-feerate child of a low-feerate parent could enter a
// template alone => missing-inputs => consensus-INVALID block => lost reward.
// This assembler fixes that with a HARD topological invariant:
//   (1) a tx is a candidate only if it is fee_known (priced snapshot) AND every
//       in-mempool parent is ALSO priced (else the parent could never be
//       included, so the child is excluded — fail closed);
//   (2) a selected package emits its unselected in-mempool ancestors FIRST, in
//       topological (parents-before-child) order;
//   (3) a final O(n) verification pass proves every selected tx's in-mempool
//       parents appear at a lower index — belt-and-suspenders against scorer
//       bugs; on any violation the offending suffix is dropped (never emitted).
//
// Every skipped tx is named (good-citizen: no silent drops). ZERO DASH code.
// ---------------------------------------------------------------------------

#include "mempool.hpp"
#include "transaction.hpp"

#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace bip110 {
namespace coin {

struct AssembledTx {
    MutableTransaction tx;
    uint256  txid;      // SHA256d(non-witness) — merkle/UTXO key
    uint256  wtxid;     // SHA256d(with-witness) — witness-commitment leaf
    uint32_t weight{0};
    uint64_t fee{0};
};

struct AssemblyResult {
    std::vector<AssembledTx> txs;        // block order (after coinbase)
    uint64_t total_fee{0};
    uint32_t total_weight{0};
    // Named exclusions (good-citizen: never a silent drop).
    std::vector<std::pair<uint256, std::string>> excluded;
};

// wtxid = SHA256d of the BIP144 (with-witness) serialization.
inline uint256 compute_wtxid(const MutableTransaction& tx) {
    auto packed = pack(TX_WITH_WITNESS(tx));
    return Hash(packed.get_span());
}

// Ancestor-package selection over an immutable priced snapshot.
//   priced      : fee_known mempool entries (Mempool::snapshot_priced()).
//   pool_txids  : ALL txids currently in the mempool (priced OR not). Needed to
//                 tell "in-mempool but unpriced parent" (topo-unsafe: exclude
//                 the child) from "confirmed / T2 / T3 parent" (safe: the input
//                 value is in the UTXO view, no in-block ancestor required).
//   max_weight  : selection cap in weight units (RDTS 800000 minus the coinbase
//                 reserve). BIP141 weight = base*4 + witness.
inline AssemblyResult assemble_block_txs(const std::vector<MempoolEntry>& priced,
                                         const std::set<uint256>& pool_txids,
                                         uint32_t max_weight)
{
    AssemblyResult R;
    const size_t N = priced.size();
    if (N == 0) return R;

    std::map<uint256, size_t> idx_of;
    for (size_t i = 0; i < N; ++i) idx_of[priced[i].txid] = i;

    // ── topo-safety: an entry is UNSAFE iff it (transitively) depends on an
    // in-mempool parent that is not priced (could never be included). ──
    std::vector<int> safe(N, -1);   // -1 unknown, 0 unsafe, 1 safe
    std::vector<int> visiting(N, 0);
    std::function<bool(size_t)> is_safe = [&](size_t i) -> bool {
        if (safe[i] != -1) return safe[i] == 1;
        if (visiting[i]) return true;   // cycle guard (mempool is a DAG; defensive)
        visiting[i] = 1;
        bool ok = true;
        for (const auto& vin : priced[i].tx.vin) {
            const uint256& ph = vin.prevout.hash;
            auto it = idx_of.find(ph);
            if (it != idx_of.end()) {           // in-mempool priced parent
                if (!is_safe(it->second)) { ok = false; break; }
            } else if (pool_txids.count(ph)) {  // in-mempool but UNPRICED parent
                ok = false; break;              // child can never be safely included
            }
            // else: parent confirmed / priced via UTXO view (T2) or side table
            // (T3) — its input value is already accounted, no in-block ancestor.
        }
        visiting[i] = 0;
        safe[i] = ok ? 1 : 0;
        return ok;
    };

    // In-mempool priced-ancestor closure (indices), memoized.
    std::vector<std::vector<size_t>> anc(N);
    std::vector<bool> anc_done(N, false);
    std::function<const std::vector<size_t>&(size_t)> ancestors = [&](size_t i) -> const std::vector<size_t>& {
        if (anc_done[i]) return anc[i];
        std::set<size_t> acc;
        for (const auto& vin : priced[i].tx.vin) {
            auto it = idx_of.find(vin.prevout.hash);
            if (it == idx_of.end()) continue;
            acc.insert(it->second);
            for (size_t a : ancestors(it->second)) acc.insert(a);
        }
        anc[i].assign(acc.begin(), acc.end());
        anc_done[i] = true;
        return anc[i];
    };

    // Package score = (self+ancestors fee) / (self+ancestors weight).
    struct Cand { size_t i; double score; uint64_t pkg_fee; uint64_t pkg_weight; };
    std::vector<Cand> cands;
    cands.reserve(N);
    for (size_t i = 0; i < N; ++i) {
        if (!is_safe(i)) continue;
        uint64_t pf = priced[i].fee, pw = priced[i].weight;
        for (size_t a : ancestors(i)) { pf += priced[a].fee; pw += priced[a].weight; }
        double sc = pw ? static_cast<double>(pf) / static_cast<double>(pw) : 0.0;
        cands.push_back({i, sc, pf, pw});
    }
    std::sort(cands.begin(), cands.end(),
              [](const Cand& a, const Cand& b) { return a.score > b.score; });

    // Topological (parents-before-child) emission order for a package.
    std::vector<char> selected(N, 0);
    std::vector<char> emitted(N, 0);
    uint32_t total_weight = 0;
    uint64_t total_fee = 0;

    std::function<void(size_t, std::vector<size_t>&)> topo = [&](size_t i, std::vector<size_t>& order) {
        if (emitted[i]) return;
        for (const auto& vin : priced[i].tx.vin) {
            auto it = idx_of.find(vin.prevout.hash);
            if (it != idx_of.end()) topo(it->second, order);
        }
        if (!emitted[i]) { emitted[i] = 1; order.push_back(i); }
    };

    for (const auto& c : cands) {
        if (selected[c.i]) continue;
        // Weight the package would ADD (ancestors already selected are free).
        uint64_t add_w = selected[c.i] ? 0 : priced[c.i].weight;
        for (size_t a : ancestors(c.i)) if (!selected[a]) add_w += priced[a].weight;
        if (total_weight + add_w > max_weight) continue;  // deferred by weight; try smaller

        std::vector<size_t> order;
        topo(c.i, order);   // emits only not-yet-emitted, parents first
        for (size_t j : order) {
            if (selected[j]) continue;
            selected[j] = 1;
            total_weight += priced[j].weight;
            total_fee    += priced[j].fee;
            AssembledTx at;
            at.tx     = priced[j].tx;
            at.txid   = priced[j].txid;
            at.wtxid  = compute_wtxid(priced[j].tx);
            at.weight = priced[j].weight;
            at.fee    = priced[j].fee;
            R.txs.push_back(std::move(at));
        }
    }

    // ── HARD verification pass (independent of the scorer): every in-mempool
    // parent MUST appear at a lower index. On any violation drop the offending
    // suffix rather than emit a consensus-invalid set. ──
    {
        std::map<uint256, size_t> pos;
        size_t good = R.txs.size();
        for (size_t k = 0; k < R.txs.size(); ++k) {
            bool ok = true;
            for (const auto& vin : R.txs[k].tx.vin) {
                auto it = pos.find(vin.prevout.hash);
                // parent in our selected set but NOT earlier => invariant broken
                if (idx_of.count(vin.prevout.hash) && it == pos.end()) { ok = false; break; }
            }
            if (!ok) { good = k; break; }
            pos[R.txs[k].txid] = k;
        }
        if (good < R.txs.size()) {
            for (size_t k = good; k < R.txs.size(); ++k) {
                total_weight -= R.txs[k].weight;
                total_fee    -= R.txs[k].fee;
                R.excluded.emplace_back(R.txs[k].txid, "topo-verify-drop");
            }
            R.txs.resize(good);
        }
    }

    // Name every safe-but-unselected (weight) and unsafe (unpriced-parent) drop.
    for (size_t i = 0; i < N; ++i) {
        if (selected[i]) continue;
        if (safe[i] == 1) {
            bool dropped = false;
            for (const auto& e : R.excluded) if (e.first == priced[i].txid) { dropped = true; break; }
            if (!dropped) R.excluded.emplace_back(priced[i].txid, "weight-cap");
        } else {
            R.excluded.emplace_back(priced[i].txid, "unpriced-in-mempool-parent");
        }
    }

    R.total_fee = total_fee;
    R.total_weight = total_weight;
    return R;
}

} // namespace coin
} // namespace bip110
