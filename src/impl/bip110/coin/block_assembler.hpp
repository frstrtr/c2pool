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
// REWARD-SAFETY (money path). Four hard invariants make a selected set a VALID
// block or nothing:
//   (1) TOPOLOGY — a tx is a candidate only if it is fee_known AND every input
//       is either an in-template priced parent (emitted first) or a CONFIRMED &
//       MATURE coin in the post-anchor UTXO view (GAP2's inclusion rule). A
//       child whose parent is merely in a peer's mempool / a stale cached fee /
//       an evicted unconfirmed parent is EXCLUDED — including it alone is a
//       missing-inputs INVALID block.
//   (2) NO DOUBLE-SPEND — a claimed-outpoint set rejects any tx whose input was
//       already claimed by an earlier-emitted tx (GAP1 Layer B); a final
//       duplicate-outpoint sweep re-proves it independently. Combined with the
//       mempool's reject-at-add (GAP1 Layer A) an assembled block can never
//       double-spend => can never be consensus-invalid on that axis.
//   (3) SIGOPS — each candidate's Bitcoin-exact sigop cost (legacy×4 + P2SH×4 +
//       witness) is bounded by the conservative RDTS cap (GAP3); a tx over the
//       per-tx budget or with an unresolvable prevout script is EXCLUDED.
//   (4) VERIFY PASS — an O(n) pass proves every selected tx's in-template parent
//       appears earlier and no outpoint repeats; on any violation the offending
//       suffix is dropped (never emitted).
//
// Every skipped tx is NAMED (good-citizen: no silent drops). ZERO DASH code.
// ---------------------------------------------------------------------------

#include "mempool.hpp"
#include "transaction.hpp"
#include "sigops.hpp"
#include "../params.hpp"

#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
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
    uint32_t total_sigop_cost{0};
    // Named exclusions (good-citizen: never a silent drop).
    std::vector<std::pair<uint256, std::string>> excluded;
};

// GAP2/GAP3 — the confirmed-input view the assembler consults for inputs that
// are NOT in-template parents. is_confirmed_mature gates inclusion (an input
// must be a mature coin in the post-anchor UTXO view); script_of resolves that
// coin's scriptPubKey for sigop accounting. Both are built by the work source
// over the SAME UTXOViewCache the pricer used (mempool.hpp), so pricing and
// inclusion agree. In-template parent scripts are resolved by the assembler
// itself from the priced snapshot — the view only answers for confirmed coins.
struct ConfirmedInputView {
    std::function<bool(const uint256& txid, uint32_t index)> is_confirmed_mature;
    std::function<std::optional<std::vector<unsigned char>>(const uint256& txid, uint32_t index)> script_of;
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
//                 the child) from a confirmed parent.
//   max_weight  : selection cap in weight units (RDTS 800000 minus the coinbase
//                 reserve). BIP141 weight = base*4 + witness.
//   view        : GAP2/GAP3 confirmed-input view (inclusion + sigop scripts).
//   max_sigop_cost : RDTS block sigop-cost cap (GAP3).
inline AssemblyResult assemble_block_txs(const std::vector<MempoolEntry>& priced,
                                         const std::set<uint256>& pool_txids,
                                         uint32_t max_weight,
                                         const ConfirmedInputView& view,
                                         uint32_t max_sigop_cost = bip110::RDTS_MAX_BLOCK_SIGOPS_COST)
{
    AssemblyResult R;
    const size_t N = priced.size();
    if (N == 0) return R;

    // Coinbase reserve on the sigop budget (the coinbase itself carries a few).
    constexpr uint32_t COINBASE_SIGOP_RESERVE = 100;
    const uint32_t sigop_budget = (max_sigop_cost > COINBASE_SIGOP_RESERVE)
                                ? (max_sigop_cost - COINBASE_SIGOP_RESERVE) : 0;

    std::map<uint256, size_t> idx_of;
    for (size_t i = 0; i < N; ++i) idx_of[priced[i].txid] = i;

    // Resolve an input's prevout scriptPubKey: an in-template priced parent's
    // vout (from the snapshot) OR a confirmed coin (view). nullopt ⇒ unknown.
    auto resolve_script = [&](const uint256& ph, uint32_t idx)
        -> std::optional<std::vector<unsigned char>> {
        auto it = idx_of.find(ph);
        if (it != idx_of.end()) {
            const auto& vo = priced[it->second].tx.vout;
            if (idx < vo.size()) return vo[idx].scriptPubKey.m_data;
            return std::nullopt;
        }
        return view.script_of ? view.script_of(ph, idx) : std::nullopt;
    };

    std::vector<uint32_t> sigcost(N, 0);
    std::vector<std::string> unsafe_reason(N);

    // ── topo-safety + inclusion rule (GAP2) + sigops (GAP3): an entry is UNSAFE
    // iff any input is (a) an in-mempool UNPRICED parent, (b) not a confirmed &
    // mature coin (input-not-in-view-or-template), (c) transitively unsafe, or
    // the tx's own sigop cost is unresolvable / over budget. ──
    std::vector<int> safe(N, -1);   // -1 unknown, 0 unsafe, 1 safe
    std::vector<int> visiting(N, 0);
    std::function<bool(size_t)> is_safe = [&](size_t i) -> bool {
        if (safe[i] != -1) return safe[i] == 1;
        if (visiting[i]) return true;   // cycle guard (mempool is a DAG; defensive)
        visiting[i] = 1;
        bool ok = true;
        std::string reason;
        // BELT-1 — WITHIN-TX duplicate input (self-conflict). A tx whose own vin
        // lists an outpoint twice fabricates a positive fee via the pricer's
        // double-count (CVE-2018-17144 shape). check_transaction at add_tx already
        // rejects it, but this independent per-tx set makes it UNSAFE (never a
        // candidate, never emitted) even if a future add-path bug lets one in.
        std::set<std::pair<uint256, uint32_t>> own_ops;
        for (const auto& vin : priced[i].tx.vin) {
            const uint256& ph = vin.prevout.hash;
            if (!own_ops.insert({ph, vin.prevout.index}).second) {
                ok = false; reason = "self-conflict"; break;
            }
            auto it = idx_of.find(ph);
            if (it != idx_of.end()) {                 // in-mempool priced parent
                if (!is_safe(it->second)) { ok = false; reason = "unpriced-in-mempool-parent"; break; }
            } else if (pool_txids.count(ph)) {        // in-mempool but UNPRICED parent
                ok = false; reason = "unpriced-in-mempool-parent"; break;
            } else if (!view.is_confirmed_mature
                       || !view.is_confirmed_mature(ph, vin.prevout.index)) {
                // GAP2: parent not in the template AND not a confirmed/mature
                // coin in the UTXO view — including this child ALONE would be a
                // missing-inputs INVALID block. Fail closed.
                ok = false; reason = "input-not-in-view-or-template"; break;
            }
        }
        if (ok) {
            // GAP3: own sigop cost. Prevout scripts are resolvable under the
            // rule above (in-template parent vout or confirmed Coin), so nullopt
            // is genuinely exceptional ⇒ exclude.
            auto sc = sigops::tx_sigop_cost(priced[i].tx, resolve_script);
            if (!sc) { ok = false; reason = "sigops-unresolvable"; }
            else {
                sigcost[i] = *sc;
                if (*sc > sigop_budget) { ok = false; reason = "sigops-cap"; }
            }
        }
        visiting[i] = 0;
        safe[i] = ok ? 1 : 0;
        if (!ok) unsafe_reason[i] = reason;
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
    uint32_t total_sigop_cost = 0;
    // GAP1 Layer B — outpoints already claimed by an emitted tx in THIS template.
    std::set<std::pair<uint256, uint32_t>> claimed;

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
        uint64_t add_s = selected[c.i] ? 0 : sigcost[c.i];
        for (size_t a : ancestors(c.i)) if (!selected[a]) { add_w += priced[a].weight; add_s += sigcost[a]; }
        if (total_weight + add_w > max_weight) continue;        // deferred by weight
        if (total_sigop_cost + add_s > sigop_budget) continue;  // deferred by sigops

        std::vector<size_t> order;
        topo(c.i, order);   // emits only not-yet-emitted, parents first
        for (size_t j : order) {
            if (selected[j]) continue;
            // BELT-2 — WITHIN-TX self-conflict, detected on a per-tx local set
            // FIRST so a rejected tx's outpoints never poison the template-wide
            // `claimed` set (which would falsely exclude later honest txs). Layer
            // B below then checks `claimed` and bulk-inserts. is_safe already
            // marks self-conflict UNSAFE, so this is defense against add-path /
            // test-path (set_tx_fee) entries that bypass is_safe's exclusion.
            {
                bool self_conflict = false;
                std::set<std::pair<uint256, uint32_t>> own;
                for (const auto& vin : priced[j].tx.vin)
                    if (!own.insert({vin.prevout.hash, vin.prevout.index}).second) { self_conflict = true; break; }
                if (self_conflict) {
                    emitted[j] = 1;   // stays unselected; never counted / emitted
                    R.excluded.emplace_back(priced[j].txid, "self-conflict");
                    continue;
                }
            }
            // GAP1 Layer B — refuse any tx whose input was already claimed by an
            // earlier-emitted tx in this template. With Layer A (reject-at-add)
            // this is nearly unreachable in production, but it still catches
            // pre-restart state, set_tx_fee test paths, and future add-path bugs.
            bool conflict = false;
            for (const auto& vin : priced[j].tx.vin)
                if (claimed.count({vin.prevout.hash, vin.prevout.index})) { conflict = true; break; }
            if (conflict) {
                emitted[j] = 1;   // stays unselected; never counted / emitted
                R.excluded.emplace_back(priced[j].txid, "conflict");
                continue;
            }
            selected[j] = 1;
            for (const auto& vin : priced[j].tx.vin)
                claimed.insert({vin.prevout.hash, vin.prevout.index});
            total_weight     += priced[j].weight;
            total_fee        += priced[j].fee;
            total_sigop_cost += sigcost[j];
            AssembledTx at;
            at.tx     = priced[j].tx;
            at.txid   = priced[j].txid;
            at.wtxid  = compute_wtxid(priced[j].tx);
            at.weight = priced[j].weight;
            at.fee    = priced[j].fee;
            R.txs.push_back(std::move(at));
        }
    }

    // ── HARD verification pass (independent of the scorer): every in-template
    // parent MUST appear at a lower index, and NO outpoint may repeat across the
    // selected set. On any violation drop the offending suffix rather than emit
    // a consensus-invalid (missing-inputs / double-spend) set. ──
    {
        std::map<uint256, size_t> pos;
        std::set<std::pair<uint256, uint32_t>> seen_ops;
        size_t good = R.txs.size();
        for (size_t k = 0; k < R.txs.size(); ++k) {
            bool ok = true;
            for (const auto& vin : R.txs[k].tx.vin) {
                auto it = pos.find(vin.prevout.hash);
                // parent in our selected set but NOT earlier => invariant broken
                if (idx_of.count(vin.prevout.hash) && it == pos.end()) { ok = false; break; }
                // BELT-2 — insert-with-result: a failed insert means this outpoint
                // already appears, either in an EARLIER selected tx (across-tx
                // double-spend) OR earlier in THIS tx's own vin (within-tx dup /
                // CVE-2018-17144). Both trip ok=false and drop the offending suffix.
                if (!seen_ops.insert({vin.prevout.hash, vin.prevout.index}).second) { ok = false; break; }
            }
            if (!ok) { good = k; break; }
            pos[R.txs[k].txid] = k;
        }
        if (good < R.txs.size()) {
            for (size_t k = good; k < R.txs.size(); ++k) {
                total_weight     -= R.txs[k].weight;
                total_fee        -= R.txs[k].fee;
                total_sigop_cost -= sigcost[idx_of[R.txs[k].txid]];
                R.excluded.emplace_back(R.txs[k].txid, "verify-drop");
            }
            R.txs.resize(good);
        }
    }

    // Name every safe-but-unselected (weight/sigops defer) and unsafe drop.
    for (size_t i = 0; i < N; ++i) {
        if (selected[i]) continue;
        bool already = false;
        for (const auto& e : R.excluded) if (e.first == priced[i].txid) { already = true; break; }
        if (already) continue;
        if (safe[i] == 1) {
            R.excluded.emplace_back(priced[i].txid, "weight-cap");
        } else {
            R.excluded.emplace_back(priced[i].txid,
                unsafe_reason[i].empty() ? "unpriced-in-mempool-parent" : unsafe_reason[i]);
        }
    }

    R.total_fee = total_fee;
    R.total_weight = total_weight;
    R.total_sigop_cost = total_sigop_cost;
    return R;
}

} // namespace coin
} // namespace bip110
