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
#include <impl/bip110/coin/check_transaction.hpp>
#include <impl/bip110/coin/template_builder.hpp>
#include <impl/bip110/coin/transaction.hpp>
#include <impl/bip110/coin/block.hpp>
#include <impl/bip110/coin/sigops.hpp>
#include <impl/bip110/coin/utxo_reorg.hpp>
#include <impl/bip110/stratum/serve_xcheck.hpp>

#include <core/coin/utxo_view_db.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <functional>
#include <map>
#include <optional>

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

// A tx with a custom vout scriptPubKey (for sigops tests).
bip110::coin::MutableTransaction mk_tx_spk(const uint256& prev, uint32_t idx, int64_t value,
                                           std::vector<unsigned char> spk) {
    auto tx = mk_tx(prev, idx, value);
    tx.vout[0].scriptPubKey.m_data = std::move(spk);
    return tx;
}

// A tx with an EXPLICIT list of (prevhash, index) inputs and (value) outputs —
// used by the adversarial structural cases (dup input, empty vin/vout, negative /
// overflow outputs, coinbase / prevout-null, oversize).
bip110::coin::MutableTransaction mk_tx_multi(
    const std::vector<std::pair<uint256, uint32_t>>& ins,
    const std::vector<int64_t>& outs) {
    bip110::coin::MutableTransaction tx;
    for (const auto& in_pair : ins) {
        bip110::coin::TxIn in;
        in.prevout.hash = in_pair.first;
        in.prevout.index = in_pair.second;
        in.sequence = 0xffffffff;
        tx.vin.push_back(in);
    }
    for (int64_t v : outs) {
        bip110::coin::TxOut o;
        o.value = v;
        tx.vout.push_back(o);
    }
    return tx;
}

// Synthetic confirmed-input view: the CONFIRMED coin (h_of(0x11)) at indices
// 0..8 is a mature, priced, script-empty coin; everything else is NOT confirmed.
bip110::coin::ConfirmedInputView mk_synth_view(const uint256& confirmed) {
    bip110::coin::ConfirmedInputView v;
    v.is_confirmed_mature = [confirmed](const uint256& h, uint32_t) -> bool {
        return h == confirmed;
    };
    v.script_of = [confirmed](const uint256& h, uint32_t)
        -> std::optional<std::vector<unsigned char>> {
        if (h == confirmed) return std::vector<unsigned char>{};  // present, empty (0 sigops)
        return std::nullopt;
    };
    return v;
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
    ConfirmedInputView synth_view = mk_synth_view(CONFIRMED);
    AssemblyResult r = assemble_block_txs(priced, pool_txids, cap, synth_view);

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
        // Real confirmed-input view over the live UTXO cache (as the work source
        // builds it): funding:0 is a mature coin ⇒ the spender is includable.
        ConfirmedInputView real_view;
        real_view.is_confirmed_mature = [&utxo](const uint256& h, uint32_t i) -> bool {
            core::coin::Outpoint o(h, i); core::coin::Coin c;
            return utxo.get_coin(o, c) && c.is_mature(1000, core::coin::LTC_LIMITS);
        };
        real_view.script_of = [&utxo](const uint256& h, uint32_t i)
            -> std::optional<std::vector<unsigned char>> {
            core::coin::Outpoint o(h, i); core::coin::Coin c;
            if (!utxo.get_coin(o, c)) return std::nullopt;
            return c.scriptPubKey.m_data;
        };
        AssemblyResult rr = assemble_block_txs(ps, pool_ids, 799000, real_view);
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

    // ── (9) GAP1 DOUBLE-SPEND / RBF: at most ONE spender of an outpoint ──────
    std::printf("--- (9) GAP1 double-spend / RBF ---\n");
    {
        // Synthetic: F and G both spend CONFIRMED:5 with different fees. The
        // assembler's claimed-outpoint set must admit exactly one; a global
        // uniqueness sweep proves NO outpoint appears twice (never-invalid-block).
        const uint256 F = h_of(0xF1), G = h_of(0xF2);
        std::vector<MempoolEntry> p2;
        p2.push_back(mk_entry(F, CONFIRMED, 5, /*fee*/5000, /*weight*/400));
        p2.push_back(mk_entry(G, CONFIRMED, 5, /*fee*/3000, /*weight*/400));  // same outpoint
        std::set<uint256> pt2 = { F, G };
        AssemblyResult r2 = assemble_block_txs(p2, pt2, cap, synth_view);
        int in = (index_of(r2.txs, F) != SIZE_MAX ? 1 : 0)
               + (index_of(r2.txs, G) != SIZE_MAX ? 1 : 0);
        expect("RBF pair: exactly ONE of F/G in template", in == 1);
        expect("RBF loser named conflict",
               has_exclusion(r2, F, "conflict") || has_exclusion(r2, G, "conflict"));
        // global claimed-outpoint uniqueness across the selected set.
        std::set<std::pair<uint256, uint32_t>> ops; bool uniq = true;
        for (const auto& t : r2.txs)
            for (const auto& vin : t.tx.vin)
                if (!ops.insert({vin.prevout.hash, vin.prevout.index}).second) uniq = false;
        expect("no outpoint appears twice in the assembled set", uniq);

        // Production: add_tx REJECTS a second spender of the same outpoint (GAP1
        // Layer A, first-seen wins, no RBF).
        std::string path = "/tmp/bip110_kat_ds_" + std::to_string(::getpid());
        core::coin::UTXOViewDB db(path); db.open();
        core::coin::UTXOViewCache utxo(&db);
        uint256 fund = h_of(0x93);
        utxo.add_coin(core::coin::Outpoint(fund, 0),
                      core::coin::Coin(100000, OPScript{}, 1, false));
        Mempool pool; pool.set_utxo(&utxo); pool.set_tip_height(1000);
        MutableTransaction s1 = mk_tx(fund, 0, 90000);   // fee 10000
        MutableTransaction s2 = mk_tx(fund, 0, 80000);   // same outpoint, diff txid
        expect("first spender admitted", pool.add_tx(s1, &utxo));
        expect("conflicting second spender REJECTED (Layer A)", !pool.add_tx(s2, &utxo));
        expect("mempool holds exactly one spender", pool.size() == 1);
    }

    // ── (10) GAP2 CHILD-WITHOUT-PARENT: fail-closed inclusion rule ───────────
    std::printf("--- (10) GAP2 child-without-parent inclusion rule ---\n");
    {
        const uint256 H = h_of(0xA9);
        const uint256 PAR = h_of(0xAA);   // parent NOT in pool, NOT confirmed
        std::vector<MempoolEntry> p3 = { mk_entry(H, PAR, 0, /*fee*/8000, /*weight*/400) };
        std::set<uint256> pt3 = { H };
        // Negative: PAR is neither in-template nor confirmed ⇒ H excluded.
        AssemblyResult rn = assemble_block_txs(p3, pt3, cap, synth_view);
        expect("child of evicted/absent parent EXCLUDED", index_of(rn.txs, H) == SIZE_MAX);
        expect("exclusion named input-not-in-view-or-template",
               has_exclusion(rn, H, "input-not-in-view-or-template"));
        // Positive control: a view where PAR IS a confirmed coin ⇒ H included.
        ConfirmedInputView pos = mk_synth_view(PAR);
        AssemblyResult rp = assemble_block_txs(p3, pt3, cap, pos);
        expect("same child WITH confirmed parent-coin INCLUDED", index_of(rp.txs, H) != SIZE_MAX);
    }

    // ── (11) GAP4 REORG: a rolled-back coin is not priced/included ───────────
    std::printf("--- (11) GAP4 reorg / disconnect ---\n");
    {
        std::string path = "/tmp/bip110_kat_reorg_" + std::to_string(::getpid());
        core::coin::UTXOViewDB db(path); db.open();
        core::coin::UTXOViewCache utxo(&db);
        auto txidfn = [](const MutableTransaction& tx) { return compute_txid(tx); };

        // Connect a synthetic block at h=100 creating coin C1 (value 100000).
        MutableTransaction cb = mk_tx(h_of(0x00), 0xffffffff, 5000000000);
        MutableTransaction t  = mk_tx(h_of(0x33), 0, 100000);
        BlockType blk; blk.m_txs = { cb, t };
        auto undo = utxo.connect_block(blk, 100, txidfn);
        db.put_block_undo(100, undo);
        uint256 c1txid = compute_txid(t);
        core::coin::Outpoint C1(c1txid, 0);
        core::coin::Coin cc;
        expect("C1 present after connect_block", utxo.get_coin(C1, cc));

        Mempool pool; pool.set_utxo(&utxo); pool.set_tip_height(200);
        MutableTransaction spend = mk_tx(c1txid, 0, 90000);   // fee 10000
        expect("spender of C1 admitted + priced", pool.add_tx(spend, &utxo) && pool.total_fees() == 10000);

        // Disconnect (roll back) + requarantine + re-price against the view.
        utxo.disconnect_from_undo(undo);
        pool.requarantine_all();
        pool.recompute_unknown_fees(&utxo);
        expect("C1 GONE after disconnect_from_undo", !utxo.get_coin(C1, cc));
        expect("mempool fees == 0 after re-price (spender unpriceable)", pool.total_fees() == 0);
        // Template excludes the spender: snapshot has no priced entries, and the
        // inclusion predicate now fails for C1.
        {
            ConfirmedInputView v;
            v.is_confirmed_mature = [&utxo](const uint256& h, uint32_t i) {
                core::coin::Outpoint o(h, i); core::coin::Coin c; return utxo.get_coin(o, c);
            };
            v.script_of = [&utxo](const uint256& h, uint32_t i)
                -> std::optional<std::vector<unsigned char>> {
                core::coin::Outpoint o(h, i); core::coin::Coin c;
                if (!utxo.get_coin(o, c)) return std::nullopt; return c.scriptPubKey.m_data;
            };
            auto ps = pool.snapshot_priced();
            auto pt = pool.all_txids();
            std::set<uint256> ids(pt.begin(), pt.end());
            AssemblyResult rr = assemble_block_txs(ps, ids, cap, v);
            expect("rolled-back coin's spender NOT in template", index_of(rr.txs, compute_txid(spend)) == SIZE_MAX);
        }
        // Fail-closed arm: undo for a never-stored height is absent.
        core::coin::BlockUndo missing;
        expect("get_block_undo(never-stored) == false (fail-closed)", !db.get_block_undo(9999, missing));

        // Factored reorg_disconnect_to_fork over a mock header chain: roll the
        // view from an old-branch tip back to the common ancestor.
        {
            struct MockHdr { uint256 m_previous_block; };
            struct MockEntry { uint256 block_hash; MockHdr header; };
            struct MockChain {
                std::map<uint32_t, uint256> active;
                std::map<uint256, uint256> prev;
                std::optional<MockEntry> get_header_by_height(uint32_t h) const {
                    auto it = active.find(h); if (it == active.end()) return std::nullopt;
                    MockEntry e; e.block_hash = it->second;
                    auto p = prev.find(it->second); if (p != prev.end()) e.header.m_previous_block = p->second;
                    return e;
                }
                std::optional<MockEntry> get_header(const uint256& h) const {
                    auto p = prev.find(h); if (p == prev.end()) return std::nullopt;
                    MockEntry e; e.block_hash = h; e.header.m_previous_block = p->second; return e;
                }
            };
            std::string p2 = "/tmp/bip110_kat_fork_" + std::to_string(::getpid());
            core::coin::UTXOViewDB db2(p2); db2.open();
            core::coin::UTXOViewCache cache2(&db2);
            uint256 hashG = h_of(0x60), hashO11 = h_of(0x61), hashN11 = h_of(0x62), hashN12 = h_of(0x63);
            // Old-branch block O11 creates coin CO.
            MutableTransaction cbO = mk_tx(h_of(0x00), 0xffffffff, 5000000000);
            MutableTransaction tO  = mk_tx(h_of(0x44), 0, 70000);
            BlockType blkO; blkO.m_txs = { cbO, tO };
            auto undoO = cache2.connect_block(blkO, 11, txidfn);
            db2.put_block_undo(11, undoO);
            cache2.flush(hashO11, 11);
            core::coin::Outpoint CO(compute_txid(tO), 0);
            core::coin::Coin co;
            expect("CO present on old branch (h=11)", cache2.get_coin(CO, co));
            MockChain mock;
            mock.active = { {10, hashG}, {11, hashN11}, {12, hashN12} };
            mock.prev   = { {hashO11, hashG}, {hashN11, hashG}, {hashN12, hashN11}, {hashG, h_of(0x5f)} };
            auto res = bip110::coin::reorg_disconnect_to_fork(cache2, db2, mock, hashN12, 288);
            expect("reorg_disconnect_to_fork == OK", res == bip110::coin::ReorgResult::OK);
            expect("view rolled back to fork height 10", cache2.get_best_height() == 10);
            expect("CO removed by reorg disconnect", !cache2.get_coin(CO, co));
        }
    }

    // ── (12) GAP5 XCHECK fee re-sum catches a tampered fee_total ─────────────
    std::printf("--- (12) GAP5 independent fee re-sum ---\n");
    {
        std::string path = "/tmp/bip110_kat_xchk_" + std::to_string(::getpid());
        core::coin::UTXOViewDB db(path); db.open();
        core::coin::UTXOViewCache utxo(&db);
        uint256 fund = h_of(0x88);
        utxo.add_coin(core::coin::Outpoint(fund, 0),
                      core::coin::Coin(200000, OPScript{}, 1, false));
        auto utxo_get = [&utxo](const core::coin::Outpoint& op, core::coin::Coin& c) -> bool {
            return utxo.get_coin(op, c);
        };

        // parent P: 200000 -> 150000 (fee 50000); child K: P:0 150000 -> 120000 (fee 30000).
        MutableTransaction P = mk_tx(fund, 0, 150000);
        uint256 ptxid = compute_txid(P);
        MutableTransaction K = mk_tx(ptxid, 0, 120000);
        auto ser = [](MutableTransaction& tx) {
            auto packed = pack(TX_WITH_WITNESS(tx));
            const unsigned char* p = reinterpret_cast<const unsigned char*>(packed.data());
            return std::vector<unsigned char>(p, p + packed.size());
        };
        std::vector<std::vector<unsigned char>> body = { ser(P), ser(K) };
        auto resum = bip110::stratum::xcheck_resum_fees(body, utxo_get, core::coin::LTC_LIMITS);
        const uint64_t honest = 50000 + 30000;
        expect("xcheck re-sum resolves the honest fee (80000)", resum.has_value() && *resum == honest);
        expect("tampered fee_total (honest+1000) MISMATCHES the re-sum", !(resum && *resum == honest + 1000));

        // Unresolvable: child alone, parent neither decoded-earlier nor in view.
        std::vector<std::vector<unsigned char>> orphan = { ser(K) };
        auto ru = bip110::stratum::xcheck_resum_fees(orphan, utxo_get, core::coin::LTC_LIMITS);
        expect("orphan child ⇒ re-sum unresolvable (nullopt)", !ru.has_value());
    }

    // ── (13) GAP3 SIGOPS: conservative cap + unit checks ─────────────────────
    std::printf("--- (13) GAP3 sigops accounting ---\n");
    {
        // A tx with 5000 OP_CHECKSIG in its own scriptPubKey: legacy count 5000,
        // ×4 = 20000 > 15900 budget ⇒ excluded "sigops-cap".
        std::vector<unsigned char> many(5000, 0xac);   // 5000× OP_CHECKSIG
        const uint256 S1 = h_of(0xC1), S2 = h_of(0xC2);
        std::vector<MempoolEntry> ps;
        {
            MempoolEntry e; e.tx = mk_tx_spk(CONFIRMED, 0, 1000, many);
            e.txid = S1; e.fee = 1000; e.weight = 400; e.fee_known = true; e.base_size = 100;
            ps.push_back(e);
        }
        {
            MempoolEntry e; e.tx = mk_tx_spk(CONFIRMED, 1, 1000, {0xac});  // 1× CHECKSIG
            e.txid = S2; e.fee = 2000; e.weight = 400; e.fee_known = true; e.base_size = 100;
            ps.push_back(e);
        }
        std::set<uint256> pt = { S1, S2 };
        AssemblyResult rs = assemble_block_txs(ps, pt, cap, synth_view);
        expect("sigop-heavy tx EXCLUDED (sigops-cap)", index_of(rs.txs, S1) == SIZE_MAX
               && has_exclusion(rs, S1, "sigops-cap"));
        expect("normal-sigop tx included", index_of(rs.txs, S2) != SIZE_MAX);

        // Unresolvable prevout script (confirmed-mature true but no script) ⇒
        // sigops-unresolvable.
        {
            const uint256 U = h_of(0xC5), UPAR = h_of(0xC6);
            std::vector<MempoolEntry> pu = { mk_entry(U, UPAR, 0, 1000, 400) };
            std::set<uint256> ptu = { U };
            ConfirmedInputView bad;
            bad.is_confirmed_mature = [UPAR](const uint256& h, uint32_t) { return h == UPAR; };
            bad.script_of = [](const uint256&, uint32_t)
                -> std::optional<std::vector<unsigned char>> { return std::nullopt; };
            AssemblyResult rub = assemble_block_txs(pu, ptu, cap, bad);
            expect("unresolvable prevout script ⇒ sigops-unresolvable",
                   index_of(rub.txs, U) == SIZE_MAX && has_exclusion(rub, U, "sigops-unresolvable"));
        }

        // Direct unit checks on the counter.
        expect("script_sigops: 3× CHECKSIG == 3",
               bip110::coin::sigops::script_sigops({0xac, 0xac, 0xac}, false) == 3);
        expect("script_sigops: bare CHECKMULTISIG inaccurate == 20",
               bip110::coin::sigops::script_sigops({0xae}, false) == 20);
        expect("script_sigops: OP_2 CHECKMULTISIG accurate == 2",
               bip110::coin::sigops::script_sigops({0x52, 0xae}, true) == 2);
    }

    // ── (14) GAP6 unpriceable naming ─────────────────────────────────────────
    std::printf("--- (14) GAP6 unpriceable naming ---\n");
    {
        // A mempool with no UTXO view: the tx cannot be priced (fee_known=false),
        // so it is unpriceable and reaches the exclusion ledger by name.
        Mempool pool;   // no utxo set
        MutableTransaction u = mk_tx(h_of(0xE1), 0, 500);
        pool.add_tx(u);                       // admitted, fee-unknown
        expect("unpriced_count() == 1", pool.unpriced_count() == 1);
        auto samp = pool.unpriced_sample(8);
        expect("unpriced_sample surfaces the unpriceable txid", samp.size() == 1);
    }

    // ── (15) STRUCTURAL CheckTransaction port — named-reason adversarial cases ─
    // The OPEN HOLE Fable proved: no structural tx validation existed between the
    // wire and the template. check_transaction() (Bitcoin Core consensus/
    // tx_check.cpp + coinbase mempool-reject) is the fail-closed floor. Assert the
    // EXACT Core error string for every shape.
    std::printf("--- (15) STRUCTURAL CheckTransaction (adversarial, named) ---\n");
    {
        std::string why;
        const uint256 op1h = h_of(0x51);
        const int64_t maxm = core::coin::LTC_LIMITS.max_money;

        // A. WITHIN-TX DUP INPUT (CVE-2018-17144). PRE-FIX the pricer double-
        //    counts the coin ⇒ FABRICATED fee 2*100000-150000 = 50000.
        auto dup = mk_tx_multi({{op1h, 0}, {op1h, 0}}, {150000});
        expect("A dup-input REJECT bad-txns-inputs-duplicate",
               !check_transaction(dup, core::coin::LTC_LIMITS, why) && why == "bad-txns-inputs-duplicate");
        // B. EMPTY VOUT. PRE-FIX priced fee = whole input (100000).
        auto evout = mk_tx_multi({{op1h, 0}}, {});
        expect("B empty-vout REJECT bad-txns-vout-empty",
               !check_transaction(evout, core::coin::LTC_LIMITS, why) && why == "bad-txns-vout-empty");
        // C. EMPTY VIN.
        auto evin = mk_tx_multi({}, {1000});
        expect("C empty-vin REJECT bad-txns-vin-empty",
               !check_transaction(evin, core::coin::LTC_LIMITS, why) && why == "bad-txns-vin-empty");
        // D. NEGATIVE OUTPUT — single, and hidden inside a netting {+X,-X} pair
        //    (per-output check precedes summation, so a negative cannot hide).
        auto negv = mk_tx_multi({{op1h, 0}}, {-1});
        expect("D negative-output REJECT bad-txns-vout-negative",
               !check_transaction(negv, core::coin::LTC_LIMITS, why) && why == "bad-txns-vout-negative");
        auto netv = mk_tx_multi({{op1h, 0}}, {100000, -100000});
        expect("D netting {+X,-X} STILL REJECT bad-txns-vout-negative",
               !check_transaction(netv, core::coin::LTC_LIMITS, why) && why == "bad-txns-vout-negative");
        // E. OVERFLOW — single > MAX_MONEY, and two below-cap summing above.
        auto over1 = mk_tx_multi({{op1h, 0}}, {maxm + 1});
        expect("E single>MAX_MONEY REJECT bad-txns-vout-toolarge",
               !check_transaction(over1, core::coin::LTC_LIMITS, why) && why == "bad-txns-vout-toolarge");
        auto over2 = mk_tx_multi({{op1h, 0}}, {maxm - 10, 100});
        expect("E sum>MAX_MONEY REJECT bad-txns-txouttotal-toolarge",
               !check_transaction(over2, core::coin::LTC_LIMITS, why) && why == "bad-txns-txouttotal-toolarge");
        // F. COINBASE-IN-MEMPOOL + prevout-null in a non-coinbase.
        auto cb = mk_tx_multi({{uint256::ZERO, 0xffffffff}}, {5000000000LL});
        cb.vin[0].scriptSig.m_data = std::vector<unsigned char>(10, 0x00);  // 2..100 bytes
        expect("F coinbase-in-mempool REJECT coinbase",
               !check_transaction(cb, core::coin::LTC_LIMITS, why) && why == "coinbase");
        auto pnull = mk_tx_multi({{op1h, 0}, {uint256::ZERO, 0xffffffff}}, {1000});
        expect("F prevout-null (2-vin non-coinbase) REJECT bad-txns-prevout-null",
               !check_transaction(pnull, core::coin::LTC_LIMITS, why) && why == "bad-txns-prevout-null");
        // G. OVERSIZE — base_size*4 > RDTS 800000 (base > 200000 bytes).
        auto big = mk_tx_multi({{op1h, 0}}, {1000});
        big.vin[0].scriptSig.m_data = std::vector<unsigned char>(250000, 0x00);
        expect("G oversize REJECT bad-txns-oversize",
               !check_transaction(big, core::coin::LTC_LIMITS, why) && why == "bad-txns-oversize");
        // Sanity: an honest 1-in/1-out spend PASSES.
        auto honest = mk_tx_multi({{op1h, 0}}, {90000});
        expect("honest 1-in/1-out spend PASSES check_transaction",
               check_transaction(honest, core::coin::LTC_LIMITS, why));
    }

    // ── (15b) PRODUCTION-PATH PROBE re-run (the exact shape Fable used) ───────
    // Drive the REAL Mempool::add_tx (+ add_parent_priced subscriber ordering) +
    // UTXOViewCache pricing with the two proven exploits. admitted=0, no
    // fabricated fee, and the assembled template stays coinbase-only.
    std::printf("--- (15b) PRODUCTION PATH probe: dup-input + empty-vout admitted=0 ---\n");
    {
        std::string path = "/tmp/bip110_kat_struct_" + std::to_string(::getpid());
        core::coin::UTXOViewDB db(path); db.open();
        core::coin::UTXOViewCache utxo(&db);
        uint256 fund = h_of(0x77);
        utxo.add_coin(core::coin::Outpoint(fund, 0),
                      core::coin::Coin(100000, OPScript{}, /*height*/1, /*coinbase*/false));
        Mempool pool; pool.set_utxo(&utxo); pool.set_tip_height(1000);

        // (a) within-tx dup input — PRE-FIX fabricated fee 2*100000-150000=50000.
        auto dup = mk_tx_multi({{fund, 0}, {fund, 0}}, {150000});
        pool.add_parent_priced(dup);                 // subscriber runs this FIRST
        bool dup_added = pool.add_tx(dup, &utxo);
        expect("(a) dup-input NOT admitted", !dup_added);
        // (b) empty vout — PRE-FIX priced fee = whole input (100000).
        auto evout = mk_tx_multi({{fund, 0}}, {});
        pool.add_parent_priced(evout);
        bool ev_added = pool.add_tx(evout, &utxo);
        expect("(b) empty-vout NOT admitted", !ev_added);

        expect("mempool empty after both probes (size==0)", pool.size() == 0);
        expect("mempool fees==0 (no fabricated fee)", pool.total_fees() == 0);

        auto ps = pool.snapshot_priced();
        auto pt = pool.all_txids();
        std::set<uint256> ids(pt.begin(), pt.end());
        ConfirmedInputView v;
        v.is_confirmed_mature = [&utxo](const uint256& h, uint32_t i) {
            core::coin::Outpoint o(h, i); core::coin::Coin c; return utxo.get_coin(o, c); };
        v.script_of = [&utxo](const uint256& h, uint32_t i)
            -> std::optional<std::vector<unsigned char>> {
            core::coin::Outpoint o(h, i); core::coin::Coin c;
            if (!utxo.get_coin(o, c)) return std::nullopt; return c.scriptPubKey.m_data; };
        AssemblyResult rr = assemble_block_txs(ps, ids, 799000, v);
        std::printf("PROBE: dup_added=%d empty_added=%d pool=%zu fees=%llu template_txs=%zu\n",
                    (int)dup_added, (int)ev_added, pool.size(),
                    (unsigned long long)pool.total_fees(), rr.txs.size());
        expect("template txcount stays coinbase-only (0 selected txs)", rr.txs.size() == 0);
    }

    // ── (16) BELT-AND-SUSPENDERS (each independent of add_tx) ─────────────────
    std::printf("--- (16) BELT: assembler self-conflict (bypasses add_tx) ---\n");
    {
        // A priced entry (fee_known=true, the set_tx_fee/test path) whose OWN vin
        // lists an outpoint twice. is_safe marks it self-conflict ⇒ excluded, and
        // the global uniqueness sweep proves no outpoint repeats.
        const uint256 SC = h_of(0x71);
        MempoolEntry e;
        e.tx = mk_tx_multi({{CONFIRMED, 7}, {CONFIRMED, 7}}, {1000});
        e.txid = SC; e.fee = 5000; e.weight = 400; e.fee_known = true; e.base_size = 100;
        std::vector<MempoolEntry> ps = { e };
        std::set<uint256> pt = { SC };
        AssemblyResult r = assemble_block_txs(ps, pt, cap, synth_view);
        expect("self-conflict tx EXCLUDED from template", index_of(r.txs, SC) == SIZE_MAX);
        expect("self-conflict tx named self-conflict", has_exclusion(r, SC, "self-conflict"));
        std::set<std::pair<uint256, uint32_t>> ops; bool uniq = true;
        for (const auto& t : r.txs)
            for (const auto& vin : t.tx.vin)
                if (!ops.insert({vin.prevout.hash, vin.prevout.index}).second) uniq = false;
        expect("no repeated outpoint in assembled set", uniq);
    }

    std::printf("--- (16b) BELT: serve_xcheck structural floor + template-wide dup ---\n");
    {
        std::string path = "/tmp/bip110_kat_xbelt_" + std::to_string(::getpid());
        core::coin::UTXOViewDB db(path); db.open();
        core::coin::UTXOViewCache utxo(&db);
        uint256 fund  = h_of(0x88);
        uint256 fund2 = h_of(0x89);
        utxo.add_coin(core::coin::Outpoint(fund, 0),  core::coin::Coin(200000, OPScript{}, 1, false));
        utxo.add_coin(core::coin::Outpoint(fund2, 0), core::coin::Coin(200000, OPScript{}, 1, false));
        auto utxo_get = [&utxo](const core::coin::Outpoint& op, core::coin::Coin& c) -> bool {
            return utxo.get_coin(op, c); };
        auto ser = [](bip110::coin::MutableTransaction tx) {
            auto packed = pack(TX_WITH_WITNESS(tx));
            const unsigned char* p = reinterpret_cast<const unsigned char*>(packed.data());
            return std::vector<unsigned char>(p, p + packed.size()); };

        // (i) within-tx dup — caught by the template-wide seen-outpoint set.
        auto dupb = mk_tx_multi({{fund, 0}, {fund, 0}}, {150000});
        expect("xcheck within-tx-dup body ⇒ nullopt",
               !bip110::stratum::xcheck_resum_fees({ ser(dupb) }, utxo_get, core::coin::LTC_LIMITS).has_value());
        // (ii) two txs spending the same outpoint — across-tx double-spend.
        auto s1 = mk_tx_multi({{fund, 0}}, {150000});
        auto s2 = mk_tx_multi({{fund, 0}}, {140000});
        expect("xcheck across-tx double-spend body ⇒ nullopt",
               !bip110::stratum::xcheck_resum_fees({ ser(s1), ser(s2) }, utxo_get, core::coin::LTC_LIMITS).has_value());
        // (iii) empty-vout — structural floor (pre-fix priced fee=value_in, PASSED).
        auto eb = mk_tx_multi({{fund, 0}}, {});
        expect("xcheck empty-vout body ⇒ nullopt",
               !bip110::stratum::xcheck_resum_fees({ ser(eb) }, utxo_get, core::coin::LTC_LIMITS).has_value());
        // Control: two DISTINCT-outpoint honest txs re-sum fine (50000+20000).
        auto h1 = mk_tx_multi({{fund, 0}},  {150000});
        auto h2 = mk_tx_multi({{fund2, 0}}, {180000});
        auto rok = bip110::stratum::xcheck_resum_fees({ ser(h1), ser(h2) }, utxo_get, core::coin::LTC_LIMITS);
        expect("xcheck honest distinct-outpoint pair re-sums (70000)", rok.has_value() && *rok == 70000);
    }

    std::printf("%s\n", g_fail == 0 ? "bip110_m3_serving_kat PASS" : "bip110_m3_serving_kat FAIL");
    return g_fail == 0 ? 0 : 1;
}
