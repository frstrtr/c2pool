// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT: DASHD-FREE self-validated own-set tx serving.
//
// Pins the two invariants the --coin-rpc cut relies on for tx-serving, both
// exercised WITHOUT a live node or a daemon:
//
//   PART A — the mempool-validity CLASSIFIER (measurement, demoted from the
//   serve gate). RED→GREEN for the h=2526495 incident class: a "missing-inputs"
//   testmempoolaccept answer while dashd's probe-time tip is AHEAD of our serve
//   parent is a Window-1 propagation artefact, NOT a defect. Before the fix it
//   classified Invalid and RESET the clean run; after, it classifies
//   PendingPropagation and the clean run is UNTOUCHED. The narrowing is proven:
//   the SAME reject reason WITHOUT the dashd-ahead fact stays Invalid, and
//   `bad-txns-inputs-missingorspent` stays Invalid even WITH the ahead fact.
//
//   PART B — the serve-time internal-consistency REFEREE (the self-validation
//   the serve decision now depends on, making ZERO dashd calls). A template
//   whose selected tx has an input spent by another selected tx (intra-set
//   double-spend) is REFUSED by OUR OWN state; a clean template is SERVED. The
//   referee is a pure function of the template — it runs identically whether or
//   not a dashd is reachable, which is exactly what "serve with dashd
//   unreachable" means.
//
// Header-only units: no RPC, no daemon, no I/O. A pure red/green pin.

#include <impl/dash/coin/mempool_validity_gate.hpp>
#include <impl/dash/coin/tx_serve_referee.hpp>
#include <impl/dash/coin/subsidy.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/rpc_data.hpp>

#include <core/uint256.hpp>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <string>

using namespace dash::coin;

static int g_fail = 0;
#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        if (!(cond)) { std::printf("  FAIL: %s\n", (msg)); ++g_fail; }          \
        else         { std::printf("  ok:   %s\n", (msg)); }                    \
    } while (0)

// A single testmempoolaccept result object for one tx.
static nlohmann::json reject(const std::string& reason)
{
    nlohmann::json j;
    j["txid"]          = "deadbeef";
    j["allowed"]       = false;
    j["reject-reason"] = reason;
    return j;
}

static void part_a_classifier()
{
    std::printf("[PART A] mempool-validity classifier (Window-1 propagation)\n");

    // The incident class: missing-inputs while dashd is AHEAD of our serve
    // parent. This is the tx the network confirmed in the very block our
    // template competed for. GREEN: PendingPropagation, not a defect.
    {
        MempoolProbeTx tx;
        tx.txid                        = "8c4efd9c";
        tx.depends_on_in_set_parent    = false;
        tx.dashd_ahead_of_serve_height = true;
        const auto r = classify_mempool_accept(tx, reject("missing-inputs"));
        CHECK(r.verdict == MempoolAcceptVerdict::PendingPropagation,
              "missing-inputs + dashd-ahead -> PendingPropagation (was Invalid)");
    }

    // The narrowing, direction 1: the SAME reject WITHOUT the ahead fact stays
    // Invalid. The exemption is fact-gated, not reason-gated.
    {
        MempoolProbeTx tx;
        tx.txid                        = "no-skew";
        tx.depends_on_in_set_parent    = false;
        tx.dashd_ahead_of_serve_height = false;
        const auto r = classify_mempool_accept(tx, reject("missing-inputs"));
        CHECK(r.verdict == MempoolAcceptVerdict::Invalid,
              "missing-inputs WITHOUT dashd-ahead -> stays Invalid");
    }

    // The narrowing, direction 2: the conflating reason is NEVER excused, even
    // under the ahead skew. missingorspent conflates unknown-with-SPENT.
    {
        MempoolProbeTx tx;
        tx.txid                        = "spent";
        tx.depends_on_in_set_parent    = false;
        tx.dashd_ahead_of_serve_height = true;
        const auto r = classify_mempool_accept(
            tx, reject("bad-txns-inputs-missingorspent"));
        CHECK(r.verdict == MempoolAcceptVerdict::Invalid,
              "bad-txns-inputs-missingorspent + dashd-ahead -> STILL Invalid");
    }

    // txn-already-known (validation.cpp:854, TX_CONFLICT, non-punishable per
    // net_processing.cpp MaybePunishNodeForTx) while dashd is AHEAD of our serve
    // parent: dashd found the tx's OWN outputs already in its UTXO set — it is
    // CONFIRMED in the ahead block our still-valid fork template competed for
    // (the h=2526495 class). GREEN: PendingPropagation, not a defect.
    {
        MempoolProbeTx tx;
        tx.txid                        = "81109abf";
        tx.depends_on_in_set_parent    = false;
        tx.dashd_ahead_of_serve_height = true;
        const auto r = classify_mempool_accept(tx, reject("txn-already-known"));
        CHECK(r.verdict == MempoolAcceptVerdict::PendingPropagation,
              "txn-already-known + dashd-ahead -> PendingPropagation");
    }

    // REWARD-SAFE FAIL-CLOSED: the SAME reason WITHOUT the ahead fact means the
    // tx is confirmed in OUR OWN ancestry — a real double-inclusion that would
    // cost the block. It stays Invalid (and resets the clean run). Fact-gated,
    // widened only in the one direction the tx is provably valid on our fork.
    {
        MempoolProbeTx tx;
        tx.txid                        = "already-ours";
        tx.depends_on_in_set_parent    = false;
        tx.dashd_ahead_of_serve_height = false;
        const auto r = classify_mempool_accept(tx, reject("txn-already-known"));
        CHECK(r.verdict == MempoolAcceptVerdict::Invalid,
              "txn-already-known WITHOUT dashd-ahead -> stays Invalid");
    }

    // Gate arithmetic: a PendingPropagation sample neither advances nor RESETS
    // the clean run — the whole point of the demotion-to-measurement.
    {
        MempoolValidityGate g;

        // h=100: one clean valid tx -> consecutive_clean advances to 1.
        MempoolValiditySample s0; s0.height = 100; s0.probed = 1; s0.valid = 1;
        g.apply(s0);
        CHECK(g.consecutive_clean == 1, "clean height advances the run to 1");

        // h=101: only a Window-1 pending-propagation tx. evidence_bearing()
        // is false -> the run is UNTOUCHED (not advanced, not reset), and the
        // class is counted separately so it stays measurable.
        MempoolValiditySample s1; s1.height = 101; s1.probed = 1;
        s1.pending_propagation = 1;
        g.apply(s1);
        CHECK(g.consecutive_clean == 1,
              "pending-propagation-only height does NOT reset the run");
        CHECK(g.txs_pending_propagation == 1,
              "pending-propagation is counted (measurable, not hidden)");

        // h=102: a valid tx AND a pending-propagation tx together -> the run
        // advances (pending does not spoil an otherwise-clean height).
        MempoolValiditySample s2; s2.height = 102; s2.probed = 2; s2.valid = 1;
        s2.pending_propagation = 1;
        g.apply(s2);
        CHECK(g.consecutive_clean == 2,
              "valid+pending height advances; pending does not reset");

        // Contrast: a genuine Invalid DOES reset (the gate still catches real
        // defects — the asymmetry is preserved).
        MempoolValiditySample s3; s3.height = 103; s3.probed = 1; s3.invalid = 1;
        MempoolAcceptResult bad; bad.txid = "x"; bad.reason = "bad-cb-amount";
        bad.verdict = MempoolAcceptVerdict::Invalid; s3.invalids.push_back(bad);
        g.apply(s3);
        CHECK(g.consecutive_clean == 0, "a genuine Invalid still RESETS the run");
    }
}

// Build a minimal armed embedded template. `dup_outpoint` makes the two
// selected txs spend the SAME coin (intra-set double-spend); otherwise they
// spend distinct coins.
static DashWorkData make_template(bool dup_outpoint)
{
    DashWorkData w;
    w.m_height = 2526494;                 // post-V20 mainnet height
    w.m_mempool_tx_first_index = 0;
    w.m_mempool_tx_count       = 2;

    const uint64_t fee0 = 1000, fee1 = 2000;
    w.m_tx_fees = { fee0, fee1 };

    w.m_tx_serve_stamp.armed                       = true;
    w.m_tx_serve_stamp.all_mempool_fee_fold_proven = true;
    w.m_tx_serve_stamp.superblock_total            = 0;

    const uint64_t subsidy = static_cast<uint64_t>(
        compute_dash_block_reward_post_v20(w.m_height));
    // Coinbase is fee-exact by construction (what the referee re-asserts).
    w.m_coinbase_value = subsidy + fee0 + fee1;

    auto make_tx = [](const uint256& h, uint32_t idx) {
        MutableTransaction m;
        TxIn in; in.prevout.hash = h; in.prevout.index = idx; in.sequence = 0;
        m.vin.push_back(in);
        return Transaction(m);
    };

    const uint256 coinA = uint256S(
        "1111111111111111111111111111111111111111111111111111111111111111");
    const uint256 coinB = uint256S(
        "2222222222222222222222222222222222222222222222222222222222222222");

    w.m_txs.push_back(make_tx(coinA, 0));
    // Second tx: same outpoint (double-spend) or a distinct one.
    w.m_txs.push_back(make_tx(dup_outpoint ? coinA : coinB, 0));
    return w;
}

static void part_b_referee()
{
    std::printf("[PART B] serve-time internal-consistency referee (ZERO dashd)\n");

    // Clean template -> SERVE OUR OWN SET. No dashd consulted anywhere in the
    // call; the referee is a pure function of the template bytes.
    {
        const DashWorkData w = make_template(/*dup_outpoint=*/false);
        const TxServeRefereeVerdict v = tx_serve_internal_referee(w);
        CHECK(v.serve_own_set,
              "clean fee-exact non-conflicting template -> serve own set");
    }

    // Intra-set double-spend -> REFUSED by OUR OWN state (no dashd).
    {
        const DashWorkData w = make_template(/*dup_outpoint=*/true);
        const TxServeRefereeVerdict v = tx_serve_internal_referee(w);
        CHECK(!v.serve_own_set && v.fail_cause == "tx-serve-double-spend",
              "intra-set double-spend -> refused (tx-serve-double-spend)");
    }

    // Coinbase over-claim (the bad-cb-amount orphan vector) -> REFUSED by our
    // own subsidy re-derivation.
    {
        DashWorkData w = make_template(/*dup_outpoint=*/false);
        w.m_coinbase_value += 1;          // claim one duff too many
        const TxServeRefereeVerdict v = tx_serve_internal_referee(w);
        CHECK(!v.serve_own_set && v.fail_cause == "tx-serve-coinbase-inconsistent",
              "coinbase over-claim -> refused (tx-serve-coinbase-inconsistent)");
    }

    // Unstamped template (provenance) -> REFUSED.
    {
        DashWorkData w = make_template(/*dup_outpoint=*/false);
        w.m_tx_serve_stamp.armed = false;
        const TxServeRefereeVerdict v = tx_serve_internal_referee(w);
        CHECK(!v.serve_own_set && v.fail_cause == "tx-serve-unstamped",
              "unstamped template -> refused (tx-serve-unstamped)");
    }
}

int main()
{
    std::printf("== dash_tx_serve_self_validation_kat ==\n");
    part_a_classifier();
    part_b_referee();
    if (g_fail) {
        std::printf("RESULT: FAIL (%d checks failed)\n", g_fail);
        return 1;
    }
    std::printf("RESULT: PASS\n");
    return 0;
}
