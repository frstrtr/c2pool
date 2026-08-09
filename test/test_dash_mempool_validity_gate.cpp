// SPDX-License-Identifier: AGPL-3.0-or-later
//
// DASH MEMPOOL VALIDITY GATE — KATs for the condition that decides when
// --embedded-serve-mempool-txs may be armed (mempool_validity_gate.hpp).
//
// What these pin, in order of what they are worth:
//   1. The three-valued logic itself: allowed -> VALID; allowed==false with
//      reason "txn-already-in-mempool" -> ALSO VALID; ANY other reason ->
//      INVALID, and a defect.
//   2. That the exemption is by EXACT NAME. A near-miss reason string
//      ("txn-already-known") is INVALID, because widening the exemption set
//      widens the gate.
//   3. That a missing answer is UNPROBED, never a pass — "we could not ask" is
//      the failure mode the whole gate exists to remove.
//   4. That the REFUSAL line names the txid, dashd's reason string, and the
//      threshold (#1038/#1039 serve-gate discipline).
//   5. That the sustained window is what it says: a clean run advances only on
//      EVIDENCE-BEARING heights, dies on one INVALID, and empty heights neither
//      advance nor reset (576 empty heights must not open the gate).
//   6. That ours_only is nowhere in the gate: a set-membership divergence, of
//      any size, cannot close it, and a strict SUBSET containing an invalid
//      transaction DOES close it — the two directions the old condition got
//      wrong.

#include <gtest/gtest.h>

#include <impl/dash/coin/mempool_validity_gate.hpp>

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

using namespace dash::coin;

namespace {

MempoolProbeTx tx(const std::string& id, bool depends = false)
{
    MempoolProbeTx t;
    t.txid    = id;
    t.raw_hex = "0100000000";   // shape only; the daemon is the oracle here
    t.depends_on_in_set_parent = depends;
    return t;
}

nlohmann::json allowed_true(const std::string& id)
{
    return nlohmann::json{{"txid", id}, {"allowed", true}};
}

nlohmann::json refused(const std::string& id, const std::string& reason)
{
    return nlohmann::json{{"txid", id}, {"allowed", false},
                          {"reject-reason", reason}};
}

bool has_line_with(const std::vector<std::string>& lines, const std::string& needle)
{
    for (const auto& l : lines)
        if (l.find(needle) != std::string::npos) return true;
    return false;
}

// A run of `n` clean, evidence-bearing heights.
void feed_clean(MempoolValidityGate& g, uint64_t n, uint32_t from_height = 1000)
{
    for (uint64_t i = 0; i < n; ++i) {
        const auto set = std::vector<MempoolProbeTx>{tx("aa")};
        const auto ans = std::vector<nlohmann::json>{allowed_true("aa")};
        g.apply(mempool_validity_sample(
            static_cast<uint32_t>(from_height + i), set, ans));
    }
}

} // namespace

// ── 1. THE THREE-VALUED LOGIC ───────────────────────────────────────────────

TEST(DashMempoolValidityGate, AllowedIsValid) {
    const auto r = classify_mempool_accept(tx("aa"), allowed_true("aa"));
    EXPECT_EQ(r.verdict, MempoolAcceptVerdict::Valid);
    EXPECT_TRUE(r.reason.empty());
}

TEST(DashMempoolValidityGate, AlreadyInMempoolIsAlsoValid) {
    // dashd saying "I already hold this" is the STRONGEST statement that the
    // transaction is acceptable to it.
    const auto r = classify_mempool_accept(
        tx("bb"), refused("bb", "txn-already-in-mempool"));
    EXPECT_EQ(r.verdict, MempoolAcceptVerdict::AlreadyInMempool);
    EXPECT_EQ(r.reason, "txn-already-in-mempool");
}

TEST(DashMempoolValidityGate, AnyOtherReasonIsInvalidAndCarriesItVerbatim) {
    const auto r = classify_mempool_accept(
        tx("cc"), refused("cc", "bad-txns-inputs-spent"));
    EXPECT_EQ(r.verdict, MempoolAcceptVerdict::Invalid);
    EXPECT_EQ(r.reason, "bad-txns-inputs-spent");   // verbatim, not paraphrased
}

// ── 2. THE EXEMPTION IS BY EXACT NAME ───────────────────────────────────────

TEST(DashMempoolValidityGate, NearMissReasonIsNotExempted) {
    // "txn-already-known" is a DIFFERENT dashd reason (the transaction is in a
    // block / recently rejected, not in the mempool). Excusing it would widen
    // the gate by prefix-matching, and a tx we would serve that dashd has
    // already MINED is a staleness defect worth stopping on.
    for (const char* reason : {"txn-already-known",
                               "txn-already-in-mempool-ish",
                               "already-in-mempool"}) {
        const auto r = classify_mempool_accept(tx("dd"), refused("dd", reason));
        EXPECT_EQ(r.verdict, MempoolAcceptVerdict::Invalid)
            << "reason=" << reason << " must NOT be exempted";
    }
}

// ── 3. A MISSING ANSWER IS NEVER A PASS ─────────────────────────────────────

TEST(DashMempoolValidityGate, NoAnswerIsUnprobedNotValid) {
    const auto r = classify_mempool_accept(tx("ee"), nlohmann::json());
    EXPECT_EQ(r.verdict, MempoolAcceptVerdict::Unprobed);
    EXPECT_EQ(r.unprobed_cause, "no-answer");

    // And a short answers vector leaves the tail UNPROBED, never VALID.
    const std::vector<MempoolProbeTx> set{tx("e1"), tx("e2"), tx("e3")};
    const std::vector<nlohmann::json> ans{allowed_true("e1")};
    const auto s = mempool_validity_sample(2500000, set, ans);
    EXPECT_EQ(s.probed,   3u);
    EXPECT_EQ(s.valid,    1u);
    EXPECT_EQ(s.unprobed, 2u);
    EXPECT_EQ(s.invalid,  0u);
}

TEST(DashMempoolValidityGate, InSetParentMissingInputsIsUnprobedOnlyWithTheBuildTimeFact) {
    // A child probed ALONE cannot show dashd a parent that only rides our
    // template. That is an artefact of the one-tx probe shape, so it is
    // UNPROBED — but ONLY because the builder recorded the dependency.
    const auto excused = classify_mempool_accept(
        tx("ff", /*depends=*/true), refused("ff", "missing-inputs"));
    EXPECT_EQ(excused.verdict, MempoolAcceptVerdict::Unprobed);
    EXPECT_EQ(excused.reason, "missing-inputs");   // still reported verbatim

    // Same reason, NO recorded dependency: a genuine missing input. INVALID.
    const auto real = classify_mempool_accept(
        tx("ff", /*depends=*/false), refused("ff", "missing-inputs"));
    EXPECT_EQ(real.verdict, MempoolAcceptVerdict::Invalid);

    // The excuse does not generalise to other reasons just because the tx has
    // an in-set parent.
    const auto other = classify_mempool_accept(
        tx("ff", /*depends=*/true), refused("ff", "bad-txns-inputs-spent"));
    EXPECT_EQ(other.verdict, MempoolAcceptVerdict::Invalid);
}

// ── 4. THE REFUSAL LINE NAMES CAUSE, TXID, REASON AND THRESHOLD ─────────────

TEST(DashMempoolValidityGate, RefusalLineCarriesTxidReasonAndThreshold) {
    MempoolValidityGate g;
    const std::vector<MempoolProbeTx> set{tx("aa"), tx("deadbeefcafe")};
    const std::vector<nlohmann::json> ans{
        allowed_true("aa"),
        refused("deadbeefcafe", "bad-txns-inputs-spent")};
    const auto s = mempool_validity_sample(2518789, set, ans);
    g.apply(s);

    const auto lines = mempool_validity_log_lines(s, g);
    EXPECT_TRUE(has_line_with(lines, "REFUSED"));
    EXPECT_TRUE(has_line_with(lines, "txid=deadbeefcafe"));
    EXPECT_TRUE(has_line_with(lines, "reason=bad-txns-inputs-spent"));
    EXPECT_TRUE(has_line_with(
        lines, "threshold=" + std::to_string(g.required)));
    EXPECT_TRUE(has_line_with(lines, "h=2518789"));
    // The summary line is always emitted too, so a soak can read the series.
    EXPECT_TRUE(has_line_with(lines, "probed=2"));
    EXPECT_TRUE(has_line_with(lines, "gate=CLOSED"));
}

// ── 5. THE SUSTAINED WINDOW ─────────────────────────────────────────────────

TEST(DashMempoolValidityGate, GateOpensOnlyAfterTheFullCleanRun) {
    MempoolValidityGate g;
    ASSERT_EQ(g.required, MempoolValidityGate::kCleanHeightsRequired);
    EXPECT_FALSE(g.open());

    feed_clean(g, g.required - 1);
    EXPECT_EQ(g.consecutive_clean, g.required - 1);
    EXPECT_FALSE(g.open()) << "one height short must still be CLOSED";

    feed_clean(g, 1, 9000);
    EXPECT_TRUE(g.open());
    EXPECT_EQ(g.txs_invalid, 0u);
}

TEST(DashMempoolValidityGate, OneInvalidKillsTheWholeRun) {
    MempoolValidityGate g;
    feed_clean(g, g.required - 1);
    ASSERT_EQ(g.consecutive_clean, g.required - 1);

    const std::vector<MempoolProbeTx> set{tx("aa"), tx("bad")};
    const std::vector<nlohmann::json> ans{allowed_true("aa"),
                                          refused("bad", "bad-txns-inputs-spent")};
    g.apply(mempool_validity_sample(9999, set, ans));

    EXPECT_EQ(g.consecutive_clean, 0u);
    EXPECT_FALSE(g.open());
    EXPECT_EQ(g.txs_invalid, 1u);
    EXPECT_EQ(g.last_invalid_txid, "bad");
    EXPECT_EQ(g.last_invalid_reason, "bad-txns-inputs-spent");
    EXPECT_EQ(g.last_invalid_height, 9999u);
    // The high-water mark survives, so the reset is visible as a reset rather
    // than as "we never got anywhere".
    EXPECT_EQ(g.best_consecutive_clean, g.required - 1);
}

TEST(DashMempoolValidityGate, EmptyHeightsNeitherAdvanceNorResetTheRun) {
    MempoolValidityGate g;
    // A whole window of heights with nothing to probe proves NOTHING; letting
    // it open the gate would be the same vacuous pass the old condition had.
    for (uint64_t i = 0; i < g.required + 10; ++i)
        g.apply(mempool_validity_sample(static_cast<uint32_t>(1000 + i), {}, {}));
    EXPECT_FALSE(g.open());
    EXPECT_EQ(g.consecutive_clean, 0u);
    EXPECT_EQ(g.heights_with_evidence, 0u);
    EXPECT_EQ(g.heights_without_evidence, g.required + 10);

    // Nor do they RESET a run in progress.
    feed_clean(g, 5, 20000);
    ASSERT_EQ(g.consecutive_clean, 5u);
    g.apply(mempool_validity_sample(30000, {}, {}));
    EXPECT_EQ(g.consecutive_clean, 5u);
}

TEST(DashMempoolValidityGate, AnAllUnprobedHeightIsNotEvidence) {
    // Probing 40 transactions and getting 40 non-answers is not a clean height:
    // it is no measurement at all.
    MempoolValidityGate g;
    std::vector<MempoolProbeTx> set;
    std::vector<nlohmann::json> ans;
    for (int i = 0; i < 40; ++i) {
        set.push_back(tx("t" + std::to_string(i)));
        ans.push_back(nlohmann::json());
    }
    const auto s = mempool_validity_sample(2500001, set, ans);
    EXPECT_FALSE(s.evidence_bearing());
    EXPECT_FALSE(s.clean());
    g.apply(s);
    EXPECT_EQ(g.consecutive_clean, 0u);
    EXPECT_EQ(g.txs_unprobed, 40u);
}

TEST(DashMempoolValidityGate, AlreadyInMempoolAloneIsEnoughEvidenceToAdvance) {
    // A height whose every transaction dashd already holds IS a measurement of
    // validity — the strongest one available.
    MempoolValidityGate g;
    const std::vector<MempoolProbeTx> set{tx("aa"), tx("bb")};
    const std::vector<nlohmann::json> ans{
        refused("aa", "txn-already-in-mempool"),
        refused("bb", "txn-already-in-mempool")};
    const auto s = mempool_validity_sample(2500002, set, ans);
    EXPECT_TRUE(s.clean());
    g.apply(s);
    EXPECT_EQ(g.consecutive_clean, 1u);
    EXPECT_EQ(g.txs_already_in_mempool, 2u);
}

// ── 6. THE TWO DIRECTIONS THE OLD CONDITION GOT WRONG ───────────────────────

TEST(DashMempoolValidityGate, SetDivergenceOfAnySizeCannotCloseTheGate) {
    // Reproduces the hotel's worst measured sample: 287 transactions we hold
    // that dashd's template did not carry. Under `ours_only == 0` that is a
    // hard block. Under VALIDITY, if dashd accepts all of them, it is a clean
    // height — because the question is whether the transactions are
    // acceptable, not whether the two mempools coincide.
    MempoolValidityGate g;
    std::vector<MempoolProbeTx> set;
    std::vector<nlohmann::json> ans;
    for (int i = 0; i < 287; ++i) {
        const std::string id = "ours" + std::to_string(i);
        set.push_back(tx(id));
        ans.push_back(allowed_true(id));
    }
    const auto s = mempool_validity_sample(2518000, set, ans);
    EXPECT_TRUE(s.clean());
    EXPECT_EQ(s.valid, 287u);
    g.apply(s);
    EXPECT_EQ(g.consecutive_clean, 1u);
    EXPECT_EQ(g.txs_invalid, 0u);
}

TEST(DashMempoolValidityGate, AStrictSubsetWithOneInvalidTxStillClosesTheGate) {
    // The case the set-membership test is BLIND to: FEWER transactions than
    // dashd (a strict subset, ours_only == 0, the old gate PASSES) with one
    // that dashd would refuse. Serving it costs a whole block.
    MempoolValidityGate g;
    const std::vector<MempoolProbeTx> set{tx("a"), tx("b")};   // dashd has a,b,c
    const std::vector<nlohmann::json> ans{
        allowed_true("a"),
        refused("b", "bad-txns-inputs-missingorspent")};       // no in-set parent
    const auto s = mempool_validity_sample(2518001, set, ans);
    EXPECT_FALSE(s.clean());
    EXPECT_EQ(s.invalid, 1u);
    g.apply(s);
    EXPECT_FALSE(g.open());
    EXPECT_EQ(g.last_invalid_txid, "b");
}

// ── PROBE-SET ASSEMBLY off a DashWorkData ───────────────────────────────────

TEST(DashMempoolValidityGate, ProbeSetIsTheCandidateSetWhenNothingIsServed) {
    DashWorkData w;
    w.m_height = 2518002;
    w.m_txset_candidates.push_back(uint256::ONE);
    w.m_txset_candidate_data_hex.push_back("0100");
    w.m_mempool_probe_depends_in_set.push_back(0);

    const auto set = mempool_probe_set(w);
    ASSERT_EQ(set.size(), 1u);
    EXPECT_EQ(set[0].txid, uint256::ONE.GetHex());
    EXPECT_EQ(set[0].raw_hex, "0100");
    EXPECT_FALSE(set[0].depends_on_in_set_parent);
}

TEST(DashMempoolValidityGate, ProbeSetSkipsTheNonMempoolPrefixOfAServedBody) {
    // A served body is [type-6 commitments][pinned local txs][mempool txs].
    // Only the last range is mempool-sourced; the others are refused by relay
    // policy BY DESIGN and probing them would manufacture INVALID verdicts out
    // of correct behaviour.
    DashWorkData w;
    w.m_height = 2518003;
    w.m_tx_hashes = {uint256::ONE, uint256::ZERO, uint256::ONE};
    w.m_tx_data_hex = {"qc", "pin", "mempool"};
    w.m_mempool_tx_first_index = 2;
    w.m_mempool_tx_count       = 1;
    w.m_mempool_probe_depends_in_set = {0};

    const auto set = mempool_probe_set(w);
    ASSERT_EQ(set.size(), 1u);
    EXPECT_EQ(set[0].raw_hex, "mempool");
}

TEST(DashMempoolValidityGate, AMisPopulatedWorkDataProbesNothingRatherThanGuessing) {
    DashWorkData w;
    w.m_height = 2518004;
    // Range points past the end of the parallel vectors.
    w.m_tx_hashes   = {uint256::ONE};
    w.m_tx_data_hex = {"aa"};
    w.m_mempool_tx_first_index = 0;
    w.m_mempool_tx_count       = 5;
    EXPECT_TRUE(mempool_probe_set(w).empty());

    // Unaligned candidate vectors: also nothing.
    DashWorkData v;
    v.m_txset_candidates = {uint256::ONE, uint256::ZERO};
    v.m_txset_candidate_data_hex = {"aa"};
    EXPECT_TRUE(mempool_probe_set(v).empty());
}

// The gate reports itself, including that ours_only is informational — a soak
// reads JSON, not comments.
TEST(DashMempoolValidityGate, JsonNamesTheThresholdAndTheInformationalStatus) {
    MempoolValidityGate g;
    feed_clean(g, 3);
    const auto j = g.to_json();
    EXPECT_EQ(j["gate"], "CLOSED");
    EXPECT_EQ(j["clean-heights-required"], MempoolValidityGate::kCleanHeightsRequired);
    EXPECT_EQ(j["consecutive-clean-heights"], 3u);
    EXPECT_NE(std::string(j["ours-only"]).find("INFORMATIONAL"), std::string::npos);
}
