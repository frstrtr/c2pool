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

// ONE clean, evidence-bearing sample AT a given height.
void feed_clean_sample_at(MempoolValidityGate& g, uint32_t height)
{
    const auto set = std::vector<MempoolProbeTx>{tx("aa")};
    const auto ans = std::vector<nlohmann::json>{allowed_true("aa")};
    g.apply(mempool_validity_sample(height, set, ans));
}

// A run of `n` clean, evidence-bearing heights — one sample each, ADVANCING.
void feed_clean(MempoolValidityGate& g, uint64_t n, uint32_t from_height = 1000)
{
    for (uint64_t i = 0; i < n; ++i)
        feed_clean_sample_at(g, static_cast<uint32_t>(from_height + i));
}

// `n` clean samples that all land on THE SAME height — the shape the probe
// cadence actually produces (on_serve fires per template re-source: every
// work-generation bump and every 30 s staleness re-poll, ~5-6 times inside one
// 157.5 s DASH block).
void feed_clean_repeats_at(MempoolValidityGate& g, uint64_t n, uint32_t height)
{
    for (uint64_t i = 0; i < n; ++i) feed_clean_sample_at(g, height);
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
    // None of these is the exact "txn-already-in-mempool" name. Excusing them
    // would widen the gate by prefix-matching. "txn-already-known" is a REAL
    // dashd reason (the tx is already CONFIRMED in dashd's chain), but WITHOUT
    // tip context (the default here) we cannot tell benign propagation from a
    // current-tip staleness defect, so the conservative reading is INVALID —
    // exactly the pre-tip-context behaviour, and the gate-CLOSED direction.
    // The tip-aware benign path is pinned separately below.
    for (const char* reason : {"txn-already-known",
                               "txn-already-in-mempool-ish",
                               "already-in-mempool"}) {
        const auto r = classify_mempool_accept(tx("dd"), refused("dd", reason));
        EXPECT_EQ(r.verdict, MempoolAcceptVerdict::Invalid)
            << "reason=" << reason << " must NOT be exempted without tip context";
    }
}

// ── 2b. THE PROPAGATION WINDOW: "txn-already-known" IS TIP-CONDITIONAL ───────
//
// FIELD MEASUREMENT (creditpool-arm + cert soaks, heights 2526398..2526404):
// 23/23 of the live [MEMPOOL-VALIDITY] invalids were reason="txn-already-known"
// and EVERY ONE was confirmed at EXACTLY the probe height — i.e. mined in the
// very block our template competed for, while our tip was legitimately h-1.
// That is benign propagation (Window 1): dashd connected block h before we did,
// so it answers "already confirmed"; our template is a valid FORK COMPETITOR at
// height h, never an orphan. The old gate reset the clean run on every one of
// these, which is why clean_run was pinned at 0/576 forever. These KATs pin the
// tip-context split that fixes it.

TEST(DashMempoolValidityGate, AlreadyKnownWithDashdAheadIsBenignPropagationNotInvalid) {
    // dashd is AHEAD of the height we built for -> the tx was confirmed in a
    // block WE HAVE NOT YET CONNECTED -> benign, not a defect.
    const auto r = classify_mempool_accept(
        tx("mined_elsewhere"), refused("mined_elsewhere", "txn-already-known"),
        /*dashd_ahead_of_serve_height=*/true);
    EXPECT_EQ(r.verdict, MempoolAcceptVerdict::ConfirmedAhead);
}

TEST(DashMempoolValidityGate, AlreadyKnownWithDashdNotAheadIsStillAnInvalidDefect) {
    // dashd sits on OUR parent (not ahead) and STILL reports the tx confirmed
    // -> it was confirmed at/below our serve-tip while we serve it: a genuine
    // current-tip staleness defect (Window 2). The gate MUST still catch this.
    const auto r = classify_mempool_accept(
        tx("stale"), refused("stale", "txn-already-known"),
        /*dashd_ahead_of_serve_height=*/false);
    EXPECT_EQ(r.verdict, MempoolAcceptVerdict::Invalid);
    EXPECT_EQ(r.reason, "txn-already-known");
}

TEST(DashMempoolValidityGate, PropagationTransientDoesNotResetTheCleanRun) {
    // The whole point. A clean run in progress must SURVIVE a height whose only
    // "invalids" are already-confirmed-in-a-block-we-haven't-connected txs.
    MempoolValidityGate g;
    feed_clean(g, 100);
    ASSERT_EQ(g.consecutive_clean, 100u);

    // A propagation sample: 4 txs, all "txn-already-known", dashd AHEAD.
    const std::vector<MempoolProbeTx> set{tx("p1"), tx("p2"), tx("p3"), tx("p4")};
    const std::vector<nlohmann::json> ans{
        refused("p1", "txn-already-known"), refused("p2", "txn-already-known"),
        refused("p3", "txn-already-known"), refused("p4", "txn-already-known")};
    const auto s = mempool_validity_sample(50000, set, ans,
                                           /*dashd_ahead_of_serve_height=*/true);
    // Not evidence, not a defect: 4 confirmed-ahead, 0 invalid.
    EXPECT_EQ(s.confirmed_ahead, 4u);
    EXPECT_EQ(s.invalid, 0u);
    EXPECT_FALSE(s.evidence_bearing());

    g.apply(s);
    EXPECT_EQ(g.consecutive_clean, 100u) << "propagation Window 1 must NOT reset";
    EXPECT_EQ(g.txs_invalid, 0u);
    EXPECT_EQ(g.txs_confirmed_ahead, 4u);
}

TEST(DashMempoolValidityGate, TheSamePropagationSampleWithoutTipContextWouldHaveResetIt) {
    // RED->GREEN CONTRAST. Feed the IDENTICAL already-known set the way the
    // pre-fix gate saw it (no tip context => dashd_ahead=false): it classifies
    // as 4 INVALID and nukes a 100-height run to 0. This is the exact live
    // defect (clean_run stuck at 0/576). The only difference from the test above
    // is the tip-context bit, which is what the fix threads through.
    MempoolValidityGate g;
    feed_clean(g, 100);
    ASSERT_EQ(g.consecutive_clean, 100u);

    const std::vector<MempoolProbeTx> set{tx("p1"), tx("p2"), tx("p3"), tx("p4")};
    const std::vector<nlohmann::json> ans{
        refused("p1", "txn-already-known"), refused("p2", "txn-already-known"),
        refused("p3", "txn-already-known"), refused("p4", "txn-already-known")};
    const auto s = mempool_validity_sample(50000, set, ans,
                                           /*dashd_ahead_of_serve_height=*/false);
    EXPECT_EQ(s.invalid, 4u);
    EXPECT_EQ(s.confirmed_ahead, 0u);

    g.apply(s);
    EXPECT_EQ(g.consecutive_clean, 0u) << "no tip context => conservative reset";
    EXPECT_EQ(g.best_consecutive_clean, 100u);
}

TEST(DashMempoolValidityGate, PropagationDoesNotMaskAGenuineInvalidInTheSameSample) {
    // Belt: a sample carrying BOTH benign propagation AND a real defect still
    // resets. The confirmed-ahead reclassification must never swallow a true
    // invalid that shares the height.
    MempoolValidityGate g;
    feed_clean(g, 100);
    const std::vector<MempoolProbeTx> set{tx("ahead"), tx("realbad")};
    const std::vector<nlohmann::json> ans{
        refused("ahead", "txn-already-known"),
        refused("realbad", "bad-txns-inputs-missingorspent")};
    const auto s = mempool_validity_sample(50000, set, ans,
                                           /*dashd_ahead_of_serve_height=*/true);
    EXPECT_EQ(s.confirmed_ahead, 1u);
    EXPECT_EQ(s.invalid, 1u);
    g.apply(s);
    EXPECT_EQ(g.consecutive_clean, 0u) << "a real defect still resets";
    EXPECT_EQ(g.last_invalid_reason, "bad-txns-inputs-missingorspent");
}

TEST(DashMempoolValidityGate, AMixedValidAndPropagationHeightStillAdvances) {
    // A height with at least one genuinely VALID tx is evidence and advances,
    // even when the rest of the set is benign propagation.
    MempoolValidityGate g;
    feed_clean(g, 10);
    const std::vector<MempoolProbeTx> set{tx("good"), tx("ahead")};
    const std::vector<nlohmann::json> ans{
        allowed_true("good"), refused("ahead", "txn-already-known")};
    const auto s = mempool_validity_sample(60000, set, ans,
                                           /*dashd_ahead_of_serve_height=*/true);
    EXPECT_TRUE(s.evidence_bearing());
    EXPECT_EQ(s.valid, 1u);
    EXPECT_EQ(s.confirmed_ahead, 1u);
    g.apply(s);
    EXPECT_EQ(g.consecutive_clean, 11u);
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
    EXPECT_EQ(g.samples_without_evidence, g.required + 10);

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

// ── 5b. THE WINDOW COUNTS DISTINCT HEIGHTS, NOT SAMPLES ─────────────────────
//
// apply() is called ONCE PER SAMPLE, and a sample is one probe run — not one
// block. probe_validity() runs from process(), process() runs from on_serve,
// and on_serve fires on EVERY template re-source: every work-generation bump
// plus a 30 s staleness re-poll (work_source.cpp kStaleAfter). DASH targets
// 157.5 s/block, so ~5-6 samples land on ONE height. If a repeated sample
// advanced the window, 576 counter ticks would be ~110 real heights (~4.8 h),
// not the 576 heights (~25.2 h) the threshold is argued from — and the
// "rule of three" power argument would be counting the same transaction, at
// the same height, five times over as five independent trials.
//
// These KATs feed the input the rest of the suite never presents: REPEATS.

TEST(DashMempoolValidityGate, RepeatedSamplesAtOneHeightAdvanceTheWindowOnce) {
    MempoolValidityGate g;
    feed_clean_repeats_at(g, 5, 2518500);

    EXPECT_EQ(g.consecutive_clean, 1u)
        << "five probes of one height are ONE height of evidence";
    EXPECT_EQ(g.heights_with_evidence, 1u);

    // The four that advanced nothing are not erased — they are RECORDED as
    // what they were, so probe cadence can never be read as progress.
    EXPECT_EQ(g.samples_seen,          5u);
    EXPECT_EQ(g.samples_repeat_height, 4u);
    EXPECT_EQ(g.txs_probed,            1u) << "one observation per tx per height";
    EXPECT_EQ(g.repeat_txs_probed,     4u);
    EXPECT_EQ(g.last_disposition,
              MempoolValidityGate::SampleDisposition::RepeatHeight);

    // And the log line SAYS SO rather than leaving it to be inferred.
    const auto set = std::vector<MempoolProbeTx>{tx("aa")};
    const auto ans = std::vector<nlohmann::json>{allowed_true("aa")};
    const auto s   = mempool_validity_sample(2518500, set, ans);
    const auto lines = mempool_validity_log_lines(s, g);
    EXPECT_TRUE(has_line_with(lines, "sample=REPEAT-HEIGHT(no-advance)"));
    EXPECT_TRUE(has_line_with(lines, "heights_with_evidence=1"));
}

TEST(DashMempoolValidityGate, AWholeWindowOfSamplesAtOneHeightCannotOpenTheGate) {
    // The failure this whole fix exists to stop: a node parked on ONE height
    // (frozen tip, stalled bridge) re-probing the same transactions for hours
    // and calling it a full day of evidence.
    MempoolValidityGate g;
    feed_clean_repeats_at(g, g.required + 50, 2518501);

    EXPECT_FALSE(g.open()) << "one height, however often probed, is one height";
    EXPECT_EQ(g.consecutive_clean, 1u);
    EXPECT_EQ(g.heights_with_evidence, 1u);
    EXPECT_EQ(g.samples_seen, g.required + 50);
    EXPECT_EQ(g.to_json()["gate"], "CLOSED");
}

TEST(DashMempoolValidityGate, ARepeatedHeightIsNotEvidenceButAnInvalidOnItStillKillsTheRun) {
    // The ASYMMETRY, stated as a test: a repeat cannot ADVANCE the run (it is
    // not new evidence) but it CAN kill it (a defect is a defect whenever it is
    // observed). Trading "over-counts clean" for "under-counts invalid" would
    // be swapping one blindness for another.
    MempoolValidityGate g;
    feed_clean(g, 4, 2518600);                 // heights 2518600..2518603
    ASSERT_EQ(g.consecutive_clean, 4u);

    // A LATER probe of the height already counted clean — this time dashd
    // refuses one of the transactions (a conflicting spend arrived).
    const std::vector<MempoolProbeTx> set{tx("aa"), tx("bad")};
    const std::vector<nlohmann::json> ans{allowed_true("aa"),
                                          refused("bad", "bad-txns-inputs-spent")};
    g.apply(mempool_validity_sample(2518603, set, ans));

    EXPECT_EQ(g.consecutive_clean, 0u) << "a repeat must still be able to RESET";
    EXPECT_EQ(g.last_invalid_txid, "bad");
    EXPECT_EQ(g.last_invalid_height, 2518603u);
    EXPECT_EQ(g.txs_invalid, 1u);

    // The defect was seen on a REPEAT, so the height is not re-banked...
    EXPECT_EQ(g.heights_with_evidence, 4u);
    // ...but it IS counted, because a defect counts wherever it is observed.
    EXPECT_EQ(g.last_disposition,
              MempoolValidityGate::SampleDisposition::RepeatHeight);

    // And a clean re-probe of that same height does NOT resurrect the run.
    feed_clean_sample_at(g, 2518603);
    EXPECT_EQ(g.consecutive_clean, 0u);

    // Only a genuinely NEW height restarts it, from one.
    feed_clean_sample_at(g, 2518604);
    EXPECT_EQ(g.consecutive_clean, 1u);
}

TEST(DashMempoolValidityGate, AHeightThatDoesNotADVANCEContributesNoEvidence) {
    // Reorg / rollback: the cursor is MONOTONE. A template height at or below
    // the last counted one carries no evidence the window has not already
    // banked, and alternating H, H-1, H must not be read as three heights.
    MempoolValidityGate g;
    feed_clean_sample_at(g, 2518700);
    feed_clean_sample_at(g, 2518699);   // rolled back
    feed_clean_sample_at(g, 2518700);   // and forward again — same height
    EXPECT_EQ(g.consecutive_clean, 1u);
    EXPECT_EQ(g.heights_with_evidence, 1u);

    feed_clean_sample_at(g, 2518701);   // a genuinely NEW height does advance
    EXPECT_EQ(g.consecutive_clean, 2u);
    EXPECT_EQ(g.heights_with_evidence, 2u);
}

TEST(DashMempoolValidityGate, AnEmptyProbeAtAHeightDoesNotBurnThatHeight) {
    // A height whose first probe found nothing has NOT been measured. When a
    // later probe of the SAME height does find transactions, that is the first
    // evidence at that height and it must count.
    MempoolValidityGate g;
    g.apply(mempool_validity_sample(2518800, {}, {}));
    EXPECT_EQ(g.consecutive_clean, 0u);
    feed_clean_sample_at(g, 2518800);
    EXPECT_EQ(g.consecutive_clean, 1u);
    EXPECT_EQ(g.heights_with_evidence, 1u);
}

// ── 5c. THE IN-SET-PARENT EXEMPTION IS PER-TRANSACTION, SO IT MUST BE NARROW ─

TEST(DashMempoolValidityGate, MissingOrSpentIsNeverExemptedEvenWithAnInSetParent) {
    // `bad-txns-inputs-missingorspent` says in its own NAME that it cannot
    // tell a missing input from a SPENT one, and testmempoolaccept never names
    // WHICH outpoint failed. `depends_on_in_set_parent` is a fact about the
    // TRANSACTION, not about the failing INPUT: a tx spending one in-set parent
    // output AND one genuinely double-spent output has the flag set and is a
    // real defect. Excusing it would let exactly the loss this gate exists to
    // prevent through as UNPROBED.
    const auto r = classify_mempool_accept(
        tx("gg", /*depends=*/true),
        refused("gg", "bad-txns-inputs-missingorspent"));
    EXPECT_EQ(r.verdict, MempoolAcceptVerdict::Invalid);
    EXPECT_EQ(r.reason, "bad-txns-inputs-missingorspent");

    // The narrow reason — dashd saying only "I do not know this input" — stays
    // excused, because that IS what a one-tx probe of a child does to a parent
    // dashd has not seen.
    const auto narrow = classify_mempool_accept(
        tx("gg", /*depends=*/true), refused("gg", "missing-inputs"));
    EXPECT_EQ(narrow.verdict, MempoolAcceptVerdict::Unprobed);
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
