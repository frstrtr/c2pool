// SPDX-License-Identifier: AGPL-3.0-or-later
/// DASH embedded-vs-dashd SHADOW-COMPARE DIAGNOSTIC — hermetic KATs
/// (embedded_shadow_compare.hpp).
///
/// This is a DIAGNOSTIC TOOL, explicitly NOT a serve gate. These KATs pin the
/// two properties the operator directive requires:
///
///   (a) FLAG-OFF / ZERO BEHAVIOR CHANGE: the compare never mutates the served
///       template — the bytes handed in are byte-identical afterward, and a
///       driver with no oracle/served input changes nothing. (shadow_evaluate
///       takes const refs; on_serve copies.)
///   (b) FLAG-ON + MISMATCHING ORACLE: when the EMBEDDED arm was SERVED and a
///       consensus-commitment field (payee / merkleRootMNList / merkleRootQuorums)
///       diverges from dashd, the distinct SERVED-MISMATCH line + the
///       shadow-served-mismatch counter fire — while the served template stays
///       byte-identical to what it would serve without the flag.
///
/// Plus the surrounding semantics: a MATCH agrees on all fields; a fallback
/// (gate-refused) divergence is MISMATCH but NOT served-mismatch (the fail-closed
/// gate did its job); an absent / tip-skewed oracle logs no-oracle. The async
/// runtime driver (worker thread + counters via stats_json) is exercised
/// end-to-end with a synthetic in-process oracle — no live node needed.

#include <gtest/gtest.h>

#include <impl/dash/coin/embedded_shadow_compare.hpp>
#include <impl/dash/coin/rpc_data.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <chrono>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace dash::coin;

namespace {

std::vector<uint8_t> encode(const vendor::CCbTx& c) {
    auto stream = ::pack(c);
    auto sp = stream.get_span();
    return std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(sp.data()),
        reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
}
uint256 hashn(uint8_t seed) {
    uint256 h;
    auto* b = reinterpret_cast<unsigned char*>(h.begin());
    for (int i = 0; i < 32; ++i) b[i] = static_cast<uint8_t>(seed + i);
    return h;
}
vendor::CCbTx make_cbtx(uint32_t height, uint8_t mn_seed = 1, uint8_t q_seed = 100) {
    vendor::CCbTx c;
    c.nVersion = vendor::CCbTx::VERSION_CLSIG_AND_BALANCE;
    c.nHeight = static_cast<int32_t>(height);
    c.merkleRootMNList = hashn(mn_seed);
    c.merkleRootQuorums = hashn(q_seed);
    c.creditPoolBalance = 1000;
    return c;
}
DashWorkData make_wd(uint32_t height, const vendor::CCbTx& cbtx,
                     const std::string& mn_payee) {
    DashWorkData w;
    w.m_height = height;
    w.m_previous_block = hashn(200);   // non-null: not a set-gap
    w.m_bits = 0x1e0ffff0u;            // non-zero: not a set-gap
    w.m_coinbase_value = 5'0000'0000ull;
    w.m_packed_payments = { {"!6a", 1234}, {mn_payee, 100000} };
    w.m_coinbase_payload = encode(cbtx);
    return w;
}

bool has_line_with(const std::vector<std::string>& lines, const std::string& needle) {
    for (const auto& l : lines)
        if (l.find(needle) != std::string::npos) return true;
    return false;
}

} // namespace

// (a) Pure identical templates -> MATCH, no served-mismatch, one MATCH line.
TEST(DashShadowCompare, MatchWhenIdentical) {
    auto cb = make_cbtx(2500000);
    auto emb = make_wd(2500000, cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    auto dref = make_wd(2500000, cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");

    auto o = shadow_evaluate(WorkSource::Embedded, emb, dref);
    EXPECT_EQ(o.kind, ShadowOutcome::Kind::Match);
    EXPECT_FALSE(o.served_mismatch);
    EXPECT_TRUE(has_line_with(o.log_lines, "[SHADOW] h=2500000 MATCH"));

    ShadowCounters c;
    c.apply(o);
    EXPECT_EQ(c.shadow_match, 1u);
    EXPECT_EQ(c.shadow_served_mismatch, 0u);
}

// (b) EMBEDDED SERVED + commitment-field divergence -> SERVED-MISMATCH line +
// counter, and the served template bytes are UNTOUCHED by the compare.
TEST(DashShadowCompare, ServedMismatchOnCommitmentDivergence) {
    auto emb_cb  = make_cbtx(2500000, /*mn_seed=*/1,  /*q_seed=*/100);
    auto dref_cb = make_cbtx(2500000, /*mn_seed=*/9,  /*q_seed=*/100); // mnlist differs
    auto emb  = make_wd(2500000, emb_cb,  "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    auto dref = make_wd(2500000, dref_cb, "yMNaddrBBBBBBBBBBBBBBBBBBBBB");     // payee differs

    // Snapshot the served template BEFORE the compare (zero-behavior-change proof).
    const auto payload_before = emb.m_coinbase_payload;
    const auto payments_before = emb.m_packed_payments;

    auto o = shadow_evaluate(WorkSource::Embedded, emb, dref);

    // Served bytes untouched — the diagnostic never alters what gets served.
    EXPECT_EQ(emb.m_coinbase_payload, payload_before);
    ASSERT_EQ(emb.m_packed_payments.size(), payments_before.size());
    EXPECT_EQ(emb.m_packed_payments[1].payee, payments_before[1].payee);

    EXPECT_EQ(o.kind, ShadowOutcome::Kind::Mismatch);
    EXPECT_TRUE(o.served_mismatch);
    EXPECT_TRUE(has_line_with(o.log_lines, "SERVED-MISMATCH field=payee"));
    EXPECT_TRUE(has_line_with(o.log_lines, "SERVED-MISMATCH field=merkleRootMNList"));

    ShadowCounters c;
    c.apply(o);
    EXPECT_EQ(c.shadow_served_mismatch, 1u);
    EXPECT_EQ(c.shadow_mismatch_by_field["payee"], 1u);
    EXPECT_EQ(c.shadow_mismatch_by_field["merkleRootMNList"], 1u);
    // merkleRootQuorums matched -> no counter for it.
    EXPECT_EQ(c.shadow_mismatch_by_field.count("merkleRootQuorums"), 0u);
}

// A gate-REFUSED height (source == DashdFallback) with the SAME divergence is a
// plain MISMATCH, NOT a SERVED-MISMATCH: nothing wrong was served.
TEST(DashShadowCompare, FallbackDivergenceIsNotServedMismatch) {
    auto emb_cb  = make_cbtx(2500000, /*mn_seed=*/1);
    auto dref_cb = make_cbtx(2500000, /*mn_seed=*/9);
    auto emb  = make_wd(2500000, emb_cb,  "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    auto dref = make_wd(2500000, dref_cb, "yMNaddrBBBBBBBBBBBBBBBBBBBBB");

    auto o = shadow_evaluate(WorkSource::DashdFallback, emb, dref);
    EXPECT_EQ(o.kind, ShadowOutcome::Kind::Mismatch);
    EXPECT_FALSE(o.served_mismatch);
    EXPECT_TRUE(has_line_with(o.log_lines, "MISMATCH field=payee"));
    EXPECT_FALSE(has_line_with(o.log_lines, "SERVED-MISMATCH"));

    ShadowCounters c;
    c.apply(o);
    EXPECT_EQ(c.shadow_served_mismatch, 0u);
    EXPECT_EQ(c.shadow_mismatch_by_field["payee"], 1u);
}

// Absent oracle -> no-oracle line + counter.
TEST(DashShadowCompare, NoOracleWhenAbsent) {
    auto cb = make_cbtx(2500000);
    auto emb = make_wd(2500000, cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");

    auto o = shadow_evaluate(WorkSource::Embedded, emb, std::nullopt);
    EXPECT_EQ(o.kind, ShadowOutcome::Kind::NoOracle);
    EXPECT_TRUE(has_line_with(o.log_lines, "[SHADOW] h=2500000 no-oracle"));

    ShadowCounters c;
    c.apply(o);
    EXPECT_EQ(c.shadow_no_oracle, 1u);
}

// Tip-skew (dashd template at a different height) -> no-oracle for THIS height,
// never a false all-fields divergence.
TEST(DashShadowCompare, TipSkewIsNoOracle) {
    auto emb_cb  = make_cbtx(2500000);
    auto dref_cb = make_cbtx(2500001);
    auto emb  = make_wd(2500000, emb_cb,  "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    auto dref = make_wd(2500001, dref_cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");

    auto o = shadow_evaluate(WorkSource::Embedded, emb, dref);
    EXPECT_EQ(o.kind, ShadowOutcome::Kind::NoOracle);
    EXPECT_TRUE(has_line_with(o.log_lines, "no-oracle reason=tip-skew"));
}

// End-to-end async DRIVER: on_serve enqueues and returns immediately (off the
// hot path); a worker thread fetches the (synthetic) oracle, compares, and the
// counter surfaces via stats_json — the monitor/dashboard read path.
TEST(DashShadowCompare, DriverAsyncServedMismatchSurfacesCounter) {
    auto emb_cb  = make_cbtx(2500000, /*mn_seed=*/1);
    auto dref_cb = make_cbtx(2500000, /*mn_seed=*/9);
    auto served  = make_wd(2500000, emb_cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    // A synthetic dashd oracle that diverges on the payee (commitment field).
    auto dref    = make_wd(2500000, dref_cb, "yMNaddrBBBBBBBBBBBBBBBBBBBBB");

    EmbeddedShadowCompare probe(
        [dref]() -> std::optional<DashWorkData> { return dref; });

    const auto payload_before = served.m_coinbase_payload;
    probe.on_serve(WorkSource::Embedded, served);   // enqueue-only, never blocks
    // The served template we still hold is unchanged (const-ref contract).
    EXPECT_EQ(served.m_coinbase_payload, payload_before);

    // Poll the counter surface until the worker processes the sample.
    bool fired = false;
    for (int i = 0; i < 200 && !fired; ++i) {
        auto j = probe.stats_json();
        if (j.value("shadow-served-mismatch", 0u) == 1u) fired = true;
        else std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_TRUE(fired);
    auto j = probe.stats_json();
    EXPECT_EQ(j["shadow-served-mismatch"], 1u);
    EXPECT_EQ(j["mode"], "embedded-shadow-compare");
}

// ═════════════════════════════════════════════════════════════════════════
// TX-SET NORMALIZATION of merkleRootMNList — the h=2516756 false-positive
// class. The consensus rule derives the committed root from the MN list AFTER
// folding the block's OWN ProTx txs (types 1-4), so an embedded coinbase-only
// template and a dashd template carrying a mempool ProTx commit to DIFFERENT
// tx sets: both roots are correct for their own blocks, and comparing them as
// answers to the same question was the false SERVED-MISMATCH. Roots may only
// be commitment-compared under the SAME ProTx fold; a divergence under
// different folds is the benign MATCH-MODULO-MEMPOOL-PROTX verdict with its
// own counter.
// ═════════════════════════════════════════════════════════════════════════

namespace {

// A template tx with a given Dash special-tx type + a distinct txid, appended
// with the parallel m_tx_hashes entry the GBT parser maintains.
void add_tx(DashWorkData& w, uint16_t type, uint8_t id_seed) {
    MutableTransaction m;
    m.type = type;
    w.m_txs.emplace_back(m);
    w.m_tx_hashes.push_back(hashn(id_seed));
}

} // namespace

// THE 2516756 REPRODUCTION: embedded serves coinbase-only; dashd's template
// carries a mempool ProUpServTx (type 2 — the revive) plus a normal type-0
// payment tx; the two merkleRootMNList values diverge (each correct for its
// own tx set). VERIFIED TO FAIL ON THE PRE-FIX TREE: shadow_evaluate flags
// SERVED-MISMATCH field=merkleRootMNList and bumps shadow-served-mismatch —
// the exact false positive observed live at h=2516756.
TEST(DashShadowCompare, MempoolProUpServTxRootDivergenceIsMatchModulo2516756) {
    auto emb_cb  = make_cbtx(2516756, /*mn_seed=*/1,  /*q_seed=*/100);
    auto dref_cb = make_cbtx(2516756, /*mn_seed=*/9,  /*q_seed=*/100); // root differs
    auto emb  = make_wd(2516756, emb_cb,  "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    auto dref = make_wd(2516756, dref_cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    // embedded: coinbase-only (no txs). dashd: mempool ProUpServTx revive +
    // an ordinary payment tx (which must NOT matter — only ProTx types fold).
    add_tx(dref, /*type=*/2, /*id_seed=*/0x21);
    add_tx(dref, /*type=*/0, /*id_seed=*/0x22);

    auto o = shadow_evaluate(WorkSource::Embedded, emb, dref);

    // The core fails-on-master assertions: NOT a served-mismatch, and no
    // SERVED-MISMATCH line — the roots answered different questions.
    EXPECT_FALSE(o.served_mismatch)
        << "coinbase-only vs mempool-ProTx tx sets flagged as a served root "
           "bug — the h=2516756 false positive";
    EXPECT_FALSE(has_line_with(o.log_lines, "SERVED-MISMATCH"));

    // And the benign verdict names itself, with its own counter.
    EXPECT_EQ(o.kind, ShadowOutcome::Kind::MatchModuloMempoolProTx);
    EXPECT_TRUE(has_line_with(o.log_lines,
        "[SHADOW] h=2516756 MATCH-MODULO-MEMPOOL-PROTX field=merkleRootMNList"));

    ShadowCounters c;
    c.apply(o);
    EXPECT_EQ(c.shadow_served_mismatch, 0u);
    EXPECT_EQ(c.shadow_match_modulo_mempool_protx, 1u);
    EXPECT_EQ(c.shadow_mismatch_by_field.count("merkleRootMNList"), 0u);
    EXPECT_EQ(c.shadow_match, 0u) << "benign-modulo must not hide in MATCH";
    auto j = c.to_json();
    EXPECT_EQ(j["shadow-match-modulo-mempool-protx"], 1u);
}

// A REAL root bug must still SERVED-MISMATCH: the SAME tx set on both sides
// (identical ProTx fold — here literally the same ProUpServTx) with diverging
// roots means the validator rule was run over the same inputs and disagreed.
TEST(DashShadowCompare, RealRootBugUnderSameTxSetStillServedMismatch) {
    auto emb_cb  = make_cbtx(2516756, /*mn_seed=*/1);
    auto dref_cb = make_cbtx(2516756, /*mn_seed=*/9); // root differs
    auto emb  = make_wd(2516756, emb_cb,  "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    auto dref = make_wd(2516756, dref_cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    // IDENTICAL ProTx fold on both sides: same ProUpServTx txid.
    add_tx(emb,  /*type=*/2, /*id_seed=*/0x21);
    add_tx(dref, /*type=*/2, /*id_seed=*/0x21);

    auto o = shadow_evaluate(WorkSource::Embedded, emb, dref);
    EXPECT_EQ(o.kind, ShadowOutcome::Kind::Mismatch);
    EXPECT_TRUE(o.served_mismatch)
        << "a root divergence under the SAME tx set is a real bug and must "
           "still fire SERVED-MISMATCH";
    EXPECT_TRUE(has_line_with(o.log_lines, "SERVED-MISMATCH field=merkleRootMNList"));

    ShadowCounters c;
    c.apply(o);
    EXPECT_EQ(c.shadow_served_mismatch, 1u);
    EXPECT_EQ(c.shadow_match_modulo_mempool_protx, 0u);
}

// Coinbase-only on BOTH sides is also the SAME tx set (empty fold == empty
// fold): the pre-existing served-mismatch semantics are unchanged there.
TEST(DashShadowCompare, CoinbaseOnlyBothSidesRootDivergenceStillServedMismatch) {
    auto emb_cb  = make_cbtx(2516756, /*mn_seed=*/1);
    auto dref_cb = make_cbtx(2516756, /*mn_seed=*/9);
    auto emb  = make_wd(2516756, emb_cb,  "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    auto dref = make_wd(2516756, dref_cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");

    auto o = shadow_evaluate(WorkSource::Embedded, emb, dref);
    EXPECT_TRUE(o.served_mismatch);
    EXPECT_TRUE(has_line_with(o.log_lines, "SERVED-MISMATCH field=merkleRootMNList"));
}

// The modulo verdict must not MASK an unrelated commitment divergence riding
// in the same sample: differing ProTx folds excuse ONLY merkleRootMNList —
// a payee divergence alongside stays a SERVED-MISMATCH.
TEST(DashShadowCompare, ModuloDoesNotMaskOtherCommitmentDivergence) {
    auto emb_cb  = make_cbtx(2516756, /*mn_seed=*/1);
    auto dref_cb = make_cbtx(2516756, /*mn_seed=*/9);          // root differs
    auto emb  = make_wd(2516756, emb_cb,  "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    auto dref = make_wd(2516756, dref_cb, "yMNaddrBBBBBBBBBBBBBBBBBBBBB"); // payee differs
    add_tx(dref, /*type=*/2, /*id_seed=*/0x21);   // folds differ

    auto o = shadow_evaluate(WorkSource::Embedded, emb, dref);
    EXPECT_EQ(o.kind, ShadowOutcome::Kind::Mismatch);
    EXPECT_TRUE(o.served_mismatch) << "the payee divergence is still real";
    EXPECT_TRUE(has_line_with(o.log_lines, "SERVED-MISMATCH field=payee"));
    // The root line keeps its benign marker; it must not read SERVED-MISMATCH.
    EXPECT_TRUE(has_line_with(o.log_lines,
        "MATCH-MODULO-MEMPOOL-PROTX field=merkleRootMNList"));
    EXPECT_FALSE(has_line_with(o.log_lines, "SERVED-MISMATCH field=merkleRootMNList"));

    ShadowCounters c;
    c.apply(o);
    EXPECT_EQ(c.shadow_served_mismatch, 1u);
    EXPECT_EQ(c.shadow_match_modulo_mempool_protx, 1u);
    EXPECT_EQ(c.shadow_mismatch_by_field["payee"], 1u);
    EXPECT_EQ(c.shadow_mismatch_by_field.count("merkleRootMNList"), 0u);
}

// Matching roots stay a plain MATCH even when the tx sets differ — the modulo
// verdict exists only to explain a DIVERGENCE, never to relabel agreement.
TEST(DashShadowCompare, MatchingRootsWithDifferentTxSetsIsStillMatch) {
    auto cb = make_cbtx(2516756);
    auto emb  = make_wd(2516756, cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    auto dref = make_wd(2516756, cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    add_tx(dref, /*type=*/2, /*id_seed=*/0x21);

    auto o = shadow_evaluate(WorkSource::Embedded, emb, dref);
    EXPECT_EQ(o.kind, ShadowOutcome::Kind::Match);
    EXPECT_FALSE(o.served_mismatch);
}


// ═══════════════════════════════════════════════════════════════════════════
// PHASE-1 MEMPOOL INGEST — the coverage measurement
//
// While dashd is present its template's tx set is a free, per-block answer key
// for our own mempool. This is the gate for ever enabling
// --embedded-serve-mempool-txs: a wrong tx set costs a whole block, a shadow
// run costs nothing. The two directions are not symmetric — dashd-only is
// revenue we are forfeiting, ours-only is a block we might lose.
// ═══════════════════════════════════════════════════════════════════════════
namespace {
// Attach a tx set to a WorkData the way the builder does: m_txs and
// m_tx_hashes are PARALLEL, and shadow_tx_set_diff refuses to measure when
// they are not (see the KAT below).
void with_txs(DashWorkData& w, const std::vector<uint8_t>& seeds) {
    w.m_txs.clear();
    w.m_tx_hashes.clear();
    for (uint8_t sd : seeds) {
        MutableTransaction t;
        t.version = 2;
        w.m_txs.emplace_back(t);
        w.m_tx_hashes.push_back(hashn(sd));
    }
}
} // namespace

TEST(DashShadowCompare, TxSetCoverageIsMeasuredAgainstDashd) {
    auto cb = make_cbtx(2500000, 11, 22);
    auto emb  = make_wd(2500000, cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    auto dref = make_wd(2500000, cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    // dashd has five; we ingested three of them.
    with_txs(emb,  {1, 2, 3});
    with_txs(dref, {1, 2, 3, 4, 5});

    const auto d = shadow_tx_set_diff(emb, dref);
    EXPECT_EQ(d.ours, 3u);
    EXPECT_EQ(d.theirs, 5u);
    EXPECT_EQ(d.both, 3u);
    EXPECT_EQ(d.dashd_only, 2u);      // the fees we are still forfeiting
    EXPECT_EQ(d.ours_only, 0u);       // the safe direction
    EXPECT_TRUE(d.coverage_defined());
    EXPECT_NEAR(d.coverage_pct(), 60.0, 1e-9);

    const auto o = shadow_evaluate(WorkSource::Embedded, emb,
                                   std::optional<DashWorkData>(dref));
    EXPECT_TRUE(has_line_with(o.log_lines, "[SHADOW-TXSET]"));
    EXPECT_TRUE(has_line_with(o.log_lines, "coverage=60%"));
    EXPECT_TRUE(has_line_with(o.log_lines, "dashd_only=2"));
    // The measurement is a DIAGNOSTIC: a coverage shortfall is not a mismatch.
    EXPECT_FALSE(o.served_mismatch);
}

// The dangerous direction is called out in the line itself, because the
// operator reads the line, not the struct.
TEST(DashShadowCompare, TxWeHaveThatDashdDoesNotIsFlaggedLoudly) {
    auto cb = make_cbtx(2500000, 11, 22);
    auto emb  = make_wd(2500000, cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    auto dref = make_wd(2500000, cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    with_txs(emb,  {1, 2, 9});        // 9 is ours alone
    with_txs(dref, {1, 2, 3});

    const auto d = shadow_tx_set_diff(emb, dref);
    EXPECT_EQ(d.ours_only, 1u);
    EXPECT_EQ(d.dashd_only, 1u);

    const auto o = shadow_evaluate(WorkSource::Embedded, emb,
                                   std::optional<DashWorkData>(dref));
    EXPECT_TRUE(has_line_with(o.log_lines, "ours_only=1"));
    EXPECT_TRUE(has_line_with(o.log_lines, "OURS-ONLY"));
    EXPECT_TRUE(has_line_with(o.log_lines,
                              "do NOT enable --embedded-serve-mempool-txs"));
}

// A coinbase-only dashd template means there was no fee to capture at this
// height. Reporting that as 0% coverage would slander a working ingest lane,
// so coverage is UNDEFINED, and the line says so.
TEST(DashShadowCompare, CoverageIsUndefinedWhenDashdHadNoTxsEither) {
    auto cb = make_cbtx(2500000, 11, 22);
    auto emb  = make_wd(2500000, cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    auto dref = make_wd(2500000, cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");

    const auto d = shadow_tx_set_diff(emb, dref);
    EXPECT_EQ(d.theirs, 0u);
    EXPECT_FALSE(d.coverage_defined());
    EXPECT_EQ(d.dashd_only, 0u);

    const auto o = shadow_evaluate(WorkSource::Embedded, emb,
                                   std::optional<DashWorkData>(dref));
    EXPECT_TRUE(has_line_with(o.log_lines, "coverage=n/a"));
}

// An unaligned WorkData must produce NO measurement rather than a fabricated
// one. A wrong number here would be read as evidence and acted on.
TEST(DashShadowCompare, UnalignedTxHashesMeasureNothingRatherThanGuess) {
    auto cb = make_cbtx(2500000, 11, 22);
    auto emb  = make_wd(2500000, cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    auto dref = make_wd(2500000, cb, "yMNaddrAAAAAAAAAAAAAAAAAAAAA");
    with_txs(dref, {1, 2, 3});
    with_txs(emb,  {1, 2, 3});
    emb.m_tx_hashes.pop_back();       // parallel vectors no longer aligned

    const auto d = shadow_tx_set_diff(emb, dref);
    EXPECT_EQ(d.ours, 0u) << "an unaligned tx set must not be measured";
    EXPECT_EQ(d.ours_only, 0u)
        << "and must never manufacture the dangerous direction";
    EXPECT_EQ(d.theirs, 3u);
    EXPECT_EQ(d.dashd_only, 3u);
}
