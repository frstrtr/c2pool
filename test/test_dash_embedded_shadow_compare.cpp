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
