// SPDX-License-Identifier: AGPL-3.0-or-later
/// DASH Embedded ORACLE-SHADOW VALIDATOR — hermetic KATs for the pure
/// regime-aware compare + graduation logic (embedded_oracle_shadow.hpp).
///
/// The runtime driver (on_new_tip) and the dashd PROPOSAL verdict need a live
/// node + dashd and are exercised by the testnet shadow soak. These KATs pin the
/// DECISION LOGIC the runtime relies on, per the adversarial-critique §6 model:
///
///   (1) EQUALITY fields (nHeight, cbtx version, bits, mintime, payee identity,
///       platform burn, normalized subsidy, roots when empty) — a mismatch
///       COUNTS as a divergence.
///   (2) A pure mempool/fee difference (raw coinbasevalue, tx set, payee
///       amounts, MN amount) produces ZERO counted divergences — the false
///       positive the separate-mempool reality would otherwise cause. The
///       EQUALITY subsidy core (coinbasevalue − Σfees) still matches.
///   (3) creditPool is an INVARIANT (normalized base), not cross-node equality:
///       a stale embedded seed VIOLATES its own base invariant and COUNTS; a
///       higher-but-consistent dashd pool does NOT.
///   (4) bestCL* is a CONSTRAINT: differing CL heights do NOT count; equal CL
///       height with differing sig DOES.
///   (5) GraduationLedger: served-clean requires proposal ACCEPTED; N + K + reorg
///       + serve-rate floor; fall-closed classes are declared as serve-gaps;
///       a chain-drift revoke withholds graduation.
///   (6) NetPeriodicity height classification.

#include <gtest/gtest.h>

#include <impl/dash/coin/embedded_oracle_shadow.hpp>
#include <impl/dash/coin/rpc_data.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <optional>
#include <string>
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
    uint256 h;   // begin() is uint32_t* (8 words); write the 32 raw bytes.
    auto* b = reinterpret_cast<unsigned char*>(h.begin());
    for (int i = 0; i < 32; ++i) b[i] = static_cast<uint8_t>(seed + i);
    return h;
}
vendor::CCbTx make_cbtx(uint32_t height, int64_t credit_pool,
                        uint8_t mn_seed = 1, uint8_t q_seed = 100,
                        uint32_t cl_diff = 0) {
    vendor::CCbTx c;
    c.nVersion = vendor::CCbTx::VERSION_CLSIG_AND_BALANCE;
    c.nHeight = static_cast<int32_t>(height);
    c.merkleRootMNList = hashn(mn_seed);
    c.merkleRootQuorums = hashn(q_seed);
    c.bestCLHeightDiff = cl_diff;
    c.bestCLSignature = {};
    c.creditPoolBalance = credit_pool;
    return c;
}
std::vector<PackedPayment> payees(uint64_t platform, uint64_t mn_amount,
                                  const std::string& mn = "yMNaddr111111111111111111111") {
    return { {"!6a", platform}, {mn, mn_amount} };
}
DashWorkData make_wd(uint32_t height, const vendor::CCbTx& cbtx,
                     const std::vector<PackedPayment>& p,
                     uint64_t coinbasevalue, std::vector<uint64_t> fees) {
    DashWorkData w;
    w.m_height = height;
    w.m_previous_block = hashn(200);
    w.m_bits = 0x1e0ffff0u;
    w.m_mintime = 1700000000u;
    w.m_coinbase_value = coinbasevalue;
    w.m_packed_payments = p;
    w.m_coinbase_payload = encode(cbtx);
    w.m_tx_fees = fees;
    w.m_tx_hashes.assign(fees.size(), hashn(50));
    return w;
}
SideContext side(const DashWorkData& wd, const vendor::CCbTx& cb) {
    SideContext s; s.wd = &wd; s.cbtx = &cb; s.cbtx_ok = true;
    s.own_fees = sum_fees(wd.m_tx_fees);
    s.platform_reward = platform_burn_amount(wd.m_packed_payments);
    s.empty_template = wd.m_tx_hashes.empty();
    return s;
}
const FieldResult* find(const std::vector<FieldResult>& fr, const std::string& f) {
    for (const auto& x : fr) if (x.field == f) return &x;
    return nullptr;
}
size_t counted(const std::vector<FieldResult>& fr) {
    size_t n = 0; for (const auto& f : fr) if (f.counts) ++n; return n;
}

} // namespace

// ── (1) identical empty templates -> zero counted divergences ────────────────
TEST(OracleShadow, IdenticalEmptyTemplatesAgree) {
    auto cb = make_cbtx(1000, 5000000);
    auto e = make_wd(1000, cb, payees(1000, 90000), 500000000, {});
    auto d = make_wd(1000, cb, payees(1000, 90000), 500000000, {});
    auto fr = compare_templates(side(e, cb), side(d, cb),
                                std::optional<int64_t>(4999000), /*dkg=*/false, /*contig=*/true);
    EXPECT_EQ(counted(fr), 0u);
}

// ── (2) mempool/fee-only difference -> ZERO counted (the keystone) ───────────
TEST(OracleShadow, MempoolFeeDifferenceIsNotCounted) {
    auto cb = make_cbtx(1000, 5000000);   // same chain state -> same CbTx
    // Embedded: 0 fees; dashd: 30000 sat of fees over 5 txs. Same subsidy core.
    auto e = make_wd(1000, cb, payees(1000, 90000), 500000000, {});
    auto d = make_wd(1000, cb, payees(1000, 91777), 500030000, {6000,6000,6000,6000,6000});
    // Non-empty on the dashd side -> roots downgrade to informational, and the
    // creditPool invariant tolerates dashd's own-tx delta.
    auto fr = compare_templates(side(e, cb), side(d, cb),
                                std::optional<int64_t>(4999000), false, true);
    EXPECT_EQ(counted(fr), 0u) << "fee/mempool differences must not count";
    EXPECT_TRUE(find(fr, "coinbasevalue_raw") && !find(fr, "coinbasevalue_raw")->match);
    EXPECT_TRUE(find(fr, "subsidy_core") && find(fr, "subsidy_core")->match);   // core matches
    EXPECT_TRUE(find(fr, "payee_amounts") && !find(fr, "payee_amounts")->match);
    EXPECT_TRUE(find(fr, "payee_identities") && find(fr, "payee_identities")->match);
    EXPECT_TRUE(find(fr, "platform_burn_amount") && find(fr, "platform_burn_amount")->match);
}

// ── (3) stale embedded creditPool seed -> INVARIANT violation, counts ────────
TEST(OracleShadow, StaleCreditPoolSeedIsCountedInvariant) {
    // base creditPool(N-1) = 4_999_000; platformReward(N) = 1000.
    // A correct committed pool = 4_999_000 + 1000 = 5_000_000.
    auto good = make_cbtx(1000, 5000000);
    auto stale = make_cbtx(1000, 4000000);           // stale seed -> base check fails
    auto e = make_wd(1000, stale, payees(1000, 90000), 500000000, {});   // embedded stale
    auto d = make_wd(1000, good,  payees(1000, 90000), 500000000, {});   // dashd correct
    auto fr = compare_templates(side(e, stale), side(d, good),
                                std::optional<int64_t>(4999000), false, /*contig=*/true);
    const auto* inv = find(fr, "creditPool_invariant");
    ASSERT_TRUE(inv);
    EXPECT_EQ(inv->regime, Regime::Invariant);
    EXPECT_TRUE(inv->counts);
    EXPECT_FALSE(inv->match);
}

// ── (3b) higher-but-consistent dashd pool (no delta) -> NOT counted ──────────
TEST(OracleShadow, ConsistentCreditPoolNotCounted) {
    // Both sides committed = base + platformReward = 4_999_000 + 1000.
    auto cb = make_cbtx(1000, 5000000);
    auto e = make_wd(1000, cb, payees(1000, 90000), 500000000, {});
    auto d = make_wd(1000, cb, payees(1000, 90000), 500000000, {});
    auto fr = compare_templates(side(e, cb), side(d, cb),
                                std::optional<int64_t>(4999000), false, true);
    const auto* inv = find(fr, "creditPool_invariant");
    ASSERT_TRUE(inv);
    EXPECT_FALSE(inv->counts);
    EXPECT_TRUE(inv->match);
}

// ── (4) bestCL CONSTRAINT: differing CL heights don't count; equal-height
//        differing sig does ──────────────────────────────────────────────────
TEST(OracleShadow, BestCLIsRangeConstraint) {
    // Different bestCLHeightDiff (propagation lag) -> NOT counted.
    auto ce = make_cbtx(1000, 5000000, 1, 100, /*cl_diff=*/2);
    auto cd = make_cbtx(1000, 5000000, 1, 100, /*cl_diff=*/0);
    auto e = make_wd(1000, ce, payees(1000, 90000), 500000000, {});
    auto d = make_wd(1000, cd, payees(1000, 90000), 500000000, {});
    auto fr = compare_templates(side(e, ce), side(d, cd),
                                std::optional<int64_t>(4999000), false, true);
    const auto* hd = find(fr, "bestCLHeightDiff");
    ASSERT_TRUE(hd);
    EXPECT_EQ(hd->regime, Regime::Constraint);
    EXPECT_FALSE(hd->counts);   // differing heights are propagation lag, not a bug

    // Same CL height, differing sig -> counts (same height => same CL => same sig).
    auto ce2 = make_cbtx(1000, 5000000, 1, 100, 0); ce2.bestCLSignature.fill(0xAB);
    auto cd2 = make_cbtx(1000, 5000000, 1, 100, 0); cd2.bestCLSignature.fill(0xCD);
    auto e2 = make_wd(1000, ce2, payees(1000, 90000), 500000000, {});
    auto d2 = make_wd(1000, cd2, payees(1000, 90000), 500000000, {});
    auto fr2 = compare_templates(side(e2, ce2), side(d2, cd2),
                                 std::optional<int64_t>(4999000), false, true);
    const auto* sig = find(fr2, "bestCLSignature");
    ASSERT_TRUE(sig);
    EXPECT_TRUE(sig->counts);
    EXPECT_FALSE(sig->match);
}

// ── (5) wrong MN root on empty templates -> EQUALITY, counts ─────────────────
TEST(OracleShadow, WrongMNRootEqualityCounts) {
    auto ce = make_cbtx(1000, 5000000, /*mn_seed=*/1);
    auto cd = make_cbtx(1000, 5000000, /*mn_seed=*/9);
    auto e = make_wd(1000, ce, payees(1000, 90000), 500000000, {});
    auto d = make_wd(1000, cd, payees(1000, 90000), 500000000, {});
    auto fr = compare_templates(side(e, ce), side(d, cd),
                                std::optional<int64_t>(4999000), false, true);
    const auto* r = find(fr, "merkleRootMNList");
    ASSERT_TRUE(r);
    EXPECT_EQ(r->regime, Regime::Equality);
    EXPECT_TRUE(r->counts);
}

// ── (6) GraduationLedger: proposal-gated clean + N/K/reorg/serve-rate ────────
TEST(OracleShadow, GraduationPredicate) {
    GraduationLedger led;
    GraduationConfig cfg;
    cfg.consecutive_clean_target = 12;
    cfg.per_class_coverage_target = 2;
    cfg.serve_rate_floor = 0.5;

    // A proposal-REJECTED served height never counts clean.
    led.record_served(1, {HeightClass::Normal}, /*proposal_ok=*/false, {});
    EXPECT_EQ(led.consecutive_clean, 0u);
    EXPECT_EQ(led.proposal_rejected, 1u);

    // Feed clean served heights covering each required class + a reorg.
    for (uint32_t h = 2; h <= 13; ++h) {
        std::set<HeightClass> cl{HeightClass::Normal};
        if (h <= 3) cl.insert(HeightClass::DkgWindow);
        if (h >= 4 && h <= 5) cl.insert(HeightClass::Superblock);
        if (h >= 6 && h <= 7) cl.insert(HeightClass::PostRestartCold);
        if (h >= 8 && h <= 9) cl.insert(HeightClass::QuorumRotation);
        if (h >= 10 && h <= 11) cl.insert(HeightClass::CreditPoolTransition);
        if (h >= 12 && h <= 13) cl.insert(HeightClass::NonEmptyTemplate);
        if (h == 7) cl.insert(HeightClass::Reorg);
        led.record_served(h, cl, /*proposal_ok=*/true, {});
    }
    EXPECT_GE(led.consecutive_clean, 12u);
    EXPECT_GE(led.reorg_covered, 1u);
    EXPECT_GT(led.serve_rate(), 0.5);
    EXPECT_TRUE(led.is_graduated(cfg)) << led.verdict_json(cfg).dump(2);

    // A counted divergence resets the streak.
    led.record_served(14, {HeightClass::Normal}, true, {"merkleRootMNList"});
    EXPECT_EQ(led.consecutive_clean, 0u);
    EXPECT_FALSE(led.is_graduated(cfg));
    EXPECT_EQ(led.divergences_by_field["merkleRootMNList"], 1u);
}

// ── (6b) fall-closed classes are declared as residual serve-gaps ─────────────
TEST(OracleShadow, FallClosedDeclaredAsServeGap) {
    GraduationLedger led;
    GraduationConfig cfg;
    // Superblock only ever fall-closed (never served) -> declared serve-gap.
    led.note_fall_closed(100, {HeightClass::Superblock, HeightClass::Normal});
    auto v = led.verdict_json(cfg);
    EXPECT_EQ(v["verdict"], "NOT-GRADUATED");
    ASSERT_TRUE(v["residual_serve_gaps"].contains("superblock"));
}

// ── (6c) revocation withholds graduation ─────────────────────────────────────
TEST(OracleShadow, RevocationWithholdsGraduation) {
    GraduationLedger led;
    GraduationConfig cfg;
    cfg.consecutive_clean_target = 1;
    cfg.per_class_coverage_target = 0;
    led.record_served(1, {HeightClass::Reorg}, true, {});
    // Even fully-covered, a revoke blocks graduation.
    led.revoked = true; led.revoked_reason = "unknown CbTx version";
    EXPECT_FALSE(led.is_graduated(cfg));
    EXPECT_EQ(led.verdict_json(cfg)["revoked"], true);
}

// ── (7) serve-rate floor gates a cherry-picking arm ──────────────────────────
TEST(OracleShadow, ServeRateFloorGates) {
    GraduationLedger led;
    GraduationConfig cfg;
    cfg.consecutive_clean_target = 1;
    cfg.per_class_coverage_target = 0;
    cfg.serve_rate_floor = 0.5;
    // 1 served normal + 9 fall-closed normals -> serve_rate 0.1 < 0.5.
    led.record_served(1, {HeightClass::Normal, HeightClass::Reorg}, true, {});
    for (uint32_t h = 2; h <= 10; ++h) led.note_fall_closed(h, {HeightClass::Normal});
    EXPECT_LT(led.serve_rate(), 0.5);
    EXPECT_FALSE(led.is_graduated(cfg));
}

// ── (8) NetPeriodicity height classification ─────────────────────────────────
TEST(OracleShadow, HeightClassification) {
    auto t = NetPeriodicity::for_net(true);
    EXPECT_TRUE(t.is_superblock(24));
    EXPECT_FALSE(t.is_superblock(25));
    EXPECT_TRUE(t.is_dkg_window(24 * 5 + 12));
    EXPECT_FALSE(t.is_dkg_window(24 * 5 + 1));
    auto m = NetPeriodicity::for_net(false);
    EXPECT_TRUE(m.is_superblock(16616));
    EXPECT_FALSE(m.is_superblock(16617));
}
