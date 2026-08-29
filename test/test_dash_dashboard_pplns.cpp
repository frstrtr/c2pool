// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// test_dash_dashboard_pplns — BINDING KATs for the DASH PPLNS dashboard views:
// the pool-wide split behind /current_payouts (and therefore
// /current_merged_payouts and the main dashboard treemap), and the PER-SHARE
// split attached to an individual share's page.
//
// THE DEFECT. rest_current_payouts() has three sources (web_server.cpp:2365):
// the #939 direct seam m_current_payouts_fn, the coinbase-builder cache
// m_cached_pplns_outputs, and a fallback. On DASH the first was never bound —
// its only callers repo-wide were in core/test/web_server_current_payouts_test
// .cpp, i.e. the seam shipped green and inert — and the second is filled by
// refresh_work(), which never runs on the DASH lane (web_server.cpp:3902).
// So the endpoint returned `{}` on a node with a full 4320-share window, which
// then propagated: compute_current_merged_payouts() starts from it (:5964), so
// /current_merged_payouts was {} too, so renderMainPPLNS({}) drew zero cells.
//
// WHY THESE KATs ARE NOT VACUOUS. The assertions pin the split against the
// SAME allocator the DASH coinbase uses — dash::coinbase::compute_dash_payouts
// over dash::mint::pplns_weights_for — rather than against a re-implementation
// here, and each positive case is paired with the honest-miss case that the
// unwired lane produced. A KAT asserting only "returns an object" would have
// passed on `{}`.
//
// Display-only surface: nothing here reaches mint, submission or the served
// coinbase. Both entry points take an already-read-locked chain and only read.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/dash/dashboard_pplns.hpp>
#include <impl/dash/node.hpp>
#include <impl/dash/params.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/share_check.hpp>

#include <core/address_utils.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace {

constexpr uint32_t P_BLOCK_BITS = 0x1d00ffff;
constexpr uint32_t P_SHARE_BITS = 0x1e0ffff0;
constexpr uint32_t P_BASE_TIME  = 1753000000;
// A real-shaped DASH block reward split: 5.00000000 DASH total, with the
// masternode taking 0.83 and the platform burn 0.49 (the proportions measured
// on our own accepted h=2516911).
constexpr uint64_t P_SUBSIDY    = 500000000;
constexpr uint64_t P_MN_PAY     =  83040000;
constexpr uint64_t P_BURN_PAY   =  49790000;

uint256 p_hash(unsigned int n)
{
    static const char* digits = "0123456789abcdef";
    std::string s = "5c";
    s += digits[(n >> 12) & 0xf];
    s += digits[(n >>  8) & 0xf];
    s += digits[(n >>  4) & 0xf];
    s += digits[ n        & 0xf];
    s += std::string(64 - s.size(), '0');
    uint256 h;
    h.SetHex(s);
    return h;
}

uint160 p_pkh(unsigned char b)
{
    static const char* digits = "0123456789abcdef";
    std::string s;
    s += digits[b >> 4];
    s += digits[b & 0x0f];
    s += std::string(40 - s.size(), '5');
    uint160 h;
    h.SetHex(s);
    return h;
}

std::string p_addr(unsigned char b)
{
    return core::script_to_address(dash::pubkey_hash_to_script2(p_pkh(b)), "", 76, 16);
}

dash::DashShare* make_pplns_share(unsigned int n, const uint256& prev,
                                  unsigned char pkh_byte, bool with_payments)
{
    auto* s = new dash::DashShare();
    s->m_hash      = p_hash(n);
    s->m_prev_hash = prev;
    s->m_min_header.m_bits      = P_BLOCK_BITS;
    s->m_min_header.m_timestamp = P_BASE_TIME + n;
    s->m_bits        = P_SHARE_BITS;
    s->m_max_bits    = P_SHARE_BITS;
    s->m_timestamp   = P_BASE_TIME + n;
    s->m_absheight   = 2500000 + n;
    s->m_pubkey_hash = p_pkh(pkh_byte);
    s->m_subsidy     = P_SUBSIDY;
    s->m_donation    = 0;
    if (with_payments) {
        // A base58 masternode payee plus the normalized OP_RETURN platform
        // burn ("!6a..."), i.e. both forms decode_payee_script handles.
        dash::PackedPayment mn;
        mn.m_payee  = p_addr(0xc0);
        mn.m_amount = P_MN_PAY;
        dash::PackedPayment burn;
        burn.m_payee  = "!6a0101";
        burn.m_amount = P_BURN_PAY;
        s->m_packed_payments = {mn, burn};
        s->m_payment_amount  = P_MN_PAY + P_BURN_PAY;
    }
    return s;
}

struct PplnsHarness
{
    dash::NodeImpl   node;
    core::CoinParams params = dash::make_coin_params(/*testnet=*/false);
    uint256          tip;

    // `n` shares alternating between three miners, so the split is
    // demonstrably proportional and not a single-recipient degenerate.
    explicit PplnsHarness(unsigned int n, bool with_payments = true)
    {
        uint256 prev = uint256::ZERO;
        for (unsigned int i = 0; i < n; ++i) {
            auto* s = make_pplns_share(i, prev,
                                       static_cast<unsigned char>(0xa0 + (i % 3)),
                                       with_payments);
            node.tracker().chain.add(s);
            prev = s->m_hash;
            tip  = s->m_hash;
        }
    }
};

double sum_values(const nlohmann::json& j)
{
    double t = 0;
    for (const auto& [k, v] : j.items()) { (void)k; t += v.get<double>(); }
    return t;
}

} // namespace

// ── KAT 1: the per-share PPLNS view ─────────────────────────────────────────
TEST(DashDashboardPplns, PerShareViewSplitsTheShareOwnWorkerPayout)
{
    PplnsHarness h(40);
    auto v = dash::dashboard::pplns_payouts_for_share(
        h.node.tracker().chain, h.params, h.tip, /*testnet=*/false);

    ASSERT_TRUE(v.ok) << "per-share PPLNS came back empty — this is the "
                         "unwired-seam symptom, not a valid answer";

    // The reward decomposition is the share's OWN recorded numbers.
    EXPECT_EQ(v.subsidy,        P_SUBSIDY);
    EXPECT_EQ(v.payments_total, P_MN_PAY + P_BURN_PAY);
    EXPECT_EQ(v.worker_payout,  P_SUBSIDY - P_MN_PAY - P_BURN_PAY);

    // Masternode / platform outputs are consensus-mandated block outputs, not
    // pool payouts — folding them in would overstate what the pool distributes.
    EXPECT_FALSE(v.payouts.contains(p_addr(0xc0)))
        << "masternode payee leaked into the PPLNS view";

    // Three miners contributed; the donation line is always emitted.
    EXPECT_GE(v.recipients, 3);
    for (unsigned char b : {0xa0, 0xa1, 0xa2})
        EXPECT_TRUE(v.payouts.contains(p_addr(static_cast<unsigned char>(b))))
            << "missing miner " << p_addr(static_cast<unsigned char>(b));

    // Every rendered key is a DASH mainnet address ('X'), never a Bitcoin '1'.
    for (const auto& [addr, amt] : v.payouts.items()) {
        (void)amt;
        EXPECT_FALSE(addr.empty());
        EXPECT_TRUE(addr[0] == 'X' || addr[0] == '7')
            << "non-DASH address rendering: " << addr;
    }

    // The pre-v36 arm reserves 1/50 of worker_payout for the block finder,
    // which IS this share's own miner — so the view sums to the full
    // worker_payout, and the finder's own row is the largest.
    EXPECT_NEAR(sum_values(v.payouts),
                static_cast<double>(v.worker_payout) / 1e8, 1e-6);
}

// ── KAT 2: honest miss on a cold / unknown chain ────────────────────────────
TEST(DashDashboardPplns, PerShareViewMissesHonestly)
{
    PplnsHarness h(40);

    // Unknown share.
    auto miss = dash::dashboard::pplns_payouts_for_share(
        h.node.tracker().chain, h.params, p_hash(9999), false);
    EXPECT_FALSE(miss.ok);
    EXPECT_TRUE(miss.payouts.empty());

    // Chain too short for a window (the genesis share has no grandparent).
    PplnsHarness cold(1);
    auto c = dash::dashboard::pplns_payouts_for_share(
        cold.node.tracker().chain, cold.params, cold.tip, false);
    EXPECT_FALSE(c.ok);
    EXPECT_TRUE(c.payouts.empty())
        << "a cold chain must yield NOTHING, never a fabricated row";
}

// ── KAT 3: no masternode payments -> the whole subsidy is the worker payout ─
TEST(DashDashboardPplns, WithoutPaymentsTheWholeSubsidyIsSplit)
{
    PplnsHarness h(40, /*with_payments=*/false);
    auto v = dash::dashboard::pplns_payouts_for_share(
        h.node.tracker().chain, h.params, h.tip, false);

    ASSERT_TRUE(v.ok);
    EXPECT_EQ(v.payments_total, 0u);
    EXPECT_EQ(v.worker_payout, P_SUBSIDY);
    EXPECT_NEAR(sum_values(v.payouts), static_cast<double>(P_SUBSIDY) / 1e8, 1e-6);
}

// ── KAT 4: the pool-wide view, and its finder-fee omission ──────────────────
TEST(DashDashboardPplns, PoolWideViewOmitsTheFinderFeeLikeLtcDoes)
{
    PplnsHarness h(40);

    std::vector<dash::coin::PackedPayment> tmpl_payments = {
        {p_addr(0xc0), P_MN_PAY},
        {"!6a0101",    P_BURN_PAY},
    };

    // Same call the pool-wide binding makes: zero finder pubkey hash, and that
    // one output dropped. This matches LTC, where get_v35_expected_payouts is
    // documented as "amounts WITHOUT finder fee — caller adds subsidy/200"
    // (share_tracker.hpp:2058) and main_ltc's pplns_fn returns it unmodified.
    auto pool = dash::dashboard::pplns_payouts_at(
        h.node.tracker().chain, h.params, h.tip, P_BLOCK_BITS, P_SUBSIDY,
        tmpl_payments, uint160(), /*drop_finder_output=*/true, /*testnet=*/false);

    ASSERT_TRUE(pool.ok);
    EXPECT_FALSE(pool.payouts.contains(p_addr(0xc0)));   // no masternode row
    // The zero-pubkey-hash placeholder must never be rendered as a payee.
    EXPECT_FALSE(pool.payouts.contains(
        core::script_to_address(dash::pubkey_hash_to_script2(uint160()), "", 76, 16)));

    // 2% of worker_payout is reserved for the (as-yet unknown) block finder, so
    // the pool-wide view sums to ~98% of it — a definite, checkable number
    // rather than "some subset".
    const double worker = static_cast<double>(pool.worker_payout) / 1e8;
    EXPECT_NEAR(sum_values(pool.payouts), worker * 0.98, worker * 0.001);

    // The per-share view of the same anchor DOES carry a finder, so it sums to
    // the full worker payout — the two views differ exactly by that 2%.
    auto with_finder = dash::dashboard::pplns_payouts_at(
        h.node.tracker().chain, h.params, h.tip, P_BLOCK_BITS, P_SUBSIDY,
        tmpl_payments, p_pkh(0xa0), /*drop_finder_output=*/false, false);
    ASSERT_TRUE(with_finder.ok);
    EXPECT_NEAR(sum_values(with_finder.payouts), worker, 1e-6);
    EXPECT_GT(sum_values(with_finder.payouts), sum_values(pool.payouts));
}

// ── KAT 5: no template -> the pool-wide view falls back to the best share ────
// This is the fix. On a fully daemonless node with ZERO local miners nothing
// ever pumps the work-source template cache (the stratum work-serving paths are
// the only producers), so TemplateSource::peek() is permanently null there and
// the pool-wide /current_payouts, /current_merged_payouts and /pplns/current
// used to render `{}` over a full sharechain window. p2pool has no such coupling
// (get_expected_payouts takes subsidy as a parameter, data.py:3273), so the
// pool-wide split must derive from the sharechain alone. It now snapshots the
// block params off the BEST SHARE's own recorded fields.
TEST(DashDashboardPplns, NoTemplateFallsBackToBestShareSnapshot)
{
    PplnsHarness h(40);
    dash::dashboard::TemplateSource tmpl;   // never bound — the zero-miner node
    EXPECT_EQ(tmpl.peek(), nullptr);

    auto snap = dash::dashboard::pplns_payouts_current(
        h.node.tracker().chain, h.params, h.tip, tmpl, /*testnet=*/false);

    ASSERT_TRUE(snap.ok) << "a full sharechain with no live template must still "
                            "render the pool-wide split — this is the zero-miner "
                            "dashboard, and {} here IS the bug";
    EXPECT_FALSE(snap.payouts.empty());

    // The snapshot uses the best SHARE's own recorded reward decomposition
    // (subsidy, masternode + burn payments), NOT a fabricated one.
    EXPECT_EQ(snap.subsidy,        P_SUBSIDY);
    EXPECT_EQ(snap.payments_total, P_MN_PAY + P_BURN_PAY);
    EXPECT_EQ(snap.worker_payout,  P_SUBSIDY - P_MN_PAY - P_BURN_PAY);

    // Pool-wide contract, identical to the live-template path: masternode payee
    // excluded, finder placeholder dropped, three miners split ~98% of the
    // worker payout (the missing 2% is the unknown finder's reserve).
    EXPECT_FALSE(snap.payouts.contains(p_addr(0xc0)));
    EXPECT_FALSE(snap.payouts.contains(
        core::script_to_address(dash::pubkey_hash_to_script2(uint160()), "", 76, 16)));
    EXPECT_GE(snap.recipients, 3);
    const double worker = static_cast<double>(snap.worker_payout) / 1e8;
    EXPECT_NEAR(sum_values(snap.payouts), worker * 0.98, worker * 0.001);

    // Every rendered key is a DASH address, never a Bitcoin '1'.
    for (const auto& [addr, amt] : snap.payouts.items()) {
        (void)amt;
        EXPECT_TRUE(!addr.empty() && (addr[0] == 'X' || addr[0] == '7'))
            << "non-DASH address rendering: " << addr;
    }

    // A LIVE template takes strict precedence over the snapshot: bind one whose
    // reward differs (single masternode payment, no burn) and the view switches
    // to it — nodes WITH miners are unchanged by this fallback.
    auto wd = std::make_shared<dash::coin::DashWorkData>();
    wd->m_coinbase_value  = P_SUBSIDY;
    wd->m_bits            = P_BLOCK_BITS;
    wd->m_packed_payments = {{p_addr(0xc0), P_MN_PAY}};
    tmpl.bind([wd]() -> std::shared_ptr<const dash::coin::DashWorkData> { return wd; });

    auto live = dash::dashboard::pplns_payouts_current(
        h.node.tracker().chain, h.params, h.tip, tmpl, false);
    ASSERT_TRUE(live.ok);
    EXPECT_EQ(live.worker_payout, P_SUBSIDY - P_MN_PAY)
        << "a bound template must win over the best-share snapshot";
}

// ── KAT 6: an empty sharechain still yields nothing (p2pool's one guard) ─────
// The fallback must NOT invent payouts when there is no share to snapshot — the
// post-restart empty-chain case stays `{}` exactly as get_expected_payouts does.
TEST(DashDashboardPplns, NoTemplateAndNoSharesStaysEmpty)
{
    // A single genesis share: present, but too short for a window (no
    // grandparent), so pplns_weights_for misses — the snapshot must degrade to
    // empty, never a fabricated row.
    PplnsHarness cold(1);
    dash::dashboard::TemplateSource tmpl;   // never bound
    auto v = dash::dashboard::pplns_payouts_current(
        cold.node.tracker().chain, cold.params, cold.tip, tmpl, /*testnet=*/false);
    EXPECT_FALSE(v.ok);
    EXPECT_TRUE(v.payouts.empty());

    // A null best-share hash (a genuinely empty chain) is the same honest empty.
    auto none = dash::dashboard::pplns_payouts_current(
        cold.node.tracker().chain, cold.params, uint256::ZERO, tmpl, false);
    EXPECT_FALSE(none.ok);
    EXPECT_TRUE(none.payouts.empty());
}
