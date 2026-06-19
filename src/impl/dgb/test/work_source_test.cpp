// dgb::stratum::DGBWorkSource — Stage 4a skeleton construction + contract test.
//
// Proves the work source instantiates against the live coin types
// (c2pool::dgb::HeaderChain + dgb::coin::Mempool), satisfies the full
// core::stratum::IWorkSource pure-virtual contract (so core::StratumServer
// can hold it via shared_ptr<IWorkSource> in the next slice), and that its
// real-now surface (config defaults, atomic work-generation, share-target
// atomics, worker registry, best-share callback) behaves. The stubbed
// work-generation / submit methods are asserted to return their documented
// safe defaults so a regression that accidentally "implements" them with
// garbage is caught.
//
// MUST appear in BOTH this ctest registration AND the build.yml --target
// allowlist, or it becomes a #143-style NOT_BUILT sentinel that reds master.

#include <impl/dgb/stratum/work_source.hpp>
#include <impl/dgb/coin/header_chain.hpp>
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/config_coin.hpp>   // dgb::CoinParams::subsidy (oracle SSOT)

#include <core/pow.hpp>                 // core::SubsidyFunc

#include <core/stratum_work_source.hpp>

#include <gtest/gtest.h>

#include <memory>
#include <optional>

namespace {

// IDENTICAL to params.hpp `p.subsidy_func` — the live CoinParams indirection.
const core::SubsidyFunc kSubsidyFunc =
    [](uint32_t height) -> uint64_t { return dgb::CoinParams::subsidy(height); };

// Construct a DGBWorkSource over default-constructed coin deps. The submit
// callback records whether it was invoked (it must NOT be in the 4a skeleton).
struct Fixture {
    c2pool::dgb::HeaderChain chain;
    dgb::coin::Mempool       mempool;
    bool                     submit_called = false;

    std::unique_ptr<dgb::stratum::DGBWorkSource> make()
    {
        auto fn = [this](const std::vector<unsigned char>&, uint32_t) -> bool {
            submit_called = true;
            return false;
        };
        return std::make_unique<dgb::stratum::DGBWorkSource>(
            chain, mempool, /*is_testnet=*/false, fn, kSubsidyFunc);
    }
};

TEST(DgbWorkSource, ConstructsAndSatisfiesIWorkSourceContract)
{
    Fixture fx;
    auto ws = fx.make();
    // Usable through the abstract interface core::StratumServer holds.
    core::stratum::IWorkSource* iface = ws.get();
    ASSERT_NE(iface, nullptr);
}

TEST(DgbWorkSource, ConfigDefaultsMatchStratumConfig)
{
    Fixture fx;
    auto ws = fx.make();
    const auto& cfg = ws->get_stratum_config();
    EXPECT_DOUBLE_EQ(cfg.min_difficulty, 0.0005);
    EXPECT_DOUBLE_EQ(cfg.max_difficulty, 65536.0);
    EXPECT_DOUBLE_EQ(cfg.target_time, 3.0);
    EXPECT_TRUE(cfg.vardiff_enabled);
}

TEST(DgbWorkSource, WorkGenerationStartsZeroAndBumps)
{
    Fixture fx;
    auto ws = fx.make();
    EXPECT_EQ(ws->get_work_generation(), 0u);
    ws->bump_work_generation();
    ws->bump_work_generation();
    EXPECT_EQ(ws->get_work_generation(), 2u);
}

TEST(DgbWorkSource, ShareTargetAtomicsRoundTrip)
{
    Fixture fx;
    auto ws = fx.make();
    EXPECT_EQ(ws->get_share_bits(), 0u);
    EXPECT_EQ(ws->get_share_max_bits(), 0u);
    ws->set_share_target(0x1d00ffff, 0x1e0fffff);
    EXPECT_EQ(ws->get_share_bits(), 0x1d00ffffu);
    EXPECT_EQ(ws->get_share_max_bits(), 0x1e0fffffu);
}

TEST(DgbWorkSource, NoMergedChainInDefaultBuild)
{
    Fixture fx;
    auto ws = fx.make();
    // DGB V36 default build is a standalone Scrypt parent (no merged mining;
    // -DAUX_DOGE dual-parent is a parked STRETCH).
    EXPECT_FALSE(ws->has_merged_chain(0x0001));
}

TEST(DgbWorkSource, BestShareHashFnEmptyUntilWired)
{
    Fixture fx;
    auto ws = fx.make();
    EXPECT_FALSE(static_cast<bool>(ws->get_best_share_hash_fn()));
    ws->set_best_share_hash_fn([]() { return uint256::ZERO; });
    auto fn = ws->get_best_share_hash_fn();
    ASSERT_TRUE(static_cast<bool>(fn));
    EXPECT_EQ(fn(), uint256::ZERO);
}

TEST(DgbWorkSource, WorkerRegistryRoundTrip)
{
    Fixture fx;
    auto ws = fx.make();
    core::stratum::WorkerInfo info;
    info.username    = "DGBaddr.worker1";
    info.worker_name = "worker1";
    ws->register_stratum_worker("sess-1", info);
    ws->update_stratum_worker("sess-1", /*hashrate=*/1.0e9, /*dead=*/0.0,
                              /*difficulty=*/16.0, /*accepted=*/3, /*rejected=*/0, /*stale=*/0);
    // No crash + idempotent unregister of a known + unknown session.
    ws->unregister_stratum_worker("sess-1");
    ws->unregister_stratum_worker("sess-unknown");
    SUCCEED();
}

TEST(DgbWorkSource, WorkGenStubsReturnSafeDefaults)
{
    Fixture fx;
    auto ws = fx.make();
    // 4a skeleton: every work-generation getter returns its documented
    // empty/default form (4c fills them in).
    EXPECT_TRUE(ws->get_current_gbt_prevhash().empty());
    // get_current_work_template() now emits height + coinbasevalue (Stage 4c
    // coinbasevalue wire); its dedicated assertions live in
    // WorkTemplateEmitsHeightAndCoinbaseValueViaSsot below.
    EXPECT_TRUE(ws->get_current_work_template().is_object());
    EXPECT_TRUE(ws->get_stratum_merkle_branches().empty());
    auto parts = ws->get_coinbase_parts();
    EXPECT_TRUE(parts.first.empty());
    EXPECT_TRUE(parts.second.empty());
}

TEST(DgbWorkSource, MiningSubmitStubRejectsWithoutCallingBroadcaster)
{
    Fixture fx;
    auto ws = fx.make();
    auto result = ws->mining_submit(
        "DGBaddr.worker1", "job-0", "en1", "en2", "ntime", "nonce", "rid-0",
        /*merged_addresses=*/{}, /*job=*/nullptr);
    // Stratum mining.submit response = [false, [code, msg, null]] reject form.
    ASSERT_TRUE(result.is_array());
    ASSERT_GE(result.size(), 1u);
    EXPECT_FALSE(result[0].get<bool>());
    // The 4a stub must NOT have reached the won-block broadcaster.
    EXPECT_FALSE(fx.submit_called);
}

TEST(DgbWorkSource, ComputeShareDifficultyReturnsNotYetSentinel)
{
    Fixture fx;
    auto ws = fx.make();
    // 4a skeleton: the per-coin (Scrypt) PoW-difficulty hook returns the
    // documented 0.0 parse-error/not-yet sentinel. The coin-agnostic
    // StratumServer's vardiff gate treats 0.0 as a hard reject, so no
    // garbage difficulty leaks into the rate monitor before 4b/4c land
    // the real scrypt_1024_1_1_256 assembly.
    double diff = ws->compute_share_difficulty(
        "coinb1", "coinb2", "en1", "en2", "ntime", "nonce",
        /*version=*/0x20000000u, "prevhash", "1e0ffff0",
        /*merkle_branches=*/{});
    EXPECT_DOUBLE_EQ(diff, 0.0);
}

// Stage 4c coinbasevalue wire: the work template surfaces the NEXT-block
// height and its coinbasevalue, the latter derived THROUGH the #207 SSOT
// (subsidy_func) keyed on next_block_height() == tip.height + 1 (#209). An
// empty chain makes next_block_height() == base_height, so seeding an oracle
// era boundary pins the value unambiguously to the p2pool-dgb-scrypt subsidy.
TEST(DgbWorkSource, WorkTemplateEmitsHeightAndCoinbaseValueViaSsot)
{
    Fixture fx;
    fx.chain.set_base_height(400000);  // phase3 first block (oracle boundary)
    auto ws = fx.make();
    auto tmpl = ws->get_current_work_template();
    ASSERT_TRUE(tmpl.is_object());
    ASSERT_TRUE(tmpl.contains("height"));
    ASSERT_TRUE(tmpl.contains("coinbasevalue"));
    // next_h = next_block_height() = base_height (empty chain) = 400000.
    EXPECT_EQ(tmpl["height"].get<uint32_t>(), 400000u);
    // Zero embedded fees, no external GBT -> oracle subsidy at the boundary.
    EXPECT_EQ(tmpl["coinbasevalue"].get<uint64_t>(), 2434410000ULL);
}

// Stage 4c GBT scaffold: alongside height + coinbasevalue, the work template
// now surfaces the GBT fields the embedded path can derive truthfully without
// a TemplateBuilder port -- version (Scrypt algo lane), curtime, mintime, and
// an (empty) transactions[]. previousblockhash + bits intentionally stay absent
// until HeaderSample carries the tip hash / next-target compact (later slices).
TEST(DgbWorkSource, WorkTemplateEmitsGbtScaffoldFields)
{
    Fixture fx;
    fx.chain.set_base_height(400000);
    auto ws = fx.make();
    auto tmpl = ws->get_current_work_template();
    ASSERT_TRUE(tmpl.is_object());

    // version pins the DGB Scrypt lane: BIP9 base | algo nibble 0x0000.
    ASSERT_TRUE(tmpl.contains("version"));
    EXPECT_EQ(tmpl["version"].get<uint32_t>(), 0x20000000u);

    // Empty chain -> median_time_past() == INT64_MIN -> mintime emitted as 0
    // (unconstrained), and curtime is a real wall-clock stamp (>= 0).
    ASSERT_TRUE(tmpl.contains("mintime"));
    EXPECT_EQ(tmpl["mintime"].get<int64_t>(), 0);
    ASSERT_TRUE(tmpl.contains("curtime"));
    EXPECT_GE(tmpl["curtime"].get<int64_t>(), 0);

    // No embedded tx selection yet -> transactions[] present but empty (no
    // fabricated entries; consistent with the total_fees=0 coinbasevalue).
    ASSERT_TRUE(tmpl.contains("transactions"));
    EXPECT_TRUE(tmpl["transactions"].is_array());
    EXPECT_TRUE(tmpl["transactions"].empty());

    // The two hash/difficulty fields are deliberately NOT emitted yet.
    EXPECT_FALSE(tmpl.contains("previousblockhash"));
    EXPECT_FALSE(tmpl.contains("bits"));
}

// ── Embedded coinbasevalue: first production caller of subsidy_func ──────────
// One pin on each side of every DGB reward-era boundary (p2pool-dgb-scrypt
// oracle vectors, test_dgb_subsidy.cpp).
namespace {
struct EraVec { uint32_t height; uint64_t subsidy; const char* era; };
constexpr EraVec kEraBoundaries[] = {
    {67199,   8000000000ULL, "phase1-fixed last"},
    {67200,   7960000000ULL, "phase2 -0.5%/wk first"},
    {399999,  6746441103ULL, "phase2 last"},
    {400000,  2434410000ULL, "phase3 -1%/wk first"},
    {1429999, 2157824200ULL, "phase3 last"},
    {1430000, 1078500000ULL, "phase4 monthly-decay first"},
};
}  // namespace

// No external GBT (embedded path): coinbasevalue is derived THROUGH the work
// source's subsidy_func at every era boundary, zero fees -> oracle subsidy.
TEST(DgbWorkSource, CoinbaseValueDerivesViaSubsidyFuncWhenNoGbt)
{
    Fixture fx;
    auto ws = fx.make();
    for (const auto& v : kEraBoundaries) {
        EXPECT_EQ(ws->coinbase_value(v.height, /*fees=*/0, std::nullopt), v.subsidy)
            << "embedded coinbasevalue diverged from oracle subsidy at " << v.era;
    }
}

// Fees compose additively on the embedded path: subsidy + total_fees.
TEST(DgbWorkSource, CoinbaseValueAddsFeesOnEmbeddedPath)
{
    Fixture fx;
    auto ws = fx.make();
    constexpr uint64_t kFees = 1234567ULL;
    for (const auto& v : kEraBoundaries) {
        EXPECT_EQ(ws->coinbase_value(v.height, kFees, std::nullopt), v.subsidy + kFees)
            << "fee addition wrong at " << v.era;
    }
}

// External-daemon fallback PERSISTS: a present GBT coinbasevalue is authoritative
// and returned verbatim through the work source, bypassing local derivation.
TEST(DgbWorkSource, CoinbaseValueHonorsGbtVerbatim)
{
    Fixture fx;
    auto ws = fx.make();
    constexpr uint64_t kGbt = 99999999999ULL;  // deliberately != subsidy+fees
    EXPECT_EQ(ws->coinbase_value(/*height=*/400000, /*fees=*/500,
                                 std::optional<uint64_t>{kGbt}),
              kGbt);
}


// previousblockhash: emitted as GBT-conventional big-endian display hex ONLY
// when the HeaderChain carries a real tip hash (tip_hash() accessor). With a
// known tip block_hash, the template surfaces it MSB-limb-first; bits stays
// HELD (no faithful embedded V36 next-target -- MultiShield V4 is V37).
TEST(DgbWorkSource, WorkTemplateEmitsPreviousBlockHashWhenTipCarriesHash)
{
    Fixture fx;
    fx.chain.set_base_height(400000);
    // Seed one Scrypt header carrying a distinctive block id. n_version with
    // algo nibble 0x0000 is the Scrypt lane; target 100 with pow_hash 0 (<=
    // target) clears the context-free PoW gate; empty-chain MTP is unconstrained.
    c2pool::dgb::HeaderSample h;
    h.n_version  = 0x20000000;
    h.n_time     = 1000;
    h.target     = 100;
    h.block_hash = dgb::coin::u256::from_u64(0x123456789abcdef0ULL);
    ASSERT_EQ(fx.chain.validate_and_append(h),
              c2pool::dgb::IngestResult::VALIDATED_SCRYPT);

    auto ws = fx.make();
    auto tmpl = ws->get_current_work_template();
    ASSERT_TRUE(tmpl.contains("previousblockhash"));
    // limb[0] is least-significant -> renders as the trailing 16 hex digits,
    // preceded by 48 zero digits (limbs 3..1 are zero). 64 chars total.
    EXPECT_EQ(tmpl["previousblockhash"].get<std::string>(),
              std::string(48, '0') + "123456789abcdef0");
    // bits remains deliberately absent (V37 MultiShield V4 wall).
    EXPECT_FALSE(tmpl.contains("bits"));
}

// The dedicated prevhash getter and the assembled template draw the tip hash
// from ONE source (chain_.tip_hash() through u256_be_display_hex), so they can
// never diverge: with a real tip the getter returns the SAME BE-display-hex the
// template emits; with no tip BOTH are absent (getter empty string, template
// omits the field).
TEST(DgbWorkSource, GbtPrevhashGetterMatchesTemplateField)
{
    Fixture fx;
    // No tip yet -> getter empty, template omits previousblockhash.
    {
        auto ws = fx.make();
        EXPECT_TRUE(ws->get_current_gbt_prevhash().empty());
        EXPECT_FALSE(ws->get_current_work_template().contains("previousblockhash"));
    }
    // Seed a Scrypt header carrying a distinctive block id (mirrors the
    // previousblockhash emit test) -> getter == template field, BE-display-hex.
    fx.chain.set_base_height(400000);
    c2pool::dgb::HeaderSample h;
    h.n_version  = 0x20000000;
    h.n_time     = 1000;
    h.target     = 100;
    h.block_hash = dgb::coin::u256::from_u64(0x123456789abcdef0ULL);
    ASSERT_EQ(fx.chain.validate_and_append(h),
              c2pool::dgb::IngestResult::VALIDATED_SCRYPT);

    auto ws = fx.make();
    const std::string expected = std::string(48, '0') + "123456789abcdef0";
    EXPECT_EQ(ws->get_current_gbt_prevhash(), expected);
    EXPECT_EQ(ws->get_current_work_template()["previousblockhash"].get<std::string>(),
              expected);
}

}  // namespace
