// SPDX-License-Identifier: AGPL-3.0-or-later
#include <cmath>
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
#include <impl/dgb/coin/dgb_arith256.hpp>  // compact_to_target (#179 MultiShield V4 served-bits window)
#include <impl/dgb/coin/mempool.hpp>
#include <impl/dgb/coin/connection_coinbase.hpp>  // build_connection_coinbase_from_pplns (SSOT under test)
#include <impl/dgb/config_coin.hpp>   // dgb::CoinParams::subsidy (oracle SSOT)
#include <impl/dgb/params.hpp>        // dgb::make_coin_params -- the LIVE production binding

#include <core/pow.hpp>                 // core::SubsidyFunc

#include <core/stratum_work_source.hpp>

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>

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

// ── Worker->mint sharechain-accept seam (set_mint_share_fn / try_mint_share) ──
// The producer half of the worker->mint run-loop standup: DGBWorkSource hands a
// share-difficulty submission's found-share fields to a callback main_dgb.cpp
// binds to mint_local_share_with_ratchet (#294) -> create_local_share. These
// pin the seam contract before the stage-4d classify branch reaches it.

TEST(DgbWorkSource, MintShareFnEmptyUntilWiredReturnsNullNoSilentDrop)
{
    Fixture fx;
    auto ws = fx.make();
    // Unbound: try_mint_share must NOT crash and must return a NULL hash
    // (the accepted share is logged, never silently dispatched into a null fn).
    dgb::stratum::DGBWorkSource::MintShareInputs in;
    in.subsidy = 500000000;
    EXPECT_EQ(ws->try_mint_share(in), uint256::ZERO);
}

TEST(DgbWorkSource, MintShareFnForwardsInputsAndReturnsHash)
{
    Fixture fx;
    auto ws = fx.make();

    // Spy mint callback: capture the inputs (forward) and return a sentinel
    // hash (pass-through back to the classify branch).
    dgb::stratum::DGBWorkSource::MintShareInputs seen;
    bool called = false;
    uint256 sentinel; sentinel.SetHex(
        "00000000000000000000000000000000000000000000000000000000cafe5a7e");

    ws->set_mint_share_fn(
        [&](const dgb::stratum::DGBWorkSource::MintShareInputs& got) -> uint256 {
            called = true;
            seen = got;
            return sentinel;
        });

    dgb::stratum::DGBWorkSource::MintShareInputs in;
    in.header_bytes   = std::vector<unsigned char>(80, 0xab);
    in.coinbase_bytes = {0x03, 0x01, 0x02, 0x03};
    in.subsidy        = 0x1234567890ULL;
    in.prev_share.SetHex(
        "00000000000000000000000000000000000000000000000000000000000000aa");
    in.merkle_branches.push_back(in.prev_share);
    in.payout_script  = {0x76, 0xa9};
    in.segwit_active  = true;

    uint256 minted = ws->try_mint_share(in);

    EXPECT_TRUE(called);
    EXPECT_EQ(minted, sentinel);                  // minted hash flows back verbatim
    EXPECT_EQ(seen.header_bytes.size(), 80u);     // inputs forwarded, not dropped
    EXPECT_EQ(seen.coinbase_bytes.size(), 4u);
    EXPECT_EQ(seen.subsidy, 0x1234567890ULL);
    EXPECT_EQ(seen.prev_share, in.prev_share);
    ASSERT_EQ(seen.merkle_branches.size(), 1u);
    EXPECT_EQ(seen.merkle_branches[0], in.prev_share);
    EXPECT_EQ(seen.payout_script.size(), 2u);
    EXPECT_TRUE(seen.segwit_active);
}

// No behavior change this slice: the seam is stood up but the 4a mining_submit
// stub still rejects every submission and must NOT reach the mint callback
// (the classify branch that calls try_mint_share lands in stage 4d).
TEST(DgbWorkSource, MiningSubmitStubDoesNotInvokeMintFnYet)
{
    Fixture fx;
    auto ws = fx.make();
    bool mint_called = false;
    ws->set_mint_share_fn(
        [&](const dgb::stratum::DGBWorkSource::MintShareInputs&) -> uint256 {
            mint_called = true;
            return uint256{};
        });
    auto result = ws->mining_submit(
        "DGBaddr.worker1", "job-0", "en1", "en2", "ntime", "nonce", "rid-0",
        /*merged_addresses=*/{}, /*job=*/nullptr);
    ASSERT_TRUE(result.is_array());
    EXPECT_FALSE(result[0].get<bool>());   // 4a stub still rejects
    EXPECT_FALSE(mint_called);             // seam wired but NOT yet reached
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

// -- Stage-4d mining_submit classify ladder (live invocation point) ----------
// A real JobSnapshot drives reconstruct -> Scrypt digest -> classify_submission
// -> dispatch. The Scrypt PoW of an arbitrary header is not steerable, so each
// KAT pins the OUTCOME CLASS by the TARGETS, not the hash: a genuinely-maximal
// compact target (0x2100ffff -> 0xffff<<240, ~2^256 -- clears every digest, NOT
// the regtest 0x207fffff which is only ~2^255 and rejects MSB-set digests) makes
// WonBlock/ShareAccept deterministic; a near-zero target (0x03000001 -> target 1)
// is satisfied by none (Reject). This exercises
// the exact tighten-first ladder the hot path runs without a scrypt fixture.
namespace {
core::stratum::JobSnapshot make_job(uint32_t share_bits, const std::string& block_nbits)
{
    core::stratum::JobSnapshot j;
    j.coinb1        = "01000000";   // minimal coinbase head (well-formed hex)
    j.coinb2        = "00000000";   // minimal coinbase tail
    j.gbt_prevhash  = std::string(64, '0');  // 32-byte prevhash, BE display hex
    j.nbits         = "1e0fffff";   // header (share) bits
    j.version       = 0x20000000u;
    j.share_bits    = share_bits;
    j.block_nbits   = block_nbits;
    j.subsidy       = 500000000ULL;
    j.segwit_active = false;
    return j;
}
const char* kEN1 = "00000000";
const char* kEN2 = "00000000";
const char* kNT  = "60000000";
const char* kNON = "00000000";
}  // namespace

TEST(DgbWorkSource, MiningSubmitWonBlockDispatchesBroadcaster)
{
    Fixture fx;
    auto ws = fx.make();
    // block_nbits = 0x2100ffff (maximal target ~2^256): every Scrypt digest
    // clears it -> WonBlock -> submit_block_fn_ MUST fire (dual-path broadcaster, #82).
    auto job = make_job(/*share_bits=*/0x2100ffffu, /*block_nbits=*/"2100ffff");
    auto result = ws->mining_submit(
        "DGBaddr.worker1", "job-won", kEN1, kEN2, kNT, kNON, "rid",
        /*merged_addresses=*/{}, &job);
    ASSERT_TRUE(result.is_boolean());
    EXPECT_TRUE(result.get<bool>());     // won block -> accepted reply
    EXPECT_TRUE(fx.submit_called);       // broadcaster reached
}

TEST(DgbWorkSource, MiningSubmitShareAcceptDispatchesMint)
{
    Fixture fx;
    auto ws = fx.make();
    bool minted = false;
    dgb::stratum::DGBWorkSource::MintShareInputs seen;
    ws->set_mint_share_fn(
        [&](const dgb::stratum::DGBWorkSource::MintShareInputs& got) -> uint256 {
            minted = true; seen = got;
            uint256 h; h.SetHex(
                "00000000000000000000000000000000000000000000000000000000000b10c5");
            return h;
        });
    // block_nbits = 0x03000001 (target 1: no digest is a block) but share_bits =
    // 0x2100ffff (maximal -> any digest clears) -> ShareAccept -> try_mint_share
    // fires, the won-block broadcaster does NOT.
    auto job = make_job(/*share_bits=*/0x2100ffffu, /*block_nbits=*/"03000001");
    auto result = ws->mining_submit(
        "DGBaddr.worker1", "job-share", kEN1, kEN2, kNT, kNON, "rid",
        /*merged_addresses=*/{}, &job);
    ASSERT_TRUE(result.is_boolean());
    EXPECT_TRUE(result.get<bool>());       // valid share -> accepted reply
    EXPECT_TRUE(minted);                   // mint dispatch reached
    EXPECT_FALSE(fx.submit_called);        // NOT a block -> no broadcast
    EXPECT_EQ(seen.header_bytes.size(), 80u);   // 80-byte header forwarded
    EXPECT_EQ(seen.subsidy, 500000000ULL);      // subsidy carried from the job
}

// -- #887 WonBlock -> mint SEAM reachability (PRE-WIRING ONLY on DGB) ---------
//
// block_target <= share_target, so a WonBlock solve clears the share target
// too -- it is the highest-work share the node will ever produce and belongs on
// the sharechain as well as in the coin block. Before #887 the WonBlock case
// returned right after the broadcaster, so the mint seam was never reached.
//
// SCOPE HONESTY -- this KAT proves ONLY that the WonBlock arm now REACHES
// DGBWorkSource::try_mint_share, with a mint fn the TEST binds itself. It does
// NOT prove a DGB share is minted in production: per #884 main_dgb.cpp never
// calls set_mint_share_fn, so DGB cannot mint ANY local share today (not this
// one, and not an ordinary ShareAccept either). The DGB half of #887 is
// pre-wiring that pays off the moment #884 binds the seam.
TEST(DgbWorkSource, MiningSubmitWonBlockAlsoReachesMintSeam)
{
    Fixture fx;
    auto ws = fx.make();
    bool minted = false;
    bool mint_saw_block_already_submitted = false;
    dgb::stratum::DGBWorkSource::MintShareInputs seen;
    ws->set_mint_share_fn(
        [&](const dgb::stratum::DGBWorkSource::MintShareInputs& got) -> uint256 {
            minted = true;
            seen   = got;
            // Reward-invariant witness: the broadcaster must already have run.
            mint_saw_block_already_submitted = fx.submit_called;
            uint256 h; h.SetHex(
                "00000000000000000000000000000000000000000000000000000000000b10c6");
            return h;
        });
    // Maximal target on BOTH bits: every Scrypt digest clears the block target
    // -> WonBlock. The broadcaster fires AND the mint seam is reached.
    auto job = make_job(/*share_bits=*/0x2100ffffu, /*block_nbits=*/"2100ffff");
    auto result = ws->mining_submit(
        "DGBaddr.worker1", "job-won-share", kEN1, kEN2, kNT, kNON, "rid",
        /*merged_addresses=*/{}, &job);
    ASSERT_TRUE(result.is_boolean());
    EXPECT_TRUE(result.get<bool>());       // won block -> accepted reply
    EXPECT_TRUE(fx.submit_called);         // block still broadcast, unchanged
    EXPECT_TRUE(minted);                   // ...and the mint seam is reached
    EXPECT_TRUE(mint_saw_block_already_submitted);  // block dispatched FIRST
    EXPECT_EQ(seen.header_bytes.size(), 80u);
    EXPECT_EQ(seen.subsidy, 500000000ULL);
}

// REWARD INVARIANT: a mint that throws must not cost the block, and must not
// turn a won block into a stratum reject.
TEST(DgbWorkSource, MiningSubmitWonBlockSurvivesAThrowingMint)
{
    Fixture fx;
    auto ws = fx.make();
    ws->set_mint_share_fn(
        [](const dgb::stratum::DGBWorkSource::MintShareInputs&) -> uint256 {
            throw std::runtime_error("mint blew up");
        });
    auto job = make_job(/*share_bits=*/0x2100ffffu, /*block_nbits=*/"2100ffff");
    auto result = ws->mining_submit(
        "DGBaddr.worker1", "job-won-throw", kEN1, kEN2, kNT, kNON, "rid",
        /*merged_addresses=*/{}, &job);
    EXPECT_TRUE(fx.submit_called);         // block reached the broadcaster
    ASSERT_TRUE(result.is_boolean());
    EXPECT_TRUE(result.get<bool>());       // and the throw did not escape
}

TEST(DgbWorkSource, MiningSubmitLowDifficultyRejectsNeitherDispatch)
{
    Fixture fx;
    auto ws = fx.make();
    bool minted = false;
    ws->set_mint_share_fn(
        [&](const dgb::stratum::DGBWorkSource::MintShareInputs&) -> uint256 {
            minted = true; return uint256{};
        });
    // Both targets near-zero (0x03000001 -> target 1): no Scrypt digest clears
    // either -> Reject. Neither the broadcaster nor the mint dispatch fires.
    auto job = make_job(/*share_bits=*/0x03000001u, /*block_nbits=*/"03000001");
    auto result = ws->mining_submit(
        "DGBaddr.worker1", "job-rej", kEN1, kEN2, kNT, kNON, "rid",
        /*merged_addresses=*/{}, &job);
    ASSERT_TRUE(result.is_array());
    EXPECT_FALSE(result[0].get<bool>());   // reject form [false, [code,msg,null]]
    EXPECT_FALSE(fx.submit_called);
    EXPECT_FALSE(minted);
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

// Stage 4b/4c live: a well-formed reconstruct (valid hex, header == 80B) is now
// SCORED -- scrypt_1024_1_1_256(header) bridged to core uint256 via the
// u256_be_display_hex SSOT and returned as chain::target_to_difficulty(pow),
// the SAME unit the coin-agnostic StratumServer vardiff/pool gate compares. A
// positive score is exactly what lets a real share clear the gate and reach
// mining_submit (the 0.0 stub silently rejected every share pre-fix).
TEST(DgbWorkSource, ComputeShareDifficultyScoresValidHeader)
{
    Fixture fx;
    auto ws = fx.make();
    const std::string prevhash(64, '0');  // 32 zero bytes (BE display hex)
    double diff = ws->compute_share_difficulty(
        "01000000", "00000000", "00", "00", "5f5e1000", "0000abcd",
        /*version=*/0x20000000u, prevhash, "1e0ffff0",
        /*merkle_branches=*/{});
    EXPECT_GT(diff, 0.0);
    EXPECT_TRUE(std::isfinite(diff));
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
    // Zero embedded fees, no external GBT -> DigiByte Core subsidy at the boundary.
    EXPECT_EQ(tmpl["coinbasevalue"].get<uint64_t>(), 243441000000ULL);
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
// One pin on each side of every DGB reward-period boundary (DigiByte Core
// GetBlockSubsidy() vectors, satoshis/COIN=1e8, test_dgb_subsidy.cpp).
namespace {
struct EraVec { uint32_t height; uint64_t subsidy; const char* era; };
constexpr EraVec kEraBoundaries[] = {
    {67199,   800000000000ULL, "PeriodIII-fixed last"},
    {67200,   796000000000ULL, "PeriodIV -0.5%/wk first"},
    {399999,  674644108854ULL, "PeriodIV last"},
    {400000,  243441000000ULL, "PeriodV -1%/wk first"},
    {1429999, 215782419560ULL, "PeriodV last"},
    {1430000, 107850000000ULL, "PeriodVI monthly-decay first"},
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


// Production-binding guard. The era-boundary tests above trust kSubsidyFunc, a
// hand-written DUPLICATE of params.hpp p.subsidy_func: they pin the schedule
// math but are blind to a regression in the ACTUAL wiring. If make_coin_params()
// shipped subsidy_func unbound (the work source then logs subsidy_func=UNSET and
// the embedded coinbasevalue silently falls through to the GBT-only path) or
// bound it to the wrong function, every test above would still pass off its
// private copy. Pin the LIVE production binding directly.
TEST(DgbCoinParams, SubsidyFuncBoundToOracleScheduleInProduction)
{
    const core::CoinParams p = dgb::make_coin_params(/*testnet=*/false);
    ASSERT_TRUE(static_cast<bool>(p.subsidy_func))
        << "make_coin_params shipped subsidy_func UNSET -- embedded coinbasevalue "
           "would silently degrade to the external-GBT-only path";
    for (const auto& v : kEraBoundaries) {
        EXPECT_EQ(p.subsidy_func(v.height), v.subsidy)
            << "production subsidy_func diverged from oracle subsidy at " << v.era;
        EXPECT_EQ(p.subsidy_func(v.height), kSubsidyFunc(v.height))
            << "production binding diverged from the schedule under test at " << v.era;
    }
}


// #179 fail-closed contract: a REAL tip hash but a MultiShield V4 window too
// shallow to derive the next Scrypt target (< 61 headers) HOLDS the whole
// template (empty object) rather than shipping a fabricated diff-1 (0x1d00ffff)
// -- the invalid-block bug this PR fixes. The stratum layer then takes its
// existing "waiting for block template (header sync)" wait path. The dedicated
// prevhash getter is INDEPENDENT of the V4 window (it reads tip_hash() directly)
// and still surfaces the tip: the tip IS known, only the next-target is not yet.
TEST(DgbWorkSource, WorkTemplateHeldWhenTipKnownButV4WindowTooShallow)
{
    Fixture fx;
    fx.chain.set_base_height(400000);
    // Seed one Scrypt header carrying a distinctive block id. n_version with
    // algo nibble 0x0000 is the Scrypt lane; target 100 with pow_hash 0 (<=
    // target) clears the context-free PoW gate; empty-chain MTP is unconstrained.
    // One header is a real tip but nowhere near the 61-header V4 window depth.
    c2pool::dgb::HeaderSample h;
    h.n_version  = 0x20000000;
    h.n_time     = 1000;
    h.target     = 100;
    h.block_hash = dgb::coin::u256::from_u64(0x123456789abcdef0ULL);
    ASSERT_EQ(fx.chain.validate_and_append(h),
              c2pool::dgb::IngestResult::VALIDATED_SCRYPT);

    auto ws = fx.make();
    const auto tmpl = ws->get_current_work_template();
    // Held: an EMPTY object on the wire -- never a fabricated bits, and never a
    // partial (previousblockhash-only) template either. Fail-closed.
    EXPECT_TRUE(tmpl.is_object());
    EXPECT_TRUE(tmpl.empty());
    EXPECT_FALSE(tmpl.contains("bits"));
    EXPECT_FALSE(tmpl.contains("previousblockhash"));
    // The tip is still known: the window-independent getter returns it.
    EXPECT_EQ(ws->get_current_gbt_prevhash(),
              std::string(48, '0') + "123456789abcdef0");
}

// The dedicated prevhash getter draws the tip hash from chain_.tip_hash()
// through u256_be_display_hex -- INDEPENDENT of the #179 V4 next-target gate.
// Contract across states:
//   * no tip           -> getter empty AND template omits previousblockhash.
//   * tip, shallow win  -> getter returns the tip, but the template is HELD
//                         (empty), so they deliberately diverge in PRESENCE:
//                         the getter is not gated on the V4 window.
// The served (deep-window) reconvergence -- getter == template's
// previousblockhash -- is pinned by WorkTemplateServesRealV4BitsAndPrevhash.
TEST(DgbWorkSource, GbtPrevhashGetterIndependentOfV4Window)
{
    Fixture fx;
    // No tip yet -> getter empty, template omits previousblockhash.
    {
        auto ws = fx.make();
        EXPECT_TRUE(ws->get_current_gbt_prevhash().empty());
        EXPECT_FALSE(ws->get_current_work_template().contains("previousblockhash"));
    }
    // Seed a Scrypt header carrying a distinctive block id -> tip known, but the
    // V4 window is one-deep so the template holds. The getter is unaffected.
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
    // Template HELD (V4 window too shallow) -> previousblockhash absent, so the
    // getter and the template diverge exactly where the fail-closed gate fires.
    EXPECT_TRUE(ws->get_current_work_template().empty());
}

// #179 served-path positive: fed a DEEP MultiShield V4 window (61+ real DigiByte
// mainnet headers), the daemonless work source stamps the template `bits` with
// the REAL network-accepted next-target -- NOT the fabricated 0x1d00ffff that
// made every won block invalid. Golden window: 62 consecutive mainnet headers
// (24155880..24155941, all 5 algos) below Scrypt block 24155942, whose accepted
// nBits is 0x1a47e953 (the same fixture verify_v4.py / multishield_v4_kat_test
// prove byte-exact against DigiByte-Core consensus). The tip carries a real
// block id, so previousblockhash is emitted too and equals the window-independent
// getter -- the served-path reconvergence GbtPrevhashGetterIndependentOfV4Window
// references.
TEST(DgbWorkSource, WorkTemplateServesRealV4BitsAndPrevhash)
{
    // {height, version, time, bits} -- heights 24155880..24155941, the 62
    // ancestors of Scrypt block 24155942 (a full 61-header V4 window + tip).
    // Reused from the #179 MultiShield V4 KAT fixture (multishield_v4_kat_test.cpp
    // header, re-derivable via /home/ubuntu/dgb179-vectors/fetch_de.py).
    struct Row { uint32_t height; uint32_t version; int64_t time; uint32_t bits; };
    static const Row kWindow[] = {
        {24155880, 536874498u, 1788581092, 0x1b061689u},
        {24155881, 536872450u, 1788581160, 0x1a020fbfu},
        {24155882, 536872450u, 1788581391, 0x1a01d9f9u},
        {24155883, 536872962u, 1788581158, 0x1a1db51cu},
        {24155884, 536874498u, 1788581164, 0x1b062685u},
        {24155885, 536870914u, 1788581167, 0x1a5f80dau},
        {24155886, 536870914u, 1788581173, 0x1a558e21u},
        {24155887, 536874498u, 1788581183, 0x1b05ebe6u},
        {24155888, 714605058u, 1788581187, 0x190a11d9u},
        {24155889, 536874498u, 1788581203, 0x1b05708cu},
        {24155890, 536870914u, 1788581209, 0x1a5501bbu},
        {24155891, 536872450u, 1788581213, 0x1a023db3u},
        {24155892, 536870914u, 1788581227, 0x1a4e7e25u},
        {24155893, 536870914u, 1788581228, 0x1a4582eau},
        {24155894, 536874498u, 1788581230, 0x1b059965u},
        {24155895, 536872962u, 1788581246, 0x1a284ab6u},
        {24155896, 537338370u, 1788581253, 0x190b89dbu},
        {24155897, 536874498u, 1788581277, 0x1b0545fdu},
        {24155898, 594264578u, 1788581284, 0x190a64fau},
        {24155899, 584040962u, 1788581296, 0x1908f4cfu},
        {24155900, 536874498u, 1788581304, 0x1b04cf7fu},
        {24155901, 536874498u, 1788581307, 0x1b04036cu},
        {24155902, 536872450u, 1788581315, 0x1a02c47du},
        {24155903, 536872450u, 1788581599, 0x1a025181u},
        {24155904, 536872450u, 1788581674, 0x1a01f289u},
        {24155905, 536870914u, 1788581360, 0x1a59661cu},
        {24155906, 536872962u, 1788581365, 0x1a31485au},
        {24155907, 740106754u, 1788581368, 0x1909af5fu},
        {24155908, 536870914u, 1788581372, 0x1a4f918au},
        {24155909, 537428482u, 1788581378, 0x19086450u},
        {24155910, 536872450u, 1788581584, 0x1a01f480u},
        {24155911, 536870914u, 1788581434, 0x1a46d1b1u},
        {24155912, 536874498u, 1788581453, 0x1b04de48u},
        {24155913, 536870914u, 1788581455, 0x1a3c458fu},
        {24155914, 536872450u, 1788581488, 0x1a01d27du},
        {24155915, 537108994u, 1788581467, 0x190872bfu},
        {24155916, 536872962u, 1788581468, 0x1a3a0a87u},
        {24155917, 536870914u, 1788581470, 0x1a38687bu},
        {24155918, 536872962u, 1788581506, 0x1a322751u},
        {24155919, 536870914u, 1788581513, 0x1a30acf7u},
        {24155920, 536870914u, 1788581520, 0x1a279c67u},
        {24155921, 536872962u, 1788581524, 0x1a2bc5e9u},
        {24155922, 536872962u, 1788581533, 0x1a22c5f3u},
        {24155923, 536872962u, 1788581541, 0x1a1b8140u},
        {24155924, 536872450u, 1788581871, 0x1a020f72u},
        {24155925, 545260034u, 1788581558, 0x190990dfu},
        {24155926, 536874498u, 1788581584, 0x1b0672dcu},
        {24155927, 536872962u, 1788581595, 0x1a18a60bu},
        {24155928, 536872450u, 1788581619, 0x1a01d54au},
        {24155929, 536872962u, 1788581599, 0x1a1428d6u},
        {24155930, 536874498u, 1788581610, 0x1b05b89bu},
        {24155931, 551477762u, 1788581616, 0x19092714u},
        {24155932, 536874498u, 1788581620, 0x1b04adddu},
        {24155933, 572326402u, 1788581674, 0x19077c59u},
        {24155934, 536874498u, 1788581689, 0x1b03d3b4u},
        {24155935, 536872450u, 1788582059, 0x1a01d2f9u},
        {24155936, 536872450u, 1788581727, 0x1a016f3cu},
        {24155937, 536874498u, 1788581727, 0x1b034153u},
        {24155938, 536874498u, 1788581746, 0x1b028f57u},
        {24155939, 600031746u, 1788581796, 0x1907298fu},
        {24155940, 758211074u, 1788581784, 0x1905a837u},
        {24155941, 579609090u, 1788581808, 0x1904850fu},
    };
    constexpr std::size_t kWindowN = sizeof(kWindow) / sizeof(kWindow[0]);
    static_assert(kWindowN == 62, "62 ancestors == full 61-header V4 window + tip");

    // Distinctive real tip block id (block 24155941), so tip_hash() is non-null
    // and the template takes the embedded (not GBT-fallback) previousblockhash+
    // bits branch.
    const uint64_t kTipId = 0xfeedface00c0ffeeULL;

    Fixture fx;
    fx.chain.set_base_height(kWindow[0].height);
    for (std::size_t i = 0; i < kWindowN; ++i) {
        const Row& r = kWindow[i];
        c2pool::dgb::HeaderSample s;
        s.n_version = static_cast<int32_t>(r.version);
        s.n_time    = r.time;
        s.target    = dgb::coin::compact_to_target(r.bits);
        s.pow_hash  = 0;                       // inert PoW gate (0 <= any target)
        s.n_bits    = r.bits;                  // fed verbatim to the V4 walk
        if (i + 1 == kWindowN)                 // populate the tip's real block id
            s.block_hash = dgb::coin::u256::from_u64(kTipId);
        const auto res = fx.chain.validate_and_append(s);
        ASSERT_NE(res, c2pool::dgb::IngestResult::REJECTED)
            << "fixture header " << r.height << " unexpectedly rejected";
    }

    auto ws = fx.make();
    const auto tmpl = ws->get_current_work_template();

    // The window is deep enough: the template is SERVED, not held.
    ASSERT_TRUE(tmpl.contains("bits"))
        << "deep V4 window must serve a real next-target, not hold";
    // Real network-accepted next-target for Scrypt block 24155942.
    EXPECT_EQ(tmpl["bits"].get<std::string>(), "1a47e953");
    // The regression sentinel: never the fabricated diff-1.
    EXPECT_NE(tmpl["bits"].get<std::string>(), "1d00ffff");

    // Real tip -> previousblockhash present, and it equals the window-independent
    // getter (served-path reconvergence).
    const std::string expected_prev = std::string(48, '0') + "feedface00c0ffee";
    ASSERT_TRUE(tmpl.contains("previousblockhash"));
    EXPECT_EQ(tmpl["previousblockhash"].get<std::string>(), expected_prev);
    EXPECT_EQ(ws->get_current_gbt_prevhash(), expected_prev);
}


// ── Per-connection coinbase live-wire (set_pplns_inputs_fn / build_connection_coinbase) ──
// The producer half of the Phase-B coinbase wire: build_connection_coinbase
// delegates to the build_connection_coinbase_from_pplns SSOT (which the verifier
// also calls). These pin three contracts: (1) UNBOUND -> empty job (pre-wire
// byte-identical no-op), (2) bound -> coinb1/coinb2 byte-identical to the SSOT
// called directly with the same inputs (proving build_connection_coinbase is a
// pure pass-through, not a second payout implementation), (3) producer nullopt
// -> empty job.
namespace {

using Script = std::vector<unsigned char>;

// A fixed, fully-populated PPLNS input set (two payout scripts, v36 no-finder).
dgb::coin::ConnCoinbasePplnsInputs sample_pplns_inputs()
{
    dgb::coin::ConnCoinbasePplnsInputs in;
    in.coinbase_script = Script{0x03, 0x01, 0x02, 0x03};       // BIP34-ish scriptSig
    in.weights = { {Script{0x76, 0xa9, 0x14, 0xaa}, uint288(3)},
                   {Script{0x76, 0xa9, 0x14, 0xbb}, uint288(1)} };
    in.total_weight = uint288(4);
    in.subsidy = 1234567;
    in.use_v36_pplns = true;
    in.donation_script = Script{0xa9, 0x14, 0xcc};
    in.ref_hash = uint256(std::vector<unsigned char>(32, 0xab));
    in.last_txout_nonce = 0x0102030405060708ULL;
    return in;
}


// ─────────────────────────────────────────────────────────────────────────────
// External-daemon GBT tip fallback (set_gbt_tip_fn) -- the empty-embedded-chain
// path that unblocks a freshly-stood-up :5025 node whose Scrypt-only HeaderChain
// has not yet ingested a tip. Fixture's HeaderChain is default-constructed
// (tip_hash()==nullopt), so these exercise exactly the live fallback condition.
// ─────────────────────────────────────────────────────────────────────────────

using GbtTip = dgb::stratum::DGBWorkSource::GbtTip;

TEST(DgbWorkSource, GbtTipFallbackPopulatesPrevhashAndBitsWhenChainEmpty)
{
    Fixture fx;
    auto ws = fx.make();
    // Values mirror the live testnet GBT the integrator confirmed (h123 tip).
    const std::string kPrev =
        "ce2fd8d332d667c009e6e031fec6cba0e4d12c963d2c84f824d6c1ae676e7de9";
    const std::string kBits = "2003ffff";
    int calls = 0;
    ws->set_gbt_tip_fn([&]() -> std::optional<GbtTip> {
        ++calls;
        return GbtTip{kPrev, kBits};
    });

    // mining.notify prevhash source (stratum_server get_current_gbt_prevhash).
    EXPECT_EQ(ws->get_current_gbt_prevhash(), kPrev);

    // The assembled GBT template carries BOTH previousblockhash and the
    // daemon-authoritative bits from the same fallback snapshot.
    auto tmpl = ws->get_current_work_template();
    ASSERT_TRUE(tmpl.contains("previousblockhash"));
    EXPECT_EQ(tmpl["previousblockhash"].get<std::string>(), kPrev);
    ASSERT_TRUE(tmpl.contains("bits"));
    EXPECT_EQ(tmpl["bits"].get<std::string>(), kBits);

    // TTL cache: the two accessors above must not each trigger a fresh RPC.
    EXPECT_LE(calls, 1);
}

TEST(DgbWorkSource, GbtTipFallbackAbsentWhenSeamUnbound)
{
    Fixture fx;
    auto ws = fx.make();
    // No set_gbt_tip_fn -> truthful absence (byte-identical to pre-wire).
    EXPECT_TRUE(ws->get_current_gbt_prevhash().empty());
    auto tmpl = ws->get_current_work_template();
    EXPECT_FALSE(tmpl.contains("previousblockhash"));
    EXPECT_FALSE(tmpl.contains("bits"));
}

TEST(DgbWorkSource, GbtTipFallbackNulloptStaysAbsent)
{
    Fixture fx;
    auto ws = fx.make();
    // Seam bound but declining (RPC down / no template yet) -> same absence as
    // unbound; never a fabricated prevhash/bits.
    ws->set_gbt_tip_fn([]() -> std::optional<GbtTip> { return std::nullopt; });
    EXPECT_TRUE(ws->get_current_gbt_prevhash().empty());
    auto tmpl = ws->get_current_work_template();
    EXPECT_FALSE(tmpl.contains("previousblockhash"));
    EXPECT_FALSE(tmpl.contains("bits"));
}

}  // namespace

TEST(DgbWorkSource, ConnectionCoinbaseEmptyUntilPplnsInputsWired)
{
    Fixture fx;
    auto ws = fx.make();
    auto r = ws->build_connection_coinbase(
        uint256::ZERO, "deadbeef", Script{}, {});
    EXPECT_TRUE(r.coinb1.empty());
    EXPECT_TRUE(r.coinb2.empty());
}

TEST(DgbWorkSource, ConnectionCoinbaseDelegatesToPplnsSsotByteIdentical)
{
    Fixture fx;
    auto ws = fx.make();
    const auto inputs = sample_pplns_inputs();

    // Bind a producer that hands back the fixed inputs regardless of args.
    ws->set_pplns_inputs_fn(
        [&](const uint256&, const std::string&, const Script&,
            const std::vector<std::pair<uint32_t, Script>>&)
            -> std::optional<dgb::coin::ConnCoinbasePplnsInputs> {
            return inputs;
        });

    auto wired = ws->build_connection_coinbase(
        uint256(std::vector<unsigned char>(32, 0x11)), "cafef00d", Script{0x01}, {});

    // The SSOT called directly with the same inputs is the oracle.
    auto oracle = dgb::coin::build_connection_coinbase_from_pplns(inputs);

    EXPECT_EQ(wired.coinb1, oracle.coinb1);
    EXPECT_EQ(wired.coinb2, oracle.coinb2);
    EXPECT_FALSE(wired.coinb1.empty());
    // Consensus ref fields are frozen onto the snapshot for the submit path.
    EXPECT_EQ(wired.snapshot.frozen_ref.ref_hash, inputs.ref_hash);
    EXPECT_EQ(wired.snapshot.frozen_ref.last_txout_nonce, inputs.last_txout_nonce);
    EXPECT_EQ(wired.snapshot.subsidy, inputs.subsidy);
}

TEST(DgbWorkSource, ConnectionCoinbaseProducerNulloptYieldsEmptyJob)
{
    Fixture fx;
    auto ws = fx.make();
    ws->set_pplns_inputs_fn(
        [&](const uint256&, const std::string&, const Script&,
            const std::vector<std::pair<uint32_t, Script>>&)
            -> std::optional<dgb::coin::ConnCoinbasePplnsInputs> {
            return std::nullopt;  // tip not yet known
        });
    auto r = ws->build_connection_coinbase(uint256::ZERO, "00", Script{}, {});
    EXPECT_TRUE(r.coinb1.empty());
    EXPECT_TRUE(r.coinb2.empty());
}

}  // namespace