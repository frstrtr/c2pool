// SPDX-License-Identifier: AGPL-3.0-or-later
// dash::stratum::DASHWorkSource -- Stage 4c/4d KATs (issue #732).
//
// The gate the v0.2.2 field failure proved missing: a stubbed work source
// returning a FIXED DashWorkData must yield a non-empty stratum template trio
// (template JSON / merkle branches / coinb1+coinb2 split), the reassembled
// coinbase must be byte-identical to the verifier-shared SSOT build
// (compute_dash_payouts -> coinbase::build) with value splits matching the
// fixture, compute_share_difficulty must return the pinned X11-derived value
// for a known header fixture, and mining_submit must classify a fixture solve
// into the right accept/won-block/reject class. Also keeps the 4a/4b
// contract KATs (construction, registry, fused get_work routing) and the
// set-gap honesty test (empty fallback -> empty trio, never fabricated).
//
// MUST appear in BOTH this ctest registration AND the build.yml --target
// allowlist, or it becomes a #143-style NOT_BUILT sentinel that reds master.

#include <impl/dash/stratum/work_source.hpp>

#include <impl/dash/coinbase_builder.hpp>     // compute_dash_payouts, build, split_coinb, be_hex_u32
#include <impl/dash/coin/block_producer.hpp>  // coinbase_txid, compute_merkle_root, serialize_header80, target_from_nbits
#include <impl/dash/crypto/hash_x11.hpp>
#include <impl/dash/params.hpp>

#include <core/stratum_work_source.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <btclibs/util/strencodings.h>        // ParseHex, HexStr

#include <gtest/gtest.h>

#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace {

// P2PKH script for a fixed 20-byte pubkey hash (0x11 repeated).
std::vector<unsigned char> fixture_miner_script()
{
    std::vector<unsigned char> s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, 0x11);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

uint160 fixture_miner_pkh()
{
    uint160 h;
    std::memset(h.begin(), 0x11, 20);
    return h;
}

// A masternode payment carried as a raw "!"+hex script (the GBT platform /
// script-payee form normalize_payment preserves) so the fixture needs no
// base58 round-trip. P2PKH to a distinct pkh (0x22 repeated).
std::string fixture_mn_payee()
{
    std::vector<unsigned char> s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, 0x22);
    s.push_back(0x88);
    s.push_back(0xac);
    return "!" + HexStr(std::span<const unsigned char>(s.data(), s.size()));
}

constexpr uint64_t kCoinbaseValue = 271570414ULL;   // sat
constexpr uint64_t kMnAmount      = 100000000ULL;   // masternode share (sat)
constexpr uint32_t kBits          = 0x1e0ffff0u;
constexpr uint32_t kCurtime       = 1751000000u;
constexpr int32_t  kVersion       = 0x20000000;
const char* const  kPrevHashHex   =
    "000000000000001b2f8c9e5a1d4b3c6e7f8091a2b3c4d5e6f708192a3b4c5d6e";

// The rich fixture template the stubbed fallback serves: standard fields +
// DASH masternode payment + a two-entry tx set.
dash::coin::DashWorkData rich_work()
{
    dash::coin::DashWorkData w;
    w.m_version        = kVersion;
    w.m_previous_block.SetHex(kPrevHashHex);
    w.m_height         = 424242u;
    w.m_coinbase_value = kCoinbaseValue;
    w.m_bits           = kBits;
    w.m_curtime        = kCurtime;

    dash::coin::PackedPayment mn;
    mn.payee  = fixture_mn_payee();
    mn.amount = kMnAmount;
    w.m_packed_payments.push_back(mn);
    w.m_payment_amount = kMnAmount;

    uint256 t1, t2;
    t1.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    t2.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
    w.m_tx_hashes = {t1, t2};
    w.m_tx_data_hex = {"aa01", "bb02"};   // opaque tx bytes for block assembly
    return w;
}

// Construct a DASHWorkSource over a default (unpopulated) NodeCoinState with
// a stubbed dashd fallback. `work` is what the fallback serves; the submit
// callback captures any won-block dispatch for inspection.
struct Fixture {
    dash::coin::NodeCoinState coin_state;             // default: populated()==false
    bool                      submit_called = false;
    uint32_t                  submit_height = 0;
    std::vector<unsigned char> submitted_block;
    dash::coin::DashWorkData  fallback_work;          // seeded by caller

    Fixture() = default;                              // set-gap fixture (empty work)
    explicit Fixture(bool rich) { if (rich) fallback_work = rich_work(); }

    std::unique_ptr<dash::stratum::DASHWorkSource> make()
    {
        auto submit = [this](const std::vector<unsigned char>& block,
                             uint32_t height) -> bool {
            submit_called   = true;
            submit_height   = height;
            submitted_block = block;
            return true;
        };
        auto fallback = [this]() -> dash::coin::DashWorkData { return fallback_work; };
        return std::make_unique<dash::stratum::DASHWorkSource>(
            coin_state, fallback, submit);
    }
};

// Reassemble coinb1 || en1 || en2 || coinb2 into raw coinbase bytes.
std::vector<unsigned char> reassemble(const std::string& coinb1,
                                      const std::string& en1,
                                      const std::string& en2,
                                      const std::string& coinb2)
{
    auto b1 = ParseHex(coinb1);
    auto e1 = ParseHex(en1);
    auto e2 = ParseHex(en2);
    auto b2 = ParseHex(coinb2);
    std::vector<unsigned char> out;
    out.insert(out.end(), b1.begin(), b1.end());
    out.insert(out.end(), e1.begin(), e1.end());
    out.insert(out.end(), e2.begin(), e2.end());
    out.insert(out.end(), b2.begin(), b2.end());
    return out;
}

// Fold LE-internal hex branches up from a leaf (the miner-side ascent).
uint256 fold_branches(uint256 leaf, const std::vector<std::string>& branches)
{
    for (const auto& hex : branches) {
        uint256 b;
        auto bb = ParseHex(hex);
        if (bb.size() == 32) std::memcpy(b.begin(), bb.data(), 32);
        unsigned char buf[64];
        std::memcpy(buf,      leaf.data(), 32);
        std::memcpy(buf + 32, b.data(),    32);
        leaf = dash::coinbase::sha256d(std::span<const unsigned char>(buf, 64));
    }
    return leaf;
}

// Assemble the 80-byte header exactly as the work source does at submit time.
std::vector<unsigned char> assemble_header(uint32_t version,
                                           const uint256& prev,
                                           const uint256& merkle_root,
                                           uint32_t ntime, uint32_t nbits,
                                           uint32_t nonce)
{
    unsigned char hdr[80];
    dash::coin::serialize_header80(hdr, static_cast<int32_t>(version), prev,
                                   merkle_root, ntime, nbits, nonce);
    return std::vector<unsigned char>(hdr, hdr + 80);
}

// ── 4a/4b contract (kept) ───────────────────────────────────────────────────

TEST(DashStratumWorkSource, ConstructsAndSatisfiesIWorkSourceContract)
{
    Fixture fx(true);
    auto ws = fx.make();
    core::stratum::IWorkSource* iface = ws.get();  // usable through the abstract iface
    ASSERT_NE(iface, nullptr);
}

TEST(DashStratumWorkSource, ConfigDefaultsMatchStratumConfigWithX11Overrides)
{
    Fixture fx(true);
    auto ws = fx.make();
    const auto& cfg = ws->get_stratum_config();
    EXPECT_DOUBLE_EQ(cfg.min_difficulty, 0.0005);
    EXPECT_DOUBLE_EQ(cfg.max_difficulty, 65536.0);
    EXPECT_DOUBLE_EQ(cfg.target_time, 3.0);
    EXPECT_TRUE(cfg.vardiff_enabled);
    // X11 = standard diff-1 scale (p2pool-dash DUMB_SCRYPT_DIFF == 1), NOT the
    // scrypt 2^16 default -- otherwise advertised difficulty inflates 65536x.
    EXPECT_DOUBLE_EQ(cfg.set_difficulty_multiplier, 1.0);
    // Runtime coin tag for the coin-agnostic core log lines (#732).
    EXPECT_EQ(cfg.coin_symbol, "DASH");
}

TEST(DashStratumWorkSource, WorkGenerationStartsZeroAndBumps)
{
    Fixture fx(true);
    auto ws = fx.make();
    EXPECT_EQ(ws->get_work_generation(), 0u);
    ws->bump_work_generation();
    ws->bump_work_generation();
    EXPECT_EQ(ws->get_work_generation(), 2u);
}

TEST(DashStratumWorkSource, ShareTargetAtomicsRoundTrip)
{
    Fixture fx(true);
    auto ws = fx.make();
    EXPECT_EQ(ws->get_share_bits(), 0u);
    EXPECT_EQ(ws->get_share_max_bits(), 0u);
    ws->set_share_target(0x1d00ffffu, 0x1e0fffffu);
    EXPECT_EQ(ws->get_share_bits(), 0x1d00ffffu);
    EXPECT_EQ(ws->get_share_max_bits(), 0x1e0fffffu);
}

TEST(DashStratumWorkSource, NoMergedChainInV36)
{
    Fixture fx(true);
    auto ws = fx.make();
    EXPECT_FALSE(ws->has_merged_chain(0x0001));
}

TEST(DashStratumWorkSource, BestShareHashFnEmptyUntilWired)
{
    Fixture fx(true);
    auto ws = fx.make();
    EXPECT_FALSE(static_cast<bool>(ws->get_best_share_hash_fn()));
    ws->set_best_share_hash_fn([]() { return uint256::ZERO; });
    auto fn = ws->get_best_share_hash_fn();
    ASSERT_TRUE(static_cast<bool>(fn));
    EXPECT_EQ(fn(), uint256::ZERO);
}

TEST(DashStratumWorkSource, WorkerRegistryRoundTrip)
{
    Fixture fx(true);
    auto ws = fx.make();
    core::stratum::WorkerInfo info;
    info.username    = "Xaddr.worker1";
    info.worker_name = "worker1";
    ws->register_stratum_worker("sess-1", info);
    ws->update_stratum_worker("sess-1", /*hashrate=*/1.0e9, /*dead=*/0.0,
                              /*difficulty=*/16.0, /*accepted=*/3, /*rejected=*/0, /*stale=*/0);
    ws->update_stratum_worker("sess-unknown", 1.0, 0.0, 1.0, 0, 0, 0);
    ws->unregister_stratum_worker("sess-1");
    ws->unregister_stratum_worker("sess-unknown");
    SUCCEED();
}

// The fused adapter: with an UNPOPULATED coin-state, get_work() routes to the
// RETAINED dashd fallback (always-reachable safety + [GBT-XCHECK] arm).
TEST(DashStratumWorkSource, GetWorkRoutesToDashdFallbackWhenCoinStateUnpopulated)
{
    Fixture fx(true);
    ASSERT_FALSE(fx.coin_state.populated());  // default bundle is a set-gap
    auto ws = fx.make();

    dash::stratum::WorkJobTargetInputs job_in;
    job_in.sane_target_min.SetHex(
        "0000000000000000000000000000000000000000000000000000000000000001");
    job_in.sane_target_max.SetHex(
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    job_in.share_info_bits_target.SetHex(
        "0000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    job_in.have_desired_pseudoshare = false;
    job_in.local_hash_rate = 0.0;

    dash::stratum::GetWork gw = ws->get_work(job_in);

    EXPECT_EQ(gw.source, dash::coin::WorkSource::DashdFallback);
    EXPECT_EQ(gw.work.m_height, 424242u);
    EXPECT_EQ(gw.work.m_coinbase_value, kCoinbaseValue);
    EXPECT_EQ(gw.targets.share_target, job_in.sane_target_max);
    EXPECT_EQ(gw.targets.min_share_target, job_in.share_info_bits_target);
}

// ── 4c: set-gap honesty ─────────────────────────────────────────────────────
// An EMPTY fallback template (unarmed dashd arm: bits == 0) must yield an
// empty trio -- an honest "no template yet", never a fabricated one.
TEST(DashStratumWorkSource, SetGapServesEmptyTrio)
{
    Fixture fx;   // fallback_work left default: m_bits == 0
    auto ws = fx.make();
    EXPECT_TRUE(ws->get_current_gbt_prevhash().empty());
    EXPECT_TRUE(ws->get_current_work_template().empty());
    EXPECT_TRUE(ws->get_stratum_merkle_branches().empty());
    auto parts = ws->get_coinbase_parts();
    EXPECT_TRUE(parts.first.empty());
    EXPECT_TRUE(parts.second.empty());
    auto cb = ws->build_connection_coinbase(uint256::ZERO, "deadbeef",
                                            fixture_miner_script(), {});
    EXPECT_TRUE(cb.coinb1.empty());
    EXPECT_TRUE(cb.coinb2.empty());
}

// ── 4c: the template trio off a fixed DashWorkData ──────────────────────────

TEST(DashStratumWorkSource, TemplateServesFixtureFieldsWithCorrectEncodings)
{
    Fixture fx(true);
    auto ws = fx.make();

    auto tmpl = ws->get_current_work_template();
    ASSERT_FALSE(tmpl.empty());
    // The exact fields + conventions StratumSession::send_notify_work reads:
    EXPECT_EQ(tmpl.value("previousblockhash", ""), std::string(kPrevHashHex));
    EXPECT_EQ(tmpl.value("version", 0), kVersion);
    EXPECT_EQ(tmpl.value("bits", ""), "1e0ffff0");        // 8-char BE hex
    EXPECT_EQ(tmpl.value("height", 0u), 424242u);
    EXPECT_EQ(tmpl.value("curtime", uint64_t{0}), uint64_t{kCurtime});
    EXPECT_EQ(tmpl.value("coinbasevalue", uint64_t{0}), kCoinbaseValue);

    // The dedicated prevhash getter serves the SAME tip as the template.
    EXPECT_EQ(ws->get_current_gbt_prevhash(), std::string(kPrevHashHex));
}

TEST(DashStratumWorkSource, MerkleBranchesFoldToTheBlockMerkleRoot)
{
    Fixture fx(true);
    auto ws = fx.make();

    auto branches = ws->get_stratum_merkle_branches();
    ASSERT_EQ(branches.size(), 2u);   // 3 leaves (cb + 2 txs) -> 2 siblings

    // Miner-side ascent from an arbitrary coinbase txid must reproduce the
    // canonical block merkle root over [cb, t1, t2] (block_producer SSOT).
    uint256 cb_txid;
    cb_txid.SetHex("3333333333333333333333333333333333333333333333333333333333333333");
    const dash::coin::DashWorkData w = rich_work();
    std::vector<uint256> leaves;
    leaves.push_back(cb_txid);
    leaves.insert(leaves.end(), w.m_tx_hashes.begin(), w.m_tx_hashes.end());
    EXPECT_EQ(fold_branches(cb_txid, branches),
              dash::coin::compute_merkle_root(leaves));
}

TEST(DashStratumWorkSource, ConnectionCoinbaseIsByteIdenticalToVerifierSSOT)
{
    Fixture fx(true);
    auto ws = fx.make();

    const auto miner_script = fixture_miner_script();
    auto cbr = ws->build_connection_coinbase(uint256::ZERO, "00000000",
                                             miner_script, {});
    ASSERT_FALSE(cbr.coinb1.empty());
    ASSERT_FALSE(cbr.coinb2.empty());
    EXPECT_EQ(cbr.snapshot.subsidy, kCoinbaseValue);
    ASSERT_TRUE(cbr.snapshot.tx_data);
    EXPECT_EQ(*cbr.snapshot.tx_data, rich_work().m_tx_data_hex);
    EXPECT_EQ(cbr.snapshot.merkle_branches.size(), 2u);

    // Reassemble with the zeroed extranonce (en1+en2 == the 8-byte nonce64
    // placeholder) -> must be BYTE-IDENTICAL to the verifier-shared SSOT
    // build: compute_dash_payouts + coinbase::build over the same fixture.
    auto reassembled = reassemble(cbr.coinb1, "00000000", "00000000", cbr.coinb2);

    const dash::coin::DashWorkData w = rich_work();
    const core::CoinParams params = dash::make_coin_params(/*testnet=*/false);
    std::map<std::vector<unsigned char>, uint64_t> weights{{miner_script, 1}};
    auto tx_outs = dash::coinbase::compute_dash_payouts(
        kCoinbaseValue, w.m_packed_payments, fixture_miner_pkh(),
        weights, /*total_weight=*/1, params);
    auto layout = dash::coinbase::build(w, tx_outs, "c2pool", params,
                                        /*ref_hash=*/uint256::ZERO);
    EXPECT_EQ(reassembled, layout.bytes);

    // Value splits: worker payout = subsidy - masternode share; the single
    // genesis miner carries it all (modulo the donation rounding remainder),
    // the masternode output carries EXACTLY its GBT amount, and the total
    // never exceeds the coinbasevalue.
    const uint64_t worker_payout = kCoinbaseValue - kMnAmount;
    uint64_t total = 0, miner_amt = 0, mn_amt = 0, donation_amt = 0;
    const auto mn_script = ParseHex(fixture_mn_payee().substr(1));
    const std::vector<unsigned char> donation_script(
        dash::DONATION_SCRIPT.begin(), dash::DONATION_SCRIPT.end());
    for (const auto& o : tx_outs) {
        total += o.amount;
        if (o.script == miner_script)   miner_amt   += o.amount;
        if (o.script == mn_script)      mn_amt      += o.amount;
        if (o.script == donation_script) donation_amt += o.amount;
    }
    EXPECT_EQ(total, kCoinbaseValue);
    EXPECT_EQ(mn_amt, kMnAmount);
    EXPECT_EQ(miner_amt + donation_amt, worker_payout);
    EXPECT_GE(miner_amt, worker_payout - 2);   // donation keeps only rounding dust
}

// ── 4d: X11 difficulty + submit classification ──────────────────────────────

struct SubmitRig {
    Fixture fx{true};
    std::unique_ptr<dash::stratum::DASHWorkSource> ws;
    core::stratum::JobSnapshot job;
    std::string en1 = "00000001";
    std::string en2 = "00000002";
    uint256 prev;

    SubmitRig()
    {
        ws = fx.make();
        auto cbr = ws->build_connection_coinbase(uint256::ZERO, en1,
                                                 fixture_miner_script(), {});
        job.coinb1          = cbr.coinb1;
        job.coinb2          = cbr.coinb2;
        job.gbt_prevhash    = kPrevHashHex;
        job.nbits           = "1e0ffff0";
        job.version         = static_cast<uint32_t>(kVersion);
        job.merkle_branches = cbr.snapshot.merkle_branches;
        job.tx_data         = cbr.snapshot.tx_data;
        job.subsidy         = cbr.snapshot.subsidy;
        prev.SetHex(kPrevHashHex);
    }

    // Reproduce the submit-side header assembly for a given nonce.
    std::vector<unsigned char> header_for(uint32_t nonce) const
    {
        auto coinbase = reassemble(job.coinb1, en1, en2, job.coinb2);
        uint256 root = fold_branches(dash::coin::coinbase_txid(coinbase),
                                     job.merkle_branches);
        return assemble_header(job.version, prev, root, kCurtime,
                               0x1e0ffff0u, nonce);
    }

    uint256 pow_for(uint32_t nonce) const
    {
        auto hdr = header_for(nonce);
        return dash::crypto::hash_x11(hdr.data(), hdr.size());
    }

    // First nonce in [0, limit) whose X11 PoW satisfies `pred`.
    template <typename Pred>
    uint32_t find_nonce(Pred pred, uint32_t limit = 5000) const
    {
        for (uint32_t n = 0; n < limit; ++n)
            if (pred(pow_for(n))) return n;
        ADD_FAILURE() << "no nonce satisfying predicate in [0," << limit << ")";
        return 0;
    }

    nlohmann::json submit(uint32_t nonce)
    {
        return ws->mining_submit(
            "XfixtureMinerAddress", "job_0", en1, en2,
            dash::coinbase::be_hex_u32(kCurtime),
            dash::coinbase::be_hex_u32(nonce),
            "rid-0", {}, &job);
    }
};

TEST(DashStratumWorkSource, ComputeShareDifficultyMatchesX11Reconstruction)
{
    SubmitRig rig;
    const uint32_t nonce = 7;

    double got = rig.ws->compute_share_difficulty(
        rig.job.coinb1, rig.job.coinb2, rig.en1, rig.en2,
        dash::coinbase::be_hex_u32(kCurtime),
        dash::coinbase::be_hex_u32(nonce),
        rig.job.version, rig.job.gbt_prevhash, rig.job.nbits,
        rig.job.merkle_branches);

    // Pin: diff1 / x11(header) over the independently assembled fixture header.
    double expected = chain::target_to_difficulty(rig.pow_for(nonce));
    ASSERT_GT(expected, 0.0);
    EXPECT_DOUBLE_EQ(got, expected);
}

TEST(DashStratumWorkSource, ComputeShareDifficultyMalformedInputIsZero)
{
    Fixture fx(true);
    auto ws = fx.make();
    // Non-hex prevhash -> malformed header -> the documented 0.0 sentinel the
    // vardiff gate treats as a hard reject.
    double diff = ws->compute_share_difficulty(
        "coinb1", "coinb2", "en1", "en2", "ntime", "nonce",
        /*version=*/0x20000000u, "prevhash", "1e0ffff0",
        /*merkle_branches=*/{});
    EXPECT_DOUBLE_EQ(diff, 0.0);
}

TEST(DashStratumWorkSource, MiningSubmitRejectsWithoutJobSnapshot)
{
    Fixture fx(true);
    auto ws = fx.make();
    auto result = ws->mining_submit(
        "Xaddr.worker1", "job-0", "en1", "en2", "ntime", "nonce", "rid-0",
        /*merged_addresses=*/{}, /*job=*/nullptr);
    ASSERT_TRUE(result.is_array());
    EXPECT_FALSE(result[0].get<bool>());
    EXPECT_EQ(result[1][0].get<int>(), 21);   // Job not found
    EXPECT_FALSE(fx.submit_called);
}

TEST(DashStratumWorkSource, MiningSubmitAcceptsShareBelowShareTarget)
{
    SubmitRig rig;
    // Easy share target, impossible block target: a deterministic ShareAccept.
    rig.job.share_bits  = 0x207fffffu;    // ~2^255 target: trivially satisfied
    rig.job.block_nbits = "1c00ffff";     // hard: fixture PoW can never meet it
    const uint256 block_target = dash::coin::target_from_nbits(0x1c00ffffu);
    const uint256 share_target = dash::coin::target_from_nbits(0x207fffffu);
    const uint32_t nonce = rig.find_nonce([&](const uint256& pow) {
        return pow <= share_target && pow > block_target;
    });

    auto result = rig.submit(nonce);
    ASSERT_TRUE(result.is_boolean());
    EXPECT_TRUE(result.get<bool>());
    // Not a block: the won-block broadcaster must NOT have fired.
    EXPECT_FALSE(rig.fx.submit_called);
}

TEST(DashStratumWorkSource, MiningSubmitRejectsLowDifficulty)
{
    SubmitRig rig;
    // Both targets impossible for the fixture PoW -> low-difficulty reject.
    rig.job.share_bits  = 0x1c00ffffu;
    rig.job.block_nbits = "1c00ffff";
    const uint256 hard_target = dash::coin::target_from_nbits(0x1c00ffffu);
    const uint32_t nonce = rig.find_nonce([&](const uint256& pow) {
        return pow > hard_target;
    });

    auto result = rig.submit(nonce);
    ASSERT_TRUE(result.is_array());
    EXPECT_FALSE(result[0].get<bool>());
    EXPECT_EQ(result[1][0].get<int>(), 23);   // Low difficulty share
    EXPECT_FALSE(rig.fx.submit_called);
}

TEST(DashStratumWorkSource, MiningSubmitWonBlockAssemblesAndBroadcasts)
{
    SubmitRig rig;
    // Trivial block target -> deterministic WonBlock for a mined-in-test nonce.
    rig.job.share_bits  = 0x207fffffu;
    rig.job.block_nbits = "207fffff";
    const uint256 block_target = dash::coin::target_from_nbits(0x207fffffu);
    const uint32_t nonce = rig.find_nonce([&](const uint256& pow) {
        return pow <= block_target;
    });

    auto result = rig.submit(nonce);
    ASSERT_TRUE(result.is_boolean());
    EXPECT_TRUE(result.get<bool>());
    ASSERT_TRUE(rig.fx.submit_called);
    EXPECT_EQ(rig.fx.submit_height, 424242u);

    // The dispatched block must be the --mine-block serialization:
    // header(80) || CompactSize(1 + ntx) || coinbase || txs.
    const auto& block = rig.fx.submitted_block;
    const auto  header = rig.header_for(nonce);
    const auto  coinbase = reassemble(rig.job.coinb1, rig.en1, rig.en2, rig.job.coinb2);
    ASSERT_GT(block.size(), 81u + coinbase.size());
    EXPECT_TRUE(std::equal(header.begin(), header.end(), block.begin()));
    EXPECT_EQ(block[80], 3u);   // CompactSize: coinbase + 2 fixture txs
    EXPECT_TRUE(std::equal(coinbase.begin(), coinbase.end(), block.begin() + 81));
    // Fixture tx bytes trail the coinbase verbatim.
    auto t1 = ParseHex("aa01"), t2 = ParseHex("bb02");
    std::vector<unsigned char> tail;
    tail.insert(tail.end(), t1.begin(), t1.end());
    tail.insert(tail.end(), t2.begin(), t2.end());
    ASSERT_EQ(block.size(), 81u + coinbase.size() + tail.size());
    EXPECT_TRUE(std::equal(tail.begin(), tail.end(),
                           block.begin() + 81 + coinbase.size()));
}

// The mint seam: a share-target submission routes the found-share fields into
// set_mint_share_fn when bound (the 4d follow-up wiring point).
TEST(DashStratumWorkSource, MiningSubmitRoutesShareIntoMintSeam)
{
    SubmitRig rig;
    rig.job.share_bits  = 0x207fffffu;
    rig.job.block_nbits = "1c00ffff";
    const uint256 block_target = dash::coin::target_from_nbits(0x1c00ffffu);
    const uint256 share_target = dash::coin::target_from_nbits(0x207fffffu);
    const uint32_t nonce = rig.find_nonce([&](const uint256& pow) {
        return pow <= share_target && pow > block_target;
    });

    bool mint_called = false;
    dash::stratum::DASHWorkSource::MintShareInputs seen;
    rig.ws->set_mint_share_fn(
        [&](const dash::stratum::DASHWorkSource::MintShareInputs& in) -> uint256 {
            mint_called = true;
            seen = in;
            uint256 h;
            h.SetHex("4444444444444444444444444444444444444444444444444444444444444444");
            return h;
        });

    auto result = rig.submit(nonce);
    ASSERT_TRUE(result.is_boolean());
    EXPECT_TRUE(result.get<bool>());
    ASSERT_TRUE(mint_called);
    EXPECT_EQ(seen.header_bytes, rig.header_for(nonce));
    EXPECT_EQ(seen.coinbase_bytes,
              reassemble(rig.job.coinb1, rig.en1, rig.en2, rig.job.coinb2));
    EXPECT_EQ(seen.subsidy, kCoinbaseValue);
    EXPECT_EQ(seen.pow_hash, rig.pow_for(nonce));
}

}  // namespace
