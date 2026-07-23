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

#include <impl/dash/stratum/submit_payee_guard.hpp>  // check_submit_payee (stale-payee fix)
#include <impl/dash/coinbase_builder.hpp>     // compute_dash_payouts, build, split_coinb, be_hex_u32
#include <impl/dash/coin/block_producer.hpp>  // coinbase_txid, compute_merkle_root, serialize_header80, target_from_nbits
#include <impl/dash/coin/zmq_tip_notify.hpp>  // dash::coin::TipHashDedup, zmq_hashblock_frame_to_hex (ZMQ hashblock instant tip-notify)
#include <impl/dash/crypto/hash_x11.hpp>
#include <impl/dash/params.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>  // CSimplifiedMNListEntry (embedded SML seed)
#include <impl/dash/coin/vendor/cbtx.hpp>           // parse_cbtx (read served creditPool)
#include <impl/dash/coin/embedded_gbt.hpp>          // encode_cbtx (GBT-xcheck fallback fixture)

#include <core/stratum_work_source.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>                // core::MiningInterface (dashboard stats seam)

#include <btclibs/util/strencodings.h>        // ParseHex, HexStr

#include <gtest/gtest.h>

#include <atomic>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
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
    // DASH adopts p2pool-dash's field-tuned 10s vardiff share-rate default (set in
    // the work-source ctor, ec26caef) to stop the X11 vardiff oscillation/reject
    // storm -- NOT the 3s BTC StratumConfig default. Keep this KAT in lockstep.
    EXPECT_DOUBLE_EQ(cfg.target_time, 10.0);
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

// ═════════════════════════════════════════════════════════════════════════════
// Stale-payee fix KATs (bad-cb-payee root cause; hex-confirmed @h1517420).
// DASH rotates the masternode payee EVERY block: a job must be ONE frozen
// template unit (header + coinbase + branches + txs), the template cache must
// die on RPC-reconnect churn, and a won block whose coinbase no longer matches
// the current height's payee set must be rejected LOUDLY, never submitted.
// ═════════════════════════════════════════════════════════════════════════════

// A rotated sibling of rich_work(): the NEXT height, new prev, and — the DASH
// property under test — a DIFFERENT masternode payee (pkh 0x33, new amount).
const char* const kRotatedPrevHashHex =
    "00000000000000c4d5e6f708192a3b4c5d6e2f8c9e5a1d4b3c6e7f8091a2b3c4";

std::string rotated_mn_payee()
{
    std::vector<unsigned char> s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, 0x33);
    s.push_back(0x88);
    s.push_back(0xac);
    return "!" + HexStr(std::span<const unsigned char>(s.data(), s.size()));
}

dash::coin::DashWorkData rotated_work()
{
    dash::coin::DashWorkData w = rich_work();
    w.m_previous_block.SetHex(kRotatedPrevHashHex);
    w.m_height += 1;
    w.m_packed_payments.clear();
    dash::coin::PackedPayment mn;
    mn.payee  = rotated_mn_payee();
    mn.amount = kMnAmount + 12345;   // rotation also changes the mandated amount
    w.m_packed_payments.push_back(mn);
    w.m_payment_amount = mn.amount;
    return w;
}

// Fix 1 pin: build_connection_coinbase freezes the header fields ATOMICALLY
// with the coinbase (WorkSnapshot::has_header) — the fields the stratum
// session must use INSTEAD of its separately-fetched template.
TEST(DashStratumWorkSource, SnapshotFreezesHeaderAtomicallyWithCoinbase)
{
    Fixture fx(true);
    auto ws = fx.make();
    auto cbr = ws->build_connection_coinbase(uint256::ZERO, "00000000",
                                             fixture_miner_script(), {});
    ASSERT_FALSE(cbr.coinb1.empty());
    EXPECT_TRUE(cbr.snapshot.has_header);
    EXPECT_EQ(cbr.snapshot.gbt_prevhash, std::string(kPrevHashHex));
    EXPECT_EQ(cbr.snapshot.header_version, static_cast<uint32_t>(kVersion));
    EXPECT_EQ(cbr.snapshot.block_nbits_hex, "1e0ffff0");
    EXPECT_EQ(cbr.snapshot.curtime, kCurtime);
    EXPECT_EQ(cbr.snapshot.height, 424242u);
    // require_job_snapshot is set: the core session refuses mixed jobs.
    EXPECT_TRUE(ws->get_stratum_config().require_job_snapshot);
}

// Fix 1 pin — THE double-fetch race. The core session fetches the template
// and the coinbase in two separate work-source calls; a rotation in between
// previously produced a MIXED job: tmpl A's header + a coinbase carrying
// height B's masternode payee -> deterministic dashd bad-cb-payee at submit.
// Pin (a) the hazard witness: the pre-rotation tmpl header differs from the
// post-rotation snapshot header, so a session composing tmpl(A)+coinbase(B)
// WOULD have mixed template generations; and (b) the fix invariant: the
// snapshot the coinbase ships with is self-consistent — its header AND its
// payee both come from the SAME (post-rotation) template.
TEST(DashStratumWorkSource, TemplateRotationBetweenFetchesYieldsSelfConsistentSnapshot)
{
    Fixture fx(true);
    auto ws = fx.make();

    // Fetch #1: the template, as StratumSession::send_notify_work does first.
    auto tmpl_a = ws->get_current_work_template();
    ASSERT_EQ(tmpl_a.value("previousblockhash", ""), std::string(kPrevHashHex));

    // The tip moves between the two fetches (new block -> payee ROTATES).
    fx.fallback_work = rotated_work();
    ws->bump_work_generation();   // the tip signal that refreshes the cache

    // Fetch #2: the per-connection coinbase.
    auto cbr = ws->build_connection_coinbase(uint256::ZERO, "00000000",
                                             fixture_miner_script(), {});
    ASSERT_FALSE(cbr.coinb1.empty());
    ASSERT_TRUE(cbr.snapshot.has_header);

    // (a) hazard witness: tmpl(A) + this coinbase(B) would be a MIXED job.
    EXPECT_NE(cbr.snapshot.gbt_prevhash, tmpl_a.value("previousblockhash", ""));

    // (b) fix invariant: snapshot header and coinbase payee are BOTH from the
    // rotated template — the new payee script is in the coinbase, the old one
    // is gone, and the frozen header names the rotated tip/height.
    EXPECT_EQ(cbr.snapshot.gbt_prevhash, std::string(kRotatedPrevHashHex));
    EXPECT_EQ(cbr.snapshot.height, 424243u);
    const std::string new_payee_hex = rotated_mn_payee().substr(1);
    const std::string old_payee_hex = fixture_mn_payee().substr(1);
    const std::string cb_hex = cbr.coinb1 + cbr.coinb2;
    EXPECT_NE(cb_hex.find(new_payee_hex), std::string::npos);
    EXPECT_EQ(cb_hex.find(old_payee_hex), std::string::npos);
}

// Fix 2 pin: a CoindRPC reconnect (the churn window) invalidates the cached
// template + bumps the work generation, so no job is served from a payee
// snapshot predating the reconnect.
TEST(DashStratumWorkSource, InvalidateTemplateCacheForcesRefetchAndBumpsGeneration)
{
    dash::coin::NodeCoinState cs;   // unpopulated -> fallback arm
    int fallback_calls = 0;
    auto ws = std::make_unique<dash::stratum::DASHWorkSource>(
        cs,
        [&fallback_calls]() {
            ++fallback_calls;
            return rich_work();
        });

    ASSERT_FALSE(ws->get_current_work_template().empty());
    EXPECT_EQ(fallback_calls, 1);
    // Same generation, inside the TTL: served from cache, no re-fetch.
    ASSERT_FALSE(ws->get_current_work_template().empty());
    EXPECT_EQ(fallback_calls, 1);

    const uint64_t gen_before = ws->get_work_generation();
    ws->invalidate_template_cache("kat: simulated CoindRPC reconnect");
    EXPECT_EQ(ws->get_work_generation(), gen_before + 1);

    // Next serve re-sources through the fallback — the stale snapshot is gone.
    ASSERT_FALSE(ws->get_current_work_template().empty());
    EXPECT_EQ(fallback_calls, 2);
}

// Fallback-arm event-driven tip refresh pin: on the dashd-fallback arm the
// template cache only re-sources on the 30 s staleness TTL, so a new DASH block
// can leave miners hashing a stale tip for up to ~30 s (accepted pseudoshares
// that can no longer win the current block). The run-path tip poller
// (main_dash.cpp) closes that window by firing the SAME refresh pair on a
// dashd best-block change that the embedded arm fires from its header-chain
// tip-changed callback: invalidate_template_cache() + bump_work_generation(),
// then notify_all() pushes a clean_jobs mining.notify. This KAT pins the
// work-source contract that pair relies on: on a tip change the served template
// must SWAP to the new tip (no stale-tip mining) AND the work generation must
// bump (the clean_jobs/notify signal every session re-pulls on). Fallback arm
// only: an UNPOPULATED coin-state, so get_work routes to the dashd fallback.
TEST(DashStratumWorkSource, FallbackArmTipChangeRefreshesTemplateAndBumpsGeneration)
{
    Fixture fx(true);                       // unpopulated coin-state -> fallback arm
    ASSERT_FALSE(fx.coin_state.populated());
    auto ws = fx.make();

    // Baseline: the fallback serves the pre-tip-change template, cached at the
    // old tip. This is what an idle miner would keep hashing until the TTL.
    auto tmpl_before = ws->get_current_work_template();
    ASSERT_FALSE(tmpl_before.empty());
    EXPECT_EQ(tmpl_before.value("previousblockhash", ""), std::string(kPrevHashHex));
    const uint64_t gen_before = ws->get_work_generation();

    // A new DASH block arrives: dashd's best-block hash changes. The fallback
    // now sources a new-tip template (rotated prev + rotated payee), exactly as
    // getbestblockhash flips for the run-path poller.
    fx.fallback_work = rotated_work();

    // The poller's refresh action on an observed tip change (the SAME pair the
    // embedded header-chain tip-changed callback fires).
    ws->invalidate_template_cache("kat: fallback-arm dashd best-block changed");
    ws->bump_work_generation();

    // (a) clean_jobs/notify signal: work generation advanced, so notify_all()
    //     will push a fresh mining.notify to every session.
    EXPECT_GT(ws->get_work_generation(), gen_before);

    // (b) no more stale-tip mining: the next served template is the NEW tip,
    //     not the cached pre-change one.
    auto tmpl_after = ws->get_current_work_template();
    ASSERT_FALSE(tmpl_after.empty());
    EXPECT_EQ(tmpl_after.value("previousblockhash", ""),
              std::string(kRotatedPrevHashHex));
    EXPECT_NE(tmpl_after.value("previousblockhash", ""),
              tmpl_before.value("previousblockhash", ""));
    EXPECT_EQ(tmpl_after.value("height", 0u), 424243u);
}

// ── #751 idle-reconnect churn fix KAT ───────────────────────────────────────
// dashd closes an idle keep-alive connection on its rpcservertimeout (default
// 30 s), so on an otherwise-idle pool c2pool reconnects every ~30-90 s. The old
// behaviour invalidated the template cache (and fired clean_jobs) on EVERY such
// reconnect, flapping the endpoint and wasting rig work even though nothing
// changed on-chain. The fix makes the fallback-arm reconnect observer tip-aware:
// on a reconnect it probes dashd's best-block hash and invalidates ONLY if the
// tip actually moved during the disconnect.
//
// This KAT models that observer (mirroring main_dash.cpp's reconnect handler the
// same way the ZMQ KAT models fire_refresh) and pins all three cases:
//   (1) reconnect with the tip UNCHANGED -> NO invalidate (cache retained, no
//       clean_jobs) -- the churn fix;
//   (2) reconnect with the tip CHANGED during the disconnect -> DOES invalidate
//       + bump (the stale-masternode-payee INVARIANT is preserved -- a moved tip
//       must still re-source fresh-payee work);
//   (3) reconnect where the best-block probe FAILS -> FAIL-SAFE invalidate
//       (never serve stale-payee work on an unproven tip).
TEST(DashStratumWorkSource, ReconnectInvalidatesOnlyWhenTipChanged)
{
    Fixture fx(true);                       // unpopulated coin-state -> fallback arm
    ASSERT_FALSE(fx.coin_state.populated());
    auto ws = fx.make();

    // Shared last-seen-tip dedup + the tip-aware reconnect observer, mirroring
    // main_dash.cpp: fire_refresh invalidates+bumps IFF the tip is new; the
    // reconnect handler adds the fail-safe invalidate on a probe failure.
    dash::coin::TipHashDedup dedup;
    int notify_count = 0;
    auto fire_refresh = [&](const std::string& tip) -> bool {
        if (!dedup.is_new_tip(tip)) return false;   // unchanged tip -> no-op
        ws->invalidate_template_cache("kat: tip changed during disconnect");
        ws->bump_work_generation();
        ++notify_count;                              // stands in for notify_all()
        return true;
    };
    auto on_reconnect = [&](bool probe_ok, const std::string& probed_tip) {
        if (!probe_ok || probed_tip.empty()) {
            // FAIL-SAFE: unproven tip -> conservatively invalidate.
            ws->invalidate_template_cache("kat: reconnect probe failed");
            ++notify_count;
            return;
        }
        // Benign idle-timeout reconnect (tip unchanged) coalesces to a no-op;
        // a real tip change fires the refresh trio.
        fire_refresh(probed_tip);
    };

    // Startup baseline: seed the dedup with the tip we are already mining (as the
    // poll does at startup, WITHOUT notifying).
    const std::string tip_old(64, 'a');
    dedup.set_last(tip_old);
    auto tmpl_before = ws->get_current_work_template();
    ASSERT_FALSE(tmpl_before.empty());
    EXPECT_EQ(tmpl_before.value("previousblockhash", ""), std::string(kPrevHashHex));
    const uint64_t gen_baseline = ws->get_work_generation();

    // (1) Idle-timeout reconnect, tip UNCHANGED -> NO invalidate, NO clean_jobs.
    //     The endpoint does not flap; the cached template stays put.
    on_reconnect(true, tip_old);
    EXPECT_EQ(notify_count, 0);
    EXPECT_EQ(ws->get_work_generation(), gen_baseline);   // no work-gen bump
    auto tmpl_still = ws->get_current_work_template();
    ASSERT_FALSE(tmpl_still.empty());
    EXPECT_EQ(tmpl_still.value("previousblockhash", ""), std::string(kPrevHashHex));

    // (2) A real tip change during the disconnect window -> MUST invalidate + bump
    //     (stale-masternode-payee invariant preserved). The fallback now sources
    //     the rotated-tip/rotated-payee template.
    fx.fallback_work = rotated_work();
    const std::string tip_new(64, 'b');
    ASSERT_NE(tip_new, tip_old);
    on_reconnect(true, tip_new);
    EXPECT_EQ(notify_count, 1);                            // trio fired
    EXPECT_GT(ws->get_work_generation(), gen_baseline);   // clean_jobs/notify signal
    auto tmpl_after = ws->get_current_work_template();
    ASSERT_FALSE(tmpl_after.empty());
    EXPECT_EQ(tmpl_after.value("previousblockhash", ""),   // no stale-tip mining
              std::string(kRotatedPrevHashHex));
    EXPECT_EQ(tmpl_after.value("height", 0u), 424243u);

    // (2b) An immediate follow-up reconnect on the SAME (now current) tip is again
    //      benign -> deduped no-op (proves case (1) still holds after a change).
    const uint64_t gen_after_change = ws->get_work_generation();
    on_reconnect(true, tip_new);
    EXPECT_EQ(notify_count, 1);
    EXPECT_EQ(ws->get_work_generation(), gen_after_change);

    // (3) FAIL-SAFE: the best-block probe fails on reconnect (RPC not ready) ->
    //     invalidate conservatively rather than risk serving stale-payee work.
    on_reconnect(false, "");
    EXPECT_EQ(notify_count, 2);                            // fail-safe invalidate fired
}

// ── io-thread-decouple KAT (mining-hotel stratum-stall fix, v0.2.3.8) ────────
// The stall fix: the stratum io_context thread must NEVER block on the dashd
// fallback getblocktemplate. cached_work() re-sources through a background
// executor (the dedicated rpc_pool in main_dash.cpp) as a SINGLE-FLIGHT job and
// serves the cached template immediately, so a generation bump (a minted share,
// ~every 15-30 s) no longer freezes 60+ sessions on a blocking GBT. Pins:
//   (a) with an executor wired, a cache-miss / gen-bump does NOT call the (slow)
//       fallback on the calling (io) thread -- it schedules ONE background job
//       and serves the current cache immediately;
//   (b) the re-source runs on the EXECUTOR's thread, not the caller's;
//   (c) single-flight: concurrent misses schedule at most one refresh;
//   (d) the gen-key freshness contract (double-fetch-race fix) is preserved --
//       a bump still triggers a refresh, only OFF the io thread.
TEST(DashStratumWorkSource, IoThreadDecoupleServesCachedAndRefreshesOffThread)
{
    dash::coin::NodeCoinState cs;   // unpopulated -> dashd-fallback arm
    std::atomic<int> fallback_calls{0};
    std::atomic<bool> fallback_on_caller{false};
    const auto caller_tid = std::this_thread::get_id();

    auto ws = std::make_unique<dash::stratum::DASHWorkSource>(
        cs,
        [&]() -> dash::coin::DashWorkData {
            fallback_calls.fetch_add(1);
            if (std::this_thread::get_id() == caller_tid)
                fallback_on_caller.store(true);
            return rich_work();
        });

    // Controllable executor: capture jobs so the test drives WHEN the background
    // re-source runs. Single-flight is enforced inside the work source.
    std::mutex jm;
    std::vector<std::function<void()>> jobs;
    ws->set_refresh_executor([&](std::function<void()> job) {
        std::lock_guard<std::mutex> l(jm);
        jobs.push_back(std::move(job));
    });

    // (1) First request: cache empty. The io thread does NOT call the fallback --
    //     it schedules ONE background job and serves an empty set-gap template.
    auto t0 = ws->get_current_work_template();
    EXPECT_TRUE(t0.empty());
    EXPECT_EQ(fallback_calls.load(), 0);              // io thread never blocked on dashd
    { std::lock_guard<std::mutex> l(jm); ASSERT_EQ(jobs.size(), 1u); }

    // (1b) Single-flight: another request while a refresh is in flight schedules
    //      no additional job.
    (void)ws->get_current_work_template();
    { std::lock_guard<std::mutex> l(jm); EXPECT_EQ(jobs.size(), 1u); }

    // (2) Run the background job on a DIFFERENT thread (the rpc_pool stand-in).
    //     The blocking fallback runs THERE; the cache is populated.
    std::function<void()> job0;
    { std::lock_guard<std::mutex> l(jm); job0 = jobs[0]; jobs.clear(); }
    std::thread(job0).join();
    EXPECT_EQ(fallback_calls.load(), 1);
    EXPECT_FALSE(fallback_on_caller.load());          // re-source ran OFF the caller thread

    // (3) Now cached + fresh: served immediately, no new fallback call, no job.
    auto t1 = ws->get_current_work_template();
    EXPECT_FALSE(t1.empty());
    EXPECT_EQ(t1.value("previousblockhash", ""), std::string(kPrevHashHex));
    EXPECT_EQ(fallback_calls.load(), 1);
    { std::lock_guard<std::mutex> l(jm); EXPECT_TRUE(jobs.empty()); }

    // (4) A generation bump (a minted best-share) breaks freshness, but the io
    //     thread STILL does not block: it serves the cached template and
    //     schedules a single background refresh.
    ws->bump_work_generation();
    auto t2 = ws->get_current_work_template();
    EXPECT_FALSE(t2.empty());                          // served cached template -- no stall
    EXPECT_EQ(fallback_calls.load(), 1);               // fallback NOT called on the io thread
    { std::lock_guard<std::mutex> l(jm); ASSERT_EQ(jobs.size(), 1u); }

    // Draining the scheduled refresh runs the fallback off-thread again.
    std::function<void()> job1;
    { std::lock_guard<std::mutex> l(jm); job1 = jobs[0]; jobs.clear(); }
    std::thread(job1).join();
    EXPECT_EQ(fallback_calls.load(), 2);
}

// ── dashd ZMQ `hashblock` INSTANT tip-notify (hardening on the #770 poll) ────
//
// dashd publishes a `hashblock` ZMQ message the instant it connects a new
// block, so a SUB subscriber closes the lost-block window from <=3 s (poll) to
// ~0 s. On a hashblock frame the subscriber fires the SAME refresh trio the
// poll fires (invalidate_template_cache + bump_work_generation + notify_all),
// and BOTH paths share ONE last-seen-tip dedup so a double-fire on the same
// block coalesces to a single refresh. These KATs pin that contract without a
// live daemon or libzmq: the pure frame-decode + dedup + the work-source trio.

// dashd publishes the hashblock frame ALREADY in RPC/display byte order
// (CZMQPublishHashBlockNotifier::NotifyBlock reverses the internal little-endian
// array before sending; Bitcoin Core doc/zmq.md: "reversed byte order, the same
// format as the RPC interface"). So the decoder hex-encodes the frame DIRECTLY
// — NO further reversal — which is exactly what makes a ZMQ notify and a poll
// tick on the SAME block produce the SAME getbestblockhash string and thus dedup
// against each other. (A second reversal here would break cross-path dedup and
// double-fire the refresh trio every block.)
TEST(DashZmqHashblock, FrameDecodeMatchesGetbestblockhashByteOrder)
{
    // 32-byte frame 0x00,0x01,...,0x1f -> hex encodes DIRECTLY, no reversal.
    unsigned char frame[32];
    for (unsigned i = 0; i < 32; ++i) frame[i] = static_cast<unsigned char>(i);
    const std::string hex = dash::coin::zmq_hashblock_frame_to_hex(frame, 32);
    // Straight order: first byte (0x00) first ... last byte (0x1f) last — the
    // string getbestblockhash would return for this block hash.
    EXPECT_EQ(hex,
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    // Cross-path contract: the frame decodes to the SAME string a poll would
    // report (both are already display order), so the shared dedup coalesces.
    const std::string poll_would_report =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    EXPECT_EQ(hex, poll_would_report);
    // Malformed length -> empty (never a bogus tip that would false-fire).
    EXPECT_TRUE(dash::coin::zmq_hashblock_frame_to_hex(frame, 31).empty());
    EXPECT_TRUE(dash::coin::zmq_hashblock_frame_to_hex(nullptr, 32).empty());
}

// Core KAT: a ZMQ hashblock message drives the refresh+notify trio exactly
// once, a double-fire (ZMQ then poll, or poll then ZMQ, on the SAME tip) is
// deduped to a no-op, and a subsequent DIFFERENT tip fires again — proving the
// poll path still works (no regression) and coexists with the ZMQ path via the
// shared dedup. Fallback arm only (unpopulated coin-state -> dashd fallback).
TEST(DashZmqHashblock, InstantNotifyFiresTrioOnceAndDedupesDoubleFire)
{
    Fixture fx(true);
    ASSERT_FALSE(fx.coin_state.populated());
    auto ws = fx.make();

    // Mirror main_dash's shared refresh: ONE dedup consulted by both paths, and
    // the trio (invalidate + bump + [notify counter]) fired only on a NEW tip.
    dash::coin::TipHashDedup dedup;
    int notify_count = 0;
    auto fire_refresh = [&](const std::string& tip) {
        if (!dedup.is_new_tip(tip)) return;     // coalesce poll+ZMQ double-fire
        ws->invalidate_template_cache("kat: tip-notify best-block changed");
        ws->bump_work_generation();
        ++notify_count;                          // stands in for notify_all()
    };

    // Startup baseline: the poll seeds the dedup with the tip we are already
    // mining WITHOUT notifying (matches main_dash's tip_dedup->set_last()).
    const std::string tip_old(64, 'a');
    dedup.set_last(tip_old);
    const uint64_t gen_before = ws->get_work_generation();
    auto tmpl_before = ws->get_current_work_template();
    ASSERT_FALSE(tmpl_before.empty());
    EXPECT_EQ(tmpl_before.value("previousblockhash", ""), std::string(kPrevHashHex));

    // (1) A new block arrives on dashd: the fallback now sources the new-tip
    //     template, and a ZMQ hashblock frame decodes to the new tip hash.
    fx.fallback_work = rotated_work();
    unsigned char frame[32];
    for (unsigned i = 0; i < 32; ++i) frame[i] = static_cast<unsigned char>(0xB0 + (i & 0x0f));
    const std::string tip_new = dash::coin::zmq_hashblock_frame_to_hex(frame, 32);
    ASSERT_FALSE(tip_new.empty());
    ASSERT_NE(tip_new, tip_old);

    // ZMQ fires first (instant).
    fire_refresh(tip_new);
    EXPECT_EQ(notify_count, 1);                       // trio fired exactly once
    EXPECT_GT(ws->get_work_generation(), gen_before); // clean_jobs/notify signal
    auto tmpl_after = ws->get_current_work_template();
    ASSERT_FALSE(tmpl_after.empty());
    EXPECT_EQ(tmpl_after.value("previousblockhash", ""),
              std::string(kRotatedPrevHashHex));       // no stale-tip mining
    EXPECT_EQ(tmpl_after.value("height", 0u), 424243u);

    // (2) The 3 s poll wakes ~instant later and observes the SAME new tip:
    //     shared dedup -> no-op (harmless double-fire coalesced).
    const uint64_t gen_after_zmq = ws->get_work_generation();
    fire_refresh(tip_new);
    EXPECT_EQ(notify_count, 1);                        // still ONE — deduped
    EXPECT_EQ(ws->get_work_generation(), gen_after_zmq);

    // (3) A THIRD, different tip (e.g. ZMQ absent and the poll alone catches the
    //     next block) fires again -> the poll path works, coexisting with ZMQ.
    const std::string tip_third(64, 'c');
    fire_refresh(tip_third);
    EXPECT_EQ(notify_count, 2);
    EXPECT_GT(ws->get_work_generation(), gen_after_zmq);
}

// Fix 3 pin (work-source side of the zero-hash pre-auth job_0 defect): a
// template with a zeroed prev is NOT mineable work — honest set-gap, never a
// zero-prev job.
TEST(DashStratumWorkSource, ZeroPrevhashTemplateIsAnHonestSetGap)
{
    Fixture fx(true);
    fx.fallback_work.m_previous_block = uint256::ZERO;   // bits stay non-zero
    auto ws = fx.make();
    EXPECT_TRUE(ws->get_current_work_template().empty());
    EXPECT_TRUE(ws->get_current_gbt_prevhash().empty());
    auto cbr = ws->build_connection_coinbase(uint256::ZERO, "00000000",
                                             fixture_miner_script(), {});
    EXPECT_TRUE(cbr.coinb1.empty());
    EXPECT_FALSE(cbr.snapshot.has_header);
}

// ── Fix 4: the submit-time payee guard (pure-function KATs) ─────────────────

std::vector<unsigned char> fixture_coinbase_bytes()
{
    Fixture fx(true);
    auto ws = fx.make();
    auto cbr = ws->build_connection_coinbase(uint256::ZERO, "00000001",
                                             fixture_miner_script(), {});
    return reassemble(cbr.coinb1, "00000001", "00000002", cbr.coinb2);
}

TEST(DashSubmitPayeeGuard, OkWhenAllMandatedPaymentsPresent)
{
    const auto cb = fixture_coinbase_bytes();
    const auto r = dash::stratum::check_submit_payee(
        cb, kPrevHashHex, rich_work(), dash::make_coin_params(false));
    EXPECT_EQ(r.verdict, dash::stratum::PayeeGuardVerdict::Ok);
}

TEST(DashSubmitPayeeGuard, PayeeMissingWhenPayeeScriptRotatedAtSameHeight)
{
    // Same prev (same height context) but the current template now mandates a
    // ROTATED masternode payee SCRIPT the frozen coinbase does not pay at all:
    // the genuine bad-cb-payee class (wrong PAYEE, not a mere amount drift).
    // The guard must forbid the submit.
    const auto cb = fixture_coinbase_bytes();
    dash::coin::DashWorkData current = rotated_work();
    current.m_previous_block.SetHex(kPrevHashHex);   // same height, new payee script
    const auto r = dash::stratum::check_submit_payee(
        cb, kPrevHashHex, current, dash::make_coin_params(false));
    EXPECT_EQ(r.verdict, dash::stratum::PayeeGuardVerdict::PayeeMissing);
    EXPECT_NE(r.detail.find("bad-cb-payee"), std::string::npos);
}

TEST(DashSubmitPayeeGuard, OkWhenMandatedAmountDriftsButScriptPresent)
{
    // THE reward-critical false-refusal fix. Same prev, same payee SCRIPT, but
    // the current template's mandated amount differs from the job's frozen one
    // (fees moved on a template re-pull at the same height). dashd validates
    // the masternode amount against the block's OWN fees, so this is a valid
    // winning block — the guard must PASS it (set-membership on scripts, no
    // amount comparison). This exact drift lost mainnet blocks 2508655/2508696.
    const auto cb = fixture_coinbase_bytes();
    dash::coin::DashWorkData current = rich_work();
    current.m_packed_payments[0].amount += 54321;   // same script, drifted amount
    const auto r = dash::stratum::check_submit_payee(
        cb, kPrevHashHex, current, dash::make_coin_params(false));
    EXPECT_EQ(r.verdict, dash::stratum::PayeeGuardVerdict::Ok);
}

TEST(DashSubmitPayeeGuard, WrongHeightWhenPrevDiffers)
{
    // The job's parent is no longer the chain tip: the block is for the wrong
    // height and dashd would reject it. The guard must refuse the submit.
    const auto cb = fixture_coinbase_bytes();
    const auto r = dash::stratum::check_submit_payee(
        cb, kPrevHashHex, rotated_work(), dash::make_coin_params(false));
    EXPECT_EQ(r.verdict, dash::stratum::PayeeGuardVerdict::WrongHeight);
}

TEST(DashSubmitPayeeGuard, UnverifiableOnGarbageCoinbaseNeverBlocks)
{
    const std::vector<unsigned char> garbage = {0x01, 0x02, 0x03};
    const auto r = dash::stratum::check_submit_payee(
        garbage, kPrevHashHex, rich_work(), dash::make_coin_params(false));
    EXPECT_EQ(r.verdict, dash::stratum::PayeeGuardVerdict::Unverifiable);
}

// ── Fix 4 wired into the hot path: mining_submit ────────────────────────────

// A won block whose payee SCRIPT rotated at the SAME height between job issue
// and submit is locally rejected LOUDLY — the broadcaster must NOT fire (never
// submit a doomed bad-cb-payee block; a genuinely omitted mandated payee).
TEST(DashStratumWorkSource, WonBlockWithStalePayeeIsLocallyRejectedNotSubmitted)
{
    SubmitRig rig;
    rig.job.share_bits  = 0x207fffffu;
    rig.job.block_nbits = "207fffff";
    const uint256 block_target = dash::coin::target_from_nbits(0x207fffffu);
    const uint32_t nonce = rig.find_nonce([&](const uint256& pow) {
        return pow <= block_target;
    });

    // Between job issue and submit: the payee SCRIPT ROTATES at the same height
    // (the churn/staleness window). The re-sourced current template now
    // mandates a payee SCRIPT the frozen job coinbase does not pay at all.
    rig.fx.fallback_work = rotated_work();
    rig.fx.fallback_work.m_previous_block.SetHex(kPrevHashHex);  // same prev
    rig.ws->bump_work_generation();   // submit-side cached_work re-sources

    auto result = rig.submit(nonce);
    ASSERT_TRUE(result.is_boolean());
    EXPECT_TRUE(result.get<bool>());          // the miner's work was honest
    EXPECT_FALSE(rig.fx.submit_called);       // ...but NOTHING was dispatched
}

// THE reward-critical false-refusal fix, end-to-end on the hot path. A won
// block whose mandated masternode AMOUNT drifted (fees moved on a same-height
// template re-pull) but whose payee SCRIPT is unchanged is a VALID winning
// block — dashd validates the amount against the block's own fees. The guard
// must PASS it and the broadcaster MUST fire. This drift lost mainnet blocks
// 2508655/2508696 before the set-membership fix.
TEST(DashStratumWorkSource, WonBlockWithMandatedAmountDriftStillSubmits)
{
    SubmitRig rig;
    rig.job.share_bits  = 0x207fffffu;
    rig.job.block_nbits = "207fffff";
    const uint256 block_target = dash::coin::target_from_nbits(0x207fffffu);
    const uint32_t nonce = rig.find_nonce([&](const uint256& pow) {
        return pow <= block_target;
    });

    // Same prev, same payee SCRIPT, only the mandated amount drifts (fee churn).
    rig.fx.fallback_work = rich_work();
    rig.fx.fallback_work.m_packed_payments[0].amount += 98765;
    rig.ws->bump_work_generation();

    auto result = rig.submit(nonce);
    ASSERT_TRUE(result.is_boolean());
    EXPECT_TRUE(result.get<bool>());
    EXPECT_TRUE(rig.fx.submit_called);        // amount drift is NOT a refusal
}

// A won block across a MOVED tip is for the wrong height (the job's parent is
// no longer the chain tip) — dashd would reject it, so the guard refuses and
// the broadcaster must NOT fire.
TEST(DashStratumWorkSource, WonBlockAcrossTipMoveIsLocallyRejected)
{
    SubmitRig rig;
    rig.job.share_bits  = 0x207fffffu;
    rig.job.block_nbits = "207fffff";
    const uint256 block_target = dash::coin::target_from_nbits(0x207fffffu);
    const uint32_t nonce = rig.find_nonce([&](const uint256& pow) {
        return pow <= block_target;
    });

    rig.fx.fallback_work = rotated_work();    // new prev AND new payee
    rig.ws->bump_work_generation();

    auto result = rig.submit(nonce);
    ASSERT_TRUE(result.is_boolean());
    EXPECT_TRUE(result.get<bool>());          // the miner's work was honest
    EXPECT_FALSE(rig.fx.submit_called);       // ...but wrong-height: NOT dispatched
}

// ── Dashboard stats seam (issue: /local_stats hashrate under-reported) ───────
//
// The DASH stratum acceptor is a standalone core::StratumServer bound to a
// DASHWorkSource; its StratumSessions register/update per-connection hashrate +
// share/difficulty state into the work source's OWN registry, NOT into the
// dashboard WebServer's MiningInterface (whose acceptor is disabled). Before the
// fix, MiningInterface::rest_local_stats read only its own empty registry, so a
// busy pool reported miner_hash_rates {} / my_hash_rates_in_last_hour.actual 0
// and a false "No miners connected — pool is idle" warning. main_dash wires
// set_stratum_workers_fn -> DASHWorkSource::get_stratum_workers to close the
// gap. This KAT pins that end-to-end: N workers of known hashrate -> summed
// aggregate, non-empty per-worker maps, no idle warning.

TEST(DashDashboardWiring, LocalStatsSumsStratumWorkerHashrate)
{
    Fixture fx(true);
    auto ws = fx.make();

    struct W { std::string sid, user, worker; double hr, dead, diff; uint64_t acc; };
    // 3 X11 rigs across 2 payout addresses; hashrates in the field's TH/s range.
    const std::vector<W> rigs = {
        {"sess-1", "Xpayout1", "rig0", 1.20e13, 0.0,    4096.0, 100},
        {"sess-2", "Xpayout1", "rig1", 8.00e12, 0.0,    2048.0,  80},
        {"sess-3", "Xpayout2", "rig0", 2.50e13, 1.0e12, 8192.0, 200},
    };
    double expected_total = 0.0, expected_dead = 0.0;
    for (const auto& r : rigs) {
        core::stratum::WorkerInfo wi;
        wi.username    = r.user;
        wi.worker_name = r.worker;
        wi.difficulty  = r.diff;
        ws->register_stratum_worker(r.sid, wi);
        ws->update_stratum_worker(r.sid, r.hr, r.dead, r.diff, r.acc, 0, 0);
        expected_total += r.hr;
        expected_dead  += r.dead;
    }
    ASSERT_EQ(ws->get_stratum_workers().size(), rigs.size());

    // Wire the live registry into a DASH dashboard exactly as main_dash.cpp does.
    core::MiningInterface mi(false, nullptr, c2pool::address::Blockchain::DASH);
    mi.set_stratum_workers_fn([wsrc = ws.get()]() {
        return wsrc->get_stratum_workers();
    });

    auto stats = mi.rest_local_stats();

    // Aggregate hashrate == SUM of connected workers (was 0 before the fix).
    ASSERT_TRUE(stats.contains("my_hash_rates_in_last_hour"));
    const auto& hr = stats["my_hash_rates_in_last_hour"];
    EXPECT_NEAR(hr["actual"].get<double>(),   expected_total,                 1.0);
    EXPECT_NEAR(hr["nonstale"].get<double>(), expected_total - expected_dead, 1.0);
    EXPECT_NEAR(hr["rewarded"].get<double>(), expected_total - expected_dead, 1.0);

    // Per-worker maps are non-empty and keyed per "address.worker".
    ASSERT_TRUE(stats.contains("miner_hash_rates"));
    EXPECT_EQ(stats["miner_hash_rates"].size(), rigs.size());
    EXPECT_FALSE(stats["miner_dead_hash_rates"].empty());
    EXPECT_FALSE(stats["miner_last_difficulties"].empty());
    EXPECT_NEAR(stats["miner_hash_rates"]["Xpayout1.rig0"].get<double>(), 1.20e13, 1.0);

    // No false "pool is idle" warning while miners ARE connected.
    ASSERT_TRUE(stats.contains("warnings"));
    for (const auto& w : stats["warnings"])
        EXPECT_EQ(w.get<std::string>().find("pool is idle"), std::string::npos);
}

// ═════════════════════════════════════════════════════════════════════════════
// C1 mainnet gate (v0.2.4 tag-blocker). The embedded template arm's only prod
// caller does not pass the E2d SML/QuorumManager seams, so build_embedded_
// workdata() emits an EMPTY CCbTx extra_payload — a coinbase that is consensus-
// INVALID (bad-cbtx) on a DIP4-active DASH MAINNET. Until the payload is
// buildable (post-v0.2.4) the embedded arm MUST be fail-closed off mainnet: a
// populated NodeCoinState must NOT serve its embedded template on mainnet (it
// routes to the reward-safe dashd-RPC fallback), while testnet/regtest keep the
// embedded arm (E5 proving ground). is_testnet_ defaults false, so an
// unconfigured node is treated as mainnet — fail-closed by default.
// ═════════════════════════════════════════════════════════════════════════════

namespace {
// A populated coin-state whose embedded template is DISTINGUISHABLE from the
// dashd-fallback fixture (different prev/height), so the served template's
// prevhash proves which arm ran. Empty MN/mempool is fine: the embedded build
// still yields a valid, mineable template (non-null prev, non-zero bits).
const char* const kEmbeddedPrevHashHex =
    "0000000000000000abcdef0123456789abcdef0123456789abcdef0123456789";
constexpr uint32_t kEmbeddedPrevHeight = 500000u;   // embedded template -> +1
void seed_populated(dash::coin::NodeCoinState& cs)
{
    uint256 emb_prev;
    emb_prev.SetHex(kEmbeddedPrevHashHex);
    cs.set_tip(kEmbeddedPrevHeight, emb_prev, /*bits_for_next=*/0x1e0ffff0u,
               /*mtp_at_tip=*/1'700'000'000u, /*addr_ver=*/76, /*p2sh_ver=*/16,
               /*curtime=*/kCurtime, /*version=*/static_cast<uint32_t>(kVersion));
}
}  // namespace

// MAINNET: a populated coin-state must NOT flip to the embedded arm — the served
// template is the reward-safe dashd fallback (prev/height of rich_work), never
// the embedded template (which would carry the empty-CCbTx coinbase).
TEST(DashStratumC1MainnetGate, MainnetPopulatedCoinStateRoutesToDashdFallback)
{
    dash::coin::NodeCoinState cs;
    seed_populated(cs);
    ASSERT_TRUE(cs.populated());
    ASSERT_TRUE(cs.make_embedded_work_inputs().viable());

    auto fallback = []() -> dash::coin::DashWorkData { return rich_work(); };
    auto submit   = [](const std::vector<unsigned char>&, uint32_t) { return true; };

    // is_testnet=false => mainnet => embedded arm GATED off.
    dash::stratum::DASHWorkSource ws(cs, fallback, submit,
                                     core::stratum::StratumConfig{},
                                     /*is_testnet=*/false);

    auto tmpl = ws.get_current_work_template();
    ASSERT_FALSE(tmpl.empty());
    // The fallback's tip/height — NOT the embedded prev/height. Embedded was
    // suppressed on mainnet.
    EXPECT_EQ(tmpl.value("previousblockhash", ""), std::string(kPrevHashHex));
    EXPECT_EQ(tmpl.value("height", 0u), 424242u);

    // The fused adapter path is gated too: source is the retained dashd arm.
    dash::stratum::WorkJobTargetInputs job_in;
    job_in.sane_target_min.SetHex(
        "0000000000000000000000000000000000000000000000000000000000000001");
    job_in.sane_target_max.SetHex(
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    job_in.share_info_bits_target.SetHex(
        "0000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    auto gw = ws.get_work(job_in);
    EXPECT_EQ(gw.source, dash::coin::WorkSource::DashdFallback);
    EXPECT_EQ(gw.work.m_height, 424242u);
}

// TESTNET/REGTEST: the SAME populated coin-state DOES serve its embedded
// template (E5 lives here) — proving the gate is mainnet-only, not a blanket
// disable.
TEST(DashStratumC1MainnetGate, TestnetPopulatedCoinStateServesEmbedded)
{
    dash::coin::NodeCoinState cs;
    seed_populated(cs);
    ASSERT_TRUE(cs.populated());

    auto fallback = []() -> dash::coin::DashWorkData { return rich_work(); };
    auto submit   = [](const std::vector<unsigned char>&, uint32_t) { return true; };

    // is_testnet=true => testnet/regtest => embedded arm ENABLED.
    dash::stratum::DASHWorkSource ws(cs, fallback, submit,
                                     core::stratum::StratumConfig{},
                                     /*is_testnet=*/true);

    uint256 emb_prev;
    emb_prev.SetHex(kEmbeddedPrevHashHex);

    auto tmpl = ws.get_current_work_template();
    ASSERT_FALSE(tmpl.empty());
    // The embedded tip/height (prev_height + 1) — the embedded arm ran.
    EXPECT_EQ(tmpl.value("previousblockhash", ""), emb_prev.GetHex());
    EXPECT_EQ(tmpl.value("height", 0u), kEmbeddedPrevHeight + 1u);

    dash::stratum::WorkJobTargetInputs job_in;
    job_in.sane_target_min.SetHex(
        "0000000000000000000000000000000000000000000000000000000000000001");
    job_in.sane_target_max.SetHex(
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    job_in.share_info_bits_target.SetHex(
        "0000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    auto gw = ws.get_work(job_in);
    EXPECT_EQ(gw.source, dash::coin::WorkSource::Embedded);
    EXPECT_EQ(gw.work.m_height, kEmbeddedPrevHeight + 1u);
}

// RE-SOAK integration: a stale-cached EMBEDDED template (built with an older
// credit-pool seed) must be dropped and re-sourced at SERVE time — the cache-hit
// path re-validates the built creditPool against the current seed. Proves the
// build-vs-serve skew the empirical soak hit is closed on the actual serve path,
// not just the predicate.
TEST(DashStratumC1MainnetGate, EmbeddedCacheHitReValidatesCreditPoolAndReSources)
{
    dash::coin::NodeCoinState cs;
    uint256 emb_prev; emb_prev.SetHex(kEmbeddedPrevHashHex);

    // Full embedded seed: SML + tip + credit-pool, freshness gates armed.
    dash::coin::vendor::CSimplifiedMNListEntry e1, e2;
    e1.proRegTxHash.SetHex(std::string(64, '4')); e1.confirmedHash.SetHex(std::string(64, '5')); e1.isValid = true;
    e2.proRegTxHash.SetHex(std::string(64, '6')); e2.confirmedHash.SetHex(std::string(64, '7')); e2.isValid = true;
    cs.sml().mnList = {e1, e2};
    cs.sml().sort();
    cs.set_have_sml(true);
    cs.set_sml_current_hash(emb_prev);
    cs.set_require_sml(true);
    cs.set_require_fresh_credit_pool(true);

    const int64_t S1 = 33971546001156LL;
    const int64_t S2 = 33971612967986LL;   // advanced seed (one reward later)
    // Seed current AT the tip (height == kEmbeddedPrevHeight) so the height gate
    // passes; the build-vs-serve skew is driven by the VALUE changing.
    cs.set_credit_pool(S1, emb_prev, static_cast<int32_t>(kEmbeddedPrevHeight));
    cs.set_tip(kEmbeddedPrevHeight, emb_prev, 0x1e0ffff0u, 1'700'000'000u,
               76, 16, kCurtime, static_cast<uint32_t>(kVersion));

    auto fallback = []() -> dash::coin::DashWorkData { return rich_work(); };
    auto submit   = [](const std::vector<unsigned char>&, uint32_t) { return true; };
    dash::stratum::DASHWorkSource ws(cs, fallback, submit,
                                     core::stratum::StratumConfig{},
                                     /*is_testnet=*/true);

    auto credit_of = [&]() -> int64_t {
        auto t = ws.peek_template();
        EXPECT_TRUE(t && !t->m_coinbase_payload.empty());
        dash::coin::vendor::CCbTx cb;
        EXPECT_TRUE(dash::coin::vendor::parse_cbtx(t->m_coinbase_payload, cb));
        return cb.creditPoolBalance;
    };

    // First serve: caches the embedded template built over seed S1.
    ASSERT_FALSE(ws.get_current_work_template().empty());
    const int64_t cp1 = credit_of();

    // Advance the credit-pool seed VALUE (same height, no work_generation bump):
    // models the build-vs-serve race where the seed moved after build+cache.
    cs.set_credit_pool(S2, emb_prev, static_cast<int32_t>(kEmbeddedPrevHeight));

    // Second serve: cache HIT on the same work-generation. The serve-time
    // re-check must find the cached creditPool stale vs the new seed, drop it,
    // and re-source a fresh embedded template over S2.
    ASSERT_FALSE(ws.get_current_work_template().empty());
    const int64_t cp2 = credit_of();

    EXPECT_NE(cp1, cp2)
        << "stale-cached embedded creditPool must not be served after the seed advanced";
    EXPECT_EQ(cp2 - cp1, S2 - S1)
        << "the re-sourced template must reflect the advanced seed exactly";
}

// GBT-xcheck reward-safety BACKSTOP: when the embedded CbTx's creditPool differs
// from dashd's GBT for the same height, the arm serves dashd's template — the
// ultimate net for any seed bug the daemonless self-checks miss.
TEST(DashStratumC1MainnetGate, GbtXcheckServesDashdOnCreditPoolMismatch)
{
    dash::coin::NodeCoinState cs;
    uint256 emb_prev; emb_prev.SetHex(kEmbeddedPrevHashHex);
    dash::coin::vendor::CSimplifiedMNListEntry e1;
    e1.proRegTxHash.SetHex(std::string(64, '4')); e1.confirmedHash.SetHex(std::string(64, '5')); e1.isValid = true;
    cs.sml().mnList = {e1}; cs.sml().sort();
    cs.set_have_sml(true);
    cs.set_sml_current_hash(emb_prev);
    cs.set_require_sml(true);
    cs.set_require_fresh_credit_pool(true);
    const int64_t seed = 500000000LL;
    cs.set_credit_pool(seed, emb_prev, static_cast<int32_t>(kEmbeddedPrevHeight));
    cs.set_tip(kEmbeddedPrevHeight, emb_prev, 0x1e0ffff0u, 1'700'000'000u,
               76, 16, kCurtime, static_cast<uint32_t>(kVersion));

    // The dashd fallback disagrees on creditPool for the same height (the block
    // dashd would build carries a DIFFERENT balance) — the backstop must catch it.
    const int64_t dashd_credit = seed + 424242LL;
    auto fallback = [&]() -> dash::coin::DashWorkData {
        dash::coin::DashWorkData w;
        w.m_height = kEmbeddedPrevHeight + 1;
        w.m_previous_block = emb_prev;
        w.m_bits = 0x1e0ffff0u;
        w.m_version = static_cast<uint32_t>(kVersion);
        w.m_curtime = kCurtime;
        dash::coin::vendor::CCbTx cb;
        cb.nVersion = dash::coin::vendor::CCbTx::VERSION_CLSIG_AND_BALANCE;
        cb.nHeight = static_cast<int32_t>(kEmbeddedPrevHeight + 1);
        cb.creditPoolBalance = dashd_credit;
        w.m_coinbase_payload = dash::coin::encode_cbtx(cb);
        return w;
    };
    auto submit = [](const std::vector<unsigned char>&, uint32_t) { return true; };
    dash::stratum::DASHWorkSource ws(cs, fallback, submit,
                                     core::stratum::StratumConfig{},
                                     /*is_testnet=*/true);
    ws.set_gbt_xcheck(true);

    ASSERT_FALSE(ws.get_current_work_template().empty());
    auto t = ws.peek_template();
    ASSERT_TRUE(t && !t->m_coinbase_payload.empty());
    dash::coin::vendor::CCbTx served;
    ASSERT_TRUE(dash::coin::vendor::parse_cbtx(t->m_coinbase_payload, served));
    EXPECT_EQ(served.creditPoolBalance, dashd_credit)
        << "on a creditPool mismatch the backstop must serve dashd's template";
}

TEST(DashDashboardWiring, LocalStatsIdleWarningWhenNoWorkers)
{
    // No provider wired and an empty local registry -> the honest idle warning
    // fires and the per-worker map stays empty (the pre-fix state was correct
    // ONLY when the pool truly had no miners).
    core::MiningInterface mi(false, nullptr, c2pool::address::Blockchain::DASH);
    auto stats = mi.rest_local_stats();

    EXPECT_TRUE(stats["miner_hash_rates"].empty());
    EXPECT_DOUBLE_EQ(stats["my_hash_rates_in_last_hour"]["actual"].get<double>(), 0.0);
    bool idle = false;
    for (const auto& w : stats["warnings"])
        if (w.get<std::string>().find("pool is idle") != std::string::npos) idle = true;
    EXPECT_TRUE(idle);
}

// ═════════════════════════════════════════════════════════════════════════════
// coin-P2P tip event closes the stale-payee window EXPLICITLY (robust under a
// future io-decouple-extended config where refresh_executor_ is SET).
// ═════════════════════════════════════════════════════════════════════════════

namespace {
// A DEFERRED refresh executor (models the rpc_pool background thread): jobs are
// queued, not run inline, so cached_work() takes the serve-stale-while-refreshing
// path — exactly the config where a bump-only tip event would REOPEN the window.
struct DeferredExecutor {
    std::vector<std::function<void()>> jobs;
    void operator()(std::function<void()> j) { jobs.push_back(std::move(j)); }
    void run() { auto q = std::move(jobs); jobs.clear(); for (auto& j : q) j(); }
};
}  // namespace

// THE FIX: invalidate_template_cache() on the coin-P2P tip event guarantees the
// next served job is re-sourced (fresh payee), never the stale cached one — even
// with a background refresh_executor_ set.
TEST(DashStratumCoinP2pTipInvalidate, InvalidateClosesStalePayeeWindowUnderRefreshExecutor)
{
    auto current  = std::make_shared<dash::coin::DashWorkData>(rich_work());   // tip A
    auto fallback = [current]() -> dash::coin::DashWorkData { return *current; };
    auto submit   = [](const std::vector<unsigned char>&, uint32_t) { return true; };
    dash::coin::NodeCoinState cs;   // unpopulated -> fallback arm

    dash::stratum::DASHWorkSource ws(cs, fallback, submit,
                                     core::stratum::StratumConfig{}, /*is_testnet=*/false);
    auto exec = std::make_shared<DeferredExecutor>();
    ws.set_refresh_executor([exec](std::function<void()> j) { (*exec)(std::move(j)); });

    // Prime the cache with tip A (dispatch the bg refresh, then run it).
    ws.get_current_work_template();   // dispatches; returns set-gap
    exec->run();                      // bg refresh sources tip A -> cache = A
    ASSERT_EQ(ws.get_current_work_template().value("previousblockhash", ""),
              std::string(kPrevHashHex));

    // The coin-P2P feed advances to tip B (a DIFFERENT masternode payee).
    *current = rotated_work();

    // The coin-P2P on_tip_changed handler fires: invalidate + bump (+ notify).
    ws.invalidate_template_cache("coin-P2P tip changed: fresh-payee re-source");
    ws.bump_work_generation();

    // Under refresh_executor_ the served job must NEVER be the stale tip-A
    // template: the invalidate dropped the cache -> honest set-gap until the bg
    // refresh lands tip B.
    auto served = ws.get_current_work_template();
    if (!served.empty())
        EXPECT_NE(served.value("previousblockhash", ""), std::string(kPrevHashHex))
            << "stale tip-A template must not be served after a coin-P2P tip event";
    exec->run();   // the deferred bg refresh completes
    auto fresh = ws.get_current_work_template();
    ASSERT_FALSE(fresh.empty());
    EXPECT_EQ(fresh.value("previousblockhash", ""), std::string(kRotatedPrevHashHex))
        << "the served job must carry the FRESH-tip (B) template/payee";
}

// CONTRAST (the window this fix closes): bump_work_generation() ALONE, under a
// refresh_executor_, serves the STALE cached tip-A template while refreshing
// async — the implicit-only path that reopens the stale-payee window.
TEST(DashStratumCoinP2pTipInvalidate, BumpAloneServesStaleUnderRefreshExecutor)
{
    auto current  = std::make_shared<dash::coin::DashWorkData>(rich_work());
    auto fallback = [current]() -> dash::coin::DashWorkData { return *current; };
    auto submit   = [](const std::vector<unsigned char>&, uint32_t) { return true; };
    dash::coin::NodeCoinState cs;

    dash::stratum::DASHWorkSource ws(cs, fallback, submit,
                                     core::stratum::StratumConfig{}, /*is_testnet=*/false);
    auto exec = std::make_shared<DeferredExecutor>();
    ws.set_refresh_executor([exec](std::function<void()> j) { (*exec)(std::move(j)); });

    ws.get_current_work_template();
    exec->run();
    ASSERT_EQ(ws.get_current_work_template().value("previousblockhash", ""),
              std::string(kPrevHashHex));

    *current = rotated_work();
    ws.bump_work_generation();   // NO invalidate — the pre-fix implicit path

    // Serves the STALE tip-A template (cache still held; async refresh not landed).
    auto served = ws.get_current_work_template();
    ASSERT_FALSE(served.empty());
    EXPECT_EQ(served.value("previousblockhash", ""), std::string(kPrevHashHex))
        << "bump-only under refresh_executor_ serves the STALE tip-A payee — the "
           "window invalidate_template_cache() closes";
}

}  // namespace
