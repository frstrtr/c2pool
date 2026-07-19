// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH run-loop mint KATs (mint campaign slice 3/3 — mint_runloop.hpp).
//
// Drives the FULL ShareAccept pipeline the --run wiring executes, KAT-style
// (no sockets, no io_context):
//   build_producer_job  -> coinb1/coinb2 split -> miner-side coinbase
//   reassembly (extranonce1||extranonce2 fills the nonce64 slot) -> stratum
//   merkle ascent -> 80-byte header -> REAL X11 solve (nonce search) ->
//   MintShareInputs (ref_hash recovered from the coinb1 tail, exactly as
//   mining_submit does) -> mint_from_inputs -> tracker insert -> get_shares
//   walk -> message_shares codec round-trip -> best-share election -> PPLNS
//   oracle-window pin.
//
// Coverage contract (task KATs):
//   (1) a ShareAccept mints a DashShare that PASSES the in-tree verifier
//       (build_share's mandatory self-verify) and whose m_hash IS the solved
//       header's X11 PoW;
//   (2) the minted share round-trips the message_shares payload codec
//       byte-identically;
//   (3) the minted share inserts into the tracker and appears in the
//       get_shares chain walk;
//   (4) best-share election picks the heaviest verified head (and refuses to
//       elect with peers-but-no-verified-chain);
//   (5) the PPLNS weights walk matches the ORACLE window (grandparent start,
//       data.py:181) — pinned against a hand-computed window;
//   (6) ban-safety: a solve whose PoW does not meet the share's own committed
//       target is DECLINED by mint_from_inputs (never minted / broadcast);
//   (7) the frozen-job registry declines unknown/evicted refs (fail-closed).

#include <gtest/gtest.h>

#include <impl/dash/mint_runloop.hpp>
#include <impl/dash/share_tracker.hpp>
#include <impl/dash/share_chain.hpp>
#include <impl/dash/share_check.hpp>       // pubkey_hash_to_script2
#include <impl/dash/params.hpp>
#include <impl/dash/crypto/hash_x11.hpp>
#include <impl/dash/coinbase_builder.hpp>  // merkle_branches_raw / sha256d
#include <impl/bitcoin_family/coin/base_block.hpp>

#include <core/coin_params.hpp>
#include <core/pack_types.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <cstring>
#include <optional>
#include <vector>

namespace {

using dash::mint::build_producer_job;
using dash::mint::mint_from_inputs;
using dash::mint::elect_best_share;
using dash::mint::pplns_weights_for;
using dash::mint::FrozenJobRegistry;
using MintShareInputs = dash::stratum::DASHWorkSource::MintShareInputs;

uint256 h256_tag(uint8_t tag)
{
    std::vector<unsigned char> v(32, 0x00);
    v[0] = tag; v[31] = 0x5a;
    return uint256(v);
}

uint160 h160_uniform(uint8_t tag)
{
    return uint160(std::vector<unsigned char>(20, tag));
}

// Easy-PoW params: identical to mainnet DASH params except max_target, so a
// nonce search finds a REAL X11 solve in a few thousand hashes. The retarget
// path (genesis: pre_target3 = max_target) then commits share bits derived
// from this target — the exact code path a fresh pool runs.
core::CoinParams easy_params()
{
    core::CoinParams p = dash::make_coin_params(false);
    p.max_target.SetHex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return p;
}

dash::coin::DashWorkData make_workdata(uint8_t prev_tag = 0x77)
{
    dash::coin::DashWorkData wd;
    wd.m_version        = 536870912;
    wd.m_previous_block = h256_tag(prev_tag);
    wd.m_height         = 1000;
    wd.m_coinbase_value = 500000000;         // 5 DASH
    wd.m_bits           = 0x1b00ffffu;       // block target (much harder than shares)
    wd.m_curtime        = 1700000005;
    return wd;
}

// One merkle ascent step (LE-internal bytes), same fold as the work source.
uint256 merkle_pair(const uint256& left, const uint256& right)
{
    unsigned char buf[64];
    std::memcpy(buf,      left.data(),  32);
    std::memcpy(buf + 32, right.data(), 32);
    return dash::coinbase::sha256d(std::span<const unsigned char>(buf, 64));
}

// The full miner+mining_submit side of the pipeline for one job build:
// reassemble the coinbase, ascend the branches, serialize the header, search
// a REAL X11 solve against the job's committed share target, and produce the
// MintShareInputs exactly as mining_submit does.
struct SolvedJob
{
    MintShareInputs in;
    dash::stratum::FrozenMintJob frozen;
    bool solved{false};
};

SolvedJob solve_job(dash::ShareTracker& tracker,
                    const core::CoinParams& params,
                    const uint256& prev_share_hash,
                    const uint160& miner_pkh,
                    const dash::coin::DashWorkData& wd,
                    uint32_t share_nonce,
                    uint16_t donation = 0)
{
    SolvedJob out;
    const auto payout_script = dash::pubkey_hash_to_script2(miner_pkh);

    auto built = build_producer_job(tracker.chain, params, prev_share_hash,
                                    payout_script, wd,
                                    /*desired_timestamp=*/wd.m_curtime,
                                    share_nonce, donation, "c2pool");
    if (!built)
        return out;
    out.frozen = built->frozen;
    const auto& job = built->job;

    // coinb1/coinb2 split around the zeroed nonce64 slot (work source path).
    std::vector<unsigned char> coinb1(job.gentx_bytes.begin(),
                                      job.gentx_bytes.begin() + job.nonce64_offset);
    std::vector<unsigned char> coinb2(job.gentx_bytes.begin() + job.nonce64_offset + 8,
                                      job.gentx_bytes.end());
    const std::vector<unsigned char> en1 = {0x01, 0x02, 0x03, 0x04};
    const std::vector<unsigned char> en2 = {0x05, 0x06, 0x07, 0x08};

    // Miner-side coinbase reassembly.
    std::vector<unsigned char> coinbase;
    coinbase.insert(coinbase.end(), coinb1.begin(), coinb1.end());
    coinbase.insert(coinbase.end(), en1.begin(), en1.end());
    coinbase.insert(coinbase.end(), en2.begin(), en2.end());
    coinbase.insert(coinbase.end(), coinb2.begin(), coinb2.end());

    // Stratum merkle ascent from the coinbase txid.
    std::vector<uint256> branches;
    if (!wd.m_tx_hashes.empty()) {
        std::vector<uint256> leaves;
        leaves.push_back(uint256::ZERO);
        leaves.insert(leaves.end(), wd.m_tx_hashes.begin(), wd.m_tx_hashes.end());
        branches = dash::coinbase::merkle_branches_raw(leaves);
    }
    uint256 merkle_root = dash::coinbase::sha256d(
        std::span<const unsigned char>(coinbase.data(), coinbase.size()));
    for (const auto& b : branches)
        merkle_root = merkle_pair(merkle_root, b);

    // 80-byte header + REAL X11 nonce search against the committed share target.
    const uint256 share_target = chain::bits_to_target(job.share_bits);
    bitcoin_family::coin::BlockHeaderType hdr;
    hdr.m_version        = wd.m_version;
    hdr.m_previous_block = wd.m_previous_block;
    hdr.m_merkle_root    = merkle_root;
    hdr.m_timestamp      = wd.m_curtime;
    hdr.m_bits           = wd.m_bits;

    uint256 pow_hash;
    std::vector<unsigned char> header_bytes;
    for (uint32_t nonce = 0; nonce < 2000000; ++nonce) {
        hdr.m_nonce = nonce;
        PackStream ps;
        ps << hdr;
        header_bytes.assign(
            reinterpret_cast<const unsigned char*>(ps.data()),
            reinterpret_cast<const unsigned char*>(ps.data()) + ps.size());
        pow_hash = dash::crypto::hash_x11(header_bytes.data(), header_bytes.size());
        if (pow_hash <= share_target) {
            out.solved = true;
            break;
        }
    }
    if (!out.solved)
        return out;

    // MintShareInputs exactly as mining_submit populates them.
    out.in.header_bytes    = header_bytes;
    out.in.coinbase_bytes  = coinbase;
    out.in.subsidy         = wd.m_coinbase_value;
    out.in.prev_share_hash = prev_share_hash;
    out.in.merkle_branches = branches;
    out.in.payout_script   = payout_script;
    out.in.pow_hash        = pow_hash;
    std::memcpy(out.in.ref_hash.begin(), coinb1.data() + coinb1.size() - 32, 32);
    uint64_t n64 = 0;
    {
        unsigned char cat[8];
        std::memcpy(cat, en1.data(), 4);
        std::memcpy(cat + 4, en2.data(), 4);
        for (int i = 7; i >= 0; --i) n64 = (n64 << 8) | cat[i];
    }
    out.in.last_txout_nonce = n64;
    return out;
}

// Mint one share onto the tracker (build + insert + verified.add), returning
// its hash. Fails the calling test on any decline.
uint256 mint_onto(dash::ShareTracker& tracker, const core::CoinParams& params,
                  const uint256& prev, const uint160& miner, uint32_t share_nonce,
                  uint8_t wd_prev_tag = 0x77)
{
    auto wd = make_workdata(wd_prev_tag);
    auto solved = solve_job(tracker, params, prev, miner, wd, share_nonce);
    EXPECT_TRUE(solved.solved);
    if (!solved.solved) return uint256();
    auto built = mint_from_inputs(tracker.chain, params, solved.in, solved.frozen);
    EXPECT_TRUE(built.has_value());
    if (!built) return uint256();
    const uint256 hash = built->share.m_hash;
    dash::ShareType st;
    st = new dash::DashShare(built->share);
    tracker.add(st);
    EXPECT_TRUE(tracker.chain.contains(hash));
    // Pre-populate verified (the load-path pattern) so election is exercised
    // independently of attempt_verify's depth heuristics.
    tracker.verified.add(tracker.chain.get_share(hash));
    return hash;
}

}  // namespace

// (1) The full ShareAccept pipeline mints a self-verified share whose m_hash
//     IS the solved header's X11 PoW, and (3) it lands in the tracker +
//     get_shares chain walk.
TEST(DashMintRunloop, ShareAcceptMintsVerifiedShareIntoTracker)
{
    const auto params = easy_params();
    dash::ShareTracker tracker;
    tracker.m_coin_params = params;

    auto wd = make_workdata();
    auto solved = solve_job(tracker, params, uint256(), h160_uniform(0x22), wd, 7);
    ASSERT_TRUE(solved.solved);

    // Register the frozen job the way the run-loop does, then look it up by
    // the ref recovered from the coinb1 tail — they must agree.
    FrozenJobRegistry registry;
    // (build_producer_job committed the ref into the gentx; the recovered
    //  in.ref_hash is the registry key.)
    registry.put(solved.in.ref_hash, solved.frozen);
    auto frozen = registry.get(solved.in.ref_hash);
    ASSERT_TRUE(frozen.has_value());

    auto built = mint_from_inputs(tracker.chain, params, solved.in, *frozen);
    ASSERT_TRUE(built.has_value());

    // The share hash IS the solved header PoW (X11 identity), and the share
    // passed build_share's MANDATORY in-tree self-verify to get here.
    EXPECT_EQ(built->share.m_hash, solved.in.pow_hash);
    EXPECT_EQ(built->ref_hash, solved.in.ref_hash);
    EXPECT_EQ(built->share.m_last_txout_nonce, solved.in.last_txout_nonce);
    EXPECT_EQ(built->share.m_bits != 0, true);
    // Committed target honored (the ban-safety gate passed for the right reason).
    EXPECT_TRUE(built->share.m_hash <= chain::bits_to_target(built->share.m_bits));

    // Tracker insert + the get_shares walk (handle_get_share's exact read).
    const uint256 hash = built->share.m_hash;
    dash::ShareType st;
    st = new dash::DashShare(built->share);
    tracker.add(st);
    ASSERT_TRUE(tracker.chain.contains(hash));
    int seen = 0;
    for (auto [h, data] : tracker.chain.get_chain(hash, 1)) {
        EXPECT_EQ(h, hash);
        EXPECT_EQ(data.share.hash(), hash);
        ++seen;
    }
    EXPECT_EQ(seen, 1);
}

// (2) The minted share round-trips the message_shares payload codec
//     (vector<chain::RawShare>) byte-identically.
TEST(DashMintRunloop, MintedShareWireRoundTripByteIdentical)
{
    const auto params = easy_params();
    dash::ShareTracker tracker;
    tracker.m_coin_params = params;

    auto wd = make_workdata();
    auto solved = solve_job(tracker, params, uint256(), h160_uniform(0x33), wd, 9);
    ASSERT_TRUE(solved.solved);
    auto built = mint_from_inputs(tracker.chain, params, solved.in, solved.frozen);
    ASSERT_TRUE(built.has_value());

    dash::ShareType st;
    st = new dash::DashShare(built->share);

    // Serialize exactly as send_shares does.
    PackStream contents = pack(st);
    std::vector<unsigned char> original(
        reinterpret_cast<const unsigned char*>(contents.data()),
        reinterpret_cast<const unsigned char*>(contents.data()) + contents.size());
    chain::RawShare rshare(st.version(), PackStream(original));

    // Wire envelope: the message_shares payload is vector<RawShare>.
    PackStream wire;
    std::vector<chain::RawShare> shares_out{rshare};
    wire << shares_out;

    std::vector<chain::RawShare> shares_in;
    wire >> shares_in;
    ASSERT_EQ(shares_in.size(), 1u);
    EXPECT_EQ(shares_in[0].type, 16u);

    // Parse back through the reception loader and re-serialize: byte-identical.
    auto reloaded = dash::load_share(shares_in[0], NetService{"kat", 0});
    PackStream contents2 = pack(reloaded);
    std::vector<unsigned char> reserialized(
        reinterpret_cast<const unsigned char*>(contents2.data()),
        reinterpret_cast<const unsigned char*>(contents2.data()) + contents2.size());
    EXPECT_EQ(original, reserialized);

    // And the reloaded share re-verifies to the SAME X11 share hash through
    // the in-tree verifier (the exact check a receiving peer runs).
    uint256 reverified;
    reloaded.invoke([&](auto* obj) {
        reverified = dash::share_init_verify(*obj, params, /*check_pow=*/false);
    });
    EXPECT_EQ(reverified, built->share.m_hash);
}

// (4) Best-share election: heaviest verified head wins; peers-but-no-verified
//     chain refuses (ZERO); genesis (no peers) bootstraps from the raw head.
TEST(DashMintRunloop, BestShareElectionPicksHeaviestVerifiedHead)
{
    const auto params = easy_params();
    dash::ShareTracker tracker;
    tracker.m_coin_params = params;

    // Empty tracker: nothing to elect.
    EXPECT_TRUE(elect_best_share(tracker, uint256(), false).IsNull());
    // With peers and no verified chain: REFUSE (never mint on unverified).
    EXPECT_EQ(elect_best_share(tracker, uint256(), true), uint256::ZERO);

    // Fork A: two chained shares. Fork B: one share (different miner/nonce).
    const uint256 a1 = mint_onto(tracker, params, uint256(),      h160_uniform(0x11), 1);
    ASSERT_FALSE(a1.IsNull());
    const uint256 a2 = mint_onto(tracker, params, a1,             h160_uniform(0x11), 2);
    ASSERT_FALSE(a2.IsNull());
    const uint256 b1 = mint_onto(tracker, params, uint256(),      h160_uniform(0x44), 3);
    ASSERT_FALSE(b1.IsNull());
    ASSERT_NE(a1, b1);

    // Heaviest verified head = A2 (two shares of accumulated work vs one).
    EXPECT_EQ(elect_best_share(tracker, uint256(), true), a2);
    // A think-elected best that IS on the verified chain is authoritative.
    EXPECT_EQ(elect_best_share(tracker, b1, true), b1);
    // A think-elected best NOT on the verified chain falls back to heaviest.
    EXPECT_EQ(elect_best_share(tracker, h256_tag(0xEE), true), a2);
}

// (5) PPLNS weights walk — ORACLE window pin: the walk starts at the
//     GRANDPARENT of the share being built (data.py:181), so the direct
//     parent's own weight is EXCLUDED and earlier shares' included.
TEST(DashMintRunloop, PplnsWeightsMatchOracleWindow)
{
    const auto params = easy_params();
    dash::ShareTracker tracker;
    tracker.m_coin_params = params;

    // Chain: g1 (miner A) <- g2 (miner B) <- g3 (miner C: the tip we build on).
    const uint160 miner_a = h160_uniform(0xa1);
    const uint160 miner_b = h160_uniform(0xb2);
    const uint160 miner_c = h160_uniform(0xc3);
    const uint256 g1 = mint_onto(tracker, params, uint256(), miner_a, 11);
    ASSERT_FALSE(g1.IsNull());
    const uint256 g2 = mint_onto(tracker, params, g1, miner_b, 12);
    ASSERT_FALSE(g2.IsNull());
    const uint256 g3 = mint_onto(tracker, params, g2, miner_c, 13);
    ASSERT_FALSE(g3.IsNull());

    uint32_t block_bits = 0;
    tracker.chain.get_share(g3).invoke([&](auto* obj) {
        block_bits = obj->m_min_header.m_bits;
    });
    auto w = pplns_weights_for(tracker.chain, params, g3, block_bits);
    ASSERT_TRUE(w.has_value());

    // Oracle window: start at g3's GRANDPARENT (g2's parent walk start = g2's
    // prev == g1's child... i.e. prev(g3)=g2 -> grandparent walk starts at g2's
    // prev = g1? NO — grandparent of the share BEING BUILT (child of g3) is g2.
    // pplns_weights_for(prev=g3) starts the walk at g3's prev_hash = g2, per
    // data.py:181 (previous_share.previous_share_hash with previous_share=g3).
    const auto script_a = dash::pubkey_hash_to_script2(miner_a);
    const auto script_b = dash::pubkey_hash_to_script2(miner_b);
    const auto script_c = dash::pubkey_hash_to_script2(miner_c);

    // g3 (the tip itself) is EXCLUDED — its miner has no weight yet.
    EXPECT_EQ(w->weights.count(script_c), 0u);
    // g2 and g1 are in the window.
    ASSERT_EQ(w->weights.count(script_b), 1u);
    ASSERT_EQ(w->weights.count(script_a), 1u);

    // Hand-computed pin (donation 0): weight(share) = ata(target(bits))*65535,
    // total = sum. All three shares carry the same bits here (same retarget
    // inputs), so A and B carry EQUAL weight and total = 2 * each.
    EXPECT_EQ(w->weights[script_a], w->weights[script_b]);
    EXPECT_EQ(w->total_weight, w->weights[script_a] + w->weights[script_b]);
    EXPECT_GT(w->total_weight, 0u);
    // Fallback-path contract: no producer commitment.
    EXPECT_TRUE(w->ref_hash.IsNull());
}

// (6) Ban-safety: a structurally-consistent solve whose PoW does NOT meet the
//     share's own committed target is DECLINED (this is what keeps a stratum
//     share-bits race from minting a peer-bannable share).
TEST(DashMintRunloop, DeclinesSolveBelowCommittedTarget)
{
    // REAL mainnet params: the committed share target is astronomically hard,
    // so an arbitrary-nonce header cannot meet it — but the byte identity
    // still holds, isolating the decline to the pow<=target gate.
    const core::CoinParams params = dash::make_coin_params(false);
    dash::ShareTracker tracker;
    tracker.m_coin_params = params;

    auto wd = make_workdata();
    const uint160 miner = h160_uniform(0x55);
    const auto payout_script = dash::pubkey_hash_to_script2(miner);
    auto built_job = build_producer_job(tracker.chain, params, uint256(),
                                        payout_script, wd, wd.m_curtime,
                                        21, 0, "c2pool");
    ASSERT_TRUE(built_job.has_value());
    const auto& job = built_job->job;

    std::vector<unsigned char> coinb1(job.gentx_bytes.begin(),
                                      job.gentx_bytes.begin() + job.nonce64_offset);
    std::vector<unsigned char> coinb2(job.gentx_bytes.begin() + job.nonce64_offset + 8,
                                      job.gentx_bytes.end());
    std::vector<unsigned char> coinbase;
    coinbase.insert(coinbase.end(), coinb1.begin(), coinb1.end());
    for (unsigned char c : {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
        coinbase.push_back(c);
    coinbase.insert(coinbase.end(), coinb2.begin(), coinb2.end());

    bitcoin_family::coin::BlockHeaderType hdr;
    hdr.m_version        = wd.m_version;
    hdr.m_previous_block = wd.m_previous_block;
    hdr.m_merkle_root    = dash::coinbase::sha256d(
        std::span<const unsigned char>(coinbase.data(), coinbase.size()));
    hdr.m_timestamp      = wd.m_curtime;
    hdr.m_bits           = wd.m_bits;
    hdr.m_nonce          = 0x12345678u;   // arbitrary — will not meet the target

    PackStream ps;
    ps << hdr;

    MintShareInputs in;
    in.header_bytes.assign(
        reinterpret_cast<const unsigned char*>(ps.data()),
        reinterpret_cast<const unsigned char*>(ps.data()) + ps.size());
    in.coinbase_bytes  = coinbase;
    in.subsidy         = wd.m_coinbase_value;
    in.prev_share_hash = uint256();
    in.payout_script   = payout_script;
    in.pow_hash        = dash::crypto::hash_x11(in.header_bytes.data(),
                                                in.header_bytes.size());
    std::memcpy(in.ref_hash.begin(), coinb1.data() + coinb1.size() - 32, 32);
    in.last_txout_nonce = 0x0807060504030201ull;

    // Structural identity holds (the exact bytes were rebuilt), so the ONLY
    // discriminator left is the pow<=target ban-safety gate — it must decline.
    const uint256 committed_target = chain::bits_to_target(job.share_bits);
    ASSERT_TRUE(in.pow_hash > committed_target);   // astronomically certain
    EXPECT_FALSE(mint_from_inputs(tracker.chain, params, in, built_job->frozen)
                     .has_value());
}

// (7) Frozen-job registry: fail-closed on unknown refs, FIFO-bounded.
TEST(DashMintRunloop, FrozenJobRegistryFailClosedAndBounded)
{
    FrozenJobRegistry registry(/*capacity=*/4);
    EXPECT_FALSE(registry.get(h256_tag(0x01)).has_value());

    for (uint8_t i = 1; i <= 6; ++i) {
        dash::stratum::FrozenMintJob job;
        job.share_nonce = i;
        registry.put(h256_tag(i), job);
    }
    EXPECT_EQ(registry.size(), 4u);
    // Oldest two evicted; newest four present.
    EXPECT_FALSE(registry.get(h256_tag(1)).has_value());
    EXPECT_FALSE(registry.get(h256_tag(2)).has_value());
    for (uint8_t i = 3; i <= 6; ++i) {
        auto j = registry.get(h256_tag(i));
        ASSERT_TRUE(j.has_value());
        EXPECT_EQ(j->share_nonce, i);
    }
}

// (8) --give-author mapping: donation percentage -> the oracle u16 field
//     (math.perfect_round(65535*pct/100)).
TEST(DashMintRunloop, DonationPercentToU16Mapping)
{
    using dash::mint::donation_percent_to_u16;
    EXPECT_EQ(donation_percent_to_u16(0.0), 0);
    EXPECT_EQ(donation_percent_to_u16(0.1), 66);     // README default 0.1%
    EXPECT_EQ(donation_percent_to_u16(0.5), 328);    // p2pool default 0.5%
    EXPECT_EQ(donation_percent_to_u16(2.5), 1638);
    EXPECT_EQ(donation_percent_to_u16(100.0), 65535);
    EXPECT_EQ(donation_percent_to_u16(250.0), 65535);  // clamped
    EXPECT_EQ(donation_percent_to_u16(-3.0), 0);       // clamped
}

// (9) --fee / --node-owner-address / --redistribute identity resolution
//     (deterministic core; the run-loop supplies the roll).
TEST(DashMintRunloop, ResolveMintIdentityFeeAndRedistribute)
{
    using dash::mint::MintFeePolicy;
    using dash::mint::resolve_mint_identity;

    const auto miner_script = dash::pubkey_hash_to_script2(h160_uniform(0x22));
    const auto owner_script = dash::pubkey_hash_to_script2(h160_uniform(0x99));
    const std::vector<unsigned char> broken_script = {0x00, 0x14};  // not P2PKH

    MintFeePolicy p;
    p.donation_u16 = 66;
    p.node_owner_fee_pct = 1.0;          // --fee 1
    p.node_owner_script = owner_script;

    // roll < fee*100 -> substituted to the owner; donation unchanged.
    auto sub = resolve_mint_identity(p, miner_script, /*roll_x100=*/99);
    ASSERT_TRUE(sub.has_value());
    EXPECT_TRUE(sub->substituted);
    EXPECT_EQ(sub->payout_script, owner_script);
    EXPECT_EQ(sub->donation_u16, 66);
    // roll >= fee*100 -> the miner keeps the share.
    auto keep = resolve_mint_identity(p, miner_script, /*roll_x100=*/100);
    ASSERT_TRUE(keep.has_value());
    EXPECT_FALSE(keep->substituted);
    EXPECT_EQ(keep->payout_script, miner_script);

    // --fee 0: never substituted regardless of roll.
    MintFeePolicy p0 = p;
    p0.node_owner_fee_pct = 0.0;
    auto never = resolve_mint_identity(p0, miner_script, 0);
    ASSERT_TRUE(never.has_value());
    EXPECT_FALSE(never->substituted);

    // Broken credentials: redistribute policy decides.
    p.redistribute = MintFeePolicy::Redistribute::FEE;
    auto rfee = resolve_mint_identity(p, broken_script, 5000);
    ASSERT_TRUE(rfee.has_value());
    EXPECT_EQ(rfee->payout_script, owner_script);
    EXPECT_EQ(rfee->donation_u16, 66);

    p.redistribute = MintFeePolicy::Redistribute::DONATE;
    auto rdon = resolve_mint_identity(p, broken_script, 5000);
    ASSERT_TRUE(rdon.has_value());
    EXPECT_EQ(rdon->payout_script, owner_script);
    EXPECT_EQ(rdon->donation_u16, 65535);   // 100% weight decays to donation

    p.redistribute = MintFeePolicy::Redistribute::PPLNS;
    EXPECT_FALSE(resolve_mint_identity(p, broken_script, 5000).has_value());

    // fee/donate without a usable owner address: fail-closed.
    MintFeePolicy no_owner = p;
    no_owner.node_owner_script.clear();
    no_owner.redistribute = MintFeePolicy::Redistribute::FEE;
    EXPECT_FALSE(resolve_mint_identity(no_owner, broken_script, 0).has_value());
}

// (10) Combined-split pin: --fee 1 --give-author 0 with the fee roll hitting.
//      The minted share carries the NODE OWNER identity (1%-of-shares fee
//      channel), donation field 0 (0% dev), and the coinbase STILL emits the
//      donation output (the always-present dust-marker semantic). Also the
//      override regression: the submit's username script is the MINER's, yet
//      the mint succeeds because FrozenMintJob.payout_script_override pins
//      the substituted identity.
TEST(DashMintRunloop, CombinedFeeSplitOwnerSubstitutionWithZeroDevFee)
{
    const auto params = easy_params();
    dash::ShareTracker tracker;
    tracker.m_coin_params = params;

    const uint160 miner_pkh = h160_uniform(0x22);
    const uint160 owner_pkh = h160_uniform(0x99);
    const auto miner_script = dash::pubkey_hash_to_script2(miner_pkh);

    dash::mint::MintFeePolicy policy;
    policy.donation_u16 = dash::mint::donation_percent_to_u16(0.0);  // --give-author 0
    policy.node_owner_fee_pct = 1.0;                                 // --fee 1
    policy.node_owner_script = dash::pubkey_hash_to_script2(owner_pkh);

    // Fee roll hits (roll 0 < 100): the job is built under the OWNER identity.
    auto identity = dash::mint::resolve_mint_identity(policy, miner_script, 0);
    ASSERT_TRUE(identity.has_value());
    ASSERT_TRUE(identity->substituted);
    EXPECT_EQ(identity->donation_u16, 0);

    auto wd = make_workdata();
    auto solved = solve_job(tracker, params, uint256(), owner_pkh, wd, 31,
                            identity->donation_u16);
    ASSERT_TRUE(solved.solved);

    // mining_submit hands the MINER's username script; the frozen override
    // must carry the substitution through the rebuild.
    solved.in.payout_script = miner_script;
    ASSERT_EQ(solved.frozen.payout_script_override,
              dash::pubkey_hash_to_script2(owner_pkh));

    auto built = mint_from_inputs(tracker.chain, params, solved.in, solved.frozen);
    ASSERT_TRUE(built.has_value());
    EXPECT_EQ(built->share.m_pubkey_hash, owner_pkh);   // 1% owner fee channel
    EXPECT_EQ(built->share.m_donation, 0);              // 0% dev fee

    // Donation output PRESENT even at --give-author 0 (dust marker): the
    // DONATION_SCRIPT bytes appear as an output of the solved coinbase.
    const std::vector<unsigned char> donation_script(
        dash::DONATION_SCRIPT.begin(), dash::DONATION_SCRIPT.end());
    auto itd = std::search(solved.in.coinbase_bytes.begin(),
                           solved.in.coinbase_bytes.end(),
                           donation_script.begin(), donation_script.end());
    EXPECT_NE(itd, solved.in.coinbase_bytes.end());
}

// (11) --give-author decays the share's PPLNS weight toward the donation
//      script by the oracle formula: weight = att*(65535-donation).
TEST(DashMintRunloop, DonationFieldDecaysPplnsWeight)
{
    const auto params = easy_params();
    dash::ShareTracker tracker;
    tracker.m_coin_params = params;

    const uint160 miner = h160_uniform(0x37);
    const uint16_t donation = 1638;   // --give-author 2.5
    auto wd = make_workdata();
    auto solved = solve_job(tracker, params, uint256(), miner, wd, 41, donation);
    ASSERT_TRUE(solved.solved);
    auto built = mint_from_inputs(tracker.chain, params, solved.in, solved.frozen);
    ASSERT_TRUE(built.has_value());
    EXPECT_EQ(built->share.m_donation, donation);

    dash::ShareType st;
    st = new dash::DashShare(built->share);
    tracker.add(st);

    const uint288 att = chain::target_to_average_attempts(
        chain::bits_to_target(built->share.m_bits));
    uint288 big;
    big.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    auto w = dash::producer::get_cumulative_weights(
        tracker.chain, built->share.m_hash, 1, big);
    const auto script = dash::pubkey_hash_to_script2(miner);
    ASSERT_EQ(w.weights.count(script), 1u);
    EXPECT_EQ(w.weights[script], att * static_cast<uint32_t>(65535 - donation));
    EXPECT_EQ(w.donation_weight, att * static_cast<uint32_t>(donation));
    EXPECT_EQ(w.total_weight, att * 65535u);
}
