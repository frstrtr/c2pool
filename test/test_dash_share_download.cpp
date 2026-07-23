// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH share-download leg KATs (#754 — the outbound sharereq/backfill slice).
//
// The download leg is what lets an EMPTY c2pool-dash node JOIN an established
// p2pool-dash sharechain: think() computes the `desired` missing-parent set,
// download_shares (node.cpp) dispatches a sharereq via the ReplyMatcher, the
// sharereply's shares ride the SAME reception pipeline live pushes use, and
// the downloaded ancestors ROOT the previously-unverifiable pushed shares.
//
// Rig-free coverage (no sockets, no io_context — the link-deferred KAT
// pattern; the shared planning/gating logic lives in pool/share_download.hpp
// exactly so this KAT drives the code the node runs):
//   (1) sharereq WIRE BYTE-PARITY: the message payload matches the python
//       p2pool oracle layout (p2p.py 'sharereq' ComposedType: 32B LE id,
//       CompactSize-prefixed hash list, VarInt parents, CompactSize-prefixed
//       stops list) — a malformed request gets the node BANNED, so the bytes
//       are pinned by hand, not by round-trip alone.
//   (2) DownloadGate: in-flight de-dup, empty-reply retry cap, per-think-cycle
//       reset (p2pool re-adds desired from scratch each cycle).
//   (3) build_stops: heads + capped nth-parents from a real minted chain.
//   (4) THE DOWNLOAD GATE PROOF: a live-pushed share with missing ancestors
//       stays UNROOTED (verified=0); a mocked sharereply carrying the
//       ancestors (RawShare wire round-trip, child→parent order exactly as
//       handle_get_share serves them) is inserted through load_share +
//       tracker.add + attempt_verify — verified climbs 0→N and the previously
//       unrooted tip ROOTS. oldest_parent() drives the continuation until the
//       genesis share (prev=ZERO) ends the backfill.

#include <gtest/gtest.h>

#include <impl/dash/mint_runloop.hpp>
#include <impl/dash/share_tracker.hpp>
#include <impl/dash/share_chain.hpp>
#include <impl/dash/share_check.hpp>       // pubkey_hash_to_script2
#include <impl/dash/params.hpp>
#include <impl/dash/messages.hpp>
#include <impl/dash/crypto/hash_x11.hpp>
#include <impl/dash/coinbase_builder.hpp>  // merkle_branches_raw / sha256d
#include <impl/bitcoin_family/coin/base_block.hpp>

#include <pool/share_download.hpp>

#include <core/coin_params.hpp>
#include <core/pack_types.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <cstring>
#include <vector>

namespace {

using dash::mint::build_producer_job;
using dash::mint::mint_from_inputs;
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

// Easy-PoW params (mint-runloop KAT pattern): mainnet DASH params except
// max_target, so the nonce search solves in a few thousand X11 hashes.
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
    wd.m_coinbase_value = 500000000;
    wd.m_bits           = 0x1b00ffffu;
    wd.m_curtime        = 1700000005;
    return wd;
}

// Full miner-side solve of one producer job (trimmed copy of the
// test_dash_mint_runloop.cpp scaffold — same target, separate TU).
struct SolvedShare
{
    dash::ShareType share;
    uint256 hash;
    bool ok{false};
};

SolvedShare solve_share(dash::ShareChain& chain, const core::CoinParams& params,
                        const uint256& prev, const uint160& miner_pkh,
                        uint32_t share_nonce)
{
    SolvedShare out;
    const auto payout_script = dash::pubkey_hash_to_script2(miner_pkh);
    const auto wd = make_workdata();

    auto built = build_producer_job(chain, params, prev, payout_script, wd,
                                    /*desired_timestamp=*/wd.m_curtime,
                                    share_nonce, /*donation=*/0, "c2pool");
    if (!built)
        return out;
    const auto& job = built->job;

    std::vector<unsigned char> coinb1(job.gentx_bytes.begin(),
                                      job.gentx_bytes.begin() + job.nonce64_offset);
    std::vector<unsigned char> coinb2(job.gentx_bytes.begin() + job.nonce64_offset + 8,
                                      job.gentx_bytes.end());
    const std::vector<unsigned char> en1 = {0x01, 0x02, 0x03, 0x04};
    const std::vector<unsigned char> en2 = {0x05, 0x06, 0x07, 0x08};

    std::vector<unsigned char> coinbase;
    coinbase.insert(coinbase.end(), coinb1.begin(), coinb1.end());
    coinbase.insert(coinbase.end(), en1.begin(), en1.end());
    coinbase.insert(coinbase.end(), en2.begin(), en2.end());
    coinbase.insert(coinbase.end(), coinb2.begin(), coinb2.end());

    uint256 merkle_root = dash::coinbase::sha256d(
        std::span<const unsigned char>(coinbase.data(), coinbase.size()));

    const uint256 share_target = chain::bits_to_target(job.share_bits);
    bitcoin_family::coin::BlockHeaderType hdr;
    hdr.m_version        = wd.m_version;
    hdr.m_previous_block = wd.m_previous_block;
    hdr.m_merkle_root    = merkle_root;
    hdr.m_timestamp      = wd.m_curtime;
    hdr.m_bits           = wd.m_bits;

    uint256 pow_hash;
    std::vector<unsigned char> header_bytes;
    bool solved = false;
    for (uint32_t nonce = 0; nonce < 2000000; ++nonce) {
        hdr.m_nonce = nonce;
        PackStream ps;
        ps << hdr;
        header_bytes.assign(
            reinterpret_cast<const unsigned char*>(ps.data()),
            reinterpret_cast<const unsigned char*>(ps.data()) + ps.size());
        pow_hash = dash::crypto::hash_x11(header_bytes.data(), header_bytes.size());
        if (pow_hash <= share_target) { solved = true; break; }
    }
    if (!solved)
        return out;

    MintShareInputs in;
    in.header_bytes    = header_bytes;
    in.coinbase_bytes  = coinbase;
    in.subsidy         = wd.m_coinbase_value;
    in.prev_share_hash = prev;
    in.merkle_branches = {};
    in.payout_script   = payout_script;
    in.pow_hash        = pow_hash;
    std::memcpy(in.ref_hash.begin(), coinb1.data() + coinb1.size() - 32, 32);
    uint64_t n64 = 0;
    {
        unsigned char cat[8];
        std::memcpy(cat, en1.data(), 4);
        std::memcpy(cat + 4, en2.data(), 4);
        for (int i = 7; i >= 0; --i) n64 = (n64 << 8) | cat[i];
    }
    in.last_txout_nonce = n64;

    auto minted = mint_from_inputs(chain, params, in, built->frozen);
    if (!minted)
        return out;
    out.hash  = minted->share.m_hash;
    out.share = new dash::DashShare(minted->share);
    out.ok    = true;
    return out;
}

// Wire round-trip: pack the share into the RawShare form a sharereply
// carries, then load it back exactly as HANDLER(sharereply) does.
chain::RawShare to_raw(dash::ShareType& share)
{
    return chain::RawShare(share.version(), pack(share));
}

void append_u256(std::vector<unsigned char>& out, const uint256& v)
{
    out.insert(out.end(), v.data(), v.data() + 32);
}

}  // namespace

// (1) sharereq wire byte-parity vs the python oracle layout (p2p.py
//     'sharereq': IntType(256) id, ListType(IntType(256)) hashes,
//     VarIntType() parents, ListType(IntType(256)) stops). IntType(256) is
//     32 raw LE bytes; ListType/VarIntType are bitcoin CompactSize. A
//     divergent request (wrong field order, fixed-width parents, missing
//     prefix) would get c2pool disconnected/banned by every oracle peer.
TEST(DashShareDownload, ShareReqWireBytesOracleParity)
{
    const uint256 id = h256_tag(0xA1);
    const uint256 h1 = h256_tag(0xB2);
    const uint256 h2 = h256_tag(0xC3);
    const uint256 s1 = h256_tag(0xD4);
    const uint64_t parents = 37;

    auto rmsg = dash::message_sharereq::make_raw(id, {h1, h2}, parents, {s1});
    ASSERT_EQ(rmsg->m_command, "sharereq");

    std::vector<unsigned char> expected;
    append_u256(expected, id);          // id: 32 raw LE bytes
    expected.push_back(0x02);           // hashes: CompactSize(2)
    append_u256(expected, h1);
    append_u256(expected, h2);
    expected.push_back(0x25);           // parents: VarInt/CompactSize(37)
    expected.push_back(0x01);           // stops: CompactSize(1)
    append_u256(expected, s1);

    const auto* raw = reinterpret_cast<const unsigned char*>(rmsg->m_data.data());
    std::vector<unsigned char> got(raw, raw + rmsg->m_data.size());
    EXPECT_EQ(got, expected);

    // And the parse side (what the oracle's reply/serve path exercises).
    auto parsed = dash::message_sharereq::make(rmsg->m_data);
    EXPECT_EQ(parsed->m_id, id);
    ASSERT_EQ(parsed->m_hashes.size(), 2u);
    EXPECT_EQ(parsed->m_hashes[0], h1);
    EXPECT_EQ(parsed->m_hashes[1], h2);
    EXPECT_EQ(parsed->m_parents, parents);
    ASSERT_EQ(parsed->m_stops.size(), 1u);
    EXPECT_EQ(parsed->m_stops[0], s1);
}

// (2) DownloadGate: de-dup while in flight, empty-reply cap, cycle reset.
TEST(DashShareDownload, DownloadGateDedupRetryCapAndCycleReset)
{
    pool::download::DownloadGate gate;
    const uint256 h = h256_tag(0x11);

    EXPECT_TRUE(gate.try_begin(h));    // first request goes out
    EXPECT_FALSE(gate.try_begin(h));   // in flight — de-duped

    // Empty replies release the hash but count failures.
    for (int i = 1; i <= pool::download::MAX_EMPTY_RETRIES; ++i) {
        EXPECT_EQ(gate.on_empty(h), i);
        if (i < pool::download::MAX_EMPTY_RETRIES)
            EXPECT_TRUE(gate.try_begin(h));   // retried below the cap
    }
    EXPECT_FALSE(gate.try_begin(h));   // failed out this cycle

    // think()-cycle reset: p2pool re-adds desired from scratch each cycle.
    gate.new_cycle();
    EXPECT_TRUE(gate.try_begin(h));

    // A success clears the failure history.
    gate.on_empty(h);
    EXPECT_TRUE(gate.try_begin(h));
    gate.on_success(h);
    EXPECT_TRUE(gate.fail_count.empty());
    EXPECT_TRUE(gate.in_flight.empty());
}

// (3)+(4) THE DOWNLOAD GATE PROOF on real minted shares.
TEST(DashShareDownload, MockedShareReplyRootsUnrootedLiveShares)
{
    const auto params = easy_params();

    // "Peer" side: an established chain g <- m <- t (genesis, middle, tip).
    dash::ShareTracker peer_tracker;
    peer_tracker.m_coin_params = params;
    auto g = solve_share(peer_tracker.chain, params, uint256(), h160_uniform(0x21), 1);
    ASSERT_TRUE(g.ok);
    peer_tracker.add(g.share);
    auto m = solve_share(peer_tracker.chain, params, g.hash, h160_uniform(0x21), 2);
    ASSERT_TRUE(m.ok);
    peer_tracker.add(m.share);
    auto t = solve_share(peer_tracker.chain, params, m.hash, h160_uniform(0x21), 3);
    ASSERT_TRUE(t.ok);
    peer_tracker.add(t.share);

    // Empty joining node receives the TIP via live push — parents missing.
    dash::ShareTracker node;
    node.m_coin_params = params;
    {
        auto raw = to_raw(t.share);
        auto pushed = dash::load_share(raw, NetService{"kat", 0});
        pushed.ACTION({
            obj->m_hash = dash::share_init_verify(*obj, node.m_coin_params, true);
        });
        ASSERT_EQ(pushed.hash(), t.hash);
        node.add(pushed);
    }
    // Unrooted: attempt_verify must NOT verify it (its ancestry is unknown),
    // and must not throw — this is the #754 pre-download steady state.
    EXPECT_FALSE(node.attempt_verify(t.hash));
    EXPECT_EQ(node.verified.size(), 0u);

    // think()'s desired set would name the missing parent; the download leg
    // requests it. Mock the ORACLE's sharereply: handle_get_share serves the
    // chain child→parent, so the reply for hashes=[m.hash] with parents is
    // [m, g] (RawShare wire form — byte round-trip like the real handler).
    std::vector<dash::ShareType> reply_items;
    for (auto* s : {&m, &g}) {
        auto raw = to_raw(s->share);
        auto loaded = dash::load_share(raw, NetService{"kat", 0});
        loaded.ACTION({
            obj->m_hash = dash::share_init_verify(*obj, node.m_coin_params, true);
        });
        reply_items.push_back(loaded);
    }
    ASSERT_EQ(reply_items[0].hash(), m.hash);
    ASSERT_EQ(reply_items[1].hash(), g.hash);

    // Backfill continuation rule: the oldest received share is the genesis
    // (prev=ZERO) → oldest_parent ends the pull.
    EXPECT_EQ(pool::download::oldest_parent(reply_items), uint256::ZERO);

    // Insert through the same seam the node's reception path uses
    // (tracker.add), then verify as think()'s bootstrap pass does.
    for (auto& s : reply_items)
        node.add(s);
    EXPECT_TRUE(node.attempt_verify(g.hash));
    EXPECT_TRUE(node.attempt_verify(m.hash));
    // THE POINT: the previously-unrooted live-pushed tip now verifies.
    EXPECT_TRUE(node.attempt_verify(t.hash));
    EXPECT_EQ(node.verified.size(), 3u);
    EXPECT_TRUE(node.verified.contains(t.hash));

    // (3) build_stops over the joined chain: contains the head, capped size.
    auto stops = pool::download::build_stops(node.chain);
    ASSERT_FALSE(stops.empty());
    EXPECT_LE(stops.size(), pool::download::STOPS_CAP);
    bool head_in_stops = false;
    for (const auto& s : stops) head_in_stops |= (s == t.hash);
    EXPECT_TRUE(head_in_stops);
}

// oldest_parent: mid-chain reply continues from the deepest received share's
// parent (the next sharereq target), empty batch returns ZERO.
TEST(DashShareDownload, OldestParentContinuationTarget)
{
    const auto params = easy_params();
    dash::ShareTracker tr;
    tr.m_coin_params = params;
    auto a = solve_share(tr.chain, params, uint256(), h160_uniform(0x31), 7);
    ASSERT_TRUE(a.ok);
    tr.add(a.share);
    auto b = solve_share(tr.chain, params, a.hash, h160_uniform(0x31), 8);
    ASSERT_TRUE(b.ok);
    tr.add(b.share);
    auto c = solve_share(tr.chain, params, b.hash, h160_uniform(0x31), 9);
    ASSERT_TRUE(c.ok);

    // Reply chunk [c, b] (child→parent): continuation target is b's parent a.
    std::vector<dash::ShareType> chunk = {c.share, b.share};
    EXPECT_EQ(pool::download::oldest_parent(chunk), a.hash);

    std::vector<dash::ShareType> empty;
    EXPECT_TRUE(pool::download::oldest_parent(empty).IsNull());
}
