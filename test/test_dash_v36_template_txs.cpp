// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH v36 network KATs: v36 shares commit the work template's transactions.
//
// A v36 share carries no tx refs; it commits the template's tx set through the
// coinbase merkle_link (the branch from the coinbase, index 0, to the header
// merkle root over the template's full tx list). Peers verify the PoW from the
// gentx hash + that link alone (share_init_verify(DashV36Share),
// share_check.hpp), and only the finder -- which holds the tx bodies it served
// -- can assemble the won block.
//
// What is pinned here (every call is on the base API, so these run red on the
// revision that declined tx-carrying v36 jobs and rebuilt every v36 won block
// as [gentx] alone):
//   A. A v36 share minted over a 3-tx template: its merkle_link is the index-0
//      branch over the template tx list, it folds the gentx hash to the header
//      merkle root the miner solved, and a second node verifies the share from
//      its wire bytes with no tx body ever reaching it.
//   B. A node that is not the finder (no frozen template bodies) refuses to
//      rebuild a tx-committing v36 won block -- never an incomplete block; a
//      coinbase-only v36 share still rebuilds as [gentx].
//   C. Every producer job over one template shares ONE frozen body vector
//      (the frozen-job registry holds up to 512 jobs; a per-job copy of the
//      template hex would pin 512 copies), a different template gets its own,
//      a coinbase-only job freezes none, and the memo never keeps bodies alive
//      past the last job that references them.
//
// The finder's block assembly (FinderBodiesLookup) and the frozen template
// bodies are pinned in test_dash_v36_finder_block.cpp. Folded into
// test_dash_node (the same harness and link set as test_dash_v36_flip.cpp).

#include <gtest/gtest.h>

#include "dash_v36_live_fixture.hpp"   // IdentityGuard, DataDirGuard, LiveNode, mine_v36, ...
#include "dash_v36_mint_fixture.hpp"   // iso_prod_params, make_wd_with_txs, solve_job, ...

#include <impl/dash/coin/reconstruct_won_block.hpp>
#include <impl/dash/mint_runloop.hpp>
#include <impl/dash/share_producer.hpp>

#include <memory>
#include <string>
#include <vector>

namespace {

// The 32 merkle-root bytes of an 80-byte serialized header.
uint256 header_merkle_root(const Bytes& header80) {
    return uint256(Bytes(header80.begin() + 36, header80.begin() + 68));
}

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// A. The minted v36 share commits the template's txs; a peer verifies it
//    without any tx body
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36TemplateTxs, MintedShareCommitsCoinbaseMerkleLinkAndPeerVerifiesWithoutBodies)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_v36_template_txs");
    const auto p = iso_prod_params();
    ASSERT_EQ(p.current_share_version, 36u);
    const std::string sub = SharechainConfig::data_subdir(false);
    const auto wd = make_wd_with_txs(3);
    const uint160 miner_a = h160(0xa3), miner_b = h160(0xb4);
    const auto expected_link =
        dash::producer::calculate_merkle_link_index0<dash::v36::MerkleLink>(wd.m_tx_hashes);
    ASSERT_EQ(expected_link.m_branch.size(), 2u) << "4 leaves (coinbase + 3 txs): 2 branches";

    // ── genesis over the tx template ──
    dash::ShareChain scratch;
    const auto j1 = solve_job(scratch, p, uint256(), miner_a, wd, 7, wd.m_curtime);
    ASSERT_TRUE(j1.built) << "the DASH v36 network serves a producer job over a tx template";
    ASSERT_TRUE(j1.solved);
    EXPECT_EQ(j1.in.merkle_branches.size(), 2u);
    const auto m1 = mint_from_inputs_any(scratch, p, j1.in, j1.build.frozen);
    ASSERT_TRUE(m1.has_value()) << "the mint-time rebuild reproduces the solved header";
    ASSERT_TRUE(m1->is_v36());
    const auto& g = v36_of(*m1);

    // ── a child over the same tx template ──
    scratch.add(new dash::DashV36Share(g.share));
    const auto j2 = solve_job(scratch, p, g.share.m_hash, miner_b, wd, 8, wd.m_curtime + 20);
    ASSERT_TRUE(j2.built);
    ASSERT_TRUE(j2.solved);
    const auto m2 = mint_from_inputs_any(scratch, p, j2.in, j2.build.frozen);
    ASSERT_TRUE(m2.has_value());
    const auto& c = v36_of(*m2);

    for (const auto* pair : {&g, &c}) {
        const auto& b = *pair;
        const auto& in = (pair == &g) ? j1.in : j2.in;
        SCOPED_TRACE(pair == &g ? "genesis" : "child");
        EXPECT_EQ(b.share.m_merkle_link.m_index, 0u);
        EXPECT_EQ(b.share.m_merkle_link.m_branch, expected_link.m_branch)
            << "the share commits the index-0 branch over the template tx list";
        EXPECT_EQ(b.share.m_merkle_link.m_branch, in.merkle_branches)
            << "== the stratum merkle branches the miner folded";
        EXPECT_EQ(b.gentx_hash, sha256d_bytes(in.coinbase_bytes))
            << "the served coinbase IS the share's gentx";
        EXPECT_EQ(dash::check_merkle_link(b.gentx_hash, b.share.m_merkle_link),
                  header_merkle_root(in.header_bytes))
            << "gentx hash + merkle_link fold to the header merkle root the miner solved";
        EXPECT_EQ(b.share.m_hash, in.pow_hash);
        EXPECT_TRUE(b.share.m_new_transaction_hashes.empty()) << "no tx refs on the v36 wire";
        EXPECT_TRUE(b.share.m_transaction_hash_refs.empty());
    }
    EXPECT_EQ(c.share.m_prev_hash, g.share.m_hash);

    // The wire bytes carry the link and nothing that names a tx body.
    const Bytes wg = wire_of(g.share), wc = wire_of(c.share);
    {
        auto back = load(36, wc);
        bool is_v36 = false;
        back.invoke([&](auto* obj) {
            using S = std::decay_t<decltype(*obj)>;
            if constexpr (std::is_same_v<S, dash::DashV36Share>) {
                is_v36 = true;
                EXPECT_EQ(obj->m_merkle_link.m_branch, expected_link.m_branch)
                    << "the merkle_link round-trips through the v36 wire";
                EXPECT_TRUE(obj->m_new_transaction_hashes.empty());
            }
        });
        EXPECT_TRUE(is_v36);
        back.destroy();
    }

    // ── node B: receives only the share wire bytes, never a tx body ──
    LiveNode b(p, sub + "_b");
    b.receive({{36, wg}, {36, wc}});
    ASSERT_TRUE(b.pump_until([&](dash::ShareTracker& t) {
        return t.chain.contains(g.share.m_hash) && t.chain.contains(c.share.m_hash);
    })) << "a second node admits the tx-committing v36 shares";
    auto& t = b.quiesce();
    EXPECT_TRUE(t.attempt_verify(g.share.m_hash));
    EXPECT_TRUE(t.attempt_verify(c.share.m_hash));
    EXPECT_TRUE(t.verified.contains(c.share.m_hash));
    EXPECT_EQ(dash::generate_share_transaction(c.share, t, p), c.gentx_hash);
}

// ═════════════════════════════════════════════════════════════════════════════
// B. A node that is not the finder refuses a tx-committing v36 won block
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36TemplateTxs, NonFinderRefusesTxCommittedV36WonBlock)
{
    IdentityGuard guard;
    const auto p = iso_params(36);

    dash::ShareChain scratch;
    const auto gen = mine_v36(scratch, p, info(uint256(), 1, 0xaa, 36));
    scratch.add(new dash::DashV36Share(gen.share));

    // A child that commits three template txs through its merkle_link.
    auto ci = info(gen.share.m_hash, 2, 0xbb, 36);
    ci.other_transaction_hashes = {tag_hash(0x31), tag_hash(0x32), tag_hash(0x33)};
    const auto child = mine_v36(scratch, p, ci);
    ASSERT_EQ(child.share.m_merkle_link.m_branch.size(), 2u);

    // And a coinbase-only sibling.
    const auto cb_only = mine_v36(scratch, p, info(gen.share.m_hash, 2, 0xcc, 36));
    ASSERT_TRUE(cb_only.share.m_merkle_link.m_branch.empty());

    dash::ShareTracker t;
    t.m_coin_params = p;
    t.add(var_of(gen.share));
    t.add(var_of(child.share));
    t.add(var_of(cb_only.share));

    // No template bodies on this node: nothing is rebuilt. A [gentx]-only block
    // under a header whose merkle root commits three more txs would be rejected
    // by dashd (bad-txnmrklroot) and would expose the node to a relay ban.
    const auto r = dash::coin::reconstruct_won_block(child.share.m_hash, child.share, t, p);
    EXPECT_FALSE(r.has_value())
        << "a non-finder must not rebuild a tx-committing v36 won block (got "
        << (r ? r->bytes.size() : 0) << " bytes)";

    // The coinbase-only v36 share still rebuilds as [gentx].
    const auto rc = dash::coin::reconstruct_won_block(cb_only.share.m_hash, cb_only.share, t, p);
    ASSERT_TRUE(rc.has_value());
    dash::coin::GentxCoinbase gc;
    ASSERT_EQ(dash::generate_share_transaction(cb_only.share, t, p, &gc), cb_only.gentx_hash);
    ASSERT_EQ(rc->bytes.size(), 80u + 1u + gc.bytes.size());
    EXPECT_EQ(rc->bytes[80], 1u) << "one transaction";
    EXPECT_EQ(p.pow_func(std::span<const unsigned char>(rc->bytes.data(), 80)), cb_only.share.m_hash);
}

// ═════════════════════════════════════════════════════════════════════════════
// C. One frozen body vector per template, shared by every job over it
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36TemplateTxs, ProducerJobsOverOneTemplateShareOneBodyVector)
{
    IdentityGuard guard;
    const auto p = iso_prod_params();
    ASSERT_EQ(p.current_share_version, 36u);
    dash::ShareChain scratch;
    const auto wd  = make_wd_with_txs(3);
    const auto wd2 = make_wd_with_txs(3, 0x7c);   // same size, other txs
    ASSERT_NE(wd.m_tx_hashes, wd2.m_tx_hashes);

    auto job = [&](const dash::coin::DashWorkData& w, uint8_t miner, uint32_t nonce) {
        return dash::mint::build_producer_job(scratch, p, uint256(),
                                              dash::pubkey_hash_to_script2(h160(miner)), w,
                                              w.m_curtime, nonce, /*donation=*/0, "c2pool");
    };

    std::weak_ptr<const std::vector<std::string>> watch;
    {
        const auto a = job(wd, 0xa1, 11);
        const auto b = job(wd, 0xb2, 12);    // another payout, same template
        const auto c = job(wd2, 0xa1, 13);   // another template
        ASSERT_TRUE(a && b && c);
        ASSERT_TRUE(a->frozen.tx_data_hex && b->frozen.tx_data_hex && c->frozen.tx_data_hex);
        EXPECT_EQ(*a->frozen.tx_data_hex, wd.m_tx_data_hex) << "template order, every body";
        EXPECT_EQ(a->frozen.tx_data_hex.get(), b->frozen.tx_data_hex.get())
            << "two jobs over one template must share one body vector, not copy it";
        EXPECT_NE(a->frozen.tx_data_hex.get(), c->frozen.tx_data_hex.get());
        EXPECT_EQ(*c->frozen.tx_data_hex, wd2.m_tx_data_hex);
        EXPECT_EQ(a->frozen.desired_tx_hashes, wd.m_tx_hashes);

        const auto cb = job(make_wd(), 0xa1, 14);
        ASSERT_TRUE(cb);
        EXPECT_FALSE(cb->frozen.tx_data_hex) << "a coinbase-only job freezes no bodies";
        watch = a->frozen.tx_data_hex;
    }
    EXPECT_TRUE(watch.expired())
        << "the memo holds weak references only: bodies die with the last frozen job";
}
