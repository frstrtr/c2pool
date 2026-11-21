// SPDX-License-Identifier: AGPL-3.0-or-later
// A DASH share that solved a block keeps its block flag across a restart.
//
// A share reloaded from the sharechain store as verified is added to the
// verified chain without being verified again (load_persisted_shares), so its
// index flag (is_block_solution), set when share_init_verify found its X11
// hash at or below the block target of its header, was lost: /web/share/<hash>
// and the explorer showed a confirmed block as an ordinary share after a
// restart. The reload now restores the flag from the share's PoW hash (on
// DASH the share hash itself) and its header bits, and fires no found-block
// event: the block was recorded when the share was first verified.
//
// Pinned through a real dash::NodeImpl over LevelDB: receive, verify,
// persist, then a second node reloads the store with a found-block hook
// bound before the load.
//
// Folded into test_dash_node (needs dash::NodeImpl + c2pool_storage).

#include <gtest/gtest.h>

#include "dash_v36_live_fixture.hpp"   // IdentityGuard, DataDirGuard, LiveNode, ProbeNode, mine_v36, ...

#include <impl/dash/dashboard_views.hpp>

#include <mutex>
#include <optional>

namespace {

// A v36 share that is also a block: its header carries the share's own easy
// bits, so meeting the share target meets the block target.
dash::producer::BuiltV36Share mine_v36_block(dash::ShareChain& sc, const core::CoinParams& p,
                                             const dash::producer::ProspectiveShareInfo& i)
{
    for (uint32_t n = 0; n < 1000000; ++n) {
        auto hdr = header(n);
        hdr.m_bits = EASY_BITS;
        auto b = dash::producer::build_share_v36(sc, p, i, hdr, NONCE64, false);
        if (!(b.share.m_hash > chain::bits_to_target(b.share.m_bits)))
            return dash::producer::build_share_v36(sc, p, i, hdr, NONCE64, true);
    }
    throw std::runtime_error("mine_v36_block: no header nonce met the target");
}

} // namespace

TEST(DashReloadBlockFlag, AReloadedBlockSolutionKeepsItsFlagAndFiresNoEvent)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_reload_block_flag");
    const auto p = iso_params(36);
    const std::string sub = SharechainConfig::data_subdir(false);

    dash::ShareChain scratch;
    const auto gen = mine_v36_block(scratch, p, info(uint256(), 1, 0xaa, 36));
    scratch.add(new dash::DashV36Share(gen.share));
    const auto child = mine_v36(scratch, p, info(gen.share.m_hash, 2, 0xbb, 36));
    const uint256 hg = gen.share.m_hash, hc = child.share.m_hash;
    ASSERT_TRUE(hg <= chain::bits_to_target(gen.share.m_min_header.m_bits)) << "the first share solves its block";
    ASSERT_FALSE(hc <= chain::bits_to_target(child.share.m_min_header.m_bits)) << "the second does not";

    int fired_first_run = 0;
    {
        LiveNode n(p, sub);
        n.node->tracker().m_on_block_found = [&](const uint256& h) {
            if (h == hg)
                ++fired_first_run;
        };
        n.receive({{36, wire_of(gen.share)}, {36, wire_of(child.share)}});
        ASSERT_TRUE(n.pump_until([&](dash::ShareTracker& t) {
            return t.chain.contains(hg) && t.chain.contains(hc);
        }));
        auto& t = n.quiesce();
        if (!t.verified.contains(hg))
            EXPECT_TRUE(t.attempt_verify(hg));
        if (!t.verified.contains(hc))
            EXPECT_TRUE(t.attempt_verify(hc));
        ASSERT_TRUE(t.verified.contains(hg));
        ASSERT_TRUE(t.verified.contains(hc));
        EXPECT_TRUE(t.chain.get_index(hg)->is_block_solution);
        EXPECT_FALSE(t.chain.get_index(hc)->is_block_solution);
        EXPECT_GE(fired_first_run, 1) << "the block is found when the share is first verified";
        n.node->shutdown_persistence();
    }   // LevelDB closed

    // The restart: the found-block hook is bound before the store is loaded,
    // as main_dash binds it before the node starts.
    boost::asio::io_context ioc;
    dash::Config cfg("dash-reload-block-flag-kat");
    auto node = std::make_unique<ProbeNode>(&ioc, &cfg);
    node->tracker().m_coin_params = p;
    int fired_on_reload = 0;
    node->tracker().m_on_block_found = [&](const uint256&) { ++fired_on_reload; };
    fs::create_directories(core::filesystem::config_path() / sub);
    node->init_storage(sub);   // load_persisted_shares
    node->join_compute_pools();
    auto& t = node->tracker();

    ASSERT_TRUE(t.chain.contains(hg));
    ASSERT_TRUE(t.verified.contains(hg)) << "reloaded as verified, not verified again";
    ASSERT_TRUE(t.verified.contains(hc));
    EXPECT_TRUE(t.chain.get_index(hg)->is_block_solution) << "the block flag survives the reload";
    EXPECT_FALSE(t.chain.get_index(hc)->is_block_solution);
    EXPECT_EQ(t.chain.get_index(hg)->pow_hash, hg) << "the X11 PoW hash is the share hash";
    EXPECT_EQ(fired_on_reload, 0) << "no second found-block event for a block already recorded";

    // What /web/share/<hash> serves.
    const dash::dashboard::ViewContext ctx;
    EXPECT_TRUE(dash::dashboard::build_share_detail(t, hg.GetHex(), ctx).value("is_block_solution", false));
    EXPECT_FALSE(dash::dashboard::build_share_detail(t, hc.GetHex(), ctx).value("is_block_solution", true));

    node->hold_think_slot(false);
    node->shutdown_persistence();
    node.reset();
}

// The verify path fires the found-block hook (which records and relays the
// block) only for header bits the coin network accepts after the share's
// parent, once main_dash's header-chain oracle (m_expected_block_bits) is
// bound. The share keeps its block flag either way. Head scoring asks the
// same oracle for a block-solving head, so the oracle-call assertions only
// pin what it is asked; `fired` is what proves the gate.
namespace {

struct VerifiedFire
{
    int fired = 0;
    int oracle_calls = 0;
    uint256 oracle_prev;
    int64_t oracle_time = 0;
    bool flagged = false;
    uint256 header_prev;
    uint32_t header_time = 0;
};

VerifiedFire verify_block_share_with_oracle(const char* dir, std::optional<uint32_t> answer)
{
    IdentityGuard guard;
    DataDirGuard dd(dir);
    const auto p = iso_params(36);
    const std::string sub = SharechainConfig::data_subdir(false);

    dash::ShareChain scratch;
    const auto gen = mine_v36_block(scratch, p, info(uint256(), 1, 0xaa, 36));
    const uint256 hg = gen.share.m_hash;

    VerifiedFire r;
    r.header_prev = gen.share.m_min_header.m_previous_block;
    r.header_time = gen.share.m_min_header.m_timestamp;
    std::mutex m;   // the hook and the oracle run on the verify/compute threads
    LiveNode n(p, sub);
    n.node->tracker().m_expected_block_bits =
        [&](const uint256& prev, int64_t time) -> std::optional<uint32_t> {
            std::lock_guard<std::mutex> lk(m);
            ++r.oracle_calls;
            r.oracle_prev = prev;
            r.oracle_time = time;
            return answer;
        };
    n.node->tracker().m_on_block_found = [&](const uint256& h) {
        std::lock_guard<std::mutex> lk(m);
        if (h == hg)
            ++r.fired;
    };
    n.receive({{36, wire_of(gen.share)}});
    EXPECT_TRUE(n.pump_until([&](dash::ShareTracker& t) { return t.chain.contains(hg); }));
    auto& t = n.quiesce();
    if (!t.chain.contains(hg)) {
        ADD_FAILURE() << "the block share never reached the chain";
        return r;
    }
    if (!t.verified.contains(hg))
        EXPECT_TRUE(t.attempt_verify(hg));
    EXPECT_TRUE(t.verified.contains(hg));
    r.flagged = t.chain.contains(hg) && t.chain.get_index(hg)->is_block_solution;
    return r;
}

} // namespace

TEST(DashReloadBlockFlag, AVerifiedBlockAtTheNetworksBitsFires)
{
    const auto r = verify_block_share_with_oracle("c2pool_dash_found_bits_match", EASY_BITS);
    EXPECT_GE(r.fired, 1) << "header bits equal the network's: the found-block hook fires";
    EXPECT_TRUE(r.flagged);
    EXPECT_GE(r.oracle_calls, 1);
    EXPECT_EQ(r.oracle_prev, r.header_prev) << "the oracle is asked about the share's parent block";
    EXPECT_EQ(r.oracle_time, static_cast<int64_t>(r.header_time)) << "...at the share's header time";
}

TEST(DashReloadBlockFlag, AVerifiedBlockAtOtherThanTheNetworksBitsDoesNotFire)
{
    const auto r = verify_block_share_with_oracle("c2pool_dash_found_bits_mismatch", 0x1b0404cbu);
    EXPECT_GE(r.oracle_calls, 1);
    EXPECT_EQ(r.fired, 0) << "a block the network rejects must be neither recorded nor relayed";
    EXPECT_TRUE(r.flagged) << "the share keeps its block flag; head scoring checks bits on its own";
}

TEST(DashReloadBlockFlag, AVerifiedBlockOnAParentTheOracleCannotAnswerDoesNotFire)
{
    const auto r = verify_block_share_with_oracle("c2pool_dash_found_bits_unknown", std::nullopt);
    EXPECT_GE(r.oracle_calls, 1);
    EXPECT_EQ(r.fired, 0) << "nothing to check the bits against: not relayed from this node";
    EXPECT_TRUE(r.flagged);
}
