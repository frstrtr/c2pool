// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <nlohmann/json.hpp>

#include <core/web_server.hpp>
#include <core/coin/node_iface.hpp>

// ---------------------------------------------------------------------------
// KATs for core::MiningInterface::rest_local_stats -> local_hashps (#919).
//
// The /local_stats endpoint surfaces this node's OWN work rate as a series a
// local-hashrate graph polls over time. The rate is read from the real stratum
// work-rate counter (set_stratum_hashrate_fn) -- the same live per-node source
// the node-fee share at web_server.cpp trusts as local_hr -- never the empty
// m_node stub that gave us the founding poolhashps=0 lie.
//
// The honesty rule these lock, in both directions:
//   * COLD (no work-rate source wired): local_hashps is null -- an honest
//     "unknown", NOT a flat 0 that would falsely claim this node mines nothing.
//   * LIVE (source wired): local_hashps is the counter's real value. A wired
//     source that reports 0.0 is a TRUE reading and stays 0, not null.
//
// Both FAIL WITHOUT THE FIX: before it, rest_local_stats emits no local_hashps
// key at all, so the cold assertion (key present AND null) and the live
// assertion (key present AND == counter) both fail on the missing field.
// ---------------------------------------------------------------------------

// COLD: no stratum work-rate source wired -> honest-absent null, never 0.
TEST(LocalHashpsSeam, ColdCounterIsHonestNullNotZero) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);

    auto r = mi.rest_local_stats();
    ASSERT_TRUE(r.is_object());
    ASSERT_TRUE(r.contains("local_hashps"))
        << "local_hashps must be present so a cold node reads as unknown, not 0";
    EXPECT_TRUE(r["local_hashps"].is_null())
        << "cold local work-rate counter must be honest-absent (null), not flat 0";
}

// LIVE: wired counter surfaces its real value verbatim.
TEST(LocalHashpsSeam, LiveCounterSurfacesRealValue) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);

    const double kLocalHs = 1234567.0;  // ~1.23 MH/s of local stratum work
    mi.set_stratum_hashrate_fn([kLocalHs]() { return kLocalHs; });

    auto r = mi.rest_local_stats();
    ASSERT_TRUE(r.is_object());
    ASSERT_TRUE(r.contains("local_hashps"));
    ASSERT_TRUE(r["local_hashps"].is_number());
    EXPECT_DOUBLE_EQ(r["local_hashps"].get<double>(), kLocalHs)
        << "live local_hashps must equal the real stratum work-rate counter";
}

// ---------------------------------------------------------------------------
// #942 node_role: the dashboard needs to know whether this node CAN have local
// miners, so a relay node's zero miners render as "not applicable" rather than
// as a measurement. Same seam as local_hashps: no Stratum acceptor wired means
// relay, a wired one (even reporting 0 H/s) means mining.
// FAIL WITHOUT THE FIX: rest_local_stats emitted no node_role key.
// ---------------------------------------------------------------------------

TEST(NodeRoleSeam, NoStratumAcceptorIsRelay) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);

    auto r = mi.rest_local_stats();
    ASSERT_TRUE(r.contains("node_role"));
    EXPECT_EQ(r["node_role"], "relay")
        << "a node with no Stratum acceptor cannot have local miners";
}

TEST(NodeRoleSeam, IdleStratumAcceptorIsStillMining) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    mi.set_stratum_hashrate_fn([]() { return 0.0; });  // listening, no miners yet

    auto r = mi.rest_local_stats();
    ASSERT_TRUE(r.contains("node_role"));
    EXPECT_EQ(r["node_role"], "mining")
        << "an acceptor with zero miners is an idle mining node, not a relay";
}

// ---------------------------------------------------------------------------
// #942 residual, daemonless basis: a Stratum acceptor with no template source
// cannot hand out work, so the node is a relay. "none" is asserted only when
// a coin node is attached and reports neither source; with no coin node the
// source is unknown (null) and the Stratum basis stands.
// FAIL WITHOUT THE FIX: rest_local_stats emitted no template_source or
// node_role_basis, and a daemonless node with an acceptor read "mining".
// ---------------------------------------------------------------------------

namespace {
struct RoleFakeCoinNode : public core::coin::ICoinNode {
    bool embedded = false;
    bool rpc = false;
    core::coin::WorkView get_work_view() override { core::coin::WorkView v; return v; }
    bool submit_block_hex(const std::string&, bool) override { return false; }
    bool is_embedded() const override { return embedded; }
    bool has_rpc() const override { return rpc; }
};
} // namespace

TEST(NodeRoleSeam, NoStratumBasisIsNamed) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    auto r = mi.rest_local_stats();
    EXPECT_EQ(r["node_role"], "relay");
    EXPECT_EQ(r["node_role_basis"], "no_stratum");
}

TEST(NodeRoleSeam, NoCoinNodeLeavesTemplateSourceUnknown) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    mi.set_stratum_hashrate_fn([]() { return 0.0; });
    auto r = mi.rest_local_stats();
    ASSERT_TRUE(r.contains("template_source"));
    EXPECT_TRUE(r["template_source"].is_null())
        << "no coin node attached is unknown, not evidence of no daemon";
    EXPECT_EQ(r["node_role"], "mining");
    EXPECT_EQ(r["node_role_basis"], "stratum");
}

TEST(NodeRoleSeam, AttachedDaemonlessCoinNodeIsRelay) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    RoleFakeCoinNode coin;  // attached, neither embedded nor RPC
    mi.set_coin_node(&coin);
    mi.set_stratum_hashrate_fn([]() { return 0.0; });
    auto r = mi.rest_local_stats();
    EXPECT_EQ(r["template_source"], "none");
    EXPECT_EQ(r["node_role"], "relay")
        << "an acceptor with no template source cannot hand miners work";
    EXPECT_EQ(r["node_role_basis"], "no_template_source");
    mi.set_coin_node(nullptr);
}

TEST(NodeRoleSeam, EmbeddedCoinNodeKeepsMining) {
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    RoleFakeCoinNode coin;
    coin.embedded = true;
    coin.rpc = true;
    mi.set_coin_node(&coin);
    mi.set_stratum_hashrate_fn([]() { return 0.0; });
    auto r = mi.rest_local_stats();
    EXPECT_EQ(r["template_source"], "embedded+rpc");
    EXPECT_EQ(r["node_role"], "mining");
    mi.set_coin_node(nullptr);
}

TEST(NodeRoleSeam, RpcFlagWithoutCoinNodeIsRpc) {
    // c2pool-dash with dashd: an external NodeRPC arm, no ICoinNode.
    core::MiningInterface mi(/*testnet=*/false, /*node=*/nullptr,
                             c2pool::address::Blockchain::LITECOIN);
    mi.set_coin_rpc_available(true);
    mi.set_stratum_hashrate_fn([]() { return 0.0; });
    auto r = mi.rest_local_stats();
    EXPECT_EQ(r["template_source"], "rpc");
    EXPECT_EQ(r["node_role"], "mining");
}
