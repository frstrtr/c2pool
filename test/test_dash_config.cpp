/// Phase S8 — Dash coin/pool config types KATs
///
/// Exercises src/impl/dash/config.hpp — the dash::PoolConfig / dash::CoinConfig
/// / dash::Config seam the broadcaster gate reads its endpoints from:
///
///     config -> [p2p_node bootstrap addrs / coin RPC+P2P endpoints] -> broadcaster_full
///
/// broadcaster_full.hpp dials the network using exactly these fields: the coin
/// RPC address+userpass for the submitblock fallback arm, and the coin P2P
/// address (+ pool bootstrap addrs) for the embedded relay arm. What is PINNED
/// here is the real observable contract those arms read:
///
///   (a) PoolConfig — m_prefix (sharechain namespace bytes), m_worker, and the
///       m_bootstrap_addrs NetService vector the embedded p2p_node seeds from.
///
///   (b) CoinConfig — m_testnet flag, the m_p2p {prefix,address} the relay arm
///       dials, and the m_rpc {address,userpass} the submitblock arm dials.
///
///   (c) the combined dash::Config (= core::Config<PoolConfig,CoinConfig>) —
///       pool() and coin() downcast to the SAME combined instance, so fields
///       set through one accessor are independently readable, which is how the
///       broadcaster is handed one config object yet reads both halves.
///
///   (d) NetService endpoint parse — host+port round-trip, the exact value the
///       broadcaster opens a socket / RPC channel to.
///
/// SCOPE NOTE (honest): this pins the config struct + downcast contract in
/// isolation against the real core::Config / core::Fileconfig / NetService
/// machinery (no mocks). No YAML file is read and init()/load() is not invoked,
/// so nothing touches the filesystem; the loader path is a later concern.

#include <gtest/gtest.h>

#include <impl/dash/config.hpp>
#include <core/netaddress.hpp>

#include <cstddef>
#include <string>
#include <vector>

using namespace dash;

// (a) PoolConfig field round-trip — sharechain prefix, worker, bootstrap addrs.
TEST(DashConfig, PoolConfigFields)
{
    PoolConfig pc{std::filesystem::path{"/tmp/dash-cfg-unused/pool.yaml"}};

    pc.m_prefix = std::vector<std::byte>{std::byte{0xfb}, std::byte{0xc0}, std::byte{0xb6}, std::byte{0xdb}};
    pc.m_worker = "yMjcVgN3UM7X8UWZQPvx6UeXTXKeR7h8dx";
    pc.m_bootstrap_addrs = std::vector<NetService>{
        NetService{std::string{"10.0.0.1"}, std::string{"9999"}},
        NetService{std::string{"10.0.0.2"}, std::string{"19999"}},
    };

    ASSERT_EQ(pc.m_prefix.size(), 4u);
    EXPECT_EQ(pc.m_prefix[0], std::byte{0xfb});
    EXPECT_EQ(pc.m_prefix[3], std::byte{0xdb});
    EXPECT_EQ(pc.m_worker, "yMjcVgN3UM7X8UWZQPvx6UeXTXKeR7h8dx");
    ASSERT_EQ(pc.m_bootstrap_addrs.size(), 2u);
    EXPECT_EQ(pc.m_bootstrap_addrs[0].port(), 9999);
    EXPECT_EQ(pc.m_bootstrap_addrs[1].port(), 19999);
}

// (b) CoinConfig field round-trip — testnet flag + P2P + RPC endpoints.
TEST(DashConfig, CoinConfigEndpoints)
{
    CoinConfig cc{std::filesystem::path{"/tmp/dash-cfg-unused/coin.yaml"}};

    EXPECT_FALSE(cc.m_testnet);  // default
    cc.m_testnet = true;

    cc.m_p2p.prefix = std::vector<std::byte>{std::byte{0xce}, std::byte{0xe2}, std::byte{0xca}, std::byte{0xff}};
    cc.m_p2p.address = NetService{std::string{"127.0.0.1"}, std::string{"19998"}};
    cc.m_rpc.address = NetService{std::string{"127.0.0.1"}, std::string{"19998"}};
    cc.m_rpc.userpass = "c2pool_dash:secret";

    EXPECT_TRUE(cc.m_testnet);
    ASSERT_EQ(cc.m_p2p.prefix.size(), 4u);
    EXPECT_EQ(cc.m_p2p.prefix[0], std::byte{0xce});
    EXPECT_EQ(cc.m_p2p.address.port(), 19998);
    EXPECT_EQ(cc.m_rpc.address.port(), 19998);
    EXPECT_EQ(cc.m_rpc.userpass, "c2pool_dash:secret");
}

// (c) combined Config — pool()/coin() downcast to the same instance; both
//     halves are independently readable from the single object handed around.
TEST(DashConfig, CombinedDowncastIdentity)
{
    Config cfg{"dash-s8-config-kat"};

    ASSERT_NE(cfg.pool(), nullptr);
    ASSERT_NE(cfg.coin(), nullptr);

    // pool() / coin() are downcasts of the same combined object.
    EXPECT_EQ(static_cast<void*>(cfg.pool()), static_cast<void*>(static_cast<PoolConfig*>(&cfg)));
    EXPECT_EQ(static_cast<void*>(cfg.coin()), static_cast<void*>(static_cast<CoinConfig*>(&cfg)));

    cfg.pool()->m_worker = "pool-worker";
    cfg.coin()->m_testnet = true;
    cfg.coin()->m_rpc.userpass = "u:p";

    // read back through both the accessor and the direct base view.
    EXPECT_EQ(static_cast<PoolConfig*>(&cfg)->m_worker, "pool-worker");
    EXPECT_TRUE(static_cast<CoinConfig*>(&cfg)->m_testnet);
    EXPECT_EQ(cfg.coin()->m_rpc.userpass, "u:p");
    EXPECT_EQ(cfg.m_name, "dash-s8-config-kat");
}

// (d) NetService endpoint parse — the host+port the broadcaster dials.
TEST(DashConfig, NetServiceEndpointParse)
{
    NetService ep{std::string{"192.168.86.52"}, std::string{"19998"}};
    EXPECT_EQ(ep.port(), 19998);
    EXPECT_EQ(ep.to_string(), std::string{"192.168.86.52:19998"});
}
