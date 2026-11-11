// SPDX-License-Identifier: AGPL-3.0-or-later
//
// LTC sharechain bootstrap hosts.
//
// The built-in bootstrap list used to include hosts of other share chains: an
// old V35 p2pool (20.113.157.65) and a separate chain (20.127.82.115,
// 20.106.76.227). A fresh c2pool-ltc node that reached them could follow their
// chain instead of the V36 one. Earlier versions also wrote that list into
// <data-dir>/ltc/pool.yaml, which is read again on every start.
//
//   DefaultsHoldNoForeignChainHost        FAILS with the old list
//   PersistedForeignHostsAreDroppedOnLoad FAILS without the load filter
//   HostMatchIgnoresPortOnly              helper behaviour
//
// FOLDED into the EXISTING allowlisted share_test target (#769 trap).

#include <gtest/gtest.h>

#include <impl/ltc/config_pool.hpp>

#include <filesystem>
#include <fstream>
#include <string>

namespace {

struct LoadablePoolConfig : ltc::PoolConfig
{
    using ltc::PoolConfig::PoolConfig;
    void run_init() { init(); }
};

} // namespace

TEST(LtcBootstrapHosts, DefaultsHoldNoForeignChainHost)
{
    ASSERT_FALSE(ltc::PoolConfig::DEFAULT_BOOTSTRAP_HOSTS.empty());
    for (const auto& host : ltc::PoolConfig::DEFAULT_BOOTSTRAP_HOSTS)
        EXPECT_FALSE(ltc::PoolConfig::is_foreign_chain_host(host)) << host;
}

TEST(LtcBootstrapHosts, PersistedForeignHostsAreDroppedOnLoad)
{
    const auto dir = std::filesystem::temp_directory_path()
        / ("c2pool-ltc-bootstrap-test-" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()));
    std::filesystem::create_directories(dir);
    const auto path = dir / "pool.yaml";
    {
        // pool.yaml as written by an earlier version with the old defaults
        std::ofstream f(path);
        f << "prefix: 7208c1a53ef629b0\n"
             "worker: \"\"\n"
             "bootstrap_addrs:\n"
             "  - ml.toom.im:9326\n"
             "  - usa.p2p-spb.xyz:9326\n"
             "  - 20.127.82.115:9326\n"
             "  - 31.25.241.224:9326\n"
             "  - 20.113.157.65:9326\n"
             "  - 20.106.76.227:9326\n";
    }
    LoadablePoolConfig cfg(path);
    cfg.run_init();

    std::vector<std::string> loaded;
    for (const auto& a : cfg.m_bootstrap_addrs)
        loaded.push_back(a.to_string());
    std::filesystem::remove_all(dir);

    EXPECT_EQ(loaded.size(), 3u);
    for (const auto& a : loaded) {
        EXPECT_EQ(a.find("20.113.157.65"), std::string::npos) << a;
        EXPECT_EQ(a.find("20.127.82.115"), std::string::npos) << a;
        EXPECT_EQ(a.find("20.106.76.227"), std::string::npos) << a;
    }
}

TEST(LtcBootstrapHosts, HostMatchIgnoresPortOnly)
{
    EXPECT_TRUE(ltc::PoolConfig::is_foreign_chain_host("20.113.157.65"));
    EXPECT_TRUE(ltc::PoolConfig::is_foreign_chain_host("20.113.157.65:9326"));
    EXPECT_TRUE(ltc::PoolConfig::is_foreign_chain_host("20.113.157.65:1234"));
    EXPECT_FALSE(ltc::PoolConfig::is_foreign_chain_host("20.113.157.6:9326"));
    EXPECT_FALSE(ltc::PoolConfig::is_foreign_chain_host("ltc.voidbind.com:9326"));
}
