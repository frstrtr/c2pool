// SPDX-License-Identifier: AGPL-3.0-or-later
// KAT for btc::build_aux_backends + btc::merged_addr_entries (NMC PE host-wire
// slice 4). Proves each parsed AuxChainConfig yields exactly one backend (with
// its config faithfully carried) and one MergedAddressEntry (chain_id + payout
// script), and that the empty --merged case produces empty vectors (v35 path).
#include <gtest/gtest.h>

#include <impl/btc/coin/merged_backend.hpp>
#include <impl/btc/coin/merged_spec.hpp>

#include <boost/asio/io_context.hpp>

#include <string>
#include <vector>

namespace {

c2pool::merged::AuxChainConfig parse(const std::string& spec)
{
    c2pool::merged::AuxChainConfig c;
    std::string err;
    EXPECT_TRUE(btc::parse_merged_spec(spec, c, err)) << "spec=" << spec << " err=" << err;
    return c;
}

// A canonical 25-byte P2PKH script (OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG).
std::vector<unsigned char> p2pkh()
{
    std::vector<unsigned char> s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, 0xab);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

TEST(BtcMergedBackend, MergedAddrEntriesMapChainIdAndScript)
{
    std::vector<c2pool::merged::AuxChainConfig> cfgs = {
        parse("NMC:1:127.0.0.1:8336:u:p"),
        parse("XYZ:42:10.0.0.1:9000:a:b:9001"),
    };
    auto script = p2pkh();
    auto entries = btc::merged_addr_entries(cfgs, script);
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[0].m_chain_id, 1u);
    EXPECT_EQ(entries[1].m_chain_id, 42u);
    EXPECT_EQ(entries[0].m_script.m_data, script);
    EXPECT_EQ(entries[1].m_script.m_data, script);
}

TEST(BtcMergedBackend, EmptyConfigsYieldEmptyEntries)
{
    std::vector<c2pool::merged::AuxChainConfig> none;
    EXPECT_TRUE(btc::merged_addr_entries(none, p2pkh()).empty());
}

TEST(BtcMergedBackend, BuildAuxBackendsOnePerConfigCarriesConfig)
{
    std::vector<c2pool::merged::AuxChainConfig> cfgs = {
        parse("NMC:1:127.0.0.1:8336:u:p"),
        parse("XYZ:42:10.0.0.1:9000:a:b:9001"),
    };
    boost::asio::io_context ioc;
    auto backends = btc::build_aux_backends(ioc, cfgs);
    ASSERT_EQ(backends.size(), 2u);
    ASSERT_NE(backends[0], nullptr);
    ASSERT_NE(backends[1], nullptr);
    EXPECT_EQ(backends[0]->config().symbol, "NMC");
    EXPECT_EQ(backends[0]->config().chain_id, 1u);
    EXPECT_EQ(backends[0]->config().rpc_host, "127.0.0.1");
    EXPECT_EQ(backends[1]->config().chain_id, 42u);
    EXPECT_EQ(backends[1]->config().rpc_port, 9000);
}

TEST(BtcMergedBackend, EmptyConfigsYieldNoBackends)
{
    boost::asio::io_context ioc;
    std::vector<c2pool::merged::AuxChainConfig> none;
    EXPECT_TRUE(btc::build_aux_backends(ioc, none).empty());
}

} // namespace
