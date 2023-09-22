#include <gtest/gtest.h>
#include <string>
#include <iostream>

#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <libcoind/types.h>
#include <libcoind/data.h>
#include <networks/network.h>

class TestNetwork : public c2pool::Network
{
public:
    TestNetwork(std::shared_ptr<coind::ParentNetwork> _par) : c2pool::Network("tLTC_test")
    {
        parent = std::move(_par);

        SOFTFORKS_REQUIRED = {"nversionbips", "csv", "segwit", "reservealgo", "odo"};
        BOOTSTRAP_ADDRS = {
                CREATE_ADDR("0.0.0.0", "5024")
        };
        PREFIX_LENGTH = 8;
        PREFIX = new unsigned char[PREFIX_LENGTH]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
        IDENTIFIER_LENGTH = 8;
        IDENTIFIER = new unsigned char[IDENTIFIER_LENGTH]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x66};
        MINIMUM_PROTOCOL_VERSION = 1600;
        SEGWIT_ACTIVATION_VERSION = 17;

        TARGET_LOOKBEHIND = 200;
        SHARE_PERIOD = 25;
        BLOCK_MAX_SIZE = 1000000;
        BLOCK_MAX_WEIGHT = 4000000;
        REAL_CHAIN_LENGTH = 24 * 60 * 60 / 10;
        CHAIN_LENGTH = 24 * 60 * 60 / 10;
        SPREAD = 30;
        PERSIST = true;

        MIN_TARGET.SetHex("0");
        MAX_TARGET.SetHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 2**256/2**20 - 1

        DONATION_SCRIPT = ParseHex("4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac");

        // init gentx_before_refhash
        {
            PackStream gentx_stream;

            StrType dnt_scpt(DONATION_SCRIPT);
            gentx_stream << dnt_scpt;

            IntType(64) empty_64int(0);
            gentx_stream << empty_64int;

            PackStream second_str_stream(std::vector<unsigned char>{0x6a, 0x28});
            IntType(256) empty_256int(uint256::ZERO);
            second_str_stream << empty_256int;
            second_str_stream << empty_64int;

            PackStream for_cut;
            StrType second_str(second_str_stream.data);
            for_cut << second_str;
            for_cut.data.erase(for_cut.data.begin() + 3 , for_cut.data.end());

            gentx_stream << for_cut;
            gentx_before_refhash = gentx_stream.data;

//            std::cout << gentx_stream.size() << std::endl;
//            for (auto v : gentx_stream.data){
//                std::cout << (unsigned int) v << " ";
//            }
//            std::cout << std::endl;

        }
    }
};

class TestParentNetwork : public coind::ParentNetwork
{
public:
    TestParentNetwork() : coind::ParentNetwork("tLTC_test")
    {
        SYMBOL = "tLTC";
        ADDRESS_VERSION = 111;
        ADDRESS_P2SH_VERSION = 58;
    }
};

class AddrConvertTest : public ::testing::Test
{
protected:
    std::shared_ptr<TestNetwork> net;

protected:

    virtual void SetUp()
    {
        std::shared_ptr<coind::ParentNetwork> parent_net = std::make_shared<TestParentNetwork>();
        net = make_shared<TestNetwork>(parent_net);
    }

    virtual void TearDown()
    {
    }
};

TEST_F(AddrConvertTest, pubkey_hash_to_address)
{
    auto pubkey_hash = uint160();
    pubkey_hash.SetHex("384f570ccc88ac2e7e00b026d1690a3fca63dd0");

    auto addr = coind::data::pubkey_hash_to_address(pubkey_hash, net->parent->ADDRESS_VERSION, -1, net);
    std::cout << "pubkey_hash_to_address: " << addr << std::endl;
}

TEST_F(AddrConvertTest, donation_script_to_address)
{
    auto donation_address = coind::data::donation_script_to_address(net);
    std::cout << "donation_script_to_address: " << donation_address << std::endl;
    ASSERT_EQ("mzW2hdZN2um7WBvTDerdahKqRgj3md9C29", donation_address);
}

TEST_F(AddrConvertTest, address_to_pubkey_hash)
{
    auto donation_address = coind::data::donation_script_to_address(net);
    auto pubkey_hash = coind::data::address_to_pubkey_hash(donation_address, net);
    std::cout << "address_to_pubkey_hash: value = " << std::get<0>(pubkey_hash) << ", version = " << (int)std::get<1>(pubkey_hash) << std::endl;

    auto true_answer = uint160();
    true_answer.SetHex("384f570ccc88ac2e7e00b026d1690a3fca63dd0");
    ASSERT_EQ(std::get<0>(pubkey_hash), true_answer);
//    ASSERT_EQ("mzW2hdZN2um7WBvTDerdahKqRgj3md9C29", donation_address);
}