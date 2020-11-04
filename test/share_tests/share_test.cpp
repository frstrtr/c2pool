#include <gtest/gtest.h>
#include <tuple>
#include <string>


#include "share.h"
#include "shareTypes.h"
#include <config.h>
#include "uint256.h"
#include "arith_uint256.h"


using namespace std;

class TestNetwork : public c2pool::config::Network
{
public:
    TestNetwork() : Network()
    {
        BOOTSTRAP_ADDRS = {
            CREATE_ADDR("192.168.0.1", "5024")
        };
        PREFIX_LENGTH = 8;
        PREFIX = new unsigned char[PREFIX_LENGTH]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
        IDENTIFIER = new unsigned char[8]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
        MINIMUM_PROTOCOL_VERSION = 1600;
        SEGWIT_ACTIVATION_VERSION = 17;

        TARGET_LOOKBEHIND = 200;
        SHARE_PERIOD = 25;
        BLOCK_MAX_SIZE = 1000000;
        BLOCK_MAX_WEIGHT = 4000000;
        REAL_CHAIN_LENGTH = 24*60*60/10;
        CHAIN_LENGTH = 24*60*60/10;
        SPREAD = 30;
    }
};

class BaseShareTest : public ::testing::Test
{
protected:
    shared_ptr<TestNetwork> net;
    BaseShare* share;

protected:
    virtual void SetUp()
    {
        net = make_shared<TestNetwork>();
        tuple<string, string> peer_addr = make_tuple<std::string, std::string>("192.168.0.1", "1337");

        ShareType share_type;

        //share = new BaseShare(net, peer_addr, share_type);
        share = new BaseShare();
    }

    virtual void TearDown()
    {
    }
};

TEST_F(BaseShareTest, InitBaseShare)
{
    cout << share->timestamp;
}