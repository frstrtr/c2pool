#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <sstream>
#include <iomanip>
#include <string>

//#include "shareTracker.h"
//#include "config.h"
//#include "uint256.h"
//#include "arith_uint256.h"

#include <sharechains/tracker.h>

using namespace std;

class TestNetwork : public c2pool::config::Network
{
public:
    TestNetwork()
    {
        BOOTSTRAP_ADDRS = {
            CREATE_ADDR("217.72.4.157", "5024")
            //"217.42.4.157:5025"
        };
        PREFIX_LENGTH = 8;
        PREFIX = new unsigned char[PREFIX_LENGTH]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
        IDENTIFIER = new unsigned char[8]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
        MINIMUM_PROTOCOL_VERSION = 1600;
        SEGWIT_ACTIVATION_VERSION = 17;
    }
};

struct TestShare
{
    arith_uint256 hash;
    arith_uint256 previous_hash;
};

class ShareTrackerTest : public ::testing::Test
{
protected:
    shared_ptr<TestNetwork> net;
    vector<TestShare> _items;
protected:
    void SetUp()
    {
        net = make_shared<TestNetwork>();
        stringstream ss;
        string hex_hash;
        for (int i = 0; i < 50; i++)
        {
            ss << hex << i;
            ss >> hex_hash;
            TestShare share = {arith_uint256(hex_hash), arith_uint256(hex_hash) - 1};
            _items.push_back(share);
        }
    }

    void TearDown()
    {
        _items.clear();
    }
};

TEST(ShareTrackerTest, InitOkayTrackerTest)
{
}
