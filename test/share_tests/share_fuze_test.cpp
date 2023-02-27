#include <gtest/gtest.h>

#include <memory>
#include <utility>

#include <libdevcore/common.h>
#include <sharechains/tracker.h>
#include <sharechains/share_store.h>
#include <sharechains/generate_tx.h>
#include <networks/network.h>
#include <btclibs/script/script.h>
#include <sharechains/data.h>

class TestNetwork : public c2pool::Network
{
public:
    TestNetwork(std::shared_ptr<coind::ParentNetwork> _par) : c2pool::Network("test_sharechain")
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
        ADDRESS_VERSION = 30;
        PERSIST = true;

        MIN_TARGET.SetHex("0");
        MAX_TARGET.SetHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 2**256/2**20 - 1

        DONATION_SCRIPT = ParseHex("5221038ab82f3a4f569c4571c483d56729e83399795badb32821cab64d04e7b5d106864104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664b410457a337b86557f5b15c94544ad267f96a582dc2b91e6873968ff7ba174fda6874af979cd9af41ec2032dfdfd6587be5b14a4355546d541388c3f1555a67d11c2d53ae");

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

class FuzeShareTest : public ::testing::Test
{
protected:
    shared_ptr<TestNetwork> net;

protected:

    virtual void SetUp()
    {
        auto pt = coind::ParentNetwork::make_default_network();
        std::shared_ptr<coind::ParentNetwork> parent_net = std::make_shared<coind::ParentNetwork>("dgb", pt);
        net = make_shared<TestNetwork>(parent_net);
    }

    virtual void TearDown()
    {
    }
};


TEST_F(FuzeShareTest, unpack_share)
{
    // Check for true load_share
    {
        PackStream stream_share;
        stream_share.from_hex("21fd4301fe0200002069a23207be25e7a85c90503b49c3afa2a1f81932d4e849db0000000000000000c35b4b637ecb001b18f3c4e670b789e2dc2fd0ead0e49f52699176d7a7a96730837024b5c8a5d4a7f5bc2e2c3d043c49f3002cfabe6d6d265e57d73d2102c2d426c33c427a5ac70d92d50b018a3ffd2f325c5bb585d01601000000000000000a5f5f6332706f6f6c5f5f2f6d9d23bb351fc9fbbd8e1f40942130e77131978df6de411a7125010a00000000000021000000000000000000000000000000000000000000000000000000000000000000000055ac137f1b1995004f2fc98705c3ed7f9cc5f8e8551c96ed0316cb4bf764ceea6709021e6709021ec85b4b637dd401008d6ebd31f80100000000000000000000000000000001000000d53919c88fe180f62b333d9a57f00b4483ed0cac2793fe3a18f2501c3156f924fd7a0100");
        LOG_INFO << "stream_share len: " << stream_share.size();

        auto share = load_share(stream_share, net, {"0.0.0.0", "0"});
    }

    // Fuze[1]
    EXPECT_THROW(
    {
        PackStream stream_share;
        stream_share.from_hex("21fd4301fe02000020693207be25e7a85c90503b49c3afa2a1f81932d4e849db0000000000000000c35b4b637ecb001b18f3c4e670b789e2dc2fd0ead0e49f52699176d7a7a96730837024b5c8a5d4a7f5bc2e2c3d043c49f3002cfabe6d6d265e57d73d2102c2d426c33c427a5ac70d92d50b018a3ffd2f325c5bb585d01601000000000000000a5f5f6332706f6f6c5f5f2f6d9d23bb351fc9fbbd8e1f40942130e77131978df6de411a7125010a00000000000021000000000000000000000000000000000000000000000000000000000000000000000055ac137f1b1995004f2fc98705c3ed7f9cc5f8e8551c96ed0316cb4bf764ceea6709021e6709021ec85b4b637dd401008d6ebd31f80100000000000000000000000000000001000000d53919c88fe180f62b333d9a57f00b4483ed0cac2793fe3a18f2501c3156f924fd7a0100");
        LOG_INFO << "stream_share len: " << stream_share.size();

        auto share_fuze = load_share(stream_share, net, {"0.0.0.0", "0"});
    }, std::invalid_argument);

    // Fuze[2]
    {
        PackStream stream_share;
        stream_share.from_hex("asd1235131414asdcфывфывфыв1231й23у4фап каываываываываываыв");
        LOG_INFO << "stream_share len: " << stream_share.size();

        auto share_fuze = load_share(stream_share, net, {"0.0.0.0", "0"});
    }
}