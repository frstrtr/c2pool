#include <gtest/gtest.h>
#include <sharechains/base_share_tracker.h>
#include <sharechains/tracker.h>

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

class TreeSharechainsTest : public ::testing::Test
{
protected:
    shared_ptr<TestNetwork> net;

protected:

    virtual void SetUp()
    {
        C2Log::Logger::Init();
        C2Log::Logger::enable_trace();

        auto pt = coind::ParentNetwork::make_default_network();
        std::shared_ptr<coind::ParentNetwork> parent_net = std::make_shared<coind::ParentNetwork>("dgb", pt);
        net = make_shared<TestNetwork>(parent_net);
    }

    virtual void TearDown()
    {
    }
};

TEST_F(TreeSharechainsTest, init)
{
    BaseShareTracker tracker;
}

TEST_F(TreeSharechainsTest, one_share)
{
    BaseShareTracker tracker;

    PackStream stream_share;
    stream_share.from_hex("21fd4301fe02000020d015122ac6c9b4ec0b3b0f684dcb88fedc106c22d66b8583d67bcdf7fa2fbe37542188632205011b492009eaa2bfe882e1f6f99596e720c18657a1dde02bdc10dcb3a8725c765625db9c3ea73d04ec59f7002cfabe6d6d9af7e5ceeeb550fe519d93acf6180dfac960ba8de50867804e3e1266e46b954a01000000000000000a5f5f6332706f6f6c5f5f04d213ddbb351fc9fbbd8e1f40942130e77131978df6de416cea4cc8090000000000002100000000000000000000000000000000000000000000000000000000000000000000009678d14ad4c5e2859d7d036b8f69b8211884a6b63711d6c3ee3c633d61610bf45d31041efb45011e552188630cd30300d98b6cb72504000000000000000000000000000000010000007e0fa5ede3dae6732ef68a7447180e26ef694d17a37d2e4c406244004c839722fd7a0100");
    auto share = load_share(stream_share, net, {"0.0.0.0", "0"});

    auto hash = share->hash;

    tracker.add(share);
    std::cout << *share->previous_hash << "/" << tracker.get_last(share->hash) << std::endl;

//    std::cout << "Desired version dist = 1" << std::endl;
//    auto desired_version1 = tracker->get_desired_version_counts(hash, 1);
//    for (auto v : desired_version1)
//    {
//        std::cout << v.first << ": " << v.second.ToString() << std::endl;
//    }
//
//    // Get
//    std::cout << "Get" << std::endl;
//    auto share2 = tracker->get(hash);
//    ASSERT_EQ(share2, share);
}