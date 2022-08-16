#include <gtest/gtest.h>

#include <memory>

#include <sharechains/tracker.h>
#include <networks/network.h>

class TestNetwork : public c2pool::Network
{
public:
    TestNetwork() : c2pool::Network("test_sharechain", nullptr)
    {
        SOFTFORKS_REQUIRED = {"nversionbips", "csv", "segwit", "reservealgo", "odo"};
        BOOTSTRAP_ADDRS = {
                CREATE_ADDR("0.0.0.0", "5024")
        };
        PREFIX_LENGTH = 8;
        PREFIX = new unsigned char[PREFIX_LENGTH]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
        IDENTIFIER_LENGHT = 8;
        IDENTIFIER = new unsigned char[IDENTIFIER_LENGHT]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
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

        DONATION_SCRIPT = ParseHex("522102ed2a267bb573c045ef4dbe414095eeefe76ab0c47726078c9b7b1c496fee2e6221023052352f04625282ffd5e5f95a4cef52107146aedb434d6300da1d34946320ea52ae");

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
//TODO: remove
//            std::cout << gentx_stream.size() << std::endl;
//            for (auto v : gentx_stream.data){
//                std::cout << (unsigned int) v << " ";
//            }
//            std::cout << std::endl;

        }
    }
};

class SharechainsTest : public ::testing::Test
{
protected:
    shared_ptr<TestNetwork> net;

protected:

    virtual void SetUp()
    {
        net = make_shared<TestNetwork>();
    }

    virtual void TearDown()
    {
    }
};

TEST_F(SharechainsTest, tracker_base_tests)
{
    std::shared_ptr<ShareTracker> tracker = std::make_shared<ShareTracker>(net);

    uint256 hash = uint256S("1");

    // tracker assert in get_pool_attempts_per_second
    ASSERT_DEATH({
                     auto attempts1 = tracker->get_pool_attempts_per_second(hash, 1);
                 }, "get_pool_attempts_per_second: assert for dist >= 2");
}

TEST_F(SharechainsTest, tracker_empty)
{
    std::shared_ptr<ShareTracker> tracker = std::make_shared<ShareTracker>(net);

    uint256 hash = uint256S("1");


    // Remove
    std::cout << "Remove" << std::endl;
    tracker->remove(hash);

    // Pool attempts for dist = 1
    std::cout << "Pool attempts for dist = 1" << std::endl;
    ASSERT_DEATH({
                     auto attempts1 = tracker->get_pool_attempts_per_second(hash, 1);
                 }, "get_pool_attempts_per_second: assert for dist >= 2");

    // Pool attempts for dist = 10
    std::cout << "Pool attempts for dist = 10" << std::endl;
    ASSERT_THROW({auto attempts10 = tracker->get_pool_attempts_per_second(hash, 10);}, std::invalid_argument);

    // Desired version dist = 1
    std::cout << "Desired version dist = 1" << std::endl;
    auto desired_version1 = tracker->get_desired_version_counts(hash, 1);
    for (auto v : desired_version1)
    {
        std::cout << v.first << ": " << v.second.ToString() << std::endl;
    }

    // Desired version dist = 10
    std::cout << "Desired version dist = 10" << std::endl;
    auto desired_version10 = tracker->get_desired_version_counts(hash, 10);
    for (auto v : desired_version10)
    {
        std::cout << v.first << ": " << v.second.ToString() << std::endl;
    }

    // Get
    std::cout << "Get" << std::endl;
    auto share = tracker->get(hash);
    ASSERT_EQ(share, nullptr);
}

TEST_F(SharechainsTest, tracker_one_share)
{
    std::shared_ptr<ShareTracker> tracker = std::make_shared<ShareTracker>(net);

    PackStream stream_share;
    stream_share.from_hex("11fda501fe02000020707524a64aa0820305612357ae0d2744695c8ba18b8e1402dc4e199b5e1bf8daae2ceb62979e001bc0006d6200000000000000000000000000000000000000000000000000000000000000003d043edaec002cfabe6d6d08d3533a81ca356a7ac1c85c9b0073aebcca7182ad83849b9498377c9a1cd8a701000000000000000a5f5f6332706f6f6c5f5f3e9922fe9ad7bdd0e20eb7f64fa6dd42734dd4f43275cc26fd4d483b0a00000000000021012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d61f2bae86d664294b8850df3f580ec9e4fb2170fe8dbae492b5159af73834eba4012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d60100000000000000000000000000000000000000000000000000000000000000000000ffff0f1effff0f1eae2ceb6201000000010010000000000000000000000000000000000000000000001fcbf0a89045913d394db52949e986b8c6385b0060cbaebf3cf7806ff1df96affd7a01012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d6");
    auto share = load_share(stream_share, net, {"0.0.0.0", "0"});
}