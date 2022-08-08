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

    PackStream stream;

}