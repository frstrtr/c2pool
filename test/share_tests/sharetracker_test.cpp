#include <gtest/gtest.h>

#include <memory>

#include <sharechains/tracker.h>
#include <networks/network.h>

class TestNetwork : public c2pool::Network
{
public:
    TestNetwork(std::shared_ptr<coind::ParentNetwork> _par) : c2pool::Network("test_sharechain", _par)
    {
        SOFTFORKS_REQUIRED = {"nversionbips", "csv", "segwit", "reservealgo", "odo"};
        BOOTSTRAP_ADDRS = {
                CREATE_ADDR("0.0.0.0", "5024")
        };
        PREFIX_LENGTH = 8;
        PREFIX = new unsigned char[PREFIX_LENGTH]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
        IDENTIFIER_LENGHT = 8;
        IDENTIFIER = new unsigned char[IDENTIFIER_LENGHT]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x66};
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

class SharechainsTest : public ::testing::Test
{
protected:
    shared_ptr<TestNetwork> net;

protected:

    virtual void SetUp()
    {
        std::shared_ptr<coind::DigibyteParentNetwork> parent_net = std::make_shared<coind::DigibyteParentNetwork>();
        net = make_shared<TestNetwork>(parent_net);
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
//    stream_share.from_hex("11fda501fe02000020707524a64aa0820305612357ae0d2744695c8ba18b8e1402dc4e199b5e1bf8daae2ceb62979e001bc0006d6200000000000000000000000000000000000000000000000000000000000000003d043edaec002cfabe6d6d08d3533a81ca356a7ac1c85c9b0073aebcca7182ad83849b9498377c9a1cd8a701000000000000000a5f5f6332706f6f6c5f5f3e9922fe9ad7bdd0e20eb7f64fa6dd42734dd4f43275cc26fd4d483b0a00000000000021012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d61f2bae86d664294b8850df3f580ec9e4fb2170fe8dbae492b5159af73834eba4012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d60100000000000000000000000000000000000000000000000000000000000000000000ffff0f1effff0f1eae2ceb6201000000010010000000000000000000000000000000000000000000001fcbf0a89045913d394db52949e986b8c6385b0060cbaebf3cf7806ff1df96affd7a01012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d6");
    stream_share.from_hex("21fd0702fe02000020617dfa46bf73eb96548e0b039a647d35b387ed0cb1a6e51c80092175857d3f5b3ac4ff62f1a9001bc0254dda4d00fe065ba137d8e108ef134db29b7e33f46327f13626975c0c2a190082018f3d04d03aee002cfabe6d6d21102609e852babee96639fbb3b65588bbcc419720fec56da52e47120c4804a501000000000000000a5f5f6332706f6f6c5f5ffc88aa669a2cd3c1310067ae7e47a7869b330d30b691c61b46fb483b0a0000000000002102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203517d2164368b766e6b9d0598510a7bbfc9882940ebfe3f65bb72173c3dbf105802f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5ef1025a29236b072d75cde8637584a3ed2fe0bcd4aadb5824b61cc42b4414e143d020000000195cbb26f405ead27fcd8cf84155cfcfab722a0cfdb3a2c735fce15fb19bc8ae4ffff0f1e8888001e3bc4ff62cc210000df798a25160000000000000000000000000000000001000000986dae33074d8c439a5dc61c2019a86726ebd1cf0eb0240582ccc0b249d12ba7fd9c0102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203");
    auto share = load_share(stream_share, net, {"0.0.0.0", "0"});

    auto hash = share->hash;

    tracker->add(share);

    std::cout << "Desired version dist = 1" << std::endl;
    auto desired_version1 = tracker->get_desired_version_counts(hash, 1);
    for (auto v : desired_version1)
    {
        std::cout << v.first << ": " << v.second.ToString() << std::endl;
    }

    // Get
    std::cout << "Get" << std::endl;
    auto share2 = tracker->get(hash);
    ASSERT_EQ(share2, share);

    // Remove
    std::cout << "Remove" << std::endl;
    tracker->remove(hash);

}