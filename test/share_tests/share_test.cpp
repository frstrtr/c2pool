#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <string>

#include <sharechains/share_tracker.h>
#include <networks/network.h>

#include <sharechains/share.h>
#include <sharechains/share_builder.h>

using namespace std;

namespace share_test
{
    class TestParentNetwork : public coind::ParentNetwork
    {
    public:
        TestParentNetwork() : ParentNetwork("parent_testnet")
        {

        }

        bool jsonrpc_check() override
        {
            return true;
        }

        bool version_check(int version) override
        {
            return true;
        };

        uint256 POW_FUNC(PackStream &packed_block_header) override
        {
            uint256 res;
            res.SetNull();
            return res;
        };
    };

    class TestNetwork : public c2pool::Network
    {
    public:
        TestNetwork(std::shared_ptr<TestParentNetwork> _parentNet) : Network("testnet", _parentNet)
        {
            BOOTSTRAP_ADDRS = {
                    CREATE_ADDR("217.72.4.157", "5024")
                    //"217.42.4.157:5025"
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
}
class ShareBaseBuilderTest : public ::testing::Test
{
protected:
    shared_ptr<share_test::TestParentNetwork> parent_net;
    shared_ptr<share_test::TestNetwork> net;
    c2pool::libnet::addr _addr;

protected:
    virtual void SetUp()
    {
        parent_net = std::make_shared<share_test::TestParentNetwork>();
        net = std::make_shared<share_test::TestNetwork>(parent_net);
        _addr = std::make_tuple("255.255.255.255", "25565");

    }

    virtual void TearDown()
    {

    }
};

class ShareObjectBuilderTest : public ShareBaseBuilderTest
{
protected:
    std::shared_ptr<ShareObjectBuilder> builder;

protected:
    void SetUp()
    {
        ShareBaseBuilderTest::SetUp();
        builder = std::make_shared<ShareObjectBuilder>(net);
    }

    void TearDown()
    {
        ShareBaseBuilderTest::TearDown();

    }
};

TEST_F(ShareObjectBuilderTest, ShareEmptyThrowTest)
{
    builder->create(17, _addr);
    ShareType share;
    ASSERT_ANY_THROW({share = builder->GetShare();});
}

TEST_F(ShareObjectBuilderTest, ShareLightTest)
{
    builder->create(16, _addr);
    std::cout << "Create share" << std::endl;

    // - min_header
    shares::types::SmallBlockHeaderType min_header(16, uint256(), 0, 0, 0);
    builder->min_header(min_header);
    std::cout << "min_header" << std::endl;

    // - share_data
    shares::types::ShareData share_data(uint256(), "00000000", 0, uint160(),
                                        0, 0, StaleInfo::unk, 16);
    builder->share_data(share_data);
    std::cout << "share_data" << std::endl;

    // - share_info
    builder->share_info(shares::types::ShareInfo{});
    std::cout << "share_info" << std::endl;

    // - ref_merkle_link
    builder->ref_merkle_link(coind::data::MerkleLink{});
    std::cout << "ref_merkle_link" << std::endl;

    // - last_txout_nonce
    builder->last_txout_nonce(0);
    std::cout << "last_txout_nonce" << std::endl;

    // - hash_link
    shares::types::HashLinkType hash_link{};
    builder->hash_link(hash_link);

    // - merkle_link
    builder->merkle_link(coind::data::MerkleLink{});
    std::cout << "merkle_link" << std::endl;

    // Get result
    ShareType share;

    share = builder->GetShare();
}