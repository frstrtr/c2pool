#include <gtest/gtest.h>

#include <memory>
#include <utility>

#include <libnet2/pool_node_data.h>
#include <libnet2/coind_node_data.h>
#include <libnet2/worker.h>
#include <libdevcore/common.h>
#include <sharechains/tracker.h>
#include <sharechains/share_store.h>
#include <networks/network.h>

#include <boost/asio.hpp>

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
        }
    }
};

class FakePoolNode : public PoolNodeData
{
public:
    FakePoolNode(std::shared_ptr<boost::asio::io_context> _context) : PoolNodeData(std::move(_context))
    {
    }

    bool is_connected() override
    {
        return true;
    }
};

class FakeCoindNode : public CoindNodeData
{
public:
    FakeCoindNode(std::shared_ptr<boost::asio::io_context> _context) : CoindNodeData(std::move(_context))
    {

    }
};

class WorkerTest : public ::testing::Test
{
protected:
    shared_ptr<TestNetwork> net;
    std::shared_ptr<ShareTracker> tracker;
    std::shared_ptr<PoolNodeData> pool_node;
    std::shared_ptr<CoindNodeData> coind_node;

protected:

    virtual void SetUp()
    {
        auto context = std::make_shared<boost::asio::io_context>();

        // NETWORK/PARENT_NETWORK
        auto pt = coind::ParentNetwork::make_default_network();
        std::shared_ptr<coind::ParentNetwork> parent_net = std::make_shared<coind::ParentNetwork>("dgb", pt);
        net = make_shared<TestNetwork>(parent_net);

        // Pool/Coind nodes
        pool_node = std::make_shared<FakePoolNode>(context);
        coind_node = std::make_shared<FakeCoindNode>(context);

        // Tracker
        tracker = std::make_shared<ShareTracker>(net);

        auto share_store = ShareStore(net);
        share_store.legacy_init(c2pool::filesystem::getProjectPath() / "shares.0", [&](auto shares, auto known){tracker->init(shares, known);});

//        std::cout << tracker->items.size() << " " << tracker->verified.items.size() << std::endl;
//        std::cout << "shares: " << tracker->heads.size() << "/" << tracker->tails.size() << std::endl;
//        std::cout << "verified: " << tracker->verified.heads.size() << "/" << tracker->verified.tails.size() << std::endl;
//
//        boost::function<int32_t(uint256)> test_block_rel_height_func = [&](uint256 hash){return 0;};
//
//        std::vector<uint8_t> _bytes = {103, 108, 55, 240, 5, 80, 187, 245, 215, 227, 92, 1, 210, 201, 113, 66, 242, 76, 148, 121, 29, 76, 3, 170, 153, 253, 61, 21, 199, 77, 202, 35};
//        auto bytes_prev_block = c2pool::dev::bytes_from_uint8(_bytes);
//        uint256 previous_block(bytes_prev_block);
    }

    virtual void TearDown()
    {
    }
};

TEST_F(WorkerTest, simple_test)
{
    std::shared_ptr<Worker> worker = std::make_shared<Worker>(net,pool_node, coind_node, tracker);
}