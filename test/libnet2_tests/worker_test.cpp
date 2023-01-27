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
    // compute_work t: (Work:
    // version = 536870914, previous_block = 1e47a6e2224db5bc2ddce3c31eb14dac8b02ca5a05ebd077d9f53a8d092e4226, bits = 453045919, coinbaseflags = [ ], height = 16518948, timestamp = 1674480469,
    // transactions = [
    //      (TxType:
    //          version = 1,
    //          tx_ins = [
    //              (TxInType:
    //                  previous_output = (PreviousOutput: hash = 46683430f87c6ceb23628e0a1908438b3288f256218acef83b8fbd524621cdcb, index = 0),
    //                  script = [ 71 48 68 2 32 80 225 63 52 132 228 124 240 95 42 165 46 150 43 36 242 47 251 5 143 241 38 168 221 181 11 81 87 13 73 10 236 2 32 81 223 167 229 20 96 248 219 8 164 39 186 101 78 96 82 212 146 185 186 247 66 178 241 148 171 255 254 208 114 122 41 1 33 3 121 83 98 152 35 127 209 217 37 49 1 223 182 5 99 50 61 211 144 248 195 103 8 174 67 244 76 6 229 151 33 30 ],
    //                  sequence = 4294967294
    //          ) ],
    //          tx_outs = [
    //              (TxOutType:
    //                  value = 30000000,
    //                  script = [ 118 169 20 106 8 40 36 103 106 143 84 149 179 250 233 207 37 131 122 136 58 115 1 136 172 ]
    //              )
    //              (TxOutType:
    //                  value = 91024511644,
    //                  script = [ 118 169 20 172 6 156 107 16 133 34 25 141 47 231 209 201 95 208 104 102 188 183 186 136 172 ]
    //              )
    //          ],
    //          lock_time = 16518944, wdata = null
    //      )
    // ],
    // transaction_fees = [ 22655 ],
    // merkle_link =
    //      (MerkleLink:
    //          branch = [ ], index = 0
    //      ),
    // subsidy = 41082666040,
    // last_update = 1674480469)

    FakeCoindNode(std::shared_ptr<boost::asio::io_context> _context) : CoindNodeData(std::move(_context))
    {
    }

    bool is_connected() override
    {
        return true;
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

        pool_node->set_coind_node(coind_node);

        // Tracker
        tracker = std::make_shared<ShareTracker>(net);

        auto share_store = ShareStore(net);
        share_store.legacy_init(c2pool::filesystem::getProjectPath() / "shares.0", [&](auto shares, auto known){tracker->init(shares, known);});

        // Set best share
        boost::function<int32_t(uint256)> test_block_rel_height_func = [&](uint256 hash){return 0;};

        std::vector<uint8_t> _bytes = {103, 108, 55, 240, 5, 80, 187, 245, 215, 227, 92, 1, 210, 201, 113, 66, 242, 76, 148, 121, 29, 76, 3, 170, 153, 253, 61, 21, 199, 77, 202, 35};
        auto bytes_prev_block = c2pool::dev::bytes_from_uint8(_bytes);
        uint256 previous_block(bytes_prev_block);


        uint32_t bits = 453027171;
        std::map<uint256, coind::data::tx_type> known_txs;

        auto [_best, _desired, _decorated_heads, _bad_peer_addresses] = tracker->think(test_block_rel_height_func, previous_block, bits, known_txs);
        std::cout << "Best = " << _best.GetHex() << std::endl;

        coind_node->best_share.set(_best);

        // Coind JSONRPC
        std::shared_ptr<coind::JSONRPC_Coind> coind = std::make_shared<coind::JSONRPC_Coind>(context, net->parent, "217.72.4.157", "14024", "user:VeryVeryLongPass123");

        // set coind_node->coind_work
        //        coind_node->coind_work.set(coind->getwork(coind_node->txidcache));
        {
            coind::getwork_result _coind_res;
            _coind_res.version = 536870914;
            _coind_res.previous_block.SetHex("1e47a6e2224db5bc2ddce3c31eb14dac8b02ca5a05ebd077d9f53a8d092e4226");
            _coind_res.bits.value = 453045919;
            _coind_res.height = 16518948;
            _coind_res.time = 1674480469;

            //TODO: tx
            auto _tx = std::make_shared<coind::data::TransactionType>(
                // version
                1,
                // tx_ins
                std::vector<coind::data::TxInType>{
                    {
                        {uint256S("46683430f87c6ceb23628e0a1908438b3288f256218acef83b8fbd524621cdcb"), 0},
                        {71, 48, 68, 2, 32, 80, 225, 63, 52, 132, 228, 124, 240, 95, 42, 165, 46, 150, 43, 36, 242, 47, 251, 5, 143, 241, 38, 168, 221, 181, 11, 81, 87, 13, 73, 10, 236, 2, 32, 81, 223, 167, 229, 20, 96, 248, 219, 8, 164, 39, 186, 101, 78, 96, 82, 212, 146, 185, 186, 247, 66, 178, 241, 148, 171, 255, 254, 208, 114, 122, 41, 1, 33, 3, 121, 83, 98, 152, 35, 127, 209, 217, 37, 49, 1, 223, 182, 5, 99, 50, 61, 211, 144, 248, 195, 103, 8, 174, 67, 244, 76, 6, 229, 151, 33, 30},
                        4294967294
                    }
                },
                // tx_outs
                std::vector<coind::data::TxOutType>{
                    {30000000, {118, 169, 20, 106, 8, 40, 36, 103, 106, 143, 84, 149, 179, 250, 233, 207, 37, 131, 122, 136, 58, 115, 1, 136, 172}},
                    {91024511644, {118, 169, 20, 172, 6, 156, 107, 16, 133, 34, 25, 141, 47, 231, 209, 201, 95, 208, 104, 102, 188, 183, 186, 136, 172}}
                },
                // lock_time
                16518944
            );
            _coind_res.transactions = {_tx};

            _coind_res.rules = {"csv","segwit","nversionbips","reservealgo","odo"};
            _coind_res.transaction_fees = {std::make_optional(22655)};
            _coind_res.subsidy = 41082666040;
            _coind_res.last_update = 1674480469;
            coind_node->coind_work.set(_coind_res);
        }
    }

    virtual void TearDown()
    {
    }
};

TEST_F(WorkerTest, simple_test)
{
    std::shared_ptr<Worker> worker = std::make_shared<Worker>(net,pool_node, coind_node, tracker);
    auto [user, pubkey_hash, desired_share_target, desired_pseudoshare_target] = worker->preprocess_request("user:pass");
    LOG_INFO << pubkey_hash.GetHex() << " " << desired_share_target.GetHex() << " " << desired_pseudoshare_target.GetHex() << " " << user;
    auto [x, got_response] = worker->get_work(pubkey_hash, desired_share_target, desired_pseudoshare_target);

    LOG_DEBUG << "x from get_work: " << x;
//    worker->get_work()
}