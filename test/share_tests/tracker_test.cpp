#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <string>

#include <sharechains/tracker.h>
#include <networks/network.h>

using namespace std;

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

    bool version_check(int version) override {
        return true;
    };

    uint256 POW_FUNC(PackStream& packed_block_header) override {
        uint256 res;
        res.SetNull();
        return res;
    };
};

class TestNetwork : public c2pool::Network
{
public:
    TestNetwork(std::shared_ptr<TestParentNetwork> _parentNet) : Network("testnet" ,_parentNet)
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
    shared_ptr<TestParentNetwork> parent_net;
    shared_ptr<TestNetwork> net;
    vector<TestShare> _items;

    std::shared_ptr<ShareTracker> tracker;
protected:
    void SetUp()
    {
        parent_net = std::make_shared<TestParentNetwork>();
        net = std::make_shared<TestNetwork>(parent_net);
        tracker = std::make_shared<ShareTracker>(net);
        stringstream ss;

        arith_uint256 _hash;
        arith_uint256 _prev_hash;

        for (int i = 0; i < 50; i++)
        {
            _hash++;

            TestShare share = {_hash, _prev_hash};
            _items.push_back(share);
//            std::cout << share.hash.GetHex() << " " << share.previous_hash.GetHex() << std::endl;
            _prev_hash = _hash;
        }
    }

    void TearDown()
    {
        _items.clear();
    }
};

TEST_F(ShareTrackerTest, InitTrackerTest)
{

}

TEST_F(ShareTrackerTest, GetEmptyTrackerTest)
{
    uint256 hash;
    auto share1 = tracker->get(hash);
    ASSERT_FALSE(share1);
}

TEST_F(ShareTrackerTest, CreateAddShareToTracker){
    UniValue share;
    share.pushKV("min_header", (UniValue) min_header);

    //share_info
    UniValue share_info(UniValue::VOBJ);
    //share_info::share_data
    UniValue share_data(UniValue::VOBJ);

    share_data.pushKV("previous_share_hash", previous_hash.GetHex());
    share_data.pushKV("coinbase", coinbase);
    share_data.pushKV("nonce", (int)nonce);
    share_data.pushKV("pubkey_hash", pubkey_hash.GetHex());
    share_data.pushKV("subsidy", subsidy);
    share_data.pushKV("donation", donation);
    share_data.pushKV("stale_info", (int) stale_info);
    share_data.pushKV("desired_version", desired_version);

    share_info.pushKV("share_data", share_data);
    //-share_info::share_data

    UniValue _new_transaction_hashes(UniValue::VARR);
    for (auto item : new_transaction_hashes)
    {
        _new_transaction_hashes.push_back(item.GetHex());
    }
    share_info.pushKV("new_transaction_hashes", _new_transaction_hashes);

    UniValue _transaction_hash_refs(UniValue::VARR);
    for (auto _tx_hash_ref : transaction_hash_refs)
    {
        UniValue _tx_ref(UniValue::VARR);
        _tx_ref.push_back(std::get<0>(_tx_hash_ref));
        _tx_ref.push_back(std::get<1>(_tx_hash_ref));
        _transaction_hash_refs.push_back(_tx_ref);
    }
    share_info.pushKV("transaction_hash_refs", _transaction_hash_refs);
    share_info.pushKV("far_share_hash", far_share_hash.GetHex());
    share_info.pushKV("max_bits", max_target.GetHex());
    share_info.pushKV("bits", target.GetHex());
    share_info.pushKV("timestamp", timestamp);
    share_info.pushKV("absheight", absheight);
    share_info.pushKV("abswork", abswork.GetHex());
    //-share_info

    result.pushKV("share_info", share_info);
    result.pushKV("ref_merkle_link", (UniValue) ref_merkle_link);
    result.pushKV("last_txout_nonce", last_txout_nonce);
    result.pushKV("hash_link", (UniValue) hash_link);
    result.pushKV("merkle_link", (UniValue) merkle_link);
}
