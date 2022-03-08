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
//        stringstream ss;
//
//        arith_uint256 _hash;
//        arith_uint256 _prev_hash;
//
//        for (int i = 0; i < 50; i++)
//        {
//            _hash++;
//
//            TestShare share = {_hash, _prev_hash};
//            _items.push_back(share);
////            std::cout << share.hash.GetHex() << " " << share.previous_hash.GetHex() << std::endl;
//            _prev_hash = _hash;
//        }
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
//
//TEST_F(ShareTrackerTest, InvalidLoadShareTest)
//{
//    UniValue share_type(UniValue::VOBJ);
//
//    share_type.pushKV("type", 16);
//    share_type.pushKV("contents", "123");
//
//    c2pool::libnet::addr _addr("255.255.255.255", "1234");
//    ASSERT_THROW(c2pool::shares::load_share(share_type, net, _addr), std::runtime_error);
//}
//
//TEST_F(ShareTrackerTest, ValidLoadShareTest)
//{
//    UniValue share_type(UniValue::VOBJ);
//
//    share_type.pushKV("type", 17);
//    share_type.pushKV("contents", "21fd4301fe020000209de9671e01aa0f06737b5aba0d547efb3064f8e8c5895e83d862169f5a46dd91bde1a36171b8001bc30a5e6eeba44141049c3f9d8453e73a0801db121e198af36ccb8c56d25c26af7e688a823d0471f4d6002cfabe6d6d5b57ca3c49353a085f40e3d5375e569349a5d6e3478f167df08a2c648e2f208b01000000000000000a5f5f6332706f6f6c5f5f8d1f6b9f9ad7bdd0e20eb7f64fa6dd42734dd4f43275cc26609753310b00000000000021000000000000000000000000000000000000000000000000000000000000000000000096f9718dd7d3ed68299d04c111d3bfb03f251d84b5b77737280a7625a4cddeb245d6011dffac0f1cbde1a361c8e614004170dc4fc36d88020000000000000000000000000005000000f60044fe657dce736492e948bdfc2894befdd62cf1641cea82fe75c1fd0197d8fd7a0100");
//
//    c2pool::libnet::addr _addr("255.255.255.255", "1234");
//    auto share = c2pool::shares::load_share(share_type, net, _addr);
//    ASSERT_TRUE(share);
//
//}
//
//TEST_F(ShareTrackerTest, CreateAddShareToTracker){
//    UniValue share;
//    share.pushKV("min_header", (UniValue) min_header);
//
//    //share_info
//    UniValue share_info(UniValue::VOBJ);
//    //share_info::share_data
//    UniValue share_data(UniValue::VOBJ);
//
//    share_data.pushKV("previous_share_hash", previous_hash.GetHex());
//    share_data.pushKV("coinbase", coinbase);
//    share_data.pushKV("nonce", (int)nonce);
//    share_data.pushKV("pubkey_hash", pubkey_hash.GetHex());
//    share_data.pushKV("subsidy", subsidy);
//    share_data.pushKV("donation", donation);
//    share_data.pushKV("stale_info", (int) stale_info);
//    share_data.pushKV("desired_version", desired_version);
//
//    share_info.pushKV("share_data", share_data);
//    //-share_info::share_data
//
//    UniValue _new_transaction_hashes(UniValue::VARR);
//    for (auto item : new_transaction_hashes)
//    {
//        _new_transaction_hashes.push_back(item.GetHex());
//    }
//    share_info.pushKV("new_transaction_hashes", _new_transaction_hashes);
//
//    UniValue _transaction_hash_refs(UniValue::VARR);
//    for (auto _tx_hash_ref : transaction_hash_refs)
//    {
//        UniValue _tx_ref(UniValue::VARR);
//        _tx_ref.push_back(std::get<0>(_tx_hash_ref));
//        _tx_ref.push_back(std::get<1>(_tx_hash_ref));
//        _transaction_hash_refs.push_back(_tx_ref);
//    }
//    share_info.pushKV("transaction_hash_refs", _transaction_hash_refs);
//    share_info.pushKV("far_share_hash", far_share_hash.GetHex());
//    share_info.pushKV("max_bits", max_target.GetHex());
//    share_info.pushKV("bits", target.GetHex());
//    share_info.pushKV("timestamp", timestamp);
//    share_info.pushKV("absheight", absheight);
//    share_info.pushKV("abswork", abswork.GetHex());
//    //-share_info
//
//    result.pushKV("share_info", share_info);
//    result.pushKV("ref_merkle_link", (UniValue) ref_merkle_link);
//    result.pushKV("last_txout_nonce", last_txout_nonce);
//    result.pushKV("hash_link", (UniValue) hash_link);
//    result.pushKV("merkle_link", (UniValue) merkle_link);
//}